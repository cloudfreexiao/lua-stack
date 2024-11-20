#include "common.h"
#include "native.bpf.h"
#include "luafunc.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024); // 1K
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
} fde_ip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, fde_state_t);
} fde_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
    __type(key, u32);
    __type(value, luaV_execute_t);
} luaV_execute_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_STACK_DEEP);
    __type(key, u32);
    __type(value, proc_stack_t);
} proc_stack_map SEC(".maps");



typedef struct table_unwind_t {
	u64 regL; //calculate luaV_execute() first param(lua_State address)
	u64 rip;
	u64 rsp;
	u64 rbp;
	u32 fde_size;
	u32 ustack_sz;
	u32 lstack_sz;
	luaV_execute_t *lt;
	lua_ctx_t *lctx;
	u64 *ustack;
	lua_func_t *lstack;
} table_unwind_t;


unsigned long FDE_IP_COUNT;
int target_pid = 0;

static u32 stack_cyc_id = 0;


static __always_inline fde_state_t *search(u64 rip, u32 fde_size) {
	u32 i = 0;
	s32 key = -1;
	u32 left = 0;

	u32 right = fde_size;
	while (i++ < 20 && left < right) {
		u64 *tmpip;
		u32 mid = (left + right) / 2;
		tmpip = bpf_map_lookup_elem(&fde_ip_map, &mid);
		if (tmpip == NULL) {
			break;
		}

		if (*tmpip > rip) {
			right = mid;
		} else {
			key = (s32)mid;
			left = mid + 1;
		}
	}
	if (key == -1) {
		return NULL;
	}
	return bpf_map_lookup_elem(&fde_state_map, &key);
}

static __always_inline u64 reg_enum_to_val(table_unwind_t *tu, u8 reg) {
	switch (reg) {
	case DWARF_RIP:
		return tu->rip;
	case DWARF_RBP:
		return tu->rbp;
	case DWARF_RSP:
		return tu->rsp;
	}

	if (reg == tu->lt->lstate.reg) {
		return tu->regL;
	}
	return 0;
}

static __always_inline u64 calc_reg(table_unwind_t *tu, fde_state_t *state, u8 reg, u64 cfa) {
	u64 value, from;

	if (reg >= DWARF_REGS) {
		return 0;
	}

	value = state->saved_registers[reg].value;
	from = state->saved_registers[reg].from;

	switch(from) {
	case REG_UNUSED:
		if (reg == DWARF_RIP) {
			return 0;
		} else {
			return reg_enum_to_val(tu, reg);
		}
	case REG_CFA: {
		u64 tmp;
		int n = bpf_probe_read_user(&tmp, 8, (void *)(cfa + value));
		return n == 0 ? tmp : 0;
	}
	case REG_OFFSET_CFA:
		return cfa + value;
	case REG_REG:
		return reg_enum_to_val(tu, value);
	case REG_SAME:
		return reg_enum_to_val(tu, reg);
	default:
		break;
	}
	return 0;
}


static __always_inline int check_lua_rip(u64 rip, u64 reg, luaV_execute_t *lt, lua_ctx_t *lctx, u32 stack_idx) {
	if (!lt || !lctx) {
		return -1;
	}

	if (lt->ip_start <= rip && rip <= lt->ip_end) {
		lua_State *L = NULL;
		if (lt->lstate.type == PARAM_IN_STACK) {
			u64 addr;
			if (bpf_probe_read_user(&addr, 8, (unsigned char*)reg + lt->lstate.offset) < 0) {
				return -1;
			}
			L = (lua_State *)addr;
			// CLOG("check 11L: %p, offset: %d, reg: %d", L, lt->lstate.offset, lt->lstate.reg);
		} else if (lt->lstate.type == PARAM_IN_REG) {
			L = (lua_State *)reg;
			// CLOG("check 22L: %p, offset: %d, reg: %d", L, lt->lstate.offset, lt->lstate.reg);
		} else {
			return -1;
		}

		if (lctx->Lp != L) {
			u32 i = lctx->lcount;
			if (i >= MAX_STACK_DEEP) {
				return -1;
			}
			lthread_t *lthread = &lctx->lbuf[i];
			lthread->L = L;
			lthread->ustack_idx = stack_idx;
			lctx->lcount++;
			lctx->Lp = L;
			return 0;
		}
	}

	return -1;
}

static int unwind_c(u32 index, void *ud) {
	table_unwind_t *tu = (table_unwind_t *)ud;

	u64 cfa;

	u32 stack_idx = tu->ustack_sz++;
	if (tu->rip > 0 && stack_idx < MAX_STACK_DEEP) {
		tu->ustack[stack_idx] = tu->rip;
	} else {
		return LOOP_BREAK;
	}

	check_lua_rip(tu->rip, tu->regL, tu->lt, tu->lctx, stack_idx);

	fde_state_t *state = search(tu->rip, tu->fde_size);
	if (state == NULL) {
		return LOOP_BREAK;
	}

	u64 tmpidx = state->cfa_register; // 这个必须用 u64 类型，用其他类型，会编译不过，不知道为什么
	if (tmpidx >= DWARF_REGS) {
		return LOOP_BREAK;
	}

	if (!state->cfa_expression) {
		cfa = reg_enum_to_val(tu, tmpidx) + state->cfa_offset;
	} else {
		return LOOP_BREAK;
	}

	tu->rbp = calc_reg(tu, state, DWARF_RBP, cfa);
	tu->rip = calc_reg(tu, state, DWARF_RIP, cfa);
	tu->regL = calc_reg(tu, state, tu->lt->lstate.reg, cfa);
	tu->rsp = cfa;
	// CLOG("[%d] cal rip: %lx, rsp: %lx, rbp: %lx\n", index, tu->rip, tu->rsp, tu->rbp);

	if (tu->rip == 0) {
		return LOOP_BREAK;
	}

	return LOOP_CONTINUE;
}

// ustack_idx is lua thread at ustack array index
static __always_inline int collect_lua_proto(table_unwind_t *tu, u32 ustack_idx) {
	lua_ctx_t *ctx = tu->lctx;

	u32 idx = tu->lstack_sz;
	if (idx >= MAX_STACK_DEEP) {
		return -1;
	}

	lua_func_t *lfunc = &tu->lstack[idx];
	lfunc->lv_idx = ustack_idx;
	if (isLua(&ctx->ci)) {
		read_lua_proto(ctx);
		if (ctx->proto.linedefined < 0 || ctx->proto.lastlinedefined < 0) {
			return -2;
		}
		lfunc->u.l.startline = ctx->proto.linedefined;
		lfunc->u.l.endline = ctx->proto.lastlinedefined;
		lfunc->u.l.currline = currentline(&ctx->ci, &ctx->proto);
		lfunc->flag = ctx->ci.callstatus; // set c addr flag
		if (read_lua_file(lfunc, ctx->proto.source) < 0) {
			return -2;
		}
		// CLOG("func: %d ,%d, source: %s", lfunc->u.l.startline, lfunc->u.l.endline, lfunc->u.l.file);
	} else {
		lfunc->flag = -1; // set c addr flag
	}

	tu->lstack_sz++;
	return 0;
}

static int unwind_lua(u32 index, void *ud) {
	table_unwind_t *tu = (table_unwind_t *)ud;
	lua_ctx_t *ctx = tu->lctx;
	bool next_thread = false;
	u32 idx = ctx->lthread_idx;

	if (idx >= ctx->lcount || idx >= MAX_STACK_DEEP) {
		return LOOP_BREAK;
	}

	lthread_t *co = &ctx->lbuf[idx];
	if (!ctx->Lp) {
		read_user_data_ret(ctx->L, co->L, LOOP_BREAK);
		ctx->Lp = &ctx->L;
		ctx->cip = ctx->L.ci;
	}

	if (bpf_probe_read_user(&ctx->ci, sizeof(CallInfo), ctx->cip) < 0) {
		next_thread = true;
		goto next;
	}

	idx = collect_lua_proto(tu, co->ustack_idx); // reuse idx
	if (idx == -1) {
		next_thread = true;
	} else if (idx == -2) {
		tu->ustack_sz = tu->lstack_sz = 0; // Skip this collection
		return LOOP_BREAK;
	}

next:
	if (next_thread) {
		ctx->lthread_idx++;
		ctx->Lp = NULL;
	} else {
		ctx->cip = ctx->ci.previous;
	}

	return LOOP_CONTINUE;
}


static int commit_unwind_info(table_unwind_t *tu) {
	struct stacktrace_event_t *event;
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 1;

	int cpu_id = bpf_get_smp_processor_id();

	event->pid = target_pid;
	event->cpu_id = cpu_id;

	if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
		event->comm[0] = 0;

	event->stack_map_idx = stack_cyc_id;
	bpf_ringbuf_submit(event, 0);
	return 0;
}


SEC("perf_event")
int profile(struct bpf_perf_event_data *ctx) {
	bpf_user_pt_regs_t *regs = &ctx->regs;

	int pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != target_pid)
		return 0;

	proc_stack_t *stk = bpf_map_lookup_elem(&proc_stack_map, &stack_cyc_id);
	if (!stk) {
		return 1;
	}
	table_unwind_t tu;
	tu.fde_size = FDE_IP_COUNT;
	tu.lctx = init_lua_ctx_map();
	tu.lt = lookup_map(luaV_execute_map);
	tu.ustack = stk->ustack;
	tu.ustack_sz = 0;
	tu.lstack = stk->lstack;
	tu.lstack_sz = 0;

	stk->kstack_sz = 0;
	stk->ustack_sz = 0;
	stk->lstack_sz = 0;
	bpf_map_update_elem(&proc_stack_map, &stack_cyc_id, stk, 0);

	if (!tu.lt) {
		return 1;
	}

	// #ifdef 
	#if (defined LUA54 || defined LUASKY)
		CLOG("---- use lua54");
	#else
		// CLOG("---- use lua53");
	#endif

	if (in_kernel(PT_REGS_IP(regs))) {
		if (!retrieve_task_registers(&tu.rip, &tu.rsp, &tu.rbp, tu.lt->lstate.reg, &tu.regL)) {
			// in kernelspace, but failed, probs a kworker
			return 1;
		}
	} else {
		// in userspace
		tu.rip = PT_REGS_IP(regs);
		tu.rsp = PT_REGS_SP(regs);
		tu.rbp = PT_REGS_FP(regs);

		// -- 这里只能复制一份出来，不能直接传给 find_reg_user，否则会运行时报错
		// -- dereference of modified ctx ptr R1 off=96 disallowed
		bpf_user_pt_regs_t tmp = *regs;
		if (!find_reg_user(tu.lt->lstate.reg, &tmp, &tu.regL)) {
			return 1;
		}
	}

	int n = bpf_loop(MAX_STACK_DEEP, unwind_c, &tu, 0);
	if (n < 0) {
		return 0;
	}

	if (tu.lctx && tu.lctx->lcount > 0) {
		tu.lctx->Lp = NULL;
		n = bpf_loop(MAX_STACK_DEEP, unwind_lua, &tu, 0);
	}

	stk->kstack_sz = bpf_get_stack(ctx, stk->kstack, sizeof(stk->kstack), 0);
	stk->lstack_sz = tu.lstack_sz;
	stk->ustack_sz = tu.ustack_sz;

	if (!bpf_map_update_elem(&proc_stack_map, &stack_cyc_id, stk, 0)) {
		commit_unwind_info(&tu);
	}

	stack_cyc_id++;
	if (stack_cyc_id >= MAX_STACK_DEEP) {
		stack_cyc_id = 0;
	}

	return 0;
}
