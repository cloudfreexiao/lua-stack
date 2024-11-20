#ifndef LUAFUNC_H_
#define LUAFUNC_H_

#include "native.bpf.h"
#include "common.h"


#if (defined LUA54 || defined LUASKY)
#include "luaref54.h"
#else
#include "luaref53.h"
#endif


typedef struct lthread_t {
	lua_State *L;
	int ustack_idx;
} lthread_t;


typedef struct lua_ctx_t {
	lthread_t lbuf[MAX_STACK_DEEP]; // lua thread number
	lua_State L, *Lp;
	Closure closure;
	Proto proto;

#if (defined LUA54 || defined LUASKY)
	StkIdRel func;	/* function index in the stack */
#else
	TValue func;
#endif
	CallInfo ci, *cip;
	u32 lthread_idx;
	int lcount;
} lua_ctx_t;



struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
  __type(key, u32);
  __type(value, lua_ctx_t);
} lua_ctx_map SEC(".maps");



static __always_inline lua_ctx_t *init_lua_ctx_map() {
	lua_ctx_t *lctx = lookup_map(lua_ctx_map);
	if (!lctx) {
		return NULL;
	}
	lctx->lcount = 0;
	lctx->lthread_idx = 0;
	lctx->Lp = NULL;

	return lctx;
}



#define read_user_data_ret(dst, from, ret) \
	do { \
		int err = bpf_probe_read_user(&dst, sizeof(dst), from); \
		if (err < 0) return ret; \
	} while(0)

#define read_user_data(dst, from) read_user_data_ret(dst, from, -1)



static __always_inline int currentpc(CallInfo *ci, Proto *p) {
	int pc = cast(int, ci->u.l.savedpc - p->code) - 1;
	// CLOG("currentpc savedpc: %p, code: %p, pc: %d", ci->u.l.savedpc, p->code, pc);
	if (pc < 0) {
		return 0;
	}
	return pc;
}

#if (defined LUA54 || defined LUASKY)

typedef struct baseline_t {
	int i;
	int pc;
	const Proto *p;
} baseline_t;

static int loop_baseline(int idx, void *ud) {
	baseline_t *bl = (baseline_t *)ud;
	int i = bl->i;

	if (i >= bl->p->sizeabslineinfo) {
		return LOOP_BREAK;
	}

	AbsLineInfo lineinfo;
	read_user_data_ret(lineinfo, bl->p->abslineinfo + i + 1, LOOP_BREAK);

	if (bl->pc < lineinfo.pc) {
		return LOOP_BREAK;
	}

	bl->i++;
	return LOOP_CONTINUE;
}

static int getbaseline(const Proto *f, int pc, int *basepc) {
	if (f->sizeabslineinfo == 0) {
		*basepc = -1;  /* start from the beginning */
		return f->linedefined;
	}
	else {
		AbsLineInfo lineinfo;
		read_user_data_ret(lineinfo, f->abslineinfo, 0);
		if (pc < lineinfo.pc) {
			*basepc = -1;  /* start from the beginning */
			return f->linedefined;
		}

		int i = cast_uint(pc) / MAXIWTHABS - 1;  /* get an estimate */
		baseline_t bl;
		bl.i = i;
		bl.p = f;
		bl.pc = pc;

		bpf_loop(f->sizeabslineinfo, loop_baseline, &bl, 0);

		// while (i + 1 < f->sizeabslineinfo && pc >= f->abslineinfo[i + 1].pc)
		// 	i++;  /* low estimate; adjust it */

		i = bl.i;

		// *basepc = f->abslineinfo[i].pc;
		read_user_data_ret(lineinfo, f->abslineinfo+i, 0);

		*basepc = lineinfo.pc;
		return lineinfo.line;
	}
}

typedef struct funcline_t {
	int basepc;
	const Proto *p;
	int pc;
	int baseline;
} funcline_t;


static int loop_funcline(int idx, void *ud) {
	funcline_t *fl = (funcline_t *)ud;
	if (fl->basepc++ >= fl->pc) {
		return LOOP_BREAK;
	}

	ls_byte line;
	read_user_data_ret(line, fl->p->lineinfo + fl->basepc, LOOP_BREAK);
	fl->baseline += line;
	return LOOP_CONTINUE;
}

static int luaG_getfuncline(const Proto *f, int pc) {
	if (f == NULL || f->lineinfo == NULL)  /* no debug information? */
		return -1;
	else {
		if (pc == 0) {
			pc = 1;
		}
		
		int basepc = 0;
		int baseline = getbaseline(f, pc, &basepc);
		// while (basepc++ < pc) {  /* walk until given instruction */
		// 	lua_assert(f->lineinfo[basepc] != ABSLINEINFO);
		// 	baseline += f->lineinfo[basepc];  /* correct line */
		// }
		funcline_t fl;
		fl.basepc = basepc;
		fl.baseline = baseline;
		fl.pc = pc;
		fl.p = f;

		bpf_loop(pc, loop_funcline, &fl, 0);
		return fl.baseline;
	}
}

#endif

static __always_inline int currentline(CallInfo *ci, Proto *p) {
#if (defined LUA54 || defined LUASKY)
	return luaG_getfuncline(p, currentpc(ci, p));
#else
	int pc = currentpc(ci, p);
	int fline;
	if (p->lineinfo && pc < p->sizelineinfo) {
		read_user_data(fline, p->lineinfo + pc);
		return fline;
	}
	return -1;
#endif
}


static __always_inline int read_lua_proto(lua_ctx_t *ctx) {
#if (defined LUA54 || defined LUASKY)
	void *ptr = (u8 *)ctx->ci.func.p;
	StackValue stk;
	if ((uintptr_t)ptr < 1024*1024) { //it's a offset
		ptr += (uintptr_t)ctx->L.stack.p;
	}
	read_user_data(stk, (void *)ptr);
	read_user_data(ctx->closure, stk.val.value_.gc);
	read_user_data(ctx->proto, ctx->closure.l.p);
#else
	read_user_data(ctx->func, ctx->ci.func);
	read_user_data(ctx->closure, ctx->func.value_.gc);
	read_user_data(ctx->proto, ctx->closure.l.p);
#endif

	return 0;
}

static __always_inline int read_lua_file(lua_func_t *lfunc, TString *ts) {
	TString tmp;
	read_user_data(tmp, ts);

	size_t sz = tsslen(&tmp);
	size_t maxsz = sizeof(lfunc->u.l.file);
	if (sz > maxsz) {
		sz = maxsz;
	}

	if (!bpf_probe_read_user(lfunc->u.l.file, sz, getstr(ts))) {
		if (sz < maxsz) {
			lfunc->u.l.file[sz] = '\0';
		}

		return 0;
	}

	return -1;
}



#endif

