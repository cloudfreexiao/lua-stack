#ifndef STACK_BPF_H
#define STACK_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

__u32 ZERO = 0;

// Values for x86_64 as of 6.0.18-200.
#define TOP_OF_KERNEL_STACK_PADDING 0
#define THREAD_SIZE_ORDER 2
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define THREAD_SIZE (PAGE_SIZE << THREAD_SIZE_ORDER)


#define lookup_map(name) bpf_map_lookup_elem(&name, &ZERO)
#define update_map(name, value) bpf_map_update_elem(&name, &ZERO, value, 0)

#define CLOG(...)  bpf_printk(__VA_ARGS__)

#define LOOP_CONTINUE		(0)
#define LOOP_BREAK		(1)


// Kernel addresses have the top bits set.
static __always_inline bool in_kernel(u64 ip) {
  return ip & (1UL << 63);
}

// kthreads mm's is not set.
//
// We don't check for the return value of `retrieve_task_registers`, it's
// caller due the verifier not liking that code.
static __always_inline bool is_kthread() {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  if (task == NULL) {
    return false;
  }

  void *mm;
  int err = bpf_probe_read_kernel(&mm, 8, &task->mm);
  if (err) {
    CLOG("[warn] bpf_probe_read_kernel failed with %d", err);
    return false;
  }

  return mm == NULL;
}


static __always_inline bool find_reg_user(unsigned int reg, bpf_user_pt_regs_t *regs, u64 *res) {
	switch (reg)
	{
	case DWARF_RBP: *res = PT_REGS_FP(regs); break;
	case DWARF_RSP: *res = PT_REGS_SP(regs); break;
	case DWARF_RIP: *res = PT_REGS_IP_CORE(regs); break;
	case DWARF_RBX: *res =  BPF_CORE_READ(regs, bx); break;
	case DWARF_RAX: *res = BPF_CORE_READ(regs, ax); break;
	case DWARF_RCX: *res = BPF_CORE_READ(regs, cx); break;
	case DWARF_RDI: *res = BPF_CORE_READ(regs, di); break;
	case DWARF_RDX: *res = BPF_CORE_READ(regs, dx); break;
	case DWARF_R8: *res = BPF_CORE_READ(regs,r8); break;
	case DWARF_R9: *res = BPF_CORE_READ(regs,r9); break;
	case DWARF_R10: *res = BPF_CORE_READ(regs,r10); break;
	case DWARF_R11: *res = BPF_CORE_READ(regs,r11); break;
	case DWARF_R12: *res = BPF_CORE_READ(regs,r12); break;
	case DWARF_R13: *res = BPF_CORE_READ(regs,r13); break;
	case DWARF_R14: *res = BPF_CORE_READ(regs,r14); break;
	case DWARF_R15: *res = BPF_CORE_READ(regs,r15); break;
	default:
		return false;
	}
	return true;
}

static __always_inline bool find_reg_value(unsigned int reg, struct pt_regs *regs, u64 *res) {
	switch (reg)
	{
	case DWARF_RBP: *res = PT_REGS_FP_CORE(regs); break;
	case DWARF_RSP: *res = PT_REGS_SP_CORE(regs); break;
	case DWARF_RIP: *res = PT_REGS_IP_CORE(regs); break;
	case DWARF_RBX: *res =  BPF_CORE_READ(regs, bx); break;
	case DWARF_RAX: *res = BPF_CORE_READ(regs, ax); break;
	case DWARF_RCX: *res = BPF_CORE_READ(regs, cx); break;
	case DWARF_RDI: *res = BPF_CORE_READ(regs, di); break;
	case DWARF_RDX: *res = BPF_CORE_READ(regs, dx); break;
	case DWARF_R8: *res = BPF_CORE_READ(regs,r8); break;
	case DWARF_R9: *res = BPF_CORE_READ(regs,r9); break;
	case DWARF_R10: *res = BPF_CORE_READ(regs,r10); break;
	case DWARF_R11: *res = BPF_CORE_READ(regs,r11); break;
	case DWARF_R12: *res = BPF_CORE_READ(regs,r12); break;
	case DWARF_R13: *res = BPF_CORE_READ(regs,r13); break;
	case DWARF_R14: *res = BPF_CORE_READ(regs,r14); break;
	case DWARF_R15: *res = BPF_CORE_READ(regs,r15); break;
	default:
		return false;
	}
	return true;
}


// avoid R0 invalid mem access 'scalar'
// Port of `task_pt_regs` in BPF.
static __always_inline bool retrieve_task_registers(u64 *ip, u64 *sp, u64 *bp, unsigned int reg, u64 *arg) {
	int err;
	void *stack;
	if (ip == NULL || sp == NULL || bp == NULL) {
		return false;
	}
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (task == NULL) {
		return false;
	}
	if (is_kthread()) {
		return false;
	}

 	err = bpf_probe_read_kernel(&stack, 8, &task->stack);
	if (err) {
		CLOG("retrieve_task_registers bpf_probe_read_kernel failed with %d", err);
		return false;
	}
	void *ptr = stack + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
	struct pt_regs *regs = ((struct pt_regs *)ptr) - 1;

	*ip = PT_REGS_IP_CORE(regs);
	*sp = PT_REGS_SP_CORE(regs);
	*bp = PT_REGS_FP_CORE(regs);

	return find_reg_value(reg, regs, arg);
}




#endif

