#ifndef COMMON_H_
#define COMMON_H_


#include "regdef.h"
#include "asshelper.h"


#define MAX_STACK_DEEP 46
#define STR_BUFFER_SIZE 128



typedef struct fde_state_t {
    struct {
        int from;
        int value;
    } saved_registers[DWARF_REGS];

    unsigned long cfa_register;
    unsigned long cfa_offset;
    unsigned char cfa_expression; // true or false
} fde_state_t;

#define PROC_COMM_LEN 16


typedef unsigned long long stack_trace_t[MAX_STACK_DEEP];

typedef struct stacktrace_event_t {
	unsigned int pid;
	unsigned int cpu_id;
	char comm[PROC_COMM_LEN];
    unsigned int stack_map_idx;
} stacktrace_event_t;


typedef struct luaV_execute_t {
    unsigned long ip_start;
    unsigned long ip_end;
    param_t lstate;
} luaV_execute_t;


typedef struct lua_func_t {
    int lv_idx;
    int flag; // ci flag
    union {
        struct {
            char file[STR_BUFFER_SIZE];
            int startline;
            int endline;
            int currline;
        } l;
        unsigned long long caddr;
    } u;
} lua_func_t;

typedef lua_func_t lua_stack_t[MAX_STACK_DEEP];

typedef struct proc_stack_t {
	int kstack_sz;
	int ustack_sz;
    int lstack_sz;
	stack_trace_t kstack;
	stack_trace_t ustack;
    lua_stack_t lstack;
} proc_stack_t;



#endif

