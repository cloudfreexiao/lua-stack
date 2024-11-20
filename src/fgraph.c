#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"
#include "fgraph.h"
#include "trace_helpers.h"


#if (defined LUA54 || defined LUASKY)
#include "luaref54.h"
#else
#include "luaref53.h"
#endif


#define UNKNOW "-"


static FILE *f = NULL;
struct syms_cache *syms_cache = NULL;


static int is_luaV_execute(const char *symname) {
	#define execute "luaV_execute"
	return !strcmp(execute, symname);
}

static int is_luaD_precall(const char *symname) {
	#define precall "luaD_precall"
	return !strcmp(precall, symname);
}

static int show_lua_next_stack(proc_stack_t *stk, const char *symname, int ustack_idx, int *next_idx, char *data) {
	if (*next_idx >= stk->lstack_sz) {
		return 0;
	}

	if (!is_luaV_execute(symname)) {
		return 0;
	}

	int start_idx = *next_idx;
	int i = start_idx;
	int sz = 0;

	for (int j = start_idx+1; j < stk->lstack_sz; j++) {
		lua_func_t *tmp = &stk->lstack[j];
		if (tmp->lv_idx == ustack_idx && stk->lstack[start_idx].lv_idx != ustack_idx) {
			i = j;
			break;
		}
	}

	for (; i < stk->lstack_sz; i++) {
		lua_func_t *p = &stk->lstack[i];
		if (p->flag < 0) {
			continue;
		}
		sz += sprintf(data + sz, "\t%d function<..%s:%d,%d> (line:%d)\n", 
				p->lv_idx, p->u.l.file, p->u.l.startline, p->u.l.endline, p->u.l.currline);
		if (p->flag & CIST_FRESH) {
			*next_idx = i+1;
			return sz;
		}
	}

	*next_idx = i+1;
	return sz;
}

static int show_ustack_trace(proc_stack_t *stk, int pid, char *data, const struct syms *syms) {
	int stack_sz = stk->ustack_sz;
    unsigned long long *stack = stk->ustack;
	int next_idx = 0;
	int is_precall = 0;
	int sz = 0;

	const struct sym *sym;

	for (int i = 0; i < stack_sz; i++) {
		sym = syms__map_addr(syms, stack[i]);
		if (!sym) {
			continue;
		}

		// remove top lua ci and remove [luaD_precall, luaV_execute] range of function
		if (i == 0 && is_luaD_precall(sym->name)) {
			is_precall = 1;
		}

		if (is_precall) {
			if (!is_luaV_execute(sym->name)) {
				continue;
			} else {
				is_precall = 0;
				next_idx = 1;
			}
		}

		sz += show_lua_next_stack(stk, sym->name, i, &next_idx, data+sz);
		sz += sprintf(data + sz, "\t%016llx %s (%s)\n", stack[i], sym->name, UNKNOW);
	}

	return sz;
}

void fgraph_output(VECTOR_TYPE(proc_stack_t) *proclist, int pid, const char *pname) {
	char buf[1024 * MAX_STACK_DEEP];
	const struct syms *syms;
	printf("collect stack frame size: %ld\n", VECTOR_GET_SIZE(proc_stack_t, proclist));

	syms = syms_cache__get_syms(syms_cache, pid);
	if (!syms) {
		return;
	}

    VECTOR_FOR_EACH_PTR(proc_stack_t, stk, proclist) {
		size_t sz = 0;
		sz = sprintf(buf, "%s  %d [0]  0.0:   0 cycles: \n", pname, pid);
        sz += show_ustack_trace(stk, pid, buf + sz, syms);
		sz += sprintf(buf + sz, "\n");
		fwrite(buf, 1, sz, f);
    }
}

int fgraph_init(const char *fname) {
    f = fopen(fname, "w");
	if (f == NULL) {
		printf("Open %s failed\n", fname);
		return -1;
	}

	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		printf("new syms_cache failed\n");
		return -1;
	}
	
    return 0;
}

void fgraph_free() {
	if (f != NULL) {
		fclose(f);
	}
	syms_cache__free(syms_cache);
}
