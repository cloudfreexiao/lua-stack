#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <signal.h>

#include "stack.skel.h"
#include "logger.h"
#include "vector.h"
#include "dwarfunwind.h"
#include "common.h"
#include "fgraph.h"
#include "asshelper.h"


#define COLLECT_MAX_SIZE 2000
#define PERF_FILE "perf.stack"


static volatile sig_atomic_t exiting = 0;

static int stack_map_fd = -1;

static VECTOR_TYPE(proc_stack_t) proclist;
static bool vec_cyc = false;
static char procname[1024];


int cmp_func(const void * a, const void * b) {
	precomputed_unwind_t *unwinda = (precomputed_unwind_t *)a;
	precomputed_unwind_t *unwindb = (precomputed_unwind_t *)b;
	return (unwinda->ip > unwindb->ip) ? 1 : -1;
}

int update_bpf_maps(struct stack_bpf *obj, 
			int pid, 
			VECTOR_TYPE(precomputed_unwind_t) *precomputed_unwinds, 
			luaV_execute_t *le) {
    int size = VECTOR_GET_SIZE(precomputed_unwind_t, precomputed_unwinds);

	bpf_map__set_max_entries(obj->maps.fde_ip_map, size);
	bpf_map__set_max_entries(obj->maps.fde_state_map, size);
	obj->bss->FDE_IP_COUNT = size;
	obj->bss->target_pid = pid;

	int err = stack_bpf__load(obj);
	if (err < 0) {
        return -1;
    }

	qsort(precomputed_unwinds->vector, size, sizeof(precomputed_unwind_t), cmp_func);

    unsigned int index = 0;
    VECTOR_FOR_EACH_PTR(precomputed_unwind_t, u, precomputed_unwinds) {
        int err = bpf_map__update_elem(obj->maps.fde_ip_map, &index, sizeof(index), &u->ip,
			   sizeof(u->ip), BPF_ANY);
        if (err < 0) {
            LOG(ERROR, "Error updating map 1: %s\n", strerror(err));
            return -1;
        }

        fde_state_t stateobj = {
            .cfa_offset = u->state.cfa_offset, 
            .cfa_register = u->state.cfa_register,
			.cfa_expression = u->state.cfa_expression != NULL ? 1 : 0
        };

        for (int i = 0; i < DWARF_REGS; i++) {
            stateobj.saved_registers[i].from = u->state.saved_registers[i].from;
            stateobj.saved_registers[i].value = u->state.saved_registers[i].value;
        }
        err = bpf_map__update_elem(obj->maps.fde_state_map, &index, sizeof(index), &stateobj,
			   sizeof(stateobj), BPF_ANY);
        if (err < 0) {
            LOG(ERROR, "Error updating map 2: %s\n", strerror(err));
            return -1;
        }

        index ++;
    }

	__u32 zero = 0;
	bpf_map__update_elem(obj->maps.luaV_execute_map, &zero, sizeof(zero), le, sizeof(luaV_execute_t), BPF_ANY);
	return 0;
}

int unwind_init(struct stack_bpf *obj, int pid) {
	int err;
	const Elf64_Sym *lsym;
    running_maps_t *maps;
    dwarf_unwind_info_t dinfo;

	// find luaV_execute address and lua_State
	unsigned long addr_ori = 0;
	unsigned long addr_start = 0;
	unsigned long addr_end = 0;
	param_t l;

	maps = create_maps(pid);
    if (maps == NULL) {
        return -1;
    }

    LOG(INFO, "pid: %d\n", pid);

    memset(&dinfo, 0, sizeof(dinfo));

    init_dwarf_unwind_info(&dinfo);

    for (int i = 0; i < maps->count; i++) {
        map_item_t *item = &maps->item[i];
        LOG(INFO, "---> %s (%lx-%lx  %lx)", item->path, item->addr_start, item->addr_end, item->addr_offset);
        dinfo.item = item;
        load_dwarf_unwind_information(&dinfo);

		if (i == 0) {
			snprintf(procname, sizeof(procname), "%s", item->path);
		}

		if (addr_start == 0) {
			lsym = find_symname_address(&item->elf, "luaV_execute");
			if (lsym) {
				addr_ori = lsym->st_value;
				addr_start = addr_ori + item->addr_start - item->addr_offset;

				err = find_func_reg1(item->elf.map, addr_ori, lsym->st_size, &l);
			    if (!err) {
					LOG(INFO, "find luaV_execute param, type: %d, reg: %u, offset: %d", l.type, l.reg, l.offset);
				}
			}
		}
    }

	VECTOR_FOR_EACH_PTR(dwarf_unwind_region_t, u, &dinfo.regions) {
		if (!err && addr_start > 0) {
			if (addr_ori == u->base) {
				addr_end = addr_start + u->length;
			}
		}

		free(u->unwind_data);
	}

	LOG(INFO, "=== luaV_execute %lx <%lx-%lx>\n", addr_ori, addr_start, addr_end);

	luaV_execute_t lt = {
		.ip_start = addr_start, 
		.ip_end = addr_end, 
		.lstate = l,
	};
    err = update_bpf_maps(obj, pid, &dinfo.precomputed_unwinds, &lt);

    free_maps(maps);

	VECTOR_FREE(precomputed_unwind_t, &dinfo.precomputed_unwinds);
	VECTOR_FREE(dwarf_unwind_region_t, &dinfo.regions);

	return err;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd,
			    unsigned long flags) {
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

/* Receive events from the ring buffer. */
static int event_handler(void *_ctx, void *data, size_t size) {
	struct stacktrace_event_t *event = data;
	proc_stack_t stk;
	if (bpf_map_lookup_elem(stack_map_fd, &event->stack_map_idx, &stk) < 0) {
		return 1;
	}

	if (stk.ustack_sz <= 0 || exiting)
		return 1;

	size_t sz = VECTOR_GET_SIZE(proc_stack_t, &proclist);
	if (sz > COLLECT_MAX_SIZE) {
		vec_cyc = true;
		VECTOR_RESIZE(proc_stack_t, &proclist, 0);
	}

	VECTOR_PUSH(proc_stack_t, &proclist, stk);

	if (exiting) {
		return -1;
	}

    return 0;
}

static int start_profile(struct stack_bpf *obj, int *pefds, struct bpf_link **links, int num_cpus) {
	int pefd;
	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_SOFTWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_SW_CPU_CLOCK;
	attr.sample_freq = 100; // 1 second frequency
	// attr.freq = 1;

	for (int cpu = 0; cpu < num_cpus; cpu++) {
		if (cpu >= 256)
			continue;

		pefd = perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pefd < 0) {
			pefds[cpu] = -1;
			continue;
		}

		pefds[cpu] = pefd;

		/* Attach a BPF program on a CPU */
		links[cpu] = bpf_program__attach_perf_event(obj->progs.profile, pefd);
		if (!links[cpu]) {
			return -1;
		}
	}

	return 0;
}

static void sig_handler(int sig) {
	exiting = 1;
}

int main(int argc, char const *argv[]) {
    if (argc != 2) {
        LOG(INFO, "Need Process PID to trace\n");
        return -1;
    }

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	VECTOR_INIT(proc_stack_t, &proclist);

	int err;
    struct ring_buffer *ring_buf = NULL;
    struct stack_bpf *obj;
	int *pefds = NULL;
	struct bpf_link **links = NULL;
	int num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		LOG(ERROR, "Fail to get the number of processors\n");
		goto cleanup;
	}

	pefds = malloc(num_cpus * sizeof(int));
	for (int i = 0; i < num_cpus; i++) {
		pefds[i] = -1;
	}

	links = calloc(num_cpus, sizeof(struct bpf_link *));

    libbpf_set_print(libbpf_print_fn);

	obj = stack_bpf__open();
	if (!obj) {
		LOG(ERROR, "failed to open BPF object\n");
		goto cleanup;
	}

    int pid = atoi(argv[1]);
    err = unwind_init(obj, pid);
	if (err < 0) {
		goto cleanup;
	}

	stack_map_fd = bpf_map__fd(obj->maps.proc_stack_map);
	if (stack_map_fd < 0) {
		goto cleanup;
	}

	// /* Prepare ring buffer to receive events from the BPF program. */
	ring_buf = ring_buffer__new(bpf_map__fd(obj->maps.events), event_handler, NULL, NULL);
	if (!ring_buf) {
		goto cleanup;
	}

    err = start_profile(obj, pefds, links, num_cpus);
    if (err < 0) {
        goto cleanup;
    }

	#if (defined LUA54 || defined LUASKY)
		LOG(INFO, "current trace is lua5.4");
	#else
		LOG(INFO, "current trace is lua5.3");
	#endif

	/* Wait and receive stack traces */
	while (!exiting) {
		err = ring_buffer__poll(ring_buf, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			break;
		}
	}

	LOG(INFO, "run end\n");
	LOG(INFO, "write file: %s ...", PERF_FILE);

	if (vec_cyc) {
		VECTOR_RESIZE(proc_stack_t, &proclist, COLLECT_MAX_SIZE);
	}

	fgraph_init(PERF_FILE);
	fgraph_output(&proclist, pid, procname);
	fgraph_free();
	LOG(INFO, "write %s file end\n", PERF_FILE);

cleanup:
	VECTOR_FREE(proc_stack_t, &proclist);

	if (links) {
		for (int cpu = 0; cpu < num_cpus; cpu++) {
			bpf_link__destroy(links[cpu]);
		}
		free(links);
	}

	if (pefds) {
		for (int i = 0; i < num_cpus; i++) {
			if (pefds[i] >= 0)
				close(pefds[i]);
		}
		free(pefds);
	}

    ring_buffer__free(ring_buf);
    stack_bpf__destroy(obj);
    return 0;
}

