#ifndef DWARF_UNWIND_H
#define DWARF_UNWIND_H

#include "elf.h"
#include "vector.h"
#include "regdef.h"

typedef struct dwarf_state_t {
    struct {
        int from;
        int value;
        unsigned char *expression;
        unsigned long expression_length;
    } saved_registers[DWARF_REGS];

    // if cfa_expression == NULL, then use cfa_register/offset
    unsigned long cfa_register;
    unsigned long cfa_offset;
    unsigned char *cfa_expression;
    size_t cfa_expression_length;
} dwarf_state_t;

struct frame_cie_t;

typedef struct precomputed_unwind_t {
    unsigned long ip;
    unsigned long length;

    dwarf_state_t state;
} precomputed_unwind_t;

typedef struct dwarf_unwind_region_t {
    unsigned long base, length;
    struct frame_cie_t *cie;
    unsigned char *unwind_data;
    size_t unwind_data_length;
} dwarf_unwind_region_t;

typedef struct map_item_t map_item_t;

typedef struct dwarf_unwind_info_t {
    VECTOR_TYPE(precomputed_unwind_t) precomputed_unwinds;
    VECTOR_TYPE(dwarf_unwind_region_t) regions;
    // unsigned long vir_addr_start;
    // unsigned long vir_addr_offset;
    // char path[PATH_MAX];
    map_item_t *item;
} dwarf_unwind_info_t;

typedef struct unwind_table_t
{
    dwarf_unwind_info_t *dinfo;
    unsigned long count;
} unwind_table_t;

void init_dwarf_unwind_info(dwarf_unwind_info_t *dinfo);

void load_dwarf_unwind_information(dwarf_unwind_info_t *dinfo);

void compute_offsets(dwarf_unwind_info_t *dinfo);
void compute_one_region(dwarf_unwind_info_t *dinfo, dwarf_unwind_region_t *region);

/*int dwarf_unwind(dwarf_unwind_info_t *dinfo, unsigned long *bp,
    unsigned long *sp, unsigned long *ip);*/

unsigned long dwarf_unwind(dwarf_unwind_info_t *dinfo, unsigned long *regs);



#endif
