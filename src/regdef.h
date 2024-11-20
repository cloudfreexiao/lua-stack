#ifndef REGDEF_H_
#define REGDEF_H_



typedef enum register_source {
    REG_UNUSED = 0,
    REG_CFA,
    REG_OFFSET_CFA,
    REG_REG,
    REG_SAME,
    REG_ATEXP,
    REG_ISEXP,
    REG_CONSTANT
} register_source;

typedef enum register_index {
    DWARF_RAX,
    DWARF_RDX,
    DWARF_RCX,
    DWARF_RBX,
    DWARF_RSI,
    DWARF_RDI,
    DWARF_RBP,
    DWARF_RSP,
    DWARF_R8,
    DWARF_R9,
    DWARF_R10,
    DWARF_R11,
    DWARF_R12,
    DWARF_R13,
    DWARF_R14,
    DWARF_R15,
    DWARF_RIP,
    DWARF_REGS
} register_index;

extern const char *regnames[];



#endif // !REGDEF_H_
