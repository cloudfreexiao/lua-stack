#include <capstone/capstone.h>
#include <string.h>
#include <linux/elf.h>
#include "asshelper.h"
#include "regdef.h"


#define LOOK_REG_MAX 10

typedef struct preg_t {
    char reg[64];
    int start;
    int end;
} preg_t;


typedef struct regslook_t {
    preg_t array[LOOK_REG_MAX];
    int count;
} regslook_t;



static int regtonumber(const char *regname) {
    for (int i = 0; i < DWARF_REGS; i++) {
        if (!strncmp(regname, regnames[i], 3)) {
            return i;
        }
    }
    return -1;
}

static int parse_left_reg(const char *inst, preg_t *out) {
    // like: mov    qword ptr [rbp - 0xc08], rdi
    // or
    // like: mov    r14, rdi
    int result = sscanf(inst, "%[^,]", out->reg);
    if (result == 1) { // maybe use stack save rdi
        return 1;
    }

    return 0;
}

static int parse_reg_str(const char *regstr, param_t *out) {
    char type[16];
    char modifier[8];
    char reg[3];
    char sign;
    int offset;

    int result = sscanf(regstr, "%s %s [%[^ ] %c %x]", type, modifier, reg, &sign, &offset);
    if (result == 5) {
        if (sign == '-') {
            offset = -offset;
        }
        int r = regtonumber(reg);
        if (r < 0) {
            return 0;
        }

        out->type = PARAM_IN_STACK;
        out->reg = r;
        out->offset = offset;
    } else {
        int r = regtonumber(regstr);
        if (r < 0) {
            return 0;
        }

        out->type = PARAM_IN_REG;
        out->reg = r;
        out->offset = 0;
    }
    return 1;
}

static int transfer_reg_next(cs_insn *ins, preg_t *reg) {
    if (strcmp("mov", ins->mnemonic)) { // is not mov instance
        if (strcmp("lea", ins->mnemonic)){ 
            return 0;
        }
    }

    int len = strlen(ins->op_str);
    int reglen = strlen(reg->reg);
    int start = len - reglen;

    // r13,QWORD PTR [rsp + 0x48]
    // or
    // QWORD PTR [rsp + 0x48],rdi
    if (!strncmp(ins->op_str + start, reg->reg, reglen)) {
        return 1;
    }

    return 0;
}

static int has_cover(cs_insn *ins, const char *reg) {
    if (strcmp("mov", ins->mnemonic)) { // is not mov instance
        if (strcmp("lea", ins->mnemonic)){ 
            return 0;
        }
    }

    //  QWORD PTR [rsp+0x48],rdi
    if (strncmp(reg, ins->op_str, strlen(reg))) {
        return 0;
    }
    return 1;
}

static void init_look(regslook_t *regslook) {
    regslook->count = 1;
    for (int i = 0; i < LOOK_REG_MAX; i++) {
        preg_t *preg = &regslook->array[i];
        preg->start = -1;
        preg->end = -1;

        if (i == 0) {
            strcpy(preg->reg, "rdi");
        }
    }
}

static int has_reg(regslook_t *regslook, const char *reg) {
    for (int i = 0; i < regslook->count; i++) {
        preg_t *tmp = &regslook->array[i];
        if (!strcmp(tmp->reg, reg)) {
            return 1;
        }   
    }
    return 0;
}

static int select_one_reg(regslook_t *regslook, param_t *out) {
    int select = 0;
    int maxrange = 0;
    int best = 100000;

    for (int i = 1; i < regslook->count; i++) {
        preg_t *look = &regslook->array[i];
        int range = look->end - look->start;

        if (look->end == -1) {
            maxrange = best;
            select = i;
        } else if (range > maxrange) {
            maxrange = range;
            select = i;
        }
    }

    if (select > 0) {
        preg_t *look = &regslook->array[select];
        parse_reg_str(look->reg, out);
        return 1;
    }
    return 0;
}

int find_func_reg1(const unsigned char *elf_data, unsigned long long address, unsigned int size, param_t *out) {
    csh handle;
    cs_insn *insn;
    size_t count;
    int ok = 0;

    out->type = PARAM_NON;

    regslook_t regslook;
    init_look(&regslook);

    // 初始化Capstone引擎
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("无法初始化Capstone引擎\n");
        return -1;
    }

    count = cs_disasm(handle, elf_data + address, size, address, 0, &insn);

    if (count > 0) {
        for (int j = 0; j < count/2; j++) {
            preg_t *look = NULL;
            cs_insn *item = &insn[j];
            
            int sz = regslook.count;
            for (int idx = 0; idx < sz; idx++) {
                look = &regslook.array[idx];
                if (look->end < 0) {
                    if (sz < LOOK_REG_MAX && transfer_reg_next(item, look)) {
                        preg_t *last = &regslook.array[regslook.count];
                        parse_left_reg(item->op_str, last);

                        if (has_reg(&regslook, last->reg)) {
                            continue;
                        }

                        last->start = j;
                        regslook.count++;
                    } else if (has_cover(item, look->reg)) {
                        look->end = j;
                    }
                }
            }
        }
        cs_free(insn, count);
    }

    if (!ok) {
        ok = select_one_reg(&regslook, out);
    }

    // 关闭Capstone引擎
    cs_close(&handle);

    if (ok) {
        return 0;
    }
    return -1;
}

