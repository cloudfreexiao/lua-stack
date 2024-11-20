#ifndef ASSHELPER_H_
#define ASSHELPER_H_


typedef enum param_type {
    PARAM_NON,
    PARAM_IN_STACK,
    PARAM_IN_REG
} param_type;

typedef struct param_t {
    unsigned char type;
    int offset;
    unsigned int reg;
} param_t;


int find_func_reg1(const unsigned char *elf_data, unsigned long long address, unsigned int size, param_t *out);


#endif

