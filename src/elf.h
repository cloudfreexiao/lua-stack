#ifndef ELF_H
#define ELF_H

#include <linux/elf.h>

#define PATH_MAX 128

typedef struct elf_t {
    unsigned char *map;
    unsigned long map_size;

    Elf64_Ehdr *header;
    Elf64_Shdr *sheaders;

    const char *shstrtab;
} elf_t;



// proc/{pid}/maps
typedef struct map_item_t {
    unsigned long addr_start;
    unsigned long addr_end;
    unsigned long addr_offset;
    char path[PATH_MAX];
    elf_t elf;
} map_item_t;

typedef struct running_maps_t
{
    map_item_t *item;
    unsigned long count;
} running_maps_t;


void parse_elf(elf_t *elf, const char *filename);
void close_elf_map(elf_t *elf);
Elf64_Shdr *find_section_header_by_name(elf_t *elf, const char *name);
const Elf64_Sym *find_symname_address(elf_t *elf, const char* symname);
running_maps_t *create_maps(int pid);
void free_maps(running_maps_t *maps);

#endif
