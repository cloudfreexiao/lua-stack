#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "elf.h"
#include "logger.h"


void parse_elf(elf_t *elf, const char *filename) {
    int fd = open(filename, O_RDONLY);
    if(fd == -1) {
        LOG(FATAL, "Could not open file \"%s\": %s\n", filename, strerror(errno));
    }

    struct stat stat;
    fstat(fd, &stat);
    elf->map_size = (stat.st_size+0xfff)&~0xfff;
    elf->map = mmap(NULL, elf->map_size, PROT_READ,
        MAP_PRIVATE, fd, 0);

    if(elf->map == MAP_FAILED) {
        LOG(FATAL, "Failed to map content: %s\n", strerror(errno));
    }

    elf->header = (Elf64_Ehdr *)elf->map;

    if(!!strncmp((char *)elf->header->e_ident, ELFMAG, SELFMAG)) {
        printf("ELF magic mismatch!\n");
        printf("\"%s\"\n", elf->header->e_ident);
        exit(1);
    }

    if(elf->header->e_ident[EI_CLASS] != ELFCLASS64) {
        printf("Only 64-bit executables supported.\n");
        exit(1);
    }

    elf->sheaders = (Elf64_Shdr *)(elf->map + elf->header->e_shoff);
    elf->shstrtab =
        (char *)elf->map + elf->sheaders[elf->header->e_shstrndx].sh_offset;

    // TODO: parse relocations?

    close(fd);
}

void close_elf_map(elf_t *elf) {
    if(elf->map) munmap(elf->map, elf->map_size);
}


Elf64_Shdr *find_section_header_by_name(elf_t *elf, const char *name) {
    Elf64_Shdr *section = NULL;

    for(int i = 0; i < elf->header->e_shnum; i ++) {
        Elf64_Shdr *shdr = elf->sheaders + i;

        if(!strcmp(elf->shstrtab + shdr->sh_name, name)) {
            section = shdr;
            break;
        }
    }

    return section;
}

const Elf64_Sym *find_symname_address(elf_t *elf, const char* symname) {
    const Elf64_Shdr *sections = (const Elf64_Shdr *)(elf->map + elf->header->e_shoff);

    const Elf64_Shdr *symtab_section = NULL;
    const Elf64_Shdr *strtab_section = NULL;

    for (int i = 0; i < elf->header->e_shnum; i++) {
        if (sections[i].sh_type == SHT_SYMTAB) {
            symtab_section = &sections[i];
            strtab_section = &sections[sections[i].sh_link];
            break;
        }
    }

    if (!symtab_section || !strtab_section) {
        return NULL;
    }

    const Elf64_Sym *symbols = (const Elf64_Sym *)(elf->map + symtab_section->sh_offset);
    const char *strings = (const char *)(elf->map + strtab_section->sh_offset);

    for (int i = 0; i < elf->header->e_shnum; i++) {
        if (sections[i].sh_type == SHT_SYMTAB) {
            int symbol_count = sections[i].sh_size / sizeof(Elf64_Sym);
            for (int j = 0; j < symbol_count; j++) {
                const char* symbol_name = strings + symbols[j].st_name;
                if (strcmp(symbol_name, symname) == 0) {
                    // Elf64_Addr address = symbols[j].st_value;
                    return &symbols[j];
                }
            }
        }
    }
    return NULL;
}

#define ITEM_MAX_LEN 1024

static void expand_item(running_maps_t *maps, int size) {
    maps->item = realloc(maps->item, size * sizeof(map_item_t));
    maps->count = size;
}

static void free_item(running_maps_t *maps) {
    free(maps->item);
    maps->item = NULL;
}

running_maps_t *create_maps(int pid) {
    FILE *f;
    char line[ITEM_MAX_LEN];

    char r, w, x, p;
    int dev_major, dev_minor, inode, item_count;
    running_maps_t *maps = malloc(sizeof(*maps));

    if (maps == NULL) {
        return NULL;
    }

    item_count = 0;
    maps->count = 0;
    maps->item = NULL;
    expand_item(maps, 2);

    sprintf(line, "/proc/%d/maps", pid);
    if ((f = fopen(line, "r")) == NULL) {
        LOG(ERROR, "cannot open %s: %s", line, strerror(errno));
        f = NULL;
        goto create_maps_failed;
    }

    memset(line, 0, sizeof(line));

    for (;;) {
        char *rp = fgets(line, sizeof(line), f); 
        if (rp == NULL) {
            break;
        }

        map_item_t *item = &maps->item[item_count];
        int scan = sscanf(line, "%zx-%zx %c%c%c%c %zx %x:%x %d %[^\t\n]",
                &item->addr_start, &item->addr_end,
                &r, &w, &x, &p,
                &item->addr_offset,
                &dev_major, &dev_minor,
                &inode,
                item->path);

        if (scan < 11 || x != 'x' || item->path[0] == '[') {
            continue;
        }

        parse_elf(&item->elf, item->path);

        item_count ++;
        if (item_count >= maps->count) {
            expand_item(maps, maps->count * 2);
        }
        // break;
    }

    if (item_count != maps->count) {
        expand_item(maps, item_count);
    }

    fclose(f);
    
    return maps;

create_maps_failed:
    LOG(ERROR, "parse maps failed by %s", line);
    if (maps->item) {
        free_item(maps);
    }

    free(maps);
    if (f) {
        fclose(f);
    }
    return NULL;
}

void free_maps(running_maps_t *maps) {
    for (size_t i = 0; i < maps->count; i++) {
        map_item_t *item = &maps->item[i];
        close_elf_map(&item->elf);
    }

    free(maps->item);
    free(maps);
}

