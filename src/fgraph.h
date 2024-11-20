#ifndef OUTFGRAPH_H_
#define OUTFGRAPH_H_


#include "vector.h"


int fgraph_init(const char *fname);
void fgraph_free();
void fgraph_output(VECTOR_TYPE(proc_stack_t) *proclist, int pid, const char *pname);

#endif
