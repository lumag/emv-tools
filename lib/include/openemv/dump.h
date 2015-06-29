#ifndef DUMP_H
#define DUMP_H

#include <stdio.h>

void dump_buffer_simple(const unsigned char *ptr, size_t len, FILE *f);
void dump_buffer(const unsigned char *ptr, size_t len, FILE *f);

#endif
