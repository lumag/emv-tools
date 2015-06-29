#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/dump.h"

#include <stdio.h>

void dump_buffer_simple(const unsigned char *ptr, size_t len, FILE *f)
{
	int i;

	for (i = 0; i < len; i ++)
		fprintf(f, "%s%02hhx", i ? " " : "", ptr[i]);
}

void dump_buffer(const unsigned char *ptr, size_t len, FILE *f)
{
	int i, j;

	for (i = 0; i < len; i += 16) {
		fprintf(f, "\t%02x:", i);
		for (j = 0; j < 16; j++) {
			if (i + j < len)
				fprintf(f, " %02hhx", ptr[i + j]);
			else
				fprintf(f, "   ");
		}
		fprintf(f, " |");
		for (j = 0; j < 16 && i + j < len; j++) {
			fprintf(f, "%c", (ptr[i+j] >= 0x20 && ptr[i+j] < 0x7f) ? ptr[i+j] : '.' );
		}
		fprintf(f, "\n");
	}
}

