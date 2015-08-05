/*
 * emv-tools - a set of tools to work with EMV family of smart cards
 * Copyright (C) 2012, 2013, 2015 Dmitry Eremin-Solenikov
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/emv_pk.h"
#include "openemv/crypto.h"
#include "openemv/config.h"

#include <stdio.h>
#include <stdlib.h>

#ifndef BUFSIZ
#define BUFSIZ 4096
#endif

int main(int argc, char **argv) {
	FILE *f;
	const char *fname;
	int rc = 0;

	fname = openemv_config_get("capk");

	f = fopen(fname, "r");
	if (!f) {
		perror("fopen");
		return 1;
	}

	while (!feof(f)) {
		char buf[BUFSIZ];
		if (fgets(buf, sizeof(buf), f) == NULL)
			break;
		struct emv_pk *pk = emv_pk_parse_pk(buf);
		if (!pk)
			continue;
		fprintf(stderr, "Verifying CA PK for %02hhx:%02hhx:%02hhx:%02hhx:%02hhx IDX %02hhx %zd bits...",
				pk->rid[0],
				pk->rid[1],
				pk->rid[2],
				pk->rid[3],
				pk->rid[4],
				pk->index,
				pk->mlen * 8);
		if (emv_pk_verify(pk)) {
			fprintf(stderr, "OK\n");
			if (argc > 2 && argv[2][0] == 'v') {
				unsigned char *c;
				c = emv_pk_dump_pk(pk);
				if (c)
					printf("%s\n", c);
				free(c);
			}
		} else {
			fprintf(stderr, "Failed!\n");
			rc = 1;
		}
		emv_pk_free(pk);
	}

	fclose(f);

	return rc;
}
