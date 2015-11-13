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
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#ifndef BUFSIZ
#define BUFSIZ 4096
#endif

static void do_pk_symlink(const char *fname, const char *linkdir, const struct emv_pk *pk)
{
	char *linkname = emv_pk_get_ca_pk_file(linkdir, pk->rid, pk->index);
	if (!linkname)
		return;

	unlink(linkname);
	int ret = symlink(fname, linkname);
	if  (ret < 0)
		perror("symlink");

	free(linkname);
}

static int do_one_file(const char *fname, const char *linkdir, bool dump)
{
	int rc = 0;
	FILE * f;

	if (!strcmp(fname, "-")) {
		f = stdin;
		linkdir = NULL; /* Do not symlink stdin */
	} else
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
		if (!pk) {
			fprintf(stderr, "Can't parse public key\n");
			rc = 1;
			break;
		}

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
			if (dump) {
				char *c = emv_pk_dump_pk(pk);
				printf("%s\n", c);
				free(c);
			}

			if (linkdir)
				do_pk_symlink(fname, linkdir, pk);
		} else {
			fprintf(stderr, "Failed!\n");
			rc = 1;
		}
		emv_pk_free(pk);
	}

	/* Don't close stdin */
	if (strcmp(fname, "-"))
		fclose(f);

	return rc;
}

static int usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [-d] [-l dir] capk...\n", progname);

	return 1;
}

int main(int argc, char **argv) {
	int rc = 0;
	bool dump = false;
	const char *linkdir = NULL;
	const char *progname;

	progname = *(argv++);

	while (*argv) {
		const char *opt = *(argv++);

		if (!strcmp(opt, "-d"))
			dump = true;
		else if (!strcmp(opt, "-l") && argv[0])
			linkdir = *(argv++);
		else if (!strcmp(opt, "-") || opt[0] != '-') {
			argv--;
			break;
		} else
			return usage(progname);
	}

	if (!*argv)
		return do_one_file(openemv_config_get_str("capk.file", "capk.txt"), linkdir, dump);

	while (*argv && !rc) {
		rc = do_one_file(*(argv++), linkdir, dump);
	}

	return rc;
}
