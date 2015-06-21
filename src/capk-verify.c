#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/emv_pk.h"
#include "openemv/crypto.h"

#include <stdio.h>
#include <stdlib.h>

#ifndef BUFSIZ
#define BUFSIZ 4096
#endif

int main(int argc, char **argv) {
	FILE *f;
	const char *fname;

	if (!crypto_be_init())
		exit(2);

	fname = argv[1];
	if (!fname)
		fname = getenv("CAPKFILE");
	if (!fname)
		fname = EMV_DATA_DIR "capk.txt";

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
		} else
			fprintf(stderr, "Failed!\n");
		emv_pk_free(pk);
	}

	return 0;
}
