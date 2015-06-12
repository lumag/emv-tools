#include "capk.h"
#include "crypto_backend.h"

#include <stdio.h>
#include <stdlib.h>

#ifndef BUFSIZ
#define BUFSIZ 4096
#endif

int main(int argc, char **argv) {

	if (!crypto_be_init())
		exit(2);

	FILE *f = fopen(argv[1] ? : "capk.txt", "r");

	if (!f) {
		perror("fopen");
		return 1;
	}

	while (!feof(f)) {
		char buf[BUFSIZ];
		if (fgets(buf, sizeof(buf), f) == NULL)
			break;
		struct capk *pk = capk_parse_pk(buf);
		if (!pk)
			continue;
		fprintf(stderr, "Verifying CA PK for %02hhx:%02hhx:%02hhx:%02hhx:%02hhx IDX %02hhx %d bits...",
				pk->rid[0],
				pk->rid[1],
				pk->rid[2],
				pk->rid[3],
				pk->rid[4],
				pk->index,
				pk->mlen * 8);
		if (capk_verify(pk)) {
			fprintf(stderr, "OK\n");
			if (argc > 2 && argv[2][0] == 'v') {
				unsigned char *c;
				c = capk_dump_pk(pk);
				if (c)
					printf("%s\n", c);
				free(c);
			}
		} else
			fprintf(stderr, "Failed!\n");
		capk_free(pk);
	}

	return 0;
}
