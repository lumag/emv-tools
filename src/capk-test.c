#include <stdio.h>
#include <stdlib.h>

#define GCRYPT_NO_DEPRECATED
#define GCRYPT_NO_MPI_MACROS
#include <gcrypt.h>

#include "capk.h"

#ifndef BUFSIZ
#define BUFSIZ 4096
#endif

static void init_gcry(void)
{
	/* Version check should be the very first call because it
	 * makes sure that important subsystems are intialized. */
	if (!gcry_check_version (GCRYPT_VERSION)) {
		fputs ("libgcrypt version mismatch\n", stderr);
		exit (2);
	}

	/* We don't want to see any warnings, e.g. because we have not yet
	 * parsed program options which might be used to suppress such
	 * warnings. */
	gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

	/* ... If required, other initialization goes here.  Note that the
	 * process might still be running with increased privileges and that
	 * the secure memory has not been intialized.  */

	/* Allocate a pool of 16k secure memory.  This make the secure memory
	 * available and also drops privileges where needed.  */
	gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

	/* It is now okay to let Libgcrypt complain when there was/is
	 * a problem with the secure memory. */
	gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

	/* ... If required, other initialization goes here.  */

	/* Tell Libgcrypt that initialization has completed. */
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

	gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 3u , 0);
//	gcry_control (GCRYCTL_PRINT_CONFIG, stdout);
}


int main(int argc, char **argv) {
	init_gcry();

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
		free(pk->modulus);
		free(pk);
	}

	return 0;
}
