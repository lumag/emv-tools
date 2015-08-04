/*
 * libopenemv - a library to work with EMV family of smart cards
 * Copyright (C) 2015 Dmitry Eremin-Solenikov
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

#include "openemv/crypto.h"

#include <stdarg.h>
#include <stdio.h>

#define GCRYPT_NO_DEPRECATED
#define GCRYPT_NO_MPI_MACROS
#include <gcrypt.h>

bool crypto_be_init(void)
{
	/* Version check should be the very first call because it
	 * makes sure that important subsystems are intialized. */
	if (!gcry_check_version (GCRYPT_VERSION)) {
		fputs ("libgcrypt version mismatch\n", stderr);
		return false;
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

//	gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 3u , 0);
//	gcry_control (GCRYCTL_PRINT_CONFIG, stdout);

	return true;
}

struct crypto_hash {
	gcry_md_hd_t md;
};

struct crypto_hash *crypto_hash_open(enum crypto_be_hash hash)
{
	struct crypto_hash *ch = malloc(sizeof(*ch));
	gcry_error_t err;
	int algo = GCRY_MD_NONE;

	if (hash == HASH_SHA_1)
		algo = GCRY_MD_SHA1;

	err = gcry_md_open(&ch->md, algo, 0);
	if (err) {
		fprintf(stderr, "LibGCrypt error %s/%s\n",
				gcry_strsource (err),
				gcry_strerror (err));
		free(ch);
		ch = NULL;
	}

	return ch;
}

void crypto_hash_close(struct crypto_hash *ch)
{
	gcry_md_close(ch->md);
	free(ch);
}

void crypto_hash_write(struct crypto_hash *ch, const unsigned char *buf, size_t len)
{
	gcry_md_write(ch->md, buf, len);
}

unsigned char *crypto_hash_read(struct crypto_hash *ch)
{
	return gcry_md_read(ch->md, 0);
}

struct crypto_pk {
	gcry_sexp_t pk;
};

static bool crypto_pk_open_rsa(struct crypto_pk *cp, va_list vl)
{
	gcry_error_t err;
	char *mod = va_arg(vl, char *);
	int modlen = va_arg(vl, size_t);
	char *exp = va_arg(vl, char *);
	int explen = va_arg(vl, size_t);

	err = gcry_sexp_build(&cp->pk, NULL, "(public-key (rsa (n %b) (e %b)))",
			modlen, mod, explen, exp);
	if (err) {
		fprintf(stderr, "LibGCrypt error %s/%s\n",
				gcry_strsource (err),
				gcry_strerror (err));
		return false;
	}

	return true;
}

struct crypto_pk *crypto_pk_open(enum crypto_be_pk pk, ...)
{
	struct crypto_pk *cp = malloc(sizeof(*cp));
	va_list vl;
	bool ok;

	va_start(vl, pk);

	switch (pk) {
	default:
	case PK_INVALID:
		ok = false;
		break;

	case PK_RSA:
		ok = crypto_pk_open_rsa(cp, vl);
		break;
	}

	va_end(vl);

	if (!ok) {
		free(cp);
		cp = NULL;
	}
	return cp;
}

void crypto_pk_close(struct crypto_pk *cp)
{
	gcry_sexp_release(cp->pk);
	free(cp);
}

unsigned char *crypto_pk_encrypt(struct crypto_pk *cp, const unsigned char *buf, size_t len, size_t *clen)
{
	gcry_error_t err;
	int blen = len;
	gcry_sexp_t dsexp, esexp, asexp;
	gcry_mpi_t tmpi;
	size_t templen;
	size_t keysize;
	unsigned char *result;

	err = gcry_sexp_build(&dsexp, NULL, "(data (flags raw) (value %b))",
			blen, buf);
	if (err) {
		fprintf(stderr, "LibGCrypt error %s/%s\n",
				gcry_strsource (err),
				gcry_strerror (err));
		return NULL;
	}

	err = gcry_pk_encrypt(&esexp, dsexp, cp->pk);
	gcry_sexp_release(dsexp);
	if (err) {
		fprintf(stderr, "LibGCrypt error %s/%s\n",
				gcry_strsource (err),
				gcry_strerror (err));
		return NULL;
	}

	asexp = gcry_sexp_find_token(esexp, "a", 1);
	gcry_sexp_release(esexp);
	if (!asexp)
		return NULL;

	tmpi = gcry_sexp_nth_mpi(asexp, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release(asexp);
	if (!tmpi)
		return NULL;

	keysize = (gcry_pk_get_nbits(cp->pk) + 7) / 8;
	result = malloc(keysize);
	if (!result) {
		gcry_mpi_release(tmpi);
		return NULL;
	}

	err = gcry_mpi_print(GCRYMPI_FMT_USG, NULL, keysize, &templen, tmpi);
	if (err) {
		fprintf(stderr, "LibGCrypt error %s/%s\n",
				gcry_strsource (err),
				gcry_strerror (err));
		gcry_mpi_release(tmpi);
		free(result);
		return NULL;
	}

	err = gcry_mpi_print(GCRYMPI_FMT_USG, result + keysize - templen, templen, &templen, tmpi);
	if (err) {
		fprintf(stderr, "LibGCrypt error %s/%s\n",
				gcry_strsource (err),
				gcry_strerror (err));
		gcry_mpi_release(tmpi);
		free(result);
		return NULL;
	}
	memset(result, 0, keysize - templen);

	*clen = keysize;
	gcry_mpi_release(tmpi);

	return result;
}
