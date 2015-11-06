/*
 * emv-tools - a set of tools to work with EMV family of smart cards
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
#include "openemv/emv_pk.h"
#include "openemv/emv_pki.h"
#include "openemv/emv_pki_priv.h"
#include "openemv/dump.h"

#include <string.h>

static const unsigned char rid[5] = {0xa0, 0x00, 0x00, 0x00, 0x00};

static int test_emv_pki_make_ca(struct crypto_pk *cp)
{
	int ret = 1;
	struct emv_pk *pk = emv_pki_make_ca(cp, rid, 0, 0x000000, HASH_SHA_1);
	if (!pk)
		goto out;

	if (!emv_pk_verify(pk))
		goto out;

	ret = 0;

out:
	emv_pk_free(pk);

	return ret;
}

int main(void)
{

	unsigned int keylength = 1024;

	printf("Testing key length %d\n", keylength);

	struct crypto_pk *cp = crypto_pk_genkey(PK_RSA, 1, keylength, 3);
	if (!cp) {
		printf("Key generation failed\n");

		return 1;
	}

	if (test_emv_pki_make_ca(cp)) {
		printf("Failed emv_pki_make_ca test\n");
		crypto_pk_close(cp);

		return 1;
	}

	crypto_pk_close(cp);

	return 0;
}
