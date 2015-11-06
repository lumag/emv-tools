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

#include "openemv/emv_pki_priv.h"
#include "openemv/crypto.h"

#include <stdlib.h>
#include <string.h>

struct emv_pk *emv_pki_make_ca(const struct crypto_pk *cp,
		const unsigned char *rid, unsigned char index,
		unsigned int expire, enum crypto_algo_hash hash_algo)
{
	size_t modlen, explen;
	unsigned char *mod, *exp;

	if (!rid)
		return NULL;

	mod = crypto_pk_get_parameter(cp, 0, &modlen);
	exp = crypto_pk_get_parameter(cp, 1, &explen);

	if (!mod || !modlen || !exp || !explen) {
		free(mod);
		free(exp);

		return NULL;
	}

	struct emv_pk *pk = emv_pk_new(modlen, explen);
	memcpy(pk->rid, rid, 5);
	pk->index = index;
	pk->expire = expire;
	pk->pk_algo = crypto_pk_get_algo(cp);
	pk->hash_algo = hash_algo;
	memcpy(pk->modulus, mod, modlen);
	memcpy(pk->exp, exp, explen);

	free(mod);
	free(exp);

	struct crypto_hash *ch = crypto_hash_open(pk->hash_algo);
	if (!ch)
		return false;

	crypto_hash_write(ch, pk->rid, sizeof(pk->rid));
	crypto_hash_write(ch, &pk->index, 1);
	crypto_hash_write(ch, pk->modulus, pk->mlen);
	crypto_hash_write(ch, pk->exp, pk->elen);

	unsigned char *h = crypto_hash_read(ch);
	if (!h) {
		crypto_hash_close(ch);
		emv_pk_free(pk);

		return NULL;
	}

	memcpy(pk->hash, h, crypto_hash_get_size(ch));
	crypto_hash_close(ch);

	return pk;
}
