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
#include "crypto_backend.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <nettle/sha.h>
#include <nettle/bignum.h>
#include <nettle/rsa.h>

struct crypto_hash_nettle {
	struct crypto_hash ch;
	struct sha1_ctx ctx;
	unsigned char digest[SHA1_DIGEST_SIZE];
};

static void crypto_hash_nettle_close(struct crypto_hash *_ch)
{
	struct crypto_hash_nettle *ch = container_of(_ch, struct crypto_hash_nettle, ch);

	free(ch);
}

static void crypto_hash_nettle_write(struct crypto_hash *_ch, const unsigned char *buf, size_t len)
{
	struct crypto_hash_nettle *ch = container_of(_ch, struct crypto_hash_nettle, ch);

	sha1_update(&ch->ctx, len, buf);
}

static unsigned char *crypto_hash_nettle_read(struct crypto_hash *_ch)
{
	struct crypto_hash_nettle *ch = container_of(_ch, struct crypto_hash_nettle, ch);

	sha1_digest(&ch->ctx, sizeof(ch->digest), ch->digest);
	return ch->digest;
}

static struct crypto_hash *crypto_hash_nettle_open(enum crypto_algo_hash hash)
{
	struct crypto_hash_nettle *ch;

	if (hash != HASH_SHA_1)
		return NULL;

	ch = malloc(sizeof(*ch));
	sha1_init(&ch->ctx);

	ch->ch.write = crypto_hash_nettle_write;
	ch->ch.read = crypto_hash_nettle_read;
	ch->ch.close = crypto_hash_nettle_close;

	return &ch->ch;
}

struct crypto_pk_nettle {
	struct crypto_pk cp;
	struct rsa_public_key key;
};

static void crypto_pk_nettle_close(struct crypto_pk *_cp)
{
	struct crypto_pk_nettle *cp = container_of(_cp, struct crypto_pk_nettle, cp);

	rsa_public_key_clear(&cp->key);
	free(cp);
}

static unsigned char *crypto_pk_nettle_encrypt(struct crypto_pk *_cp, const unsigned char *buf, size_t len, size_t *clen)
{
	struct crypto_pk_nettle *cp = container_of(_cp, struct crypto_pk_nettle, cp);
	mpz_t data;
	size_t datasize;
	unsigned char *out;

	nettle_mpz_init_set_str_256_u(data, len, buf);
	mpz_powm(data, data, cp->key.e, cp->key.n);
	datasize = nettle_mpz_sizeinbase_256_u(data);

	out = malloc(cp->key.size);
	if (!out) {
		*clen = 0;
		return NULL;
	}
	nettle_mpz_get_str_256(datasize, out + cp->key.size - datasize, data);
	memset(out, 0, cp->key.size - datasize);
	mpz_clear(data);

	*clen = cp->key.size;

	return out;
}

static struct crypto_pk *crypto_pk_nettle_open(enum crypto_algo_pk pk, va_list vl)
{
	struct crypto_pk_nettle *cp;
	unsigned char *mod;
	int modlen;
	unsigned char *exp;
	int explen;
	int rc;

	if (pk != PK_RSA)
		return NULL;

	mod = va_arg(vl, unsigned char *);
	modlen = va_arg(vl, size_t);
	exp = va_arg(vl, unsigned char *);
	explen = va_arg(vl, size_t);

	cp = malloc(sizeof(*cp));
	rsa_public_key_init(&cp->key);
	nettle_mpz_set_str_256_u(cp->key.n, modlen, mod);
	nettle_mpz_set_str_256_u(cp->key.e, explen, exp);

	rc = rsa_public_key_prepare(&cp->key);
	if (!rc) {
		rsa_public_key_clear(&cp->key);
		free(cp);
		return NULL;
	}

	cp->cp.close = crypto_pk_nettle_close;
	cp->cp.encrypt = crypto_pk_nettle_encrypt;

	return &cp->cp;
}

static struct crypto_backend crypto_nettle_backend = {
	.hash_open = crypto_hash_nettle_open,
	.pk_open = crypto_pk_nettle_open,
};

struct crypto_backend *crypto_nettle_init(void)
{
	return &crypto_nettle_backend;
}
