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

#include "openemv/config.h"
#include "openemv/crypto.h"
#include "crypto_backend.h"

#include <string.h>

static struct crypto_backend *crypto_backend;

static bool crypto_init(void)
{
	const char *driver;

	if (crypto_backend)
		return true;

	driver = openemv_config_get("crypto.driver");
	if (!driver)
		return false;
	else if (!strcmp(driver, "libgcrypt"))
		crypto_backend = crypto_libgcrypt_init();
	else if (!strcmp(driver, "nettle"))
		crypto_backend = crypto_nettle_init();

	if (!crypto_backend)
		return false;

	return true;
}

struct crypto_hash *crypto_hash_open(enum crypto_algo_hash hash)
{
	if (!crypto_init())
		return NULL;

	return crypto_backend->hash_open(hash);
}

void crypto_hash_close(struct crypto_hash *ch)
{
	ch->close(ch);
}

void crypto_hash_write(struct crypto_hash *ch, const unsigned char *buf, size_t len)
{
	ch->write(ch, buf, len);
}

unsigned char *crypto_hash_read(struct crypto_hash *ch)
{
	return ch->read(ch);
}

struct crypto_pk *crypto_pk_open(enum crypto_algo_pk pk, ...)
{
	struct crypto_pk *cp;
	va_list vl;

	if (!crypto_init())
		return NULL;

	va_start(vl, pk);
	cp = crypto_backend->pk_open(pk, vl);
	va_end(vl);

	return cp;
}

struct crypto_pk *crypto_pk_open_priv(enum crypto_algo_pk pk, ...)
{
	struct crypto_pk *cp;
	va_list vl;

	if (!crypto_init())
		return NULL;

	if (!crypto_backend->pk_open_priv)
		return NULL;

	va_start(vl, pk);
	cp = crypto_backend->pk_open_priv(pk, vl);
	va_end(vl);

	return cp;
}

struct crypto_pk *crypto_pk_genkey(enum crypto_algo_pk pk, ...)
{
	struct crypto_pk *cp;
	va_list vl;

	if (!crypto_init())
		return NULL;

	if (!crypto_backend->pk_genkey)
		return NULL;

	va_start(vl, pk);
	cp = crypto_backend->pk_genkey(pk, vl);
	va_end(vl);

	return cp;
}

void crypto_pk_close(struct crypto_pk *cp)
{
	cp->close(cp);
}

unsigned char *crypto_pk_encrypt(struct crypto_pk *cp, const unsigned char *buf, size_t len, size_t *clen)
{
	return cp->encrypt(cp, buf, len, clen);
}

unsigned char *crypto_pk_decrypt(struct crypto_pk *cp, const unsigned char *buf, size_t len, size_t *clen)
{
	if (!cp->decrypt) {
		*clen = 0;

		return NULL;
	}

	return cp->decrypt(cp, buf, len, clen);
}
