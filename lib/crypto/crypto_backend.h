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

#ifndef CRYPTO_BACKEND_H
#define CRYPTO_BACKEND_H

#include "openemv/crypto.h"

#include <stddef.h>
#include <stdarg.h>

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})

struct crypto_hash {
	void (*write)(struct crypto_hash *ch, const unsigned char *buf, size_t len);
	unsigned char *(*read)(struct crypto_hash *ch);
	void (*close)(struct crypto_hash *ch);
};

struct crypto_pk {
	unsigned char *(*encrypt)(struct crypto_pk *cp, const unsigned char *buf, size_t len, size_t *clen);
	unsigned char *(*decrypt)(struct crypto_pk *cp, const unsigned char *buf, size_t len, size_t *clen);
	void (*close)(struct crypto_pk *cp);
};

struct crypto_backend {
	struct crypto_hash *(*hash_open)(enum crypto_algo_hash hash);
	struct crypto_pk *(*pk_open)(enum crypto_algo_pk pk, va_list vl);
	struct crypto_pk *(*pk_open_priv)(enum crypto_algo_pk pk, va_list vl);
	struct crypto_pk *(*pk_genkey)(enum crypto_algo_pk pk, va_list vl);
};

#ifdef ENABLE_CRYPTO_LIBGCRYPT
struct crypto_backend *crypto_libgcrypt_init(void);
#else
static inline struct crypto_backend *crypto_libgcrypt_init(void)
{
	return NULL;
}
#endif

#ifdef ENABLE_CRYPTO_NETTLE
struct crypto_backend *crypto_nettle_init(void);
#else
static inline struct crypto_backend *crypto_nettle_init(void)
{
	return NULL;
}
#endif

#endif
