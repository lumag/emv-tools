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
#include <stdio.h>

#include <nettle/sha.h>
#include <nettle/bignum.h>
#include <nettle/rsa.h>
#include <nettle/yarrow.h>

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
	struct rsa_public_key rsa_pub;
	struct rsa_private_key rsa_priv;
};

static void crypto_pk_nettle_close(struct crypto_pk *_cp)
{
	struct crypto_pk_nettle *cp = container_of(_cp, struct crypto_pk_nettle, cp);

	rsa_public_key_clear(&cp->rsa_pub);
	rsa_private_key_clear(&cp->rsa_priv);
	free(cp);
}

static unsigned char *crypto_pk_nettle_encrypt(struct crypto_pk *_cp, const unsigned char *buf, size_t len, size_t *clen)
{
	struct crypto_pk_nettle *cp = container_of(_cp, struct crypto_pk_nettle, cp);
	mpz_t data;
	size_t datasize;
	unsigned char *out;

	nettle_mpz_init_set_str_256_u(data, len, buf);
	mpz_powm(data, data, cp->rsa_pub.e, cp->rsa_pub.n);
	datasize = nettle_mpz_sizeinbase_256_u(data);

	out = malloc(cp->rsa_pub.size);
	if (!out) {
		*clen = 0;
		return NULL;
	}
	nettle_mpz_get_str_256(datasize, out + cp->rsa_pub.size - datasize, data);
	memset(out, 0, cp->rsa_pub.size - datasize);
	mpz_clear(data);

	*clen = cp->rsa_pub.size;

	return out;
}

static unsigned char *crypto_pk_nettle_decrypt(struct crypto_pk *_cp, const unsigned char *buf, size_t len, size_t *clen)
{
	struct crypto_pk_nettle *cp = container_of(_cp, struct crypto_pk_nettle, cp);
	mpz_t data;
	size_t datasize;
	unsigned char *out;

	nettle_mpz_init_set_str_256_u(data, len, buf);
	rsa_compute_root(&cp->rsa_priv, data, data);
	datasize = nettle_mpz_sizeinbase_256_u(data);

	out = malloc(cp->rsa_priv.size);
	if (!out) {
		*clen = 0;
		return NULL;
	}
	nettle_mpz_get_str_256(datasize, out + cp->rsa_priv.size - datasize, data);
	memset(out, 0, cp->rsa_priv.size - datasize);
	mpz_clear(data);

	*clen = cp->rsa_priv.size;

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
	rsa_public_key_init(&cp->rsa_pub);
	rsa_private_key_init(&cp->rsa_priv);
	nettle_mpz_set_str_256_u(cp->rsa_pub.n, modlen, mod);
	nettle_mpz_set_str_256_u(cp->rsa_pub.e, explen, exp);

	rc = rsa_public_key_prepare(&cp->rsa_pub);
	if (!rc) {
		rsa_public_key_clear(&cp->rsa_pub);
		rsa_private_key_clear(&cp->rsa_priv);
		free(cp);
		return NULL;
	}

	cp->cp.close = crypto_pk_nettle_close;
	cp->cp.encrypt = crypto_pk_nettle_encrypt;

	return &cp->cp;
}

static struct crypto_pk *crypto_pk_nettle_open_priv(enum crypto_algo_pk pk, va_list vl)
{
	struct crypto_pk_nettle *cp;
	int rc;

	if (pk != PK_RSA)
		return NULL;

	unsigned char *mod = va_arg(vl, unsigned char *);
	int modlen = va_arg(vl, size_t);
	unsigned char *exp = va_arg(vl, unsigned char *);
	int explen = va_arg(vl, size_t);
	unsigned char *d = va_arg(vl, unsigned char *);
	int dlen = va_arg(vl, size_t);
	unsigned char *p = va_arg(vl, unsigned char *);
	int plen = va_arg(vl, size_t);
	unsigned char *q = va_arg(vl, unsigned char *);
	int qlen = va_arg(vl, size_t);
	unsigned char *dp = va_arg(vl, unsigned char *);
	int dplen = va_arg(vl, size_t);
	unsigned char *dq = va_arg(vl, unsigned char *);
	int dqlen = va_arg(vl, size_t);
	unsigned char *inv = va_arg(vl, unsigned char *);
	int invlen = va_arg(vl, size_t);

	cp = malloc(sizeof(*cp));
	rsa_public_key_init(&cp->rsa_pub);
	rsa_private_key_init(&cp->rsa_priv);
	nettle_mpz_set_str_256_u(cp->rsa_pub.n, modlen, mod);
	nettle_mpz_set_str_256_u(cp->rsa_pub.e, explen, exp);
	nettle_mpz_set_str_256_u(cp->rsa_priv.d, dlen, d);
	nettle_mpz_set_str_256_u(cp->rsa_priv.p, plen, p);
	nettle_mpz_set_str_256_u(cp->rsa_priv.q, qlen, q);
	nettle_mpz_set_str_256_u(cp->rsa_priv.a, dplen, dp);
	nettle_mpz_set_str_256_u(cp->rsa_priv.b, dqlen, dq);
	nettle_mpz_set_str_256_u(cp->rsa_priv.c, invlen, inv);

	rc = rsa_public_key_prepare(&cp->rsa_pub);
	if (!rc) {
		rsa_public_key_clear(&cp->rsa_pub);
		rsa_private_key_clear(&cp->rsa_priv);
		free(cp);
		return NULL;
	}

	rc = rsa_private_key_prepare(&cp->rsa_priv);
	if (!rc) {
		rsa_private_key_clear(&cp->rsa_priv);
		rsa_public_key_clear(&cp->rsa_pub);
		free(cp);
		return NULL;
	}

	cp->cp.close = crypto_pk_nettle_close;
	cp->cp.encrypt = crypto_pk_nettle_encrypt;
	cp->cp.decrypt = crypto_pk_nettle_decrypt;

	return &cp->cp;
}

#define RND_N_SOURCES 2

static struct {
	struct yarrow256_ctx yactx;
	struct yarrow_source sources[RND_N_SOURCES];
} rndctx;

#if defined(HAVE_GETENTROPY)
#include <unistd.h>
/* getentropy call is declared in unistd.h */
#elif defined(linux)
#include <linux/random.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#if defined SYS_getrandom
static int getrandom(void *buf, size_t buflen, unsigned int flags)
{
	return syscall(SYS_getrandom, buf, buflen, flags);
}
#else
static int getrandom(void *buf, size_t buflen, unsigned int flags)
{
	errno = ENOSYS;
	return -1;
}
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

static int getentropy_urandom(void *buf, size_t len)
{
	static int fd = -1;
	size_t pos;

	if (fd == -1) {
		int old;

		fd = open("/dev/urandom", O_RDONLY);
		if (fd < 0) {
			return fd;
		}

		old = fcntl(fd, F_GETFD);
		if (old != -1)
			old = fcntl(fd, F_SETFD, old | FD_CLOEXEC);
		if (old < 0)
			return old;
	}

	for (pos = 0; pos < len; ) {
		ssize_t res = read(fd, buf + pos, len - pos);
		if (res < 0) {
			if (errno == EINTR)
				continue;

			return res;
		} else if (res == 0)
			return -1;
		else
			pos += res;
	}

	return 0;
}

static int getentropy(void *buf, size_t buflen)
{
	int ret;

	if (buflen > 256)
		goto failure;

	ret = getrandom(buf, buflen, 0);
	if (ret < 0) {
		if (errno == ENOSYS)
			return getentropy_urandom(buf, buflen);
		return ret;
	}
	if (ret == buflen)
		return 0;
failure:
	errno = EIO;
	return -1;
}
#else
#error Your system is not yet supported. Please add a getentropy function
#endif

#define GETENTROPY_BUF_SIZE 16

static int rnd_source_getentropy(int init)
{
	unsigned char buf[GETENTROPY_BUF_SIZE];
	unsigned int read_size = sizeof(buf);
	int rc;

	rc = getentropy(buf, read_size);
	if (rc < 0) {
		perror("getentropy");

		return rc;
	}

	return yarrow256_update(&rndctx.yactx, init,
			read_size * 8 / 2, read_size, buf);

}

#if NETTLE_VERSION_MAJOR > 2
typedef size_t rnd_size_t;
#else
typedef unsigned int rnd_size_t;
#endif

static void rnd_func(void *_ctx, rnd_size_t length, uint8_t *data)
{
	yarrow256_random(&rndctx.yactx, length, data);
}

static bool rnd_reseed(void)
{
	if (rnd_source_getentropy(0) < 0)
		return false;

	if (rnd_source_getentropy(1) < 0)
		return false;

	yarrow256_slow_reseed(&rndctx.yactx);

	return true;
}

static bool rnd_init(void)
{
	static bool initialized = false;

	if (initialized)
		return true;

	yarrow256_init(&rndctx.yactx, RND_N_SOURCES, rndctx.sources);

	initialized = rnd_reseed();

	return initialized;
}

static struct crypto_pk *crypto_pk_nettle_genkey(enum crypto_algo_pk pk, va_list vl)
{
	struct crypto_pk_nettle *cp;
	/*int transient;*/
	unsigned int nbits;
	unsigned int exp;

	if (pk != PK_RSA)
		return NULL;

	/*transient = */va_arg(vl, int);
	nbits = va_arg(vl, unsigned int);
	exp = va_arg(vl, unsigned int);

	cp = malloc(sizeof(*cp));
	rsa_public_key_init(&cp->rsa_pub);
	rsa_private_key_init(&cp->rsa_priv);

	mpz_set_ui(cp->rsa_pub.e, exp);

	rsa_generate_keypair(&cp->rsa_pub, &cp->rsa_priv, NULL,
			rnd_func, NULL, NULL,
			nbits, 0);

	cp->cp.close = crypto_pk_nettle_close;
	cp->cp.encrypt = crypto_pk_nettle_encrypt;
	cp->cp.decrypt = crypto_pk_nettle_decrypt;

	return &cp->cp;
}

static struct crypto_backend crypto_nettle_backend = {
	.hash_open = crypto_hash_nettle_open,
	.pk_open = crypto_pk_nettle_open,
	.pk_open_priv = crypto_pk_nettle_open_priv,
	.pk_genkey = crypto_pk_nettle_genkey,
};

struct crypto_backend *crypto_nettle_init(void)
{
	if (!rnd_init())
		return NULL;
	return &crypto_nettle_backend;
}
