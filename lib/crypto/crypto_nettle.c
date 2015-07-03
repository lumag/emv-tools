#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/crypto.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <nettle/sha.h>
#include <nettle/bignum.h>
#include <nettle/rsa.h>

bool crypto_be_init(void)
{
	return true;
}

struct crypto_hash {
	struct sha1_ctx ctx;
	unsigned char digest[SHA1_DIGEST_SIZE];
};

struct crypto_hash *crypto_hash_open(enum crypto_be_hash hash)
{
	struct crypto_hash *ch;

	if (hash != HASH_SHA_1)
		return NULL;

	ch = malloc(sizeof(*ch));
	sha1_init(&ch->ctx);

	return ch;
}

void crypto_hash_close(struct crypto_hash *ch)
{
	free(ch);
}

void crypto_hash_write(struct crypto_hash *ch, const unsigned char *buf, size_t len)
{
	sha1_update(&ch->ctx, len, buf);
}

unsigned char *crypto_hash_read(struct crypto_hash *ch)
{
	sha1_digest(&ch->ctx, sizeof(ch->digest), ch->digest);
	return ch->digest;
}

struct crypto_pk {
	struct rsa_public_key key;
};

struct crypto_pk *crypto_pk_open(enum crypto_be_pk pk, ...)
{
	struct crypto_pk *cp;
	va_list vl;
	unsigned char *mod;
	int modlen;
	unsigned char *exp;
	int explen;
	int rc;

	if (pk != PK_RSA)
		return NULL;

	va_start(vl, pk);
	mod = va_arg(vl, unsigned char *);
	modlen = va_arg(vl, size_t);
	exp = va_arg(vl, unsigned char *);
	explen = va_arg(vl, size_t);
	va_end(vl);

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

	return cp;
}

void crypto_pk_close(struct crypto_pk *cp)
{
	rsa_public_key_clear(&cp->key);
	free(cp);
}

unsigned char *crypto_pk_encrypt(struct crypto_pk *cp, const unsigned char *buf, size_t len, size_t *clen)
{
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

	*clen = cp->key.size;

	return out;
}
