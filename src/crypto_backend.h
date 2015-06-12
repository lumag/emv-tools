#ifndef CRYPTO_BACKEND_H
#define CRYPTO_BACKEND_H

#include <stdbool.h>
#include <stddef.h>

bool crypto_be_init(void);

enum crypto_be_hash {
	HASH_INVALID,
	HASH_SHA_1,
};

struct crypto_hash *crypto_hash_open(enum crypto_be_hash hash);
void crypto_hash_close(struct crypto_hash *ch);
void crypto_hash_write(struct crypto_hash *ch, const unsigned char *buf, size_t len);
unsigned char *crypto_hash_read(struct crypto_hash *ch);

enum crypto_be_pk {
	PK_INVALID,
	PK_RSA,
};

struct crypto_pk *crypto_pk_open(enum crypto_be_pk pk, ...);
void crypto_pk_close(struct crypto_pk *cp);
unsigned char *crypto_pk_encrypt(struct crypto_pk *cp, const unsigned char *buf, size_t len, size_t *clen);

#endif
