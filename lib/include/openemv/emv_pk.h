#ifndef EMV_PK_H
#define EMV_PK_H

#include <stdbool.h>
#include <stddef.h>

struct emv_pk {
	unsigned char rid[5];
	unsigned char index;
	unsigned char hash_algo;
	unsigned char pk_algo;
	unsigned char hash[20];
	unsigned char exp[3];
	size_t elen;
	size_t mlen;
	unsigned char *modulus;
	unsigned int expire;
};

#define EXPIRE(yy, mm, dd)	0x ## yy ## mm ## dd

struct emv_pk *emv_pk_parse_pk(char *buf);
struct emv_pk *emv_pk_new(size_t modlen, size_t explen);
void emv_pk_free(struct emv_pk *pk);
unsigned char *emv_pk_dump_pk(const struct emv_pk *pk);
bool emv_pk_verify(const struct emv_pk *pk);

#endif
