#ifndef CAPK_H
#define CAPK_H

#include <stdbool.h>
#include <stddef.h>

struct capk {
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

struct capk *capk_parse_pk(char *buf);
void capk_free(struct capk *pk);
unsigned char *capk_dump_pk(const struct capk *pk);
bool capk_verify(const struct capk *pk);

#endif
