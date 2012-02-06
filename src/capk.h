#ifndef CAPK_H
#define CAPK_H

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

#define HASH_SHA_1	1
#define PK_RSA		1
#define EXPIRE(yy, mm, dd)	0x ## yy ## mm ## dd
/* Based on VSDC specs - technically it's not never but in a distant future */
#define EXPIRE_NEVER EXPIRE(20, 12, 31)


#endif
