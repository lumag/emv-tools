#ifndef SCARD_H
#define SCARD_H

#include <stdbool.h>

struct sc;

struct sc *scard_init(void);
void scard_shutdown(struct sc **psc);

bool scard_is_error(struct sc *sc);
const char *scard_error(struct sc *sc);

void scard_connect(struct sc *sc);
void scard_disconnect(struct sc *sc);

int scard_transmit(struct sc *sc,
		const unsigned char *inbuf, size_t inlen,
		unsigned char *outbuf, size_t outlen);

#endif
