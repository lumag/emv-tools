#ifndef SCARD_H
#define SCARD_H

#include <stdbool.h>
#include <stddef.h>

struct sc;

struct sc *scard_init(void);
void scard_shutdown(struct sc **psc);

enum {
	SCARD_NO_ERROR = 0,
	SCARD_CARD,
	SCARD_MEMORY,
	SCARD_PARAMETER,
	_SCARD_ERROR_MAX,
};
void scard_raise_error(struct sc *sc, int type);
bool scard_is_error(struct sc *sc);
const char *scard_error(struct sc *sc);

void scard_connect(struct sc *sc);
void scard_disconnect(struct sc *sc);

size_t scard_transmit(struct sc *sc,
		const unsigned char *inbuf, size_t inlen,
		unsigned char *outbuf, size_t outlen);

#endif
