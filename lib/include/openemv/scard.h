#ifndef SCARD_H
#define SCARD_H

#include <stdbool.h>
#include <stddef.h>

struct sc;

struct sc *scard_init(void);
void scard_shutdown(struct sc *sc);

enum scard_error {
	SCARD_NO_ERROR = 0,
	SCARD_CARD,
	SCARD_MEMORY,
	SCARD_PARAMETER,
};
void scard_raise_error(struct sc *sc, int type);
bool scard_is_error(struct sc *sc);
const char *scard_error(struct sc *sc);

void scard_connect(struct sc *sc, unsigned idx);
void scard_disconnect(struct sc *sc);

size_t scard_transmit(struct sc *sc,
		const unsigned char *inbuf, size_t inlen,
		unsigned char *outbuf, size_t outlen);

enum scard_proto {
	SCARD_PROTO_INVALID,
	SCARD_PROTO_T0,
	SCARD_PROTO_T1,
};
int scard_getproto(struct sc *sc);

#endif
