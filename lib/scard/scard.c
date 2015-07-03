#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/scard.h"
#include "scard_backend.h"

struct sc *scard_init()
{
	return scard_pcsc_init();
}

void scard_shutdown(struct sc *sc)
{
	sc->shutdown(sc);
}

void scard_raise_error(struct sc *sc, int type)
{
	sc->error = type;
}

bool scard_is_error(struct sc *sc)
{
	return sc && (sc->error != SCARD_NO_ERROR);
}

const char *scard_error(struct sc *sc)
{
	switch (sc->error) {
	case SCARD_NO_ERROR:
		return "No error";
	case SCARD_CARD:
		return "Card error";
	case SCARD_MEMORY:
		return "Memory error";
	case SCARD_PARAMETER:
		return "Parameter error";
	}

	return "Unknown???";
}

void scard_connect(struct sc *sc, unsigned idx)
{
	return sc->connect(sc, idx);
}

void scard_disconnect(struct sc *sc)
{
	sc->disconnect(sc);
}

int scard_getproto(struct sc *sc)
{
	if (!sc)
		return SCARD_PROTO_INVALID;

	return sc->proto;
}

size_t scard_transmit(struct sc *sc,
		const unsigned char *inbuf, size_t inlen,
		unsigned char *outbuf, size_t outlen)
{
	return sc->transmit(sc, inbuf, inlen, outbuf, outlen);
}
