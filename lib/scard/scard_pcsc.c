#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/scard.h"

#include <stdlib.h>
#include <string.h>
#include <winscard.h>
//#undef SCARD_AUTOALLOCATE

struct sc {
	SCARDCONTEXT hContext;
	SCARDHANDLE hCard;
	LONG rv;
	LPSTR rfunc;
	LPSTR mszReaders;
	LPCSCARD_IO_REQUEST pioSendPci;
	enum scard_proto wProto;
};

#define CHECK(sc, ret, func, ...) \
	do { \
		(sc)->rv = func(__VA_ARGS__); \
		if ((sc)->rv != SCARD_S_SUCCESS) { \
			(sc)->rfunc = #func; \
			return ret; \
		} \
	} while (0)

struct sc *scard_init(void)
{
	struct sc *sc = calloc(1, sizeof(*sc));
	DWORD dwReaders;

	if (!sc)
		return NULL;

	CHECK(sc, sc, SCardEstablishContext, SCARD_SCOPE_SYSTEM, NULL, NULL, &sc->hContext);

#ifdef SCARD_AUTOALLOCATE
	dwReaders = SCARD_AUTOALLOCATE;

	CHECK(sc, sc, SCardListReaders, sc->hContext, NULL, (LPSTR)&sc->mszReaders, &dwReaders);
#else
	CHECK(sc, sc, SCardListReaders, sc->hContext, NULL, NULL, &dwReaders);

	sc->mszReaders = calloc(dwReaders, sizeof(char));
	if (!sc->mszReaders) {
		scard_shutdown(sc);
		return NULL;
	}
	CHECK(sc, sc, SCardListReaders, sc->hContext, NULL, sc->mszReaders, &dwReaders);
#endif

	return sc;
}

void scard_shutdown(struct sc *sc)
{
	scard_disconnect(sc);

#ifdef SCARD_AUTOALLOCATE
	CHECK(sc, , SCardFreeMemory, sc->hContext, sc->mszReaders);
#else
	if (sc->mszReaders)
		free(sc->mszReaders);
#endif

	CHECK(sc, , SCardReleaseContext, sc->hContext);

	free(sc);
}

bool scard_is_error(struct sc *sc)
{
	return sc && (sc->rv != SCARD_S_SUCCESS);
}

#include "stdio.h"
const char *scard_error(struct sc *sc)
{
	printf("%s: %s\n", sc->rfunc, pcsc_stringify_error(sc->rv));
	return "\n"; // FIXME
}

static LONG _SCardInvalidProtocol(void)
{
	return SCARD_E_INVALID_VALUE;
}

static LONG _SCardGetReader(struct sc *sc, unsigned idx, LPSTR *pReader)
{
	LPSTR r = sc->mszReaders;

	while (idx && *r) {
		r += strlen(r) + 1;
		idx--;
	}

	if (!*r)
		return SCARD_E_UNKNOWN_READER;

	*pReader = r;

	return SCARD_S_SUCCESS;
}

void scard_connect(struct sc *sc, unsigned idx)
{
	DWORD dwActiveProtocol;
	LPSTR r;

	CHECK(sc, , _SCardGetReader, sc, idx, &r);

	CHECK(sc, , SCardConnect, sc->hContext, r, SCARD_SHARE_EXCLUSIVE,
		SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &sc->hCard, &dwActiveProtocol);

	switch(dwActiveProtocol)
	{
	case SCARD_PROTOCOL_T0:
		sc->pioSendPci = SCARD_PCI_T0;
		sc->wProto = SCARD_PROTO_T0;
		break;

	case SCARD_PROTOCOL_T1:
		sc->pioSendPci = SCARD_PCI_T1;
		sc->wProto = SCARD_PROTO_T1;
		break;
	default:
		sc->wProto = SCARD_PROTO_INVALID;
		SCardDisconnect(sc->hCard, SCARD_LEAVE_CARD);
		CHECK(sc, , _SCardInvalidProtocol);
	}
}

void scard_disconnect(struct sc *sc)
{
	if (sc->wProto != SCARD_PROTO_INVALID) {
		CHECK(sc, ,SCardDisconnect, sc->hCard, SCARD_RESET_CARD);
		sc->wProto = SCARD_PROTO_INVALID;
	}
}

size_t scard_transmit(struct sc *sc,
		const unsigned char *inbuf, size_t inlen,
		unsigned char *outbuf, size_t outlen)
{
	DWORD dwRecvLength = outlen;
	CHECK(sc, 0, SCardTransmit, sc->hCard, sc->pioSendPci,
			inbuf, inlen, NULL, outbuf, &dwRecvLength);

	return dwRecvLength;
}

void scard_raise_error(struct sc *sc, int type)
{
	switch (type) {
	case SCARD_NO_ERROR:
		sc->rv = SCARD_S_SUCCESS;
		break;
	case SCARD_CARD:
		sc->rv = SCARD_F_COMM_ERROR;
		break;
	case SCARD_MEMORY:
		sc->rv = SCARD_E_NO_MEMORY;
		break;
	case SCARD_PARAMETER:
		sc->rv = SCARD_E_INVALID_PARAMETER;
		break;
	default:
		sc->rv = SCARD_E_INVALID_PARAMETER;
		break;
	}
}

int scard_getproto(struct sc *sc)
{
	if (!sc)
		return SCARD_PROTO_INVALID;

	return sc->wProto;
}

#ifdef WIN32
static char *pcsc_stringify_error(LONG rv)
{

	static char out[20];
	sprintf_s(out, sizeof(out), "0x%08X", rv);

	return out;
}
#endif
