/*
 * libopenemv - a library to work with EMV family of smart cards
 * Copyright (C) 2012, 2015 Dmitry Eremin-Solenikov
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/scard.h"

#include "scard_backend.h"

#include <stdlib.h>
#include <string.h>
#include <winscard.h>
//#undef SCARD_AUTOALLOCATE

struct sc_pcsc {
	struct sc sc;
	SCARDCONTEXT hContext;
	SCARDHANDLE hCard;
	LONG rv;
	LPSTR rfunc;
	LPSTR mszReaders;
	LPCSCARD_IO_REQUEST pioSendPci;
};

static int scard_pcsc_get_error(LONG rv)
{
	switch (rv) {
	case SCARD_S_SUCCESS:
		return SCARD_NO_ERROR;
	case SCARD_E_NO_MEMORY:
		return SCARD_MEMORY;
	case SCARD_E_INVALID_PARAMETER:
	case SCARD_E_INVALID_VALUE:
		return SCARD_PARAMETER;
	default:
		return SCARD_CARD;
	}
}

#define CHECK(sc, ret, func, ...) \
	do { \
		(sc)->sc.error = scard_pcsc_get_error(func(__VA_ARGS__)); \
		if ((sc)->sc.error != SCARD_S_SUCCESS) { \
			(sc)->rfunc = #func; \
			return ret; \
		} \
	} while (0)

static void scard_pcsc_shutdown(struct sc *_sc)
{
	struct sc_pcsc *sc = container_of(_sc, struct sc_pcsc, sc);

	scard_disconnect(_sc);

#ifdef SCARD_AUTOALLOCATE
	CHECK(sc, , SCardFreeMemory, sc->hContext, sc->mszReaders);
#else
	if (sc->mszReaders)
		free(sc->mszReaders);
#endif

	CHECK(sc, , SCardReleaseContext, sc->hContext);

	free(sc);
}

static LONG _SCardInvalidProtocol(void)
{
	return SCARD_E_INVALID_VALUE;
}

static LONG _SCardGetReader(struct sc_pcsc *sc, unsigned idx, LPSTR *pReader)
{
	LPSTR r = sc->mszReaders;

	if (!r)
		return SCARD_E_UNKNOWN_READER;

	while (idx && *r) {
		r += strlen(r) + 1;
		idx--;
	}

	if (!*r)
		return SCARD_E_UNKNOWN_READER;

	*pReader = r;

	return SCARD_S_SUCCESS;
}

static void scard_pcsc_connect(struct sc *_sc, unsigned idx)
{
	struct sc_pcsc *sc = container_of(_sc, struct sc_pcsc, sc);

	DWORD dwActiveProtocol;
	LPSTR r;

	CHECK(sc, , _SCardGetReader, sc, idx, &r);

	CHECK(sc, , SCardConnect, sc->hContext, r, SCARD_SHARE_EXCLUSIVE,
		SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &sc->hCard, &dwActiveProtocol);

	switch(dwActiveProtocol)
	{
	case SCARD_PROTOCOL_T0:
		sc->pioSendPci = SCARD_PCI_T0;
		_sc->proto = SCARD_PROTO_T0;
		break;

	case SCARD_PROTOCOL_T1:
		sc->pioSendPci = SCARD_PCI_T1;
		_sc->proto = SCARD_PROTO_T1;
		break;
	default:
		_sc->proto = SCARD_PROTO_INVALID;
		SCardDisconnect(sc->hCard, SCARD_LEAVE_CARD);
		CHECK(sc, , _SCardInvalidProtocol);
	}
}

static void scard_pcsc_disconnect(struct sc *_sc)
{
	struct sc_pcsc *sc = container_of(_sc, struct sc_pcsc, sc);

	if (_sc->proto != SCARD_PROTO_INVALID) {
		CHECK(sc, ,SCardDisconnect, sc->hCard, SCARD_RESET_CARD);
		_sc->proto = SCARD_PROTO_INVALID;
	}
}

static size_t scard_pcsc_transmit(struct sc *_sc,
		const unsigned char *inbuf, size_t inlen,
		unsigned char *outbuf, size_t outlen)
{
	struct sc_pcsc *sc = container_of(_sc, struct sc_pcsc, sc);

	DWORD dwRecvLength = outlen;
	CHECK(sc, 0, SCardTransmit, sc->hCard, sc->pioSendPci,
			inbuf, inlen, NULL, outbuf, &dwRecvLength);

	return dwRecvLength;
}

struct sc *scard_pcsc_init(void)
{
	struct sc_pcsc *sc = calloc(1, sizeof(*sc));
	DWORD dwReaders;

	if (!sc)
		return NULL;

	sc->sc.shutdown = scard_pcsc_shutdown;
	sc->sc.connect = scard_pcsc_connect;
	sc->sc.disconnect = scard_pcsc_disconnect;
	sc->sc.transmit = scard_pcsc_transmit;

	CHECK(sc, &sc->sc, SCardEstablishContext, SCARD_SCOPE_SYSTEM, NULL, NULL, &sc->hContext);

#ifdef SCARD_AUTOALLOCATE
	dwReaders = SCARD_AUTOALLOCATE;

	CHECK(sc, &sc->sc, SCardListReaders, sc->hContext, NULL, (LPSTR)&sc->mszReaders, &dwReaders);
#else
	CHECK(sc, &sc->sc, SCardListReaders, sc->hContext, NULL, NULL, &dwReaders);

	sc->mszReaders = calloc(dwReaders, sizeof(char));
	if (!sc->mszReaders) {
		scard_pcsc_shutdown(&sc->sc);
		return NULL;
	}
	CHECK(sc, &sc->sc, SCardListReaders, sc->hContext, NULL, sc->mszReaders, &dwReaders);
#endif

	return &sc->sc;
}
