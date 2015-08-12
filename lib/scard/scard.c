/*
 * libopenemv - a library to work with EMV family of smart cards
 * Copyright (C) 2015 Dmitry Eremin-Solenikov
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

#include "openemv/config.h"
#include "openemv/scard.h"
#include "scard_backend.h"

#include <string.h>

struct sc *scard_init(const char *driver)
{
	if (!driver)
		driver = openemv_config_get("scard.driver");

	if (!driver)
		return NULL;
	else if (!strcmp(driver, "pcsc"))
		return scard_pcsc_init();
	else if (!strcmp(driver, "emu"))
		return scard_emu_init();
	else if (!strcmp(driver, "apduio_t0"))
		return scard_apduio_t0_init();
	else if (!strcmp(driver, "apduio_t1"))
		return scard_apduio_t1_init();
	else
		return NULL;
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
