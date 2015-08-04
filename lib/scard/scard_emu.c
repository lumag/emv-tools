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
#include "openemv/emu_glue.h"

#include "scard_backend.h"

#include <stdlib.h>
#include <string.h>

struct sc_emu {
	struct sc sc;
	struct emu_card *card;
};

static void scard_emu_shutdown(struct sc *_sc)
{
	struct sc_emu *sc = container_of(_sc, struct sc_emu, sc);

	if (sc->card)
		emu_card_free(sc->card);
	free(sc);
}

static void scard_emu_connect(struct sc *_sc, unsigned idx)
{
	struct sc_emu *sc = container_of(_sc, struct sc_emu, sc);
	const char *fname;

	if (idx || sc->card)
		scard_raise_error(_sc, SCARD_PARAMETER);

	fname = openemv_config_get("scard.emu.file");
	if (!fname) {
		scard_raise_error(_sc, SCARD_CARD);
		return;
	}

	sc->card = emu_card_parse(fname);
	if (!sc->card) {
		scard_raise_error(_sc, SCARD_CARD);
		return;
	}

	_sc->proto = SCARD_PROTO_T1;
	_sc->error = SCARD_NO_ERROR;
}

static void scard_emu_disconnect(struct sc *_sc)
{
	struct sc_emu *sc = container_of(_sc, struct sc_emu, sc);

	_sc->proto = SCARD_PROTO_INVALID;
	_sc->error = SCARD_NO_ERROR;
	emu_card_free(sc->card);
	sc->card = NULL;
}

static size_t scard_emu_transmit(struct sc *_sc,
		const unsigned char *inbuf, size_t inlen,
		unsigned char *outbuf, size_t outlen)
{
	struct sc_emu *sc = container_of(_sc, struct sc_emu, sc);
	unsigned char cla, ins, p1, p2;
	size_t lc, le;
	unsigned short sw;
	const unsigned char *ret;
	size_t retlen;

	if (outlen < 2 || inlen < 4) {
		scard_raise_error(_sc, SCARD_PARAMETER);
		return 0;
	}

	if (!sc->card) {
		scard_raise_error(_sc, SCARD_CARD);
		return 0;
	}

	cla = inbuf[0];
	ins = inbuf[1];
	p1 = inbuf[2];
	p2 = inbuf[3];

	if (inlen == 5) {
		lc = 0;
		le = inbuf[4];
		if (!le)
			le = 256;
	} else {
		lc = inbuf[4];
		if (inlen == 5 + lc) {
			le = 0;
		} else if (inlen == 6 + lc) {
			le = inbuf[inlen - 1];
			if (!le)
				le = 256;
		} else {
			scard_raise_error(_sc, SCARD_CARD);
			return 0;
		}
	}

	if (le + 2 > outlen) {
		scard_raise_error(_sc, SCARD_CARD);
		return 0;
	}

	sw = emu_command(sc->card, cla, ins, p1, p2, lc, lc ? inbuf + 5 : NULL, &ret, &retlen);

	if (retlen > le) {
		ret = NULL;
		retlen = 0;
		sw = 0x6700;
	}

	memcpy(outbuf, ret, retlen);

	outbuf[retlen ++] = sw >> 8;
	outbuf[retlen ++] = sw & 0xff;

	return retlen;
}

struct sc *scard_emu_init(void)
{
	struct sc_emu *sc = calloc(1, sizeof(*sc));

	sc->sc.proto = SCARD_PROTO_INVALID;
	sc->sc.shutdown = scard_emu_shutdown;
	sc->sc.connect = scard_emu_connect;
	sc->sc.disconnect = scard_emu_disconnect;
	sc->sc.transmit = scard_emu_transmit;

	return &sc->sc;
}
