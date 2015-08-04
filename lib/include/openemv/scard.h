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

#ifndef SCARD_H
#define SCARD_H

#include <stdbool.h>
#include <stddef.h>

struct sc;

struct sc *scard_init(const char *driver);
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
