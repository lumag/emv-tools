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

#ifndef SCARD_BACKEND_H
#define SCARD_BACKEND_H

#include "openemv/scard.h"

struct sc {
	void (*shutdown)(struct sc *sc);
	void (*connect)(struct sc *sc, unsigned idx);
	void (*disconnect)(struct sc *sc);
	size_t (*transmit)(struct sc *sc,
		const unsigned char *inbuf, size_t inlen,
		unsigned char *outbuf, size_t outlen);

	enum scard_proto proto;
	enum scard_error error;
};

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})

#ifdef ENABLE_SCARD_PCSC
struct sc *scard_pcsc_init(void);
#else
static inline struct sc *scard_pcsc_init(void)
{
	return NULL;
}
#endif

#ifdef ENABLE_SCARD_EMU
struct sc *scard_emu_init(void);
#else
static inline struct sc *scard_emu_init(void)
{
	return NULL;
}
#endif

#ifdef ENABLE_SCARD_APDUIO
struct sc *scard_apduio_t0_init(void);
struct sc *scard_apduio_t1_init(void);
#else
static inline struct sc *scard_apduio_t0_init(void)
{
	return NULL;
}

static inline struct sc *scard_apduio_t1_init(void)
{
	return NULL;
}
#endif

#endif
