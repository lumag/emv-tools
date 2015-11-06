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

#ifndef EMV_PKI_PRIV_H
#define EMV_PKI_PRIV_H

#include "openemv/crypto.h"
#include "openemv/emv_pk.h"

struct emv_pk *emv_pki_make_ca(const struct crypto_pk *cp,
		const unsigned char *rid, unsigned char index,
		unsigned int expire, enum crypto_algo_hash hash_algo);

#endif
