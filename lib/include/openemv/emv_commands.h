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

#ifndef EMV_COMMANDS_H
#define EMV_COMMANDS_H

#include "openemv/scard.h"

#include <stdbool.h>
#include <stddef.h>

unsigned char *emv_get_challenge(struct sc *sc);
struct tlvdb *emv_select(struct sc *sc, const unsigned char *aid, size_t aid_len);
unsigned char *emv_read_record(struct sc *sc, unsigned char sfi, unsigned char record, unsigned short *psw, size_t *plen);
bool emv_read_records(struct sc *sc, struct tlvdb *db, unsigned char **pdata, size_t *plen);
struct tlvdb *emv_gpo(struct sc *sc, const unsigned char *data, size_t len);
struct tlvdb *emv_generate_ac(struct sc *sc, unsigned char type, const unsigned char *data, size_t len);
struct tlvdb *emv_internal_authenticate(struct sc *sc, const unsigned char *data, size_t len);
struct tlvdb *emv_get_data(struct sc *sc, tlv_tag_t tag);

#endif
