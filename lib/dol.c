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

#include "openemv/dol.h"
#include "openemv/tlv.h"

#include <stdlib.h>
#include <string.h>

static size_t dol_calculate_len(const struct tlv *tlv, size_t data_len)
{
	if (!tlv)
		return 0;

	const unsigned char *buf = tlv->value;
	size_t left = tlv->len;
	size_t count = 0;

	while (left) {
		struct tlv tlv;
		if (!tlv_parse_tl(&buf, &left, &tlv))
			return 0;

		count += tlv.len;

		/* Last tag can be of variable length */
		if (tlv.len == 0 && left == 0)
			count = data_len;
	}

	return count;
}

unsigned char *dol_process(const struct tlv *tlv, const struct tlvdb *tlvdb, size_t *len)
{
	if (!tlv) {
		*len = 0;
		return NULL;
	}

	const unsigned char *buf = tlv->value;
	size_t left = tlv->len;
	size_t res_len = dol_calculate_len(tlv, 0);
	unsigned char *res;
	size_t pos = 0;

	if (!res_len) {
		*len = 0;
		return NULL;
	}

	res = malloc(res_len);

	while (left) {
		struct tlv cur_tlv;
		if (!tlv_parse_tl(&buf, &left, &cur_tlv) || pos + cur_tlv.len > res_len) {
			free(res);
			return NULL;
		}

		const struct tlv *tag_tlv = tlvdb_get(tlvdb, cur_tlv.tag, NULL);
		if (!tag_tlv) {
			memset(res + pos, 0, cur_tlv.len);
		} else if (tag_tlv->len > cur_tlv.len) {
			memcpy(res + pos, tag_tlv->value, cur_tlv.len);
		} else {
			// FIXME: cn data should be padded with 0xFF !!!
			memcpy(res + pos, tag_tlv->value, tag_tlv->len);
			memset(res + pos + tag_tlv->len, 0, cur_tlv.len - tag_tlv->len);
		}
		pos += cur_tlv.len;
	}

	*len = pos;

	return res;
}

struct tlvdb *dol_parse(const struct tlv *tlv, const unsigned char *data, size_t data_len)
{
	if (!tlv)
		return NULL;

	const unsigned char *buf = tlv->value;
	size_t left = tlv->len;
	size_t res_len = dol_calculate_len(tlv, data_len);
	size_t pos = 0;
	struct tlvdb *db = NULL;

	if (res_len != data_len)
		return NULL;

	while (left) {
		struct tlv cur_tlv;
		if (!tlv_parse_tl(&buf, &left, &cur_tlv) || pos + cur_tlv.len > res_len) {
			tlvdb_free(db);
			return NULL;
		}

		/* Last tag can be of variable length */
		if (cur_tlv.len == 0 && left == 0)
			cur_tlv.len = res_len - pos;

		struct tlvdb *tag_db = tlvdb_fixed(cur_tlv.tag, cur_tlv.len, data + pos);
		if (!db)
			db = tag_db;
		else
			tlvdb_add(db, tag_db);

		pos += cur_tlv.len;
	}

	return db;
}
