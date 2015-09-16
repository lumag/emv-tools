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

#include "openemv/scard.h"
#include "openemv/sc_helpers.h"
#include "openemv/tlv.h"
#include "openemv/dol.h"
#include "openemv/emv_commands.h"

#include <stdlib.h>
#include <string.h>

unsigned char *emv_get_challenge(struct sc *sc)
{
	unsigned short sw;
	size_t outlen;
	unsigned char *outbuf = sc_command(sc, 0x00, 0x84, 0x00, 0x00, 0, NULL, &sw, &outlen);

	if (sw == 0x9000 && outbuf && outlen == 8)
		return outbuf;

	free(outbuf);

	return NULL;
}

struct tlvdb *emv_select(struct sc *sc, const unsigned char *aid, size_t aid_len)
{
	unsigned short sw;
	size_t outlen;
	unsigned char *outbuf;
	struct tlvdb *t = NULL;

	outbuf = sc_command(sc, 0x00, 0xa4, 0x04, 0x00, aid_len, aid, &sw, &outlen);
	if (!outbuf)
		return NULL;

	if (sw != 0x9000) {
		free(outbuf);

		return NULL;
	}

	t = tlvdb_parse(outbuf, outlen);
	free(outbuf);

	return t;
}

unsigned char *emv_read_record(struct sc *sc, unsigned char sfi, unsigned char record, unsigned short *psw, size_t *plen)
{
	return sc_command(sc, 0x00, 0xb2, record, (sfi << 3) | 0x04, 0, NULL, psw, plen);
}

bool emv_read_records(struct sc *sc, struct tlvdb *db, unsigned char **pdata, size_t *plen)
{
	*pdata = NULL;
	*plen = 0;

	const struct tlv *afl = tlvdb_get(db, 0x94, NULL);
	if (!afl)
		return 1;

	unsigned char *sda_data = NULL;
	size_t sda_len = 0;

	int i;
	for (i = 0; i < afl->len; i += 4) {
		unsigned char p2 = afl->value[i + 0];
		unsigned char first = afl->value[i + 1];
		unsigned char last = afl->value[i + 2];
		unsigned char sdarec = afl->value[i + 3];
		unsigned char sfi = p2 >> 3;

		if (sfi == 0 || sfi == 31 || first == 0 || first > last)
			return false;

		for (; first <= last; first ++) {
			unsigned short sw;
			size_t outlen;
			unsigned char *outbuf;
			struct tlvdb *t;

			outbuf = emv_read_record(sc, sfi, first, &sw, &outlen);
			if (!outbuf)
				return false;

			if (sw == 0x9000) {
				t = tlvdb_parse(outbuf, outlen);
				if (!t)
					return false;
			} else
				return false;

			if (sdarec) {
				const unsigned char *data;
				size_t data_len;

				if (sfi < 11) {
					const struct tlv *e = tlvdb_get(t, 0x70, NULL);
					if (!e)
						return false;

					data = e->value;
					data_len = e->len;
				} else {
					data = outbuf;
					data_len = outlen;
				}

				sda_data = realloc(sda_data, sda_len + data_len);
				memcpy(sda_data + sda_len, data, data_len);
				sda_len += data_len;
				sdarec --;
			}

			free(outbuf);
			tlvdb_add(db, t);
		}
	}

	const struct tlv *sdatl_tlv = tlvdb_get(db, 0x9f4a, NULL);
	if (sdatl_tlv) {
		const struct tlv *aip_tlv = tlvdb_get(db, 0x82, NULL);
		if (sdatl_tlv->len == 1 && sdatl_tlv->value[0] == 0x82 && aip_tlv) {
			sda_data = realloc(sda_data, sda_len + aip_tlv->len);
			memcpy(sda_data + sda_len, aip_tlv->value, aip_tlv->len);
			sda_len += aip_tlv->len;
		} else {
			/* Error!! */
			free(sda_data);
			sda_data = NULL;
			sda_len = 0;
		}
	}

	*pdata = sda_data;
	*plen = sda_len;

	return true;
}

static struct tlvdb *emv_command_handle_format(const unsigned char *buf, size_t len, const struct tlv *dol)
{
	if (buf[0] != 0x80)
		return tlvdb_parse(buf, len);

	size_t left = len;
	const unsigned char *ptr = buf;
	struct tlv e;

	if (!tlv_parse_tl(&ptr, &left, &e) || e.len != left)
		return NULL;

	return dol_parse(dol, ptr, left);
}

static const unsigned char gpo_dol_value[] = {
	0x82, 0x02, /* AIP */
	0x94, 0x00, /* AFL */
};
static const struct tlv gpo_dol_tlv = {
	.len = sizeof(gpo_dol_value),
	.value = gpo_dol_value,
};

struct tlvdb *emv_gpo(struct sc *sc, const unsigned char *data, size_t len)
{
	unsigned short sw;
	size_t outlen;
	unsigned char *outbuf = sc_command(sc, 0x80, 0xa8, 0x00, 0x00, len, data, &sw, &outlen);
	if (!outbuf)
		return NULL;

	if (sw != 0x9000) {
		free(outbuf);

		return NULL;
	}

	struct tlvdb *t = emv_command_handle_format(outbuf, outlen, &gpo_dol_tlv);
	free(outbuf);

	return t;
}

static const unsigned char ac_dol_value[] = {
	0x9f, 0x27, 0x01, /* CID */
	0x9f, 0x36, 0x02, /* ATC */
	0x9f, 0x26, 0x08, /* AC */
	0x9f, 0x10, 0x00, /* IAD */
};
static const struct tlv ac_dol_tlv = {
	.len = sizeof(ac_dol_value),
	.value = ac_dol_value,
};

struct tlvdb *emv_generate_ac(struct sc *sc, unsigned char type, const unsigned char *data, size_t len)
{
	unsigned short sw;
	size_t outlen;
	unsigned char *outbuf = sc_command(sc, 0x80, 0xae, type, 0x00, len, data, &sw, &outlen);
	if (!outbuf)
		return NULL;

	if (sw != 0x9000) {
		free(outbuf);

		return NULL;
	}

	struct tlvdb *t = emv_command_handle_format(outbuf, outlen, &ac_dol_tlv);
	free(outbuf);

	return t;
}

static const unsigned char ia_dol_value[] = {
	0x9f, 0x4b, 0x00, /* SDAD */
};
static const struct tlv ia_dol_tlv = {
	.len = sizeof(ia_dol_value),
	.value = ia_dol_value,
};

struct tlvdb *emv_internal_authenticate(struct sc *sc, const unsigned char *data, size_t len)
{
	unsigned short sw;
	size_t outlen;
	unsigned char *outbuf = sc_command(sc, 0x00, 0x88, 0x00, 0x00, len, data, &sw, &outlen);
	if (!outbuf)
		return NULL;

	if (sw != 0x9000) {
		free(outbuf);

		return NULL;
	}

	struct tlvdb *t = emv_command_handle_format(outbuf, outlen, &ia_dol_tlv);
	free(outbuf);

	return t;
}

struct tlvdb *emv_get_data(struct sc *sc, tlv_tag_t tag)
{
	unsigned short sw;
	size_t outlen;
	unsigned char *outbuf;
	struct tlvdb *t = NULL;

	outbuf = sc_command(sc, 0x80, 0xca, tag >> 8, tag & 0xff, 0, NULL, &sw, &outlen);
	if (!outbuf)
		return NULL;

	if (sw != 0x9000) {
		free(outbuf);

		return NULL;
	}

	t = tlvdb_parse(outbuf, outlen);
	free(outbuf);

	return t;
}
