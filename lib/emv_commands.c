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
#include <search.h>

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

struct tlvdb *emv_select(struct sc *sc, const struct tlv *aid_tlv)
{
	unsigned short sw;
	size_t outlen;
	unsigned char *outbuf;
	struct tlvdb *t = NULL;

	if (!aid_tlv)
		return NULL;

	outbuf = sc_command(sc, 0x00, 0xa4, 0x04, 0x00, aid_tlv->len, aid_tlv->value, &sw, &outlen);
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

struct sda_list {
	struct sda_list *forw;
	struct sda_list *back;
	unsigned char *buf;
	size_t offset;
	size_t len;
};

static struct sda_list *sda_list_new(unsigned char *buf, size_t offset, size_t len)
{
	struct sda_list *elem = malloc(sizeof(*elem));

	if (!elem)
		return NULL;

	elem->buf = buf;
	elem->offset = offset;
	elem->len = len;

	return elem;
}

static void sda_list_free(struct sda_list *head)
{
	while (head->forw != head) {
		struct sda_list *elem = head->forw;

		remque(elem);
		free(elem->buf);
		free(elem);
	}
}

struct tlv *emv_read_records(struct sc *sc, struct tlvdb *db)
{
	const struct tlv *afl = tlvdb_get(db, 0x94, NULL);
	if (!afl)
		return NULL;

	struct sda_list sda_list_head = {
		.forw = &sda_list_head,
		.back = &sda_list_head,
	};
	int i;
	for (i = 0; i < afl->len; i += 4) {
		unsigned char p2 = afl->value[i + 0];
		unsigned char first = afl->value[i + 1];
		unsigned char last = afl->value[i + 2];
		unsigned char sdarec = afl->value[i + 3];
		unsigned char sfi = p2 >> 3;

		if (sfi == 0 || sfi == 31 || first == 0 || first > last)
			goto err;

		for (; first <= last; first ++) {
			unsigned short sw;
			size_t outlen;
			unsigned char *outbuf;

			outbuf = emv_read_record(sc, sfi, first, &sw, &outlen);
			if (!outbuf)
				goto err;

			if (sw != 0x9000) {
				free(outbuf);
				goto err;
			}

			struct tlvdb *t = tlvdb_parse(outbuf, outlen);
			if (!t) {
				free(outbuf);
				goto err;
			}

			if (sdarec) {
				struct sda_list *elem = NULL;

				if (sfi < 11) {
					const unsigned char *tmp = outbuf;
					size_t tmplen = outlen;
					struct tlv e;

					/*  We can be pretty sure here -- it was checked after parsing the record */
					if (tlv_parse_tl(&tmp, &tmplen, &e))
						elem = sda_list_new(outbuf, outlen - tmplen, tmplen);
				} else
					elem = sda_list_new(outbuf, 0, outlen);

				if (!elem) {
					free(outbuf);
					goto err;
				}

				insque(elem, sda_list_head.back);
				sdarec--;
			} else
				free(outbuf);

			tlvdb_add(db, t);
		}
	}

	const struct tlv *sdatl_tlv = tlvdb_get(db, 0x9f4a, NULL);
	if (sdatl_tlv) {
		const struct tlv *aip_tlv = tlvdb_get(db, 0x82, NULL);
		if (sdatl_tlv->len == 1 && sdatl_tlv->value[0] == 0x82 && aip_tlv) {
			unsigned char *buf = malloc(aip_tlv->len);
			if (!buf)
				goto err;

			memcpy(buf, aip_tlv->value, aip_tlv->len);

			struct sda_list *elem = sda_list_new(buf, 0, aip_tlv->len);
			if (!elem) {
				free(buf);
				goto err;
			}

			insque(elem, sda_list_head.back);
		} else
			goto err;
	}

	size_t sda_len = 0;
	struct sda_list *elem;

	for (elem = sda_list_head.forw; elem != &sda_list_head; elem = elem->forw)
		sda_len += elem->len;

	struct tlv *sda_tlv = malloc(sizeof(*sda_tlv) + sda_len);
	if (!sda_tlv)
		goto err;

	unsigned char *sda_data = (unsigned char *)(sda_tlv + 1);
	sda_tlv->tag = 0;
	sda_tlv->len = sda_len;
	sda_tlv->value = sda_data;

	for (elem = sda_list_head.forw; elem != &sda_list_head; elem = elem->forw) {
		memcpy(sda_data, elem->buf + elem->offset, elem->len);
		sda_data += elem->len;
	}

	sda_list_free(&sda_list_head);

	return sda_tlv;
err:

	sda_list_free(&sda_list_head);

	return NULL;
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

static const struct tlv default_pdol_data_tlv = {
	.tag = 0x83,
	.len = 0,
	.value = NULL
};

struct tlvdb *emv_gpo(struct sc *sc, const struct tlv *pdol_data_tlv)
{
	if (!pdol_data_tlv)
		pdol_data_tlv = &default_pdol_data_tlv;

	size_t pdol_data_tlv_data_len;
	unsigned char *pdol_data_tlv_data = tlv_encode(pdol_data_tlv, &pdol_data_tlv_data_len);
	if (!pdol_data_tlv_data)
		return NULL;

	unsigned short sw;
	size_t outlen;
	unsigned char *outbuf = sc_command(sc, 0x80, 0xa8, 0x00, 0x00, pdol_data_tlv_data_len, pdol_data_tlv_data, &sw, &outlen);
	if (!outbuf) {
		free(pdol_data_tlv_data);

		return NULL;
	}

	if (sw != 0x9000) {
		free(outbuf);
		free(pdol_data_tlv_data);

		return NULL;
	}

	struct tlvdb *t = emv_command_handle_format(outbuf, outlen, &gpo_dol_tlv);
	free(outbuf);
	free(pdol_data_tlv_data);

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

struct tlvdb *emv_generate_ac(struct sc *sc, unsigned char type, const struct tlv *crm_tlv)
{
	if (!crm_tlv)
		return NULL;

	unsigned short sw;
	size_t outlen;
	unsigned char *outbuf = sc_command(sc, 0x80, 0xae, type, 0x00, crm_tlv->len, crm_tlv->value, &sw, &outlen);
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

struct tlvdb *emv_internal_authenticate(struct sc *sc, const struct tlv *data_tlv)
{
	if (!data_tlv)
		return NULL;

	unsigned short sw;
	size_t outlen;
	unsigned char *outbuf = sc_command(sc, 0x00, 0x88, 0x00, 0x00, data_tlv->len, data_tlv->value, &sw, &outlen);
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
