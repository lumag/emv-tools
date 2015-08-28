/*
 * emv-tools - a set of tools to work with EMV family of smart cards
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
#include "openemv/sc_helpers.h"
#include "openemv/tlv.h"
#include "openemv/emv_tags.h"
#include "openemv/dol.h"
#include "openemv/dump.h"
#include "openemv/pinpad.h"
#include "openemv/emv_commands.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool print_cb(void *data, const struct tlv *tlv)
{
	if (tlv_is_constructed(tlv)) return true;
	emv_tag_dump(tlv, stdout);
	dump_buffer(tlv->value, tlv->len, stdout);

	return true;
}

static bool verify(struct sc *sc, uint8_t pb_type, const unsigned char *pb, size_t pb_len)
{
	unsigned short sw;

	sc_command(sc, 0x00, 0x20, 0x00, pb_type, pb_len, pb, &sw, NULL);

	printf("PIN VERIFY, type %02hhx, SW %04hx\n", pb_type, sw);

	return sw == 0x9000 ? true : false;
}

static bool verify_offline_clear(struct tlvdb *db, struct sc *sc)
{
	size_t pb_len;
	unsigned char *pb;
	bool ret;

	pb = pinpad_enter(&pb_len);
	if (!pb)
		return false;

	ret = verify(sc, 0x80, pb, pb_len);
	free(pb);

	return ret;
}

unsigned char ipb_dol_value[] = {
	0x5f, 0x34, 0x01, /* PSN */
	0x9f, 0x27, 0x01, /* CID */
	0x9f, 0x36, 0x02, /* ATC */
	0x9f, 0x26, 0x08, /* AC */
	0x9f, 0x10, 0x00, /* IAD */
};

const struct tlv ipb_dol = {0x0, sizeof(ipb_dol_value), ipb_dol_value};

static void build_cap(struct tlvdb *db)
{
	const struct tlv *ipb = tlvdb_get(db, 0x9f56, NULL);

	ipb_dol_value[sizeof(ipb_dol_value) - 1] = ipb->len - (1 + 1 + 2 + 8);

	size_t ipb_data_len;
	unsigned char *ipb_data = dol_process(&ipb_dol, db, &ipb_data_len);
	if (!ipb_data)
		return;

	dump_buffer(ipb_data, ipb_data_len, stdout);
	dump_buffer(ipb->value, ipb->len, stdout);
	if (ipb_data_len < ipb->len) {
		free(ipb_data);
		return;
	}

	unsigned char buf[ipb->len];
	int i, j, k = 0;
	unsigned char c = 0;
	for (i = ipb->len; i > 0; i--) {
		for (j = 0; j < 8; j++) {
			if ((ipb->value[i-1] & (1 << j)) == 0)
				continue;

			c |= ((ipb_data[i-1] >> j) & 1) << (k % 8);
			k++;

			if (k % 8 != 0)
				continue;

			buf[k / 8 - 1] = c;
			c = 0;
		}
	}
	free(ipb_data);

	if (k % 8 != 0) {
		k += 8 - (k % 8);
		buf[k / 8 - 1] = c;
	}

	k /= 8;

	unsigned long data = 0;
	for (i = 0; i < k; i++)
		data |= ((unsigned long) buf[i]) << (8 * i);
	dump_buffer(buf, k, stdout);

	fprintf(stdout, "CAP data: %lu\n", data);
}

const struct {
	size_t name_len;
	const unsigned char name[16];
} apps[] = {
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x04, 0x80, 0x02, }},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x03, 0x80, 0x02, }},
	{ 0, {}},
};

int main(void)
{
	int i;
	struct sc *sc;

	sc = scard_init(NULL);
	if (!sc) {
		printf("Cannot init scard\n");
		return 1;
	}

	scard_connect(sc, 0);
	if (scard_is_error(sc)) {
		printf("%s\n", scard_error(sc));
		return 1;
	}

	struct tlvdb *s;
	struct tlvdb *t;
	for (i = 0, s = NULL; apps[i].name_len != 0; i++) {
		s = emv_select(sc, apps[i].name, apps[i].name_len);
		if (s)
			break;
	}
	if (!s)
		return 1;

	size_t pdol_data_len;
	unsigned char *pdol_data = dol_process(tlvdb_get(s, 0x9f38, NULL), s, &pdol_data_len);
	struct tlv pdol_data_tlv = { .tag = 0x83, .len = pdol_data_len, .value = pdol_data };

	size_t pdol_data_tlv_data_len;
	unsigned char *pdol_data_tlv_data = tlv_encode(&pdol_data_tlv, &pdol_data_tlv_data_len);
	free(pdol_data);
	if (!pdol_data_tlv_data)
		return 1;

	t = emv_gpo(sc, pdol_data_tlv_data, pdol_data_tlv_data_len);
	free(pdol_data_tlv_data);
	if (!t)
		return 1;
	tlvdb_add(s, t);

	unsigned char *sda_data = NULL;
	size_t sda_len = 0;
	bool ok = emv_read_records(sc, s, &sda_data, &sda_len);
	if (!ok)
		return 1;

	/* Only PTC read should happen before VERIFY */
	tlvdb_add(s, emv_get_data(sc, 0x9f17));

	verify_offline_clear(s, sc);

#define TAG(tag, len, value...) tlvdb_add(s, tlvdb_fixed(tag, len, (unsigned char[]){value}))
//	TAG(0x9f02, 6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
//	TAG(0x9f1a, 2, 0x06, 0x43);
	TAG(0x95, 5, 0x80, 0x00, 0x00, 0x00, 0x00);
//	TAG(0x5f2a, 2, 0x06, 0x43);
//	TAG(0x9a, 3, 0x14, 0x09, 0x25);
//	TAG(0x9c, 1, 0x50);
//	TAG(0x9f37, 4, 0x12, 0x34, 0x57, 0x79);
	TAG(0x9f35, 1, 0x34);
	TAG(0x9f34, 3, 0x01, 0x00, 0x02);
#undef TAG

	/* Generate ARQC */
	size_t crm_data_len;
	unsigned char *crm_data;
	crm_data = dol_process(tlvdb_get(s, 0x8c, NULL), s, &crm_data_len);
	t = emv_generate_ac(sc, 0x80, crm_data, crm_data_len);
	free(crm_data);
	tlvdb_add(s, t);

	build_cap(s);

#define TAG(tag, len, value...) tlvdb_add(s, tlvdb_fixed(tag, len, (unsigned char[]){value}))
	TAG(0x8a, 2, 'Z', '3');
#undef TAG

	/* Generate AC asking for AAC */
	crm_data = dol_process(tlvdb_get(s, 0x8d, NULL), s, &crm_data_len);
	t = emv_generate_ac(sc, 0x00, crm_data, crm_data_len);
	free(crm_data);
	tlvdb_add(s, t);

	tlvdb_visit(s, print_cb, NULL);
	tlvdb_free(s);

	scard_disconnect(sc);
	if (scard_is_error(sc)) {
		printf("%s\n", scard_error(sc));
		return 1;
	}
	scard_shutdown(sc);

	return 0;
}
