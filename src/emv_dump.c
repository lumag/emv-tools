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
#include "openemv/emv_commands.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool print_cb(void *data, const struct tlv *tlv)
{
//	if (tlv_is_constructed(tlv)) return true;
	emv_tag_dump(tlv, stdout);
	dump_buffer(tlv->value, tlv->len, stdout);

	return true;
}

const struct {
	size_t name_len;
	const unsigned char name[16];
} apps[] = {
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, }},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10, }},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, }},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x04, 0x30, 0x60, }},
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

	free(sda_data);

	/* Generate AC asking for AAC */
	size_t crm_data_len;
	unsigned char *crm_data = dol_process(tlvdb_get(s, 0x8c, NULL), s, &crm_data_len);
	t = emv_generate_ac(sc, 0x00, crm_data, crm_data_len);
	free(crm_data);
	tlvdb_add(s, t);

	tlvdb_add(s, emv_get_data(sc, 0x9f36));
	tlvdb_add(s, emv_get_data(sc, 0x9f13));
	tlvdb_add(s, emv_get_data(sc, 0x9f17));
	tlvdb_add(s, emv_get_data(sc, 0x9f4f));

	tlvdb_visit(s, print_cb, NULL);

	const struct tlv *logent_tlv = tlvdb_get(s, 0x9f4d, NULL);
	const struct tlv *logent_dol = tlvdb_get(s, 0x9f4f, NULL);
	if (logent_tlv && logent_tlv->len == 2 && logent_dol) {
		for (i = 1; i <= logent_tlv->value[1]; i++) {
			unsigned short sw;
			size_t log_len;
			unsigned char *log = emv_read_record(sc, logent_tlv->value[0], i, &sw, &log_len);
			if (!log)
				continue;

			if (sw == 0x9000) {
				printf("Log #%d\n", i);
				struct tlvdb *log_db = dol_parse(logent_dol, log, log_len);
				tlvdb_visit(log_db, print_cb, NULL);
				tlvdb_free(log_db);
			}
			free(log);
		}
	}

	tlvdb_free(s);

	scard_disconnect(sc);
	if (scard_is_error(sc)) {
		printf("%s\n", scard_error(sc));
		return 1;
	}
	scard_shutdown(sc);

	return 0;
}
