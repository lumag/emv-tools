/*
 * emv-tools - a set of tools to work with EMV family of smart cards
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
#include "openemv/dump.h"
#include "openemv/emu_ast.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const struct {
	size_t name_len;
	const unsigned char name[16];
} apps[] = {
	{14, {0x31, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31}},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, }},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10, }},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x03, 0x80, 0x02, }},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, }},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x04, 0x30, 0x60, }},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x04, 0x80, 0x02, }},
	{ 0, {}},
};

const tlv_tag_t card_data[] = {
	0x9f13,
	0x9f17,
	0x9f36,
	0x9f4f,
	0,
};

static struct emu_df *read_df(FILE *f, struct sc *sc, const unsigned char *name, size_t name_len)
{
	struct emu_df *df;
	int i, j;
	struct tlvdb *s;
	unsigned short sw;
	size_t outlen;
	unsigned char *outbuf;
	struct tlv pdol_data_tlv;
	size_t pdol_data_len;
	unsigned char *pdol_data;

	outbuf = sc_command(sc, 0x00, 0xa4, 0x04, 0x00, name_len, name, &sw, &outlen);
	if (sw != 0x9000)
		return NULL;

	s = tlvdb_parse(outbuf, outlen);
	if (!s)
		return NULL;

	df = emu_df_new();

	pdol_data_tlv.tag = 0x83;
	pdol_data_tlv.value = dol_process(tlvdb_get(s, 0x9f38, NULL), s, &pdol_data_tlv.len);
	pdol_data = tlv_encode(&pdol_data_tlv, &pdol_data_len);
	if (!pdol_data)
		return NULL;
	free((unsigned char *)pdol_data_tlv.value);

	tlvdb_free(s);

	emu_df_append(df, emu_property_new("name", emu_value_new_buf(name, name_len)));

	emu_df_append(df, emu_property_new("fci", emu_value_new_buf(outbuf, outlen)));
	free(outbuf);

	outbuf = sc_command(sc, 0x80, 0xa8, 0x00, 0x00, pdol_data_len, pdol_data, &sw, &outlen);
	free(pdol_data);
	if (sw == 0x9000) {
		emu_df_append(df, emu_property_new("gpo", emu_value_new_buf(outbuf, outlen)));
		free(outbuf);
	}

	for (i = 1; i < 31; i++) {
		int last = 0;
		struct emu_value *value = NULL;
		char buf[7];

		snprintf(buf, sizeof(buf), "sfi%d", i);

		for (j = 1; j < 256; j++) {
			outbuf = sc_command(sc, 0x00, 0xb2, j, (i << 3) | 4, 0, NULL, &sw, &outlen);
			if (sw == 0x6985)
				continue;
			else if (sw != 0x9000)
				break;

			for (; last < j - 1; last++)
				value = emu_value_append(value, "");

			value = emu_value_append_buf(value, outbuf, outlen);
			last ++;
			free(outbuf);
		}
		if (value)
			emu_df_append(df, emu_property_new(buf, value));
	}

	for (i = 0; card_data[i]; i++) {
		char buf[10];
		tlv_tag_t tag = card_data[i];
		outbuf = sc_command(sc, 0x80, 0xca, tag >> 8, tag & 0xff, 0, NULL, &sw, &outlen);
		if (sw != 0x9000)
			continue;

		snprintf(buf, sizeof(buf), "data%x", tag);
		emu_df_append(df, emu_property_new(buf, emu_value_new_buf(outbuf, outlen)));
		free(outbuf);
	}

	return df;
}

int main(int argc, char **argv)
{
	FILE *f;
	int i;
	struct sc *sc;
	struct emu_fs *fs;

	if (argc == 1 || !strcmp(argv[1], "-"))
		f = stdout;
	else
		f = fopen(argv[1], "w");
	if (!f) {
		perror("fopen");
		return 1;
	}

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

	fs = emu_fs_new();
	for (i = 0; apps[i].name_len != 0; i++)
		emu_fs_append(fs, read_df(f, sc, apps[i].name, apps[i].name_len));

	emu_fs_dump(fs, f);

	fclose(f);

	emu_fs_free(fs);

	scard_disconnect(sc);
	if (scard_is_error(sc)) {
		printf("%s\n", scard_error(sc));
		return 1;
	}
	scard_shutdown(sc);

	return 0;
}
