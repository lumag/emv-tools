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

#include "openemv/emu_ast.h"
#include "openemv/emu_glue.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

struct emu_card {
	struct emu_fs *fs;
	const struct emu_df *selected;
};

static uint16_t emu_error(struct emu_card *card, const unsigned char **ret, size_t *ret_len, uint16_t sw)
{
	*ret = NULL;
	*ret_len = 0;

	return sw;
}

static uint16_t emu_command_ins_not_supported(struct emu_card *card, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len)
{
	return emu_error(card, ret, ret_len, 0x6d00);
}

static uint16_t emu_command_verify(struct emu_card *card, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len)
{
	size_t pb_len;
	const unsigned char *pb;

	if (p1 != 0 || p2 != 0x80)
		return emu_error(card, ret, ret_len, 0x6a86);

	pb = emu_df_get_value(card->selected, "pinblock", 1, &pb_len);
	if (!pb || pb_len != 8)
		return emu_error(card, ret, ret_len, 0x6a81);

	if (lc != 8)
		return emu_error(card, ret, ret_len, 0x6700);

	if (memcmp(pb, data, lc))
		return emu_error(card, ret, ret_len, 0x63c3);

	*ret = NULL;
	*ret_len = 0;

	return 0x9000;
}

static uint16_t emu_command_select(struct emu_card *card, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len)
{
	const struct emu_df *df;

	if (p1 != 4 || p2 != 0)
		return emu_error(card, ret, ret_len, 0x6a86);

	df = emu_fs_get_df(card->fs, data, lc);
	if (!df)
		return emu_error(card, ret, ret_len, 0x6a82);

	card->selected = df;

	*ret = emu_df_get_value(card->selected, "fci", 1, ret_len);
	if (!*ret)
		return emu_error(card, ret, ret_len, 0x6a80);

	return 0x9000;
}

static uint16_t emu_command_read_record(struct emu_card *card, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len)
{
	char tag[6];

	if ((p2 & 0x7) != 4)
		return emu_error(card, ret, ret_len, 0x6a86);

	snprintf(tag, sizeof(tag), "sfi%d", p2 >> 3);

	*ret = emu_df_get_value(card->selected, tag, p1, ret_len);
	if (!*ret)
		// FIXME -- differentiate between record not present and hidden record
		return emu_error(card, ret, ret_len, 0x6a80);

	return 0x9000;
}

static uint16_t emu_command_emv_generate_ac(struct emu_card *card, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len)
{
	if (p2 != 0)
		return emu_error(card, ret, ret_len, 0x6a86);

	*ret = emu_df_get_value(card->selected, "ac", 1, ret_len);
	if (!*ret)
		return emu_error(card, ret, ret_len, 0x6a80);

	return 0x9000;
}

static uint16_t emu_command_emv_get_processing_options(struct emu_card *card, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len)
{
	if (p1 != 0 || p2 != 0)
		return emu_error(card, ret, ret_len, 0x6a86);

	*ret = emu_df_get_value(card->selected, "gpo", 1, ret_len);
	if (!*ret)
		return emu_error(card, ret, ret_len, 0x6a80);

	return 0x9000;
}

static uint16_t emu_command_emv_get_data(struct emu_card *card, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len)
{
	char tag[9];

	snprintf(tag, sizeof(tag), "data%02x%02x", p1, p2);

	*ret = emu_df_get_value(card->selected, tag, 1, ret_len);
	if (!*ret)
		return emu_error(card, ret, ret_len, 0x6a88);

	return 0x9000;
}


static uint16_t emu_command_cla_00(struct emu_card *card, uint8_t ins, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len)
{
	switch (ins) {
	case 0x20:
		return emu_command_verify(card, p1, p2, lc, data, ret, ret_len);
	case 0xa4:
		return emu_command_select(card, p1, p2, lc, data, ret, ret_len);
	case 0xb2:
		return emu_command_read_record(card, p1, p2, lc, data, ret, ret_len);
	default:
		return emu_command_ins_not_supported(card, p1, p2, lc, data, ret, ret_len);
	}
}

static uint16_t emu_command_cla_80(struct emu_card *card, uint8_t ins, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len)
{
	switch (ins) {
	case 0xa8:
		return emu_command_emv_get_processing_options(card, p1, p2, lc, data, ret, ret_len);
	case 0xae:
		return emu_command_emv_generate_ac(card, p1, p2, lc, data, ret, ret_len);
	case 0xca:
		return emu_command_emv_get_data(card, p1, p2, lc, data, ret, ret_len);
	default:
		return emu_command_ins_not_supported(card, p1, p2, lc, data, ret, ret_len);
	}
}

static uint16_t emu_command_cla_not_supported(struct emu_card *card, uint8_t ins, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len)
{
	return emu_error(card, ret, ret_len, 0x6e00);
}

uint16_t emu_command(struct emu_card *card, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len)
{
	switch (cla) {
	case 0x00:
		return emu_command_cla_00(card, ins, p1, p2, lc, data, ret, ret_len);
	case 0x80:
		return emu_command_cla_80(card, ins, p1, p2, lc, data, ret, ret_len);
	default:
		return emu_command_cla_not_supported(card, ins, p1, p2, lc, data, ret, ret_len);
	}
}

struct emu_card *emu_card_parse(const char *fname)
{
	FILE *f;
	struct emu_card *card;

	card = malloc(sizeof(*card));
	if (!card)
		return NULL;

	card->fs = NULL;
	card->selected = NULL;

	if (!strcmp(fname, "-")) {
		f = stdin;
		fname = "<stdin>";
	} else
		f = fopen(fname, "r");

	if (!f) {
		perror("fopen");
		emu_card_free(card);
		return NULL;
	}

	card->fs = emu_fs_parse(f, fname);

	if (f != stdin)
		fclose(f);

	if (!card->fs) {
		emu_card_free(card);
		return NULL;
	}

	card->selected = emu_fs_get_df(card->fs, NULL, 0);
	if (!card->selected) {
		emu_card_free(card);
		return NULL;
	}

	return card;
}

void emu_card_free(struct emu_card *card)
{
	if (!card)
		return;

	emu_fs_free(card->fs);
	/* df is freed as a part of fs free */

	free(card);
}
