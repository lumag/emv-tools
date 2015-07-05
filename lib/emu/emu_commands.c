#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/emu_ast.h"
#include "openemv/emu_glue.h"

#include <stdint.h>
#include <string.h>

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
	const struct emu_df *df;
	size_t pb_len;
	const unsigned char *pb;

	if (p1 != 0 || p2 != 0x80)
		return emu_error(card, ret, ret_len, 0x6a86);

	df = card_get_df(card, NULL, 0); // FIXME
	if (!df)
		return emu_error(card, ret, ret_len, 0x6a82);

	pb = emu_df_get_value(df, "pinblock", 1, &pb_len);
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

	df = card_get_df(card, NULL, 0); // FIXME
	if (!df)
		return emu_error(card, ret, ret_len, 0x6a82);

	*ret = emu_df_get_value(df, "fci", 1, ret_len);
	if (!*ret)
		return emu_error(card, ret, ret_len, 0x6a80);

	return 0x9000;
}

static uint16_t emu_command_read_record(struct emu_card *card, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len)
{
	const struct emu_df *df;
	char tag[6];

	if ((p2 & 0x7) != 4)
		return emu_error(card, ret, ret_len, 0x6a86);

	df = card_get_df(card, NULL, 0); // FIXME
	if (!df)
		return emu_error(card, ret, ret_len, 0x6a82);

	snprintf(tag, sizeof(tag), "sfi%d", p2 >> 3);

	*ret = emu_df_get_value(df, tag, p1, ret_len);
	if (!*ret)
		// FIXME -- differentiate between record not present and hidden record
		return emu_error(card, ret, ret_len, 0x6a80);

	return 0x9000;
}

static uint16_t emu_command_emv_generate_ac(struct emu_card *card, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len)
{
	const struct emu_df *df;

	if (p2 != 0)
		return emu_error(card, ret, ret_len, 0x6a86);

	df = card_get_df(card, NULL, 0); // FIXME
	if (!df)
		return emu_error(card, ret, ret_len, 0x6a82);

	*ret = emu_df_get_value(df, "ac", 1, ret_len);
	if (!*ret)
		return emu_error(card, ret, ret_len, 0x6a80);

	return 0x9000;
}

static uint16_t emu_command_emv_get_processing_options(struct emu_card *card, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len)
{
	const struct emu_df *df;

	if (p1 != 0 || p2 != 0)
		return emu_error(card, ret, ret_len, 0x6a86);

	df = card_get_df(card, NULL, 0); // FIXME
	if (!df)
		return emu_error(card, ret, ret_len, 0x6a82);

	*ret = emu_df_get_value(df, "gpo", 1, ret_len);
	if (!*ret)
		return emu_error(card, ret, ret_len, 0x6a80);

	return 0x9000;
}

static uint16_t emu_command_emv_get_data(struct emu_card *card, uint8_t p1, uint8_t p2, size_t lc, const unsigned char *data, const unsigned char **ret, size_t *ret_len)
{
	const struct emu_df *df;
	char tag[9];

	df = card_get_df(card, NULL, 0); // FIXME
	if (!df)
		return emu_error(card, ret, ret_len, 0x6a82);

	snprintf(tag, sizeof(tag), "data%02x%02x", p1, p2);

	*ret = emu_df_get_value(df, tag, 1, ret_len);
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
