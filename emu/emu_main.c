#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "emu_ast.h"
#include "emu_glue.h"
#include "openemv/dump.h"

#include <stdio.h>
#include <stdbool.h>

int main(int argc, char **argv)
{
	struct emu_card *card;

	if (argc > 2)
		return 1;

	card = card_parse(argc == 1 ? "-" : argv[1]);
	if (!card)
		return 1;

	const struct emu_df *df = card_get_df(card, NULL, 0);
	if (!df)
		return 1;

	const struct emu_property *prop = df_get_property(df, "name");
	if (!prop)
		return 1;

	const struct emu_value *value = property_get_value(prop, 1);
	if (!value)
		return 1;

	size_t buf_len;
	const unsigned char *buf = value_get(value, &buf_len);

	dump_buffer(buf, buf_len, stdout);
	buf = df_get_value(df, "name", 1, &buf_len);
	dump_buffer(buf, buf_len, stdout);

	card_free(card);

	return 0;
}
