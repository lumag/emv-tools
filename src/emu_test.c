#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/emu_ast.h"
#include "openemv/dump.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

int main(int argc, char **argv)
{
	const char *fname;
	FILE *f;
	struct emu_fs *fs;

	if (argc > 2)
		return 1;

	if (argc == 1 || !strcmp(argv[1], "-")) {
		fname = "<stdin>";
		f = stdin;
	} else {
		fname = argv[1];
		f = fopen(fname, "r");
	}

	if (!f) {
		perror("fopen");
		return 1;
	}

	fs = emu_fs_parse(f, fname);
	if (!fs)
		return 1;

	fclose(f);

	const struct emu_df *df = emu_fs_get_df(fs, NULL, 0);
	if (!df)
		return 1;

	const struct emu_property *prop = emu_df_get_property(df, "name");
	if (!prop)
		return 1;

	const struct emu_value *value = emu_property_get_value(prop);
	if (!value)
		return 1;

	size_t buf_len;
	const unsigned char *buf = emu_value_get(value, 1, &buf_len);

	dump_buffer(buf, buf_len, stdout);
	buf = emu_df_get_value(df, "name", 1, &buf_len);
	dump_buffer(buf, buf_len, stdout);

	emu_fs_free(fs);

	return 0;
}
