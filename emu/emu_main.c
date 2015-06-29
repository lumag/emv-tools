#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "emu_syntax.h"
#include "emu_ast.h"
#include "emu_glue.h"

#include <stdio.h>
#include <stdbool.h>

static bool had_errors = false;

void yyerror(YYLTYPE *yylloc, const char *name, struct emu_df **pdf, char *msg)
{
	fprintf(stderr, "%s:%d:%d: %s\n", name, yylloc->first_line, yylloc->first_column, msg);

	had_errors = true;
}

int main(int argc, char **argv)
{
	struct emu_df *df;
	int ret;

	if (argc > 2)
		return 5;

	ret = yyparse(argc == 1 ? "-" : argv[1], &df);
	if (ret)
		return ret;

	if (had_errors)
		return 3;

	df_free(df);

	return 0;
}
