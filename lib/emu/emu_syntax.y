%{
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/emu_ast.h"

#include <stdio.h>
#include <string.h>

//#define YYDEBUG 1

typedef void* yyscan_t;
static int yyparse (yyscan_t scanner, const char *name, struct emu_fs **pfs);
#define yylex emu_lex

%}

%union {
	char *str;
	struct emu_value *val;
	struct emu_property *prop;
	struct emu_df *df;
	struct emu_fs *fs;
}

%locations
%token EQ LBRACE RBRACE SEMICOLON COMMA
%token <str> STRING VALUE
%type <val> values
%type <prop> property
%type <df> df properties
%type <fs> file

%define api.pure true

%printer { fprintf (yyoutput, "%s", $$ ); } STRING VALUE
%printer { emu_value_dump($$, yyoutput); } values
%printer { emu_property_dump($$, yyoutput); } property
%printer { emu_df_dump($$, yyoutput); } properties df
%printer { emu_fs_dump($$, yyoutput); } file
%destructor { free($$); } STRING VALUE
%destructor { emu_value_free($$); } values
%destructor { emu_property_free($$); } property
%destructor { emu_df_free($$); } properties df
%parse-param {yyscan_t scanner}
%parse-param {const char *name}
%parse-param {struct emu_fs **pfs}
%lex-param {scanner}

%code provides {
#include <stdio.h>
extern int emu_lex(YYSTYPE * yylval_param, YYLTYPE * yylloc_param, yyscan_t scanner);
extern int emu_lex_init (yyscan_t* scanner);
extern void emu_set_in  (FILE * in_str ,yyscan_t yyscanner );
extern int emu_lex_destroy (yyscan_t yyscanner );
}

%code {
static void yyerror(YYLTYPE *yylloc, yyscan_t scanner, const char *name, struct emu_fs **pfs, char *msg);
}

%%

file: /* empty */ { $$ = emu_fs_new(); if (!$$) YYABORT; *pfs = $$; }
    | file df { if (yynerrs) YYABORT; $$ = emu_fs_append($1, $2); }
    ;

df: LBRACE properties RBRACE SEMICOLON { $$ = $2; }
  ;

properties: /* empty */ { $$ = emu_df_new(); if (!$$) YYABORT; }
	  | properties property { $$ = emu_df_append($1, $2); }
	  | properties error { $$ = $1; }
	;

property: STRING EQ values SEMICOLON { $$ = emu_property_new($1, $3); free($1); }
	;

values: VALUE { $$ = emu_value_new($1); free($1); }
      | values COMMA VALUE { $$ = emu_value_append($1, $3); free($3); }
	;

%%
static void yyerror(YYLTYPE *yylloc, yyscan_t scanner, const char *name, struct emu_fs **pfs, char *msg)
{
	fprintf(stderr, "%s:%d:%d: %s\n", name, yylloc->first_line, yylloc->first_column, msg);
}

struct emu_fs *emu_fs_parse(FILE *f, const char *fname)
{
	struct emu_fs *fs;
	int ret;
	yyscan_t scanner;

#if YYDEBUG
	yydebug = 1;
#endif

	ret = emu_lex_init(&scanner);
	if (ret) {
		perror("emu_lex_init");
		return NULL;
	}
	emu_set_in(f, scanner);
	ret = yyparse(scanner, fname, &fs);
	emu_lex_destroy(scanner);

	if (ret)
		return NULL;

	return fs;
}
