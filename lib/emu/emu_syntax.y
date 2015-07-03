%{
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/emu_ast.h"
#include "openemv/emu_glue.h"

#include <stdio.h>
#include <string.h>

struct emu_card {
	struct emu_df *df;
};

static struct emu_card *card_new(struct emu_df *df);
typedef void* yyscan_t;
static int yyparse (yyscan_t scanner, const char *name, struct emu_card **pcard);
#define yylex emu_lex

%}

%union {
	char *str;
	struct emu_value *val;
	struct emu_property *prop;
	struct emu_df *df;
}

%locations
%token EQ LBRACE RBRACE SEMICOLON COMMA
%token <str> STRING VALUE
%type <val> values
%type <prop> property properties
%type <df> df

%define api.pure true

%printer { fprintf (yyoutput, "%s", $$ ); } STRING VALUE
%printer { value_dump($$, yyoutput); } values
%printer { property_dump($$, yyoutput); } properties property
%destructor { free($$); } STRING VALUE
%destructor { value_free($$); } values
%destructor { property_free($$); } properties property
%parse-param {yyscan_t scanner}
%parse-param {const char *name}
%parse-param {struct emu_card **pcard}
%lex-param {scanner}

%code requires {
struct emu_card;
}

%code provides {
#include <stdio.h>
extern int emu_lex(YYSTYPE * yylval_param, YYLTYPE * yylloc_param, yyscan_t scanner);
extern int emu_lex_init (yyscan_t* scanner);
extern void emu_set_in  (FILE * in_str ,yyscan_t yyscanner );
extern int emu_lex_destroy (yyscan_t yyscanner );
}

%code {
static void yyerror(YYLTYPE *yylloc, yyscan_t scanner, const char *name, struct emu_card **pcard, char *msg);
}

%%

file: df { struct emu_card *card; if (yynerrs) YYABORT; card = card_new($1); if (!card) YYABORT; *pcard = card;}
    ;

df: LBRACE properties RBRACE SEMICOLON { $$ = df_new($2); }
  ;

properties: property {$$ = $1; }
	  | properties property { $$ = property_append($1, $2); }
	  | properties error {$$ = $1; }
	;

property: STRING EQ values SEMICOLON { $$ =  property_new($1, $3); }
	;

values: VALUE { $$ = value_new($1); }
      | values COMMA VALUE { $$ = value_append($1, value_new($3)); }
	;

%%
static void yyerror(YYLTYPE *yylloc, yyscan_t scanner, const char *name, struct emu_card **pcard, char *msg)
{
	fprintf(stderr, "%s:%d:%d: %s\n", name, yylloc->first_line, yylloc->first_column, msg);
}

static struct emu_card *card_new(struct emu_df *df)
{
	struct emu_card *card = malloc(sizeof(*card));

	card->df = df;

	return card;
}

void card_free(struct emu_card *card)
{
	df_free(card->df);
	free(card);
}

struct emu_card *card_parse(const char *fname)
{
	struct emu_card *card;
	int ret;
	FILE * f;
	yyscan_t scanner;

	if (!strcmp(fname, "-")) {
		f = stdin;
		fname = "<stdin>";
	} else
		f = fopen(fname, "r");

	if (!f) {
		perror("fopen");
		return NULL;
	}

	ret = emu_lex_init(&scanner);
	if (ret) {
		perror("emu_lex_init");
		return NULL;
	}
	emu_set_in(f, scanner);
	ret = yyparse(scanner, fname, &card);
	if (f != stdin)
		fclose(f);
	emu_lex_destroy(scanner);

	if (ret)
		return NULL;

	return card;
}

const struct emu_df *card_get_df(const struct emu_card *card, const unsigned char *name, size_t len)
{
	struct emu_df *df = card->df;

	if (len == 0)
		return df;

	size_t buf_len;
	const unsigned char *buf = df_get_value(df, "name", 1, &buf_len);

	if (len > buf_len)
		return NULL;

	if (memcmp(buf, name, len))
		return NULL;

	return df;
}
