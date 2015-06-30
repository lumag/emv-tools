%{
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "emu_ast.h"
#include "emu_glue.h"

#include <stdio.h>
#include <string.h>

struct emu_card {
	struct emu_df *df;
};

static struct emu_card *card_new(struct emu_df *df);

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
%parse-param {const char *name}
%parse-param {struct emu_card **pcard}

%initial-action {
	FILE * f;

	if (!strcmp(name, "-"))
		f = stdin;
	else
		f = fopen(name, "r");

	if (!f) {
		perror("fopen");
		YYABORT;
	}

	yyset_in(f);
}

%code requires {
struct emu_card;
}

%code provides {
#include <stdio.h>
extern int yylex(YYSTYPE * yylval_param, YYLTYPE * yylloc_param );
extern void yyset_in(FILE *  in_str );
}

%code {
static void yyerror(YYLTYPE *yylloc, const char *name, struct emu_card **pcard, char *msg);
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
static void yyerror(YYLTYPE *yylloc, const char *name, struct emu_card **pcard, char *msg)
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

const struct emu_df *card_get_df(const struct emu_card *card)
{
	struct emu_df *df = card->df;

	return df;
}
