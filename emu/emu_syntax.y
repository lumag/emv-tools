%{
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "emu_syntax.h"
#include "emu_ast.h"
#include "emu_glue.h"

#include <stdio.h>
#include <string.h>
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
%parse-param {struct emu_df **pdf}

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

%%

file: df { *pdf = $1; }
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
