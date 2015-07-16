%{
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "emu_syntax.h"

#define LOC_STEP yylloc->last_column += strlen(yytext)
#define LOC_ITEM do { yylloc->first_column = yylloc->last_column; yylloc->first_line = yylloc->last_line; LOC_STEP; } while (0)
#define LOC_NEWLINE do { yylloc->last_column = 1; ++yylloc->last_line; } while (0)

#define VALUE_BUF_SIZE (2 * 256 + 1)

static void init_value(YYSTYPE *yylval)
{
	yylval->str = malloc(VALUE_BUF_SIZE);
	yylval->str[0] = '\0';
}

static void expand_value(YYSTYPE *yylval, char *text)
{
	size_t len = strlen(yylval->str);

	if (len + 3 < VALUE_BUF_SIZE) {
		yylval->str[len++] = text[0];
		yylval->str[len++] = text[1];
		yylval->str[len++] = '\0';
	}
}

%}

%option nounput noinput noyywrap
%option bison-bridge bison-locations
%option warn
%option nodefault
%option reentrant
%option prefix="emu_"
%option outfile="lex.yy.c"

%x value
%x comment

HEXDIGIT [0-9A-Fa-f]

%%

<*>[ \t]+ LOC_STEP;
<*>\n	LOC_NEWLINE;

<value>{HEXDIGIT}{HEXDIGIT}  LOC_STEP; expand_value(yylval, yytext);
\<	LOC_ITEM; BEGIN(value); init_value(yylval);
<value>\>	LOC_STEP; BEGIN(INITIAL); return VALUE;

"/*"	LOC_STEP; BEGIN(comment);
<comment>[^*\n]*	LOC_STEP; /* eat anything that's not a '*' */
<comment>"*"+[^*/\n]*	LOC_STEP; /* eat up '*'s not followed by '/'s */
<comment>"*"+"/"	LOC_ITEM; BEGIN(INITIAL);


[a-z][a-z0-9]+  LOC_ITEM; yylval->str = strdup(yytext); return STRING;
=	LOC_ITEM; return EQ;
;	LOC_ITEM; return SEMICOLON;
\{	LOC_ITEM; return LBRACE;
\}	LOC_ITEM; return RBRACE;
,	LOC_ITEM; return COMMA;

<*>.	LOC_ITEM; return yytext[0];
