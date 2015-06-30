#ifndef EMU_GLUE_H
#define EMU_GLUE_H

#include "emu_syntax.h"
struct emu_card;

extern int yylex(YYSTYPE * yylval_param,YYLTYPE * yylloc_param );
extern void yyset_in (FILE *  in_str );
extern void yyerror(YYLTYPE *yylloc, const char *name, struct emu_card **pcard, char *msg);
struct emu_card *card_parse(const char *fname);
void card_free(struct emu_card *card);
const struct emu_df *card_get_df(const struct emu_card *card);

#endif
