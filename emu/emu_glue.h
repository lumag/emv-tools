#ifndef EMU_GLUE_H
#define EMU_GLUE_H

#include "emu_syntax.h"

extern int yylex(YYSTYPE * yylval_param,YYLTYPE * yylloc_param );
extern void yyset_in (FILE *  in_str );
extern void yyerror(YYLTYPE *yylloc, const char *name, struct emu_df **pdf, char *msg);

#endif
