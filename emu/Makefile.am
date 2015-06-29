AM_YFLAGS = -d
AM_CPPFLAGS = -I$(srcdir)/../lib/include
AM_LDFLAGS = -Wl,--as-needed

noinst_PROGRAMS = emu
emu_SOURCES = emu_lex.l emu_syntax.y emu_ast.c emu_ast.h emu_main.c emu_glue.h
emu_LDADD = ../lib/libopenemv.la
BUILT_SOURCES = emu_syntax.h
