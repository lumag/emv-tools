AM_YFLAGS = -d
AM_CPPFLAGS = -I$(srcdir)/../lib/include
AM_LDFLAGS = -Wl,--as-needed

noinst_LTLIBRARIES = libemu.la
libemu_la_SOURCES = emu_lex.l emu_syntax.y emu_ast.c emu_ast.h emu_glue.h
libemu_la_LIBADD = ../lib/libopenemv.la
BUILT_SOURCES = emu_syntax.h

noinst_PROGRAMS = emu
emu_SOURCES = emu_main.c
emu_LDADD = libemu.la ../lib/libopenemv.la
