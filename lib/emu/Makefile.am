AM_YFLAGS = -d
AM_CPPFLAGS = -I$(srcdir)/../include
AM_LDFLAGS = -Wl,--as-needed

noinst_LTLIBRARIES = libemu.la
libemu_la_SOURCES = emu_lex.l emu_syntax.y emu_ast.c emu_commands.c
BUILT_SOURCES = emu_syntax.h
