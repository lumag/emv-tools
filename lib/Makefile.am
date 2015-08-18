SUBDIRS = include crypto emu scard

noinst_LTLIBRARIES = libopenemv.la

libopenemv_la_SOURCES = \
	config.c \
	dol.c \
	dump.c \
	emv_commands.c \
	emv_pk.c \
	emv_pki.c \
	emv_tags.c \
	pinpad.c \
	tlv.c
libopenemv_la_CPPFLAGS = \
	-I$(srcdir)/include \
	-DOPENEMV_CONFIG_DIR="\"$(pkgsysconfdir)\"" \
	$(CONFIG_CFLAGS)
libopenemv_la_LIBADD = \
	$(CONFIG_LIBS) \
	crypto/libcrypto.la \
	emu/libemu.la \
	scard/libscard.la

# Pkg-config script.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = openemv.pc
DISTCLEANFILES = $(pkgconfig_DATA)

openemv.pc: $(srcdir)/Makefile.in $(top_builddir)/config.status
