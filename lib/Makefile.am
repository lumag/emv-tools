SUBDIRS = include crypto emu scard

noinst_LTLIBRARIES = libopenemv.la

libopenemv_la_SOURCES = \
	dol.c \
	dump.c \
	emv_pk.c \
	emv_pki.c \
	emv_tags.c \
	pinpad.c \
	tlv.c
libopenemv_la_CPPFLAGS = -I$(srcdir)/include
libopenemv_la_LIBADD = \
	crypto/libcrypto.la \
	emu/libemu.la \
	scard/libscard.la
