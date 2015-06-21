SUBDIRS = include crypto scard

noinst_LTLIBRARIES = libopenemv.la

libopenemv_la_SOURCES = \
	dol.c \
	emv_pk.c \
	emv_pki.c \
	emv_tags.c \
	tlv.c
libopenemv_la_CPPFLAGS = -I$(srcdir)/include
libopenemv_la_LIBADD = \
	crypto/libcrypto.la \
	scard/libscard.la
