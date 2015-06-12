AM_CFLAGS = -Wall -Werror -Wmissing-prototypes
AM_LDFLAGS = -Wl,--as-needed

noinst_LIBRARIES = libopenemv.a
libopenemv_a_CFLAGS = $(AM_CFLAGS) $(PCSC_CFLAGS)
OPENEMV_LIBS = libopenemv.a $(PCSC_LIBS)
libopenemv_a_SOURCES = \
	scard.c scard.h \
	sc_helpers.c sc_helpers.h \
	tlv.c tlv.h \
	emv_tags.c emv_tags.h \
	crypto_backend.h \
	capk.c capk.h

libopenemv_a_SOURCES += crypto_gcrypt.c
libopenemv_a_CFLAGS += $(LIBGCRYPT_CFLAGS)
OPENEMV_LIBS += $(LIBGCRYPT_LIBS)

LDADD = $(OPENEMV_LIBS)
bin_PROGRAMS = capk-test sda-test tlv-test pcsc3 pcsc_sda
