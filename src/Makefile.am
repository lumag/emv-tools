AM_CFLAGS = -Wall -Werror -Wmissing-prototypes -Wformat=2 -DEMV_DATA_DIR="\"$(pkgdatadir)\""
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
	dol.c dol.h \
	emv_pki.c emv_pki.h \
	capk.c capk.h

libopenemv_a_SOURCES += crypto_gcrypt.c
libopenemv_a_CFLAGS += $(LIBGCRYPT_CFLAGS)
OPENEMV_LIBS += $(LIBGCRYPT_LIBS)

LDADD = $(OPENEMV_LIBS)
bin_PROGRAMS = capk-verify emv_dump emv_dda
check_PROGRAMS = tlv-test

TESTS = tlv-test capk-verify
TESTS_ENVIRONMENT = env CAPKFILE="$(srcdir)"/capk.txt

dist_pkgdata_DATA = capk.txt
