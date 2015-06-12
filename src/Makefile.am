AM_CFLAGS = -Wall -Wmissing-prototypes
noinst_LIBRARIES = libopenemv.a
bin_PROGRAMS = tlv-test pcsc3 capk-test sda-test
tlv_test_SOURCES = tlv-test.c
libopenemv_a_SOURCES = tlv.c tlv.h scard.c scard.h sc_helpers.c sc_helpers.h capk.c capk.h crypto_gcrypt.c crypto_backend.h

libopenemv_a_CFLAGS = $(AM_CFLAGS) $(PCSC_CFLAGS) $(LIBGCRYPT_CFLAGS)
capk_test_CFLAGS = $(LIBGCRYPT_CFLAGS)
sda_test_CFLAGS = $(LIBGCRYPT_CFLAGS)

tlv_test_LDADD = libopenemv.a
pcsc3_LDADD = $(AM_LDADD) $(PCSC_LIBS) libopenemv.a
capk_test_LDADD = $(AM_LDADD) $(LIBGCRYPT_LIBS) libopenemv.a
sda_test_LDADD = $(AM_LDADD) $(LIBGCRYPT_LIBS) libopenemv.a
