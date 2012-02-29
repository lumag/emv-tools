AM_CFLAGS = -Wall -Wmissing-prototypes
noinst_LIBRARIES = libopenemv.a
bin_PROGRAMS = main pcsc3 capk-test sda-test
main_SOURCES = main.c
libopenemv_a_SOURCES = tlv.c tlv.h scard.c scard.h sc_helpers.c sc_helpers.h tlvs.c tlvs.h capk.c capk.h

libopenemv_a_CFLAGS = $(AM_CFLAGS) $(PCSC_CFLAGS)
capk_test_CFLAGS = $(LIBGCRYPT_CFLAGS)
sda_test_CFLAGS = $(LIBGCRYPT_CFLAGS)

main_LDADD = libopenemv.a
pcsc3_LDADD = $(AM_LDADD) $(PCSC_LIBS) libopenemv.a
capk_test_LDADD = $(AM_LDADD) $(LIBGCRYPT_LIBS) libopenemv.a
sda_test_LDADD = $(AM_LDADD) $(LIBGCRYPT_LIBS)
