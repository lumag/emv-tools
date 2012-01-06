AM_CFLAGS = -Wall -Wmissing-prototypes
noinst_LIBRARIES = libopenemv.a
bin_PROGRAMS = main pcsc2
main_SOURCES = main.c
pcsc2_SOURCES = pcsc2.c
libopenemv_a_SOURCES = tlv.c tlv.h scard.c scard.h

libopenemv_a_CFLAGS = $(AM_CFLAGS) $(PCSC_CFLAGS)

main_LDADD = libopenemv.a
pcsc2_LDADD = $(AM_LDADD) $(PCSC_LIBS) libopenemv.a
