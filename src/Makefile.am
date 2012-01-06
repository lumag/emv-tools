AM_CFLAGS = -Wall -Wmissing-prototypes
noinst_LIBRARIES = libopenemv.a
bin_PROGRAMS = main
main_SOURCES = main.c
libopenemv_a_SOURCES = tlv.c tlv.h scard.c scard.h

libopenemv_a_CFLAGS = $(AM_CFLAGS) $(PCSC_CFLAGS)

main_LDADD = libopenemv.a
