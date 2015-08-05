AM_CPPFLAGS = -I$(srcdir)/../lib/include
AM_LDFLAGS = -Wl,--as-needed

LDADD = ../lib/libopenemv.la
check_PROGRAMS = tlv-test sda-test

TESTS = tlv-test sda-test
TESTS_ENVIRONMENT = env OPENEMV_CONFIG="$(builddir)"/../data/notinst.txt
