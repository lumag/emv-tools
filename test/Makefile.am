include $(top_srcdir)/Makefile-gcov

AM_CPPFLAGS = -I$(srcdir)/../lib/include
AM_LDFLAGS = -Wl,--as-needed

LDADD = ../lib/libopenemv.la
check_PROGRAMS = \
	emu_test\
	crypto-test \
	emv_pki_priv_test \
	tlv-test \
	cda-test \
	dda-test \
	sda-test

TESTS = \
	emu_test\
	crypto-test \
	emv_pki_priv_test \
	tlv-test \
	cda-test \
	dda-test \
	sda-test

TESTS_ENVIRONMENT = env OPENEMV_CONFIG="$(builddir)"/../data/notinst.txt
