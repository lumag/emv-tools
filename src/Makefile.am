AM_CPPFLAGS = -I$(srcdir)/../lib/include
AM_LDFLAGS = -Wl,--as-needed

LDADD = ../lib/libopenemv.la
bin_PROGRAMS = \
	capk-verify\
	emv_dump\
	emv_dda\
	emv_cl_cda\
	emv_dump_emu\
	emv_cap \
	emv_pse\
	emv_ppse

TESTS = capk-verify
TESTS_ENVIRONMENT = env OPENEMV_CONFIG="$(builddir)"/../data/notinst.txt
