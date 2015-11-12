include $(top_srcdir)/Makefile-gcov

AM_CPPFLAGS = -I$(srcdir)/../lib/include
AM_LDFLAGS = -Wl,--as-needed

LDADD = ../lib/libopenemv.la
bin_PROGRAMS = \
	emv_dump\
	emv_dda\
	emv_cl_cda\
	emv_dump_emu\
	emv_cap \
	emv_select \
	emv_pse\
	emv_ppse
