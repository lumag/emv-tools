AM_CPPFLAGS = -DEMV_DATA_DIR="\"$(pkgdatadir)\"" -I$(srcdir)/../lib/include
AM_LDFLAGS = -Wl,--as-needed

LDADD = ../lib/libopenemv.la
bin_PROGRAMS = capk-verify emu_test emv_dump emv_dda emv_cl_cda
check_PROGRAMS = tlv-test

TESTS = tlv-test capk-verify
TESTS_ENVIRONMENT = env CAPKFILE="$(srcdir)"/capk.txt

dist_pkgdata_DATA = capk.txt
