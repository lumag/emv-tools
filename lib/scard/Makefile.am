noinst_LTLIBRARIES = libscard.la

libscard_la_SOURCES = \
	sc_helpers.c
libscard_la_CPPFLAGS = -I$(srcdir)/../include
libscard_la_LIBADD =

libscard_la_SOURCES += \
	scard_pcsc.c
libscard_la_CPPFLAGS += $(PCSC_CFLAGS)
libscard_la_LIBADD += $(PCSC_LIBS)
