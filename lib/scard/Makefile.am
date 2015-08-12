noinst_LTLIBRARIES = libscard.la

libscard_la_SOURCES = \
	scard.c scard_backend.h \
	sc_helpers.c
libscard_la_CPPFLAGS = -I$(srcdir)/../include
libscard_la_LIBADD =

if SCARD_PCSC
libscard_la_SOURCES += \
	scard_pcsc.c
libscard_la_CPPFLAGS += $(PCSC_CFLAGS)
libscard_la_LIBADD += $(PCSC_LIBS)
endif

if SCARD_EMU
libscard_la_SOURCES += \
	scard_emu.c
endif

if SCARD_APDUIO
libscard_la_SOURCES += \
	scard_apduio_t1.c \
	scard_apduio_t0.c
endif
