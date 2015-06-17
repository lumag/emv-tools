noinst_LTLIBRARIES = libcrypto.la

libcrypto_la_SOURCES =
libcrypto_la_CPPFLAGS = -I$(srcdir)/../include
libcrypto_la_LIBADD =

libcrypto_la_SOURCES += crypto_gcrypt.c
libcrypto_la_CPPFLAGS += $(LIBGCRYPT_CFLAGS)
libcrypto_la_LIBADD += $(LIBGCRYPT_LIBS)
