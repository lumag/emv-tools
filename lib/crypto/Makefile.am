noinst_LTLIBRARIES = libcrypto.la

libcrypto_la_SOURCES = \
       crypto.c crypto_backend.h
libcrypto_la_CPPFLAGS = -I$(srcdir)/../include
libcrypto_la_LIBADD =

if CRYPTO_LIBGCRYPT
libcrypto_la_SOURCES += crypto_libgcrypt.c
libcrypto_la_CPPFLAGS += $(LIBGCRYPT_CFLAGS)
libcrypto_la_LIBADD += $(LIBGCRYPT_LIBS)
endif

if CRYPTO_NETTLE
libcrypto_la_SOURCES += crypto_nettle.c
libcrypto_la_CPPFLAGS += $(NETTLE_CFLAGS)
libcrypto_la_LIBADD += $(NETTLE_LIBS)
endif
