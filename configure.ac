#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([emv-tools],[0.1],[dbaryshkov@gmail.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([lib/tlv.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([lib/m4])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES], [])
AM_MAINTAINER_MODE

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB
AM_PROG_AR
LT_INIT([disable-shared])
AM_PROG_LEX
AC_PROG_YACC
PKG_PROG_PKG_CONFIG
PKG_CONFIG="${PKG_CONFIG} --static"

AC_DEFUN([C_FLAG_CHECK],
[dnl
 AC_MSG_CHECKING([if $CC supports $1])
 AC_LANG_PUSH([C])
 ac_saved_cflags="$CFLAGS"
 CFLAGS="$1"
 AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
 [AC_MSG_RESULT([yes])
 CFLAGS="$ac_saved_cflags $1"
 ],
 [AC_MSG_RESULT([no])
 CFLAGS="$ac_saved_cflags"
 ]
 )
 AC_LANG_POP([C])
])

C_FLAG_CHECK([-Wall])
C_FLAG_CHECK([-Wmissing-prototypes])
C_FLAG_CHECK([-Wformat=2])

# Checks for libraries.
PKG_CHECK_MODULES([CONFIG], [libconfig])
OPENEMV_PRIVATE_PKG([libconfig])

OPENEMV_MODULE([scard], [pcsc], [PCSC smart card interface], [yes],
      [PKG_CHECK_MODULES([PCSC], [libpcsclite])
       OPENEMV_PRIVATE_PKG([libpcsclite])])

OPENEMV_MODULE([scard], [emu], [emulated smart card interface], [no])

OPENEMV_MODULE([scard], [apduio], [APDUIO smart card interface], [no])

OPENEMV_MODULE([crypto], [libgcrypt], [libgcrypt crypto library], [yes],
      [AM_PATH_LIBGCRYPT
       OPENEMV_PRIVATE_LIBS([${LIBGCRYPT_LIBS}])])

OPENEMV_MODULE([crypto], [nettle], [nettle crypto library], [yes],
      [PKG_CHECK_MODULES([NETTLE], [hogweed nettle])
       OPENEMV_PRIVATE_PKG([hogweed, nettle])])

# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([arpa/inet.h inttypes.h libintl.h malloc.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset socket strdup])

AC_CONFIG_FILES([
		 Makefile
		 data/Makefile
		 lib/Makefile
		 lib/openemv.pc
		 lib/include/Makefile
		 lib/crypto/Makefile
		 lib/emu/Makefile
		 lib/scard/Makefile
		 src/Makefile
		 ])
AC_OUTPUT
