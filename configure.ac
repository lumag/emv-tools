#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([emv-tools],[0.1],[dbaryshkov@gmail.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([lib/tlv.c])
AC_CONFIG_HEADERS([config.h])
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
AC_ARG_ENABLE([scard-pcsc],
	      [AS_HELP_STRING([--disable-scard-pcsc],
			      [disable support for PCSC smart card interface])],
			      [],
			      [enable_scard_pcsc=yes])
AS_IF([test "x$enable_scard_pcsc" != "xno"],
      [PKG_CHECK_MODULES([PCSC], [libpcsclite])
       AC_DEFINE([ENABLE_SCARD_PCSC], [1], [Define if you enable PCSC smart card interface])])
AM_CONDITIONAL([SCARD_PCSC], [test "x$enable_scard_pcsc" != "xno"])

AC_ARG_ENABLE([scard-emu],
	      [AS_HELP_STRING([--enable-scard-emu],
			      [disable support for emulated smart card interface])],
			      [],
			      [enable_scard_emu=no])
AS_IF([test "x$enable_scard_emu" != "xno"],
      [AC_DEFINE([ENABLE_SCARD_EMU], [1], [Define if you enable EMU smart card interface])])
AM_CONDITIONAL([SCARD_EMU], [test "x$enable_scard_emu" != "xno"])

AC_ARG_ENABLE([crypto-libgcrypt],
	    [AS_HELP_STRING([--disable-crypto-libgcrypt],
			    [disable support for libgcrypt crypto library])],
			    [],
			    [with_libgcrypt=yes])
AS_IF([test "x$enable_libgcrypt" != "xno"],
      [AM_PATH_LIBGCRYPT
       AC_DEFINE([ENABLE_CRYPTO_LIBGCRYPT], [1], [Define if you enable libgcrypt crypto library])])
AM_CONDITIONAL([CRYPTO_LIBGCRYPT], [test "x$enable_libgcrypt" != "xno"])

# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([inttypes.h libintl.h malloc.h stddef.h stdint.h stdlib.h string.h unistd.h])

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
AC_CHECK_FUNCS([memset strdup])

AC_CONFIG_FILES([
		 Makefile
		 emu/Makefile
		 lib/Makefile
		 lib/include/Makefile
		 lib/crypto/Makefile
		 lib/emu/Makefile
		 lib/scard/Makefile
		 src/Makefile
		 ])
AC_OUTPUT
