#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([emv-tools],[0.1],[dbaryshkov@gmail.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([lib/tlv.c])
AC_CONFIG_HEADERS([config.h])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES], [])
AM_MAINTAINER_MODE

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB
AM_PROG_AR
LT_INIT

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
PKG_CHECK_MODULES([PCSC], [libpcsclite])
AM_PATH_LIBGCRYPT

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h stddef.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([
		 Makefile
		 lib/Makefile
		 lib/include/Makefile
		 lib/crypto/Makefile
		 lib/scard/Makefile
		 src/Makefile
		 ])
AC_OUTPUT
