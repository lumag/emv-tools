# openemv_flags.m4 - Macros to support configurable compiler flags
# serial 1 OPENEMV_CHECK_CFLAG
#
# Copyright (C) 2015 Dmitry Eremin-Solenikov
#
# This file is free software; authors give
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# OPENEMV_CHECK_CFLAG([flag], [ACTION-IF_YES], [ACTION-IF-NOT])
AC_DEFUN([OPENEMV_CHECK_CFLAG],
[dnl
 AC_MSG_CHECKING([if $CC supports $1])
 AC_LANG_PUSH([C])
 ac_saved_cflags="$CFLAGS"
 CFLAGS="$1"
 AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
 [AC_MSG_RESULT([yes])
 CFLAGS="$ac_saved_cflags $1"
 m4_default([$2], [])dnl
 ],
 [AC_MSG_RESULT([no])
 CFLAGS="$ac_saved_cflags"
 m4_default([$3], [])dnl
 ]
 )
 AC_LANG_POP([C])
])
