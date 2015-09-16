# openemv_module.m4 - Macros to support configurable modules in libopenemv
# serial 1 OPENEMV_MODULE
#
# Copyright (C) 2015 Dmitry Eremin-Solenikov
#
# This file is free software; authors give
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# OPENEMV_MODULE([SUBSYS], [NAME], [DESCRIPTION], [DEFAULT], [COMMANDS])
AC_DEFUN([OPENEMV_MODULE],
[dnl
m4_pushdef([openemv_endis], [m4_if([$4],[no],[en],[dis])])dnl
m4_pushdef([openemv_SUBSYS], [m4_translit([$1],[a-z],[A-Z])])dnl
m4_pushdef([openemv_NAME], [m4_translit([$2],[a-z],[A-Z])])dnl
AC_ARG_ENABLE([$1-$2],
	      [AS_HELP_STRING([--]openemv_endis[able-$1-$2],
			      openemv_endis[able support for $3])],
			      [],
			      [enable_$1_$2=$4])
AS_IF([test "x$enable_$1_$2" != "xno"],
      [m4_ifvaln([$5], [$5])dnl
AS_IF([test "x$default_$1" = "x"],
      [default_$1="$2"
AC_SUBST([default_$1])dnl
AC_DEFINE([DEFAULT_]openemv_SUBSYS, [$2], [Default provider for $1])])dnl
AC_DEFINE([ENABLE_]openemv_SUBSYS[_]openemv_NAME, [1], [Define if you enable $3])])
AM_CONDITIONAL(openemv_SUBSYS[_]openemv_NAME, [test "x$enable_$1_$2" != "xno"])dnl
m4_popdef([openemv_NAME])dnl
m4_popdef([openemv_SUBSYS])dnl
m4_popdef([openemv_endis])])

# OPENEMV_PRIVATE_PKG([pkgs])
AC_DEFUN([OPENEMV_PRIVATE_PKG],
[if test "x$OPENEMV_REQUIRES_PRIVATE" = "x"; then
	OPENEMV_REQUIRES_PRIVATE="Requires.private: $1"
else
	OPENEMV_REQUIRES_PRIVATE="${OPENEMV_REQUIRES_PRIVATE}, $1"
fi
AC_SUBST([OPENEMV_REQUIRES_PRIVATE])])

# OPENEMV_PRIVATE_LIBS([libs])
AC_DEFUN([OPENEMV_PRIVATE_LIBS],
[OPENEMV_LIBS_PRIVATE="${OPENEMV_LIBS_PRIVATE} $1"
AC_SUBST([OPENEMV_LIBS_PRIVATE])])
