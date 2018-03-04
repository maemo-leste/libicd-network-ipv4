AC_INIT([ipv4 network configuration module], patsubst(esyscmd([dpkg-parsechangelog | sed -n '/^Version: \(.*\)$/ {s//\1/;p}']), [
]),[],[libicd-network-ipv4])
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([foreign])

AC_PREFIX_DEFAULT([/usr])

AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

PKG_CHECK_MODULES(GLIB, glib-2.0)
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES(GCONF, gconf-2.0)
AC_SUBST(GCONF_CFLAGS)
AC_SUBST(GCONF_LIBS)

PKG_CHECK_MODULES(ICD2, icd2)
AC_SUBST(ICD2_CFLAGS)
AC_SUBST(ICD2_LIBS)

AC_MSG_CHECKING([where ICd2 plugin dir is])
ICD_PLUGIN_DIR=`$PKG_CONFIG --variable=icdplugindir icd2`
AC_SUBST(ICD_PLUGIN_DIR)
AC_MSG_RESULT($ICD_PLUGIN_DIR)

PKG_CHECK_MODULES(OSSO_IC_DEV, osso-ic >= 0.1)
AC_SUBST(OSSO_IC_DEV_CFLAGS)

PKG_CHECK_MODULES(DBUS, dbus-1)
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

AC_MSG_CHECKING([wheter to send logs to stderr])
AC_ARG_ENABLE(log_stderr,
	[AS_HELP_STRING([--enable-log-stderr],
			[send logs to stderr (default=no)]
			)],
	[],
	enable_log_stderr=no)
if (test x$enable_log_stderr = xyes); then
	AC_DEFINE(ICD_LOG_STDERR, 1, [Log messages to stderr.])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING([wheter to build doxygen documentation])
AC_ARG_ENABLE(doxygen,
	[AS_HELP_STRING([--enable-doxygen],
			[enable doxygen document creation (default=no)]
			)])
if (test x$enable_doxygen = xyes); then
   AC_MSG_RESULT(yes)
   AC_CHECK_PROG(DOXYGEN, doxygen, doxygen, [])
   if (test x$DOXYGEN = x); then
      AC_MSG_WARN([doxygen requested but doxygen not found])
   else
      echo -n
      AC_SUBST(DOXYGEN)
   fi
else
   AC_MSG_RESULT(no)
fi
AM_CONDITIONAL(DOXYGEN_DOCS_ENABLED, [test x$DOXYGEN != x])

CFLAGS="$CFLAGS -Wall -Werror -Wno-missing-prototypes"
CFLAGS="$CFLAGS -include config.h"


AC_OUTPUT([
	Makefile
	src/Makefile
	etc/Makefile
	])
