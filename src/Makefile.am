MAINTAINERCLEANFILES = \
	Makefile.in

INCLUDES = \
	@GLIB_CFLAGS@ \
	@GCONF_CFLAGS@ \
	@ICD2_CFLAGS@ \
	@OSSO_IC_DEV_CFLAGS@ \
	@DBUS_CFLAGS@

LDFLAGS = -avoid-version

plugindir = @ICD_PLUGIN_DIR@

plugin_LTLIBRARIES = \
	libicd_network_ipv4.la

libicd_network_ipv4_la_SOURCES = \
	libicd_network_ipv4.c

libicd_network_ipv4_la_LIBADD = \
	@GLIB_LIBS@ \
	@GCONF_LIBS@ \
	@ICD2_LIBS@ \
	@OSSO_IC_DEV_LIBS@ \
	@DBUS_LIBS@
