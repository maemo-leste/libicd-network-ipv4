
SUBDIRS = src etc

EXTRA_DIST = \
	autogen.sh \
	debian/changelog \
	debian/compat \
	debian/control \
	debian/copyright \
	debian/libicd-network-dummy.install \
	debian/libicd-network-dummy.postinst \
	debian/libicd-network-dummy.prerm \
	debian/rules

MAINTAINERCLEANFILES = \
	Makefile.in aclocal.m4 config.guess config.h.in config.sub \
	install-sh ltmain.sh missing

.PHONY: doxygen-doc

doxygen-doc:
if DOXYGEN_DOCS_ENABLED
	@DOXYGEN@ Doxyfile
endif
