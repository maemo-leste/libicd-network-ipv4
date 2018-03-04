#!/bin/sh

set -e
set -x

libtoolize --force --copy
aclocal
autoheader -f
automake --foreign --add-missing --force-missing -i --copy
autoconf
