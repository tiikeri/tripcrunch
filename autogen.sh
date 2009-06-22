#!/bin/sh

ACINCLUDE="${HOME}/bin/cflags/acinclude.m4"

if test -f "${ACINCLUD}" ; then
	cp "${ACINCLUDE}" .
fi
autoreconf -fiv
exit 0
