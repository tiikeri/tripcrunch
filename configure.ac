AC_INIT([tripcrunch], [1.0.0], [tatu.kilappa_AT_iki.fi], [tripcrunch])

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([dist-bzip2])

AC_CHECK_CC
AC_REQUEST_C99([HAVE_C99], [yes])

AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_C_BIGENDIAN

AC_COMPILE_MODE([TRIPCRUNCH_DEBUG])

AC_CHECK_HEADER([pthread.h],
								[pthread=yes],                                                      
								[pthread=no])
AC_CHECK_LIB([pthread],
						 [pthread_create],
						 [],                                                                    
						 [pthread=no])
AC_CHECK_HEADER([openssl/des.h],
								[openssl=yes],
								[openssl=no])
AC_CHECK_LIB([ssl],
						 [DES_fcrypt],
						 [],
						 [openssl=no])
iconv=[yes]

AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

AC_MSG_CHECKING([if build is possible])
if test x$pthread == xno ; then
	AC_MSG_ERROR([pthread not found])
fi
if test x$crypt == xno ; then
	AC_MSG_ERROR([openssl DES_fcrypt() not found])
fi
if test x$iconv == xno ; then
	AC_MSG_ERROR([iconv not found])
fi
AC_MSG_RESULT([yes])

# libtool
VERSION_CURRENT=[1]
VERSION_REVISION=[0]
VERSION_AGE=[0]
LIBTOOL_VERSION=[$VERSION_CURRENT:$VERSION_REVISION:$VERSION_AGE]
AC_SUBST(LIBTOOL_VERSION)

echo "
Configuration for $PACKAGE_TARNAME $PACKAGE_VERSION:
	Enable debug:             $TRIPCRUNCH_DEBUG
	Enable optimizations:     $optimizations
	Compiler flags:           $CFLAGS
	Linker flags:             $LDFLAGS
	Libs:                     $LIBS
	Install prefix:           $prefix
Type 'make' to build and 'make install' to install $PACKAGE."
