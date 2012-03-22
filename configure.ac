#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT(libarms, 5.01)
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([http/url.c])
AC_CONFIG_HEADERS([config.h])

# libtool
LT_INIT
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_YACC
AC_PROG_CC
AC_PROG_LEX
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

# Checks for libraries.
# FIXME: Replace `main' with a function in `-ldl':
#AC_CHECK_LIB([dl], [main])
# FIXME: Replace `main' with a function in `-lexpat':
AC_CHECK_LIB([expat], [XML_ParserCreate],,[AC_MSG_ERROR(We need expat library.)])
# FIXME: Replace `main' with a function in `-lrt':
#AC_CHECK_LIB([rt], [main])
# FIXME: Replace `main' with a function in `-lcrypto':
AC_CHECK_LIB([crypto], [EVP_DigestInit])
# FIXME: Replace `main' with a function in `-lssl':
AC_CHECK_LIB([ssl], [SSL_new],,[AC_MSG_ERROR(We need OpenSSL library.)])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h paths.h  stdlib.h string.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MKTIME
AC_CHECK_FUNCS([clock_gettime gettimeofday fcntl localtime signal srandom setsockopt getaddrinfo getnameinfo htons inet_ntoa isascii memchr memset regcomp select socket strcasecmp strchr strcspn strdup strerror strlcpy strtok_r strncasecmp strstr strtol strtoul strtoull])
AC_CHECK_MEMBERS(struct sockaddr.sa_len,,,[#include <sys/types.h>
#include <sys/socket.h>])
AC_CHECK_TYPES(struct sockaddr_storage,,,[#include <sys/types.h>
#include <sys/socket.h>])

# Specify external software include path.
AC_ARG_WITH(expat-incdir,
            [AC_HELP_STRING([--with-expat-incdir=PATH],
                            [specify include directory of expat library])],
            [],
            [with_expat_incdir=""])

AC_ARG_WITH(openssl-incdir,
            [AC_HELP_STRING([--with-openssl-incdir=PATH],
                            [specify include directory of OpenSSL library])],
            [],
            [with_openssl_incdir=""])

AC_ARG_WITH(arms-vendor,
            [AC_HELP_STRING([--with-arms-vendor=VENDORNAME],
                            [use vendor specific configuration])],
            [],
            [with_arms_vendor=""])

CPPFLAGS="$CPPFLAGS -I./include"
if test "x$with_expat_incdir" != "x"; then
  CPPFLAGS="$CPPFLAGS -I$with_expat_incdir"
fi
if test "x$with_openssl_incdir" != "x"; then
  CPPFLAGS="$CPPFLAGS -I$with_openssl_incdir"
fi
if test "x$with_arms_vendor" != "x"; then
  CPPFLAGS="$CPPFLAGS -DUSE_KEY -I./vendor/$with_arms_vendor"
fi

AC_ARG_ENABLE(ipv6,
	      AS_HELP_STRING([--disable-ipv6],
	      [disable support IPv6]),
	      [],
	      [enable_ipv6=check])
AS_IF([test "x$enable_ipv6" != xno],
  [AC_CHECK_DECL(AF_INET6,
    CPPFLAGS="$CPPFLAGS -DUSE_INET6",
    [if test "x$enable_ipv6" != xcheck; then
      AC_MSG_FAILURE(
        [--enable-ipv6 was given, but test for ipv6 failed])
     fi
    ],
    [#include <sys/types.h>
#include <sys/socket.h>])])
    

AC_ARG_ENABLE(debug,
              AS_HELP_STRING([--enable-debug],
              [enable debugging]),
              CPPFLAGS="$CPPFLAGS -DARMS_DEBUG",)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT_COMMANDS([echo timestamp > stamp-h1])
AC_OUTPUT
