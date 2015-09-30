# $Id $

sysconfdir=${prefix}/etc
piddir=/var/run
srcdir=.
top_srcdir=../../..


CC=i686-pc-mingw32-gcc
LD=i686-pc-mingw32-gcc
CFLAGS=-g -O2 -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wformat-security -Wno-pointer-sign -Wno-unused-result -fno-strict-aliasing -fno-builtin-memset -fstack-protector-all -I/cygdrive/c/openssh/Win32-OpenSSH/contrib/win32/win32compat/includes -I/cygdrive/c/openssh/Win32-OpenSSH/openbsd-compat -I/cygdrive/c/openssh/Win32-OpenSSH/contrib/win32/win32compat/includes -I/cygdrive/c/openssh/Win32-OpenSSH/libkrb -I/usr/local 
CPPFLAGS=-I. -I../../.. -I$(srcdir) -I$(top_srcdir) -I$(srcdir)/includes -I/cygdrive/c/openssh/openssl-1.0.2d/include -I/cygdrive/c/openssh/zlib-1.2.8  -DHAVE_CONFIG_H
LIBS=-lcrypto -lz  -lws2_32 -lgdi32 -lNetAPI32 -luserenv -lsecur32 -lshlwapi 
AR=/usr/bin/ar
RANLIB=i686-pc-mingw32-ranlib
INSTALL=/usr/bin/install -c
LDFLAGS=-L. -L/cygdrive/c/openssh/openssl-1.0.2d -L/cygdrive/c/openssh/zlib-1.2.8  -fstack-protector-all

WIN32COMPATFILES = daemon.o gettimeofday.o homedirhelp.o pwd.o sfds.o \
	socket.o startupneeds.o strcasecmp.o syslog.o lsalogon.o lsastring.o \
	stringhelp.o deskright.o win32auth.o kerberos.o

WIN32COMPATLIB=libwin32compat.a

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

all: $(WIN32COMPATLIB)

install:

clean:
	rm -f *.o *.a core

distclean: clean
	rm -f Makefile *~

$(WIN32COMPATFILES): ../../../config.h

$(WIN32COMPATLIB): $(WIN32COMPATFILES)
	$(AR) rv $@ $(WIN32COMPATFILES)
	$(RANLIB) $@
