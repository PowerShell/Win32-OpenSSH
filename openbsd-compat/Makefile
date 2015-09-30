# $Id: Makefile.in,v 1.56 2014/09/30 23:43:08 djm Exp $

sysconfdir=${prefix}/etc
piddir=/var/run
srcdir=.
top_srcdir=..


CC=i686-pc-mingw32-gcc
LD=i686-pc-mingw32-gcc
CFLAGS=-g -O2 -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wformat-security -Wno-pointer-sign -Wno-unused-result -fno-strict-aliasing -fno-builtin-memset -fstack-protector-all -I/cygdrive/c/openssh/Win32-OpenSSH/contrib/win32/win32compat/includes -I/cygdrive/c/openssh/Win32-OpenSSH/openbsd-compat -I/cygdrive/c/openssh/Win32-OpenSSH/contrib/win32/win32compat/includes -I/cygdrive/c/openssh/Win32-OpenSSH/libkrb -I/usr/local 
CPPFLAGS=-I. -I.. -I$(srcdir) -I$(srcdir)/.. -I/cygdrive/c/openssh/openssl-1.0.2d/include -I/cygdrive/c/openssh/zlib-1.2.8  -DHAVE_CONFIG_H
LIBS=-lcrypto -lz  -lws2_32 -lgdi32 -lNetAPI32 -luserenv -lsecur32 -lshlwapi 
AR=/usr/bin/ar
RANLIB=i686-pc-mingw32-ranlib
INSTALL=/usr/bin/install -c
LDFLAGS=-L. -L/cygdrive/c/openssh/openssl-1.0.2d -L/cygdrive/c/openssh/zlib-1.2.8  -fstack-protector-all

OPENBSD=base64.o basename.o bcrypt_pbkdf.o bindresvport.o blowfish.o daemon.o dirname.o fmt_scaled.o getcwd.o getgrouplist.o getopt_long.o getrrsetbyname.o glob.o inet_aton.o inet_ntoa.o inet_ntop.o mktemp.o pwcache.o readpassphrase.o reallocarray.o realpath.o rresvport.o setenv.o setproctitle.o sha1.o sha2.o rmd160.o md5.o sigact.o strlcat.o strlcpy.o strmode.o strnlen.o strptime.o strsep.o strtonum.o strtoll.o strtoul.o strtoull.o timingsafe_bcmp.o vis.o blowfish.o bcrypt_pbkdf.o explicit_bzero.o

COMPAT=arc4random.o bsd-asprintf.o bsd-closefrom.o bsd-cray.o bsd-cygwin_util.o bsd-getpeereid.o getrrsetbyname-ldns.o bsd-misc.o bsd-nextstep.o bsd-openpty.o bsd-poll.o bsd-setres_id.o bsd-snprintf.o bsd-statvfs.o bsd-waitpid.o fake-rfc2553.o openssl-compat.o xmmap.o xcrypt.o kludge-fd_set.o

PORTS=port-aix.o port-irix.o port-linux.o port-solaris.o port-tun.o port-uw.o

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

all: libopenbsd-compat.a

$(COMPAT): ../config.h
$(OPENBSD): ../config.h
$(PORTS): ../config.h

libopenbsd-compat.a:  $(COMPAT) $(OPENBSD) $(PORTS)
	$(AR) rv $@ $(COMPAT) $(OPENBSD) $(PORTS)
	$(RANLIB) $@

clean:
	rm -f *.o *.a core 

distclean: clean
	rm -f Makefile *~
