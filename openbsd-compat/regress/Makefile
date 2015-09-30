# $Id: Makefile.in,v 1.5 2014/06/17 13:06:08 dtucker Exp $

sysconfdir=${prefix}/etc
piddir=/var/run
srcdir=.
top_srcdir=../..


CC=i686-pc-mingw32-gcc
LD=i686-pc-mingw32-gcc
CFLAGS=-g -O2 -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wformat-security -Wno-pointer-sign -Wno-unused-result -fno-strict-aliasing -fno-builtin-memset -fstack-protector-all -I/cygdrive/c/openssh/Win32-OpenSSH/contrib/win32/win32compat/includes -I/cygdrive/c/openssh/Win32-OpenSSH/openbsd-compat -I/cygdrive/c/openssh/Win32-OpenSSH/contrib/win32/win32compat/includes -I/cygdrive/c/openssh/Win32-OpenSSH/libkrb -I/usr/local 
CPPFLAGS=-I. -I.. -I$(srcdir) -I$(srcdir)/.. -I/cygdrive/c/openssh/openssl-1.0.2d/include -I/cygdrive/c/openssh/zlib-1.2.8  -DHAVE_CONFIG_H
EXEEXT=.exe
LIBCOMPAT=../libopenbsd-compat.a
LIBS=-lcrypto -lz  -lws2_32 -lgdi32 -lNetAPI32 -luserenv -lsecur32 -lshlwapi 
LDFLAGS=-L/cygdrive/c/openssh/openssl-1.0.2d -L/cygdrive/c/openssh/zlib-1.2.8  -fstack-protector-all $(LIBCOMPAT)

TESTPROGS=closefromtest$(EXEEXT) snprintftest$(EXEEXT) strduptest$(EXEEXT) \
	strtonumtest$(EXEEXT) opensslvertest$(EXEEXT)

all:	t-exec ${OTHERTESTS}

%$(EXEEXT):	%.c $(LIBCOMPAT)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $< $(LIBCOMPAT) $(LIBS)

t-exec:	$(TESTPROGS)
	@echo running compat regress tests
	@for TEST in ""$?; do \
		echo "run test $${TEST}" ... 1>&2; \
		./$${TEST}$(EXEEXT) || exit $$? ; \
	done
	@echo finished compat regress tests

clean:
	rm -f *.o *.a core $(TESTPROGS) valid.out

distclean: clean
	rm -f Makefile *~
