/* $OpenBSD: sshpty.c,v 1.30 2015/07/30 23:09:15 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Allocating a pseudo-terminal, and making it the controlling tty.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include "includes.h"

/*
 * We support only client side kerberos on Windows.
 */

#ifdef WIN32_FIXME
  #undef GSSAPI
  #undef KRB5
#endif

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <signal.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#ifdef HAVE_PATHS_H
# include <paths.h>
#endif
#include <pwd.h>
#include <stdarg.h>
#include <string.h>
#include <termios.h>
#ifdef HAVE_UTIL_H
# include <util.h>
#endif
#include <unistd.h>

#include "sshpty.h"
#include "log.h"
#include "misc.h"

#ifdef HAVE_PTY_H
# include <pty.h>
#endif

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

#ifdef __APPLE__
# include <AvailabilityMacros.h>
# if (MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_5)
#  define __APPLE_PRIVPTY__
# endif
#endif

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

int
pty_allocate(int *ptyfd, int *ttyfd, char *namebuf, size_t namebuflen)
{
#ifndef WIN32_FIXME
	/* openpty(3) exists in OSF/1 and some other os'es */
	char *name;
	int i;

	i = openpty(ptyfd, ttyfd, NULL, NULL, NULL);
	if (i < 0) {
		error("openpty: %.100s", strerror(errno));
		return 0;
	}
	name = ttyname(*ttyfd);
	if (!name)
		fatal("openpty returns device for which ttyname fails.");

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	return 1;
#else

  /*
   * Simple console screen implementation in Win32 to give a Unix like pty for interactive sessions
   */
  *ttyfd = 0; // first ttyfd & ptyfd is indexed at 0
  *ptyfd = 0;
  strlcpy(namebuf, "console", namebuflen);
  return 1;
  //return 0;
   
#endif
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

void
pty_release(const char *tty)
{
#ifndef WIN32_FIXME
#if !defined(__APPLE_PRIVPTY__) && !defined(HAVE_OPENPTY)
	if (chown(tty, (uid_t) 0, (gid_t) 0) < 0)
		error("chown %.100s 0 0 failed: %.100s", tty, strerror(errno));
	if (chmod(tty, (mode_t) 0666) < 0)
		error("chmod %.100s 0666 failed: %.100s", tty, strerror(errno));
#endif /* !__APPLE_PRIVPTY__ && !HAVE_OPENPTY */
#endif
}

/* Makes the tty the process's controlling tty and sets it to sane modes. */

void
pty_make_controlling_tty(int *ttyfd, const char *tty)
{
#ifndef WIN32_FIXME
	int fd;

#ifdef _UNICOS
	if (setsid() < 0)
		error("setsid: %.100s", strerror(errno));

	fd = open(tty, O_RDWR|O_NOCTTY);
	if (fd != -1) {
		signal(SIGHUP, SIG_IGN);
		ioctl(fd, TCVHUP, (char *)NULL);
		signal(SIGHUP, SIG_DFL);
		setpgid(0, 0);
		close(fd);
	} else {
		error("Failed to disconnect from controlling tty.");
	}

	debug("Setting controlling tty using TCSETCTTY.");
	ioctl(*ttyfd, TCSETCTTY, NULL);
	fd = open("/dev/tty", O_RDWR);
	if (fd < 0)
		error("%.100s: %.100s", tty, strerror(errno));
	close(*ttyfd);
	*ttyfd = fd;
#else /* _UNICOS */

	/* First disconnect from the old controlling tty. */
#ifdef TIOCNOTTY
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	if (fd >= 0) {
		(void) ioctl(fd, TIOCNOTTY, NULL);
		close(fd);
	}
#endif /* TIOCNOTTY */
	if (setsid() < 0)
		error("setsid: %.100s", strerror(errno));

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	if (fd >= 0) {
		error("Failed to disconnect from controlling tty.");
		close(fd);
	}
	/* Make it our controlling tty. */
#ifdef TIOCSCTTY
	debug("Setting controlling tty using TIOCSCTTY.");
	if (ioctl(*ttyfd, TIOCSCTTY, NULL) < 0)
		error("ioctl(TIOCSCTTY): %.100s", strerror(errno));
#endif /* TIOCSCTTY */
#ifdef NEED_SETPGRP
	if (setpgrp(0,0) < 0)
		error("SETPGRP %s",strerror(errno));
#endif /* NEED_SETPGRP */
	fd = open(tty, O_RDWR);
	if (fd < 0) {
		error("%.100s: %.100s", tty, strerror(errno));
	} else {
		close(fd);
	}
	/* Verify that we now have a controlling tty. */
	fd = open(_PATH_TTY, O_WRONLY);
	if (fd < 0)
		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    strerror(errno));
	else
		close(fd);
#endif /* _UNICOS */
#endif
}

/* Changes the window size associated with the pty. */

void
pty_change_window_size(int ptyfd, u_int row, u_int col,
	u_int xpixel, u_int ypixel)
{
#ifndef WIN32_FIXME
	struct winsize w;

	/* may truncate u_int -> u_short */
	w.ws_row = row;
	w.ws_col = col;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(void) ioctl(ptyfd, TIOCSWINSZ, &w);
#else
	extern HANDLE hConsole ;
	hConsole = ptyfd;
	ConSetScreenSize( col, row );
#endif
}

void
pty_setowner(struct passwd *pw, const char *tty)
{
#ifndef WIN32_FIXME
	struct group *grp;
	gid_t gid;
	mode_t mode;
	struct stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	gid = (grp != NULL) ? grp->gr_gid : pw->pw_gid;
	mode = (grp != NULL) ? 0620 : 0600;

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	if (stat(tty, &st))
		fatal("stat(%.100s) failed: %.100s", tty,
		    strerror(errno));

#ifdef WITH_SELINUX
	ssh_selinux_setup_pty(pw->pw_name, tty);
#endif

	if (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		if (chown(tty, pw->pw_uid, gid) < 0) {
			if (errno == EROFS &&
			    (st.st_uid == pw->pw_uid || st.st_uid == 0))
				debug("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
			else
				fatal("chown(%.100s, %u, %u) failed: %.100s",
				    tty, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));
		}
	}

	if ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != mode) {
		if (chmod(tty, mode) < 0) {
			if (errno == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0)
				debug("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
			else
				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    tty, (u_int)mode, strerror(errno));
		}
	}
#endif
}
