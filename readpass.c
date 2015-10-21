/* $OpenBSD: readpass.c,v 1.50 2014/02/02 03:44:31 djm Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_PATHS_H
# include <paths.h>
#endif
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "misc.h"
#include "pathnames.h"
#include "log.h"
#include "ssh.h"
#include "uidswap.h"

#ifdef WIN32_FIXME

  #include <conio.h>
  #include <sys/socket.h>
  
  extern int PassInputFd;
  extern int PassOutputFd;
  extern int PassErrorFd;

#endif

static char *
ssh_askpass(char *askpass, const char *msg)
{
#ifndef WIN32_FIXME

  /*
   * Original openssh code.
   */
	pid_t pid, ret;
	size_t len;
	char *pass;
	int p[2], status;
	char buf[1024];
	void (*osigchld)(int);

	if (fflush(stdout) != 0)
		error("ssh_askpass: fflush: %s", strerror(errno));
	if (askpass == NULL)
		fatal("internal error: askpass undefined");
	if (pipe(p) < 0) {
		error("ssh_askpass: pipe: %s", strerror(errno));
		return NULL;
	}
	osigchld = signal(SIGCHLD, SIG_DFL);
	if ((pid = fork()) < 0) {
		error("ssh_askpass: fork: %s", strerror(errno));
		signal(SIGCHLD, osigchld);
		return NULL;
	}
	if (pid == 0) {
		permanently_drop_suid(getuid());
		close(p[0]);
		if (dup2(p[1], STDOUT_FILENO) < 0)
			fatal("ssh_askpass: dup2: %s", strerror(errno));
		execlp(askpass, askpass, msg, (char *) 0);
		fatal("ssh_askpass: exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	do {
		ssize_t r = read(p[0], buf + len, sizeof(buf) - 1 - len);

		if (r == -1 && errno == EINTR)
			continue;
		if (r <= 0)
			break;
		len += r;
	} while (sizeof(buf) - 1 - len > 0);
	buf[len] = '\0';

	close(p[0]);
	while ((ret = waitpid(pid, &status, 0)) < 0)
		if (errno != EINTR)
			break;
	signal(SIGCHLD, osigchld);
	if (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, sizeof(buf));
		return NULL;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, sizeof(buf));
	return pass;
#else

  /*
   * Win32 code.
   */
   
  HANDLE g_hChildStd_OUT_Rd = NULL;
  HANDLE g_hChildStd_OUT_Wr = NULL;

  SECURITY_ATTRIBUTES saAttr; 
  
  PROCESS_INFORMATION piProcInfo; 
  
  STARTUPINFO siStartInfo;
  
  BOOL bSuccess = FALSE;
  
  DWORD dwRead; 
  
  CHAR buf[1024]; 
  
  int length = 8192;
  
  CHAR command[length];
  
  char *pass = NULL;
  
  saAttr.nLength              = sizeof(SECURITY_ATTRIBUTES); 
  saAttr.bInheritHandle       = TRUE; 
  saAttr.lpSecurityDescriptor = NULL; 

  if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
  {
    DWORD dw = GetLastError();
 
    error("ssh_askpass: failed to create pipe: %d", (int) dw);
    
    return NULL;
  }

  if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
  {
    DWORD dw = GetLastError();
    
    error("ssh_askpass: failed to set pipe for inherit: %d", (int) dw);
    
    return NULL;
  }

  snprintf(command, length, "\"%s\" \"%s\"", askpass, msg);

  ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
  ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
  
  siStartInfo.cb         = sizeof(STARTUPINFO); 
  siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
  siStartInfo.dwFlags   |= STARTF_USESTDHANDLES;

  bSuccess = CreateProcess(NULL, command, NULL, NULL, TRUE, 0,
                               NULL, NULL, &siStartInfo, &piProcInfo);
  
  if (!bSuccess)
  {
    DWORD dw = GetLastError();

    error("ssh_askpass: CreateProcess failed: %d", (int) dw);
    
    return NULL;
  }
  else 
  {
    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);
  }
    
  if (!CloseHandle(g_hChildStd_OUT_Wr)) 
  {
    DWORD dw = GetLastError();

    error("ssh_askpass: failed to close write end of pipe: %d", (int) dw);
    
    return NULL;
  }

  bSuccess = ReadFile(g_hChildStd_OUT_Rd, buf, 1024, &dwRead, NULL);
  
  if (!bSuccess)
  {
    DWORD dw = GetLastError();
   
    error("ssh_askpass: failed to read from child: %d", (int) dw);
    
    return NULL;
  }  
  
  if (dwRead == 0)
  {
    error("ssh_askpass: read 0 bytes from child");
    
    return NULL;
  }    

  buf[strcspn(buf, "\r\n")] = '\0';

  pass = xstrdup(buf);
  
  memset(buf, 0, sizeof(buf));
  
  return pass;
  
#endif
}

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is available
 */
char *
read_passphrase(const char *prompt, int flags)
{
	
#ifndef WIN32_FIXME

  /*
   * Original openssh code.
   */

	char *askpass = NULL, *ret, buf[1024];
	int rppflags, use_askpass = 0, ttyfd;

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	if (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	else if (flags & RP_ALLOW_STDIN) {
		if (!isatty(STDIN_FILENO)) {
			debug("read_passphrase: stdin is not a tty");
			use_askpass = 1;
		}
	} else {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		if (ttyfd >= 0)
			close(ttyfd);
		else {
			debug("read_passphrase: can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

	if ((flags & RP_USE_ASKPASS) && getenv("DISPLAY") == NULL)
		return (flags & RP_ALLOW_EOF) ? NULL : xstrdup("");

	if (use_askpass && getenv("DISPLAY")) {
		if (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		else
			askpass = _PATH_SSH_ASKPASS_DEFAULT;
		if ((ret = ssh_askpass(askpass, prompt)) == NULL)
			if (!(flags & RP_ALLOW_EOF))
				return xstrdup("");
		return ret;
	}

	if (readpassphrase(prompt, buf, sizeof buf, rppflags) == NULL) {
		if (flags & RP_ALLOW_EOF)
			return NULL;
		return xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, sizeof(buf));
	return ret;
	

  /*
   * Win32 code.
   */
   
#else

  char *askpass  = NULL;
  char *ret      = NULL;
  char buf[1024] = {0};

  DWORD mode;
        
  size_t len = 0;

  int retr = 0;
        
  if (getenv(SSH_ASKPASS_ENV))
  {
    askpass = getenv(SSH_ASKPASS_ENV);
    
    if ((ret = ssh_askpass(askpass, prompt)) == NULL)
    {
      if (!(flags & RP_ALLOW_EOF))
      {
        return xstrdup("");
      }
    }
   
    return ret;                
  }        

  /*
   * Show prompt for user.
   */

  _write(PassErrorFd, prompt, strlen(prompt));

  len = retr = 0;
  int bufsize = sizeof(buf);

	while (_kbhit())
		_getch();

	while ( len < bufsize ) {

	 	buf[len] = (unsigned char) _getch() ;


		if ( buf[len] == '\r' ) {
			if (_kbhit() )
				_getch(); // read linefeed if its there
			break;
		}
		else if ( buf[len] == '\n' ) {
			break;
		}
		else if ( buf[len] == '\b' ) { // backspace
			if (len > 0 )
				len--; // overwrite last character
		}
		else {

			//_putch( (int) '*' ); // show a star in place of what is typed
			len++; // keep reading in the loop
		}
	}

	buf[len] = '\0' ; // get rid of the cr/lf
	_write(PassErrorFd,"\n", strlen("\n")); // show a newline as we do not echo password or the line

  ret = xstrdup(buf);

  memset(buf, 'x', sizeof(buf));
  
  return ret;
  
#endif

}

int
ask_permission(const char *fmt, ...)
{
	va_list args;
	char *p, prompt[1024];
	int allowed = 0;

	va_start(args, fmt);
	vsnprintf(prompt, sizeof(prompt), fmt, args);
	va_end(args);

	p = read_passphrase(prompt, RP_USE_ASKPASS|RP_ALLOW_EOF);
	if (p != NULL) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		if (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		free(p);
	}

	return (allowed);
}
