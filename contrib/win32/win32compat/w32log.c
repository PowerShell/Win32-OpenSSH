/*
* Copyright (c) 2016 Microsoft Corp.
* All rights reserved
*
* Implementation of sys log for windows:
* openlog(), closelog, syslog
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
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

#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "inc\syslog.h"
#include "misc_internal.h"

#define MSGBUFSIZ 1024
static int logfd = -1;

void
openlog(char *ident, unsigned int option, int facility)
{
	if (logfd != -1 || ident == NULL)
		return;

	wchar_t path[PATH_MAX], log_file[PATH_MAX + 12];
	if (GetModuleFileNameW(NULL, path, PATH_MAX) == 0)
		return;

	path[PATH_MAX - 1] = '\0';

	/* split path root and module */
	{
		wchar_t* tail = path + wcslen(path), *p;
		while (tail > path && *tail != L'\\' && *tail != L'/')
			tail--;

		memcpy(log_file, path, (tail - path) * sizeof(wchar_t));
		p = log_file + (tail - path);
		memcpy(p, L"\\logs\\", 12);
		p += 6;
		memcpy(p, tail + 1, (wcslen(tail + 1) - 3) * sizeof(wchar_t));
		p += wcslen(tail + 1) - 3;
		memcpy(p, L"log\0", 8);
	}

	logfd = _wopen(log_file, O_WRONLY | O_CREAT | O_APPEND, S_IREAD | S_IWRITE);
	if (logfd != -1)
		SetHandleInformation((HANDLE)_get_osfhandle(logfd), HANDLE_FLAG_INHERIT, 0);
}

void
closelog(void)
{
	/*NOOP*/
}

void
syslog(int priority, const char *format, const char *formatBuffer)
{
	char msgbufTimestamp[MSGBUFSIZ];
	SYSTEMTIME st;

	if (logfd == -1)
		return;

	GetLocalTime(&st);
	snprintf(msgbufTimestamp, sizeof msgbufTimestamp, "%d %02d:%02d:%02d %03d %s\n",
		GetCurrentProcessId(), st.wHour, st.wMinute, st.wSecond,
		st.wMilliseconds, formatBuffer);
	_write(logfd, msgbufTimestamp, strlen(msgbufTimestamp));
}