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
#include <stdio.h>
#include "inc/sys/stat.h"

#include "inc\syslog.h"
#include "misc_internal.h"

#define MSGBUFSIZ 1024
static int logfd = -1;

/*
 * open a log file using the name of executable under logs folder
 * Ex. if called from c:\windows\system32\openssh\sshd.exe
 * logfile - c:\windows\system32\openssh\logs\sshd.log
 */
void
openlog(char *ident, unsigned int option, int facility)
{
	wchar_t *logs_dir = L"\\logs\\";
	if (logfd != -1 || ident == NULL)
		return;

	wchar_t path[PATH_MAX] = { 0 }, log_file[PATH_MAX + 12] = { 0 };
	errno_t r = 0;
	if (GetModuleFileNameW(NULL, path, PATH_MAX) == 0)
		return;

	path[PATH_MAX - 1] = L'\0';

	if (wcsnlen(path, MAX_PATH) > MAX_PATH - wcslen(logs_dir))
		return;

	/* split path root and module */
	{
		wchar_t* tail = path + wcsnlen(path, MAX_PATH);
		while (tail > path && *tail != L'\\' && *tail != L'/')
			tail--;

		if (((r = wcsncat_s(log_file, PATH_MAX + 12, path, tail - path)) != 0 ) ||
			(r = wcsncat_s(log_file, PATH_MAX + 12, logs_dir, 6) != 0 )||
			(r = wcsncat_s(log_file, PATH_MAX + 12, tail + 1, wcslen(tail + 1) - 3) != 0 ) ||
			(r = wcsncat_s(log_file, PATH_MAX + 12, L"log", 3) != 0 ))
			return;
	}
	
	
	errno_t err = _wsopen_s(&logfd, log_file, O_WRONLY | O_CREAT | O_APPEND, SH_DENYNO, S_IREAD | S_IWRITE);
		
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
	int r;

	if (logfd == -1)
		return;

	GetLocalTime(&st);
	r = _snprintf_s(msgbufTimestamp, sizeof(msgbufTimestamp), _TRUNCATE, "%d %02d:%02d:%02d:%03d %s\n",
		GetCurrentProcessId(), st.wHour, st.wMinute, st.wSecond,
		st.wMilliseconds, formatBuffer);
	if (r == -1) {
		_write(logfd, "_snprintf_s failed.", 30);
		return;
	}
	msgbufTimestamp[strnlen(msgbufTimestamp, MSGBUFSIZ)] = '\0';
	_write(logfd, msgbufTimestamp, (unsigned int)strnlen(msgbufTimestamp, MSGBUFSIZ));
}