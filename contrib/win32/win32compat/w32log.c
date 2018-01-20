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
#include "inc\utf.h"

#define MSGBUFSIZ 1024
static int logfd = -1;

/*
 * log file location will be - "%programData%\\openssh\\logs\\<module_name>.log"
 */
void
openlog(char *ident, unsigned int option, int facility)
{	
	if (logfd != -1 || ident == NULL)
		return;

	wchar_t *logs_dir = L"\\logs\\";
	wchar_t module_path[PATH_MAX] = { 0 }, log_file[PATH_MAX + 12] = { 0 };

	if (GetModuleFileNameW(NULL, module_path, PATH_MAX) == 0)
		return;

	if (wcsnlen(module_path, MAX_PATH) > MAX_PATH - wcslen(logs_dir))
		return;

	/* split path root and module */
	{
		wchar_t* tail = module_path + wcsnlen(module_path, MAX_PATH);
		while (tail > module_path && *tail != L'\\' && *tail != L'/')
			tail--;
		
		char ssh_cfg_path[PATH_MAX] = {0 ,};
		strcat_s(ssh_cfg_path, _countof(ssh_cfg_path), get_program_data_path()); /* "%programData%" */
		strcat_s(ssh_cfg_path, _countof(ssh_cfg_path), "\\ssh"); /* "%programData%\\ssh" */

		wchar_t* ssh_root_path_w = utf8_to_utf16(ssh_cfg_path); /* "%programData%\\ssh" */

		if ((wcsncat_s(log_file, PATH_MAX + 12, ssh_root_path_w, wcslen(ssh_root_path_w)) != 0) ||
		    (wcsncat_s(log_file, PATH_MAX + 12, logs_dir, 6) != 0) ||
		    (wcsncat_s(log_file, PATH_MAX + 12, tail + 1, wcslen(tail + 1) - 3) != 0 ) ||
		    (wcsncat_s(log_file, PATH_MAX + 12, L"log", 3) != 0))
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
	r = _snprintf_s(msgbufTimestamp, sizeof(msgbufTimestamp), _TRUNCATE, "%d %04d-%02d-%02d %02d:%02d:%02d.%03d %s\n",
		GetCurrentProcessId(), st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
		st.wMilliseconds, formatBuffer);
	if (r == -1) {
		_write(logfd, "_snprintf_s failed.", 30);
		return;
	}
	msgbufTimestamp[strnlen(msgbufTimestamp, MSGBUFSIZ)] = '\0';
	_write(logfd, msgbufTimestamp, (unsigned int)strnlen(msgbufTimestamp, MSGBUFSIZ));
}
