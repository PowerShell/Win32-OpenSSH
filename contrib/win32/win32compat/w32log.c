
#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "inc\syslog.h"

#define MSGBUFSIZ 1024
static int logfd = -1;

void openlog(char *ident, unsigned int option, int facility) {
	if ((logfd == -1) && (ident != NULL)) {
		wchar_t path[MAX_PATH], log_file[MAX_PATH + 12];
		if (GetModuleFileNameW(NULL, path, MAX_PATH) == 0)
			return;
		path[MAX_PATH - 1] = '\0';
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
		logfd = _wopen(log_file, O_WRONLY | O_CREAT | O_APPEND,
			S_IREAD | S_IWRITE);
		if (logfd != -1)
			SetHandleInformation((HANDLE)_get_osfhandle(logfd),
			HANDLE_FLAG_INHERIT, 0);
	}
}

void closelog(void) {
	//NOOP
}

void 
syslog(int priority, const char *format, const char *formatBuffer) {
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