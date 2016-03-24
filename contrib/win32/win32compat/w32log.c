
#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "inc\syslog.h"

#define MSGBUFSIZ 1024
static int logfd = -1;

void openlog(char *ident, unsigned int option, int facility) {
	if ((logfd == -1) && (ident != NULL)) {
		char path[MAX_PATH];
		GetModuleFileNameA(NULL, path, MAX_PATH);
		path[MAX_PATH - 1] = '\0';
		memcpy(path + strlen(path) - 3, "log", 3);
		logfd = _open(path, O_WRONLY | O_CREAT | O_APPEND,
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