/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Copyright(c) 2016 Microsoft Corp.
* All rights reserved
*
* Misc Unix POSIX routine implementations for Windows
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met :
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and / or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES(INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <Windows.h>
#include <stdio.h>
#include <time.h>
#include <Shlwapi.h>
#include <conio.h>
#include <LM.h>
#include <Sddl.h>
#include <Aclapi.h>

#include "inc\unistd.h"
#include "inc\sys\stat.h"
#include "inc\sys\statvfs.h"
#include "inc\sys\time.h"
#include "misc_internal.h"
#include "inc\dlfcn.h"
#include "inc\dirent.h"
#include "inc\sys\types.h"
#include "inc\sys\ioctl.h"
#include "inc\fcntl.h"
#include "inc\utf.h"
#include "signal_internal.h"
#include "debug.h"
#include "w32fd.h"
#include "inc\string.h"
#include "inc\grp.h"

static char* s_programdir = NULL;

/* Maximum reparse buffer info size. The max user defined reparse 
 * data is 16KB, plus there's a header. 
 */
#define MAX_REPARSE_SIZE 17000 
#define IO_REPARSE_TAG_SYMBOLIC_LINK IO_REPARSE_TAG_RESERVED_ZERO 
#define IO_REPARSE_TAG_MOUNT_POINT (0xA0000003L) /* winnt ntifs */
#define IO_REPARSE_TAG_HSM (0xC0000004L) /* winnt ntifs */
#define IO_REPARSE_TAG_SIS (0x80000007L) /* winnt ntifs */
#define REPARSE_MOUNTPOINT_HEADER_SIZE 8

 /* Difference in us between UNIX Epoch and Win32 Epoch */
#define EPOCH_DELTA_US  116444736000000000ULL
#define RATE_DIFF 10000000ULL /* 1000 nsecs */

typedef struct _REPARSE_DATA_BUFFER {
	ULONG  ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR PathBuffer[1];
		} SymbolicLinkReparseBuffer;

		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR PathBuffer[1];
		} MountPointReparseBuffer;

		struct {
			UCHAR  DataBuffer[1];
		} GenericReparseBuffer;
	};
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

/* Windows CRT defines error string messages only till 43 in errno.h
 * This is an extended list that defines messages for EADDRINUSE through EWOULDBLOCK
 */
char* _sys_errlist_ext[] = {
	"Address already in use",				/* EADDRINUSE      100 */
	"Address not available",				/* EADDRNOTAVAIL   101 */
	"Address family not supported",				/* EAFNOSUPPORT    102 */
	"Connection already in progress",			/* EALREADY        103 */
	"Bad message",						/* EBADMSG         104 */
	"Operation canceled",					/* ECANCELED       105 */
	"Connection aborted",					/* ECONNABORTED    106 */
	"Connection refused",					/* ECONNREFUSED    107 */
	"Connection reset",					/* ECONNRESET      108 */
	"Destination address required",				/* EDESTADDRREQ    109 */
	"Host is unreachable",					/* EHOSTUNREACH    110 */
	"Identifier removed",					/* EIDRM           111 */
	"Operation in progress",				/* EINPROGRESS     112 */
	"Socket is connected",					/* EISCONN         113 */
	"Too many levels of symbolic links",			/* ELOOP           114 */
	"Message too long",					/* EMSGSIZE        115 */
	"Network is down",					/* ENETDOWN        116 */
	"Connection aborted by network",			/* ENETRESET       117 */
	"Network unreachable",					/* ENETUNREACH     118 */
	"No buffer space available",				/* ENOBUFS         119 */
	"No message is available on the STREAM head read queue",/* ENODATA         120 */
	"Link has been severed",				/* ENOLINK         121 */
	"No message of the desired type",			/* ENOMSG          122 */
	"Protocol not available",				/* ENOPROTOOPT     123 */
	"No STREAM resources",					/* ENOSR           124 */
	"Not a STREAM",						/* ENOSTR          125 */
	"The socket is not connected",				/* ENOTCONN        126 */
	"enotrecoverable",					/* ENOTRECOVERABLE 127 */
	"Not a socket",						/* ENOTSOCK        128 */
	"Operation not supported",				/* ENOTSUP         129 */
	"Operation not supported on socket",			/* EOPNOTSUPP      130 */
	"eother",						/* EOTHER          131 */
	"Value too large to be stored in data type",		/* EOVERFLOW       132 */
	"eownerdead",						/* EOWNERDEAD      133 */
	"Protocol error",					/* EPROTO          134 */
	"Protocol not supported",				/* EPROTONOSUPPORT 135 */
	"Protocol wrong type for socket",			/* EPROTOTYPE      136 */
	"Timer expired",					/* ETIME           137 */
	"Connection timed out",					/* ETIMEDOUT       138 */
	"Text file busy",					/* ETXTBSY         139 */
	"Operation would block"					/* EWOULDBLOCK     140 */
};

int
usleep(unsigned int useconds)
{
	Sleep(useconds / 1000);
	return 1;
}

int
nanosleep(const struct timespec *req, struct timespec *rem)
{
	HANDLE timer;
	LARGE_INTEGER li;

	if (req->tv_sec < 0 || req->tv_nsec < 0 || req->tv_nsec > 999999999) {
		errno = EINVAL;
		return -1;
	}

	if ((timer = CreateWaitableTimerW(NULL, TRUE, NULL)) == NULL) {
		errno = EFAULT;
		return -1;
	}

	li.QuadPart = -req->tv_nsec;
	if (!SetWaitableTimer(timer, &li, 0, NULL, NULL, FALSE)) {
		CloseHandle(timer);
		errno = EFAULT;
		return -1;
	}

	/* TODO - use wait_for_any_event, since we want to wake up on interrupts*/
	switch (WaitForSingleObject(timer, INFINITE)) {
	case WAIT_OBJECT_0:
		CloseHandle(timer);
		return 0;
	default:
		errno = EFAULT;
		return -1;
	}
}

/* This routine is contributed by  * Author: NoMachine <developers@nomachine.com>
 * Copyright (c) 2009, 2010 NoMachine
 * All rights reserved
 */
int
gettimeofday(struct timeval *tv, void *tz)
{
	union {
		FILETIME ft;
		unsigned long long ns;
	} timehelper;
	unsigned long long us;

	/* Fetch time since Jan 1, 1601 in 100ns increments */
	GetSystemTimeAsFileTime(&timehelper.ft);	

	/* Remove the epoch difference */
	us = timehelper.ns - EPOCH_DELTA_US;

	/* Stuff result into the timeval */
	tv->tv_sec = (long)(us / RATE_DIFF);
	tv->tv_usec = (long)(us % RATE_DIFF);

	return 0;
}

void
explicit_bzero(void *b, size_t len)
{
	SecureZeroMemory(b, len);
}

HMODULE
dlopen(const char *filename, int flags)
{
	return LoadLibraryA(filename);
}

int
dlclose(HMODULE handle)
{
	FreeLibrary(handle);
	return 0;
}

FARPROC 
dlsym(HMODULE handle, const char *symbol)
{
	return GetProcAddress(handle, symbol);
}


/*fopen on Windows to mimic https://linux.die.net/man/3/fopen
* only r, w, a are supported for now
*/
FILE *
w32_fopen_utf8(const char *path, const char *mode)
{
	wchar_t wpath[PATH_MAX], wmode[5];
	FILE* f;
	char utf8_bom[] = { 0xEF,0xBB,0xBF };
	char first3_bytes[3];
	int status = 1;
	errno_t r = 0;

	if (mode[1] != '\0') {
		errno = ENOTSUP;
		return NULL;
	}

	if(NULL == path) { 
		errno = EINVAL;
		debug3("fopen - ERROR:%d", errno);
		return NULL; 
	}

	/* if opening null device, point to Windows equivalent */
	if (0 == strncmp(path, NULL_DEVICE, strlen(NULL_DEVICE)+1)) {
		if ((r = wcsncpy_s(wpath, PATH_MAX, L"NUL", 3)) != 0) {
			debug3("wcsncpy_s failed with error: %d.", r);
			return NULL;
		}
	}
	else
		status = MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, PATH_MAX);

	if ((0 == status) ||
	    (0 == MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, 5))) {
		errno = EFAULT;
		debug3("WideCharToMultiByte failed for %c - ERROR:%d", path, GetLastError());
		return NULL;
	}

	if ((_wfopen_s(&f, wpath, wmode) != 0) || (f == NULL)) {
		debug3("Failed to open file:%s error:%d", path, errno);
		return NULL;
	}		

	/* BOM adjustments for file streams*/
	if (mode[0] == 'w' && fseek(f, 0, SEEK_SET) != EBADF) {
		/* write UTF-8 BOM - should we ?*/
		/*if (fwrite(utf8_bom, sizeof(utf8_bom), 1, f) != 1) {
			fclose(f);
			return NULL;
		}*/

	} else if (mode[0] == 'r' && fseek(f, 0, SEEK_SET) != EBADF) {
		/* read out UTF-8 BOM if present*/
		if (fread(first3_bytes, 3, 1, f) != 1 ||
			memcmp(first3_bytes, utf8_bom, 3) != 0) {
			fseek(f, 0, SEEK_SET);
		}
	}

	return f;
}

/*
* fgets to support Unicode input 
* each UTF-16 char may bloat up to 4 utf-8 chars. We cannot determine if the length of 
* input unicode string until it is readed and converted to utf8 string.
* There is a risk to miss on unicode char when last unicode char read from console
* does not fit the remain space in str. use cauciously. 
*/
char*
 w32_fgets(char *str, int n, FILE *stream) {
	if (!str || !n || !stream) return NULL;

	HANDLE h = (HANDLE)_get_osfhandle(_fileno(stream));
	wchar_t* str_w = NULL;
	char *ret = NULL, *str_tmp = NULL, *cp = NULL;
	int actual_read = 0;
	errno_t r = 0;

	if (h != NULL && h != INVALID_HANDLE_VALUE
	    && GetFileType(h) == FILE_TYPE_CHAR) {

		/* Allocate memory for one UTF-16 char (up to 4 bytes) and a terminate char (\0) */
		if ((str_w = malloc(3 * sizeof(wchar_t))) == NULL) {
			errno = ENOMEM;
			goto cleanup;
		}
		/* prepare for Unicode input */
		_setmode(_fileno(stream), O_U16TEXT);
		cp = str;
		/*
		* each UTF-16 char may bloat up to 4 utf-8 chars
		* read one wide chars at time from console and convert it to utf8
		* stop reading until reach '\n' or the converted utf8 string length is n-1
		*/
		do {
			if (str_tmp)
				free(str_tmp);			
			if (fgetws(str_w, 2, stream) == NULL)
				goto cleanup;
			if ((str_tmp = utf16_to_utf8(str_w)) == NULL) {
				debug3("utf16_to_utf8 failed!");
				errno = ENOMEM;
				goto cleanup;
			}
			
			if((actual_read + strlen(str_tmp)) >= n)
				break;
			if ((r = memcpy_s(cp, n - actual_read, str_tmp, strlen(str_tmp))) != 0) {
				debug3("memcpy_s failed with error: %d.", r);
				goto cleanup;
			}
			actual_read += (int)strlen(str_tmp);
			cp += strlen(str_tmp);
			
		} while ((actual_read < n - 1) && *str_tmp != '\n');
		*cp = '\0';

		if (actual_read > n - 1) {
			/* shouldn't happen. but handling in case */
			debug3("actual_read %d exceeds the limit:%d", actual_read, n-1);
			errno = EINVAL;
			goto cleanup;
		}		
		ret = str;
	}
	else
		ret = fgets(str, n, stream);
cleanup:
	if (str_w)
		free(str_w);
	if (str_tmp)
		free(str_tmp);
	return ret;
}

/* Account for differences between Unix's and Windows versions of setvbuf */
int 
w32_setvbuf(FILE *stream, char *buffer, int mode, size_t size) {
	
	/* BUG: setvbuf on console stream interferes with Unicode I/O	*/
	HANDLE h = (HANDLE)_get_osfhandle(_fileno(stream));
	
	if (h != NULL && h != INVALID_HANDLE_VALUE
	    && GetFileType(h) == FILE_TYPE_CHAR)
		return 0;

	/* BUG: setvbuf on file stream is interfering with w32_fopen */
	/* short circuit for now*/
	return 0;

	/*
	 * if size is 0, set no buffering. 
	 * Windows does not differentiate __IOLBF and _IOFBF
	 */
	if (size == 0)
		return setvbuf(stream, NULL, _IONBF, 0);
	else
		return setvbuf(stream, buffer, mode, size);
}

char *
w32_programdir()
{
	wchar_t* wpgmptr;

	if (s_programdir != NULL)
		return s_programdir;

	if (_get_wpgmptr(&wpgmptr) != 0)
		return NULL;

	if ((s_programdir = utf16_to_utf8(wpgmptr)) == NULL)
		return NULL;

	/* null terminate after directory path */
	char* tail = s_programdir + strlen(s_programdir);
	while (tail > s_programdir && *tail != '\\' && *tail != '/')
		tail--;

	if (tail > s_programdir)
		*tail = '\0';
	else
		*tail = '.'; /* current directory */

	return s_programdir;
}

int
daemon(int nochdir, int noclose)
{
	FreeConsole();
	return 0;
}

int
w32_ioctl(int d, int request, ...)
{
	va_list valist;
	va_start(valist, request);

	switch (request) {
	case TIOCGWINSZ: {
		struct winsize* wsize = va_arg(valist, struct winsize*);
		CONSOLE_SCREEN_BUFFER_INFO c_info;
		if (wsize == NULL || !GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &c_info)) {
			errno = EINVAL;
			return -1;
		}

		wsize->ws_col = c_info.dwSize.X;
		wsize->ws_row = c_info.srWindow.Bottom - c_info.srWindow.Top + 1;
		wsize->ws_xpixel = 640;
		wsize->ws_ypixel = 480;

		return 0;
	}
	default:
		errno = ENOTSUP;
		return -1;
	}
}

/* p should be at least 12 bytes long*/
void
strmode(mode_t mode, char *p)
{
	/* print type */
	switch (mode & S_IFMT) {
	case S_IFDIR:			/* directory */
		*p++ = 'd';
		break;
	case S_IFCHR:			/* character special */
		*p++ = 'c';
		break;
	case S_IFREG:			/* regular */
		*p++ = '-';
		break;
#ifdef S_IFSOCK
	case S_IFSOCK:			/* socket */
		*p++ = 's';
		break;
#endif
	case _S_IFIFO:			/* fifo */
		*p++ = 'p';
		break;
	default:			/* unknown */
		*p++ = '?';
		break;
	}

	/* group, other are not applicable on the windows */

	/* usr */
	if (mode & S_IREAD)
		*p++ = 'r';
	else
		*p++ = '-';
	if (mode & S_IWRITE)
		*p++ = 'w';
	else
		*p++ = '-';
	if (mode & S_IEXEC)
		*p++ = 'x';
	else
		*p++ = '-';

	const char *permissions = "****** ";	
	for(int i = 0; i < strlen(permissions); i++)
		*p++ = permissions[i];
	
	*p = '\0';
}

int
w32_chmod(const char *pathname, mode_t mode)
{
	int ret;
	wchar_t *resolvedPathName_utf16 = utf8_to_utf16(sanitized_path(pathname));
	if (resolvedPathName_utf16 == NULL) {
		errno = ENOMEM;
		return -1;
	}
	ret = _wchmod(resolvedPathName_utf16, mode);
	free(resolvedPathName_utf16);
	return ret;
}

int
w32_chown(const char *pathname, unsigned int owner, unsigned int group)
{
	/* TODO - implement this */
	errno = EOPNOTSUPP;
	return -1;
}

/* Convert a UNIX time into a Windows file time */
void
unix_time_to_file_time(ULONG t, LPFILETIME pft)
{
	ULONGLONG ull;
	ull = UInt32x32To64(t, RATE_DIFF) + EPOCH_DELTA_US;

	pft->dwLowDateTime = (DWORD)ull;
	pft->dwHighDateTime = (DWORD)(ull >> 32);
}

/* Convert a Windows file time into a UNIX time_t */
void
file_time_to_unix_time(const LPFILETIME pft, time_t * winTime)
{
	*winTime = ((long long)pft->dwHighDateTime << 32) + pft->dwLowDateTime;
	*winTime -= EPOCH_DELTA_US;
	*winTime /= RATE_DIFF;		 /* Nano to seconds resolution */
}

static BOOL
is_root_or_empty(wchar_t * path)
{
	wchar_t * path_start;
	int len;
	if (!path) 
		return FALSE;
	len = (int)wcslen(path);
	if((len > 1) && __ascii_iswalpha(path[0]) && path[1] == L':')
		path_start = path + 2;
	else
		path_start = path;
	/*path like  c:\, /, \ are root directory*/
	if ((*path_start == L'\0') || ((*path_start == L'\\' || *path_start == L'/' ) && path_start[1] == L'\0'))
		return TRUE;
	return FALSE;
}

static BOOL
has_executable_extension(wchar_t * path)
{
	wchar_t * last_dot;
	if (!path)
		return FALSE;

	last_dot = wcsrchr(path, L'.');
	if (!last_dot)
		return FALSE;
	if (_wcsnicmp(last_dot, L".exe", 4) != 0 && _wcsnicmp(last_dot, L".cmd", 4) != 0 &&
	_wcsnicmp(last_dot, L".bat", 4) != 0 && _wcsnicmp(last_dot, L".com", 4) != 0)
		return FALSE; 
	return TRUE;
}

int
file_attr_to_st_mode(wchar_t * path, DWORD attributes)
{
	int mode = S_IREAD;
	BOOL isReadOnlyFile = FALSE;
	if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 || is_root_or_empty(path))
		mode |= S_IFDIR | _S_IEXEC;
	else {
		mode |= S_IFREG;
		/* See if file appears to be an executable by checking its extension */
		if (has_executable_extension(path))
			mode |= _S_IEXEC;

	}
	if (!(attributes & FILE_ATTRIBUTE_READONLY))
		mode |= S_IWRITE;
	else
		isReadOnlyFile = TRUE;

	// We don't populate the group permissions as its not applicable to windows OS.
	// propagate owner read/write/execute bits to other fields.	
	mode |= get_others_file_permissions(path, isReadOnlyFile);

	return mode;
}

static int
settimes(wchar_t * path, FILETIME *cretime, FILETIME *acttime, FILETIME *modtime)
{
	HANDLE handle;
	handle = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (handle == INVALID_HANDLE_VALUE) {
		/* TODO - convert Win32 error to errno */
		errno = GetLastError();
		debug3("w32_settimes - CreateFileW ERROR:%d", errno);
		return -1;
	}

	if (SetFileTime(handle, cretime, acttime, modtime) == 0) {
		errno = GetLastError();
		debug3("w32_settimes - SetFileTime ERROR:%d", errno);
		CloseHandle(handle);
		return -1;
	}

	CloseHandle(handle);
	return 0;
}

int
w32_utimes(const char *filename, struct timeval *tvp)
{
	int ret;
	FILETIME acttime, modtime;
	wchar_t *resolvedPathName_utf16 = utf8_to_utf16(sanitized_path(filename));
	if (resolvedPathName_utf16 == NULL) {
		errno = ENOMEM;
		return -1;
	}
	memset(&acttime, 0, sizeof(FILETIME));
	memset(&modtime, 0, sizeof(FILETIME));

	unix_time_to_file_time((ULONG)tvp[0].tv_sec, &acttime);
	unix_time_to_file_time((ULONG)tvp[1].tv_sec, &modtime);
	ret = settimes(resolvedPathName_utf16, NULL, &acttime, &modtime);
	free(resolvedPathName_utf16);
	return ret;
}

int
w32_symlink(const char *target, const char *linkpath)
{
	/* Not supported in windows */
	errno = EOPNOTSUPP;
	return -1;
}

int
link(const char *oldpath, const char *newpath)
{
	/* Not supported in windows */
	errno = EOPNOTSUPP;
	return -1;
}

int
w32_rename(const char *old_name, const char *new_name)
{
	wchar_t *resolvedOldPathName_utf16 = utf8_to_utf16(sanitized_path(old_name));
	wchar_t *resolvedNewPathName_utf16 = utf8_to_utf16(sanitized_path(new_name));

	if (NULL == resolvedOldPathName_utf16 || NULL == resolvedNewPathName_utf16) {
		errno = ENOMEM;
		return -1;
	}

	/*
	 * To be consistent with POSIX rename(),
	 * 1) if the new_name is file, then delete it so that _wrename will succeed.
	 * 2) if the new_name is directory and it is empty then delete it so that _wrename will succeed.
	 */
	struct _stat64 st;
	if (fileio_stat(sanitized_path(new_name), &st) != -1) {
		if (((st.st_mode & _S_IFMT) == _S_IFREG))
			w32_unlink(new_name);
		else {
			DIR *dirp = opendir(new_name);
			if (NULL != dirp) {
				struct dirent *dp = readdir(dirp);
				closedir(dirp);

				if (dp == NULL)
					w32_rmdir(new_name);
			}
		}
	}

	int returnStatus = _wrename(resolvedOldPathName_utf16, resolvedNewPathName_utf16);
	free(resolvedOldPathName_utf16);
	free(resolvedNewPathName_utf16);

	return returnStatus;
}

int
w32_unlink(const char *path)
{
	wchar_t *resolvedPathName_utf16 = utf8_to_utf16(sanitized_path(path));
	if (NULL == resolvedPathName_utf16) {
		errno = ENOMEM;
		return -1;
	}

	int returnStatus = _wunlink(resolvedPathName_utf16);
	free(resolvedPathName_utf16);

	return returnStatus;
}

int
w32_rmdir(const char *path)
{
	wchar_t *resolvedPathName_utf16 = utf8_to_utf16(sanitized_path(path));
	if (NULL == resolvedPathName_utf16) {
		errno = ENOMEM;
		return -1;
	}

	int returnStatus = _wrmdir(resolvedPathName_utf16);
	free(resolvedPathName_utf16);

	return returnStatus;
}

int
w32_chdir(const char *dirname_utf8)
{
	wchar_t *dirname_utf16 = utf8_to_utf16(dirname_utf8);
	if (dirname_utf16 == NULL) {
		errno = ENOMEM;
		return -1;
	}

	int returnStatus = _wchdir(dirname_utf16);
	free(dirname_utf16);

	return returnStatus;
}

char *
w32_getcwd(char *buffer, int maxlen)
{
	if(!buffer) return NULL;

	wchar_t wdirname[PATH_MAX];
	char* putf8 = NULL;

	if (_wgetcwd(wdirname, PATH_MAX) == NULL)
		return NULL;

	if ((putf8 = utf16_to_utf8(wdirname)) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	if (strlen(putf8) >= maxlen) {
		errno = ERANGE;
		free(putf8);
		return NULL;
	}

	if (strcpy_s(buffer, maxlen, putf8)) 
		return NULL;
	free(putf8);

	return buffer;
}

int
w32_mkdir(const char *path_utf8, unsigned short mode)
{
	int curmask;
	wchar_t *path_utf16 = utf8_to_utf16(sanitized_path(path_utf8));
	if (path_utf16 == NULL) {
		errno = ENOMEM;
		return -1;
	}
	int returnStatus = _wmkdir(path_utf16);
	if (returnStatus < 0) {
		free(path_utf16);
		return -1;
	}

	errno_t error = _umask_s(0, &curmask);
	if(!error)
		_umask_s(curmask, &curmask);

	returnStatus = _wchmod(path_utf16, mode & ~curmask & (_S_IREAD | _S_IWRITE));
	free(path_utf16);

	return returnStatus;
}

int
w32_stat(const char *path, struct w32_stat *buf)
{
	return fileio_stat(sanitized_path(path), (struct _stat64*)buf);
}

/* if file is symbolic link, copy its link into "link" */
int
readlink(const char *path, char *link, int linklen)
{
	if(strcpy_s(link, linklen, sanitized_path(path)))
		return -1;
	return 0;
}

/* convert forward slash to back slash */
void
convertToBackslash(char *str)
{
	while (*str) {
		if (*str == '/')
			*str = '\\';
		str++;
	}
}

void
convertToBackslashW(wchar_t *str)
{
	while (*str) {
		if (*str == L'/')
			*str = L'\\';
		str++;
	}
}

/* convert back slash to forward slash */
void
convertToForwardslash(char *str)
{
	while (*str) {
		if (*str == '\\')
			*str = '/';
		str++;
	}
}

/*
 * This method will resolves references to /./, /../ and extra '/' characters in the null-terminated string named by
 *  path to produce a canonicalized absolute pathname.
 */
char *
realpath(const char *path, char resolved[PATH_MAX])
{
	errno_t r = 0;
	if (!path || !resolved) return NULL;

	char tempPath[PATH_MAX];
	size_t path_len = strlen(path);

	if (path_len > PATH_MAX - 1) {
		errno = EINVAL;
		return NULL;
	}

	if ((path_len >= 2) && (path[0] == '/') && path[1] && (path[2] == ':')) {
		if((r = strncpy_s(resolved, PATH_MAX, path + 1, path_len)) != 0 ) /* skip the first '/' */ {
			debug3("memcpy_s failed with error: %d.", r);
			return NULL;
		}
	}
	else if(( r = strncpy_s(resolved, PATH_MAX, path, path_len + 1)) != 0) {
		debug3("memcpy_s failed with error: %d.", r);
		return NULL;
	}

	if ((resolved[0]) && (resolved[1] == ':') && (resolved[2] == '\0')) { /* make "x:" as "x:\\" */
		resolved[2] = '\\';
		resolved[3] = '\0';
	}

	if (_fullpath(tempPath, resolved, PATH_MAX) == NULL)
		return NULL;

	convertToForwardslash(tempPath);

	resolved[0] = '/'; /* will be our first slash in /x:/users/test1 format */
	if ((r = strncpy_s(resolved+1, PATH_MAX - 1, tempPath, sizeof(tempPath) - 1)) != 0) {
		debug3("memcpy_s failed with error: %d.", r);
		return NULL;
	}
	return resolved;
}

char*
sanitized_path(const char *path)
{
	if(!path) return NULL;

	static char newPath[PATH_MAX] = { '\0', };
	errno_t r = 0;

	if (path[0] == '/' && path[1]) {
		if (path[2] == ':') {
			if (path[3] == '\0') { /* make "/x:" as "x:\\" */
				if((r = strncpy_s(newPath, sizeof(newPath), path + 1, strlen(path) - 1)) != 0 ) {
					debug3("memcpy_s failed with error: %d.", r);
					return NULL;
				}
				newPath[2] = '\\';
				newPath[3] = '\0';

				return newPath;
			} else
				return (char *)(path + 1); /* skip the first "/" */
		}
	}

	return (char *)path;
}

int
statvfs(const char *path, struct statvfs *buf)
{
	DWORD sectorsPerCluster;
	DWORD bytesPerSector;
	DWORD freeClusters;
	DWORD totalClusters;

	wchar_t* path_utf16 = utf8_to_utf16(sanitized_path(path));
	if (path_utf16 && (GetDiskFreeSpaceW(path_utf16, &sectorsPerCluster, &bytesPerSector,
	    &freeClusters, &totalClusters) == TRUE)) {
		debug5("path              : [%s]", path);
		debug5("sectorsPerCluster : [%lu]", sectorsPerCluster);
		debug5("bytesPerSector    : [%lu]", bytesPerSector);
		debug5("bytesPerCluster   : [%lu]", sectorsPerCluster * bytesPerSector);
		debug5("freeClusters      : [%lu]", freeClusters);
		debug5("totalClusters     : [%lu]", totalClusters);

		buf->f_bsize = sectorsPerCluster * bytesPerSector;
		buf->f_frsize = sectorsPerCluster * bytesPerSector;
		buf->f_blocks = totalClusters;
		buf->f_bfree = freeClusters;
		buf->f_bavail = freeClusters;
		buf->f_files = -1;
		buf->f_ffree = -1;
		buf->f_favail = -1;
		buf->f_fsid = 0;
		buf->f_flag = 0;
		buf->f_namemax = PATH_MAX - 1;

		free(path_utf16);
		return 0;
	} else {
		debug5("ERROR: Cannot get free space for [%s]. Error code is : %d.\n", path, GetLastError());

		free(path_utf16);
		return -1;
	}
}

int
fstatvfs(int fd, struct statvfs *buf)
{
	errno = ENOTSUP;
	return -1;
}

char *
w32_strerror(int errnum)
{
	if (errnum >= EADDRINUSE  && errnum <= EWOULDBLOCK)
		return _sys_errlist_ext[errnum - EADDRINUSE];
	
	strerror_s(errorBuf, ERROR_MSG_MAXLEN, errnum);
	return errorBuf;
}

char *
readpassphrase(const char *prompt, char *outBuf, size_t outBufLen, int flags)
{
	int current_index = 0;
	char ch;
	wchar_t* wtmp = NULL;

	if (outBufLen == 0) {
		errno = EINVAL;
		return NULL;
	}

	while (_kbhit()) _getch();

	wtmp = utf8_to_utf16(prompt);
	if (wtmp == NULL)
		fatal("unable to alloc memory");

	_cputws(wtmp);
	free(wtmp);

	while (current_index < outBufLen - 1) {
		ch = _getch();
		
		if (ch == '\r') {
			if (_kbhit()) _getch(); /* read linefeed if its there */
			break;
		} else if (ch == '\n') {
			break;
		} else if (ch == '\b') { /* backspace */
			if (current_index > 0) {
				if (flags & RPP_ECHO_ON)
					printf_s("%c \b", ch);

				current_index--; /* overwrite last character */
			}
		} else if (ch == '\003') { /* exit on Ctrl+C */
			fatal("");
		} else {
			if (flags & RPP_SEVENBIT)
				ch &= 0x7f;

			if (isalpha((unsigned char)ch)) {
				if(flags & RPP_FORCELOWER)
					ch = tolower((unsigned char)ch);
				if(flags & RPP_FORCEUPPER)
					ch = toupper((unsigned char)ch);
			}

			outBuf[current_index++] = ch;
			if(flags & RPP_ECHO_ON)
				printf_s("%c", ch);
		}
	}

	outBuf[current_index] = '\0';
	_cputs("\n");

	return outBuf;
}

void 
invalid_parameter_handler(const wchar_t* expression, const wchar_t* function, const wchar_t* file, unsigned int line, uintptr_t pReserved)
{	
	debug3("Invalid parameter in function: %ls. File: %ls Line: %d.", function, file, line);
	debug3("Expression: %s", expression);
}

int
get_machine_domain_name(wchar_t *domain, int size)
{
	LPWKSTA_INFO_100 pBuf = NULL;
	NET_API_STATUS nStatus;
	LPWSTR pszServerName = NULL;

	nStatus = NetWkstaGetInfo(pszServerName, 100, (LPBYTE *)&pBuf);
	if (nStatus != NERR_Success) {
		error("Unable to fetch the machine domain, error:%d\n", nStatus);
		return 0;
	}

	debug3("Machine domain:%ls", pBuf->wki100_langroup);
	wcscpy_s(domain, size, pBuf->wki100_langroup);

	if (pBuf != NULL)
		NetApiBufferFree(pBuf);
	
	return 1;
}

/*
 * This method will fetch all the groups (listed below) even if the user is indirectly a member.
 * - Local machine groups
 * - Domain groups
 * - global group
 * - universal groups
*/
char **
getusergroups(const char *user, int *ngroups)
{	
	LPGROUP_USERS_INFO_0 local_groups = NULL;
	LPGROUP_USERS_INFO_0 domain_groups = NULL;
	LPGROUP_USERS_INFO_0 global_universal_groups = NULL;	
	DWORD num_local_groups_read = 0;
	DWORD total_local_groups = 0;
	DWORD num_domain_groups_read = 0;
	DWORD total_domain_groups = 0;
	DWORD num_global_universal_groups_read = 0;
	DWORD total_global_universal_groups = 0;

	DWORD flags = LG_INCLUDE_INDIRECT;
	NET_API_STATUS nStatus;
	wchar_t *user_name_utf16 = NULL;
	char *user_domain = NULL;
	LPWSTR dc_name_utf16 = NULL;
	char **user_groups = NULL;
	int num_user_groups = 0;
	wchar_t machine_domain_name_utf16[DNLEN + 1] = { 0 };
	wchar_t local_user_fmt_utf16[UNLEN + DNLEN + 2] = { 0 };
	size_t local_user_fmt_len = UNLEN + DNLEN + 2;
	char *user_name = NULL;
	
	user_name = malloc(strlen(user)+1);
	if(!user_name) {
		error("failed to allocate memory!");
		goto cleanup;
	}

	memcpy(user_name, user, strlen(user)+1);

	if (user_domain = strchr(user_name, '@')) {
		char *t = user_domain;
		user_domain++;
		*t='\0';
	}

	user_name_utf16 = utf8_to_utf16(user_name);
	if (!user_name_utf16) {
		error("utf8_to_utf16 failed! for %s", user_name);
		goto cleanup;
	}

	/* Fetch groups on the Local machine */	
	if(get_machine_domain_name(machine_domain_name_utf16, DNLEN+1)) {
		if (machine_domain_name_utf16) {
			if(!machine_domain_name)
				machine_domain_name = utf16_to_utf8(machine_domain_name_utf16);
		
			if (user_domain) {
				wcscpy_s(local_user_fmt_utf16, local_user_fmt_len, machine_domain_name_utf16);
				wcscat_s(local_user_fmt_utf16, local_user_fmt_len, L"\\");
			}

			wcscat_s(local_user_fmt_utf16, local_user_fmt_len, user_name_utf16);
			nStatus = NetUserGetLocalGroups(NULL,
				    local_user_fmt_utf16,
				    0,
				    flags,
				    (LPBYTE *)&local_groups,
				    MAX_PREFERRED_LENGTH,
				    &num_local_groups_read,
				    &total_local_groups);

			if (NERR_Success != nStatus)
				error("Failed to get local groups on this machine, error: %d\n", nStatus);
		}
	}

	if (user_domain) {
		/* Fetch Domain groups */
		nStatus = NetGetDCName(NULL, machine_domain_name_utf16, (LPBYTE *)&dc_name_utf16);
		if (NERR_Success == nStatus) {
			debug3("domain controller name: %ls", dc_name_utf16);

			nStatus = NetUserGetLocalGroups(dc_name_utf16,
				    user_name_utf16,
				    0,
				    flags,
				    (LPBYTE *)&domain_groups,
				    MAX_PREFERRED_LENGTH,
				    &num_domain_groups_read,
				    &total_domain_groups);

			if (NERR_Success != nStatus)
				error("Failed to get domain groups from DC:%s error: %d\n", dc_name_utf16, nStatus);
		}
		else
			error("Failed to get the domain controller name, error: %d\n", nStatus);

		/* Fetch global, universal groups */
		nStatus = NetUserGetGroups(dc_name_utf16,
			user_name_utf16,
			0,
			(LPBYTE *)&global_universal_groups,
			MAX_PREFERRED_LENGTH,
			&num_global_universal_groups_read,
			&total_global_universal_groups);

		if (NERR_Success != nStatus)
			error("Failed to get global,universal groups from DC:%ls error: %d\n", dc_name_utf16, nStatus);
	}

	int total_user_groups = num_local_groups_read + num_domain_groups_read + num_global_universal_groups_read;

	/* populate the output */
	user_groups = malloc(total_user_groups * sizeof(*user_groups));	

	populate_user_groups(user_groups, &num_user_groups, num_local_groups_read, total_local_groups, (LPBYTE) local_groups, LOCAL_GROUP);
	if (user_domain) {
		populate_user_groups(user_groups, &num_user_groups, num_domain_groups_read, total_domain_groups, (LPBYTE)domain_groups, DOMAIN_GROUP);
		populate_user_groups(user_groups, &num_user_groups, num_global_universal_groups_read, total_global_universal_groups, (LPBYTE)global_universal_groups, GLOBAL_UNIVERSAL_GROUP);
	}
	
	for (int i = 0; i < num_user_groups; i++)
		to_lower_case(user_groups[i]);

	print_user_groups(user, user_groups, num_user_groups);

	cleanup:
		if(local_groups)
			NetApiBufferFree(local_groups);

		if(domain_groups)
			NetApiBufferFree(domain_groups);

		if(global_universal_groups)
			NetApiBufferFree(global_universal_groups);

		if(dc_name_utf16)
			NetApiBufferFree(dc_name_utf16);
	
		if(user_name_utf16)
			free(user_name_utf16);
				
		if(user_name)
			free(user_name);

		*ngroups = num_user_groups;
		return user_groups;
}

/* This method will return in "group@domain" format */
char *
append_domain_to_groupname(char *groupname)
{
	if(!groupname) return NULL;

	int len = (int) strlen(machine_domain_name) + (int) strlen(groupname) + 2;
	char *groupname_with_domain = malloc(len);
	if(!groupname_with_domain) {
		error("failed to allocate memory!");
		return NULL;
	}

	strcpy_s(groupname_with_domain, len, groupname);
	strcat_s(groupname_with_domain, len, "@");
	strcat_s(groupname_with_domain, len, machine_domain_name);	

	groupname_with_domain[len-1]= '\0';

	return groupname_with_domain;
}

void
populate_user_groups(char **group_name, int *group_index, DWORD groupsread, DWORD totalgroups, LPBYTE buf, group_type groupType)
{
	if(0 == groupsread) return;
	char *user_group_name = NULL;
		
	if (groupType == GLOBAL_UNIVERSAL_GROUP) {
		LPGROUP_USERS_INFO_0 pTmpBuf = (LPGROUP_USERS_INFO_0)buf;
		for (DWORD i = 0; (i < groupsread) && pTmpBuf; i++, pTmpBuf++) {
			if (!(user_group_name = utf16_to_utf8(pTmpBuf->grui0_name))) {
				error("utf16_to_utf8 failed to convert:%ls", pTmpBuf->grui0_name);
				return;
			}

			group_name[*group_index] = append_domain_to_groupname(user_group_name);
			if(group_name[*group_index])
				(*group_index)++;
		}
	} else {
		LPLOCALGROUP_USERS_INFO_0 pTmpBuf = (LPLOCALGROUP_USERS_INFO_0)buf;
		for (DWORD i = 0; (i < groupsread) && pTmpBuf; i++, pTmpBuf++) {
			if (!(user_group_name = utf16_to_utf8(pTmpBuf->lgrui0_name))) {
				error("utf16_to_utf8 failed to convert:%ls", pTmpBuf->lgrui0_name);
				return;
			}				

			if(groupType == DOMAIN_GROUP)
				group_name[*group_index] = append_domain_to_groupname(user_group_name);
			else
				group_name[*group_index] = user_group_name;

			if (group_name[*group_index])
				(*group_index)++;
		}
	}

	if (groupsread < totalgroups)
		error("groupsread:%d totalgroups:%d groupType:%d", groupsread, totalgroups, groupType);
}

void 
print_user_groups(const char *user, char **user_groups, int num_user_groups)
{
	debug3("Group list for user:%s", user);
	for(int i=0; i < num_user_groups; i++)
		debug3("group name:%s", user_groups[i]);
}

void
to_lower_case(char *s)
{
	for (; *s; s++)
		*s = tolower((u_char)*s);
}

static int
get_final_mode(int allow_mode, int deny_mode)
{	
	// If deny permissions are not specified then return allow permissions.
	if (!deny_mode) return allow_mode;

	// If allow permissions are not specified then return allow permissions (0).
	if (!allow_mode) return allow_mode;
	
	if(deny_mode & S_IROTH)
		allow_mode = allow_mode & ~S_IROTH;

	if (deny_mode & S_IWOTH)
		allow_mode = allow_mode & ~S_IWOTH;

	if (deny_mode & S_IXOTH)
		allow_mode = allow_mode & ~S_IXOTH;

	return allow_mode;
}

int
get_others_file_permissions(wchar_t * file_name, int isReadOnlyFile)
{
	PSECURITY_DESCRIPTOR pSD = NULL;
	PSID owner_sid = NULL, current_trustee_sid = NULL;
	PACL dacl = NULL;
	DWORD error_code = ERROR_SUCCESS;
	BOOL is_valid_sid = FALSE, is_valid_acl = FALSE;
	int ret = 0, allow_mode_world = 0, allow_mode_auth_users = 0, deny_mode_world = 0, deny_mode_auth_users = 0;
	wchar_t *w_sid = NULL;

	/*Get the owner sid of the file.*/
	if ((error_code = GetNamedSecurityInfoW(file_name, SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		&owner_sid, NULL, &dacl, NULL, &pSD)) != ERROR_SUCCESS) {
		debug3("failed to retrieve the owner sid and dacl of file: %ls with error code: %d", file_name, error_code);
		goto cleanup;
	}

	if (((is_valid_sid = IsValidSid(owner_sid)) == FALSE) || ((is_valid_acl = IsValidAcl(dacl)) == FALSE)) {
		debug3("IsValidSid: %d; is_valid_acl: %d", is_valid_sid, is_valid_acl);
		goto cleanup;
	}

	for (DWORD i = 0; i < dacl->AceCount; i++) {
		PVOID current_ace = NULL;
		PACE_HEADER current_aceHeader = NULL;
		ACCESS_MASK current_access_mask = 0;
		int mode_tmp = 0;
		if (!GetAce(dacl, i, &current_ace)) {
			debug3("GetAce() failed");
			goto cleanup;
		}

		current_aceHeader = (PACE_HEADER)current_ace;
		/* only interested in Allow ACE */
		if (current_aceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) {
			PACCESS_ALLOWED_ACE pAllowedAce = (PACCESS_ALLOWED_ACE)current_ace;
			current_trustee_sid = &(pAllowedAce->SidStart);
			current_access_mask = pAllowedAce->Mask;
		} else if (current_aceHeader->AceType == ACCESS_DENIED_ACE_TYPE) {
			PACCESS_DENIED_ACE pDeniedAce = (PACCESS_DENIED_ACE)current_ace;
			current_trustee_sid = &(pDeniedAce->SidStart);
			current_access_mask = pDeniedAce->Mask;
		} else continue;
		
		if (!(IsWellKnownSid(current_trustee_sid, WinWorldSid) || 
		    IsWellKnownSid(current_trustee_sid, WinAuthenticatedUserSid)))
			continue;
		
		if ((current_access_mask & READ_PERMISSIONS) == READ_PERMISSIONS)
			mode_tmp |= S_IROTH;

		if (!isReadOnlyFile && ((current_access_mask & WRITE_PERMISSIONS) == WRITE_PERMISSIONS))
			mode_tmp |= S_IWOTH;

		if ((current_access_mask & EXECUTE_PERMISSIONS) == EXECUTE_PERMISSIONS)
			mode_tmp |= S_IXOTH;

		if (IsWellKnownSid(current_trustee_sid, WinWorldSid)) {
			if(current_aceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
				allow_mode_world |= mode_tmp;
			else
				deny_mode_world |= mode_tmp;
		} else if (IsWellKnownSid(current_trustee_sid, WinAuthenticatedUserSid)) {
			if (current_aceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
				allow_mode_auth_users |= mode_tmp;
			else
				deny_mode_auth_users |= mode_tmp;
		}
	}
	
	allow_mode_world = get_final_mode(allow_mode_world, deny_mode_world);
	allow_mode_auth_users = get_final_mode(allow_mode_auth_users, deny_mode_auth_users);

	ret = allow_mode_world ? allow_mode_world : allow_mode_auth_users;
cleanup:
	if (pSD)
		LocalFree(pSD);
	return ret;
}
