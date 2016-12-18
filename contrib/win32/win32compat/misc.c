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
#include "inc\defs.h"
#include "sys\stat.h"
#include "inc\sys\statvfs.h"
#include "inc\sys\time.h"
#include <time.h>
#include <Shlwapi.h>

int usleep(unsigned int useconds)
{
	Sleep(useconds / 1000);
	return 1;
}

int nanosleep(const struct timespec *req, struct timespec *rem) {
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

/* Difference in us between UNIX Epoch and Win32 Epoch */
#define EPOCH_DELTA_US  11644473600000000ULL

/* This routine is contributed by  * Author: NoMachine <developers@nomachine.com>
* Copyright (c) 2009, 2010 NoMachine
* All rights reserved
*/
int
gettimeofday(struct timeval *tv, void *tz)
{
        union
        {
                FILETIME ft;
                unsigned long long ns;
        } timehelper;
        unsigned long long us;

        /* Fetch time since Jan 1, 1601 in 100ns increments */
        GetSystemTimeAsFileTime(&timehelper.ft);

        /* Convert to microseconds from 100 ns units */
        us = timehelper.ns / 10;

        /* Remove the epoch difference */
        us -= EPOCH_DELTA_US;

        /* Stuff result into the timeval */
        tv->tv_sec = (long)(us / 1000000ULL);
        tv->tv_usec = (long)(us % 1000000ULL);

        return 0;
}

void
explicit_bzero(void *b, size_t len) {
	SecureZeroMemory(b, len);
}

int statvfs(const char *path, struct statvfs *buf) {
	DWORD sectorsPerCluster;
	DWORD bytesPerSector;
	DWORD freeClusters;
	DWORD totalClusters;

	if (GetDiskFreeSpace(path, &sectorsPerCluster, &bytesPerSector,
		&freeClusters, &totalClusters) == TRUE)
	{
		debug3("path              : [%s]", path);
		debug3("sectorsPerCluster : [%lu]", sectorsPerCluster);
		debug3("bytesPerSector    : [%lu]", bytesPerSector);
		debug3("bytesPerCluster   : [%lu]", sectorsPerCluster * bytesPerSector);
		debug3("freeClusters      : [%lu]", freeClusters);
		debug3("totalClusters     : [%lu]", totalClusters);

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
		buf->f_namemax = MAX_PATH - 1;

		return 0;
	}
	else
	{
		debug3("ERROR: Cannot get free space for [%s]. Error code is : %d.\n",
			path, GetLastError());

		return -1;
	}
}

int fstatvfs(int fd, struct statvfs *buf) {
	errno = ENOTSUP;
	return -1;
}

#include "inc\dlfcn.h"
HMODULE dlopen(const char *filename, int flags) {
	return LoadLibraryA(filename);
}

int dlclose(HMODULE handle) {
	FreeLibrary(handle);
	return 0;
}

FARPROC dlsym(HMODULE handle, const char *symbol) {
	return GetProcAddress(handle, symbol);
}


/*fopen on Windows to mimic https://linux.die.net/man/3/fopen
* only r, w, a are supported for now
*/
FILE*
w32_fopen_utf8(const char *path, const char *mode) {
	wchar_t wpath[MAX_PATH], wmode[5];
	FILE* f;
	char utf8_bom[] = { 0xEF,0xBB,0xBF };
	char first3_bytes[3];

	if (mode[1] != '\0') {
		errno = ENOTSUP;
		return NULL;
	}

	if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH) == 0 ||
		MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, 5) == 0) {
		errno = EFAULT;
		debug("WideCharToMultiByte failed for %c - ERROR:%d", path, GetLastError());
		return NULL;
	}

	f = _wfopen(wpath, wmode);

	if (f) {
		/* BOM adjustments for file streams*/
		if (mode[0] == 'w' && fseek(f, 0, SEEK_SET) != EBADF) {
			/* write UTF-8 BOM - should we ?*/
			/*if (fwrite(utf8_bom, sizeof(utf8_bom), 1, f) != 1) {
				fclose(f);
				return NULL;
			}*/

		}
		else if (mode[0] == 'r' && fseek(f, 0, SEEK_SET) != EBADF) {
			/* read out UTF-8 BOM if present*/
			if (fread(first3_bytes, 3, 1, f) != 1 ||
				memcmp(first3_bytes, utf8_bom, 3) != 0) {
				fseek(f, 0, SEEK_SET);
			}
		}
	}

	return f;
}


wchar_t*
utf8_to_utf16(const char *utf8) {
        int needed = 0;
        wchar_t* utf16 = NULL;
        if ((needed = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0)) == 0 ||
                (utf16 = malloc(needed * sizeof(wchar_t))) == NULL ||
                MultiByteToWideChar(CP_UTF8, 0, utf8, -1, utf16, needed) == 0)
                return NULL;
        return utf16;
}

char*
utf16_to_utf8(const wchar_t* utf16) {
        int needed = 0;
        char* utf8 = NULL;
        if ((needed = WideCharToMultiByte(CP_UTF8, 0, utf16, -1, NULL, 0, NULL, NULL)) == 0 ||
                (utf8 = malloc(needed)) == NULL ||
                WideCharToMultiByte(CP_UTF8, 0, utf16, -1, utf8, needed, NULL, NULL) == 0)
                return NULL;
        return utf8;
}

static char* s_programdir = NULL;
char* w32_programdir() {
        if (s_programdir != NULL)
                return s_programdir;

        if ((s_programdir = utf16_to_utf8(_wpgmptr)) == NULL)
                return NULL;

        /* null terminate after directory path */
        {
                char* tail = s_programdir + strlen(s_programdir);
                while (tail > s_programdir && *tail != '\\' && *tail != '/')
                        tail--;

                if (tail > s_programdir)
                        *tail = '\0';
                else
                        *tail = '.'; /* current directory */
        }

        return s_programdir;

}

int 
daemon(int nochdir, int noclose)
{
        FreeConsole();
        return 0;
}

int w32_ioctl(int d, int request, ...) {
        va_list valist;
        va_start(valist, request);

        switch (request){
        case TIOCGWINSZ: {
                struct winsize* wsize = va_arg(valist, struct winsize*);
                CONSOLE_SCREEN_BUFFER_INFO c_info;
                if (wsize == NULL || !GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &c_info)) {
                        errno = EINVAL;
                        return -1;
                }
                wsize->ws_col = c_info.dwSize.X - 5;
                wsize->ws_row = c_info.dwSize.Y;
                wsize->ws_xpixel = 640;
                wsize->ws_ypixel = 480;
                return 0;
        }
        default:
                errno = ENOTSUP;
                return -1;
        }
}

HANDLE w32_fd_to_handle(int fd);
int 
spawn_child(char* cmd, int in, int out, int err, DWORD flags) {
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	BOOL b;
	char* abs_cmd;
	wchar_t * cmd_utf16;

	/* relative ? if so, add current module path to start */
	if (!(cmd && cmd[0] != '\0' && (cmd[1] == ':' || cmd[0] == '\\' || cmd[0] == '.'))) {
		char* ctr;
		abs_cmd = malloc(strlen(w32_programdir()) + 1 + strlen(cmd) + 1);
		if (abs_cmd == NULL) {
			errno = ENOMEM;
			return -1;
		}
		ctr = abs_cmd;
		memcpy(ctr, w32_programdir(), strlen(w32_programdir()));
		ctr += strlen(w32_programdir());
		*ctr++ = '\\';
		memcpy(ctr, cmd, strlen(cmd) + 1);
	}
	else
		abs_cmd = cmd;
	   
	debug("spawning %s", abs_cmd);

	if ((cmd_utf16 = utf8_to_utf16(abs_cmd)) == NULL) {
		errno = ENOMEM;
		return -1;
	}

	if(abs_cmd != cmd)
		free(abs_cmd);

	memset(&si, 0, sizeof(STARTUPINFOW));
	si.cb = sizeof(STARTUPINFOW);
	si.hStdInput = w32_fd_to_handle(in);
	si.hStdOutput = w32_fd_to_handle(out);
	si.hStdError = w32_fd_to_handle(err);
	si.dwFlags = STARTF_USESTDHANDLES;

	b = CreateProcessW(NULL, cmd_utf16, NULL, NULL, TRUE, flags, NULL, NULL, &si, &pi);

	if (b) {
		if (sw_add_child(pi.hProcess, pi.dwProcessId) == -1) {
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			pi.dwProcessId = -1;
		}
		CloseHandle(pi.hThread);
	}
	else {
		errno = GetLastError();
		pi.dwProcessId = -1;
	}

	free(cmd_utf16);
	return pi.dwProcessId;
}

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
		//case S_IFBLK:			/* block special */
		//		*p++ = 'b';
		//		break;
	case S_IFREG:			/* regular */
		*p++ = '-';
		break;
		//case S_IFLNK:			/* symbolic link */
		//		*p++ = 'l';
		//		break;
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
	
	// The below code is commented as the group, other is not applicable on the windows.
	// This will be properly fixed in next releases.
	// As of now we are keeping "*" for everything.
	const char *permissions = "********* ";
	strncpy(p, permissions, strlen(permissions) + 1);
	p = p + strlen(p);
	///* usr */
	//if (mode & S_IRUSR)
	//	*p++ = 'r';
	//else
	//	*p++ = '-';
	//if (mode & S_IWUSR)
	//	*p++ = 'w';
	//else
	//	*p++ = '-';
	//switch (mode & (S_IXUSR)) {
	//case 0:
	//	*p++ = '-';
	//	break;
	//case S_IXUSR:
	//	*p++ = 'x';
	//	break;
	//	//case S_ISUID:
	//	//		*p++ = 'S';
	//	//		break;
	//	//case S_IXUSR | S_ISUID:
	//	//		*p++ = 's';
	//	//		break;
	//}
	///* group */
	//if (mode & S_IRGRP)
	//	*p++ = 'r';
	//else
	//	*p++ = '-';
	//if (mode & S_IWGRP)
	//	*p++ = 'w';
	//else
	//	*p++ = '-';
	//switch (mode & (S_IXGRP)) {
	//case 0:
	//	*p++ = '-';
	//	break;
	//case S_IXGRP:
	//	*p++ = 'x';
	//	break;
	//	//case S_ISGID:
	//	//		*p++ = 'S';
	//	//		break;
	//	//case S_IXGRP | S_ISGID:
	//	//		*p++ = 's';
	//	//		break;
	//}
	///* other */
	//if (mode & S_IROTH)
	//	*p++ = 'r';
	//else
	//	*p++ = '-';
	//if (mode & S_IWOTH)
	//	*p++ = 'w';
	//else
	//	*p++ = '-';
	//switch (mode & (S_IXOTH)) {
	//case 0:
	//	*p++ = '-';
	//	break;
	//case S_IXOTH:
	//	*p++ = 'x';
	//	break;
	//}
	//*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}

int 
w32_chmod(const char *pathname, mode_t mode) {
    /* TODO - implement this */
	errno = EOPNOTSUPP;
    return -1;
}

int 
w32_chown(const char *pathname, unsigned int owner, unsigned int group) {
	/* TODO - implement this */
	errno = EOPNOTSUPP;
	return -1;
}

char *realpath_win(const char *path, char resolved[MAX_PATH]);

int
w32_utimes(const char *filename, struct timeval *tvp) {
	struct utimbuf ub;
	ub.actime = tvp[0].tv_sec;
	ub.modtime = tvp[1].tv_sec;
	int ret;

	// Skip the first '/' in the pathname
	char resolvedPathName[MAX_PATH];
	realpath_win(filename, resolvedPathName);
	wchar_t *resolvedPathName_utf16 = utf8_to_utf16(resolvedPathName);
	if (resolvedPathName_utf16 == NULL) {
		errno = ENOMEM;
		return -1;
	}

	ret = _wutime(resolvedPathName_utf16, &ub);
	free(resolvedPathName_utf16);
	return ret;
}

int 
w32_symlink(const char *target, const char *linkpath) {
	// Not supported in windows
	errno = EOPNOTSUPP;
	return -1;
}

int 
link(const char *oldpath, const char *newpath) {
	// Not supported in windows	
	errno = EOPNOTSUPP;
	return -1;
}

int
w32_rename(const char *old_name, const char *new_name) {
	// Skip the first '/' in the pathname
	char resolvedOldPathName[MAX_PATH];
	realpath_win(old_name, resolvedOldPathName);

	// Skip the first '/' in the pathname
	char resolvedNewPathName[MAX_PATH];
	realpath_win(new_name, resolvedNewPathName);

	wchar_t *resolvedOldPathName_utf16 = utf8_to_utf16(resolvedOldPathName);
	wchar_t *resolvedNewPathName_utf16 = utf8_to_utf16(resolvedNewPathName);
	if (NULL == resolvedOldPathName_utf16 || NULL == resolvedNewPathName_utf16) {
		errno = ENOMEM;
		return -1;
	}

	int returnStatus = _wrename(resolvedOldPathName_utf16, resolvedNewPathName_utf16);
	free(resolvedOldPathName_utf16);
	free(resolvedNewPathName_utf16);

	return returnStatus;
}

int
w32_unlink(const char *path) {
	// Skip the first '/' in the pathname
	char resolvedPathName[MAX_PATH];
	realpath_win(path, resolvedPathName);

	wchar_t *resolvedPathName_utf16 = utf8_to_utf16(resolvedPathName);
	if (NULL == resolvedPathName_utf16) {
		errno = ENOMEM;
		return -1;
	}

	int returnStatus = _wunlink(resolvedPathName_utf16);
	free(resolvedPathName_utf16);

	return returnStatus;
}

int
w32_rmdir(const char *path) {
	// Skip the first '/' in the pathname
	char resolvedPathName[MAX_PATH];
	realpath_win(path, resolvedPathName);

	wchar_t *resolvedPathName_utf16 = utf8_to_utf16(resolvedPathName);
	if (NULL == resolvedPathName_utf16) {
		errno = ENOMEM;
		return -1;
	}

	int returnStatus = _wrmdir(resolvedPathName_utf16);
	free(resolvedPathName_utf16);

	return returnStatus;
}

int 
w32_chdir(const char *dirname_utf8) {
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
w32_getcwd(char *buffer, int maxlen) {
	wchar_t wdirname[MAX_PATH];
	char* putf8 = NULL;

	_wgetcwd(&wdirname[0], MAX_PATH);

	if ((putf8 = utf16_to_utf8(&wdirname[0])) == NULL)
		fatal("failed to convert input arguments");
	strcpy(buffer, putf8);
	free(putf8);

	return buffer;
}

int
w32_mkdir(const char *path_utf8, unsigned short mode) {
	// Skip the first '/' in the pathname
	char resolvedPathName[MAX_PATH];
	realpath_win(path_utf8, resolvedPathName);

	wchar_t *path_utf16 = utf8_to_utf16(resolvedPathName);
	if (path_utf16 == NULL) {
		errno = ENOMEM;
		return -1;
	}
	int returnStatus = _wmkdir(path_utf16);
	free(path_utf16);

	return returnStatus;
}

void
getrnd(u_char *s, size_t len) {
	HCRYPTPROV hProvider;
	if (CryptAcquireContextW(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT) == FALSE ||
	    CryptGenRandom(hProvider, len, s) == FALSE ||
	    CryptReleaseContext(hProvider, 0) == FALSE)
		DebugBreak();
}

int
w32_stat(const char *path, struct w32_stat *buf) {
	// Skip the first '/' in the pathname
	char resolvedPathName[MAX_PATH];
	realpath_win(path, resolvedPathName);

	return fileio_stat(resolvedPathName, (struct _stat64*)buf);
}

// if file is symbolic link, copy its link into "link" .
int 
readlink(const char *path, char *link, int linklen)
{
	// Skip the first '/' in the pathname
	char resolvedPathName[MAX_PATH];
	realpath_win(path, resolvedPathName);

	strcpy_s(link, linklen, resolvedPathName);
	return 0;
}

/*
* This method will expands all symbolic links and resolves references to /./,
*  /../ and extra '/' characters in the null-terminated string named by
*  path to produce a canonicalized absolute pathname.
*/
char *
realpath(const char *path, char resolved[MAX_PATH])
{
	char tempPath[MAX_PATH];

	if ((0 == strcmp(path, "./")) || (0 == strcmp(path, "."))) {
		tempPath[0] = '/';
		_getcwd(&tempPath[1], sizeof(tempPath) - 1);
		slashconvert(tempPath);

		strncpy(resolved, tempPath, strlen(tempPath) + 1);
		return resolved;
	}

	if (path[0] != '/')
		strlcpy(resolved, path, sizeof(tempPath));
	else
		strlcpy(resolved, path + 1, sizeof(tempPath));

	backslashconvert(resolved);
	PathCanonicalizeA(tempPath, resolved);
	slashconvert(tempPath);

	// Store terminating slash in 'X:/' on Windows.	
	if (tempPath[1] == ':' && tempPath[2] == 0) {
		tempPath[2] = '/';
		tempPath[3] = 0;
	}

	resolved[0] = '/'; // will be our first slash in /x:/users/test1 format
	strncpy(resolved + 1, tempPath, sizeof(tempPath) - 1);
	return resolved;
}

// like realpathWin32() but takes out the first slash so that windows systems can work on the actual file or directory
char *
realpath_win(const char *path, char resolved[MAX_PATH])
{
	char tempPath[MAX_PATH];
	realpath(path, tempPath);

	strncpy(resolved, &tempPath[1], sizeof(tempPath) - 1);
	return resolved;
}

// Maximum reparse buffer info size. The max user defined reparse 
// data is 16KB, plus there's a header. 
#define MAX_REPARSE_SIZE	17000 
#define IO_REPARSE_TAG_SYMBOLIC_LINK      IO_REPARSE_TAG_RESERVED_ZERO 
#define IO_REPARSE_TAG_MOUNT_POINT              (0xA0000003L)       // winnt ntifs 
#define IO_REPARSE_TAG_HSM                      (0xC0000004L)       // winnt ntifs 
#define IO_REPARSE_TAG_SIS                      (0x80000007L)       // winnt ntifs 
#define REPARSE_MOUNTPOINT_HEADER_SIZE   8 


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

BOOL 
ResolveLink(wchar_t * tLink, wchar_t *ret, DWORD * plen, DWORD Flags)
{
	HANDLE   fileHandle;
	BYTE     reparseBuffer[MAX_REPARSE_SIZE];
	PBYTE    reparseData;
	PREPARSE_GUID_DATA_BUFFER reparseInfo = (PREPARSE_GUID_DATA_BUFFER)reparseBuffer;
	PREPARSE_DATA_BUFFER msReparseInfo = (PREPARSE_DATA_BUFFER)reparseBuffer;
	DWORD   returnedLength;

	if (Flags & FILE_ATTRIBUTE_DIRECTORY)
	{
		fileHandle = CreateFileW(tLink, 0,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, 0);

	}
	else {

		//    
		// Open the file    
		//    
		fileHandle = CreateFileW(tLink, 0,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING,
			FILE_FLAG_OPEN_REPARSE_POINT, 0);
	}
	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		swprintf_s(ret, *plen, L"%ls", tLink);
		return TRUE;
	}

	if (GetFileAttributesW(tLink) & FILE_ATTRIBUTE_REPARSE_POINT) {

		if (DeviceIoControl(fileHandle, FSCTL_GET_REPARSE_POINT,
			NULL, 0, reparseInfo, sizeof(reparseBuffer),
			&returnedLength, NULL)) {

			if (IsReparseTagMicrosoft(reparseInfo->ReparseTag)) {

				switch (reparseInfo->ReparseTag) {
				case 0x80000000 | IO_REPARSE_TAG_SYMBOLIC_LINK:
				case IO_REPARSE_TAG_MOUNT_POINT:
					if (*plen >= msReparseInfo->MountPointReparseBuffer.SubstituteNameLength)
					{
						reparseData = (PBYTE)&msReparseInfo->SymbolicLinkReparseBuffer.PathBuffer;
						WCHAR temp[1024];
						wcsncpy_s(temp, 1024,
							(PWCHAR)(reparseData + msReparseInfo->MountPointReparseBuffer.SubstituteNameOffset),
							(size_t)msReparseInfo->MountPointReparseBuffer.SubstituteNameLength);
						temp[msReparseInfo->MountPointReparseBuffer.SubstituteNameLength] = 0;
						swprintf_s(ret, *plen, L"%ls", &temp[4]);
					}
					else
					{
						swprintf_s(ret, *plen, L"%ls", tLink);
						return FALSE;
					}

					break;
				default:
					break;
				}
			}
		}
	}
	else {
		swprintf_s(ret, *plen, L"%ls", tLink);
	}

	CloseHandle(fileHandle);
	return TRUE;
}