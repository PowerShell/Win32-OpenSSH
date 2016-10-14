#include <Windows.h>
#include <stdio.h>
#include "inc\defs.h"
#include "inc\sys\statvfs.h"

int usleep(unsigned int useconds)
{
	Sleep(useconds / 1000);
	return 1;
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
	errno = ENOSYS;
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

/*TODO implement Unicode host name support in Windows*/
int 
w32_gethostname(char *name, size_t len) {
	return gethostname(name, len);
}