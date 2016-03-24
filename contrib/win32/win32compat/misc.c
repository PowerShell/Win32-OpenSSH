#include <Windows.h>
#include "inc\defs.h"
#include "inc\sys\statvfs.h"

int usleep(unsigned int useconds)
{
	Sleep(useconds / 1000);
	return 1;
}

pid_t waitpid(pid_t pid, int *status, int options) {
	/* TODO - implement this*/
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