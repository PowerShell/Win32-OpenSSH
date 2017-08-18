/*
* Copyright (c) 2016 Microsoft Corp.
* All rights reserved
*
* directory entry functions in Windows platform like Ubix/Linux
* opendir(), readdir(), closedir().
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

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "inc\utf.h"
#include "inc\dirent.h"
#include "inc\libgen.h"
#include "misc_internal.h"

struct DIR_ {
	intptr_t hFile;
	struct _wfinddata_t c_file;
	int first;
	wchar_t * nextdisk;
};

#define ATTR_ROOTDIR  UINT_MAX

/* Enumerate all devices which have drive name.
   Return a DIR stream on the root directory, or NULL if it could not be enumerated. */
DIR *
openrootdir(const char *name)
{
	int hr = 0;
	DWORD dw;
	DIR * pdir;
	struct _wfinddata_t c_file = {0};
	wchar_t * p;

	dw = GetLogicalDriveStringsW(_countof(c_file.name) - 2, c_file.name);
	if (!dw) {
		errno = ENODEV;
		return NULL;
	}
	c_file.attrib = ATTR_ROOTDIR;
	c_file.size = 0;
	p = c_file.name;
	while (*p) {
		size_t len = wcslen(p);
		if (len == 0)
			break;
		p += len + 1;
		c_file.size++;
	}
	if (c_file.size == 0) {
		errno = ENODEV;
		return NULL;
	}
	pdir = malloc(sizeof(DIR));
	if (!pdir) {
		errno = ENOMEM;
		return NULL;
	}
	memset(pdir, 0, sizeof(DIR));
	pdir->hFile = 0;
	if (memcpy_s(&pdir->c_file, sizeof(c_file), &c_file, sizeof(c_file))) {
		return NULL;
	}
	pdir->first = 1;

	return pdir;
}

/* Open a directory stream on NAME.
   Return a DIR stream on the directory, or NULL if it could not be opened.  */
DIR *
opendir(const char *name)
{
	struct _wfinddata_t c_file;
	intptr_t hFile;
	DIR *pdir;
	wchar_t searchstr[PATH_MAX];
	wchar_t* wname = NULL;
	size_t len;

	/* Detect root dir */
	if (name && strcmp(name, "/") == 0)
		return openrootdir(name);

	if ((wname = utf8_to_utf16(sanitized_path(name))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	convertToBackslashW(wname);
	len = wcslen(wname);
	if (len && wname[len-1] == L'\\') {
		len--;
		wname[len] = 0;
	}
	if (len >= PATH_MAX) {
		free(wname);
		errno = ENAMETOOLONG;
		return NULL;
	}

	/* add *.* for Windows _findfirst() search pattern */
	swprintf_s(searchstr, _countof(searchstr) - 1, L"%s\\*.*", wname);
	free(wname);

	if ((hFile = _wfindfirst(searchstr, &c_file)) == -1L)
		return NULL; /* errno is set by _wfindfirst */
	else {
		if ((pdir = malloc(sizeof(DIR))) == NULL) {
			_findclose(hFile);
			errno = ENOMEM;
			return NULL;
		}

		memset(pdir, 0, sizeof(DIR));
		pdir->hFile = hFile;
		if (memcpy_s(&pdir->c_file, sizeof(c_file), &c_file, sizeof(c_file))) {
			_findclose(hFile);
			return NULL;
		}
		pdir->first = 1;

		return pdir;
	}
}

/* Close the directory stream DIRP.
   Return 0 if successful, -1 if not.  */
int 
closedir(DIR *dirp)
{
	if(!dirp) return -1;

	if (dirp && (dirp->hFile)) {
		_findclose(dirp->hFile);
	}
	free(dirp);

	return 0;
}

/* Read a root directory entry from DIRP.
   Return a pointer to a `struct dirent' describing the entry,
   or NULL for EOF or error.  The storage returned may be overwritten
   by a later readdir call on the same DIR stream.  */
struct dirent *
readrootdir(DIR * dirp)
{
	wchar_t * p;
	size_t len = 0;
	struct dirent *pdirentry;
	UINT dt;
	ULARGE_INTEGER totalNumberOfBytes;
	BOOL x;

	if (dirp->c_file.size <= 0) {
		errno = ENODATA;
		return NULL;
	}
	if (dirp->first) {
		dirp->first = 0;
		dirp->nextdisk = dirp->c_file.name;
	}

	p = dirp->nextdisk;

	for ( ; ; p += len + 1) {
		len = wcslen(p);
		if (len == 0) {
			dirp->nextdisk = p;
			errno = ENODATA;
			return NULL;     /* end of multi-string */
		}

		dt = GetDriveTypeW(p);
		if (dt == DRIVE_UNKNOWN || dt == DRIVE_NO_ROOT_DIR || dt == DRIVE_RAMDISK)
			continue;

		x = GetDiskFreeSpaceExW(p, NULL, &totalNumberOfBytes, NULL);
		if (!x || totalNumberOfBytes.QuadPart == 0)
			continue;

		break;   // process filtered disk
	}
	dirp->nextdisk = p + len + 1;

	if ((pdirentry = malloc(sizeof(struct dirent))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	pdirentry->d_name[0] = (char)p[0];
	pdirentry->d_name[1] = ':';
	pdirentry->d_name[2] = 0;

	pdirentry->d_ino = 1; // a fictious one like UNIX to say it is nonzero
	return pdirentry;
}

/* Read a directory entry from DIRP.
   Return a pointer to a `struct dirent' describing the entry,
   or NULL for EOF or error.  The storage returned may be overwritten
   by a later readdir call on the same DIR stream.  */
struct dirent *
readdir(void *avp)
{
	if(!avp) return NULL;

	static struct dirent pdirentry;
	struct _wfinddata_t c_file;
	DIR *dirp = (DIR *)avp;
	char *tmp = NULL;

	if (dirp->hFile == 0 && dirp->c_file.attrib == ATTR_ROOTDIR)
		return readrootdir(dirp);

	for (;;) {
		if (dirp->first) {
			if (memcpy_s(&c_file, sizeof(c_file), &dirp->c_file, sizeof(c_file))) {
				return NULL;
			}
			dirp->first = 0;
		} else if (_wfindnext(dirp->hFile, &c_file) != 0)
			return NULL;

		if (wcscmp(c_file.name, L".") == 0 || wcscmp(c_file.name, L"..") == 0)
			continue;

		if ((tmp = utf16_to_utf8(c_file.name)) == NULL) {
			errno = ENOMEM;
			return NULL;
		}

		if (strncpy_s(pdirentry.d_name, PATH_MAX, tmp, strlen(tmp) + 1)) {
			return NULL;
		}
		free(tmp);

		pdirentry.d_ino = 1; /* a fictious one like UNIX to say it is nonzero */
		return &pdirentry;
	}
}

/* return last part of a path. The last path being a filename */
char *
basename(char *path)
{
	char *pdest;

	if (!path)
		return ".";
	pdest = strrchr(path, '/');
	if (pdest)
		return (pdest + 1);
	pdest = strrchr(path, '\\');
	if (pdest)
		return (pdest + 1);

	return path; /* path does not have a slash */
}
