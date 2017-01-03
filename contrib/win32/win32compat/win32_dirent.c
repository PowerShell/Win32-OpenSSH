// win32_dirent.c
// directory entry functions in Windows platform like Ubix/Linux
// opendir(), readdir(), closedir().

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
};

/* Open a directory stream on NAME.
   Return a DIR stream on the directory, or NULL if it could not be opened.  */
DIR * opendir(const char *name)
{
	struct _wfinddata_t c_file;
	intptr_t hFile;
	DIR *pdir;
	wchar_t searchstr[MAX_PATH];
	wchar_t* wname = NULL;
	int needed;
	
	if ((wname = utf8_to_utf16(sanitized_path(name))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	// add *.* for Windows _findfirst() search pattern
	swprintf_s(searchstr, MAX_PATH, L"%s\\*.*", wname);
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
		memcpy(&pdir->c_file, &c_file, sizeof(c_file));
		pdir->first = 1;

		return pdir ;
	}
}

/* Close the directory stream DIRP.
   Return 0 if successful, -1 if not.  */
int closedir(DIR *dirp)
{
    if ( dirp && (dirp->hFile) ) {
        _findclose( dirp->hFile );
        dirp->hFile = 0;
        free (dirp);
    }

    return 0;
}

/* Read a directory entry from DIRP.
   Return a pointer to a `struct dirent' describing the entry,
   or NULL for EOF or error.  The storage returned may be overwritten
   by a later readdir call on the same DIR stream.  */
struct dirent *readdir(void *avp)
{
	struct dirent *pdirentry;
	struct _wfinddata_t c_file;
	DIR *dirp = (DIR *)avp;
	char *tmp = NULL;

	for (;;) {
		if (dirp->first) {
			memcpy(&c_file, &dirp->c_file, sizeof(c_file));
			dirp->first = 0;
		}
		else if (_wfindnext(dirp->hFile, &c_file) != 0)
			return NULL;
			
		if (wcscmp(c_file.name, L".") == 0 || wcscmp(c_file.name, L"..") == 0 )
			continue;
		    
		if ((pdirentry = malloc(sizeof(struct dirent))) == NULL ||
		    (tmp = utf16_to_utf8(c_file.name)) == NULL) {
			errno = ENOMEM;
			return NULL;
		}

		strncpy(pdirentry->d_name, tmp, strlen(tmp) + 1);
		free(tmp);

		pdirentry->d_ino = 1; // a fictious one like UNIX to say it is nonzero
		return pdirentry ;
        }
}

// return last part of a path. The last path being a filename.
char *basename(char *path)
{
	char *pdest;

	if (!path)
		return ".";
	pdest = strrchr(path, '/');
	if (pdest)
		return (pdest+1);
	pdest = strrchr(path, '\\');
	if (pdest)
		return (pdest+1);
	
	return path; // path does not have a slash
}
// end of dirent functions in Windows
