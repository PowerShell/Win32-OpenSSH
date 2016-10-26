// win32_dirent.c
// directory entry functions in Windows platform like Ubix/Linux
// opendir(), readdir(), closedir().

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <utf.h>

#include "win32_dirent.h"

/* Open a directory stream on NAME.
   Return a DIR stream on the directory, or NULL if it could not be opened.  */
DIR * opendir(char *name)
{
    struct _wfinddata_t c_file;
    intptr_t hFile;
    DIR *pdir;
    wchar_t searchstr[MAX_PATH];
    wchar_t* wname = NULL;
    int needed;
    char *tmp = NULL;

    if ((wname = utf8_to_utf16(name)) == NULL)
        fatal("failed to covert input arguments");

    // add *.* for Windows _findfirst() search pattern
    swprintf_s(searchstr, MAX_PATH, L"%s\\*.*", wname);
    free(wname);

    if ((hFile = _wfindfirst(searchstr, &c_file)) == -1L) {
        if (1) // verbose
            printf( "No files found for %s search.\n", name );
        return (DIR *) NULL;
    }
    else {
        pdir = (DIR *) malloc( sizeof(DIR) );
        pdir->hFile = hFile ;
        pdir->c_file.attrib = c_file.attrib ;
        pdir->c_file.size = c_file.size;
        pdir->c_file.time_access = c_file.time_access;
        pdir->c_file.time_create = c_file.time_create;
        pdir->c_file.time_write = c_file.time_write;

        if ((tmp = utf16_to_utf8(&(c_file.name))) == NULL)
            fatal("failed to covert input arguments");

        strcpy_s(pdir->c_file.name, MAX_PATH, tmp);
        strcpy_s(pdir->initName, sizeof(pdir->initName), pdir->c_file.name);
        free(tmp);

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
        if ( _wfindnext( dirp->hFile, &c_file ) == 0 ) {
		    if ( ( wcscmp (c_file.name, L".") == 0 ) ||
			     ( wcscmp (c_file.name, L"..") == 0 ) ) {
			    continue ;
		    }
		    pdirentry = (struct dirent *) malloc( sizeof(struct dirent) );

            if ((tmp = utf16_to_utf8(&(c_file.name))) == NULL)
                fatal("failed to covert input arguments");
            pdirentry->d_name= tmp;
            tmp = NULL;

		    pdirentry->d_ino = 1; // a fictious one like UNIX to say it is nonzero
		    return pdirentry ;
        }
        else {
	        return (struct dirent *) NULL;
        }
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
