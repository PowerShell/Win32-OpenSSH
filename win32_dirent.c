// win32_dirent.c
// directory entry functions in Windows platform like Ubix/Linux
// opendir(), readdir(), closedir().

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <windows.h>

#include "win32_dirent.h"

/* Open a directory stream on NAME.
   Return a DIR stream on the directory, or NULL if it could not be opened.  */
DIR * opendir(char *name)
{
   struct _finddata_t c_file;
   intptr_t hFile;
	DIR *pdir;
	char searchstr[256];

	// add *.* for Windows _findfirst() search pattern
	sprintf_s(searchstr, sizeof(searchstr), "%s\\*.*",name);

   if ((hFile = _findfirst(searchstr, &c_file)) == -1L) {
       if (1) // verbose
			printf( "No files found for %s search.\n", name );
		return (DIR *) NULL;
   }
   else {
		pdir = (DIR *) malloc( sizeof(DIR) );
		pdir->hFile = hFile ;
		pdir->c_file = c_file ;
		strcpy_s(pdir->initName,sizeof(pdir->initName), c_file.name);

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
	DIR *dirp = (DIR *)avp;

 for (;;) {
  if ( _findnext( dirp->hFile, &(dirp->c_file) ) == 0 ) {
		if ( ( strcmp (dirp->c_file.name,".") == 0 ) ||
			  ( strcmp (dirp->c_file.name,"..") == 0 ) ) {
			continue ;
		}
		pdirentry = (struct dirent *) malloc( sizeof(struct dirent) );
		pdirentry->d_name = dirp->c_file.name ;
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
