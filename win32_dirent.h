// direntry functions in Windows platform like Ubix/Linux
// opendir(), readdir(), closedir().
// 	NT_DIR * nt_opendir(char *name) ;
// 	struct nt_dirent *nt_readdir(NT_DIR *dirp);
// 	int nt_closedir(NT_DIR *dirp) ;

#ifndef __DIRENT_H__
#define __DIRENT_H__

#include <direct.h>
#include <io.h> 

// Windows directory structure content
struct dirent {
	char *d_name ; // name of the directory entry
	int  d_ino; // UNIX inode
	//unsigned attrib ; // its attributes
};

typedef struct {
	intptr_t hFile;
     struct _finddata_t c_file;
	 int	bRoot;
	 int	bDrive;
	 char	initName[260];
} DIR;

DIR * opendir(char *name);
int closedir(DIR *dirp);
struct dirent *readdir(void *avp);
char *basename(char *path);

#endif