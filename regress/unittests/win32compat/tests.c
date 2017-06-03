/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*/
/* disable inclusion of compatability defitnitions in CRT headers */
#define __STDC__ 1
#include "includes.h"
#include <inc/dirent.h>
#include <fcntl.h>
#include <sys\types.h>
#include <sys\stat.h>

#include "../test_helper/test_helper.h"
#include "tests.h"

extern void log_init(char *av0, int level, int facility, int on_stderr);

void 
tests()
{
    _set_abort_behavior(0, 1);
    log_init(NULL, 7, 2, 0);
    socket_tests();
    file_tests();
    dir_tests();
    str_tests();
    miscellaneous_tests();
}

char *
dup_str(char *inStr)
{
	if(NULL == inStr)
		return NULL;

	int len = strlen(inStr);
	char *outStr = malloc(len + 1);
	strncpy(outStr, inStr, len);
	outStr[len] = '\0';
	return outStr;
}

void
delete_dir_recursive(char *full_dir_path)
{
	DIR *dirp = opendir(full_dir_path);
	if (!dirp) return;

	struct stat st;
	struct dirent *dp;
	char mode[12];
	char *tmpFullPath = malloc(MAX_PATH + 1);
	strcpy(tmpFullPath, full_dir_path);
	int tmpStrLen = strlen(tmpFullPath);
	tmpFullPath[tmpStrLen++] = '\\';

	while (dp = readdir(dirp)) {
		strcpy(tmpFullPath + tmpStrLen, dp->d_name);
		tmpFullPath[tmpStrLen + strlen(dp->d_name)] = '\0';

		stat(tmpFullPath, &st);
		strmode(st.st_mode, mode);
		if (mode[0] == '-') /* regular file */
			unlink(tmpFullPath);
		else if (mode[0] == 'd') /* directory */
			delete_dir_recursive(tmpFullPath);
	}

	closedir(dirp);
	rmdir(full_dir_path);

	free(tmpFullPath);
}
