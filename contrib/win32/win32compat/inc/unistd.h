/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* POSIX header and needed function definitions
*/
#ifndef COMPAT_UNISTD_H
#define COMPAT_UNISTD_H 1

#include "w32posix.h"

#define pipe w32_pipe
#define open w32_open
#define read w32_read
#define write w32_write
#define writev w32_writev
/* can't do this #define isatty w32_isatty
* as there is a variable in code named isatty*/
#define isatty(a)	w32_isatty((a))
#define close w32_close
#define dup w32_dup
#define dup2 w32_dup2

#define sleep(sec) Sleep(1000 * sec)
#define alarm w32_alarm
#define lseek w32_lseek

#define getdtablesize() MAX_FDS
#define gethostname w32_gethostname

#define fsync(a) w32_fsync((a))
#define ftruncate(a, b) w32_ftruncate((a), (b))

#define symlink w32_symlink
#define chown w32_chown
#define unlink w32_unlink
#define rmdir w32_rmdir
#define chdir w32_chdir
#define getcwd w32_getcwd

int daemon(int nochdir, int noclose);
char *crypt(const char *key, const char *salt);
int link(const char *oldpath, const char *newpath);
int w32_symlink(const char *target, const char *linkpath);
int w32_chown(const char *pathname, unsigned int owner, unsigned int group);
int w32_unlink(const char *path);
int w32_rmdir(const char *pathname);
int w32_chdir(const char *dirname);
char *w32_getcwd(char *buffer, int maxlen);
int readlink(const char *path, char *link, int linklen);
#endif
