/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* POSIX header and needed function definitions
*/
#pragma once
#include <stddef.h>
#include "sys\types.h"
#include "fcntl.h"

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

int w32_ftruncate(int, off_t);
#define ftruncate(a, b) w32_ftruncate((a), (b))

#define pipe w32_pipe
int w32_pipe(int *pfds);

#define read w32_read
int w32_read(int fd, void *dst, size_t max);

#define write w32_write
int w32_write(int fd, const void *buf, size_t max);

#define writev w32_writev
int w32_writev(int fd, const struct iovec *iov, int iovcnt);

int w32_isatty(int fd);
/* can't do this #define isatty w32_isatty
* as there is a variable in code named isatty*/
#define isatty(a)	w32_isatty((a))

int w32_close(int fd);
#define close w32_close

int w32_dup(int oldfd);
#define dup w32_dup

int w32_dup2(int oldfd, int newfd);
#define dup2 w32_dup2

#define sleep(sec) Sleep(1000 * sec)

unsigned int w32_alarm(unsigned int seconds);
#define alarm w32_alarm

long w32_lseek(int fd, unsigned __int64 offset, int origin);
#define lseek w32_lseek

#define getdtablesize() MAX_FDS

int w32_gethostname(char *, size_t);
#define gethostname w32_gethostname

int w32_fsync(int fd);
#define fsync(a) w32_fsync((a))

int w32_symlink(const char *target, const char *linkpath);
#define symlink w32_symlink

int w32_chown(const char *pathname, unsigned int owner, unsigned int group);
#define chown w32_chown

int w32_unlink(const char *path);
#define unlink w32_unlink

int w32_rmdir(const char *pathname);
#define rmdir w32_rmdir

int w32_chdir(const char *dirname);
#define chdir w32_chdir

char *w32_getcwd(char *buffer, int maxlen);
#define getcwd w32_getcwd

int daemon(int nochdir, int noclose);
char *crypt(const char *key, const char *salt);
int link(const char *oldpath, const char *newpath);
int readlink(const char *path, char *link, int linklen);
int spawn_child(char*, char**, int, int, int, unsigned long);

/* 
 * readpassphrase.h definitions 
 * cannot create a separate header due to the way
 * its included in openbsdcompat.h
 */

#define RPP_ECHO_OFF    0x00		/* Turn off echo (default). */
#define RPP_ECHO_ON     0x01		/* Leave echo on. */
#define RPP_REQUIRE_TTY 0x02		/* Fail if there is no tty. */
#define RPP_FORCELOWER  0x04		/* Force input to lower case. */
#define RPP_FORCEUPPER  0x08		/* Force input to upper case. */
#define RPP_SEVENBIT    0x10		/* Strip the high bit from input. */
#define RPP_STDIN       0x20		/* Read from stdin, not /dev/tty */

char * readpassphrase(const char *, char *, size_t, int);