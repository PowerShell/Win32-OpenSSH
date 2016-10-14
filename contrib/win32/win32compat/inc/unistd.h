/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* POSIX header and needed function definitions
*/
#ifndef COMPAT_UNISTD_H
#define COMPAT_UNISTD_H 1

#include "w32posix.h"
//
//#define pipe(a)		w32_pipe((a))
//#define open(a,b,...)	w32_open((a), (b),  __VA_ARGS__)
//#define read(a,b,c)	w32_read((a), (b), (c))
//#define write(a,b,c)	w32_write((a), (b), (c))
#define isatty(a)	w32_isatty((a))
//#define close(a)	w32_close((a))
//#define dup(a)		w32_dup((a))
//#define dup2(a,b)	w32_dup2((a), (b))
//
//#define sleep(sec)	Sleep(1000 * sec)
//#define alarm(a)	w32_alarm((a))

#define pipe w32_pipe
#define open w32_open
#define read w32_read
#define write w32_write
//#define isatty w32_isatty
#define close w32_close
#define dup w32_dup
#define dup2 w32_dup2

#define sleep(sec) Sleep(1000 * sec)
#define alarm w32_alarm
#define lseek w32_lseek

#define getdtablesize() MAX_FDS
#define gethostname w32_gethostname

#define fopen w32_fopen_utf8

/* Compatibility header to avoid lots of #ifdefs in includes.h on Win32 */

#include <conio.h>

/* We can't put these in string.h since we can't easily override that header, so here they are */
#if !defined(HAVE_STRCASECMP) && !defined(__MINGW32__)
size_t strcasecmp(const char *left, const char *right);
#endif

#if !defined(HAVE_STRNCASECMP) && !defined(__MINGW32__)
size_t strncasecmp(const char *left, const char *right, size_t n);
#endif

int gettimeofday(struct timeval *tv, void *tz);

#define popen _popen
#define pclose _pclose

/* End of prototypes in the wrong file */

#endif
