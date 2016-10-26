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

#define fopen w32_fopen_utf8

int daemon(int nochdir, int noclose);

/* Compatibility header to avoid lots of #ifdefs in includes.h on Win32 */

#include <conio.h>

/* We can't put these in string.h since we can't easily override that header, so here they are */
#if !defined(HAVE_STRCASECMP) && !defined(__MINGW32__)
size_t strcasecmp(const char *left, const char *right);
#endif

#if !defined(HAVE_STRNCASECMP) && !defined(__MINGW32__)
size_t strncasecmp(const char *left, const char *right, size_t n);
#endif

#define popen _popen
#define pclose _pclose

/* End of prototypes in the wrong file */

#endif
