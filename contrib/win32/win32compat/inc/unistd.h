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
#define realpath(a, b) w32_realpath((a),(b))

int daemon(int nochdir, int noclose);

#endif
