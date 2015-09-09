#ifndef COMPAT_UNISTD_H
#define COMPAT_UNISTD_H 1


/* Compatibility header to avoid lots of #ifdefs in includes.h on Win32 */

#include <sys/uio.h>
#include <conio.h>
#include <direct.h>

/* We can't put these in string.h since we can't easily override that header, so here they are */
#if !defined(HAVE_STRCASECMP) && !defined(__MINGW32__)
size_t strcasecmp(const char *left, const char *right);
#endif

#if !defined(HAVE_STRNCASECMP) && !defined(__MINGW32__)
size_t strncasecmp(const char *left, const char *right, size_t n);
#endif

int gettimeofday (struct timeval *tv, void *tz);
/* End of prototypes in the wrong file */

#endif
