#ifndef COMPAT_TYPES_H
#define COMPAT_TYPES_H 1


/* Compatibility header to allow code that uses these types to compile on Win32 */
				/* device code */

#if defined(__MINGW32__)

typedef unsigned short _mode_t;
typedef _mode_t mode_t;

//typedef long time_t;
typedef long long __time64_t;
typedef long long off64_t;

/* On Win32 group and other permissions are the same as user permissions, sort of */
/*
FIXME: GFPZR: In newer GCC versions these seems to be defined.
*/
/*
#ifndef S_IXGRP
#define S_IXGRP S_IXUSR
#endif

#ifndef S_IXOTH
#define S_IXOTH S_IXUSR
#endif
*/
#endif

#endif
