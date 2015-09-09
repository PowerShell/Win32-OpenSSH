#ifndef COMPAT_UIO_H
#define COMPAT_UIO_H 1


/* Compatibility header to avoid #ifdefs on Win32 */

#include <sys/socket.h>

#define _O_BINARY       0x8000

/* All socket io stuff has been replaced with read/Close/Write, so this works now */
//#define open	_open
//#define pipe(a)	_pipe(a, 2048, _O_BINARY)
//#define dup		_dup
//#define dup2	_dup2

#ifdef __MINGW32__
struct iovec
{
	void *iov_base;
	size_t iov_len;
};
#endif

#endif
