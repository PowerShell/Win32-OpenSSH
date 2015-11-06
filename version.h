/* $OpenBSD: version.h,v 1.75 2015/08/21 03:45:26 djm Exp $ */

#define SSH_VERSION	"OpenSSH_7.1"

#ifndef WIN32_FIXME
#define SSH_PORTABLE	"p1"
#else
#ifdef WIN32_VS
#define SSH_PORTABLE	"p1 Microsoft Win32 port with VS"
#else
#define SSH_PORTABLE	"p1 Microsoft Win32 port"
#endif
#endif
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE
