/* $OpenBSD: version.h,v 1.77 2016/07/24 11:45:36 djm Exp $ */

#define SSH_VERSION	"OpenSSH_7.3"

#ifndef WIN32_FIXME
#define SSH_PORTABLE	"p1"
#else
#ifdef WIN32_VS
#define SSH_PORTABLE	"p1 Microsoft_Win32_port_with_VS"
#else
#define SSH_PORTABLE	"p1 Microsoft_Win32_port"
#endif
#endif
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE
