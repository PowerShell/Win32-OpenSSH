#ifndef _LIBWINSOCKHELP_SOCKET_H_
#define _LIBWINSOCKHELP_SOCKET_H_ 1

/* Include the original header */
#define WIN32_LEAN_AND_MEAN 1
#define _WIN32_WINNT 0x501

#include <winsock2.h>
#include <windows.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Set to 1 (macros as function decl's) or 0 (simple macros) depending upon needs */
#define NEED_FUNC_MACROS 0


/* Declare our indirection functions */
FILE* WSHELPfdopen(int sfd, const char *mode);
int WSHELPfstat(int sfd, struct stat *buf);
int WSHELPisatty (int sfd);
int WSHELPpipe(int *pfds);
int WSHELPdup (int oldfd);
int WSHELPdup2(int oldfd, int newfd);
int WSHELPopen (const char *pathname, int flags, ...);
int WSHELPwopen(const wchar_t *pathname, int flags, ...);
int WSHELPcreat (const char *pathname, int mode);
int WSHELPsocket (int af, int type, int protocol);
int WSHELPsetsockopt (int sfd, int level, int optname, const char* optval, int optlen);
int WSHELPgetsockopt(int sfd, int level, int optname, char* optval, int* optlen);
int WSHELPgetsockname(int sfd, struct sockaddr* name, int* namelen);
int WSHELPgetpeername(int sfd, struct sockaddr* name, int* namelen);
int WSHELPioctlsocket(int sfd, long cmd, u_long* argp);
int WSHELPlisten (int sfd, int backlog);
int WSHELPbind (int sfd, const struct sockaddr *name, int namelen);
int WSHELPconnect (int sfd, const struct sockaddr* name, int namelen);
int WSHELPshutdown(int sfd, int how);
int WSHELPaccept(int sfd, struct sockaddr* addr, int* addrlen);
int WSHELPselect (int sfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval *timeout);


/* Other helpers */
void WSHELPinitialize();
int map_standard_descriptor(int *fd);
void allocate_standard_descriptor(int fd);


/* Redirect callers of socket functions to use our indirection functions */
#if NEED_FUNC_MACROS
#define isatty(sfd)								WSHELPisatty(sfd)
#define fstat(sfd, buf)                                                         WSHELPfstat(sfd, buf)
#define fdopen(sfd, mode)                                                       WSHELPfdopen(sfd, mode)
#define pipe(pfds)								WSHELPpipe(pfds)
#define dup(oldfd)                                                              WSHELPdup(oldfd)
#define socket(af, type, protocol)						WSHELPsocket(af, type, protocol)
#define setsockopt(sfd, level, optname, optval, optlen)				WSHELPsetsockopt(sfd, level, optname, optval, optlen)
#define getsockopt(sfd, level, optname, optval, optlen)				WSHELPgetsockopt(sfd, level, optname, optval, optlen)
#define getsockname(sfd, name, namelen)						WSHELPgetsockname(sfd, name, namelen)
#define getpeername(sfd, name, namelen)						WSHELPgetpeername(sfd, name, namelen)
#define ioctlsocket(sfd, cmd, argp)						WSHELPioctlsocket(sfd, cmd, argp)
#define listen(sfd, backlog)							WSHELPlisten(sfd, backlog)
#define bind(sfd, name, namelen)						WSHELPbind(sfd, name, namelen)
#define connect(sfd, name, namelen)						WSHELPconnect(sfd, name, namelen)
#define shutdown(sfd, how)							WSHELPshutdown(sfd, how)
#define accept(sfd, addr, addrlen)						WSHELPaccept(sfd, addr, addrlen)
#define select(sfds, readsfds, writesfds, exceptsfds, timeout)		        WSHELPselect(sfds, readsfds, writesfds, exceptsfds, timeout)
#else /* NEED_FUNC_MACROS */
//#define isatty				WSHELPisatty
#define fstat                           WSHELPfstat
#define fdopen                          WSHELPfdopen
#define pipe				WSHELPpipe
#define socket				WSHELPsocket
#define dup                             WSHELPdup
#define dup2                            WSHELPdup2
#define open                            WSHELPopen
#define creat                           WSHELPcreat
#define setsockopt			WSHELPsetsockopt
#define getsockopt			WSHELPgetsockopt
#define getsockname			WSHELPgetsockname
#define getpeername			WSHELPgetpeername
#define ioctlsocket			WSHELPioctlsocket
#define listen				WSHELPlisten
#define bind				WSHELPbind
#define connect				WSHELPconnect
#define shutdown			WSHELPshutdown
#define accept				WSHELPaccept
#define select				WSHELPselect
#endif /* NEED_FUNC_MACROS */

/* Declare new functions */
int socketpair(int socks[2]);

/* Debug helpers */
void debug_sfd(int sfd);

/* Include the original header */
#include <io.h>

/* Declare our indirection functions */
int WSHELPread(int sfd, void *dst, unsigned int max);
int WSHELPwrite(int sfd, const void *buf, unsigned int max);
int WSHELPclose(int sfd);

/* Redirect callers of io functions to use our indirection functions */
#if NEED_FUNC_MACROS
#define read(fd, dst, max)		WSHELPread(fd, dst, max)
#define write(fd, buf, max)		WSHELPwrite(fd, buf, max)
#define close(fd)			WSHELPclose(fd)
#else /* NEED_FUNC_MACROS */
#define read WSHELPread
#define write WSHELPwrite
#define close WSHELPclose
#endif /* NEED_FUNC_MACROS */

#ifndef sleep
#define sleep(a) Sleep(1000 * a)
#endif

/* Shutdown constants */
#define SHUT_WR SD_SEND
#define SHUT_RD SD_RECEIVE
#define SHUT_RDWR SD_BOTH

/* Other constants */
#define IN_LOOPBACKNET	127 /* 127.* is the loopback network */
#define MAXHOSTNAMELEN	64


/* Errno helpers */
#ifndef ENETDOWN
#define ENETDOWN		WSAENETDOWN
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT            WSAEAFNOSUPPORT
#endif
#ifndef EINPROGRESS
#define	EINPROGRESS		WSAEINPROGRESS
#endif
#ifndef EXX
#define EXX			WSAEMFILE
#endif
#ifndef EXX1
#define EXX1			WSAENOBUFS
#endif
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT	        WSAEPROTONOSUPPORT
#endif
#ifndef EPROTOTYPE
#define EPROTOTYPE		WSAEPROTOTYPE
#endif
#ifndef ESOCKTNOSUPPORT
#define	ESOCKTNOSUPPORT         WSAESOCKTNOSUPPORT
#endif
#ifndef EADDRINUSE
#define EADDRINUSE		WSAEADDRINUSE
#endif
#ifndef EISCONN
#define EISCONN			WSAEISCONN
#endif
#ifndef ENOTSOCK
#define ENOTSOCK		WSAENOTSOCK
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP		WSAENOTSUPP
#endif
#ifndef EALREADY
#define EALREADY		WSAEALREADY
#endif
#ifndef ECONNREFUSED
#define	ECONNREFUSED	        WSAECONNREFUSED
#endif
#ifndef ENOTUNREACH
#define ENOTUNREACH		WSAENOTUNREACH
#endif
#ifndef EHOSTUNREACH
#define EHOSTUNREACH	        WSAEHOSTUNREACH
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT		WSAETIMEDOUT
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK		WSAEWOULDBLOCK
#endif
#ifndef EACCES
#define	EACCES			WSAEACCESS
#endif
#ifndef ECONNRESET
#define ECONNRESET		WSAECONNRESET
#endif
#ifndef ENOPROTOOPT
#define ENOPROTOOPT		WSAENOPROTOOPT
#endif
#ifndef EPFNOSUPPORT
#define EPFNOSUPPORT	        WSAEPFNOSUPPORT
#endif
#ifndef ENOTCONN
#define ENOTCONN		WSAENOTCONN
#endif


#endif
