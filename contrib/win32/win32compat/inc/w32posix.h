/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Win32 renamed POSIX APIs
*/
#pragma once
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdio.h>
#include "defs.h"
#include "utf.h"
#include "sys\param.h"

typedef struct w32_fd_set_ {
	unsigned char bitmap[MAX_FDS >> 3];
}w32_fd_set;

#define fd_set w32_fd_set

void w32posix_initialize();
void w32posix_done();

/*network i/o*/
int w32_socket(int domain, int type, int protocol);
int w32_accept(int fd, struct sockaddr* addr, int* addrlen);
int w32_setsockopt(int fd, int level, int optname, const void* optval, int optlen);
int w32_getsockopt(int fd, int level, int optname, void* optval, int* optlen);
int w32_getsockname(int fd, struct sockaddr* name, int* namelen);
int w32_getpeername(int fd, struct sockaddr* name, int* namelen);
int w32_listen(int fd, int backlog);
int w32_bind(int fd, const struct sockaddr *name, int namelen);
int w32_connect(int fd, const struct sockaddr* name, int namelen);
int w32_recv(int fd, void *buf, size_t len, int flags);
int w32_send(int fd, const void *buf, size_t len, int flags);
int w32_shutdown(int fd, int how);
int w32_socketpair(int domain, int type, int protocol, int sv[2]);

/*non-network (file) i/o*/
#undef fdopen
#define fdopen(a,b)	w32_fdopen((a), (b))
#define fstat(a,b)	w32_fstat((a), (b))

#define rename w32_rename

struct w32_stat;
int w32_pipe(int *pfds);
int w32_open(const char *pathname, int flags, ...);
int w32_read(int fd, void *dst, size_t max);
int w32_write(int fd, const void *buf, unsigned int max);
int w32_writev(int fd, const struct iovec *iov, int iovcnt);
int w32_fstat(int fd, struct w32_stat *buf);
int w32_stat(const char *path, struct w32_stat *buf);
long w32_lseek( int fd, long offset, int origin);
int w32_isatty(int fd);
FILE* w32_fdopen(int fd, const char *mode);
int w32_rename(const char *old_name, const char *new_name);

/*common i/o*/
#define fcntl(a,b,...)		w32_fcntl((a), (b),  __VA_ARGS__)
#define select(a,b,c,d,e)	w32_select((a), (b), (c), (d), (e))
int w32_close(int fd);
int w32_select(int fds, w32_fd_set* readfds, w32_fd_set* writefds, w32_fd_set* exceptfds, 
	const struct timeval *timeout);
int w32_fcntl(int fd, int cmd, ... /* arg */);
int w32_dup(int oldfd);
int w32_dup2(int oldfd, int newfd);


/* misc */
unsigned int w32_alarm(unsigned int seconds);
sighandler_t w32_signal(int signum, sighandler_t handler);
int w32_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int w32_raise(int sig);
int w32_kill(int pid, int sig);
int w32_gethostname(char *, size_t);
void w32_freeaddrinfo(struct addrinfo *);
int w32_getaddrinfo(const char *, const char *,
        const struct addrinfo *, struct addrinfo **);
FILE* w32_fopen_utf8(const char *, const char *);
int w32_ftruncate(int fd, off_t length);
char* w32_programdir();
int w32_fsync(int fd);
int w32_ioctl(int d, int request, ...);

/* Shutdown constants */
#define SHUT_WR SD_SEND
#define SHUT_RD SD_RECEIVE
#define SHUT_RDWR SD_BOTH

/* Other constants */
#define IN_LOOPBACKNET	127 /* 127.* is the loopback network */
#define MAXHOSTNAMELEN	64


/* Errno helpers */
#ifndef EXX
#define EXX			WSAEMFILE
#endif
#ifndef EXX1
#define EXX1			WSAENOBUFS
#endif
#ifndef ESOCKTNOSUPPORT
#define	ESOCKTNOSUPPORT         WSAESOCKTNOSUPPORT
#endif
#ifndef ENOTUNREACH
#define ENOTUNREACH		WSAENOTUNREACH
#endif
#ifndef EPFNOSUPPORT
#define EPFNOSUPPORT	        WSAEPFNOSUPPORT
#endif

int spawn_child(char* cmd, int in, int out, int err, DWORD flags);


/* 
 * these routines are temporarily defined here to allow transition 
 * from older POSIX wrapper to the newer one. After complete transition 
 * these should be gone or moved to a internal header.
 */
HANDLE w32_fd_to_handle(int fd);
int w32_allocate_fd_for_handle(HANDLE h, BOOL is_sock);
int sw_add_child(HANDLE child, DWORD pid);

/* temporary definitions to aid in transition */
#define sfd_to_handle(a) w32_fd_to_handle((a))

/* TODO - These defs need to revisited and positioned appropriately */
#define environ _environ

typedef unsigned int	nfds_t;

struct w32_pollfd {

	int  fd;
	SHORT   events;
	SHORT   revents;

};

#define pollfd w32_pollfd

struct iovec
{
	void *iov_base;
	size_t iov_len;
};


#define bzero(p,l) memset((void *)(p),0,(size_t)(l))

void
explicit_bzero(void *b, size_t len);

/* string.h overrides */
#define strcasecmp _stricmp
#define strncasecmp _strnicmp

/* stdio.h overrides */
#define fopen w32_fopen_utf8
#define popen _popen
#define pclose _pclose

void convertToBackslash(char *str);
void convertToForwardslash(char *str);
