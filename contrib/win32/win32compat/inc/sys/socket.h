/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* POSIX header and needed function definitions
*/

#pragma once
#include <WinSock2.h>
#include <WS2tcpip.h>

/* Shutdown constants */
#define SHUT_WR SD_SEND
#define SHUT_RD SD_RECEIVE
#define SHUT_RDWR SD_BOTH

/* Other constants */
#define IN_LOOPBACKNET	127 /* 127.* is the loopback network */
#define MAXHOSTNAMELEN	64

#define EPFNOSUPPORT	        WSAEPFNOSUPPORT

/*network i/o*/
int w32_socket(int domain, int type, int protocol);
#define socket(a,b,c)		w32_socket((a), (b), (c))

int w32_accept(int fd, struct sockaddr* addr, int* addrlen);
#define accept(a,b,c)		w32_accept((a), (b), (c))

int w32_setsockopt(int fd, int level, int optname, const void* optval, int optlen);
#define setsockopt(a,b,c,d,e)	w32_setsockopt((a), (b), (c), (d), (e))

int w32_getsockopt(int fd, int level, int optname, void* optval, int* optlen);
#define getsockopt(a,b,c,d,e)	w32_getsockopt((a), (b), (c), (d), (e))

int w32_getsockname(int fd, struct sockaddr* name, int* namelen);
#define getsockname(a,b,c)	w32_getsockname((a), (b), (c))

int w32_getpeername(int fd, struct sockaddr* name, int* namelen);
#define getpeername(a,b,c)	w32_getpeername((a), (b), (c))

int w32_listen(int fd, int backlog);
#define listen(a,b)		    w32_listen((a), (b))

int w32_bind(int fd, const struct sockaddr *name, int namelen);
#define bind(a,b,c)		    w32_bind((a), (b), (c))

int w32_connect(int fd, const struct sockaddr* name, int namelen);
#define connect(a,b,c)		w32_connect((a), (b), (c))

int w32_recv(int fd, void *buf, size_t len, int flags);
#define recv(a,b,c,d)		w32_recv((a), (b), (c), (d))

int w32_send(int fd, const void *buf, size_t len, int flags);
#define send(a,b,c,d)		w32_send((a), (b), (c), (d))

int w32_shutdown(int fd, int how);
#define shutdown(a,b)		w32_shutdown((a), (b))

int w32_socketpair(int domain, int type, int protocol, int sv[2]);
#define socketpair(a,b,c,d)	w32_socketpair((a), (b), (c), (d))

void w32_freeaddrinfo(struct addrinfo *);
#define freeaddrinfo        w32_freeaddrinfo

int w32_getaddrinfo(const char *, const char *,
	const struct addrinfo *, struct addrinfo **);
#define getaddrinfo         w32_getaddrinfo

struct w32_pollfd {
	int  fd;
	short   events;
	short   revents;
};
#define pollfd w32_pollfd

