/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Redefined and missing POSIX macros
*/
#pragma once

#include <memory.h>

/* total fds that can be allotted */
#define MAX_FDS 256  /* a 2^n number */

#undef FD_ZERO
#define FD_ZERO(set) (memset( (set), 0, sizeof(w32_fd_set)))
#undef FD_SET
#define FD_SET(fd,set) ( (set)->bitmap[(fd) >> 3] |= (0x80 >> ((fd) % 8)))
#undef FD_ISSET
#define FD_ISSET(fd, set) (( (set)->bitmap[(fd) >> 3] & (0x80 >> ((fd) % 8)))?1:0)
#undef FD_CLR
#define FD_CLR(fd, set) ((set)->bitmap[(fd) >> 3] &= (~(0x80 >> ((fd) % 8))))

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

/*fcntl commands*/
#define F_GETFL 0x1
#define F_SETFL 0x2
#define F_GETFD 0x4
#define F_SETFD 0x8

/*fd flags*/
#define FD_CLOEXEC 0x1

/* signal related defs*/
/* signal types */
#define W32_SIGINT		0   
#define W32_SIGSEGV		1	  

#define W32_SIGPIPE		2
#define W32_SIGCHLD		3
#define W32_SIGALRM		4
#define W32_SIGTSTP		5 

#define W32_SIGHUP		6 
#define W32_SIGQUIT		7 
#define W32_SIGTERM		8
#define W32_SIGTTIN		9
#define W32_SIGTTOU		10

#define W32_SIGMAX		11

/* signal action codes*/
#define W32_SIG_ERR		-1
#define W32_SIG_DFL		0
#define W32_SIG_IGN		1
#define W32_SIG_USR		2

/* singprocmask "how" codes*/
#define SIG_BLOCK		0
#define SIG_UNBLOCK		1
#define SIG_SETMASK		2

typedef void(*sighandler_t)(int);
typedef int sigset_t;
#define sigemptyset(set) (memset( (set), 0, sizeof(sigset_t)))
#define sigaddset(set, sig) ( (*(set)) |= (0x80000000 >> (sig)))
#define sigismember(set, sig) ( (*(set) & (0x80000000 >> (sig)))?1:0 )
#define sigdelset(set, sig) ( (*(set)) &= (~( 0x80000000 >> (sig)) ) )


typedef unsigned short _mode_t;
typedef _mode_t mode_t;
typedef unsigned long pid_t;
