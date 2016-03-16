/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Redefined and missing POSIX macros
*/
#pragma once

#include <memory.h>

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
typedef void(*sighandler_t)(int);
// Signal types
#define SIGINT          2   // interrupt
#define SIGSEGV         11  // segment violation

#define SIGPIPE		27
#define SIGCHLD		26
#define SIGALRM		14
#define SIGTSTP		5 //"CTRL+Z" - no portable number

#define SIGHUP		1 //Terminate from console
#define SIGQUIT		3 
#define SIGTERM		15// Software termination signal from kill
#define SIGTTIN		6//noportabel number
#define SIGTTOU		7 //no portable number



//#define SIGINT          2   // interrupt
//#define SIGILL          4   // illegal instruction - invalid function image
//#define SIGFPE          8   // floating point exception
//#define SIGSEGV         11  // segment violation
//#define SIGTERM         15  // Software termination signal from kill
//#define SIGBREAK        21  // Ctrl-Break sequence
//#define SIGABRT         22  // abnormal termination triggered by abort call
//#define SIGWINCH 
//
//#define SIGABRT_COMPAT  6   // SIGABRT compatible with other platforms, same as SIGABRT
//
//#define SIGALRM 14
//#define SIGCHLD 26
//#define SIGHUP  1
//#define SIGPIPE 27
//#define SIGQUIT 3

// Signal action codes
#define SIG_DFL (0)     // default signal action
#define SIG_IGN (1)     // ignore signal
#define SIG_GET (2)     // return current value
#define SIG_SGE (3)     // signal gets error
#define SIG_ACK (4)     // acknowledge
