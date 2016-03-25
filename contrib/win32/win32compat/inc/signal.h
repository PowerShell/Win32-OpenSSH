/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* POSIX header and needed function definitions
*/
#ifndef COMPAT_SIGNAL_H
#define COMPAT_SIGNAL_H 1

#include "w32posix.h"

#define signal(a,b)	w32_signal((a), (b))
#define mysignal(a,b)	w32_signal((a), (b))
#define raise(a)	w32_raise(a)
#define kill(a,b)	w32_kill((a), (b))
#define sigprocmask(a,b,c) w32_sigprocmask((a), (b), (c))

#define SIGINT	W32_SIGINT		
#define SIGSEGV	W32_SIGSEGV		
#define SIGPIPE	W32_SIGPIPE		
#define SIGCHLD	W32_SIGCHLD		
#define SIGALRM	W32_SIGALRM		
#define SIGTSTP	W32_SIGTSTP		 
#define SIGHUP	W32_SIGHUP		
#define SIGQUIT	W32_SIGQUIT		 
#define SIGTERM	W32_SIGTERM		
#define SIGTTIN	W32_SIGTTIN		
#define SIGTTOU	W32_SIGTTOU		
#define SIGWINCH W32_SIGWINCH

#define SIG_DFL	W32_SIG_DFL
#define SIG_IGN	W32_SIG_IGN
#define SIG_ERR W32_SIG_ERR

#endif