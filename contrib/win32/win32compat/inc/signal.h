/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* POSIX header and needed function definitions
*/
#ifndef COMPAT_SIGNAL_H
#define COMPAT_SIGNAL_H 1


/* signal related defs*/
/* supported signal types */
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
#define W32_SIGWINCH	        11

#define W32_SIGMAX		12
/* these signals are not supposed to be raised on Windows*/
#define W32_SIGSTOP             13
#define W32_SIGABRT             14
#define W32_SIGFPE              15
#define W32_SIGILL              16
#define W32_SIGKILL             17
#define W32_SIGUSR1             18
#define W32_SIGUSR2             19

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

/* signal action codes*/
#define W32_SIG_ERR		((sighandler_t)-1)
#define W32_SIG_DFL		((sighandler_t)0)
#define W32_SIG_IGN		((sighandler_t)1)

sighandler_t w32_signal(int signum, sighandler_t handler);
//#define signal(a,b)	w32_signal((a), (b))
//#define mysignal(a,b)	w32_signal((a), (b))
sighandler_t mysignal(int signum, sighandler_t handler);


int w32_raise(int sig);
#define raise(a)	w32_raise(a)

int w32_kill(int pid, int sig);
#define kill(a,b)	w32_kill((a), (b))

int w32_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
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
#define SIGSTOP  W32_SIGSTOP
#define SIGSTOP W32_SIGSTOP            
#define SIGABRT W32_SIGABRT 
#define SIGFPE W32_SIGFPE 
#define SIGILL W32_SIGILL 
#define SIGKILL W32_SIGKILL
#define SIGUSR1 W32_SIGUSR1
#define SIGUSR2 W32_SIGUSR2

#define SIG_DFL	W32_SIG_DFL
#define SIG_IGN	W32_SIG_IGN
#define SIG_ERR W32_SIG_ERR

/* TOTO - implement http://www.manpagez.com/man/3/sys_siglist/*/
#undef NSIG
#define NSIG 0

#endif