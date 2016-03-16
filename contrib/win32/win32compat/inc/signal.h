/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* POSIX header and needed function definitions
*/
#ifndef COMPAT_SIGNAL_H
#define COMPAT_SIGNAL_H 1

#include "w32posix.h"

// Signal types
#define SIGINT          2   // interrupt
#define SIGILL          4   // illegal instruction - invalid function image
#define SIGFPE          8   // floating point exception
#define SIGSEGV         11  // segment violation
#define SIGTERM         15  // Software termination signal from kill
#define SIGBREAK        21  // Ctrl-Break sequence
#define SIGABRT         22  // abnormal termination triggered by abort call

#define SIGABRT_COMPAT  6   // SIGABRT compatible with other platforms, same as SIGABRT

#define SIGALRM 14
#define SIGCHLD 26
#define SIGHUP  1
#define SIGPIPE 27
#define SIGQUIT 3

// Signal action codes
#define SIG_DFL (0)     // default signal action
#define SIG_IGN (1)     // ignore signal
#define SIG_GET (2)     // return current value
#define SIG_SGE (3)     // signal gets error
#define SIG_ACK (4)     // acknowledge

#endif