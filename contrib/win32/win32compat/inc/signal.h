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


#endif