#pragma once
#include "..\w32posix.h"

//#define _W_INT(w)	(*(int*)&(w))	/* convert union wait to int */
//#define WIFEXITED(w)	(!((_W_INT(w)) & 0377))
//#define WIFSTOPPED(w)	((_W_INT(w)) & 0100)
//#define WIFSIGNALED(w)	(!WIFEXITED(w) && !WIFSTOPPED(w))
//#define WEXITSTATUS(w)	(int)(WIFEXITED(w) ? ((_W_INT(w) >> 8) & 0377) : -1)
//#define WTERMSIG(w)	(int)(WIFSIGNALED(w) ? (_W_INT(w) & 0177) : -1)

#define WIFEXITED(w)	TRUE
#define WIFSTOPPED(w)	TRUE
#define WIFSIGNALED(w)	FALSE
#define WEXITSTATUS(w)	w
#define WTERMSIG(w)	-1

int waitpid(int pid, int *status, int options);