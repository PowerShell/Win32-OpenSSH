#include <Windows.h>
#include "inc\defs.h"

int usleep(unsigned int useconds)
{
	Sleep(useconds / 1000);
	return 1;
}

pid_t waitpid(pid_t pid, int *status, int options) {
	/* TODO - implement this*/
	return 0;
}