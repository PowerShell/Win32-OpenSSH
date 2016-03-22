#include <Windows.h>

int usleep(unsigned int useconds)
{
	Sleep(useconds / 1000);
	return 1;
}