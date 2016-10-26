#include <sys\utime.h>

#define utimbuf _utimbuf
int usleep(unsigned int);
int gettimeofday(struct timeval *tv, void *tz);
