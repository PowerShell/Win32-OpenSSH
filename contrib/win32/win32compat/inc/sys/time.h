#include <sys\utime.h>

#define utimbuf _utimbuf
#define utimes w32_utimes

int usleep(unsigned int);
int gettimeofday(struct timeval *tv, void *tz);
int nanosleep(const struct timespec *req, struct timespec *rem);
int w32_utimes(const char *filename, struct timeval *tvp);