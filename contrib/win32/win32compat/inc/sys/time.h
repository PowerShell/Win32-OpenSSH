#include <sys\utime.h>

#define utimbuf _utimbuf
#define utimes w32_utimes

int usleep(unsigned int);
int gettimeofday(struct timeval *, void *);
int nanosleep(const struct timespec *, struct timespec *);
int w32_utimes(const char *, struct timeval *);