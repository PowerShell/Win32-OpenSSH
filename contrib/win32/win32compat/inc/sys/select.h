/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* POSIX header and needed function definitions 
*/
#pragma once

/* total fds that can be allotted */
#define MAX_FDS 256  /* a 2^n number */

typedef struct w32_fd_set_ {
	unsigned char bitmap[MAX_FDS >> 3];
}w32_fd_set;

#define fd_set w32_fd_set

#undef FD_ZERO
#define FD_ZERO(set) (memset( (set), 0, sizeof(w32_fd_set)))
#undef FD_SET
#define FD_SET(fd,set) ( (set)->bitmap[(fd) >> 3] |= (0x80 >> ((fd) % 8)))
#undef FD_ISSET
#define FD_ISSET(fd, set) (( (set)->bitmap[(fd) >> 3] & (0x80 >> ((fd) % 8)))?1:0)
#undef FD_CLR
#define FD_CLR(fd, set) ((set)->bitmap[(fd) >> 3] &= (~(0x80 >> ((fd) % 8))))

#undef FD_SETSIZE
#define FD_SETSIZE MAX_FDS

int w32_select(int fds, w32_fd_set * , w32_fd_set * , w32_fd_set * ,
	const struct timeval *);
#define select(a,b,c,d,e)	w32_select((a), (b), (c), (d), (e))



