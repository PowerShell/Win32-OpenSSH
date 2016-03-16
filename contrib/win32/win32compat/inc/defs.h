/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Redefined and missing POSIX macros
*/
#pragma once

#include <memory.h>

#undef FD_ZERO
#define FD_ZERO(set) (memset( (set), 0, sizeof(w32_fd_set)))
#undef FD_SET
#define FD_SET(fd,set) ( (set)->bitmap[(fd) >> 3] |= (0x80 >> ((fd) % 8)))
#undef FD_ISSET
#define FD_ISSET(fd, set) (( (set)->bitmap[(fd) >> 3] & (0x80 >> ((fd) % 8)))?1:0)
#undef FD_CLR
#define FD_CLR(fd, set) ((set)->bitmap[(fd) >> 3] &= (~(0x80 >> ((fd) % 8))))

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

/*fcntl commands*/
#define F_GETFL 0x1
#define F_SETFL 0x2
#define F_GETFD 0x4
#define F_SETFD 0x8

/*fd flags*/
#define FD_CLOEXEC 0x1
