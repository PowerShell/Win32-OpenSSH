#include "crtheaders.h"
#include FCNTL_H

/*fcntl commands*/
#define F_GETFL 0x1
#define F_SETFL 0x2
#define F_GETFD 0x4
#define F_SETFD 0x8

/*fd flags*/
#define FD_CLOEXEC 0x1

#define F_OK 0


int w32_fcntl(int fd, int cmd, ... /* arg */);
#define fcntl(a,b,...)		w32_fcntl((a), (b),  __VA_ARGS__)

#define open w32_open
int w32_open(const char *pathname, int flags, ...);

void* w32_fd_to_handle(int fd);
int w32_allocate_fd_for_handle(void* h, int is_sock);

#define O_ACCMODE	  0x0003
#define O_RDONLY     _O_RDONLY
#define O_WRONLY     _O_WRONLY
#define O_RDWR       _O_RDWR
#define O_APPEND     _O_APPEND
#define O_CREAT      _O_CREAT
#define O_TRUNC      _O_TRUNC
#define O_EXCL       _O_EXCL
#define O_TEXT       _O_TEXT
#define O_BINARY     _O_BINARY
#define O_RAW        _O_BINARY
#define O_TEMPORARY  _O_TEMPORARY
#define O_NOINHERIT  _O_NOINHERIT
#define O_SEQUENTIAL _O_SEQUENTIAL
#define O_RANDOM     _O_RANDOM
#define O_U16TEXT     _O_U16TEXT