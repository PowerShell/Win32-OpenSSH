/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Redefined and missing POSIX macros
*/
#pragma once

#include <memory.h>

#define fd_set w32_fd_set
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


/*open access modes. only one of these can be specified*/
#define O_RDONLY    0x1
#define O_WRONLY    0x2
#define O_RDWR      0x4
/*open file creation and file status flags // can be bitwise-or'd*/
#define O_NONBLOCK  0x10    /*io operations wont block*/
#define O_APPEND    0x20    /*file is opened in append mode*/
#define O_CREAT     0x40    /*If the file does not exist it will be created*/
/* 
 * If the file exists and is a regular file, and the file is successfully 
 * opened O_RDWR or O_WRONLY, its length shall be truncated to 0, and the mode 
 * and owner shall be unchanged
 */
#define O_TRUNC     0x80    
 //If O_CREAT and O_EXCL are set, open() shall fail if the file exists
#define O_EXCL      0x100   
#define O_BINARY    0x200   //Gives raw data (while O_TEXT normalises line endings
// open modes
#define S_IRUSR     00400   //user has read permission 
#define S_IWUSR     00200   //user has write permission 
#define S_IRGRP     00040   //group has read permission 
#define S_IROTH     00004   //others have read permission