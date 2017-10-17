#pragma once
#include "..\crtheaders.h"
#include "types.h"
#include SYS_STAT_H

#define _S_IFLNK  0xA000 // symbolic link
#define _S_IFSOCK 0xC000 // socket

#define S_IFMT   _S_IFMT
#define S_IFDIR  _S_IFDIR
#define S_IFCHR  _S_IFCHR
#define S_IFREG  _S_IFREG
#define S_IREAD  _S_IREAD
#define S_IWRITE _S_IWRITE
#define S_IEXEC  _S_IEXEC
#define S_IFLNK  _S_IFLNK
#define S_IFSOCK _S_IFSOCK

# define S_ISUID            0x800 
# define S_ISGID            0x400

#define READ_PERMISSIONS (FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA)
#define WRITE_PERMISSIONS (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA)
#define EXECUTE_PERMISSIONS (READ_PERMISSIONS | FILE_EXECUTE)

int w32_fstat(int fd, struct w32_stat *buf);
#define fstat(a,b)	w32_fstat((a), (b))

int w32_stat(const char *path, struct w32_stat *buf);
#define stat w32_stat
#define lstat w32_stat

int w32_mkdir(const char *pathname, unsigned short mode);
#define mkdir w32_mkdir

int w32_chmod(const char *, mode_t);
#define chmod w32_chmod

struct w32_stat {
	dev_t     st_dev;     /* ID of device containing file */
	unsigned short     st_ino;     /* inode number */
	unsigned short    st_mode;    /* protection */
	short    st_nlink;   /* number of hard links */
	short     st_uid;     /* user ID of owner */
	short     st_gid;     /* group ID of owner */
	dev_t     st_rdev;    /* device ID (if special file) */
	__int64     st_size;    /* total size, in bytes */
	__int64    st_atime;   /* time of last access */
	__int64    st_mtime;   /* time of last modification */
	__int64    st_ctime;   /* time of last status change */
};


void strmode(mode_t mode, char *p);

int get_others_file_permissions(wchar_t * file_name, int isReadOnlyFile);
