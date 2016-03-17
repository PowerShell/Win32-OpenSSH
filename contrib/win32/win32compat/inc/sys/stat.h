/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* private stat.h (all code relying on POSIX wrapper should include this version
* instead of the one in Windows SDK. 
*/
#pragma once

/* flags COPIED FROM STAT.H
 */
#define _S_IFMT   0xF000 // File type mask
#define _S_IFDIR  0x4000 // Directory
#define _S_IFCHR  0x2000 // Character special
#define _S_IFIFO  0x1000 // Pipe
#define _S_IFREG  0x8000 // Regular
#define _S_IREAD  0x0100 // Read permission, owner
#define _S_IWRITE 0x0080 // Write permission, owner
#define _S_IEXEC  0x0040 // Execute/search permission, owner


#define S_IFMT   _S_IFMT
#define S_IFDIR  _S_IFDIR
#define S_IFCHR  _S_IFCHR
#define S_IFREG  _S_IFREG
#define S_IREAD  _S_IREAD
#define S_IWRITE _S_IWRITE
#define S_IEXEC  _S_IEXEC

#define stat w32_stat
#define lstat w32_stat
#define mkdir w32_mkdir

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