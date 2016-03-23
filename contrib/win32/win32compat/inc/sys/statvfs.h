#pragma once

#define ST_RDONLY	1
#define ST_NOSUID	2
typedef unsigned long fsblkcnt_t;
typedef unsigned long fsfilcnt_t;

struct statvfs {
	unsigned long f_bsize;	/* File system block size. */
	unsigned long f_frsize;	/* Fundamental file system block size. */
	fsblkcnt_t f_blocks;	/* Total number of blocks on file system in */
				/* units of f_frsize. */
	fsblkcnt_t    f_bfree;	/* Total number of free blocks. */
	fsblkcnt_t    f_bavail;	/* Number of free blocks available to  */
				/* non-privileged process.  */
	fsfilcnt_t    f_files;	/* Total number of file serial numbers. */
	fsfilcnt_t    f_ffree;	/* Total number of free file serial numbers. */
	fsfilcnt_t    f_favail;	/* Number of file serial numbers available to */
				/* non-privileged process. */
	unsigned long f_fsid;	/* File system ID. */
	unsigned long f_flag;	/* BBit mask of f_flag values. */
	unsigned long f_namemax;/*  Maximum filename length. */
};

int statvfs(const char *, struct statvfs *);
int fstatvfs(int, struct statvfs *);