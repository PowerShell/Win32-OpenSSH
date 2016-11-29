/* $OpenBSD: sftp-common.c,v 1.28 2015/01/20 23:14:00 deraadt Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#ifdef WINDOWS
void strmode(mode_t mode, char *p);
void strmode_from_attrib(unsigned attrib, char *p);
#endif

#include <sys/param.h>	/* MAX */
#include <sys/types.h>
#include <sys/stat.h>

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#ifdef HAVE_UTIL_H
#include <util.h>
#endif

#include "xmalloc.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "log.h"

#include "sftp.h"
#include "sftp-common.h"

/* Clear contents of attributes structure */
void
attrib_clear(Attrib *a)
{
	a->flags = 0;
	a->size = 0;
	a->uid = 0;
	a->gid = 0;
	a->perm = 0;
	a->atime = 0;
	a->mtime = 0;
}

/* Convert from struct stat to filexfer attribs */
void
stat_to_attrib(const struct stat *st, Attrib *a)
{
	attrib_clear(a);
	a->flags = 0;
	a->flags |= SSH2_FILEXFER_ATTR_SIZE;
	a->size = st->st_size;
	a->flags |= SSH2_FILEXFER_ATTR_UIDGID;
	a->uid = st->st_uid;
	a->gid = st->st_gid;
	a->flags |= SSH2_FILEXFER_ATTR_PERMISSIONS;
	a->perm = st->st_mode;
	a->flags |= SSH2_FILEXFER_ATTR_ACMODTIME;
	a->atime = st->st_atime;
	a->mtime = st->st_mtime;
}

/* Convert from filexfer attribs to struct stat */
void
attrib_to_stat(const Attrib *a, struct stat *st)
{
	memset(st, 0, sizeof(*st));

	if (a->flags & SSH2_FILEXFER_ATTR_SIZE)
		st->st_size = a->size;
	if (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		st->st_uid = a->uid;
		st->st_gid = a->gid;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS)
		st->st_mode = a->perm;
	if (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		st->st_atime = a->atime;
		st->st_mtime = a->mtime;
	}
}

/* Decode attributes in buffer */
int
decode_attrib(struct sshbuf *b, Attrib *a)
{
	int r;

	attrib_clear(a);
	if ((r = sshbuf_get_u32(b, &a->flags)) != 0)
		return r;
	if (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		if ((r = sshbuf_get_u64(b, &a->size)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		if ((r = sshbuf_get_u32(b, &a->uid)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->gid)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		if ((r = sshbuf_get_u32(b, &a->perm)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		if ((r = sshbuf_get_u32(b, &a->atime)) != 0 ||
		    (r = sshbuf_get_u32(b, &a->mtime)) != 0)
			return r;
	}
	/* vendor-specific extensions */
	if (a->flags & SSH2_FILEXFER_ATTR_EXTENDED) {
		char *type;
		u_char *data;
		size_t dlen;
		u_int i, count;

		if ((r = sshbuf_get_u32(b, &count)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
		for (i = 0; i < count; i++) {
			if ((r = sshbuf_get_cstring(b, &type, NULL)) != 0 ||
			    (r = sshbuf_get_string(b, &data, &dlen)) != 0)
				return r;
			debug3("Got file attribute \"%.100s\" len %zu",
			    type, dlen);
			free(type);
			free(data);
		}
	}
	return 0;
}

/* Encode attributes to buffer */
int
encode_attrib(struct sshbuf *b, const Attrib *a)
{
	int r;

	if ((r = sshbuf_put_u32(b, a->flags)) != 0)
		return r;
	if (a->flags & SSH2_FILEXFER_ATTR_SIZE) {
		if ((r = sshbuf_put_u64(b, a->size)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_UIDGID) {
		if ((r = sshbuf_put_u32(b, a->uid)) != 0 ||
		    (r = sshbuf_put_u32(b, a->gid)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
		if ((r = sshbuf_put_u32(b, a->perm)) != 0)
			return r;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		if ((r = sshbuf_put_u32(b, a->atime)) != 0 ||
		    (r = sshbuf_put_u32(b, a->mtime)) != 0)
			return r;
	}
	return 0;
}

/* Convert from SSH2_FX_ status to text error message */
const char *
fx2txt(int status)
{
	switch (status) {
	case SSH2_FX_OK:
		return("No error");
	case SSH2_FX_EOF:
		return("End of file");
	case SSH2_FX_NO_SUCH_FILE:
		return("No such file or directory");
	case SSH2_FX_PERMISSION_DENIED:
		return("Permission denied");
	case SSH2_FX_FAILURE:
		return("Failure");
	case SSH2_FX_BAD_MESSAGE:
		return("Bad message");
	case SSH2_FX_NO_CONNECTION:
		return("No connection");
	case SSH2_FX_CONNECTION_LOST:
		return("Connection lost");
	case SSH2_FX_OP_UNSUPPORTED:
		return("Operation unsupported");
	default:
		return("Unknown status");
	}
	/* NOTREACHED */
}

/*
 * drwxr-xr-x    5 markus   markus       1024 Jan 13 18:39 .ssh
 */
char *
ls_file(const char *name, const struct stat *st, int remote, int si_units)
{
	int ulen, glen, sz = 0;
	struct tm *ltime = localtime(&st->st_mtime);
	char *user, *group;
	char buf[1024], mode[11+1], tbuf[12+1], ubuf[11+1], gbuf[11+1];
	char sbuf[FMT_SCALED_STRSIZE];
	time_t now;

    strmode(st->st_mode, mode);
#ifdef WINDOWS
	strmode_from_attrib(remote, mode);
#endif
	if (!remote) {
#ifndef WIN32_FIXME
        user = user_from_uid(st->st_uid, 0);
#else
        user = "\0";
        snprintf(gbuf, sizeof gbuf, "%u", (u_int)st->st_gid);
        group = gbuf;
#endif
	} else {
		snprintf(ubuf, sizeof ubuf, "%u", (u_int)st->st_uid);
		user = ubuf;
#ifdef WINDOWS
        snprintf(gbuf, sizeof gbuf, "%u", (u_int) st -> st_gid);  
        group = gbuf;
#else
	    if (!remote) {
		    group = group_from_gid(st->st_gid, 0);
	    } else {
		    snprintf(gbuf, sizeof gbuf, "%u", (u_int)st->st_gid);
		    group = gbuf;
	    }
#endif
	}
	if (ltime != NULL) {
		now = time(NULL);
		if (now - (365*24*60*60)/2 < st->st_mtime &&
		    now >= st->st_mtime)
			sz = strftime(tbuf, sizeof tbuf, "%b %e %H:%M", ltime);
		else
			sz = strftime(tbuf, sizeof tbuf, "%b %e  %Y", ltime);
	}
	if (sz == 0)
		tbuf[0] = '\0';
	ulen = MAX(strlen(user), 8);
	glen = MAX(strlen(group), 8);
	if (si_units) {
		fmt_scaled((long long)st->st_size, sbuf);
		snprintf(buf, sizeof buf, "%s %3u %-*s %-*s %8s %s %s", mode,
		    (u_int)st->st_nlink, ulen, user, glen, group,
		    sbuf, tbuf, name);
	} else {
		snprintf(buf, sizeof buf, "%s %3u %-*s %-*s %8llu %s %s", mode,
		    (u_int)st->st_nlink, ulen, user, glen, group,
		    (unsigned long long)st->st_size, tbuf, name);
	}
	return xstrdup(buf);
}

#ifdef WINDOWS

#include <sys/types.h>
#include <windows.h>

void
strmode_from_attrib(unsigned attrib, char *p)
{
	if (attrib & FILE_ATTRIBUTE_REPARSE_POINT)
		*p = 'l';
	else if (attrib & FILE_ATTRIBUTE_DIRECTORY)
		*p = 'd';
	else
		*p = '-';
}

void
strmode(mode_t mode, char *p)
{
	/* print type */
	switch (mode & S_IFMT) {
	case S_IFDIR:			/* directory */
		*p++ = 'd';
		break;
	case S_IFCHR:			/* character special */
		*p++ = 'c';
		break;
		//case S_IFBLK:			/* block special */
		//		*p++ = 'b';
		//		break;
	case S_IFREG:			/* regular */
		*p++ = '-';
		break;
		//case S_IFLNK:			/* symbolic link */
		//		*p++ = 'l';
		//		break;
#ifdef S_IFSOCK
	case S_IFSOCK:			/* socket */
		*p++ = 's';
		break;
#endif
	case _S_IFIFO:			/* fifo */
		*p++ = 'p';
		break;
	default:			/* unknown */
		*p++ = '?';
		break;
	}
	/* usr */
	if (mode & S_IRUSR)
		*p++ = 'r';
	else
		*p++ = '-';
	if (mode & S_IWUSR)
		*p++ = 'w';
	else
		*p++ = '-';
	switch (mode & (S_IXUSR)) {
	case 0:
		*p++ = '-';
		break;
	case S_IXUSR:
		*p++ = 'x';
		break;
		//case S_ISUID:
		//		*p++ = 'S';
		//		break;
		//case S_IXUSR | S_ISUID:
		//		*p++ = 's';
		//		break;
	}
	/* group */
	if (mode & S_IRGRP)
		*p++ = 'r';
	else
		*p++ = '-';
	if (mode & S_IWGRP)
		*p++ = 'w';
	else
		*p++ = '-';
	switch (mode & (S_IXGRP)) {
	case 0:
		*p++ = '-';
		break;
	case S_IXGRP:
		*p++ = 'x';
		break;
		//case S_ISGID:
		//		*p++ = 'S';
		//		break;
		//case S_IXGRP | S_ISGID:
		//		*p++ = 's';
		//		break;
	}
	/* other */
	if (mode & S_IROTH)
		*p++ = 'r';
	else
		*p++ = '-';
	if (mode & S_IWOTH)
		*p++ = 'w';
	else
		*p++ = '-';
	switch (mode & (S_IXOTH)) {
	case 0:
		*p++ = '-';
		break;
	case S_IXOTH:
		*p++ = 'x';
		break;
	}
	*p++ = ' ';		/* will be a '+' if ACL's implemented */
	*p = '\0';
}

#include <winioctl.h>
// Maximum reparse buffer info size. The max user defined reparse 
// data is 16KB, plus there's a header. 
// 
#define MAX_REPARSE_SIZE	17000 

#define IO_REPARSE_TAG_SYMBOLIC_LINK      IO_REPARSE_TAG_RESERVED_ZERO 
#define IO_REPARSE_TAG_MOUNT_POINT              (0xA0000003L)       // winnt ntifs 
#define IO_REPARSE_TAG_HSM                      (0xC0000004L)       // winnt ntifs 
#define IO_REPARSE_TAG_SIS                      (0x80000007L)       // winnt ntifs 


// 
// Undocumented FSCTL_SET_REPARSE_POINT structure definition 
// 
#define REPARSE_MOUNTPOINT_HEADER_SIZE   8 
typedef struct {
	DWORD          ReparseTag;
	DWORD          ReparseDataLength;
	WORD           Reserved;
	WORD           ReparseTargetLength;
	WORD           ReparseTargetMaximumLength;
	WORD           Reserved1;
	WCHAR          ReparseTarget[1];
} REPARSE_MOUNTPOINT_DATA_BUFFER, *PREPARSE_MOUNTPOINT_DATA_BUFFER;


typedef struct _REPARSE_DATA_BUFFER {
	ULONG  ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR PathBuffer[1];
		} MountPointReparseBuffer;
		struct {
			UCHAR  DataBuffer[1];
		} GenericReparseBuffer;
	};
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

BOOL ResolveLink(wchar_t * tLink, wchar_t *ret, DWORD * plen, DWORD Flags)
{
	HANDLE   fileHandle;
	BYTE     reparseBuffer[MAX_REPARSE_SIZE];
	PBYTE    reparseData;
	PREPARSE_GUID_DATA_BUFFER reparseInfo = (PREPARSE_GUID_DATA_BUFFER)reparseBuffer;
	PREPARSE_DATA_BUFFER msReparseInfo = (PREPARSE_DATA_BUFFER)reparseBuffer;
	DWORD   returnedLength;

	if (Flags & FILE_ATTRIBUTE_DIRECTORY)
	{
		fileHandle = CreateFileW(tLink, 0,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, 0);

	}
	else {

		//    
		// Open the file    
		//    
		fileHandle = CreateFileW(tLink, 0,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING,
			FILE_FLAG_OPEN_REPARSE_POINT, 0);
	}
	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		sprintf_s(ret, *plen, L"%ls", tLink);
		return TRUE;
	}

	if (GetFileAttributesW(tLink) & FILE_ATTRIBUTE_REPARSE_POINT) {

		if (DeviceIoControl(fileHandle, FSCTL_GET_REPARSE_POINT,
			NULL, 0, reparseInfo, sizeof(reparseBuffer),
			&returnedLength, NULL)) {

			if (IsReparseTagMicrosoft(reparseInfo->ReparseTag)) {

				switch (reparseInfo->ReparseTag) {
				case 0x80000000 | IO_REPARSE_TAG_SYMBOLIC_LINK:
				case IO_REPARSE_TAG_MOUNT_POINT:
					if (*plen >= msReparseInfo->MountPointReparseBuffer.SubstituteNameLength)
					{
						reparseData = (PBYTE)&msReparseInfo->SymbolicLinkReparseBuffer.PathBuffer;
						WCHAR temp[1024];
						wcsncpy_s(temp, 1024,
							(PWCHAR)(reparseData + msReparseInfo->MountPointReparseBuffer.SubstituteNameOffset),
							(size_t)msReparseInfo->MountPointReparseBuffer.SubstituteNameLength);
						temp[msReparseInfo->MountPointReparseBuffer.SubstituteNameLength] = 0;
						swprintf_s(ret, *plen, L"%ls", &temp[4]);
					}
					else
					{
						swprintf_s(ret, *plen, L"%ls", tLink);
						return FALSE;
					}

					break;
				default:
					break;
				}
			}
		}
	}
	else {
		swprintf_s(ret, *plen, L"%ls", tLink);
	}

	CloseHandle(fileHandle);
	return TRUE;
}

char * get_inside_path(char * opath, BOOL bResolve, BOOL bMustExist)
{
	char * ipath;
	char * temp_name;
	wchar_t temp[1024];
    DWORD templen = 1024;
    WIN32_FILE_ATTRIBUTE_DATA  FileInfo;

    wchar_t* opath_w = utf8_to_utf16(opath);
    if (!GetFileAttributesExW(opath_w, GetFileExInfoStandard, &FileInfo) && bMustExist)
    {
        free(opath_w);
        return NULL;
    }

    if (bResolve)
    {
        ResolveLink(opath_w, temp, &templen, FileInfo.dwFileAttributes);
        ipath = utf16_to_utf8(temp);
    }
    else
    {
        ipath = xstrdup(opath);
    }

    free(opath_w);
	return ipath;
}

// if file is symbolic link, copy its link into "link" .
int readlink(const char *path, char *link, int linklen)
{
	strcpy_s(link, linklen, path);
	return 0;
}
#endif
