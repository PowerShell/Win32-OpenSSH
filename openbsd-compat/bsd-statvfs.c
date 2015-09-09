/* $Id: bsd-statvfs.c,v 1.1 2008/06/08 17:32:29 dtucker Exp $ */

/*
 * Copyright (c) 2008 Darren Tucker <dtucker@zip.com.au>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <errno.h>

#ifndef HAVE_STATVFS
int statvfs(const char *path, struct statvfs *buf)
{
  #ifdef WIN32_FIXME
  
  DWORD sectorsPerCluster;
  DWORD bytesPerSector;
  DWORD freeClusters;
  DWORD totalClusters;
  
  if (GetDiskFreeSpace(path, &sectorsPerCluster, &bytesPerSector, 
                           &freeClusters, &totalClusters) == TRUE)
  {     
    debug3("path              : [%s]", path);
    debug3("sectorsPerCluster : [%lu]", sectorsPerCluster);
    debug3("bytesPerSector    : [%lu]", bytesPerSector);
    debug3("bytesPerCluster   : [%lu]", sectorsPerCluster * bytesPerSector);
    debug3("freeClusters      : [%lu]", freeClusters);
    debug3("totalClusters     : [%lu]", totalClusters);

    buf -> f_bsize   = sectorsPerCluster * bytesPerSector;
    buf -> f_frsize  = sectorsPerCluster * bytesPerSector;
    buf -> f_blocks  = totalClusters;
    buf -> f_bfree   = freeClusters;
    buf -> f_bavail  = freeClusters;
    buf -> f_files   = -1;
    buf -> f_ffree   = -1;
    buf -> f_favail  = -1;
    buf -> f_fsid    = 0;
    buf -> f_flag    = 0;
    buf -> f_namemax = MAX_PATH - 1;

    return 0;
  }
  else
  {
    debug3("ERROR: Cannot get free space for [%s]. Error code is : %d.\n",
               path, GetLastError());

    return -1;
  }
  
  #else /* WIN32_FIXME */
  
	errno = ENOSYS;
	return -1;
  
  #endif /* !WIN32_FIXME */
}
#endif

#ifndef HAVE_FSTATVFS
int fstatvfs(int fd, struct statvfs *buf)
{
	errno = ENOSYS;
	return -1;
}
#endif
