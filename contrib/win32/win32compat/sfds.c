/*
 * Author: NoMachine <developers@nomachine.com>
 *
 * Copyright (c) 2009, 2012 NoMachine
 * All rights reserved
 *
 * Support functions and system calls' replacements needed to let the
 * software run on Win32 based operating systems.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
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

#include <winsock2.h>
#include <io.h>
#include "sfds.h"

extern void debug(const char *fmt,...);
extern void debug2(const char *fmt,...);
extern void debug3(const char *fmt,...);
extern void error(const char *fmt,...);
extern void fatal(const char *fmt,...);

/* 
 * structure to store real file descriptor and type for sfd
 */
 
static struct
{
  int fd;
  HANDLE handle;
  sfd_type type;
} sfd_map[SFD_MAP_SIZE];

static int sfd_map_init = 0;
static int sfd_count = 0;
int sfd_start = 0;

/* 
 * store real fd in map, detect fd type and return sfd number.
 */
 
int allocate_sfd(int fd_or_handle)
{
  int slot = SFD_FD_INVALID;
  int i;
  int real_fd;

  HANDLE real_handle;
  
  DWORD handle_type;

  /*
   * Init the map once 
   */
   
  if (!sfd_map_init)
  {
    sfd_map_init = 1;
    
    for (i = 0; i < SFD_MAP_SIZE; ++i)
    {
      sfd_map[i].fd = SFD_FD_INVALID;
      sfd_map[i].type = SFD_TYPE_NONE;
    }
  }

  /*
   * Find an open slot 
   */
   
  for (i = sfd_start; i < SFD_MAP_SIZE; ++i)
  {
    /*
     * Is this slot open? 
     */
     
     if (sfd_map[i].fd == SFD_FD_INVALID)
     {
       slot = i;
      
       break;
     }
  }  
  
  /*
   * Bail if no slot found 
   */
   
  if (slot == SFD_FD_INVALID)
  {
    error("ERROR: Too many connections.");
                    
    return -1;
  }

  /*
   * Detect and save real fd and real handle 
   */
   
  real_handle = (HANDLE) _get_osfhandle(fd_or_handle);

  if (real_handle == INVALID_HANDLE_VALUE)
  {
    /*
     * fd_or_handle was a handle, we can try to create a fd for it
     */

    real_handle = (HANDLE) fd_or_handle;

    real_fd = _open_osfhandle((long) real_handle, 0);
  }
  else
  {
    /*
     * fd_or_handle was a fd 
     */
    
    real_fd = fd_or_handle;
  }

  debug3("_get_osfhandle() for real_fd [%d] returned [%d]", real_fd, real_handle);

  /*
   * Detect and save type 
   */
   
  handle_type = GetFileType(real_handle);

  debug3("GetFileType() for handle [%d] returned [%d]", real_handle, handle_type);

  switch (handle_type)
  {
    case FILE_TYPE_CHAR:
    {
      sfd_map[slot].type = SFD_TYPE_CONSOLE;

      break;
    }
    
    case FILE_TYPE_PIPE:
    {
      int optVal = 0;
      int optLen = sizeof(optVal);
      
      if (getsockopt((SOCKET) real_handle, SOL_SOCKET, 
                         SO_ACCEPTCONN, (char *) &optVal, &optLen))
      {                              
        sfd_map[slot].type = SFD_TYPE_PIPE;
      }
      else
      {
        sfd_map[slot].type = SFD_TYPE_SOCKET;
      }
    
      break;
    }  

    case FILE_TYPE_DISK:
    {
      sfd_map[slot].type = SFD_TYPE_FD;

      break;
    }
  
    case FILE_TYPE_UNKNOWN:
    {
      error("unknown type for handle [%d]", real_handle);

      return SFD_FD_INVALID;

      break;
    }
  
    default:
    {
      error("cannot detect a type for handle [%d]", real_handle);
  
      return SFD_FD_INVALID;

      break;
    }
  }

  /*
   * Save the fd and handle 
   */
   
  sfd_map[slot].fd = (int) real_fd;
  
  sfd_map[slot].handle = (HANDLE) real_handle;

  debug("allocating new sfd, sfd [%i] fd [%i] handle [%d] type [%i]",
            slot, real_fd, real_handle, sfd_map[slot].type);

  sfd_count++;

  /*
   * Return the slot as the sfd 
   */
   
  return (slot);
}

/* 
 * For a real fd, get our sfd 
 */
 
int fd_to_sfd(int real_fd)
{
  int i;
  int sfds;

  /* 
   * Walk the list.
   */
   
  for (i = 0, sfds = 0; i < SFD_MAP_SIZE && sfds < sfd_count; i++)
  {
    /*
     * Increment the count of sfds that we have encountered in our walk,
     */

    if (sfd_map[i].fd != SFD_FD_INVALID)
    {
      sfds++;
    }

    if (sfd_map[i].fd == real_fd)
    {
      return i;
    }
  }

  fatal("cannot convert fd to sfd");
  
  return SFD_FD_INVALID;
}

/*
 * For an sfd, get the real descriptor behind it.
 */

int sfd_to_fd(int sfd)
{
  return sfd_map[sfd].fd;
}

/*
 * For an sfd, get the real handle behind it 
 */
 
HANDLE sfd_to_handle(int sfd)
{
  return sfd_map[sfd].handle;
}

void sfd_replace(int sfd, HANDLE handle, int type)
{
  //_close(sfd_map[sfd].handle);

  sfd_map[sfd].handle = handle;
  sfd_map[sfd].type   = type;
}

/*
 * For an sfd, get the type 
 */
 
int get_sfd_type(int sfd)
{
  if(sfd < sizeof(sfd_map) / sizeof(sfd_map[0]))
  {
    return sfd_map[sfd].type;
  }
  else
  {
    return -1;
  }
}

/*
 * Free an sfd from the map.
 */
 
void free_sfd(int sfd)
{
  if (sfd_map[sfd].type != SFD_TYPE_NONE 
          && sfd < sizeof(sfd_map) / sizeof(sfd_map[0]))
  {
    /* 
     * Blank the slot 
     */
     
    sfd_map[sfd].fd = SFD_FD_INVALID;
    sfd_map[sfd].handle = (HANDLE) SFD_HANDLE_INVALID;
    sfd_map[sfd].type = SFD_TYPE_NONE;
    sfd_count--;
  }
}

/*
 * Check if sfd is file.
 */
 
int
sfd_is_fd(int sfd)
{
  if (sfd_map[sfd].type == SFD_TYPE_FD)
  {
    return 1;
  }
  
  return 0;
}

/*
 * Check if sfd is socket.
 */
 
int sfd_is_socket(int sfd)
{
  if (sfd_map[sfd].type == SFD_TYPE_SOCKET)
  {
    return 1;
  }

  return 0;
}

/*
 * Check if sfd is pipe.
 */
 
int sfd_is_pipe(int sfd)
{
  if (sfd_map[sfd].type == SFD_TYPE_PIPE)
  {
    return 1;
  }
 
  return 0;
}

/*
 * Check if sfd is console.
 */
 
int sfd_is_console(int sfd)
{
  if (sfd_map[sfd].type == SFD_TYPE_CONSOLE)
  {
    return 1;
  }
 
  return 0;
}

/*
 * Check if sfd is file or console.
 */
 
int sfd_is_fd_or_console(int sfd)
{
  if (sfd_is_fd(sfd) || sfd_is_console(sfd))
  {
    return 1;
  }

  return 0;
}

/*
 * Check if sfd is socket or pipe.
 */

int sfd_is_socket_or_pipe(int sfd)
{
  if (sfd_is_socket(sfd) || sfd_is_pipe(sfd))
  {
    return 1;
  }

  return 0;
}
