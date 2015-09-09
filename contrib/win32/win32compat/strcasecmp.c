/*
 * Author: NoMachine <developers@nomachine.com>
 *
 * Copyright (c) 2009, 2010 NoMachine
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


/* Similar to strcasecmp.c from OpenBSD */
/* Note: This could be moved to the OpenBSD-Compat layer in OpenSSH and added to config.h etc. */

#include "includes.h"
#if !defined(HAVE_STRCASECMP) || !defined(HAVE_STRNCASECMP)
#include <sys/types.h>
#include <string.h>
#endif

#ifndef HAVE_STRCASECMP
size_t strcasecmp(const char *left, const char *right)
{
  #if 0
 
  const unsigned char *uleft = (const unsigned char *) left, *uright = (const unsigned char *) right;

  while (tolower(*uleft) == tolower(*uright))
  {
    if (*uleft++ == '\0')
    {
      return (0);
    }
    
    uright++;
  }
  
  return (tolower(*uleft) - tolower(*uright));
  
  #else
  
  return stricmp(left, right);
  
  #endif
}
#endif

#ifndef HAVE_STRNCASECMP
size_t strncasecmp(const char *left, const char *right, size_t n)
{
  #if 0

  if (n != 0)
  {
    const unsigned char *uleft = (const unsigned char *) left, *uright = (const unsigned char *) right;

    do
    {
      if (tolower(*uleft) != tolower(*uright))
      {
        return (tolower(*uleft) - tolower(*uright));
      }
      
      if (*uleft++ == '\0')
      {
        break;
      }
      
      uright++;
    }
    while (--n != 0);
  }
  
  return (0);

  #else
  
  return strnicmp(left, right, n);
  
  #endif
}
#endif
