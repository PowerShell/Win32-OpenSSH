/*
 * Author: NoMachine <developers@nomachine.com>
 *
 * Copyright (c) 2009, 2011 NoMachine
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

#include "LsaString.h"
 
/*
 * Allocate UNICODE_STRING's buffer and initializes it with
 * given string.
 *
 * lsaStr - UNICODE_STRING to initialize (IN/OUT)
 * wstr   - string, which will be copied to lsaStr (IN)
 *
 * RETURNS: 0 if OK.
 */

int InitUnicodeString(UNICODE_STRING *lsaStr, const wchar_t *wstr)
{
  int exitCode = 1; 
  
  int size = (wstr) ? wcslen(wstr) * 2 : 0;

  lsaStr -> Length        = size;
  lsaStr -> MaximumLength = size + 2;
  lsaStr -> Buffer        = (wchar_t *) malloc(size + 2);
  
  FAIL(lsaStr -> Buffer == NULL);

  memcpy(lsaStr -> Buffer, wstr, size);

  lsaStr -> Buffer[size / 2] = 0;
  
  exitCode = 0;
  
fail:

  if (exitCode)
  {
    printf("ERROR. Cannot initialize UNICODE_STRING...");
  }
  
  return exitCode;
}


/*
 * Allocate LSA_STRING's buffer and initializes it with
 * given string.
 *
 * lsaStr - LSA_STRING to initialize (IN/OUT)
 * str    - string, which will be copied to lsaStr (IN)
 *
 * RETURNS: 0 if OK.
 */

int InitLsaString(LSA_STRING *lsaStr, const char *str)
{
  int exitCode = 1; 
  
  int len = (str) ? strlen(str) : 0;
  
  lsaStr -> Length        = len;
  lsaStr -> MaximumLength = len + 1;
  lsaStr -> Buffer        = (char *) malloc(len + 1);
  
  FAIL(lsaStr -> Buffer == NULL);
  
  memcpy(lsaStr -> Buffer, str, len);

  lsaStr -> Buffer[len] = 0;
  
  exitCode = 0;
  
fail:

  if (exitCode)
  {
    printf("ERROR. Cannot initialize LSA_STRING...");
  }
  
  return exitCode;
}


/*
 * Clear LSA_STRING's buffer.
 *
 * lsaStr - LSA_STRING to clear (IN/OUT)
 */

void ClearLsaString(LSA_STRING *lsaStr)
{
  if (lsaStr)
  {
    if (lsaStr -> Buffer)
    {
      free(lsaStr -> Buffer);
      
      lsaStr -> Buffer = NULL;
    }
    lsaStr -> MaximumLength = 0;
    lsaStr -> Length = 0;
  }
}

/*
 * Clear UNICODE_STRING's buffer.
 *
 * lsaStr - UNICODE_STRING to clear (IN/OUT)
 */

void ClearUnicodeString(UNICODE_STRING *lsaStr)
{
  if (lsaStr)
  {
    if (lsaStr -> Buffer)
    {
      free(lsaStr -> Buffer);
      
      lsaStr -> Buffer = NULL;
    }
    lsaStr -> MaximumLength = 0;
    lsaStr -> Length = 0;
  }
}
