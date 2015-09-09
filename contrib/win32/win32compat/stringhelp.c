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

#include <winsock2.h>
#include <Windows.h>
#include "Debug.h"

#undef  DEBUG

#ifdef DEBUG
# define DBG_MSG(...) debug3(__VA_ARGS__)
#else
# define DBG_MSG(...) 
#endif

#define SocketErrorStringSize 1024

char * strerror_win32(int error)
{

  static char SocketErrorString[2 * SocketErrorStringSize] = { 0 };

  DWORD error_win32 = WSAGetLastError();

  if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL, error_win32, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                            (LPTSTR) SocketErrorString, SocketErrorStringSize,
                                NULL ) != 0)
  {
    return SocketErrorString;
  }
  else
  {
    return "Unknown error";
  }
}

/*
 * Convert string encoding from one 8-bit CP to another 8-bit CP.
 * WARNING: Returned strong MUST be free by caller.
 *
 * src     - source string (IN).
 * srcSize - size of src string in bytes or -1 if zero terminated (IN).
 * srcCP   - code page used by src string (IN).
 * dstCP   - target code page (IN).
 * retSize - size of returned string, may be NULL (OUT/OPTIONAL).
 *
 * RETURNS: Pointer to new allocated string encoded in target CP 
 *          or NULL if error.
 *
 */
 
void *CovertCodePage(const char *src, int srcSize, 
                         DWORD srcCP, DWORD dstCP, int *retSize)
{
  int exitCode = -1;

  int utf16Len = 0;
  int dstLen   = 0;
  
  wchar_t *utf16 = NULL;
  
  char *ret = NULL;
  
  DBG_MSG("-> ConvertCodePage(src=[%s], srcSize=[%d])...", src, srcSize);
  
  /*
   * Check args.
   */
  
  FAIL(src == NULL);
  
  /*
   * Retrieve size for UTF16.
   */
  
  DBG_MSG("Retrieving size of UTF16...");
  
  utf16Len = MultiByteToWideChar(srcCP, 0, src, srcSize, NULL, 0);
  
  FAIL(utf16Len <= 0);
  
  /*
   * Allocate buffer for UTF16.
   */
   
  DBG_MSG("Allocating [%d] bytes for UTF16...", utf16Len * sizeof(wchar_t));
  
  utf16 = (wchar_t *) malloc((utf16Len + 1) * sizeof(wchar_t));
  
  FAIL(utf16 == NULL);
  
  /*
   * Convert src to UTF16.
   */
   
  DBG_MSG("Allocating [%d] bytes for UTF16...", utf16Len * sizeof(wchar_t));
  
  FAIL(MultiByteToWideChar(srcCP, 0, src, srcSize, utf16, utf16Len) < 0);

  /*
   * Allocate buffer for return.
   */
  
  DBG_MSG("Allocating buffer for dst...");
  
  dstLen = WideCharToMultiByte(dstCP, 0, utf16, -1, NULL, 0, NULL, NULL);

  ret = malloc(dstLen + 1);
  
  FAIL(ret == NULL);
  
  ret[dstLen] = 0;

  /*
   * Convert utf16 to target CP.
   */
  
  DBG_MSG("Converting UTF16 to dst...");
  
  dstLen = WideCharToMultiByte(dstCP, 0, utf16, utf16Len, 
                                   ret, dstLen + 1, NULL, NULL);

  FAIL(dstLen < 0);
  
  if (retSize)
  {
    *retSize = dstLen;
  }
  
  /*
   * Clean up.
   */
   
  exitCode = 0;
  
  fail:
  
  if (exitCode)
  {
    debug3("ERROR: Cannot convert [%s] from CP[0x%x] to CP[0x%x]."
               "Error code is : %d.\n", src, srcCP, dstCP, GetLastError());
               
    if (ret)
    {
      free(ret);
      
      ret = NULL;
    }
  }
  
  if (utf16)
  {
    free(utf16);
  }
  
  DBG_MSG("<- ConvertCodePage()...");
  
  return ret;
}

/*
 * Covert string from UTF8 to CP used by current thread (Local8).
 *
 * utf8          - string in UTF8 (IN).
 * utf8Size      - size of utf8 string in bytes or -1 if zero terminated (IN).
 * bytesReturned - size of returned Local8 string (OUT).
 *
 * RETURNS: Pointer to new allocated Local8 string or NULL if error.
 */
 
void *CovertUtf8ToLocal8(const char *utf8, int utf8Size, int *bytesReturned)
{
  return CovertCodePage(utf8, utf8Size, CP_UTF8, GetACP(), bytesReturned);
}

/*
 * Covert string from CP used by current thread (Local8) to UTF8.
 *
 * local8        - string in Local8 CP (IN).
 * local8Size    - size of local8 string in bytes or -1 if zero terminated (IN).
 * bytesReturned - size of returned UTF8 string (OUT).
 *
 * RETURNS: Pointer to new allocated UTF8 string or NULL if error.
 */

void *ConvertLocal8ToUtf8(const char *local8, int local8Size, int *bytesReturned)
{
  return CovertCodePage(local8, local8Size, 
                            GetACP(), CP_UTF8, bytesReturned);
}
