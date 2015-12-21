/*
 * Author: NoMachine <developers@nomachine.com>
 *
 * Copyright (c) 2009, 2013 NoMachine
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

#ifdef __VS_BUILD__
#define UMDF_USING_NTSTATUS 
#include <winsock2.h>
#include <Windows.h>
#include <LsaLookup.h>
#include <Ntsecapi.h>
#endif

#include <winsock2.h>
#include "LsaString.h"

#ifdef __VS_BUILD__
#ifdef __cplusplus
extern "C" {
#endif
#endif // __VS_BUILD__
	extern LSA_SECPKG_FUNCTION_TABLE LsaApi;
#ifdef __VS_BUILD__
#ifdef __cplusplus
}
#endif
#endif

//
// Allocate empty UNICODE_STRING in LSA address space.
//
// lsaStr - pointer to new UNICODE_STRING (OUT)
// wstr   - size of string buffer (IN)
//
// RETURNS: NTSTATUS code.
//

NTSTATUS LsaAllocUnicodeString(PUNICODE_STRING *lsaStr, DWORD maxLen)
{
  NTSTATUS ntStat = STATUS_NO_MEMORY; 
  
  FAIL(lsaStr == NULL);

  *lsaStr = (PUNICODE_STRING) LsaApi.AllocateLsaHeap(sizeof(UNICODE_STRING));
  
  FAIL((*lsaStr) == NULL);
  
  (*lsaStr) -> Buffer = (WCHAR *) LsaApi.AllocateLsaHeap(sizeof(maxLen));
  (*lsaStr) -> Length = 0;
  (*lsaStr) -> MaximumLength = maxLen;
  
  FAIL((*lsaStr) -> Buffer == NULL);
  
  ntStat = 0;
  
fail:

  if (ntStat)
  {
    if (lsaStr && (*lsaStr))
    {
      LsaApi.FreeLsaHeap((*lsaStr) -> Buffer);
      
      LsaApi.FreeLsaHeap((*lsaStr));
    }
    
    DBG_MSG("ERROR. Cannot allocate LSA UNICODE_STRING...\n");
  }
  
  return ntStat;
}

//
// Free UNICODE_STRING from LSA address space.
//
// lsaStr - pointer to UNICODE_STRING to free (IN/OUT)
//

void LsaFreeUnicodeString(PUNICODE_STRING lsaStr)
{
  if (lsaStr)
  {
    if (lsaStr -> Buffer)
    {
      LsaApi.FreeLsaHeap(lsaStr -> Buffer);
    }

    LsaApi.FreeLsaHeap(lsaStr);
  }
}

//
// Write ASCIIZ char table into UNICODE_STRING.
//
// lsaStr - pointer to new UNICODE_STRING (OUT)
// wstr   - size of string buffer (IN)
//
// RETURNS: NTSTATUS code.
//

NTSTATUS FillUnicodeString(UNICODE_STRING *lsaStr, const Char *str)
{
  NTSTATUS ntStat = STATUS_NO_MEMORY;
  
  DWORD cbSize = 0;
  
  //
  // Is arguments ok?
  //
  
  FAIL(lsaStr == NULL);
 
  FAIL(lsaStr -> Buffer == NULL);

  FAIL(str == NULL);
   
  //
  // Is string buffer too small?
  //
  
  cbSize = strlen(str);
  
  FAIL(cbSize >= lsaStr -> MaximumLength);
  
  //
  // Fill string buffer.
  //
  
#ifdef __VS_BUILD__
  _swprintf(lsaStr -> Buffer, L"%hs", str);
#else
  swprintf(lsaStr->Buffer, L"%hs", str);
#endif
  
  lsaStr -> Length = cbSize * 2;
  
  lsaStr -> Buffer[cbSize * 2] = 0x0000;
  
  ntStat = STATUS_SUCCESS;
  
fail:

  if (ntStat)
  {
    DBG_MSG("ERROR. Cannot fill UNICODE_STRING...\n");    
  }
  
  return ntStat;  
}
