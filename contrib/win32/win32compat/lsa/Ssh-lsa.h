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

#ifndef SSH_Lsa_H
#define SSH_Lsa_H

#undef STRING
#undef TEST_APP
#define UMDF_USING_NTSTATUS 
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <Ntsecapi.h>
#include <NTSecPkg.h>
#include <ntstatus.h>
#include "Types.h"

#define PKG_NAME "SSH-LSA"

#define PKG_NAME_SIZE sizeof(PKG_NAME)
                                              
#define MAX_ACCOUNT_NAME_SIZE (256 * 2)

#define VERSION "4.0.346"

typedef struct _SshLsaAuth
{
  DWORD totalSize_;
  DWORD dataFellow_;
  DWORD userSize_;
  DWORD signSize_;
  DWORD dataSize_;
  DWORD pkBlobSize_;
  DWORD authFilesCount_;
  
  BYTE buf_[1];
} 
SshLsaAuth;

#ifndef __VS_BUILD__
typedef VOID WINAPI (*RtlInitUnicodeStringPtr) 
                         (PUNICODE_STRING, PCWSTR SourceString);

#else
typedef VOID (WINAPI *RtlInitUnicodeStringPtr)
						(PUNICODE_STRING, PCWSTR SourceString);
#endif

#define FAIL(CONDITION) if(CONDITION) goto fail

#define NTFAIL(NTFUNC) if((ntStat = (NTFUNC))) goto fail

NTSTATUS LsaAllocUnicodeString(UNICODE_STRING **lsaStr, DWORD maxLen);

NTSTATUS FillUnicodeString(UNICODE_STRING *lsaStr, const Char *str);

void LsaFreeUnicodeString(UNICODE_STRING *lsaStr);

#endif
