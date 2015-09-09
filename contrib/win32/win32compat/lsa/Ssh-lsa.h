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

#include "Win64Fix.h"

#include <winsock2.h>
#include <windows.h>

#include <NTSecPkg.h>

#ifdef _WIN64
#include <ntstatus.h>
#else
#include <ddk/ntstatus.h>
#endif

#include <Userenv.h>
#include <Shlwapi.h>
#include <sddl.h>

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ssl.h>

#include "Debug.h"
#include "KeyAuth.h"
#include "LsaString.h"
#include "SSLFix.h"
#include "DeskRight.h"

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

typedef VOID WINAPI (*RtlInitUnicodeStringPtr) 
                         (PUNICODE_STRING, PCWSTR SourceString);

#ifndef _WIN64
typedef struct _LSA_TOKEN_INFORMATION_V1
{
  LARGE_INTEGER ExpirationTime;
  
  TOKEN_USER User;
  
  PTOKEN_GROUPS Groups;
  
  TOKEN_PRIMARY_GROUP PrimaryGroup;
  
  PTOKEN_PRIVILEGES Privileges;
  
  TOKEN_OWNER Owner;

  TOKEN_DEFAULT_DACL DefaultDacl;
} 
LSA_TOKEN_INFORMATION_V1, *PLSA_TOKEN_INFORMATION_V1;
#endif

#endif
