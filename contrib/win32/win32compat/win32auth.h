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

#ifndef WIN32AUTH_H
#define WIN32AUTH_H 1

#include <winsock2.h>
#include <windows.h>
#include <winnt.h>
#include <Lmcons.h>
#include <Lm.h>
#include <stdlib.h>
#include <ntsecapi.h>
#include <AccCtrl.h>
#include <Aclapi.h>
#include "Debug.h"
#ifdef WIN32
#define STATUS_OBJECT_NAME_NOT_FOUND     ((NTSTATUS)0xC0000034L)
#else
#include <ddk/ntstatus.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
typedef struct _OBJECT_ATTRIBUTES
{
  ULONG Length;

  HANDLE RootDirectory;
 
  PUNICODE_STRING ObjectName;
 
  ULONG Attributes;

  PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
   
  PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
}
OBJECT_ATTRIBUTES;

typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
#endif

#ifndef NYSYSAPI
#define NTSYSAPI DECLSPEC_IMPORT
#endif

//
// Prototype for undocumented NtCreateToken() function from 'ntdll.dll'
//
#ifdef USE_NTCREATETOKEN
typedef NTSYSAPI NTSTATUS
    (NTAPI *NtCreateTokenPtr) (PHANDLE, ACCESS_MASK,
                                   POBJECT_ATTRIBUTES,
                                       TOKEN_TYPE, PLUID, PLARGE_INTEGER, 
                                           PTOKEN_USER, PTOKEN_GROUPS, 
                                               PTOKEN_PRIVILEGES, PTOKEN_OWNER,
                                                   PTOKEN_PRIMARY_GROUP, 
                                                       PTOKEN_DEFAULT_DACL,
                                                           PTOKEN_SOURCE);
#endif /* USE_NTCREATETOKEN */

HANDLE CreateUserToken(const char *pUserName,
                           const char *pDomainName, const char *pSourceName);

int EnablePrivilege(const char *privName, int enabled);

#ifdef __cplusplus
};
#endif

#endif /* WIN32AUTH_H */
