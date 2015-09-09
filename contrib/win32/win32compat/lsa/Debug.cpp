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

#include "Debug.h"

//
// All code below is for debug version only.
//

#ifdef DEBUG

#include <cstdio>
#include <winnt.h>
#include <Lmcons.h>
#include <Lm.h>
#include <stdlib.h>
#include <ntsecapi.h>
#include <AccCtrl.h>
#include <Aclapi.h>

static Int DbgDeep = 0;

static Int DbgTreeMode = 1;

static Char DbgLogFile[MAX_PATH] = "C:\\tmp\\ssh-lsa.log";

//
// Initialize directory path, where debug log will be created.
//

void DbgInit(Char *unused)
{
  Char processId[32];
  
  //
  // FIXME. Log are moved to standard temp dir due to bug realeted 
  // with paths longer than 55 chars in authentication packages list
  // in registry key.
  //
  
  //
  // Put current process ID as logfile extension.
  //
  
  sprintf(processId, "%u", (Unsigned Int) GetCurrentProcessId());
  
  strcat(DbgLogFile, ".");
  strcat(DbgLogFile, processId);
  
  DBG_MSG("Log iniciated propertly.\n");
  
  DBG_MSG("[Build " __DATE__ " " __TIME__ "]\n");
}

//
// Debug message for function entry.
//

void DbgEntry(const Char *funcName)
{
  DbgMsg("-> %s()...\n", funcName);

  DbgDeep += 3;
}

//
// Debug message for function leave.
//

void DbgLeave(const Char *funcName)
{
  DbgDeep -= 3;

  DbgMsg("<- %s()...\n", funcName);
}

//
// Write DbgDeep spaces for tree mode messages.
//

void DbgSpaces()
{
  if (DbgTreeMode)
  {
    for (int i = 0; i < DbgDeep; i++)
    {
      DBG_MSG_NOLN(" ");
    }
  }
}

//
// Dump memory block to file.
//

void DbgDumpToFile(const Char *fname, void *ptr, Int size)
{
  DbgMsg("-> DbgDumpToFile(%s)...\n", fname);
  
  FILE *f = fopen(fname, "wb+");
  
  fwrite(ptr, size, 1, f);
  
  fclose(f);
}  

//
// Print debug message.
//

void DbgMsg(const Char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
   
  FILE *f = fopen(DbgLogFile, "at+");

  if (f == NULL)
  {
    return;
  }
  
  SYSTEMTIME st;

  Char msg[4096];

  Char timeStr[256];
  
  Char timeMsg[4096];

  GetLocalTime(&st);

  snprintf(timeStr, sizeof(timeStr), "%02d:%02d:%02d %03d",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

  if (DbgTreeMode)
  {
    for (int i = 0; i < DbgDeep; i++)
    {
      strncat(timeStr, " ", sizeof(timeStr));
    }
  }  

                
  vsnprintf(msg, sizeof(msg), fmt, ap);

  snprintf(timeMsg, sizeof(timeMsg), "[%d][%d] %s %s", (Int) GetCurrentProcessId(),
               (Int) GetCurrentThreadId(), timeStr, msg);
  

  fprintf(f, timeMsg);
  
/*
  vfprintf(f, fmt, ap);

  fprintf(f, "\n");
*/    

  fclose(f);
   
  va_end(ap);
}

//
// Print debug message without extra new line character.
//

void DbgMsgNoLn(const Char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
   
  FILE *f = fopen(DbgLogFile, "at+");

  if (f == NULL)
  {
    return;
  }
  
  vfprintf(f, fmt, ap);

  fclose(f);
    
  va_end(ap);
}

//
// Print SID number to debug log.
//

void DbgPrintSid(const Char *pre, PSID pSid, const Char *post)
{
  if (IsValidSid(pSid))
  {
    DWORD len = GetLengthSid(pSid);
    
    BYTE *buf = (BYTE *) pSid;

    DWORD i;
    
    DbgSpaces();
    
    DBG_MSG_NOLN("%s{", pre);
    
    for (i = 0; i < len; i++)
    {
      DBG_MSG_NOLN("%x, ", buf[i]);
    }
    
    DBG_MSG_NOLN("}%s", post);
  }
  else
  {
    DBG_MSG_NOLN("%s{INCORRECT_SID}%s", pre, post);
  }
}

//
// Print LUID number to debug log.
//

void DbgPrintLuid(const Char *pre, LUID luid, const Char *post)
{

  DbgSpaces();
  
  DBG_MSG_NOLN("%s{%x, %x}%s", pre, luid.LowPart, luid.HighPart, post);
}

//
// Print Token source to debug log.
//

void DbgPrintSource(const Char *pre, PTOKEN_SOURCE source, const Char *post)
{
  DbgSpaces();
  
  DBG_MSG_NOLN(pre);
  
  for (int i = 0; i < 8; i++)
  {
    DBG_MSG_NOLN("%c", source -> SourceName[i]);
  }
  
  DBG_MSG_NOLN("{%x, %x}", source -> SourceIdentifier.LowPart,
                   source -> SourceIdentifier.HighPart);

  DBG_MSG_NOLN(post);
}

//
// Print debug info about access token.
//
// token - handle to token (IN)
//

void DbgPrintToken(HANDLE token)
{
  DBG_ENTRY("DbgPrintToken");
  
  PTOKEN_USER pUserToken             = NULL;
  PTOKEN_GROUPS pGroupsToken         = NULL;
  PTOKEN_PRIVILEGES pPrivilegesToken = NULL;
  PTOKEN_OWNER pOwnerToken           = NULL;

  PTOKEN_PRIMARY_GROUP pPrimaryGroupToken = NULL;

  PTOKEN_SOURCE pSourceToken     = NULL;
  PTOKEN_DEFAULT_DACL pDaclToken = NULL;
  
  DWORD cbSize = 0;

  DWORD i = 0;
  
  //
  // Retrieve TOKEN_USER from token.
  //
  
  DBG_MSG("Retrieving TOKEN_USER...\n");
  
  GetTokenInformation(token, TokenUser, NULL, 0, &cbSize);
  
  pUserToken = (PTOKEN_USER) LocalAlloc(LPTR, cbSize);

  FAIL(GetTokenInformation(token, TokenUser,
                               pUserToken, cbSize, &cbSize) == FALSE);
  
  //
  // Retrieve TOKEN_GROUP from token.
  //

  DBG_MSG("Retrieving TOKEN_GROUP...\n");
  
  GetTokenInformation(token, TokenGroups, NULL, 0, &cbSize);

  pGroupsToken = (PTOKEN_GROUPS) LocalAlloc(LPTR, cbSize);
  
  FAIL(GetTokenInformation(token, TokenGroups, 
                               pGroupsToken, cbSize, &cbSize) == FALSE);

  //
  // Retrieve TOKEN_PRIVILEGES from token.
  //

  DBG_MSG("Retrieving TOKEN_PRIVILEGES...\n");
  
  GetTokenInformation(token, TokenPrivileges, NULL, 0, &cbSize);
  
  pPrivilegesToken = (PTOKEN_PRIVILEGES) LocalAlloc(LPTR, cbSize);

  FAIL(GetTokenInformation(token, TokenPrivileges, 
                               pPrivilegesToken, cbSize, &cbSize) == FALSE);

  //
  // Retrieve TOKEN_OWNER from token.
  //

  DBG_MSG("Retrieving TOKEN_OWNER...\n");
  
  GetTokenInformation(token, TokenOwner, NULL, 0, &cbSize);
  
  pOwnerToken = (PTOKEN_OWNER) LocalAlloc(LPTR, cbSize);

  FAIL(GetTokenInformation(token, TokenOwner, 
                               pOwnerToken, cbSize, &cbSize) == FALSE);
  
  //
  // Retrieve TOKEN_PRIMARY GROUP from token.
  //

  DBG_MSG("Retrieving TOKEN_PRIMARY_GROUP...\n");

  GetTokenInformation(token, TokenPrimaryGroup, NULL, 0, &cbSize);
  
  pPrimaryGroupToken = (PTOKEN_PRIMARY_GROUP) LocalAlloc(LPTR, cbSize);

  FAIL(GetTokenInformation(token, TokenPrimaryGroup, 
                               pPrimaryGroupToken, cbSize, &cbSize) == FALSE);

  //
  // Retrieve TOKEN_DEFAULT_DACL from token.
  //

  DBG_MSG("Retrieving TOKEN_DEFAULT_DACL...\n");
  
  GetTokenInformation(token, TokenDefaultDacl, NULL, 0, &cbSize);
  
  pDaclToken = (PTOKEN_DEFAULT_DACL) LocalAlloc(LPTR, cbSize);

  FAIL(GetTokenInformation(token, TokenDefaultDacl, 
                               pDaclToken, cbSize, &cbSize) == FALSE);

  //
  // Retrieve TOKEN_SOURCE from token.
  //

  DBG_MSG("Retrieving TOKEN_SOURCE...\n");
  
  GetTokenInformation(token, TokenSource, NULL, 0, &cbSize);
  
  pSourceToken = (PTOKEN_SOURCE) LocalAlloc(LPTR, cbSize);
  
  FAIL(GetTokenInformation(token, TokenSource, 
                               pSourceToken, cbSize, &cbSize) == FALSE);
  
  //
  // Print user SID
  //
    
  DbgPrintSid("UserSID = ", pUserToken -> User.Sid, "\n\n");

  //
  // Print TOKEN_GROUP list.
  //
  
  DBG_MSG("TOKEN_GROUP, SID list:\n");
  
  for (i = 0; i < pGroupsToken -> GroupCount; i++)
  {
    DbgPrintSid("  ", pGroupsToken -> Groups[i].Sid, ", ");

    DBG_MSG_NOLN(", %x\n\n", pGroupsToken -> Groups[i].Attributes);
  }
  
  //
  // Print TOKEN_PRIVILEGES.
  //
  
  DBG_MSG("TOKEN_PRIVILEGES, LUID list:\n");
  
  for (i = 0; i < pPrivilegesToken -> PrivilegeCount; i++)
  {
    DbgPrintLuid("  ", pPrivilegesToken -> Privileges[i].Luid, "");
    
    DBG_MSG_NOLN(", %x\n\n", pPrivilegesToken -> Privileges[i].Attributes);
  }
  
  //
  // Print Owner SID.
  //
  
  DbgPrintSid("OwnerSID = ", pOwnerToken -> Owner, "\n\n");
  
  //
  // Print Primary group SID.
  //
  
  DbgPrintSid("PrimaryGroupSID = ", 
                  pPrimaryGroupToken -> PrimaryGroup, "\n\n");

  //
  // Print does any DEFAULT_DACL exists.
  //
  
  if (pDaclToken == NULL)
  {
    DBG_MSG("TOKEN_DEFAULT_DACL is NULL.\n");
  }
  else
  {
    DBG_MSG("TOKEN_DEFAULT_DACL is NOT NULL.\n");
  }
  
  //
  // Print TOKEN_SOURCE.
  //
  
  DbgPrintSource("TOLEN_SOURCE = ", pSourceToken, "\n\n");
  
fail:

  //
  // Clean up.
  //
  
  LocalFree(pUserToken);
  LocalFree(pGroupsToken);
  LocalFree(pPrivilegesToken);
  LocalFree(pOwnerToken);
  LocalFree(pPrimaryGroupToken);
  LocalFree(pDaclToken);
  LocalFree(pSourceToken);

  DBG_LEAVE("DbgPrintToken");
}

#endif
