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

#include <windows.h>
#include <Lmcons.h>
#include <Lm.h>
#include <Userenv.h>
#include <shlobj.h>
#include <Shlwapi.h>

#include "win32auth.h"

wchar_t HomeDirLsaW[MAX_PATH] = {L'\0'};

wchar_t *gethomedir_w(char *pUserName, char *pDomainName)
{
  HANDLE token;

  PROFILEINFOW profileInfo;
  
  wchar_t szPathW[MAX_PATH] = {0};
  
  wchar_t pUserName_w[UNLEN + 1] = {0};
  
  static wchar_t username_w[UNLEN + 1] = {0}; 
  
  DWORD usernamelen = UNLEN + 1;
  
  wchar_t pDomainName_w[UNLEN + 1] = {0};
  
  wchar_t *userprofile_w;
  
  /*
   * If there is home dir from lsa return it.
   */
  
  if (HomeDirLsaW[0] != L'\0')
  {
    debug("Using LSA HomeDirW.");
    
    return _wcsdup(HomeDirLsaW);
  }

  szPathW[0] = '\0';
  
  if (MultiByteToWideChar(CP_UTF8, 0, pUserName, -1, pUserName_w, UNLEN) == 0)
  {
    return NULL;
  }  
  
  if (pDomainName && 
          MultiByteToWideChar(CP_UTF8, 0, pDomainName,
                                  -1, pDomainName_w, UNLEN) == 0)
  {
    return NULL;
  }  

  debug3("gethomedir: pUserName [%s]", pUserName);

  GetUserNameW(username_w, &usernamelen);

  debug3("gethomedir: username [%ls]", username_w);

  if (wcscmp(pUserName_w, username_w) == 0)
  {
    /*
     * User query his own home dir, we can take it from env.
     */
    
    debug3("gethomedir: getenv");
  
    userprofile_w = _wgetenv(L"USERPROFILE");
    
    if (userprofile_w)
    {
      debug3("gethomedir: userprofile [%ls]", userprofile_w);
      
      /*
       * We have a %USERPROFILE% and we can return it
       */
      
      return _wcsdup(userprofile_w);
    }
    
    /*
     * Env not set, let's try to take it from token
     */
  }

  /*
   * If all above fail try to create user token manually
   * and get homedir using this token.
   */
  
  #ifdef USE_NTCREATETOKEN
  
  token = CreateUserTokenW(pUserName_w, pDomainName_w, L"sshd");
  
  if (token == NULL)
  {
    debug("gethomedir: create token failed");

    return NULL;
  }

  debug2("setting up profile info...");
  
  /*
   * Become the user
   */
  
  memset(&profileInfo, 0, sizeof(profileInfo));

  profileInfo.dwSize = sizeof(profileInfo);
  profileInfo.lpUserName = pUserName_w;
  profileInfo.lpServerName = pDomainName_w;

  debug2("LoadUserProfile()...");
  
  if (!LoadUserProfile(token, &profileInfo))
  {
    DWORD dwLast = GetLastError();
  
    debug("gethomedir: load profile failed [%d]", dwLast);
    
    return NULL;
  }

  /*
   * Get user's home directory
   */
  
  //if (!SUCCEEDED(SHGetFolderPath(NULL, CSIDL_APPDATA, token, 0, szPath)))
  
  debug2("SGGetFolderPath()...");
  
  if (!SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, token, 0, szPathW)))
  {
    debug("gethomedir: get folder failed");

    /*
     * Become self again.
     */

    UnloadUserProfile(token, profileInfo.hProfile);

    RevertToSelf();

    CloseHandle(token);

    return NULL;
  }

  debug3("gethomedir: szPathW [%ls]", szPathW);

  /*
   * Become self again.
   */
  
  UnloadUserProfile(token, profileInfo.hProfile);

  RevertToSelf();
  
  CloseHandle(token);

  debug2("<- gethomedir()...");
  
  return _wcsdup(szPathW);
  
  #else
  
  return NULL;
  
  #endif
}

/*
 * Retreave path, where current binary live.
 *
 * buffer  - buffer, where path store (OUT)
 * bufSize - size of output buffer (IN)
 *
 * RETURNS: 0 if OK.
 */
 
int GetRootBaseDir(char *buffer, int bufSize)
{
  int exitCode = -1;

  char *end = NULL;
  char *tmp = buffer;

  FAIL(buffer == NULL);
  
  FAIL(GetModuleFileName(NULL, buffer, bufSize) == FALSE);

  FAIL(PathRemoveFileSpec(buffer) == FALSE);
  
  while ((tmp = strstr(tmp, "\\bin")))
  {
    end = tmp;
    tmp++;
  }

  FAIL(end == NULL);
  
  *end = 0;

  exitCode = 0;
  
fail:

  return exitCode;
}
