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

#include "includes.h"

#include <Lmcons.h>
#include <Lm.h>
#include <stdlib.h>
#include <ntsecapi.h>
#include <errno.h>
#include <shlobj.h>
#include <Userenv.h>

#include "win32auth.h"
#include "homedirhelp.h"


uid_t getuid(void)
{
  return 0;
}

gid_t getgid(void)
{
  return 0;
}

uid_t geteuid(void)
{
  return 0;
}

gid_t getegid(void)
{
  return 0;
}

int setuid(uid_t uid)
{
  return 0;
}

int setgid(gid_t gid)
{
  return 0;
}

int seteuid(uid_t uid)
{
  return 0;
}

int setegid(gid_t gid)
{
  return 0;
}

/*
 * Global pw variables
 */

static struct passwd pw;

static char pw_gecos[UNLEN + 1]    = {'\0'};
static char pw_username[UNLEN + 1] = {'\0'};
static char pw_passwd[UNLEN + 1]   = {'\0'};
static wchar_t pw_homedir[MAX_PATH]   = {L'\0'};
static char pw_password[MAX_PATH]  = {'\0'};
static char pw_shellpath[MAX_PATH] = {'\0'};

/*
 * Retrieve user homedir from token, save it in static string
 * and return pointer to this string.
 *
 * userName - user's name (IN)
 * token    - logon user's token (IN)
 *
 * RETURNS: pointer to static string with homedir or NULL if fails.
 */

char *GetHomeDirFromToken(char *userName, HANDLE token)
{
  
  wchar_t userNameW[UNLEN + 1];
  
  debug("-> GetHomeDirFromToken()...");
  
  PROFILEINFOW profileInfo;
  
  if (MultiByteToWideChar(CP_UTF8, 0, userName, -1, userNameW, UNLEN) == 0)
  {
    debug("userName encoding conversion failure");
    return NULL;
  }
  
  memset(&profileInfo, 0, sizeof(profileInfo));

  profileInfo.dwSize       = sizeof(profileInfo);
  profileInfo.lpUserName   = userNameW;
  profileInfo.lpServerName = NULL;
  
  if (LoadUserProfile(token, &profileInfo) == FALSE)
  {
    debug("<- GetHomeDirFromToken()...");
    debug("LoadUserProfile failure: %d", GetLastError());
    
    return NULL;
  }

  /*
   * And retrieve homedir from profile.
   */
        
  if (!SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, token, 0, pw_homedir)))
  {
    debug("<- GetHomeDirFromToken()...");
    debug("SHGetFolderPath failed");
    
    return NULL;
  }
          
  /*
   * Unload user profile.
   */
       
  if (UnloadUserProfile(token, profileInfo.hProfile) == FALSE)
  {
    debug("WARNING. Cannot unload user profile (%u).", GetLastError());
  }
  
  debug("<- GetHomeDirFromToken()...");
  
  return pw_homedir;
}


wchar_t *GetHomeDir(char *userName)
{
  /*
   * Get home directory path (if this fails, the user is invalid, bail)
   */

  wchar_t *homeDir = NULL;
  
  homeDir = gethomedir_w(userName, NULL);
  
  if (homeDir == NULL || homeDir[0] == L'\0')
  {
    return NULL;
  }
  
  debug3("GetHomeDir: homedir [%ls]", homeDir);
  
  wcsncpy(pw_homedir, homeDir, sizeof(pw_homedir));

  free(homeDir);
  
  return pw_homedir;
}

/*
 * Not thread safe, would need to use thread local
 * storage instead of a static.
 */

struct passwd *getpwuid(uid_t uid)
{
  static struct passwd pw;

  static char username[UNLEN + 1];
  
  DWORD usernamelen = UNLEN + 1;
  
  wchar_t *homedir_w;

  /*
   * Clear errno.
   */
  
  errno = 0;

  /*
   * Zero out the structure.
   */
  
  memset(&pw, 0, sizeof(pw));
  
  memset(pw_username, 0, sizeof(pw_username));
  memset(pw_homedir, 0, sizeof(pw_homedir));
  memset(pw_password, 0, sizeof(pw_password));
  memset(pw_shellpath, 0, sizeof(pw_shellpath));

  /*
   * Point to the static string variables.
   */
  
  pw.pw_name = pw_username;
  pw.pw_passwd = pw_password;
  pw.pw_gecos = pw_gecos;
  pw.pw_shell = pw_shellpath;
  pw.pw_dir = pw_homedir;

  /*
   * Get the current user's name.
   */
  
  GetUserName(username, &usernamelen);
  
  debug3("getpwuid: username [%s]", username);
  
  strncpy(pw_username, username, sizeof(pw_username));

  /*
   * ssh need path to 'known_hosts' file, so we don't
   * comment it here (see -> getpwnam() function).
   */
  
  /*
   * Get default shell path.
   */
  
  GetSystemDirectory(pw_shellpath, MAX_PATH);
  
  debug3("getpwuid: system dir [%s]", pw_shellpath);
  
  strcat(pw_shellpath, "\\cmd.exe");
  
  debug3("getpwuid: shell path [%s]", pw_shellpath);

  /*
   * Get home directory path (if this fails,
   * the user is invalid, bail)
   */
  
  homedir_w = gethomedir_w(username, NULL);
  
  if (!homedir_w || homedir_w[0] == '\0')
  {
    /*
     * Bail out.
     */
      
    errno = ENOENT;

    return &pw;
  }

  debug3("getpwuid: homedir [%ls]", homedir_w);
    
  wcsncpy(pw_homedir, homedir_w, sizeof(pw_homedir));
        
  free(homedir_w);

  /*
   * Point to the username static variable.
   */
  
  pw.pw_name   = pw_username;
  pw.pw_passwd = pw_passwd;
  pw.pw_gecos  = pw_gecos;
  pw.pw_shell  = pw_shellpath;
  pw.pw_dir    = pw_homedir;

  return &pw;
}


struct passwd *getpwnam(const char *userin)
{
  char *homedir;

  debug3("getpwnam: username [%s]", userin);

  /*
   * Clear errno.
   */
  
  errno = 0;

  /*
   * Zero out the structure.
   */
  
  memset(&pw, 0, sizeof(pw));
  
  memset(pw_username, 0, sizeof(pw_username));
  memset(pw_homedir, 0, sizeof(pw_homedir));
  memset(pw_password, 0, sizeof(pw_password));
  memset(pw_shellpath, 0, sizeof(pw_shellpath));

  /*
   * Point to the static string variables.
   */
  
  pw.pw_name   = pw_username;
  pw.pw_passwd = pw_password;
  pw.pw_gecos  = pw_gecos;
  pw.pw_shell  = pw_shellpath;
  pw.pw_dir    = pw_homedir;

  /*
   * Get default shell path.
   */
  
  GetSystemDirectory(pw_shellpath, MAX_PATH);

  debug3("getpwnam: system dir [%s]", pw_shellpath);
  
  strcat(pw_shellpath, "\\cmd.exe");
  
  debug3("getpwnam: shell path [%s]", pw_shellpath);

  /*
   * Copy user name to static structure.
   */
  
  strncpy(pw_username, userin, UNLEN + 1);

  /*
   * Get a token for this user.
   */
  
  return &pw;
}

void endpwent(void)
{
  /*
   * This normally cleans up access to the passwd file,
   * which we don't have, thus no cleanup.
   */
}


#ifdef USE_NTCREATETOKEN

/*
 * Simple helper to avoid having to include win32auth.h.
 */

PWD_USER_TOKEN PwdCreateUserToken(const char *pUserName, 
                                      const char *pDomainName, 
                                          const char *pSourceName)
{
  return (PWD_USER_TOKEN) CreateUserToken(pUserName, pDomainName, pSourceName);
}

#endif
