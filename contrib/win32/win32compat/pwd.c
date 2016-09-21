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
#include <sddl.h>

#include "win32auth.h"
#include "homedirhelp.h"


char *GetHomeDirFromToken(char *userName, HANDLE token);

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
static char pw_homedir_ascii[MAX_PATH]   = {'\0'};
static char pw_password[MAX_PATH]  = {'\0'};
static char pw_shellpath[MAX_PATH] = {'\0'};

/* given a access token, find the domain name of user account of the access token */
int GetDomainFromToken ( HANDLE *hAccessToken, UCHAR *domain, DWORD dwSize)
{
   UCHAR InfoBuffer[1000],username[200];
   PTOKEN_USER pTokenUser = (PTOKEN_USER)InfoBuffer;
   DWORD dwInfoBufferSize,dwAccountSize = 200, dwDomainSize = dwSize;
   SID_NAME_USE snu;

   domain[0] = '\0' ;
   GetTokenInformation(*hAccessToken,TokenUser,InfoBuffer,
						1000, &dwInfoBufferSize);

   LookupAccountSid(NULL, pTokenUser->User.Sid, (LPSTR)username,
				        &dwAccountSize,(LPSTR)domain, &dwDomainSize, &snu);
   return 0;
}

/*
 * Retrieve user homedir from token, save it in static string
 * and return pointer to this string.
 *
 * userName - user's name (IN)
 * token    - logon user's token (IN)
 *
 * RETURNS: pointer to static string with homedir or NULL if fails.
 */

#define SET_USER_ENV(folder_id, evn_variable) do  {                \
       if (SHGetKnownFolderPath(&folder_id,0,token,&path) == S_OK)              \
        {                                                                       \
                SetEnvironmentVariableW(evn_variable, path);                    \
                CoTaskMemFree(path);                                            \
       }                                                                        \
} while (0)                                                                     

char *GetHomeDirFromToken(char *userName, HANDLE token)
{
	UCHAR InfoBuffer[1000];
	PTOKEN_USER pTokenUser = (PTOKEN_USER)InfoBuffer;
	DWORD dwInfoBufferSize, tmp_len;
	LPWSTR sid_str = NULL;
	wchar_t reg_path[MAX_PATH];
	HKEY reg_key = 0;

	/* set home dir to Windows if any of below fair*/
	GetWindowsDirectoryW(pw_homedir, MAX_PATH);

	tmp_len = MAX_PATH;
	if (GetTokenInformation(token, TokenUser, InfoBuffer,
		1000, &dwInfoBufferSize) == FALSE ||
	    ConvertSidToStringSidW(pTokenUser->User.Sid, &sid_str) == FALSE ||
	    swprintf(reg_path, MAX_PATH, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%ls", sid_str) == MAX_PATH ||
	    RegOpenKeyExW(HKEY_LOCAL_MACHINE, reg_path, 0, STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &reg_key) != 0 ||
	    RegQueryValueExW(reg_key, L"ProfileImagePath", 0, NULL, pw_homedir, &tmp_len) != 0 ){
		/* one of the above failed */
		debug("cannot retirve profile path - perhaps user profile is not created yet");
	}

	if (sid_str)
		LocalFree(sid_str);
	
	if (reg_key)
		RegCloseKey(reg_key);

        { /* retrieve and set env variables. */
                /* TODO - Get away with fixed limits and dynamically allocated required memory*/
#define MAX_VALUE_LEN  1000
#define MAX_DATA_LEN   2000
#define MAX_EXPANDED_DATA_LEN 5000
                wchar_t *path;
                wchar_t value_name[MAX_VALUE_LEN];
                wchar_t value_data[MAX_DATA_LEN], value_data_expanded[MAX_EXPANDED_DATA_LEN], *to_apply;
                DWORD value_type, name_len, data_len;
                int i;
                LONG ret;
                
                ImpersonateLoggedOnUser(token);
                SET_USER_ENV(FOLDERID_LocalAppData, L"LOCALAPPDATA");
                SET_USER_ENV(FOLDERID_Profile, L"USERPROFILE");
                SET_USER_ENV(FOLDERID_RoamingAppData, L"APPDATA");
                reg_key = 0;
                if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_QUERY_VALUE, &reg_key) == ERROR_SUCCESS) {
                        i = 0;
                        while (1) {
                                name_len = MAX_VALUE_LEN * 2;
                                data_len = MAX_DATA_LEN * 2;
                                to_apply = NULL;
                                if (RegEnumValueW(reg_key, i++, &value_name, &name_len, 0, &value_type, &value_data, &data_len) != ERROR_SUCCESS)
                                        break;
                                if (value_type == REG_SZ) 
                                        to_apply = value_data;
                                else if (value_type == REG_EXPAND_SZ) {
                                        ExpandEnvironmentStringsW(value_data, value_data_expanded, MAX_EXPANDED_DATA_LEN);
                                        to_apply = value_data_expanded;
                                }          

                                if (wcsicmp(value_name, L"PATH") == 0) {
                                        DWORD size;
                                        if ((size = GetEnvironmentVariableW(L"PATH", NULL, 0)) != ERROR_ENVVAR_NOT_FOUND) {
                                                memcpy(value_data_expanded + size, to_apply, (wcslen(to_apply) + 1)*2);
                                                GetEnvironmentVariableW(L"PATH", value_data_expanded, MAX_EXPANDED_DATA_LEN);
                                                value_data_expanded[size-1] = L';';
                                                to_apply = value_data_expanded;
                                        }

                                }
                                if (to_apply)
                                        SetEnvironmentVariableW(value_name, to_apply);


                        }
                        RegCloseKey(reg_key);
                }


                RevertToSelf();
        }



	debug("<- GetHomeDirFromToken()...");
  
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
  pw.pw_dir = pw_homedir_ascii;

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
  
  //GetSystemDirectory(pw_shellpath, MAX_PATH);
  
  //debug3("getpwuid: system dir [%s]", pw_shellpath);
  pw_shellpath[0] = '\0';
  strcat(pw_shellpath, "ssh-shellhost.exe");
  
  //debug3("getpwuid: shell path [%s]", pw_shellpath);

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
    
  //wcsncpy(pw_homedir, homedir_w, sizeof(pw_homedir));
  // convert to ascii from widechar(unicode)
  int rc = WideCharToMultiByte( CP_UTF8, // UTF8/ANSI Code Page
		0, // No special handling of unmapped chars
		homedir_w, // wide-character string to be converted
		-1, // Unicode src str len, -1 means calc it
		pw_homedir_ascii, 
		sizeof(pw_homedir_ascii),
		NULL, NULL ); // Unrepresented char replacement - Use Default
 
  free(homedir_w);

  if ( rc == 0 ) {
	  debug3("Could not convert homedirectory [%ls]from unicode to utf8", homedir_w);
  }
  
  /*
   * Point to the username static variable.
   */
  
  //pw.pw_name   = pw_username;
  //pw.pw_passwd = pw_passwd;
  //pw.pw_gecos  = pw_gecos;
  //pw.pw_shell  = pw_shellpath;
  //pw.pw_dir    = pw_homedir;

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
  
   //GetSystemDirectory(pw_shellpath, MAX_PATH);

   //debug3("getpwuid: system dir [%s]", pw_shellpath);

  pw_shellpath[0] = '\0';
  strcat(pw_shellpath, "ssh-shellhost.exe");

  //debug3("getpwuid: shell path [%s]", pw_shellpath);

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

#define	NCACHE	64			/* power of 2 */
#define	MASK	(NCACHE - 1)		/* bits to store with */

const char *
user_from_uid(uid_t uid, int nouser)
{
	static struct ncache {
		uid_t	uid;
		char	*name;
	} c_uid[NCACHE];
	static int pwopen;
	static char nbuf[15];		/* 32 bits == 10 digits */
	struct passwd *pw;
	struct ncache *cp;

	cp = c_uid + (uid & MASK);
	if (cp->uid != uid || cp->name == NULL) {
		if (pwopen == 0) {
			pwopen = 1;
		}
		if ((pw = getpwuid(uid)) == NULL) {
			if (nouser)
				return (NULL);
			(void)snprintf(nbuf, sizeof(nbuf), "%u", uid);
		}
		cp->uid = uid;
		if (cp->name != NULL)
			free(cp->name);
		cp->name = strdup(pw ? pw->pw_name : nbuf);
	}
	return (cp->name);
}

/* TODO - this is moved from realpath.c in openbsdcompat. Review and finalize its position*/

#include <Shlwapi.h>

void backslashconvert(char *str)
{
	while (*str) {
		if (*str == '/')
			*str = '\\'; // convert forward slash to back slash
		str++;
	}

}

// convert back slash to forward slash
void slashconvert(char *str)
{
	while (*str) {
		if (*str == '\\')
			*str = '/'; // convert back slash to forward slash
		str++;
	}
}

char *realpathWin32(const char *path, char resolved[PATH_MAX])
{
	char realpath[PATH_MAX];

	strlcpy(resolved, path + 1, sizeof(realpath));
	backslashconvert(resolved);
	PathCanonicalizeA(realpath, resolved);
	slashconvert(realpath);

	/*
	* Store terminating slash in 'X:/' on Windows.
	*/

	if (realpath[1] == ':' && realpath[2] == 0)
	{
		realpath[2] = '/';
		realpath[3] = 0;
	}

	resolved[0] = *path; // will be our first slash in /x:/users/test1 format
	strncpy(resolved + 1, realpath, sizeof(realpath));
	return resolved;
}

// like realpathWin32() but takes out the first slash so that windows systems can work on the actual file or directory
char *realpathWin32i(const char *path, char resolved[PATH_MAX])
{
	char realpath[PATH_MAX];

	if (path[0] != '/') {
		// absolute form x:/abc/def given, no first slash to take out
		strlcpy(resolved, path, sizeof(realpath));
	}
	else
		strlcpy(resolved, path + 1, sizeof(realpath));

	backslashconvert(resolved);
	PathCanonicalizeA(realpath, resolved);
	slashconvert(realpath);

	/*
	* Store terminating slash in 'X:/' on Windows.
	*/

	if (realpath[1] == ':' && realpath[2] == 0)
	{
		realpath[2] = '/';
		realpath[3] = 0;
	}

	strncpy(resolved, realpath, sizeof(realpath));
	return resolved;
}
