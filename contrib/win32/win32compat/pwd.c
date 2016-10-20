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

#include <Windows.h>
#include <stdio.h>
#include <LM.h>
#include <sddl.h>
#define SECURITY_WIN32
#include <security.h>
#include "inc\pwd.h"
#include "inc\utf.h"

static struct passwd pw;
static char* pw_shellpath = "ssh-shellhost.exe";

int
initialize_pw() {
        if (pw.pw_shell != pw_shellpath) {
                memset(&pw, 0, sizeof(pw));
                pw.pw_shell = pw_shellpath;
                pw.pw_passwd = "\0";
        }
        return 0;
}

void
reset_pw() {
        initialize_pw();
        if (pw.pw_name)
                free(pw.pw_name);
        if (pw.pw_dir)
                free(pw.pw_dir);
}

static struct passwd*
get_passwd(const char *user_utf8, LPWSTR user_sid) {
        struct passwd *ret = NULL;
        wchar_t *user_utf16 = NULL, *uname_utf16, *udom_utf16, *tmp;
        char *uname_utf8 = NULL, *pw_home_utf8 = NULL;
        LPBYTE user_info = NULL;
        LPWSTR user_sid_local = NULL;
        wchar_t reg_path[MAX_PATH], profile_home[MAX_PATH];
        HKEY reg_key = 0;
        int tmp_len = MAX_PATH;

        errno = 0;

        reset_pw();

        if ((user_utf16 = utf8_to_utf16(user_utf8) ) == NULL) {
                errno = ENOMEM;
                goto done;
        }

        /*find domain part if any*/
        if ((tmp = wcschr(user_utf16, L'\\')) != NULL) {
                udom_utf16 = user_utf16;
                uname_utf16 = tmp + 1;
                *tmp = L'\0';

        }
        else if ((tmp = wcschr(user_utf16, L'@')) != NULL) {
                udom_utf16 = tmp + 1;
                uname_utf16 = user_utf16;
                *tmp = L'\0';
        }
        else {
                uname_utf16 = user_utf16;
                udom_utf16 = NULL;
        }

        if (user_sid == NULL) {
                if (NetUserGetInfo(udom_utf16, uname_utf16, 23, &user_info) != NERR_Success ||
                        ConvertSidToStringSidW(((LPUSER_INFO_23)user_info)->usri23_user_sid, &user_sid_local) == FALSE) {
                        errno = ENOMEM; //??
                        goto done;
                }
                user_sid = user_sid_local;
        }

        if (swprintf(reg_path, MAX_PATH, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%ls", user_sid) == MAX_PATH ||
                RegOpenKeyExW(HKEY_LOCAL_MACHINE, reg_path, 0, STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &reg_key) != 0 ||
                RegQueryValueExW(reg_key, L"ProfileImagePath", 0, NULL, (LPBYTE)profile_home, &tmp_len) != 0)
                GetWindowsDirectoryW(profile_home, MAX_PATH);

        if ((uname_utf8 = _strdup(user_utf8)) == NULL ||
                (pw_home_utf8 = utf16_to_utf8(profile_home)) == NULL) {
                errno = ENOMEM;
                goto done;
        }
        
        pw.pw_name = uname_utf8;
        uname_utf8 = NULL;
        pw.pw_dir = pw_home_utf8;
        pw_home_utf8 = NULL;
        ret = &pw;
done:
        if (user_utf16)
                free(user_utf16);
        if (uname_utf8)
                free(uname_utf8);
        if (pw_home_utf8)
                free(pw_home_utf8);
        if (user_info)
                NetApiBufferFree(user_info);
        if (user_sid_local)
                LocalFree(user_sid_local);
        if (reg_key)
                RegCloseKey(reg_key);
        return ret;
}

struct passwd*
w32_getpwnam(const char *user_utf8) {
        return get_passwd(user_utf8, NULL);
}

struct passwd*
w32_getpwuid(uid_t uid) {
        wchar_t* wuser = NULL;
        char* user_utf8 = NULL;
        ULONG needed = 0;
        struct passwd *ret = NULL;
        HANDLE token = 0;
        DWORD info_len = 0;
        TOKEN_USER* info = NULL;
        LPWSTR user_sid = NULL;

        errno = 0;
       
        if (GetUserNameExW(NameSamCompatible, NULL, &needed) != 0 ||
                (wuser = malloc(needed * sizeof(wchar_t))) == NULL ||
                GetUserNameExW(NameSamCompatible, wuser, &needed) == 0 ||
                (user_utf8 = utf16_to_utf8(wuser)) == NULL  ||
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == FALSE ||
                GetTokenInformation(token, TokenUser, NULL, 0, &info_len) == TRUE ||
                (info = (TOKEN_USER*)malloc(info_len)) == NULL ||
                GetTokenInformation(token, TokenUser, info, info_len, &info_len) == FALSE ||
                ConvertSidToStringSidW(info->User.Sid, &user_sid) == FALSE){
                errno = ENOMEM;
                goto done;
        }
        ret = get_passwd(user_utf8, user_sid);

done:
        if (wuser)
                free(wuser);
        if (user_utf8)
                free(user_utf8);
        if (token)
                CloseHandle(token);
        if (info)
                free(info);
        if (user_sid)
                LocalFree(user_sid);
        return ret;
}

#define SET_USER_ENV(folder_id, evn_variable) do  {                \
       if (SHGetKnownFolderPath(&folder_id,0,token,&path) == S_OK)              \
        {                                                                       \
                SetEnvironmentVariableW(evn_variable, path);                    \
                CoTaskMemFree(path);                                            \
       }                                                                        \
} while (0)                                                                     


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


uid_t
getuid(void) {
	return 0;
}

gid_t
getgid(void) {
	return 0;
}

uid_t
geteuid(void) {
	return 0;
}

gid_t
getegid(void) {
	return 0;
}

int
setuid(uid_t uid) {
	return 0;
}

int
setgid(gid_t gid) {
	return 0;
}

int
seteuid(uid_t uid) {
	return 0;
}

int
setegid(gid_t gid) {
	return 0;
}
