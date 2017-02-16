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
#include <DsGetDC.h>
#define SECURITY_WIN32
#include <security.h>

#include "inc\pwd.h"
#include "inc\grp.h"
#include "inc\utf.h"
#include "misc_internal.h"

static struct passwd pw;
static char* pw_shellpath = NULL;
#define SHELL_HOST "\\ssh-shellhost.exe"


int
initialize_pw()
{
	if (pw_shellpath == NULL) {
		if ((pw_shellpath = malloc(strlen(w32_programdir()) + strlen(SHELL_HOST) + 1)) == NULL)
			fatal("initialize_pw - out of memory");
		else {
			char* head = pw_shellpath;
			memcpy(head, w32_programdir(), strlen(w32_programdir()));
			head += strlen(w32_programdir());
			memcpy(head, SHELL_HOST, strlen(SHELL_HOST));
			head += strlen(SHELL_HOST);
			*head = '\0';
		}
	}

	if (pw.pw_shell != pw_shellpath) {
		memset(&pw, 0, sizeof(pw));
		pw.pw_shell = pw_shellpath;
		pw.pw_passwd = "\0";
		/* pw_uid = 0 for root on Unix and SSH code has specific restrictions for root
		 * that are not applicable in Windows */
		pw.pw_uid = 1;
	}
	return 0;
}

void
reset_pw()
{
	initialize_pw();
	if (pw.pw_name)
		free(pw.pw_name);
	if (pw.pw_dir)
		free(pw.pw_dir);
	if (pw.pw_sid)
		free(pw.pw_sid);
	pw.pw_name = NULL;
	pw.pw_dir = NULL;
	pw.pw_sid = NULL;
}

static struct passwd*
get_passwd(const char *user_utf8, LPWSTR user_sid)
{
	struct passwd *ret = NULL;
	wchar_t *user_utf16 = NULL, *uname_utf16, *udom_utf16, *tmp;
	char *uname_utf8 = NULL, *uname_upn = NULL, *udom_utf8 = NULL, *pw_home_utf8 = NULL, *user_sid_utf8 = NULL;
	LPBYTE user_info = NULL;
	LPWSTR user_sid_local = NULL;
	wchar_t reg_path[PATH_MAX], profile_home[PATH_MAX];
	HKEY reg_key = 0;
	int tmp_len = PATH_MAX;
	PDOMAIN_CONTROLLER_INFOW pdc = NULL;
	DWORD dsStatus, uname_upn_len = 0;;

	errno = 0;
	reset_pw();
	if ((user_utf16 = utf8_to_utf16(user_utf8)) == NULL) {
		errno = ENOMEM;
		goto done;
	}

	/*find domain part if any*/
	if ((tmp = wcschr(user_utf16, L'\\')) != NULL) {
		udom_utf16 = user_utf16;
		uname_utf16 = tmp + 1;
		*tmp = L'\0';

	} else if ((tmp = wcschr(user_utf16, L'@')) != NULL) {
		udom_utf16 = tmp + 1;
		uname_utf16 = user_utf16;
		*tmp = L'\0';
	} else {
		uname_utf16 = user_utf16;
		udom_utf16 = NULL;
	}

	if (user_sid == NULL) {
		NET_API_STATUS status;
		if ((status = NetUserGetInfo(udom_utf16, uname_utf16, 23, &user_info)) != NERR_Success) {
			debug("NetUserGetInfo() failed with error: %d for user: %ls and domain: %ls \n", status, uname_utf16, udom_utf16);

			if ((dsStatus = DsGetDcNameW(NULL, udom_utf16, NULL, NULL, DS_DIRECTORY_SERVICE_PREFERRED, &pdc)) != ERROR_SUCCESS) {
				error("DsGetDcNameW() failed with error: %d \n", dsStatus);
				errno = ENOENT;
				goto done;
			}

			if ((status = NetUserGetInfo(pdc->DomainControllerName, uname_utf16, 23, &user_info)) != NERR_Success) {
				debug("NetUserGetInfo() with domainController: %ls failed with error: %d \n", pdc->DomainControllerName, status);
				errno = ENOENT;
				goto done;
			}
		}

		if (ConvertSidToStringSidW(((LPUSER_INFO_23)user_info)->usri23_user_sid, &user_sid_local) == FALSE) {
			debug("NetUserGetInfo() Succeded but ConvertSidToStringSidW() failed with error: %d\n", GetLastError());
			errno = ENOENT;
			goto done;
		}

		user_sid = user_sid_local;
	}

	/* if one of below fails, set profile path to Windows directory */
	if (swprintf(reg_path, PATH_MAX, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%ls", user_sid) == PATH_MAX ||
		RegOpenKeyExW(HKEY_LOCAL_MACHINE, reg_path, 0, STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &reg_key) != 0 ||
		RegQueryValueExW(reg_key, L"ProfileImagePath", 0, NULL, (LPBYTE)profile_home, &tmp_len) != 0)
		GetWindowsDirectoryW(profile_home, PATH_MAX);

	if ((uname_utf8 = utf16_to_utf8(uname_utf16)) == NULL ||
	    (udom_utf16 && (udom_utf8 = utf16_to_utf8(udom_utf16)) == NULL) ||
	    (pw_home_utf8 = utf16_to_utf8(profile_home)) == NULL ||
	    (user_sid_utf8 = utf16_to_utf8(user_sid)) == NULL) {
		errno = ENOMEM;
		goto done;
	}

	uname_upn_len = strlen(uname_utf8) + 1;
	if (udom_utf8)
		uname_upn_len += strlen(udom_utf8) + 1;

	if ((uname_upn = malloc(uname_upn_len)) == NULL) {
		errno = ENOMEM;
		goto done;
	}

	memcpy(uname_upn, uname_utf8, strlen(uname_utf8) + 1);
	if (udom_utf8) {
		/* TODO - get domain FQDN */
		uname_upn[strlen(uname_utf8)] = '@';
		memcpy(uname_upn + strlen(uname_utf8) + 1, udom_utf8, strlen(udom_utf8) + 1);
	}
	pw.pw_name = uname_upn;
	uname_upn = NULL;
	pw.pw_dir = pw_home_utf8;
	pw_home_utf8 = NULL;
	pw.pw_sid = user_sid_utf8;
	user_sid_utf8 = NULL;
	ret = &pw;

done:
	if (user_utf16)
		free(user_utf16);
	if (uname_utf8)
		free(uname_utf8);
	if (uname_upn)
		free(uname_upn);
	if (udom_utf8)
		free(udom_utf8);
	if (pw_home_utf8)
		free(pw_home_utf8);
	if (user_sid_utf8)
		free(user_sid_utf8);
	if (user_info)
		NetApiBufferFree(user_info);
	if (user_sid_local)
		LocalFree(user_sid_local);
	if (reg_key)
		RegCloseKey(reg_key);
	if (pdc)
		NetApiBufferFree(pdc);
	return ret;
}

struct passwd*
w32_getpwnam(const char *user_utf8)
{
	return get_passwd(user_utf8, NULL);
}

struct passwd*
w32_getpwuid(uid_t uid)
{
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
	    (user_utf8 = utf16_to_utf8(wuser)) == NULL ||
	    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == FALSE ||
	    GetTokenInformation(token, TokenUser, NULL, 0, &info_len) == TRUE ||
	    (info = (TOKEN_USER*)malloc(info_len)) == NULL ||
	    GetTokenInformation(token, TokenUser, info, info_len, &info_len) == FALSE ||
	    ConvertSidToStringSidW(info->User.Sid, &user_sid) == FALSE) {
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



char *
group_from_gid(gid_t gid, int nogroup)
{
	return "-";
}

char *
user_from_uid(uid_t uid, int nouser)
{
	return "-";
}

uid_t
getuid(void)
{
	return 0;
}

gid_t
getgid(void)
{
	return 0;
}

uid_t
geteuid(void)
{
	return 0;
}

gid_t
getegid(void)
{
	return 0;
}

int
setuid(uid_t uid)
{
	return 0;
}

int
setgid(gid_t gid)
{
	return 0;
}

int
seteuid(uid_t uid)
{
	return 0;
}

int
setegid(gid_t gid)
{
	return 0;
}
