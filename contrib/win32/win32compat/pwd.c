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
#include "debug.h"

static struct passwd pw;
static char* pw_shellpath = NULL;
#define SHELL_HOST "\\ssh-shellhost.exe"


int
initialize_pw()
{
	errno_t r = 0;
	char* program_dir = w32_programdir();
	size_t program_dir_len = strlen(program_dir);
	size_t shell_host_len = strlen(SHELL_HOST);
	if (pw_shellpath == NULL) {
		if ((pw_shellpath = malloc(program_dir_len + shell_host_len + 1)) == NULL)
			fatal("initialize_pw - out of memory");
		else {
			char* head = pw_shellpath;
			if ((r= memcpy_s(head, program_dir_len + shell_host_len + 1, w32_programdir(), program_dir_len)) != 0) {
				fatal("memcpy_s failed with error: %d.", r);
			}
			head += program_dir_len;
			if ((r = memcpy_s(head, shell_host_len + 1, SHELL_HOST, shell_host_len)) != 0) {
				fatal("memcpy_s failed with error: %d.", r);
			}
			head += shell_host_len;
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
	wchar_t reg_path[PATH_MAX], profile_home[PATH_MAX], profile_home_exp[PATH_MAX];
	HKEY reg_key = 0;
	int tmp_len = PATH_MAX;
	PDOMAIN_CONTROLLER_INFOW pdc = NULL;
	DWORD dsStatus, uname_upn_len = 0, uname_len = 0, udom_len = 0;
	wchar_t wmachine_name[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD wmachine_name_len = MAX_COMPUTERNAME_LENGTH + 1;
	errno_t r = 0;

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

	if (udom_utf16) {
		/* this should never fail */
		GetComputerNameW(wmachine_name, &wmachine_name_len);
		/* If this is a local account (domain part and computer name are the same), strip out domain */
		if (_wcsicmp(udom_utf16, wmachine_name) == 0)
			udom_utf16 = NULL;
	}

	if (user_sid == NULL) {
		NET_API_STATUS status;
		if ((status = NetUserGetInfo(udom_utf16, uname_utf16, 23, &user_info)) != NERR_Success) {
			debug3("NetUserGetInfo() failed with error: %d for user: %ls and domain: %ls \n", status, uname_utf16, udom_utf16);

			if ((dsStatus = DsGetDcNameW(NULL, udom_utf16, NULL, NULL, DS_DIRECTORY_SERVICE_PREFERRED, &pdc)) != ERROR_SUCCESS) {
				error("DsGetDcNameW() failed with error: %d \n", dsStatus);
				errno = ENOENT;
				goto done;
			}

			if ((status = NetUserGetInfo(pdc->DomainControllerName, uname_utf16, 23, &user_info)) != NERR_Success) {
				debug3("NetUserGetInfo() with domainController: %ls failed with error: %d \n", pdc->DomainControllerName, status);
				errno = ENOENT;
				goto done;
			}
		}

		if (ConvertSidToStringSidW(((LPUSER_INFO_23)user_info)->usri23_user_sid, &user_sid_local) == FALSE) {
			debug3("NetUserGetInfo() Succeded but ConvertSidToStringSidW() failed with error: %d\n", GetLastError());
			errno = ENOENT;
			goto done;
		}

		user_sid = user_sid_local;
	}

	/* if one of below fails, set profile path to Windows directory */
	if (swprintf_s(reg_path, PATH_MAX, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%ls", user_sid) == -1 ||
	    RegOpenKeyExW(HKEY_LOCAL_MACHINE, reg_path, 0, STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &reg_key) != 0 ||
	    RegQueryValueExW(reg_key, L"ProfileImagePath", 0, NULL, (LPBYTE)profile_home, &tmp_len) != 0 ||
	    ExpandEnvironmentStringsW(profile_home, NULL, 0) > PATH_MAX || 
	    ExpandEnvironmentStringsW(profile_home, profile_home_exp, PATH_MAX) == 0)
		if (GetWindowsDirectoryW(profile_home_exp, PATH_MAX) == 0) {
			debug3("GetWindowsDirectoryW failed with %d", GetLastError());
			errno = EOTHER;
			goto done;
		}

	if ((uname_utf8 = utf16_to_utf8(uname_utf16)) == NULL ||
	    (udom_utf16 && (udom_utf8 = utf16_to_utf8(udom_utf16)) == NULL) ||
	    (pw_home_utf8 = utf16_to_utf8(profile_home_exp)) == NULL ||
	    (user_sid_utf8 = utf16_to_utf8(user_sid)) == NULL) {
		errno = ENOMEM;
		goto done;
	}
	uname_len = (DWORD)strlen(uname_utf8);	
	uname_upn_len = uname_len + 1;
	if (udom_utf8) {
		udom_len = (DWORD)strlen(udom_utf8);
		uname_upn_len += udom_len + 1;
	}

	if ((uname_upn = malloc(uname_upn_len)) == NULL) {
		errno = ENOMEM;
		goto done;
	}

	if ((r = memcpy_s(uname_upn, uname_upn_len, uname_utf8, uname_len + 1)) != 0) {
		debug3("memcpy_s failed with error: %d.", r);
		goto done;
	}
	if (udom_utf8) {
		/* TODO - get domain FQDN */
		uname_upn[uname_len] = '@';
		if ((r = memcpy_s(uname_upn + uname_len + 1, udom_len + 1, udom_utf8, udom_len + 1)) != 0) {
			debug3("memcpy_s failed with error: %d.", r);
			goto done;
		}
	}

	to_lower_case(uname_upn);
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
w32_getpwtoken(HANDLE t)
{
	wchar_t* wuser = NULL;
	char* user_utf8 = NULL;
	ULONG needed = 0;
	struct passwd *ret = NULL;
	DWORD info_len = 0;
	TOKEN_USER* info = NULL;
	LPWSTR user_sid = NULL;

	errno = 0;

	if (GetUserNameExW(NameSamCompatible, NULL, &needed) != 0 ||
	    (wuser = malloc(needed * sizeof(wchar_t))) == NULL ||
	    GetUserNameExW(NameSamCompatible, wuser, &needed) == 0 ||
	    (user_utf8 = utf16_to_utf8(wuser)) == NULL ||
	    GetTokenInformation(t, TokenUser, NULL, 0, &info_len) == TRUE ||
	    (info = (TOKEN_USER*)malloc(info_len)) == NULL ||
	    GetTokenInformation(t, TokenUser, info, info_len, &info_len) == FALSE ||
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
	if (info)
		free(info);
	if (user_sid)
		LocalFree(user_sid);
	return ret;
}

struct passwd*
w32_getpwuid(uid_t uid)
{
	HANDLE token;
	struct passwd* ret;
	if ((OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) == FALSE) {
		debug("unable to get process token");
		errno = EOTHER;
		return NULL;
	}

	ret = w32_getpwtoken(token);
	CloseHandle(token);
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

void 
endpwent(void)
{
	return;
}
