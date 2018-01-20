/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
* Utitilites to generate user tokens
*
* Copyright (c) 2015 Microsoft Corp.
* All rights reserved
*
* Microsoft openssh win32 port
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

#define UMDF_USING_NTSTATUS 
#include <Windows.h>
#include <UserEnv.h>
#include <Ntsecapi.h>
#include <ntstatus.h>
#include <Shlobj.h>
#include "inc\utf.h"
#include "logonuser.h"
#include <Ntsecapi.h>
#include <ntstatus.h>
#include "misc_internal.h"
#include "Debug.h"

#pragma warning(push, 3)

static void
InitLsaString(LSA_STRING *lsa_string, const char *str)
{
	if (!str)
		memset(lsa_string, 0, sizeof(LSA_STRING));
	else {
		lsa_string->Buffer = (char *)str;
		lsa_string->Length = (USHORT)strlen(str);
		lsa_string->MaximumLength = lsa_string->Length + 1;
	}
}

static void
EnablePrivilege(const char *privName, int enabled)
{
	TOKEN_PRIVILEGES tp;
	HANDLE hProcToken = NULL;
	LUID luid;

	int exitCode = 1;

	if (LookupPrivilegeValueA(NULL, privName, &luid) == FALSE ||
		OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hProcToken) == FALSE)
		goto done;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = enabled ? SE_PRIVILEGE_ENABLED : 0;

	AdjustTokenPrivileges(hProcToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

done:
	if (hProcToken)
		CloseHandle(hProcToken);

	return;
}


static HANDLE
LoadProfile(HANDLE user_token, wchar_t* user, wchar_t* domain) {
	PROFILEINFOW profileInfo;
	HANDLE ret = NULL;

	profileInfo.dwFlags = PI_NOUI;
	profileInfo.lpProfilePath = NULL;
	profileInfo.lpUserName = user;
	profileInfo.lpDefaultPath = NULL;
	profileInfo.lpServerName = domain;
	profileInfo.lpPolicyPath = NULL;
	profileInfo.hProfile = NULL;
	profileInfo.dwSize = sizeof(profileInfo);
	EnablePrivilege("SeBackupPrivilege", 1);
	EnablePrivilege("SeRestorePrivilege", 1);
	if (LoadUserProfileW(user_token, &profileInfo) == FALSE) {
		debug("Loading user (%ls,%ls) profile failed ERROR: %d", user, domain, GetLastError());
		goto done;
	}
	else
		ret = profileInfo.hProfile;
done:
	EnablePrivilege("SeBackupPrivilege", 0);
	EnablePrivilege("SeRestorePrivilege", 0);
	return ret;
}

#define MAX_USER_LEN 64
/* https://technet.microsoft.com/en-us/library/active-directory-maximum-limits-scalability(v=ws.10).aspx */
#define MAX_FQDN_LEN 64 
#define MAX_PW_LEN 64

static HANDLE
generate_user_token(wchar_t* user_cpn) {
	HANDLE lsa_handle = 0, token = 0;
	LSA_OPERATIONAL_MODE mode;
	ULONG auth_package_id;
	NTSTATUS ret, subStatus;
	void * logon_info = NULL;
	size_t logon_info_size;
	LSA_STRING logon_process_name, auth_package_name, originName;
	TOKEN_SOURCE sourceContext;
	PKERB_INTERACTIVE_PROFILE pProfile = NULL;
	LUID logonId;
	QUOTA_LIMITS quotas;
	DWORD cbProfile;
	BOOL domain_user;

	domain_user = wcschr(user_cpn, L'@')? TRUE : FALSE;

	InitLsaString(&logon_process_name, "sshd");
	if (domain_user)
		InitLsaString(&auth_package_name, MICROSOFT_KERBEROS_NAME_A);
	else
		InitLsaString(&auth_package_name, MSV1_0_PACKAGE_NAME);

	InitLsaString(&originName, "sshd");
	if (ret = LsaRegisterLogonProcess(&logon_process_name, &lsa_handle, &mode) != STATUS_SUCCESS)
		goto done;

	if (ret = LsaLookupAuthenticationPackage(lsa_handle, &auth_package_name, &auth_package_id) != STATUS_SUCCESS)
		goto done;

	if (domain_user) {
		KERB_S4U_LOGON *s4u_logon;
		logon_info_size = sizeof(KERB_S4U_LOGON);
		logon_info_size += (wcslen(user_cpn) * 2 + 2);
		logon_info = malloc(logon_info_size);
		if (logon_info == NULL)
			goto done;
		s4u_logon = (KERB_S4U_LOGON*)logon_info;
		s4u_logon->MessageType = KerbS4ULogon;
		s4u_logon->Flags = 0;
		s4u_logon->ClientUpn.Length = (USHORT)wcslen(user_cpn) * 2;
		s4u_logon->ClientUpn.MaximumLength = s4u_logon->ClientUpn.Length;
		s4u_logon->ClientUpn.Buffer = (WCHAR*)(s4u_logon + 1);
		if (memcpy_s(s4u_logon->ClientUpn.Buffer, s4u_logon->ClientUpn.Length + 2, user_cpn, s4u_logon->ClientUpn.Length + 2))
			goto done;
		s4u_logon->ClientRealm.Length = 0;
		s4u_logon->ClientRealm.MaximumLength = 0;
		s4u_logon->ClientRealm.Buffer = 0;
	} else {
		MSV1_0_S4U_LOGON *s4u_logon;
		logon_info_size = sizeof(MSV1_0_S4U_LOGON);
		/* additional buffer size = size of user_cpn + size of "." and their null terminators */
		logon_info_size += (wcslen(user_cpn) * 2 + 2) + 4;
		logon_info = malloc(logon_info_size);
		if (logon_info == NULL)
			goto done;
		s4u_logon = (MSV1_0_S4U_LOGON*)logon_info;
		s4u_logon->MessageType = MsV1_0S4ULogon;
		s4u_logon->Flags = 0;
		s4u_logon->UserPrincipalName.Length = (USHORT)wcslen(user_cpn) * 2;
		s4u_logon->UserPrincipalName.MaximumLength = s4u_logon->UserPrincipalName.Length;
		s4u_logon->UserPrincipalName.Buffer = (WCHAR*)(s4u_logon + 1);
		if(memcpy_s(s4u_logon->UserPrincipalName.Buffer, s4u_logon->UserPrincipalName.Length + 2, user_cpn, s4u_logon->UserPrincipalName.Length + 2))
			goto done;
		s4u_logon->DomainName.Length = 2;
		s4u_logon->DomainName.MaximumLength = 2;
		s4u_logon->DomainName.Buffer = ((WCHAR*)s4u_logon->UserPrincipalName.Buffer) + wcslen(user_cpn) + 1;
		if(memcpy_s(s4u_logon->DomainName.Buffer, 4, L".", 4))
			goto done;
	}

	if(memcpy_s(sourceContext.SourceName, TOKEN_SOURCE_LENGTH, "sshd", sizeof(sourceContext.SourceName)))
		goto done;

	if (AllocateLocallyUniqueId(&sourceContext.SourceIdentifier) != TRUE)
		goto done;

	if (ret = LsaLogonUser(lsa_handle,
		&originName,
		Network,
		auth_package_id,
		logon_info,
		(ULONG)logon_info_size,
		NULL,
		&sourceContext,
		(PVOID*)&pProfile,
		&cbProfile,
		&logonId,
		&token,
		&quotas,
		&subStatus) != STATUS_SUCCESS) {
		debug("LsaLogonUser failed NTSTATUS: %d", ret);
		goto done;
	}
	debug3("LsaLogonUser succeeded");
done:
	if (lsa_handle)
		LsaDeregisterLogonProcess(lsa_handle);
	if (logon_info)
		free(logon_info);
	if (pProfile)
		LsaFreeReturnBuffer(pProfile);

	return token;
}

HANDLE
process_custom_lsa_auth(char* user, const char* pwd, char* lsa_pkg)
{
	wchar_t *userw = NULL, *pwdw = NULL, *domw = NULL, *tmp, *providerw = NULL;
	HANDLE token = NULL, lsa_handle = NULL;
	LSA_OPERATIONAL_MODE mode;
	ULONG auth_package_id, logon_info_size = 0;
	NTSTATUS ret, subStatus;
	wchar_t *logon_info = NULL;
	LSA_STRING logon_process_name, lsa_auth_package_name, originName;
	TOKEN_SOURCE sourceContext;
	PVOID pProfile = NULL;
	LUID logonId;
	QUOTA_LIMITS quotas;
	DWORD cbProfile;
	int retVal = -1;

	debug("LSA auth request, user:%s lsa_pkg:%s ", user, lsa_pkg);

	if ((userw = utf8_to_utf16(user)) == NULL ||
	    (pwdw = utf8_to_utf16(pwd)) == NULL) {
		debug("out of memory");
		goto done;
	}

	/* split user and domain */
	if ((tmp = wcschr(userw, L'@')) != NULL) {
		domw = tmp + 1;
		*tmp = L'\0';
	}

	/* call into LSA provider , get and duplicate token */
	InitLsaString(&logon_process_name, "sshd");
	InitLsaString(&lsa_auth_package_name, lsa_pkg);
	InitLsaString(&originName, "sshd");

	if ((ret = LsaRegisterLogonProcess(&logon_process_name, &lsa_handle, &mode)) != STATUS_SUCCESS) {
		error("LsaRegisterLogonProcess failed, error:%x", ret);
		goto done;
	}

	if ((ret = LsaLookupAuthenticationPackage(lsa_handle, &lsa_auth_package_name, &auth_package_id)) != STATUS_SUCCESS) {
		error("LsaLookupAuthenticationPackage failed, lsa auth pkg:%ls error:%x", lsa_pkg, ret);
		goto done;
	}

	logon_info_size = (ULONG)((wcslen(userw) + wcslen(pwdw) + wcslen(domw) + 3) * sizeof(wchar_t));
	logon_info = (wchar_t *)malloc(logon_info_size);
	if (NULL == logon_info)
		fatal("%s:out of memory", __func__);

	wcscpy_s(logon_info, logon_info_size, userw);
	wcscat_s(logon_info, logon_info_size, L";");
	wcscat_s(logon_info, logon_info_size, pwdw);
	wcscat_s(logon_info, logon_info_size, L";");
	wcscat_s(logon_info, logon_info_size, domw);

	memcpy(sourceContext.SourceName, "sshd", sizeof(sourceContext.SourceName));

	if (!AllocateLocallyUniqueId(&sourceContext.SourceIdentifier)) {
		error("AllocateLocallyUniqueId failed, error:%d", GetLastError());
		goto done;
	}		

	if ((ret = LsaLogonUser(lsa_handle,
		&originName,
		Network,
		auth_package_id,
		logon_info,
		logon_info_size,
		NULL,
		&sourceContext,
		&pProfile,
		&cbProfile,
		&logonId,
		&token,
		&quotas,
		&subStatus)) != STATUS_SUCCESS) {		
		if(ret == STATUS_ACCOUNT_RESTRICTION)
			error("LsaLogonUser failed, error:%x subStatus:%ld", ret, subStatus);
		else
			error("LsaLogonUser failed error:%x", ret);

		goto done;
	}

	retVal = 0;
done:
	/* delete allocated memory*/
	if (lsa_handle)
		LsaDeregisterLogonProcess(lsa_handle);
	if (logon_info)
		free(logon_info);
	if (pProfile)
		LsaFreeReturnBuffer(pProfile);
	if (userw)
		free(userw);
	if (pwdw)
		free(pwdw);

	return token;
}

HANDLE
get_user_token(char* user) {
	HANDLE token = NULL;
	wchar_t *user_utf16 = NULL;
	
	if ((user_utf16 = utf8_to_utf16(user)) == NULL) {
		debug("out of memory");
		goto done;
	}

	if ((token = generate_user_token(user_utf16)) == 0) {
		error("unable to generate token for user %ls", user_utf16);
		/* work around for https://github.com/PowerShell/Win32-OpenSSH/issues/727 by doing a fake login */
		LogonUserExExWHelper(L"FakeUser", L"FakeDomain", L"FakePasswd",
			LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_PROVIDER_DEFAULT, NULL, &token, NULL, NULL, NULL, NULL);
		if ((token = generate_user_token(user_utf16)) == 0) {
			error("unable to generate token on 2nd attempt for user %ls", user_utf16);
			goto done;
		}
	}

done:
	if (user_utf16)
		free(user_utf16);

	return token;
}

int load_user_profile(HANDLE user_token, char* user) {
	int r = 0;
	HANDLE profile_handle = NULL;
	wchar_t *user_utf16 = NULL, *dom_utf16 = NULL, *tmp;

	if ((user_utf16 = utf8_to_utf16(user)) == NULL) {
		debug("out of memory");
		goto done;
	}

	/* split user and domain */
	if ((tmp = wcschr(user_utf16, L'@')) != NULL) {
		dom_utf16 = tmp + 1;
		*tmp = L'\0';
	}

	if ((profile_handle = LoadProfile(user_token, user_utf16, dom_utf16)) == NULL)
		goto done;

done:
	if (user_utf16)
		free(user_utf16);
	return r;
}

#pragma warning(pop)