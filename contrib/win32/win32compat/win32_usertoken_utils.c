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
#include <LM.h>

#include "inc\utf.h"
#include "logonuser.h"
#include <Ntsecapi.h>
#include <Strsafe.h>
#include <sddl.h>
#include <ntstatus.h>
#include "misc_internal.h"
#include "lsa_missingdefs.h"
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
generate_s4u_user_token(wchar_t* user_cpn) {
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
process_custom_lsa_auth(const char* user, const char* pwd, const char* lsa_pkg)
{
	wchar_t *providerw = NULL;
	HANDLE token = NULL, lsa_handle = NULL;
	LSA_OPERATIONAL_MODE mode;
	ULONG auth_package_id, logon_info_size = 0;
	NTSTATUS ret, subStatus;
	wchar_t *logon_info_w = NULL;
	LSA_STRING logon_process_name, lsa_auth_package_name, originName;
	TOKEN_SOURCE sourceContext;
	PVOID pProfile = NULL;
	LUID logonId;
	QUOTA_LIMITS quotas;
	DWORD cbProfile;
	int retVal = -1;
	char *domain = NULL, *logon_info = NULL, user_name[UNLEN] = { 0, }, *tmp = NULL;

	debug3("LSA auth request, user:%s lsa_pkg:%s ", user, lsa_pkg);

	logon_info_size = (ULONG)(strlen(user) + strlen(pwd) + 2); // 1 - ";", 1 - "\0"
	strcpy_s(user_name, _countof(user_name), user);
	if (tmp = strstr(user_name, "@")) {
		domain = tmp + 1;
		*tmp = '\0';
		logon_info_size++; // 1 - ";"
	}

	logon_info = malloc(logon_info_size);
	if(!logon_info)
		fatal("%s out of memory", __func__);

	strcpy_s(logon_info, logon_info_size, user_name);
	strcat_s(logon_info, logon_info_size, ";");
	strcat_s(logon_info, logon_info_size, pwd);

	if (domain) {
		strcat_s(logon_info, logon_info_size, ";");
		strcat_s(logon_info, logon_info_size, domain);
	}

	if (NULL == (logon_info_w = utf8_to_utf16(logon_info))) {
		error("utf8_to_utf16 failed to convert %s", logon_info);
		goto done;
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

	memcpy(sourceContext.SourceName, "sshd", sizeof(sourceContext.SourceName));

	if (!AllocateLocallyUniqueId(&sourceContext.SourceIdentifier)) {
		error("AllocateLocallyUniqueId failed, error:%d", GetLastError());
		goto done;
	}

	if ((ret = LsaLogonUser(lsa_handle,
		&originName,
		Network,
		auth_package_id,
		logon_info_w,
		logon_info_size * sizeof(wchar_t),
		NULL,
		&sourceContext,
		&pProfile,
		&cbProfile,
		&logonId,
		&token,
		&quotas,
		&subStatus)) != STATUS_SUCCESS) {
		if (ret == STATUS_ACCOUNT_RESTRICTION)
			error("LsaLogonUser failed, error:%x subStatus:%ld", ret, subStatus);
		else
			error("LsaLogonUser failed error:%x", ret);

		goto done;
	}

	debug3("LSA auth request is successful for user:%s ", user);
	retVal = 0;
done:
	if (lsa_handle)
		LsaDeregisterLogonProcess(lsa_handle);
	if (pProfile)
		LsaFreeReturnBuffer(pProfile);
	if (logon_info)
		free(logon_info);
	if (logon_info_w)
		free(logon_info_w);

	return token;
}

HANDLE generate_sshd_virtual_token();

HANDLE
get_user_token(char* user) {
	HANDLE token = NULL;
	wchar_t *user_utf16 = NULL;
	
	if ((user_utf16 = utf8_to_utf16(user)) == NULL) {
		debug("out of memory");
		goto done;
	}

	if (wcscmp(user_utf16, L"sshd") == 0) {
		if ((token = generate_sshd_virtual_token()) != 0)
			goto done;
		debug3("unable to generate sshd virtual token, falling back to s4u");
	}

	if ((token = generate_s4u_user_token(user_utf16)) == 0) {
		error("unable to generate token for user %ls", user_utf16);
		/* work around for https://github.com/PowerShell/Win32-OpenSSH/issues/727 by doing a fake login */
		LogonUserExExWHelper(L"FakeUser", L"FakeDomain", L"FakePasswd",
			LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_PROVIDER_DEFAULT, NULL, &token, NULL, NULL, NULL, NULL);
		if ((token = generate_s4u_user_token(user_utf16)) == 0) {
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


/* *** virtual account token generation logic ***/

char* LSAMappingErrorDetails[] = {
	"LsaSidNameMappingOperation_Success",
	"LsaSidNameMappingOperation_NonMappingError",
	"LsaSidNameMappingOperation_NameCollision",
	"LsaSidNameMappingOperation_SidCollision",
	"LsaSidNameMappingOperation_DomainNotFound",
	"LsaSidNameMappingOperation_DomainSidPrefixMismatch",
	"LsaSidNameMappingOperation_MappingNotFound"
};

#define VIRTUALUSER_DOMAIN L"VIRTUAL USERS"
#define VIRTUALUSER_GROUP_NAME L"ALL VIRTUAL USERS"

/* returns 0 on success -1 on failure */
int
AddSidMappingToLsa(PUNICODE_STRING domain_name,
	 PUNICODE_STRING account_name,
	 PSID sid)
{
	LSA_SID_NAME_MAPPING_OPERATION_INPUT   input = { 0 };
	PLSA_SID_NAME_MAPPING_OPERATION_OUTPUT p_output = NULL;
	LSA_SID_NAME_MAPPING_OPERATION_ERROR op_result =
		LsaSidNameMappingOperation_NonMappingError;
	NTSTATUS status = STATUS_SUCCESS;
	int ret = 0;

	input.AddInput.DomainName = *domain_name;
	if (account_name)
		input.AddInput.AccountName = *account_name;
	input.AddInput.Sid = sid;

	status = LsaManageSidNameMapping(LsaSidNameMappingOperation_Add,
		&input,
		&p_output);
	if (status != STATUS_SUCCESS) {
		ret = -1;
		if (p_output) {
			op_result = p_output->AddOutput.ErrorCode;
			if (op_result == LsaSidNameMappingOperation_NameCollision || op_result == LsaSidNameMappingOperation_SidCollision)
				ret = 0; /* OK as it failed due to collision */
			else
				error("LsaManageSidNameMapping failed with : %s \n", LSAMappingErrorDetails[op_result]);
		}
		else
			error("LsaManageSidNameMapping failed with ntstatus: %d \n", status);
	}

	/* TODO - Free p_output */
	/*if (p_output)
		LsaFreeMemory(p_output);*/

	return ret;
}


int RemoveVirtualAccountLSAMapping(PUNICODE_STRING domain_name,
	PUNICODE_STRING account_name)
{
	int ret = 0;

	LSA_SID_NAME_MAPPING_OPERATION_INPUT         input = { 0 };
	PLSA_SID_NAME_MAPPING_OPERATION_OUTPUT       p_output = NULL;
	PLSA_SID_NAME_MAPPING_OPERATION_REMOVE_INPUT remove_input = &input.RemoveInput;

	remove_input->DomainName = *domain_name;
	if (account_name)
		remove_input->AccountName = *account_name;
	
	NTSTATUS status = LsaManageSidNameMapping(LsaSidNameMappingOperation_Remove,
		&input,
		&p_output);
	if (status != STATUS_SUCCESS)
		ret = -1;

	/* TODO - Free p_output */
	/*if (p_output)
		LsaFreeMemory(p_output);*/

	return ret;
}

void 
InitUnicodeString(PUNICODE_STRING dest, PCWSTR source)
{
	dest->Buffer = source;
	dest->Length = wcslen(source) * sizeof(wchar_t);
	dest->MaximumLength = dest->Length + 2;
}

HANDLE generate_sshd_virtual_token()
{
	SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
	UNICODE_STRING domain, group, account;
	WCHAR va_name[32]; /* enough to accomodate sshd_123457890 */

	PSID sid_domain = NULL, sid_group = NULL, sid_user = NULL;
	HANDLE va_token = 0, va_token_restricted = 0;

	StringCchPrintfW(va_name, 32, L"%s_%d", L"sshd", GetCurrentProcessId());

	InitUnicodeString(&domain, VIRTUALUSER_DOMAIN);
	InitUnicodeString(&group, VIRTUALUSER_GROUP_NAME);
	InitUnicodeString(&account, va_name);

	/* Initialize SIDs */
	/* domain SID - S-1-5-111 */
	if (!(AllocateAndInitializeSid(&nt_authority,
	    1,
	    111,
	    0,
	    0,
	    0,
	    0,
	    0,
	    0,
	    0,
	    &sid_domain)))
		goto cleanup;

	/* group SID - S-1-5-111-0 */
	if (!(AllocateAndInitializeSid(&nt_authority,
	    2,
	    111,
	    0,
	    0,
	    0,
	    0,
	    0,
	    0,
	    0,
	    &sid_group)))
		goto cleanup;

	/* 
	 * account SID 
	 * this is derived from higher RIDs in sshd service account SID to ensure there are no conflicts
	 * S-1-5-80-3847866527-469524349-687026318-516638107-1125189541 (Well Known group: NT SERVICE\sshd)
	 * Ex account SID - S-1-5-111-3847866527-469524349-687026318-516638107-1125189541-123
	 */
	if (!(AllocateAndInitializeSid(&nt_authority,
	    7,
	    111,
	    3847866527,
	    469524349,
	    687026318,
	    516638107,
	    1125189541,
	    GetCurrentProcessId(),
	    0,
	    &sid_user)))
		goto cleanup;

	/* Map the domain SID */
	if (AddSidMappingToLsa(&domain, NULL, sid_domain) != 0)
		goto cleanup;

	/* Map the group SID */
	if (AddSidMappingToLsa(&domain, &group, sid_group) != 0)
		goto cleanup;

	/* Map the user SID */
	if (AddSidMappingToLsa(&domain, &account, sid_user) != 0)
		goto cleanup;

	/* Logon virtual and create token */
	if (!LogonUserExExWHelper(
	    va_name,
	    VIRTUALUSER_DOMAIN,
	    L"",
	    LOGON32_LOGON_INTERACTIVE,
	    LOGON32_PROVIDER_VIRTUAL,
	    NULL,
	    &va_token,
	    NULL,
	    NULL,
	    NULL,
	    NULL)) {
		debug3("LogonUserExExW failed with %d \n", GetLastError());
		goto cleanup;
	}

	/* remove all privileges */
	if (!CreateRestrictedToken(va_token, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &va_token_restricted ))
		debug3("CreateRestrictedToken failed with %d \n", GetLastError());

	CloseHandle(va_token);

cleanup:
	RemoveVirtualAccountLSAMapping(&domain, &account);

	if (sid_domain)
		FreeSid(sid_domain);
	if (sid_user)
		FreeSid(sid_user);
	if (sid_group)
		FreeSid(sid_group);

	return va_token_restricted;
}



#pragma warning(pop)