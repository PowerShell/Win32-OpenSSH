/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
* ssh-agent implementation on Windows
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
#include "agent.h"
#include "agent-request.h"
#include "key.h"
#include "inc\utf.h"
#include "..\priv-agent.h"
#include "logonuser.h"

#pragma warning(push, 3)

int pubkey_allowed(struct sshkey* pubkey, char*  user_utf8);

static void
InitLsaString(LSA_STRING *lsa_string, const char *str)
{
	if (str == NULL)
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

	InitLsaString(&logon_process_name, "ssh-agent");
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

	if(memcpy_s(sourceContext.SourceName, TOKEN_SOURCE_LENGTH, "sshagent", sizeof(sourceContext.SourceName)))
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

static HANDLE
duplicate_token_for_client(struct agent_connection* con, HANDLE t) {
	ULONG client_pid;
	HANDLE client_proc = NULL, dup_t = NULL;

	/* Should the token match client's session id?
	ULONG client_sessionId;
	if (GetNamedPipeClientSessionId(con->pipe_handle, &client_sessionId) == FALSE ||
	    SetTokenInformation(t, TokenSessionId, &client_sessionId, sizeof(client_sessionId)) == FALSE) {
		error("unable to set token session id, error: %d", GetLastError());
		goto done;
	}*/

	if ((FALSE == GetNamedPipeClientProcessId(con->pipe_handle, &client_pid)) ||
		((client_proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, client_pid)) == NULL) ||
		DuplicateHandle(GetCurrentProcess(), t, client_proc, &dup_t, TOKEN_QUERY | TOKEN_IMPERSONATE, FALSE, DUPLICATE_SAME_ACCESS) == FALSE ) {
		error("failed to duplicate user token");
		goto done;
	}

done:
	if (client_proc)
		CloseHandle(client_proc);
	return dup_t;
}

int process_pubkeyauth_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) {
	int r = -1;
	char *key_blob, *user, *sig, *blob;
	size_t key_blob_len, user_len, sig_len, blob_len;
	struct sshkey *key = NULL;
	HANDLE token = NULL, dup_token = NULL;
	wchar_t *user_utf16 = NULL;
	PWSTR wuser_home = NULL;
	

	user = NULL;
	if (sshbuf_get_string_direct(request, &key_blob, &key_blob_len) != 0 ||
	    sshbuf_get_cstring(request, &user, &user_len) != 0 ||
	    user_len > MAX_USER_LEN ||
	    sshbuf_get_string_direct(request, &sig, &sig_len) != 0 ||
	    sshbuf_get_string_direct(request, &blob, &blob_len) != 0 ||
	    sshkey_from_blob(key_blob, key_blob_len, &key) != 0) {
		debug("invalid pubkey auth request");
		goto done;
	}

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

	
	if (pubkey_allowed(key, user) != 1) {
		debug("unable to verify public key for user %ls (profile:%ls)", user_utf16, wuser_home);
		goto done;
	}

	if (key_verify(key, sig, (u_int)sig_len, blob, (u_int)blob_len) != 1) {
		debug("signature verification failed");
		goto done;
	}

	if ((dup_token = duplicate_token_for_client(con, token)) == NULL)
		goto done;

	if (sshbuf_put_u32(response, (int)(intptr_t)dup_token) != 0)
		goto done;

	r = 0;
done:
	/* TODO Fix this hacky protocol*/
	if ((r == -1) && (sshbuf_put_u8(response, SSH_AGENT_FAILURE) == 0))
		r = 0;

	if (user)
		free(user);
	if (user_utf16)
		free(user_utf16);
	if (key)
		sshkey_free(key);
	if (wuser_home)
		CoTaskMemFree(wuser_home);
	if (token)
		CloseHandle(token);
	return r;
}

int process_loadprofile_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) {
	int r = 0, success = 0;
	char *user;
	size_t user_len;
	u_int32_t user_token_int = 0;
	HANDLE user_token = NULL;
	wchar_t *user_utf16 = NULL, *dom_utf16 = NULL, *tmp;

	/* is profile already loaded */
	if (con->profile_handle) {
		success = 1;
		goto done;
	}
	
	if (sshbuf_get_cstring(request, &user, &user_len) != 0 ||
	    user_len > MAX_USER_LEN ||
	    sshbuf_get_u32(request, &user_token_int) != 0){
		debug("invalid loadprofile request");
		goto done;
	}
	
	if (DuplicateHandle(con->client_process_handle, (HANDLE)(INT_PTR)user_token_int, GetCurrentProcess(),
		&user_token, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, FALSE, 0) == FALSE) {
		debug("cannot duplicate user token, error: %d", GetLastError());
		goto done;
	}
	
	if ((user_utf16 = utf8_to_utf16(user)) == NULL) {
		debug("out of memory");
		goto done;
	}

	/* split user and domain */
	if ((tmp = wcschr(user_utf16, L'@')) != NULL) {
		dom_utf16 = tmp + 1;
		*tmp = L'\0';
	}

	if ((con->profile_handle = LoadProfile(user_token, user_utf16, dom_utf16)) == NULL)
		goto done;
	
	con->profile_token = user_token;
	user_token = NULL;
	success = 1;
done:
	if (sshbuf_put_u8(response, success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE) != 0)
		r = -1;

	if (user_token)
		CloseHandle(user_token);
	return r;
}

int process_privagent_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) {
	char *opn;
	size_t opn_len;
	if (sshbuf_get_string_direct(request, &opn, &opn_len) != 0) {
		debug("invalid auth request");
		return -1;
	}

	/* allow only admins and NT Service\sshd to send auth requests */
	if (con->client_type != SSHD_SERVICE && con->client_type != ADMIN_USER) {
		error("cannot process request: client process is not admin or sshd");
		return -1;
	}
		
	if (memcmp(opn, PUBKEY_AUTH_REQUEST, opn_len) == 0)
		return process_pubkeyauth_request(request, response, con);
	else if (memcmp(opn, LOAD_USER_PROFILE_REQUEST, opn_len) == 0)
		return process_loadprofile_request(request, response, con);
	else {
		debug("unknown auth request: %s", opn);
		return -1;
	}
}

#pragma warning(pop)