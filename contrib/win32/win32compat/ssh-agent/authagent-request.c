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

static void 
InitLsaString(LSA_STRING *lsa_string, const char *str)
{
	if (str == NULL)
		memset(lsa_string, 0, sizeof(LSA_STRING));
	else {
		lsa_string->Buffer = (char *)str;
		lsa_string->Length = strlen(str);
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


void
LoadProfile(struct agent_connection* con, wchar_t* user, wchar_t* domain) {
	PROFILEINFOW profileInfo;
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
        if (LoadUserProfileW(con->auth_token, &profileInfo) == FALSE)
                debug("Loading user (%ls,%ls) profile failed ERROR: %d", user, domain, GetLastError());
        else
                con->hProfile = profileInfo.hProfile;
	EnablePrivilege("SeBackupPrivilege", 0);
	EnablePrivilege("SeRestorePrivilege", 0);
}

#define MAX_USER_LEN 256
static HANDLE 
generate_user_token(wchar_t* user) {
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
	wchar_t user_copy[MAX_USER_LEN];
	
	/* prep user name - TODO: implment an accurate check if user is domain account*/
	if (wcsnlen(user, MAX_USER_LEN) == MAX_USER_LEN) {
		debug("user length is not supported");
		goto done;
	}

	if (wcschr(user, L'\\') != NULL) {
		wchar_t *un = NULL, *dn = NULL;
		DWORD un_len = 0, dn_len = 0;
		dn = user;
		dn_len = wcschr(user, L'\\') - user;
		un = wcschr(user, L'\\') + 1;
		un_len = wcsnlen(user, MAX_USER_LEN) - dn_len - 1;
		if (dn_len == 0 || un_len == 0) {
			debug("cannot get user token - bad user name");
			goto done;
		}
		memcpy(user_copy, un, un_len * sizeof(wchar_t));
		user_copy[un_len] = L'@';
		memcpy(user_copy + un_len + 1, dn, dn_len * sizeof(wchar_t));
		user_copy[dn_len + 1 + un_len] = L'\0';
		user = user_copy;
	}
	
	domain_user = (wcschr(user, L'@') != NULL) ? TRUE : FALSE;

	InitLsaString(&logon_process_name, "ssh-agent");
	if (domain_user)
		InitLsaString(&auth_package_name, MICROSOFT_KERBEROS_NAME_A);
	else 
		InitLsaString(&auth_package_name, "SSH-LSA");

	InitLsaString(&originName, "sshd");
	if (ret = LsaRegisterLogonProcess(&logon_process_name, &lsa_handle, &mode) != STATUS_SUCCESS)
		goto done;

	if (ret = LsaLookupAuthenticationPackage(lsa_handle, &auth_package_name, &auth_package_id) != STATUS_SUCCESS)
		goto done;

	if (domain_user) {
		KERB_S4U_LOGON *s4u_logon;
		logon_info_size = sizeof(KERB_S4U_LOGON);
		logon_info_size += (wcslen(user) * 2 + 2);
		logon_info = malloc(logon_info_size);
		if (logon_info == NULL)
			goto done;
		s4u_logon = (KERB_S4U_LOGON*)logon_info;
		s4u_logon->MessageType = KerbS4ULogon;
		s4u_logon->Flags = 0;
		s4u_logon->ClientUpn.Length = wcslen(user) * 2;
		s4u_logon->ClientUpn.MaximumLength = s4u_logon->ClientUpn.Length;
		s4u_logon->ClientUpn.Buffer = (WCHAR*)(s4u_logon + 1);
		memcpy(s4u_logon->ClientUpn.Buffer, user, s4u_logon->ClientUpn.Length + 2);
		s4u_logon->ClientRealm.Length = 0;
		s4u_logon->ClientRealm.MaximumLength = 0;
		s4u_logon->ClientRealm.Buffer = 0;
	}
	else {
		logon_info_size = (wcslen(user) + 1)*sizeof(wchar_t);
		logon_info = malloc(logon_info_size);
		if (logon_info == NULL)
			goto done;
		memcpy(logon_info, user, logon_info_size);
	}

	memcpy(sourceContext.SourceName,"sshagent", sizeof(sourceContext.SourceName));

	if (AllocateLocallyUniqueId(&sourceContext.SourceIdentifier) != TRUE)
		goto done;

	if (ret = LsaLogonUser(lsa_handle,
	    &originName,
	    Network,
	    auth_package_id,
	    logon_info,
	    logon_info_size,
	    NULL,
	    &sourceContext,
	    (PVOID*)&pProfile,
	    &cbProfile,
	    &logonId,
	    &token,
	    &quotas,
	    &subStatus) != STATUS_SUCCESS) {
	    debug("LsaLogonUser failed %d", ret);
		goto done;
	}

done:
	if (lsa_handle)
		LsaDeregisterLogonProcess(lsa_handle);
	if (logon_info)
		free(logon_info);
	if (pProfile)
		LsaFreeReturnBuffer(pProfile);

	return token;
}

#define PUBKEY_AUTH_REQUEST "pubkey"
#define PASSWD_AUTH_REQUEST "password"
#define MAX_USER_NAME_LEN 256
#define MAX_PW_LEN 128

int process_passwordauth_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) {
        char *user = NULL, *pwd = NULL;
        wchar_t userW_buf[MAX_USER_NAME_LEN], pwdW_buf[MAX_PW_LEN];
	wchar_t *userW = userW_buf, *domW = NULL, *pwdW = pwdW_buf, *tmp;
	size_t user_len = 0, pwd_len = 0, dom_len = 0;
	int r = -1;
	HANDLE token = 0, dup_token, client_proc = 0;
	ULONG client_pid;

	if (sshbuf_get_cstring(request, &user, &user_len) != 0 ||
		sshbuf_get_cstring(request, &pwd, &pwd_len) != 0 ||
		user_len == 0 ||
		pwd_len == 0 ){
		debug("bad password auth request");
		goto done;
	}

	userW[0] = L'\0';
        if (MultiByteToWideChar(CP_UTF8, 0, user, user_len + 1, userW, MAX_USER_NAME_LEN) == 0 ||
                MultiByteToWideChar(CP_UTF8, 0, pwd, pwd_len + 1, pwdW, MAX_PW_LEN) == 0) {
                debug("unable to convert user (%s) or password to UTF-16", user);
                goto done;
        }
	
        if ((tmp = wcschr(userW, L'\\')) != NULL) {
		domW = userW;
		userW = tmp + 1;
		*tmp = L'\0';

	}
	else if ((tmp = wcschr(userW, L'@')) != NULL) {
		domW = tmp + 1;
		*tmp = L'\0';
	}

        if (LogonUserW(userW, domW, pwdW, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &token) == FALSE) {
                debug("failed to logon user");
                goto done;
        }
                
	if ((FALSE == GetNamedPipeClientProcessId(con->connection, &client_pid)) ||
	    ((client_proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, client_pid)) == NULL) ||
	    (FALSE == DuplicateHandle(GetCurrentProcess(), token, client_proc, &dup_token, TOKEN_QUERY | TOKEN_IMPERSONATE, FALSE, DUPLICATE_SAME_ACCESS)) ||
	    (sshbuf_put_u32(response, dup_token) != 0)) {
	        debug("failed to duplicate user token");
		goto done;
	}

        con->auth_token = token;
        LoadProfile(con, userW, domW);
	r = 0;
done:
	/* TODO Fix this hacky protocol*/
	if ((r == -1) && (sshbuf_put_u8(response, SSH_AGENT_FAILURE) == 0))
		r = 0;
	
	if (user)
		free(user);
	if (pwd)
		free(pwd);
	if (client_proc)
		CloseHandle(client_proc);

	return r;
}

int process_pubkeyauth_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) {
	int r = -1;
	char *key_blob, *user, *sig, *blob;
	size_t key_blob_len, user_len, sig_len, blob_len;
	struct sshkey *key = NULL;
	HANDLE token = NULL, dup_token = NULL, client_proc = NULL;
	wchar_t wuser[MAX_USER_NAME_LEN];
	PWSTR wuser_home = NULL;
	ULONG client_pid;

	user = NULL;
	if (sshbuf_get_string_direct(request, &key_blob, &key_blob_len) != 0 ||
	    sshbuf_get_cstring(request, &user, &user_len) != 0 ||
	    sshbuf_get_string_direct(request, &sig, &sig_len) != 0 ||
	    sshbuf_get_string_direct(request, &blob, &blob_len) != 0 ||
	    sshkey_from_blob(key_blob, key_blob_len, &key) != 0) {
		debug("invalid pubkey auth request");
		goto done;
	}

        wuser[0] = L'\0';
	if (MultiByteToWideChar(CP_UTF8, 0, user, user_len + 1, wuser, MAX_USER_NAME_LEN) == 0 ||
	    (token = generate_user_token(wuser)) == 0) {
		debug("unable to generate token for user %ls", wuser);
		goto done;
	}

        con->auth_token = token;

	if (SHGetKnownFolderPath(&FOLDERID_Profile, 0, token, &wuser_home) != S_OK ||
		pubkey_allowed(key, wuser, wuser_home) != 1) {
		debug("given public key is not mapped to user %ls (profile:%ls)", wuser, wuser_home);
		goto done;
	}

	if (key_verify(key, sig, sig_len, blob, blob_len) != 1) {
		debug("signature verification failed");
		goto done;
	}
	
	if ((FALSE == GetNamedPipeClientProcessId(con->connection, &client_pid)) ||
	    ( (client_proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, client_pid)) == NULL) ||
	    (FALSE == DuplicateHandle(GetCurrentProcess(), token, client_proc, &dup_token, TOKEN_QUERY | TOKEN_IMPERSONATE, FALSE, DUPLICATE_SAME_ACCESS)) ||
	    (sshbuf_put_u32(response, dup_token) != 0) ) {
		debug("failed to authorize user");
		goto done;
	}
	
        {
                wchar_t *tmp, *userW, *domW;
                userW = wuser;
                if ((tmp = wcschr(userW, L'\\')) != NULL) {
                        domW = userW;
                        userW = tmp + 1;
                        *tmp = L'\0';

                }
                else if ((tmp = wcschr(userW, L'@')) != NULL) {
                        domW = tmp + 1;
                        *tmp = L'\0';
                }
		LoadProfile(con, userW, domW);
	}

	r = 0;
done:
        /* TODO Fix this hacky protocol*/
        if ((r == -1) && (sshbuf_put_u8(response, SSH_AGENT_FAILURE) == 0))
                r = 0;

	if (user)
		free(user);
	if (key)
		sshkey_free(key);
	if (wuser_home)
		CoTaskMemFree(wuser_home);
	if (client_proc)
		CloseHandle(client_proc);
	return r;
}

int process_authagent_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) {
	char *opn;
	size_t opn_len;
	if (sshbuf_get_string_direct(request, &opn, &opn_len) != 0) {
		debug("invalid auth request");
		return -1;
	}

	if (opn_len == strlen(PUBKEY_AUTH_REQUEST) && memcmp(opn, PUBKEY_AUTH_REQUEST, opn_len) == 0)
		return process_pubkeyauth_request(request, response, con);
	else if (opn_len == strlen(PASSWD_AUTH_REQUEST) && memcmp(opn, PASSWD_AUTH_REQUEST, opn_len) == 0)
		return process_passwordauth_request(request, response, con);
	else {
		debug("unknown auth request: %s", opn);
		return -1;
	}
		
}