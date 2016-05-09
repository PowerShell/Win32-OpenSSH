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

#include <Windows.h>
#include <Ntsecapi.h>
//#include <ntstatus.h>
#include "agent.h"
#include "agent-request.h"


int process_authagent_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) {
	while (1)
	{
		HANDLE lsa_handle;
		PLSA_OPERATIONAL_MODE mode;
		ULONG auth_package_id;
		NTSTATUS ret;
		KERB_S4U_LOGON *s4u_logon;
		size_t logon_info_size;
		LSA_STRING logon_process_name, auth_package_name, originName;
		InitLsaString(&logon_process_name, "ssh-agent");
		//InitLsaString(&auth_package_name, MICROSOFT_KERBEROS_NAME_A);
		InitLsaString(&auth_package_name, "Negotiate");
		InitLsaString(&originName, "sshd");
		if (ret = LsaRegisterLogonProcess(&logon_process_name, &lsa_handle, &mode) != STATUS_SUCCESS)
			break;

		if (ret = LsaLookupAuthenticationPackage(lsa_handle, &auth_package_name, &auth_package_id) != STATUS_SUCCESS)
			break;
#define USER_NAME L"user@domain"
		logon_info_size = sizeof(KERB_S4U_LOGON);
		logon_info_size += (wcslen(USER_NAME) * 2 + 2);
		s4u_logon = malloc(logon_info_size);
		s4u_logon->MessageType = KerbS4ULogon;
		s4u_logon->Flags = 0;
		s4u_logon->ClientUpn.Length = wcslen(USER_NAME) * 2;
		s4u_logon->ClientUpn.MaximumLength = s4u_logon->ClientUpn.Length;
		s4u_logon->ClientUpn.Buffer = (WCHAR*)(s4u_logon + 1);
		memcpy(s4u_logon->ClientUpn.Buffer, USER_NAME, s4u_logon->ClientUpn.Length + 2);
		s4u_logon->ClientRealm.Length = 0;
		s4u_logon->ClientRealm.MaximumLength = 0;
		s4u_logon->ClientRealm.Buffer = 0;

		TOKEN_SOURCE sourceContext;
		RtlCopyMemory(
			sourceContext.SourceName,
			".Jobs   ",
			sizeof(sourceContext.SourceName)
			);

		if (AllocateLocallyUniqueId(&sourceContext.SourceIdentifier) != TRUE)
			break;

		PKERB_INTERACTIVE_PROFILE pProfile = NULL;
		LUID            logonId;
		QUOTA_LIMITS    quotas;
		NTSTATUS        subStatus;
		DWORD           cbProfile;
		HANDLE          hToken = INVALID_HANDLE_VALUE;
		if (ret = LsaLogonUser(lsa_handle, &originName, Network, auth_package_id, s4u_logon, logon_info_size, NULL, &sourceContext,
			(PVOID*)&pProfile,
			&cbProfile,
			&logonId,
			&hToken,
			&quotas,
			&subStatus) != STATUS_SUCCESS)
			break;

		CloseHandle(hToken);
		LsaDeregisterLogonProcess(lsa_handle);
		break;
	}
	return -1;
}