/*
 * Author: NoMachine <developers@nomachine.com>
 * Copyright (c) 2009, 2013 NoMachine
 * All rights reserved
 *
 * Author: Manoj Ampalam <manojamp@microsoft.com>
 * Simplified code to just perform local user logon
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
 * DATA, OR PROFITS; OR BUSINESS intERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define WINVER 0x501

#define UMDF_USING_NTSTATUS 
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <Ntsecapi.h>
#include <NTSecPkg.h>
#include <ntstatus.h>
#include <stdio.h>
#include "..\misc_internal.h"

#define Unsigned  unsigned
#define Char char
#define Int int
#define Long long
#define Not(value) ((value) == 0)
#define PKG_NAME "SSH-LSA"
#define PKG_NAME_SIZE sizeof(PKG_NAME)
#define MAX_ACCOUNT_NAME_SIZE (256 * 2)
#define VERSION "4.0.346"


typedef VOID(WINAPI *RtlInitUnicodeStringPtr)
(PUNICODE_STRING, PCWSTR SourceString);
#define FAIL(CONDITION) if(CONDITION) goto fail

#define NTFAIL(NTFUNC) if((ntStat = (NTFUNC))) goto fail

RtlInitUnicodeStringPtr RtlInitUnicodeString = NULL;
HMODULE NtDll = NULL;
LSA_SECPKG_FUNCTION_TABLE LsaApi;

NTSTATUS LsaAllocUnicodeString(PUNICODE_STRING *lsaStr, USHORT maxLen)
{
	NTSTATUS ntStat = STATUS_NO_MEMORY;
	FAIL(lsaStr == NULL);
	*lsaStr = (PUNICODE_STRING)LsaApi.AllocateLsaHeap(sizeof(UNICODE_STRING));
	FAIL((*lsaStr) == NULL);
	(*lsaStr)->Buffer = (WCHAR *)LsaApi.AllocateLsaHeap(sizeof(maxLen));
	(*lsaStr)->Length = 0;
	(*lsaStr)->MaximumLength = maxLen;
	FAIL((*lsaStr)->Buffer == NULL);

	ntStat = 0;
fail:

	if (ntStat) {
		if (lsaStr && (*lsaStr)) {
			LsaApi.FreeLsaHeap((*lsaStr)->Buffer);
			LsaApi.FreeLsaHeap((*lsaStr));
		}
	}

	return ntStat;
}

void LsaFreeUnicodeString(PUNICODE_STRING lsaStr)
{
	if (lsaStr) {
		if (lsaStr->Buffer)
			LsaApi.FreeLsaHeap(lsaStr->Buffer);
		LsaApi.FreeLsaHeap(lsaStr);
	}
}

NTSTATUS FillUnicodeString(UNICODE_STRING *lsaStr, const Char *str)
{
	NTSTATUS ntStat = STATUS_NO_MEMORY;
        size_t cbSize = 0;
        FAIL(lsaStr == NULL);
	FAIL(lsaStr->Buffer == NULL);
	FAIL(str == NULL);
	cbSize = strlen(str);
	FAIL(cbSize >= lsaStr->MaximumLength);
	_swprintf(lsaStr->Buffer, L"%hs", str);
        lsaStr->Length = (USHORT)(cbSize * 2);
        lsaStr->Buffer[cbSize * 2] = 0x0000;
	ntStat = STATUS_SUCCESS;

fail:
	return ntStat;
}


NTSTATUS NTAPI LsaApCallPackagePassthrough(PLSA_CLIENT_REQUEST request,
	PVOID submitBuf,
	PVOID clientBufBase,
	ULONG submitBufSize,
	PVOID *outBuf,
	PULONG outBufSize,
	PNTSTATUS status) {
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI LsaApCallPackageUntrusted(PLSA_CLIENT_REQUEST request,
	PVOID submitBuf,
	PVOID clientBufBase,
	ULONG submitBufSize,
	PVOID *outBuf,
	PULONG outBufSize,
	PNTSTATUS status) {
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI LsaApCallPackage(PLSA_CLIENT_REQUEST request, PVOID submitBuf,
	PVOID clientBufBase, ULONG submitBufSize,
	PVOID *outBuf, PULONG outBufSize,
	PNTSTATUS status) {
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI LsaApInitializePackage(ULONG pkgId,
	PLSA_SECPKG_FUNCTION_TABLE func,
	PLSA_STRING database,
	PLSA_STRING confident,
	PLSA_STRING *pkgName)
{
	memcpy(&LsaApi, func, sizeof(LsaApi));

	*pkgName = (PLSA_STRING)LsaApi.AllocateLsaHeap(sizeof(LSA_STRING));
	(*pkgName)->Buffer = (PCHAR)LsaApi.AllocateLsaHeap(PKG_NAME_SIZE);

	/* fill buffer with package name */
	memcpy((*pkgName)->Buffer, PKG_NAME, PKG_NAME_SIZE);
	(*pkgName)->Length = PKG_NAME_SIZE - 1;
	(*pkgName)->MaximumLength = PKG_NAME_SIZE;

	return STATUS_SUCCESS;
}

int LsaCopySid(PSID *dst, PSID src)
{
	int exitCode = 1;
	DWORD size = 0;

	FAIL(IsValidSid(src) == FALSE);
	size = GetLengthSid(src);
	*dst = LsaApi.AllocateLsaHeap(size);
	memcpy(*dst, src, size);
	exitCode = 0;
fail:
	return exitCode;
}

int LsaAllocTokenInfo(PLSA_TOKEN_INFORMATION_V1 *info, HANDLE token)
{

	int exitCode = 1;
	DWORD cbSize = 0;
	DWORD i = 0;

	PTOKEN_USER pUserToken = NULL;
	PTOKEN_GROUPS pGroupsToken = NULL;
	PTOKEN_OWNER pOwnerToken = NULL;
	PTOKEN_PRIMARY_GROUP pPrimaryGroupToken = NULL;
	PLSA_TOKEN_INFORMATION_V1 tokenInfo;

	*info = (PLSA_TOKEN_INFORMATION_V1)
		LsaApi.AllocateLsaHeap(sizeof(LSA_TOKEN_INFORMATION_V1));

	FAIL(*info == NULL);
	tokenInfo = *info;
	GetTokenInformation(token, TokenUser, NULL, 0, &cbSize);
	pUserToken = (PTOKEN_USER)LocalAlloc(LPTR, cbSize);
	FAIL(GetTokenInformation(token, TokenUser,
		pUserToken, cbSize, &cbSize) == FALSE);
	tokenInfo->User.User.Attributes = pUserToken->User.Attributes;
	FAIL(LsaCopySid(&tokenInfo->User.User.Sid, pUserToken->User.Sid));

	GetTokenInformation(token, TokenGroups, NULL, 0, &cbSize);
	pGroupsToken = (PTOKEN_GROUPS)LocalAlloc(LPTR, cbSize);
	FAIL(GetTokenInformation(token, TokenGroups,
		pGroupsToken, cbSize, &cbSize) == FALSE);
	cbSize = pGroupsToken->GroupCount * sizeof(SID_AND_ATTRIBUTES) + sizeof(DWORD);
	tokenInfo->Groups = (PTOKEN_GROUPS)LsaApi.AllocateLsaHeap(cbSize);
	tokenInfo->Groups->GroupCount = pGroupsToken->GroupCount;

	for (i = 0; i < pGroupsToken->GroupCount; i++)
	{
		FAIL(LsaCopySid(&tokenInfo->Groups->Groups[i].Sid,
			pGroupsToken->Groups[i].Sid));

		tokenInfo->Groups->Groups[i].Attributes = pGroupsToken->Groups[i].Attributes;
	}

	GetTokenInformation(token, TokenPrivileges, NULL, 0, &cbSize);
	tokenInfo->Privileges = (PTOKEN_PRIVILEGES)LsaApi.AllocateLsaHeap(cbSize);
	FAIL(GetTokenInformation(token, TokenPrivileges,
		tokenInfo->Privileges, cbSize, &cbSize) == FALSE);
	GetTokenInformation(token, TokenOwner, NULL, 0, &cbSize);
	pOwnerToken = (PTOKEN_OWNER)LocalAlloc(LPTR, cbSize);
	FAIL(GetTokenInformation(token, TokenOwner,
		pOwnerToken, cbSize, &cbSize) == FALSE);
	FAIL(LsaCopySid(&tokenInfo->Owner.Owner, pOwnerToken->Owner));

	GetTokenInformation(token, TokenPrimaryGroup, NULL, 0, &cbSize);
	pPrimaryGroupToken = (PTOKEN_PRIMARY_GROUP)LocalAlloc(LPTR, cbSize);
	FAIL(GetTokenInformation(token, TokenPrimaryGroup,
		pPrimaryGroupToken, cbSize, &cbSize) == FALSE);
	FAIL(LsaCopySid(&tokenInfo->PrimaryGroup.PrimaryGroup,
		pPrimaryGroupToken->PrimaryGroup));

	tokenInfo->DefaultDacl.DefaultDacl = NULL;
	tokenInfo->ExpirationTime.HighPart = 0x7fffffff;
	tokenInfo->ExpirationTime.LowPart = 0xffffffff;
	exitCode = 0;

fail:
	LsaApi.FreeLsaHeap(pUserToken);
	LsaApi.FreeLsaHeap(pGroupsToken);
	LsaApi.FreeLsaHeap(pOwnerToken);
	LsaApi.FreeLsaHeap(pPrimaryGroupToken);

	return exitCode;
}


NTSTATUS NTAPI
LsaApLogonUser(PLSA_CLIENT_REQUEST request, SECURITY_LOGON_TYPE logonType,
	PVOID authData, PVOID clientAuthData, ULONG authDataSize,
	PVOID *profile, PULONG profileSize, PLUID logonId,
	PNTSTATUS subStat,
	PLSA_TOKEN_INFORMATION_TYPE tokenInfoType,
	PVOID *tokenInfo,
	PLSA_UNICODE_STRING *accountName,
	PLSA_UNICODE_STRING *authority)
{

	NTSTATUS ntStat = STATUS_LOGON_FAILURE;
	int exitCode = 1;
	wchar_t *inUserName = NULL;
	WCHAR samUserBuf[MAX_ACCOUNT_NAME_SIZE + 1];
	SECURITY_STRING samUser;
	UNICODE_STRING *flatName = NULL;
	UCHAR *userAuth = NULL;
	ULONG userAuthSize;
	wchar_t homeDir[PATH_MAX];
	TOKEN_SOURCE tokenSource;

	HANDLE token = NULL;
	HANDLE clientToken = NULL;
	SECPKG_CLIENT_INFO clientInfo;
	inUserName = (wchar_t *)authData;

	NTFAIL(LsaApi.GetClientInfo(&clientInfo));
	FAIL(Not(clientInfo.HasTcbPrivilege));
	NTFAIL(LsaAllocUnicodeString(authority, MAX_ACCOUNT_NAME_SIZE));
	NTFAIL(LsaAllocUnicodeString(accountName, MAX_ACCOUNT_NAME_SIZE));
	NTFAIL(LsaAllocUnicodeString(&flatName, MAX_ACCOUNT_NAME_SIZE));

	lstrcpyW(samUserBuf, inUserName);
	samUserBuf[MAX_ACCOUNT_NAME_SIZE] = 0x00;
	RtlInitUnicodeString((PUNICODE_STRING)&samUser, samUserBuf);
	NTFAIL(LsaApi.GetAuthDataForUser(&samUser, SecNameFlat, NULL,
		&userAuth, &userAuthSize, flatName));

	memcpy(tokenSource.SourceName, "_sshlsa_", 8);
	AllocateLocallyUniqueId(&tokenSource.SourceIdentifier);
	NTFAIL(LsaApi.ConvertAuthDataToToken(userAuth, userAuthSize,
		SecurityDelegation,
		&tokenSource, Network,
		*authority, &token, logonId,
		*accountName, subStat));

	NTFAIL(LsaApi.AllocateClientBuffer(request, PATH_MAX * sizeof(wchar_t), profile));
	*profileSize = PATH_MAX;
	NTFAIL(LsaApi.CopyToClientBuffer(request, PATH_MAX * sizeof(wchar_t),
		*profile, homeDir));

	PLSA_TOKEN_INFORMATION_V1 outTokenInfo;
	FAIL(LsaAllocTokenInfo(&outTokenInfo, token));
	*tokenInfoType = LsaTokenInformationV1;
	*tokenInfo = outTokenInfo;

	NTFAIL(LsaApi.DuplicateHandle(token, &clientToken));
	ntStat = STATUS_SUCCESS;
	exitCode = 0;

fail:
	if (exitCode)
	{
		ntStat = STATUS_LOGON_FAILURE;
		CloseHandle(clientToken);
		LsaApi.DeleteLogonSession(logonId);
		*profileSize = 0;
	}

	CloseHandle(token);
	LsaFreeUnicodeString(flatName);
	return ntStat;
}


VOID NTAPI LsaApLogonTerminated(PLUID logonId)
{
}

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpRes)
{
	BOOL exitCode = FALSE;

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		NtDll = GetModuleHandle("ntdll.dll");

		FAIL(NtDll == NULL);
		RtlInitUnicodeString = (RtlInitUnicodeStringPtr)
			GetProcAddress(NtDll, "RtlInitUnicodeString");
		FAIL(RtlInitUnicodeString == NULL);
		break;
	}

	case DLL_PROCESS_DETACH:
		FreeModule(NtDll);
	}

	exitCode = TRUE;

fail:

	if (exitCode == FALSE)
		FreeModule(NtDll);

	return exitCode;
}
