/*
 * Author: NoMachine <developers@nomachine.com>
 *
 * Copyright (c) 2009, 2013 NoMachine
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

#define WINVER 0x501

#include "Ssh-lsa.h"

#ifdef __cplusplus
extern "C" {
#endif

	//
	// Handle to 'ntdll.dll' module and address of 'RtlInitUnicodeString()'
	// function.
	//

	RtlInitUnicodeStringPtr RtlInitUnicodeString = NULL;

	HMODULE NtDll = NULL;

	//
	// This is table with addresses of LSA API functions.
	// We retrieve this table from system at package initialization
	// moment.
	//

	LSA_SECPKG_FUNCTION_TABLE LsaApi;

	//
	// Called once to initialize package at system startup.
	//
	// pkgId     - our package's ID given by LSA (IN)
	// func      - table with adresses of LSA functions (IN)
	// database  - uunsed / reserved (IN)
	// confident - unused / reserved (IN)
	// pkgName   - name of our package (OUT)
	//
	// RETURNS: STATUSS_SUCCESS if OK.
	//         

	NTSTATUS NTAPI LsaApInitializePackage(ULONG pkgId,
		PLSA_SECPKG_FUNCTION_TABLE func,
		PLSA_STRING database,
		PLSA_STRING confident,
		PLSA_STRING *pkgName)
	{

		//
		// Save table with adresses of LSA API functions.
		//

		memcpy(&LsaApi, func, sizeof(LsaApi));

		//
		// Allocate buffer for package name.
		//


		*pkgName = (PLSA_STRING)LsaApi.AllocateLsaHeap(sizeof(LSA_STRING));

		(*pkgName)->Buffer = (PCHAR)LsaApi.AllocateLsaHeap(PKG_NAME_SIZE);

		//
		// Fill buffer with our name.
		//


		memcpy((*pkgName)->Buffer, PKG_NAME, PKG_NAME_SIZE);

		(*pkgName)->Length = PKG_NAME_SIZE - 1;

		(*pkgName)->MaximumLength = PKG_NAME_SIZE;


		return STATUS_SUCCESS;
	}

	//
	// Allocate new buffer in LSA address space and copy input SID to it.
	//
	// dst - pointer that retrieves new allocated copy of input SID (OUT)
	// src - input SID to copy (IN)
	//
	// RETURNS: 0 if OK.
	//

	Int LsaCopySid(PSID &dst, PSID src)
	{
		Int exitCode = 1;

		DWORD size = 0;

		FAIL(IsValidSid(src) == FALSE);

		size = GetLengthSid(src);

		dst = LsaApi.AllocateLsaHeap(size);

		memcpy(dst, src, size);

		exitCode = 0;

	fail:

		if (exitCode)
		{
		}

		return exitCode;
	}

	//
	// Allocate LSA_TOKEN_INFORMATION_V1 structure in LSA address space
	// and fill it with data from given token.
	//
	// tokenInfo - new allocated struct with info from given token (OUT)
	// token     - handle to token (IN)
	//
	// RETURNS: 0 if OK.
	//

	Int LsaAllocTokenInfo(PLSA_TOKEN_INFORMATION_V1 &tokenInfo, HANDLE token)
	{

		Int exitCode = 1;

		DWORD cbSize = 0;

		DWORD i = 0;

		//
		// Temporary buffers for infos retrieved from input token.
		//

		PTOKEN_USER pUserToken = NULL;
		PTOKEN_GROUPS pGroupsToken = NULL;
		PTOKEN_OWNER pOwnerToken = NULL;

		PTOKEN_PRIMARY_GROUP pPrimaryGroupToken = NULL;

		//
		// Allocate LSA_TOKEN_INFORMATION_V1 struct for output,
		//


		tokenInfo = (PLSA_TOKEN_INFORMATION_V1)
			LsaApi.AllocateLsaHeap(sizeof(LSA_TOKEN_INFORMATION_V1));

		FAIL(tokenInfo == NULL);

		//
		// Copy TOKEN_USER part from input token.
		// We can't retrieve all token infos directly to output buffer,
		// becouse SIDs must be allocated as separately memory blocks.
		//


		GetTokenInformation(token, TokenUser, NULL, 0, &cbSize);

		pUserToken = (PTOKEN_USER)LocalAlloc(LPTR, cbSize);

		FAIL(GetTokenInformation(token, TokenUser,
			pUserToken, cbSize, &cbSize) == FALSE);

		tokenInfo->User.User.Attributes = pUserToken->User.Attributes;

		FAIL(LsaCopySid(tokenInfo->User.User.Sid, pUserToken->User.Sid));

		//
		// Copy TOKEN_GROUPS part from input token.
		//


		GetTokenInformation(token, TokenGroups, NULL, 0, &cbSize);

		pGroupsToken = (PTOKEN_GROUPS)LocalAlloc(LPTR, cbSize);

		FAIL(GetTokenInformation(token, TokenGroups,
			pGroupsToken, cbSize, &cbSize) == FALSE);


		cbSize = pGroupsToken->GroupCount * sizeof(SID_AND_ATTRIBUTES) + sizeof(DWORD);

		tokenInfo->Groups = (PTOKEN_GROUPS)LsaApi.AllocateLsaHeap(cbSize);

		tokenInfo->Groups->GroupCount = pGroupsToken->GroupCount;


		for (i = 0; i < pGroupsToken->GroupCount; i++)
		{
			FAIL(LsaCopySid(tokenInfo->Groups->Groups[i].Sid,
				pGroupsToken->Groups[i].Sid));

			tokenInfo->Groups->Groups[i].Attributes = pGroupsToken->Groups[i].Attributes;
		}

		//
		// Retrieve TOKEN_PRIVILEGES part from input token. There are no SID's
		// in this struct, so we can retrieve it directly to output buffer.
		//


		GetTokenInformation(token, TokenPrivileges, NULL, 0, &cbSize);

		tokenInfo->Privileges = (PTOKEN_PRIVILEGES)LsaApi.AllocateLsaHeap(cbSize);

		FAIL(GetTokenInformation(token, TokenPrivileges,
			tokenInfo->Privileges, cbSize, &cbSize) == FALSE);

		//
		// Copy TOKEN_OWNER part from input token.
		//


		GetTokenInformation(token, TokenOwner, NULL, 0, &cbSize);

		pOwnerToken = (PTOKEN_OWNER)LocalAlloc(LPTR, cbSize);

		FAIL(GetTokenInformation(token, TokenOwner,
			pOwnerToken, cbSize, &cbSize) == FALSE);

		FAIL(LsaCopySid(tokenInfo->Owner.Owner, pOwnerToken->Owner));

		//
		// Copy TOKEN_PRIMARY_GROUP part from input token.
		//  


		GetTokenInformation(token, TokenPrimaryGroup, NULL, 0, &cbSize);

		pPrimaryGroupToken = (PTOKEN_PRIMARY_GROUP)LocalAlloc(LPTR, cbSize);

		FAIL(GetTokenInformation(token, TokenPrimaryGroup,
			pPrimaryGroupToken, cbSize, &cbSize) == FALSE);

		FAIL(LsaCopySid(tokenInfo->PrimaryGroup.PrimaryGroup,
			pPrimaryGroupToken->PrimaryGroup));

		//
		// Copy TOKEN_DEFAULT_DACL part from input token.
		//


		//GetTokenInformation(token, TokenDefaultDacl, NULL, 0, &cbSize);

		//pDaclToken = (PTOKEN_DEFAULT_DACL) LocalAlloc(LPTR, cbSize);

		//FAIL(GetTokenInformation(token, TokenDefaultDacl, 
		//                             pDaclToken, cbSize, &cbSize) == FALSE);

		tokenInfo->DefaultDacl.DefaultDacl = NULL;

		//
		// Fill expiration time. Our token never expires.
		//

		tokenInfo->ExpirationTime.HighPart = 0x7fffffff;
		tokenInfo->ExpirationTime.LowPart = 0xffffffff;

		exitCode = 0;

	fail:

		//
		// Clean up.
		//       

		LsaApi.FreeLsaHeap(pUserToken);
		LsaApi.FreeLsaHeap(pGroupsToken);
		LsaApi.FreeLsaHeap(pOwnerToken);
		LsaApi.FreeLsaHeap(pPrimaryGroupToken);

		if (exitCode)
		{
		}


		return exitCode;
	}


	//
	// Called, when client logon process want logon user.
	//
	// request        - internal LSA struct for allocating client buffer (IN)
	// logonType      - what type of logon client need (e.g. Interactive) (IN)
	// authData       - buffer with authorization data (we use SshLsaAuth) (IN)
	// authDataClient - adress of original authData in client address space (IN)
	// authDataSize   - size of authData buffer in bytes (IN)
	// profile        - profile data (we decide what to return) (OUT)
	// profileSize    - number of bytes returnet in profile (OUT)
	// subStat        - additional NTSTATUS code used when logon failure (OUT)
	// tokenInfoType  - what structure we returned to LSA in tokenInfo (OUT)
	// tokenInfo      - structure with token's parts for LSA (OUT)
	// accountName    - on which account we try to logon (OUT)
	// authority      - ?? We use it as domain name and fill with NULL (OUT)
	//

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

		Int exitCode = 1;

		//
		// Function should retrieve authorization data as SshLsaAuth struct.
		//

		wchar_t *inUserName = NULL;

		//
		// Buffers used for retrieving user auth data from SAM database.
		//

		WCHAR samUserBuf[MAX_ACCOUNT_NAME_SIZE + 1];

		SECURITY_STRING samUser;

		UNICODE_STRING *flatName = NULL;

		UCHAR *userAuth = NULL;

		ULONG userAuthSize;

		wchar_t homeDir[MAX_PATH];

		//
		// Buffers used for creating new token from SAM data.
		// We use this token as pattern for token info, which we send to LSA
		// on output args.
		//

		TOKEN_SOURCE tokenSource;

		HANDLE token = NULL;
		HANDLE clientToken = NULL;

		//
		// Info about client process. We use it to detect has client got
		// SeTcbPrivilege.
		//

		SECPKG_CLIENT_INFO clientInfo;

		//
		// Check are input args ok?
		//


		inUserName = (wchar_t *)authData;




		//
		// Get info about client process.
		//


		NTFAIL(LsaApi.GetClientInfo(&clientInfo));


		//
		// Fail if client has not got SeTcbPrivilege.
		//

		FAIL(Not(clientInfo.HasTcbPrivilege));

		//
		// Allocate buffers.
		//


		NTFAIL(LsaAllocUnicodeString(authority, MAX_ACCOUNT_NAME_SIZE));
		NTFAIL(LsaAllocUnicodeString(accountName, MAX_ACCOUNT_NAME_SIZE));
		NTFAIL(LsaAllocUnicodeString(&flatName, MAX_ACCOUNT_NAME_SIZE));

		//
		// Retrieve user data from SAM base.
		//


		lstrcpyW(samUserBuf, inUserName);

		samUserBuf[MAX_ACCOUNT_NAME_SIZE] = 0x00;

		RtlInitUnicodeString((PUNICODE_STRING)&samUser, samUserBuf);

		NTFAIL(LsaApi.GetAuthDataForUser(&samUser, SecNameFlat, NULL,
			&userAuth, &userAuthSize, flatName));


		//
		// Create token basing on SAM data.
		//


		memcpy(tokenSource.SourceName, "_sshlsa_", 8);

		AllocateLocallyUniqueId(&tokenSource.SourceIdentifier);

		NTFAIL(LsaApi.ConvertAuthDataToToken(userAuth, userAuthSize,
			SecurityDelegation,
			&tokenSource, Network,
			*authority, &token, logonId,
			*accountName, subStat));

		//
		// Print token info.
		//


		//
		// Allocate client buffer and copy home dir to it.
		//


		NTFAIL(LsaApi.AllocateClientBuffer(request, MAX_PATH * sizeof(wchar_t), profile));

		*profileSize = MAX_PATH;


		NTFAIL(LsaApi.CopyToClientBuffer(request, MAX_PATH * sizeof(wchar_t),
			*profile, homeDir));

		//
		// Fill token info for LSA, using token created from SAM database
		// as input pattern. We create LSA_TOKEN_INFORMATION_V1 struct
		// here.
		//


		PLSA_TOKEN_INFORMATION_V1 outTokenInfo;

		FAIL(LsaAllocTokenInfo(outTokenInfo, token));

		*tokenInfoType = LsaTokenInformationV1;

		*tokenInfo = outTokenInfo;

		//
		// Duplicate token from lsa space to client space.
		//


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
		else
		{
		}

		//
		// Cleanup temporary buffers.
		//

		CloseHandle(token);


		LsaFreeUnicodeString(flatName);


		return ntStat;
	}


	//
	// This functions is called, after session closed. This is only 
	// information for package and we don't need to do anything here.
	//

	VOID NTAPI LsaApLogonTerminated(PLUID logonId)
	{
	}


	//
	// DllMain function (called when DLL is loaded or unloaded)
	//

	BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpRes)
	{
		BOOL exitCode = FALSE;

		switch (dwReason)
		{

			//
			// init package dll.
			//

		case DLL_PROCESS_ATTACH:
		{
			//
			// Initialize log.
			// 



			//
			// Load 'ntdll.dll' module.
			//


			NtDll = GetModuleHandle("ntdll.dll");

			FAIL(NtDll == NULL);

			//
			// Load RtlInitUnicodeString() function from 'ntdll.dll'.
			//


			RtlInitUnicodeString = (RtlInitUnicodeStringPtr)
				GetProcAddress(NtDll, "RtlInitUnicodeString");

			FAIL(RtlInitUnicodeString == NULL);

			break;
		}

		//
		// uninit package dll.
		//

		case DLL_PROCESS_DETACH:
		{

			FreeModule(NtDll);
		}
		}

		exitCode = TRUE;

	fail:

		if (exitCode == FALSE)
		{

			FreeModule(NtDll);
		}

		return exitCode;
	}

	//
	// For compatibility only.
	//

	NTSTATUS NTAPI LsaApCallPackagePassthrough(PLSA_CLIENT_REQUEST request,
		PVOID submitBuf,
		PVOID clientBufBase,
		ULONG submitBufSize,
		PVOID *outBuf,
		PULONG outBufSize,
		PNTSTATUS status)
	{

		return STATUS_NOT_IMPLEMENTED;
	}

	//
	// For compatibility only.
	//

	NTSTATUS NTAPI LsaApCallPackageUntrusted(PLSA_CLIENT_REQUEST request,
		PVOID submitBuf,
		PVOID clientBufBase,
		ULONG submitBufSize,
		PVOID *outBuf,
		PULONG outBufSize,
		PNTSTATUS status)
	{

		return STATUS_NOT_IMPLEMENTED;
	}

	//
	// For compatibility only.
	//

	NTSTATUS NTAPI LsaApCallPackage(PLSA_CLIENT_REQUEST request, PVOID submitBuf,
		PVOID clientBufBase, ULONG submitBufSize,
		PVOID *outBuf, PULONG outBufSize,
		PNTSTATUS status)
	{

		return STATUS_NOT_IMPLEMENTED;
	}

#ifdef __cplusplus
}
#endif
