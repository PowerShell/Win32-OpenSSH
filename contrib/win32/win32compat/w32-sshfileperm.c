/*
* Author: Yanbing Wang <yawang@microsoft.com>
*
* Support file permission check on Win32 based operating systems.
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
#include <Sddl.h>
#include <Aclapi.h>
#include <lm.h>
#include <stdio.h> 

#include "inc\pwd.h"
#include "sshfileperm.h"
#include "debug.h"

#define SSHD_ACCOUNT L"NT Service\\sshd"

/*
* The function is to check if current user is secure to access to the file. 
* Check the owner of the file is one of these types: Local Administrators groups, system account, current user account
* Check the users have access permission to the file don't voilate the following rules:	
	1. no user other than local administrators group, system account, and pwd user have write permission on the file
	2. sshd account can only have read permission	
* Returns 0 on success and -1 on failure
*/
int
check_secure_file_permission(const char *name, struct passwd * pw)
{	
	PSECURITY_DESCRIPTOR pSD = NULL;
	wchar_t * name_utf16 = NULL;
	PSID owner_sid = NULL, user_sid = NULL;
	PACL dacl = NULL;
	DWORD error_code = ERROR_SUCCESS; 
	BOOL is_valid_sid = FALSE, is_valid_acl = FALSE;
	struct passwd * pwd = pw;
	char *bad_user = NULL;
	int ret = 0;

	if (pwd == NULL)
		if ((pwd = getpwuid(0)) == NULL) 
			fatal("getpwuid failed.");
	
	if (ConvertStringSidToSid(pwd->pw_sid, &user_sid) == FALSE ||
		(IsValidSid(user_sid) == FALSE)) {
		debug3("failed to retrieve sid of user %s", pwd->pw_name);
		ret = -1;
		goto cleanup;
	}
	if ((name_utf16 = utf8_to_utf16(name)) == NULL) {
		ret = -1;
		errno = ENOMEM;
		goto cleanup;
	}

	/*Get the owner sid of the file.*/
	if ((error_code = GetNamedSecurityInfoW(name_utf16, SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		&owner_sid, NULL, &dacl, NULL, &pSD)) != ERROR_SUCCESS) {
		debug3("failed to retrieve the owner sid and dacl of file %s with error code: %d", name, error_code);
		errno = EOTHER;
		ret = -1;
		goto cleanup;
	}
	if (((is_valid_sid = IsValidSid(owner_sid)) == FALSE) || ((is_valid_acl = IsValidAcl(dacl)) == FALSE)) {
		debug3("IsValidSid: %d; is_valid_acl: %d", is_valid_sid, is_valid_acl);		
		ret = -1;
		goto cleanup;
	}
	if (!IsWellKnownSid(owner_sid, WinBuiltinAdministratorsSid) &&
		!IsWellKnownSid(owner_sid, WinLocalSystemSid) &&
		!EqualSid(owner_sid, user_sid)) {
		debug3("Bad owner on %s", name);
		ret = -1;
		goto cleanup;
	}
	/*
	iterate all aces of the file to find out if there is voilation of the following rules:
		1. no others than administrators group, system account, and current user account have write permission on the file
		2. sshd account can only have read permission
	*/
	for (DWORD i = 0; i < dacl->AceCount; i++) {
		PVOID current_ace = NULL;
		PACE_HEADER current_aceHeader = NULL;
		PSID current_trustee_sid = NULL;
		ACCESS_MASK current_access_mask = 0;		

		if (!GetAce(dacl, i, &current_ace)) {
			debug3("GetAce() failed");
			errno = EOTHER;
			ret = -1;
			goto cleanup;
		}

		current_aceHeader = (PACE_HEADER)current_ace;
		/* only interested in Allow ACE */
		if(current_aceHeader->AceType != ACCESS_ALLOWED_ACE_TYPE)
			continue;
		
		PACCESS_ALLOWED_ACE pAllowedAce = (PACCESS_ALLOWED_ACE)current_ace;
		current_trustee_sid = &(pAllowedAce->SidStart);
		current_access_mask = pAllowedAce->Mask;	
		
		/*no need to check administrators group, pwd user account, and system account*/
		if (IsWellKnownSid(current_trustee_sid, WinBuiltinAdministratorsSid) ||
			IsWellKnownSid(current_trustee_sid, WinLocalSystemSid) ||
			EqualSid(current_trustee_sid, user_sid)) {
			continue;
		}
		else if(is_sshd_account(current_trustee_sid)){
			if ((current_access_mask & ~FILE_GENERIC_READ) != 0){
				debug3("Bad permission. %s can only read access to %s", SSHD_ACCOUNT, name);	
				ret = -1;			
				break;			
			}			
		}
		else {
			ret = -1;
			if (ConvertSidToStringSid(current_trustee_sid, &bad_user) == FALSE) {
				debug3("ConvertSidToSidString failed with %d. ", GetLastError());
				break;
			}
			debug3("Bad permissions. Try removing permissions for user: %s on file %s.", bad_user, name);
			break;
		}
	}	
cleanup:
	if(bad_user)
		LocalFree(bad_user);
	if (pSD)
		LocalFree(pSD);
	if (user_sid)
		LocalFree(user_sid);
	if(name_utf16)
		free(name_utf16);
	return ret;
}

/*TODO: optimize to get sshd sid first and then call EqualSid*/
static BOOL
is_sshd_account(PSID user_sid) {	
	wchar_t user_name[UNCLEN] = { 0 }, full_name[UNCLEN + DNLEN + 2] = { 0 };
	DWORD name_length = UNCLEN, domain_name_length = 0, full_name_len = UNCLEN + DNLEN + 2;
	SID_NAME_USE sid_type = SidTypeInvalid;
	BOOL ret = FALSE;
	errno_t r = 0;
	
	if (LookupAccountSidLocalW(user_sid, user_name, &name_length, full_name, &full_name_len, &sid_type) == FALSE)
	{
		debug3("LookupAccountSidLocalW() failed with error: %d. ", GetLastError());
		errno = ENOENT;
		return FALSE;
	}	
	domain_name_length = wcsnlen(full_name, _countof(full_name));
	full_name[domain_name_length] = L'\\';
	if ((r = wmemcpy_s(full_name + domain_name_length + 1, _countof(full_name) - domain_name_length -1, user_name, wcsnlen_s(user_name, UNCLEN) + 1)) != 0) {
		debug3("wmemcpy_s failed with error: %d.", r);
		return FALSE;
	}
	return (wcsicmp(full_name, SSHD_ACCOUNT) == 0);
}
