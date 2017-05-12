/*
* Author: Yanbing Wang <yawang@microsoft.com>
*
* Copyright (c) 2009, 2011 NoMachine
* All rights reserved
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
#include <Ntsecapi.h>
#include <lm.h>
#include <stdio.h> 

#include "inc\pwd.h"
#include "sshfileperm.h"
#include "misc_internal.h"
#include "debug.h"

#define SSHD_ACCOUNT L"NT Service\\sshd"

/*
* The function is to check if user prepresented by pw is secure to access to the file. 
* Check the owner of the file is one of these types: Local Administrators groups, system account,
* direct user accounts in local administrators, or user represented by pw
* Check the users have access permission to the file don't voilate the following rules:	
	1. no user other than local administrators group, system account, user represented by pw,
	   and owner accounts have write permission on the file
	2. sshd account can only have read permission
	3. user represented by pw and file owner should at least have read permission.
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
		debug3("failed to retrieve the sid of the pwd");
		ret = -1;
		goto cleanup;
	}
	if ((name_utf16 = utf8_to_utf16(name)) == NULL) {
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
		!EqualSid(owner_sid, user_sid) &&
		!is_admin_account(owner_sid)) {
		debug3("Bad owner on %s", name);
		ret = -1;
		goto cleanup;
	}
	/*
	iterate all aces of the file to find out if there is voilation of the following rules:
		1. no others than administrators group, system account, and current user, owner accounts have write permission on the file
		2. sshd account can only have read permission
		3. this user and file owner should at least have read permission 
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
		// Determine the location of the trustee's sid and the value of the access mask
		switch (current_aceHeader->AceType) {
		case ACCESS_ALLOWED_ACE_TYPE: {
			PACCESS_ALLOWED_ACE pAllowedAce = (PACCESS_ALLOWED_ACE)current_ace;
			current_trustee_sid = &(pAllowedAce->SidStart);
			current_access_mask = pAllowedAce->Mask;
			break;
		}
		case ACCESS_DENIED_ACE_TYPE: {
			PACCESS_DENIED_ACE pDeniedAce = (PACCESS_DENIED_ACE)current_ace;
			current_trustee_sid = &(pDeniedAce->SidStart);			
			if((pDeniedAce->Mask & (FILE_GENERIC_READ & ~(SYNCHRONIZE | READ_CONTROL))) != 0) {
				if (EqualSid(current_trustee_sid, owner_sid)){
					debug3("Bad permission on %s. The owner of the file should at least have read permission.", name);
					ret = -1;
					goto cleanup;
				}
				else if (EqualSid(current_trustee_sid, user_sid)) {
					debug3("Bad permission on %s. The user should at least have read permission.", name);
					ret = -1;
					goto cleanup;
				}
			}
			continue;
		}
		default: {
			// Not interested ACE
			continue;
		}
		}
		
		/*no need to check administrators group, owner account, user account and system account*/
		if (IsWellKnownSid(current_trustee_sid, WinBuiltinAdministratorsSid) ||
			IsWellKnownSid(current_trustee_sid, WinLocalSystemSid) ||
			EqualSid(current_trustee_sid, owner_sid) ||
			EqualSid(current_trustee_sid, user_sid) ||
			is_admin_account(current_trustee_sid)) {
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
		FreeSid(user_sid);
	if(name_utf16)
		free(name_utf16);
	return ret;
}

static BOOL
is_sshd_account(PSID user_sid) {	
	wchar_t user_name[UNCLEN], full_name[UNCLEN + DNLEN + 2];
	DWORD name_length = UNCLEN, domain_name_length = 0, full_name_len = UNCLEN + DNLEN + 2;
	SID_NAME_USE sid_type = SidTypeInvalid;
	BOOL ret = FALSE;

	if (LookupAccountSidLocalW(user_sid, user_name, &name_length, full_name, &full_name_len, &sid_type) == FALSE)
	{
		debug3("LookupAccountSidLocalW() failed with error: %d. ", GetLastError());
		errno = ENOENT;
		return FALSE;
	}
	domain_name_length = wcslen(full_name);
	full_name[domain_name_length] = L'\\';
	wmemcpy(full_name + domain_name_length + 1, user_name, wcslen(user_name)+1);
	return (wcsicmp(full_name, SSHD_ACCOUNT) == 0);
}

/*
 * Check if the user is in local administrators group 
 * currently only check if the user is directly in the group
 * Returns TRUE if the user is in administrators group; otherwise false; 
*/
static BOOL
is_admin_account(PSID user_sid)
{
	DWORD entries_read = 0, total_entries = 0, i = 0, name_length = UNCLEN, domain_name_length = DNLEN, sid_size;
	LPLOCALGROUP_MEMBERS_INFO_1 local_groups_member_info = NULL;
	char admins_sid[SECURITY_MAX_SID_SIZE];
	wchar_t admins_group_name[UNCLEN], domain_name[DNLEN];
	SID_NAME_USE sid_type = SidTypeInvalid;
	NET_API_STATUS status;
	BOOL ret = FALSE;

	if (CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admins_sid, &sid_size) == FALSE) {
		debug3("CreateWellKnownSid failed with error code: %d.", GetLastError());
		goto done;
	}

	if (LookupAccountSidLocalW(admins_sid, admins_group_name, &name_length,
		domain_name, &domain_name_length, &sid_type) == FALSE) {
		debug3("LookupAccountSidLocalW() failed with error: %d. ", GetLastError());
		errno = ENOENT;
		goto done;
	}

	status = NetLocalGroupGetMembers(NULL, admins_group_name, 1, (LPBYTE*)&local_groups_member_info,
		MAX_PREFERRED_LENGTH, &entries_read, &total_entries, NULL);
	if (status != NERR_Success) {
		debug3("NetLocalGroupGetMembers failed with error code: %d.", status);
		goto done;
	}

	for (i = 0; i < entries_read; i++) {
		if (local_groups_member_info[i].lgrmi1_sidusage == SidTypeDeletedAccount)
			continue;
		else if (EqualSid(local_groups_member_info[i].lgrmi1_sid, user_sid)) {
			ret = TRUE;
			break;
		}
	}

done:
	if (local_groups_member_info)
		NetApiBufferFree(local_groups_member_info);
	return ret;
}

/*
* Set the owner of the secure file to the user represented by pw and only grant
* it the full control access
*/
int
set_secure_file_permission(const char *name, struct passwd * pw)
{
	PSECURITY_DESCRIPTOR pSD = NULL;
	PSID owner_sid = NULL;
	PACL dacl = NULL;
	wchar_t *name_utf16 = NULL, *sid_utf16 = NULL, sddl[256];
	DWORD error_code = ERROR_SUCCESS;
	struct passwd * pwd = pw;
	BOOL present, defaulted;
	int ret = 0;

	if (pwd == NULL)
		if ((pwd = getpwuid(0)) == NULL)
			fatal("getpwuid failed.");

	if (ConvertStringSidToSid(pwd->pw_sid, &owner_sid) == FALSE) {
		debug3("failed to retrieve the sid of the pwd with error code: %d", GetLastError());
		ret = -1;
		goto cleanup;
	}
	
	if((IsValidSid(owner_sid) == FALSE)) {
		debug3("IsValidSid(owner_sid): FALSE");
		ret = -1;
		goto cleanup;		
	}	

	if ((sid_utf16 = utf8_to_utf16(pwd->pw_sid)) == NULL) {
		debug3("Failed to get utf16 of the sid string");
		errno = ENOMEM;
		ret = -1;
		goto cleanup;
	}
	swprintf(sddl, sizeof(sddl) - 1, L"D:P(A;;FA;;;%s)", sid_utf16);
	if(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION, &pSD, NULL) == FALSE) {
		debug3("ConvertStringSecurityDescriptorToSecurityDescriptorW failed with error code %d", GetLastError());
		ret = -1;
		goto cleanup;
	}

	if (IsValidSecurityDescriptor(pSD) == FALSE) {
		debug3("IsValidSecurityDescriptor return FALSE");
		ret = -1;
		goto cleanup;
	}

	if (GetSecurityDescriptorDacl(pSD, &present, &dacl, &defaulted) == FALSE) {
		debug3("GetSecurityDescriptorDacl failed with error code %d", GetLastError());
		ret = -1;
		goto cleanup;
	}
	if (!present || dacl == NULL) {
		debug3("failed to find the acl from security descriptior.");
		ret = -1;
		goto cleanup;
	}	

	if ((name_utf16 = utf8_to_utf16(name)) == NULL) {
		debug3("Failed to get utf16 of the name");
		errno = ENOMEM;
		ret = -1;
		goto cleanup;
	}

	/*Set the owner sid and acl of the file.*/
	if ((error_code = SetNamedSecurityInfoW(name_utf16, SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
		owner_sid, NULL, dacl, NULL)) != ERROR_SUCCESS) {
		debug3("failed to set the owner sid and dacl of file %s with error code: %d", name, error_code);
		errno = EOTHER;
		ret = -1;
		goto cleanup;
	}
cleanup:
	if (pSD)
		LocalFree(pSD);
	if (name_utf16)
		free(name_utf16);
	if(sid_utf16)
		free(sid_utf16);
	if (owner_sid)
		FreeSid(owner_sid);	
	
	return ret;
}
