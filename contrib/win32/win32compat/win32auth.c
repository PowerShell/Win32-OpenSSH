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

#include "win32auth.h"

/*
 * Retrieve Security ID (SID) from username.
 *
 * psid   - output SID (OUT)
 * user   - username string (IN)
 *
 * RETURNS: 0 if OK.
 */

static int GetSidW(PSID *psid, const wchar_t *user)
{
  wchar_t *refDomain = NULL;

  DWORD refDomainSize = 0;

  DWORD sidSize = 0;

  SID_NAME_USE peUse;
    
  int exitCode = 1;

  /*
   * Retrieve SID's size
   */

  LookupAccountNameW(NULL, user, NULL, &sidSize, NULL, &refDomainSize, &peUse);

  FAIL(GetLastError() != ERROR_INSUFFICIENT_BUFFER);

  /*
   * Allocate buffer and retrieve SID
   */
  
  *psid = (PSID) LocalAlloc(LPTR, sidSize);

  refDomain = (wchar_t *) LocalAlloc(LPTR, refDomainSize * sizeof(wchar_t));

  FAIL(LookupAccountNameW(NULL, user, *psid, &sidSize, 
                             refDomain, &refDomainSize, &peUse) == FALSE);
  
  exitCode = 0;
  
fail:
  
  /*
   * We don't need reference domain.
   */
  
  if (refDomain)
  {
    LocalFree(refDomain);
  }
  
  if (exitCode != 0)
  {
    debug("ERROR. Cannot retrieve SID (%u).", GetLastError());
  }
  
  return exitCode;
}


/*
 * Enable or disable privilege for current running process
 *
 * privName - privilege name (IN)
 * enabled  - 1 for enabling, 0 for disabling (IN)
 *
 * RETURNS: 0 if OK.
 */

int EnablePrivilege(const char *privName, int enabled)
{
  TOKEN_PRIVILEGES tp;
  
  HANDLE hProcToken = NULL;
  
  LUID luid;

  int exitCode = 1;

  /*
   * Retrievie LUID from privilege name
   */
  
  FAIL(LookupPrivilegeValue(NULL, privName, &luid) == FALSE);
  
  /*
   * Retrievie token for current running process
   */

  FAIL(OpenProcessToken(GetCurrentProcess(), 
                            TOKEN_ADJUST_PRIVILEGES, &hProcToken) == FALSE);

  /*
   * Adjust privilege to current running process
   */
  
  tp.PrivilegeCount           = 1;
  tp.Privileges[0].Luid       = luid;
  tp.Privileges[0].Attributes = enabled ? SE_PRIVILEGE_ENABLED : 0;

  FAIL(AdjustTokenPrivileges(hProcToken, FALSE, &tp, 
                                 sizeof(TOKEN_PRIVILEGES), NULL, NULL) == FALSE);

  exitCode = 0;
  
fail:

  /*
   * Free allocated memory if needed.
   */
  
  if (hProcToken)
  {
    CloseHandle(hProcToken);
  }  

  if (exitCode)
  {
    DWORD err = GetLastError();
    
    debug("ERROR. Cannot enable privilege to current process (%u).", err);
  }
  
  return exitCode;
}

/*
 * This functions allocate and initialize some 'well known' SIDs.
 * This SIDs are global uniqualy, i.e. they are the same on all
 * machines.
 */

static PSID LocalSID()
{
  PSID psid = NULL;

  SID_IDENTIFIER_AUTHORITY nt = SECURITY_LOCAL_SID_AUTHORITY;
  
  AllocateAndInitializeSid(&nt, 1, 0, 0, 0, 0, 0, 0, 0, 0, &psid);
  
  return psid;
}

static PSID EveryoneSID()
{
  PSID psid = NULL;
  
  SID_IDENTIFIER_AUTHORITY nt = SECURITY_WORLD_SID_AUTHORITY;

  AllocateAndInitializeSid(&nt, 1, 0, 0, 0, 0, 0, 0, 0, 0, &psid);
  
  return psid;
}

static PSID AuthenticatedUsersSID()
{
  PSID psid = NULL;

  SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
  
  AllocateAndInitializeSid(&nt, 1, SECURITY_AUTHENTICATED_USER_RID, 
                               0, 0, 0, 0, 0, 0, 0, &psid);
  
  return psid;
}

static PSID InteractiveSID()
{
  PSID psid = NULL;
  
  SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
  
  AllocateAndInitializeSid(&nt, 1, SECURITY_INTERACTIVE_RID,
                               0, 0, 0, 0, 0, 0, 0, &psid);
  
  return psid;
}

/*
 * Allocate new TOKEN_PRIVILEGES structure and fill it with privileges
 * from given user account.
 *
 * pPrivToken - new, allocated structure (OUT)
 * userSid    - SID of user (IN)
 *
 * RETURNS: 0 if OK.
 */

int SetupTokenPrivileges(PTOKEN_PRIVILEGES *pPrivToken, PSID userSid)
{
  DWORD ntStat = 0;
  
  int exitCode = 1;
  
  LSA_OBJECT_ATTRIBUTES lsaOA = {0};

  PLSA_UNICODE_STRING userRights = NULL;
  
  ULONG nRights = 0;
  
  DWORD size;
  
  int i, j;
  
  /*
   * Open local policy.
   */

  LSA_HANDLE hPolicy;
  
  lsaOA.Length = sizeof(lsaOA);
  
  ACCESS_MASK mask = POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES;
  
  debug("Opening local policy...");
  
  ntStat = LsaOpenPolicy(NULL, &lsaOA, mask, &hPolicy);
  
  FAIL(ntStat);
  
  /*
   * Retrieve user's privileges.
   */
  
  debug("Retrieving user's privileges list...");
  
  ntStat = LsaEnumerateAccountRights(hPolicy, userSid, &userRights, &nRights);

  /*
   * This error code means there is no any rights.
   * In this case, we should create empty list.
   */
  
  if (ntStat == STATUS_OBJECT_NAME_NOT_FOUND)
  {
    nRights = 0;
    ntStat  = 0;
  }
  
  FAIL(ntStat);
  
  /*
   * FIXME. Now if some privilege name is not recognized by
   * LookupPrivilegeName() part of pPrivToken buffer will be
   * unused.
   */
   
  /*
   * Allocate buffer for TOKEN_PRIVILEGES.
   */
  
  debug("Allocating buffer for TOKEN_PRIVILEGES [%u]...", nRights);
  
  size = sizeof(DWORD) + nRights * sizeof(LUID_AND_ATTRIBUTES);
  
  (*pPrivToken) = LocalAlloc(LPTR, size);
  
  FAIL(pPrivToken == NULL);
  
  /*
   * Fill TOKEN_PRIVILEGES with LUIDs of retrieved privileges.
   */
  
  j = 0;
  
  for (i = 0; i < nRights; i++)
  {
    /*
     * Retrieve unicode name of privilege.
     * Make sure there is a zero word at the end.
     */
    
    wchar_t privName[128];
    
    int len = userRights[i].Length;
    
    memcpy(privName, userRights[i].Buffer, len * sizeof(wchar_t));
    
    privName[len] = 0;
    
    debug("Adding %ls... ", privName);

    /*
     * Retrieve LUID for given privilege name.
     */
    
    if(LookupPrivilegeValueW(NULL, privName,
                                   &(*pPrivToken) -> Privileges[i].Luid) == FALSE)
    {
      debug("WARNING. Cannot add privilege to token (%u).", GetLastError());
    }
    else
    {
      (*pPrivToken) -> Privileges[j].Attributes = SE_PRIVILEGE_ENABLED;

      j++;
    }  
  }
  
  /*
   * j = number of privileges, which were recognized by
   * LookupPrivilegesValue().
   */
  
  (*pPrivToken) -> PrivilegeCount = j;
  
  exitCode = 0;

fail:

  /*
   * Clenup.
   */
  
  if (userRights)
  {
    LsaFreeMemory(userRights);
  }
  
  if (hPolicy)
  {
    CloseHandle(hPolicy);
  }  
  
  if (exitCode)
  {
    debug("ERROR. Cannot setup TOKEN_PRIVILEGES (err=%u, ntStat=%x).",
              GetLastError(), ntStat);
  }
}


/*
 * Allocate new TOKEN_GROUPS structure and fill it with groups, which
 * given user belong to.
 *
 * pGroupsToken - new, allocated TOKEN_GROUPS structure (OUT)
 * userNameW    - wide string with username (IN)
 *
 * RETURNS: 0 if OK.
 */

int SetupTokenGroups(PTOKEN_GROUPS *groupsToken, wchar_t *userNameW)
{
  wchar_t **localGroups  = NULL;
  wchar_t **globalGroups = NULL;
  
  DWORD nLocalGroups     = 0;
  DWORD nLocalGroupsTot  = 0;
  
  DWORD nGlobalGroups    = 0;
  DWORD nGlobalGroupsTot = 0;
  
  DWORD nGroupsTotal     = 0;
  
  DWORD size;
  
  int i;
  
  int exitCode = 1;

  /*
   * Retrieve local groups, which user belong to.
   */
  
  debug("Retrieving local groups list...");
  
  FAIL(NetUserGetLocalGroups(NULL, userNameW, 0, 
                                LG_INCLUDE_INDIRECT, 
                                    (LPBYTE *) &localGroups,
                                         MAX_PREFERRED_LENGTH,
                                             &nLocalGroups, 
                                                 &nLocalGroupsTot));

  debug("Retrieving global groups list...");
  
  /*
   * Retrieve global groups, which user belong to.
   */

  FAIL(NetUserGetGroups(NULL, userNameW, 0, (LPBYTE *) 
                            &globalGroups, MAX_PREFERRED_LENGTH, 
                                &nGlobalGroups, &nGlobalGroupsTot));
  

  /*
   * Allocate buffer for TOKEN_GROUPS struct.
   *
   * We assume user belong to Everyone, AuthenticatedUsers, Local, Interactive
   * and groups retrievied from NetUserGetLocalGroups() and NetUserGetGroups()
   * for given user.
   */
  
  nGroupsTotal = nLocalGroups + nGlobalGroups + 4;

  size = (nGroupsTotal + 1) * sizeof(SID_AND_ATTRIBUTES) + sizeof(DWORD);
  
  *groupsToken = (TOKEN_GROUPS *) LocalAlloc(LPTR, size);
  
  (*groupsToken) -> GroupCount = nGroupsTotal;

  /*
   * Write SIDs of local groups into TOKEN_GROUPS struct.
   */
  
  #define INSIDE_GROUP_FLAG SE_GROUP_ENABLED\
                            | SE_GROUP_ENABLED_BY_DEFAULT\
                            | SE_GROUP_MANDATORY

  int delta = 4;

  for (i = 0; i < nLocalGroups; i++)
  {
    FAIL(GetSidW(&(*groupsToken) -> Groups[i + delta].Sid, localGroups[i]));

    (*groupsToken) -> Groups[i + delta].Attributes = INSIDE_GROUP_FLAG;
  }
  
  /*
   * Write SIDs of global groups into TOKEN_GROUPS struct.
   */

  delta = 4 + nLocalGroups;

  for (i = 0; i < nGlobalGroups; i++)
  {
    FAIL(GetSidW(&(*groupsToken) -> Groups[delta + i].Sid, globalGroups[i]));

    (*groupsToken) -> Groups[delta + i].Attributes = INSIDE_GROUP_FLAG;
  }
  
  /*
   * Write SIDs of Everyone, AuthenticatedUsers, Local and Interactive
   * groups into TOKEN_GROUPS struct.
   */
  
  (*groupsToken) -> Groups[0].Sid = EveryoneSID();
  (*groupsToken) -> Groups[0].Attributes = INSIDE_GROUP_FLAG;
  
  (*groupsToken) -> Groups[1].Sid = AuthenticatedUsersSID();
  (*groupsToken) -> Groups[1].Attributes = INSIDE_GROUP_FLAG;
  
  (*groupsToken) -> Groups[2].Sid = LocalSID();
  (*groupsToken) -> Groups[2].Attributes = INSIDE_GROUP_FLAG;
  
  (*groupsToken) -> Groups[3].Sid = InteractiveSID();
  (*groupsToken) -> Groups[3].Attributes = INSIDE_GROUP_FLAG;

  exitCode = 0;

fail:

  /*
   * Clean up.
   */
  
  NetApiBufferFree(localGroups);
  NetApiBufferFree(globalGroups);

  if (exitCode)
  {
    debug("ERROR. Failed to setup TOKEN_GROUPS (%u).", GetLastError());
  }
  
  return exitCode;
}

#ifdef USE_NTCREATETOKEN

/*
 * Creates new user's access token using NtCreateToken() function.
 *
 * userName   - user name string (IN)
 * domainName - domain name (IN) (UNUSED)
 * sourceName - ?? (IN)
 *
 * RETURNS: Handle to created token or INVALID_HANDLE_VALUE if fails.
 */

HANDLE CreateUserToken(const char *userName, 
                           const char *domainName, const char *sourceName)
{
  debug2("-> CreateUserToken()...");
  
  HMODULE hNtDll = NULL;
  
  NtCreateTokenPtr NtCreateToken = NULL;
  
  HANDLE token = INVALID_HANDLE_VALUE;
  
  /*
   * These are compounds of user's access token structure.
   * The goal is setup these strutures and combine them
   * into one access token using NtCreateToken() WINAPI function.
   */
  
  LUID authId = SYSTEM_LUID;
  
  TOKEN_USER userToken;

  PTOKEN_GROUPS groupsToken = NULL;
  
  PTOKEN_PRIVILEGES pPrivToken = NULL;
  
  TOKEN_OWNER ownerToken;
  
  TOKEN_PRIMARY_GROUP primaryGroupToken;

  TOKEN_SOURCE sourceToken;  
  
  PTOKEN_DEFAULT_DACL pDaclToken = NULL;
  
  LARGE_INTEGER expirationTime = {0xFFFFFFFF, 0x7FFFFFFF};
  
  OBJECT_ATTRIBUTES oa;
  
  /*
   * Temporary variables
   */
  
  SECURITY_QUALITY_OF_SERVICE sqos = 
  {
    sizeof(sqos), 
    SecurityAnonymous, 
    SECURITY_STATIC_TRACKING,
    FALSE
  };
    
  int i;
  
  size_t size = 0;
  
  wchar_t *userNameW = NULL;
  
  DWORD cbSize;
  
  HANDLE hProcToken = NULL;
  
  /*
   * Variables to handle error codes.
   */
  
  int exitCode = 1;
  int ntStat   = 0;
  
  /*
   * Make wide char version of user's name.
   */
  
  size = (strlen(userName) + 1) * sizeof(wchar_t);
  
  userNameW = (wchar_t *) LocalAlloc(LPTR, size);;

  swprintf(userNameW, L"%hs", userName);
  
  /*
   * Give needed privilege to current running process
   */
  
  debug("Enabling privilege to current running process...");

  EnablePrivilege("SeTcbPrivilege", 1);
  EnablePrivilege("SeChangeNotifyPrivilege", 1);
  EnablePrivilege("SeIncreaseQuotaPrivilege", 1);
  EnablePrivilege("SeAssignPrimaryTokenPrivilege", 1);
  EnablePrivilege("SeCreateTokenPrivilege", 1);
  
  /*
   * Create TOKEN_USER part
   */
      
  debug("Setting up TOKEN_USER...");
  
  FAIL(GetSidW(&userToken.User.Sid, userNameW));

  userToken.User.Attributes = 0;
  
  /*
   * Create TOKEN_OWNER part. We assume Owner = User.
   */
  
  debug("Setting up TOKEN_OWNER...");
  
  FAIL(GetSidW(&ownerToken.Owner, userNameW));
  
  /*
   * Create TOKEN_SOURCE part
   */
  
  debug("Setting up TOKEN_SOURCE...");
  
  FAIL(AllocateLocallyUniqueId(&sourceToken.SourceIdentifier) == FALSE);
  
  size = min(strlen(sourceName), 8);
      
  memcpy(sourceToken.SourceName, "********", 8);
  memcpy(sourceToken.SourceName, sourceName, size);

  /*
   * Create TOKEN_GROUPS part
   */
  
  debug("Setting up TOKEN_GROUPS...");
  
  FAIL(SetupTokenGroups(&groupsToken, userNameW));
  
  /*
   * Create TOKEN_PRIVILEGES part
   */
  
  debug("Setting up TOKEN_PRIVILEGES...");
  
  FAIL(SetupTokenPrivileges(&pPrivToken, userToken.User.Sid));
  
  /*
   * Create TOKEN_PRIMARY_GROUP part
   */
  
  debug("Setting up TOKEN_PRIMARY GROUP...");
  
  primaryGroupToken.PrimaryGroup = EveryoneSID();
  
  /*
   * Setup object attributes
   */
  
  memset(&oa, 0, sizeof(oa));

  oa.Length = sizeof(oa);
  
  oa.SecurityQualityOfService = &sqos;

  /*
   * Setup TOKEN_DEFAULT_DACL part.
   */
  
  debug("Setting up TOKEN_DEFAULT_DACL...");
  
  debug("Opening current process's token...");

  FAIL(OpenProcessToken(GetCurrentProcess(),
                            TOKEN_QUERY | TOKEN_QUERY_SOURCE, 
                                &hProcToken) == FALSE);

  debug("Retrieving TOKEN_DEFAULT_DACL...");

  GetTokenInformation(hProcToken, TokenDefaultDacl, NULL, 0, &cbSize);
  
  pDaclToken = LocalAlloc(LPTR, cbSize);

  FAIL(GetTokenInformation(hProcToken, TokenDefaultDacl,
                               pDaclToken, cbSize, &cbSize) == FALSE);

  /*
   * Print debug info about parts
   */
  
  //PrintPartsInfo(&token, TOKEN_ALL_ACCESS, &oa, 
  //                            TokenPrimary, &authId, &expirationTime,
  //                                &userToken, groupsToken, pPrivToken,
  //                                    &ownerToken, &primaryGroupToken, 
  //                                        pDaclToken, &sourceToken);

  /*
   * Retrieve address of NtCreateToken() function.
   */

  debug("Retrieving NtCreateToken() address...");
  
  hNtDll = GetModuleHandle("ntdll.dll");
  
  FAIL(hNtDll == NULL);

  NtCreateToken = (NtCreateTokenPtr) GetProcAddress(hNtDll, "NtCreateToken");

  FAIL(NtCreateToken == NULL);

  /*
   * Create new user acces token from parts setted up above.
   */

  debug("Creating token from parts...");
  
  ntStat = NtCreateToken(&token, TOKEN_ALL_ACCESS, &oa,
                              TokenPrimary, &authId, &expirationTime,
                                  &userToken, groupsToken, pPrivToken,
                                      &ownerToken, &primaryGroupToken,
                                          pDaclToken, &sourceToken);                         
  FAIL(ntStat);

  /*
   * Add rights to use 'default' desktop and WinStation0.
   */

  if (AddRightsToDesktopBySid(userToken.User.Sid))
  {
    debug("WARNING. Cannot add rights to 'winsta0\\default'!");
  }

  exitCode = 0;
  
fail:

  /*
   * Free allocated memory
   */
  
  debug2("Freeing groupsToken...");
  
  if (groupsToken)
  {
    /*
     * We don't need to test were SIDs allocated correctly,
     * becouse FreeSid() do it.
     */
    
    for (i = 0; i < groupsToken -> GroupCount; i++)
    {
      FreeSid(groupsToken -> Groups[i].Sid);
    }

    LocalFree(groupsToken);
  }
  
  debug2("Freeing local buffers...");
  
  LocalFree(userNameW);
  LocalFree(pDaclToken);
  LocalFree(pPrivToken);
  
  debug2("Freeing SIDs...");
  
  FreeSid(userToken.User.Sid);
  FreeSid(ownerToken.Owner);
  FreeSid(primaryGroupToken.PrimaryGroup);
  
  debug2("Closing hProcToken...");
  
  CloseHandle(hProcToken);

  debug2("Closing hNtDll...");
  
  CloseHandle(hNtDll);
  
  /*
   * Something was wrong.
   */
  
  if (exitCode)
  {
    debug("ERROR. Cannot create user's acces token. (err = %u, ntStat = %x)",
              GetLastError(), ntStat);
  }

  debug2("<- CreateUserToken()...");
  
  return token;
}

#endif
