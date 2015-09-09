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

#include <winsock2.h>
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

#ifdef DYNAMIC_OPENSSL
  //
  // Handle to 'libcrypto.dll' and 'libssl.dll' modules.
  //

  HMODULE LibCrypto = NULL;
  HMODULE LibSSL    = NULL;

  //
  // This is global struct with dynamic loaded libssl and libcrypto
  // functions. 
  //

  SSLFuncList DynSSL;
#endif

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
  DBG_ENTRY("LsaApInitializePackage");

  //
  // Save table with adresses of LSA API functions.
  //
  
  memcpy(&LsaApi, func, sizeof(LsaApi));
  
  //
  // Allocate buffer for package name.
  //
  
  DBG_MSG("Allocating buffer for pkgName...\n");
  
  *pkgName = (PLSA_STRING) LsaApi.AllocateLsaHeap(sizeof(LSA_STRING));
  
  (*pkgName) -> Buffer = (PCHAR) LsaApi.AllocateLsaHeap(PKG_NAME_SIZE);

  //
  // Fill buffer with our name.
  //
  
  DBG_MSG("Setting up pkgName...\n");
  
  memcpy((*pkgName) -> Buffer, PKG_NAME, PKG_NAME_SIZE);
  
  (*pkgName) -> Length = PKG_NAME_SIZE - 1;
  
  (*pkgName) -> MaximumLength = PKG_NAME_SIZE;
 
  //
  // Initialize OpenSSL lib.
  //
  
  DBG_MSG("Initializing OpenSSL...\n");
  
  OPENSSL(SSL_library_init());
  
  DBG_MSG("Initializing OpenSSL digest table...\n");
  
  OPENSSL(OpenSSL_add_all_digests());

  
  DBG_LEAVE("LsaApInitializePackage");
  
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
    DBG_MSG("ERROR. Cannot to copy SID.\n");
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
  DBG_ENTRY("LsaAllocTokenInfo");
  
  Int exitCode = 1;

  DWORD cbSize = 0;
  
  DWORD i = 0;
  
  //
  // Temporary buffers for infos retrieved from input token.
  //
  
  PTOKEN_USER pUserToken     = NULL;
  PTOKEN_GROUPS pGroupsToken = NULL;
  PTOKEN_OWNER pOwnerToken   = NULL;
  
  PTOKEN_PRIMARY_GROUP pPrimaryGroupToken = NULL;
  
  //
  // Allocate LSA_TOKEN_INFORMATION_V1 struct for output,
  //
  
  DBG_MSG("Allocating LSA_TOKEN_INFORMATION_V1 buffer...\n");
  
  tokenInfo = (PLSA_TOKEN_INFORMATION_V1) 
                   LsaApi.AllocateLsaHeap(sizeof(LSA_TOKEN_INFORMATION_V1));
  
  FAIL(tokenInfo == NULL);

  //
  // Copy TOKEN_USER part from input token.
  // We can't retrieve all token infos directly to output buffer,
  // becouse SIDs must be allocated as separately memory blocks.
  //

  DBG_MSG("Copying TOKEN_USER...\n");

  GetTokenInformation(token, TokenUser, NULL, 0, &cbSize);
  
  pUserToken = (PTOKEN_USER) LocalAlloc(LPTR, cbSize);

  FAIL(GetTokenInformation(token, TokenUser, 
                               pUserToken, cbSize, &cbSize) == FALSE);
  
  tokenInfo -> User.User.Attributes = pUserToken -> User.Attributes;
  
  FAIL(LsaCopySid(tokenInfo -> User.User.Sid, pUserToken -> User.Sid));
  
  //
  // Copy TOKEN_GROUPS part from input token.
  //
  
  DBG_MSG("Copying TOKEN_GROUP...\n");

  GetTokenInformation(token, TokenGroups, NULL, 0, &cbSize);
  
  pGroupsToken = (PTOKEN_GROUPS) LocalAlloc(LPTR, cbSize);

  FAIL(GetTokenInformation(token, TokenGroups, 
                               pGroupsToken, cbSize, &cbSize) == FALSE);

                               
  cbSize = pGroupsToken -> GroupCount * sizeof(SID_AND_ATTRIBUTES) + sizeof(DWORD);

  tokenInfo -> Groups = (PTOKEN_GROUPS) LsaApi.AllocateLsaHeap(cbSize);
  
  tokenInfo -> Groups -> GroupCount = pGroupsToken -> GroupCount;


  for (i = 0; i < pGroupsToken -> GroupCount; i++)
  {
    FAIL(LsaCopySid(tokenInfo -> Groups -> Groups[i].Sid,
                        pGroupsToken -> Groups[i].Sid));
                        
    tokenInfo -> Groups -> Groups[i].Attributes = pGroupsToken -> Groups[i].Attributes;
  }
  
  //
  // Retrieve TOKEN_PRIVILEGES part from input token. There are no SID's
  // in this struct, so we can retrieve it directly to output buffer.
  //

  DBG_MSG("Retrieving TOKEN_PRIVILEGES directly...\n");
  
  GetTokenInformation(token, TokenPrivileges, NULL, 0, &cbSize);
  
  tokenInfo -> Privileges = (PTOKEN_PRIVILEGES) LsaApi.AllocateLsaHeap(cbSize);

  FAIL(GetTokenInformation(token, TokenPrivileges, 
                               tokenInfo -> Privileges, cbSize, &cbSize) == FALSE);
                               
  //
  // Copy TOKEN_OWNER part from input token.
  //

  DBG_MSG("Copying TOKEN_OWNER...\n");

  GetTokenInformation(token, TokenOwner, NULL, 0, &cbSize);
 
  pOwnerToken = (PTOKEN_OWNER) LocalAlloc(LPTR, cbSize);

  FAIL(GetTokenInformation(token, TokenOwner, 
                               pOwnerToken, cbSize, &cbSize) == FALSE);
  
  FAIL(LsaCopySid(tokenInfo -> Owner.Owner, pOwnerToken -> Owner));
                      
  //
  // Copy TOKEN_PRIMARY_GROUP part from input token.
  //  
  
  DBG_MSG("Copying TOKEN_PRIMARY_GROUP...\n");

  GetTokenInformation(token, TokenPrimaryGroup, NULL, 0, &cbSize);
  
  pPrimaryGroupToken = (PTOKEN_PRIMARY_GROUP) LocalAlloc(LPTR, cbSize);

  FAIL(GetTokenInformation(token, TokenPrimaryGroup, 
                               pPrimaryGroupToken, cbSize, &cbSize) == FALSE);
  
  FAIL(LsaCopySid(tokenInfo -> PrimaryGroup.PrimaryGroup,
                      pPrimaryGroupToken -> PrimaryGroup));  

  //
  // Copy TOKEN_DEFAULT_DACL part from input token.
  //
  
  DBG_MSG("Retrieving TOKEN_DEFAULT_DACL...\n");

  //GetTokenInformation(token, TokenDefaultDacl, NULL, 0, &cbSize);
  
  //pDaclToken = (PTOKEN_DEFAULT_DACL) LocalAlloc(LPTR, cbSize);

  //FAIL(GetTokenInformation(token, TokenDefaultDacl, 
  //                             pDaclToken, cbSize, &cbSize) == FALSE);
    
  tokenInfo -> DefaultDacl.DefaultDacl = NULL;
  
  //
  // Fill expiration time. Our token never expires.
  //
 
  tokenInfo -> ExpirationTime.HighPart = 0x7fffffff;
  tokenInfo -> ExpirationTime.LowPart  = 0xffffffff;
  
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
    DBG_MSG("ERROR. Cannot allocate token information.\n");
  }
  
  DBG_LEAVE("LsaAllocTokenInfo");
  
  return exitCode;
}  

//
// This function performs user authorization.
//
// homedir - user's home dir if authorized success (OUT)
// token   - handle to user access token (IN)
// auth    - SshLsaAuth struct with authorization data (IN)
// 
// RETURNS: 0 if OK.
//

Int AuthorizeUser(wchar_t homeDir[MAX_PATH], HANDLE token, SshLsaAuth *auth)
{
  DBG_ENTRY("AuthorizeUser");
  
  Int exitCode = 1;
  
  Int authorized = 0;
  
  PROFILEINFOW profile = {sizeof(PROFILEINFOW)};
  
  Key *key = NULL;

  wchar_t keyFileName[MAX_PATH];
  
  wchar_t *nextFile = NULL;
  
  //Char homeDir[MAX_PATH];

  DWORD homeDirSize = MAX_PATH;
  
  //
  // Compute adressess of SshLsaAuth fields. 
  //
  
  BYTE *userPtr = (BYTE *) &(auth -> buf_);
  BYTE *signPtr = (BYTE *) userPtr + auth -> userSize_;
  BYTE *dataPtr = (BYTE *) signPtr + auth -> signSize_;
  BYTE *blobPtr = (BYTE *) dataPtr + auth -> dataSize_;
  BYTE *authPtr = (BYTE *) blobPtr + auth -> pkBlobSize_;
                
  //
  // Create Key struct from pkBlob.
  //
  
  DBG_MSG("Reproduce Key struct from blob...n");
  
  FAIL(KeyFromBlob(key, blobPtr, auth -> pkBlobSize_));

  FAIL(key == NULL);
  
  //
  // Retrieve user's home directory.
  //
  
  DBG_MSG("Retrieving user's homedir...");
  
  profile.lpUserName = (wchar_t *) userPtr;
  
  FAIL(LoadUserProfileW(token, &profile) == FALSE);
  
  FAIL(GetUserProfileDirectoryW(token, homeDir, &homeDirSize) == FALSE);

  //
  // Try authorize using authkey files given by ssh.
  //
  
  nextFile = (wchar_t *) authPtr;
  
  for (Unsigned Int i = 0; Not(authorized) && i < auth -> authFilesCount_; i++)
  {
    wchar_t *fileToCheck = nextFile;
    
    DBG_MSG("Trying keys from [%ls]...\n", nextFile);
    
    //
    // Expand relative paths to user homedir like openssh do.
    //

    if (wcschr(nextFile, ':') == NULL)
    {
      DBG_MSG("Expanding relative path to user homedir.\n");
      
      snwprintf(keyFileName, sizeof(keyFileName), 
                    L"%ls\\%ls", homeDir, nextFile);
                          
      fileToCheck = keyFileName;
    }

    //
    // Try to find key in next 'authorized_key' file.
    //
  
    if(FindKeyInFile(fileToCheck, key) == 0)
    {
      //
      // Verify given key.
      //

      DBG_MSG("Veryfing key...\n");
  
      authorized = (VerifyKey(key, signPtr, auth -> signSize_, 
                                  dataPtr, auth -> dataSize_, 
                                      auth -> dataFellow_) == 0);
    }
    
    //
    // Go to next file in list.
    //
    
    nextFile = wcschr(nextFile, 0) + sizeof(wchar_t);
  }
  
  FAIL(Not(authorized));
  
  exitCode = 0;

fail:

  if (exitCode)
  {
    DBG_MSG("ERROR. Auhtorization failed (%u).\n", GetLastError());
    
    //
    // If authorization error clear homedir.
    //
    
    ZeroMemory(homeDir, MAX_PATH);
  }
  
  UnloadUserProfile(token, profile.hProfile);
  
  DBG_LEAVE("AuthorizeUser");
  
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
  DBG_ENTRY("LsaApLogonUser");
  
  NTSTATUS ntStat = STATUS_LOGON_FAILURE;
  
  Int exitCode = 1;

  //
  // Function should retrieve authorization data as SshLsaAuth struct.
  //
  
  wchar_t *inUserName = NULL;
  
  SshLsaAuth *auth = (SshLsaAuth *) authData;

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

  HANDLE token       = NULL;
  HANDLE clientToken = NULL;
  
  //
  // Info about client process. We use it to detect has client got
  // SeTcbPrivilege.
  //

  SECPKG_CLIENT_INFO clientInfo;
  
  //
  // Check are input args ok?
  //
  
  DBG_MSG("Checking input args...\n");

  FAIL(auth == NULL);
  
  FAIL(auth -> buf_ == NULL);
  
  inUserName = (wchar_t *) auth -> buf_;
  
  DBG_MSG("Checking SshLsaAuth size...\n");

  FAIL(auth -> totalSize_ != authDataSize);

  DBG_MSG("logonType = %u\n", logonType);
  
  DBG_MSG("userName = [%ls]\n", inUserName);
  
  //
  // Get info about client process.
  //
  
  DBG_MSG("Retreving info about client process...\n");
  
  NTFAIL(LsaApi.GetClientInfo(&clientInfo));
  
  DBG_MSG("Client info:\n");
  DBG_MSG("  LogonId         : %d\n", clientInfo.LogonId);
  DBG_MSG("  ProcessID       : %d\n", clientInfo.ProcessID);
  DBG_MSG("  ThreadID        : %d\n", clientInfo.ThreadID);
  DBG_MSG("  HasTcbPrivilege : %d\n", clientInfo.HasTcbPrivilege);
  DBG_MSG("  Impersonating   : %d\n", clientInfo.Impersonating);
  DBG_MSG("  Restricted      : %d\n", clientInfo.Restricted);
  
  //
  // Fail if client has not got SeTcbPrivilege.
  //
  
  FAIL(Not(clientInfo.HasTcbPrivilege));
  
  //
  // Allocate buffers.
  //
  
  DBG_MSG("Allocating string buffers...\n");
  
  NTFAIL(LsaAllocUnicodeString(authority, MAX_ACCOUNT_NAME_SIZE));
  NTFAIL(LsaAllocUnicodeString(accountName, MAX_ACCOUNT_NAME_SIZE));
  NTFAIL(LsaAllocUnicodeString(&flatName, MAX_ACCOUNT_NAME_SIZE));

  //
  // Retrieve user data from SAM base.
  //
  
  DBG_MSG("GetAuthDataForUser()...\n");

  lstrcpyW(samUserBuf, inUserName);

  samUserBuf[MAX_ACCOUNT_NAME_SIZE] = 0x00;
  
  RtlInitUnicodeString((PUNICODE_STRING) &samUser, samUserBuf);
  
  NTFAIL(LsaApi.GetAuthDataForUser(&samUser, SecNameFlat, NULL,
                                      &userAuth, &userAuthSize, flatName));

  DBG_MSG("userAuthSize = %u\n", userAuthSize);
  
  //
  // Create token basing on SAM data.
  //
  
  DBG_MSG("ConvertAuthDataToToken()...\n");

  memcpy (tokenSource.SourceName, "_sshlsa_", 8);
  
  AllocateLocallyUniqueId(&tokenSource.SourceIdentifier);
  
  NTFAIL(LsaApi.ConvertAuthDataToToken(userAuth, userAuthSize,
                                           SecurityDelegation,
                                               &tokenSource, Network,
                                                   *authority, &token, logonId,
                                                       *accountName, subStat));

  //
  // Print token info.
  //
  
  DBG_PRINT_TOKEN(token);
    
  //
  // Perform authorization and retrieve homeDir if success.
  //

  DBG_MSG("Performing authorization...\n");
  
  FAIL(AuthorizeUser(homeDir, token, auth));
  
  //
  // Allocate client buffer and copy home dir to it.
  //
  
  DBG_MSG("Filling profile buffer...\n");
  
  NTFAIL(LsaApi.AllocateClientBuffer(request, MAX_PATH * sizeof(wchar_t), profile));

  *profileSize = MAX_PATH;
  
  DBG_MSG("homeDir = %ls\n", homeDir);
  
  NTFAIL(LsaApi.CopyToClientBuffer(request, MAX_PATH * sizeof(wchar_t), 
                                       *profile, homeDir));

  //
  // Fill token info for LSA, using token created from SAM database
  // as input pattern. We create LSA_TOKEN_INFORMATION_V1 struct
  // here.
  //
  
  DBG_MSG("Creating token infos for LSA output...\n");
  
  PLSA_TOKEN_INFORMATION_V1 outTokenInfo;
  
  FAIL(LsaAllocTokenInfo(outTokenInfo, token));

  *tokenInfoType = LsaTokenInformationV1;
  
  *tokenInfo = outTokenInfo;
  
  //
  // Duplicate token from lsa space to client space.
  //
  
  DBG_MSG("Duplicating token into client space...\n");
  
  NTFAIL(LsaApi.DuplicateHandle(token, &clientToken));
  
  //
  // Create new logon session.
  //

  /*  
  DBG_MSG("Creating new logon session...\n");
  
  FAIL(AllocateLocallyUniqueId(logonId) == FALSE);
  
  *subStat = LsaApi.CreateLogonSession(logonId);

  FAIL(*subStat);
  */
  
  ntStat = STATUS_SUCCESS;
  
  exitCode = 0;
  
fail:
  
  if (exitCode)
  {
    DBG_MSG("ERROR. Cannot logon user "
                "(err = %u, ntStat = %x, subNtStat = %x).\n",
                    GetLastError(), ntStat, *subStat);
                
    ntStat = STATUS_LOGON_FAILURE;
    
    CloseHandle(clientToken);
  
    LsaApi.DeleteLogonSession(logonId);
    
    *profileSize = 0;
  }
  else
  {
    DBG_MSG("LsaApLogonUser : OK.\n");
  }
  
  //
  // Cleanup temporary buffers.
  //
  
  CloseHandle(token);
  
  DBG_MSG("Freeing temp buffers...\n");
  
  LsaFreeUnicodeString(flatName);

  DBG_LEAVE("LsaApLogonUser");

  return ntStat;
}


//
// This functions is called, after session closed. This is only 
// information for package and we don't need to do anything here.
//

VOID NTAPI LsaApLogonTerminated(PLUID logonId)
{
  DBG_MSG("LsaApLogonTerminated(id = %d)...\n", *logonId);
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

      DBG_INIT(NULL);

      DBG_MSG("DllMain -> DLL_PROCESS_ATTACH\n");
      
      DBG_MSG("[SSH-LSA-%s]\n", VERSION);
      
      //
      // Load 'ntdll.dll' module.
      //
      
      DBG_MSG("Loading 'ntdll.dll' module...\n");
  
      NtDll = GetModuleHandle("ntdll.dll");
      
      FAIL(NtDll == NULL);
      
      //
      // Load RtlInitUnicodeString() function from 'ntdll.dll'.
      //
  
      DBG_MSG("Retrieving 'RtlInitUnicodeString' address...\n");
      
      RtlInitUnicodeString = (RtlInitUnicodeStringPtr) 
                                  GetProcAddress(NtDll, "RtlInitUnicodeString");
      
      FAIL(RtlInitUnicodeString == NULL);
      
      //
      // This code is code for dynamic, 'on the fly' OpenSSL libs loading.
      //
      
      #ifdef DYNAMIC_OPENSSL

        //
        // Load 'libssl.dll' module.
        //

        DBG_MSG("Loading 'libssl.dll' module...\n");

        LibSSL = LoadLibrary("libssl.dll");

        FAIL(LibSSL == NULL);

        //
        // Load 'libcrypto.dll' module.
        //

        DBG_MSG("Loading 'libcrypto.dll' module...\n");

        LibCrypto = LoadLibrary("libcrypto.dll");

        FAIL(LibCrypto == NULL);

        //
        // Load 'libSSL.dll' functions.
        //

        DynSSL.SSL_library_init = (SSL_library_init_Ptr) GetProcAddress(LibSSL, "SSL_library_init");

        //
        // Load 'libcrypto.dll' functions.
        //

        DynSSL.EVP_sha1         = (EVP_sha1_Ptr) GetProcAddress(LibCrypto, "EVP_sha1");
        DynSSL.EVP_DigestInit   = (EVP_DigestInit_Ptr) GetProcAddress(LibCrypto, "EVP_DigestInit");
        DynSSL.EVP_DigestFinal  = (EVP_DigestFinal_Ptr) GetProcAddress(LibCrypto, "EVP_DigestFinal");
        DynSSL.EVP_DigestUpdate = (EVP_DigestUpdate_Ptr) GetProcAddress(LibCrypto, "EVP_DigestUpdate");
        DynSSL.EVP_Digest       = (EVP_Digest_Ptr) GetProcAddress(LibCrypto, "EVP_Digest");

        DynSSL.EVP_get_digestbyname = (EVP_get_digestbyname_Ptr) GetProcAddress(LibCrypto, "EVP_get_digestbyname");

        DynSSL.DSA_SIG_free  = (DSA_SIG_free_Ptr) GetProcAddress(LibCrypto, "DSA_SIG_free");
        DynSSL.DSA_SIG_new   = (DSA_SIG_new_Ptr) GetProcAddress(LibCrypto, "DSA_SIG_new");
        DynSSL.DSA_do_verify = (DSA_do_verify_Ptr) GetProcAddress(LibCrypto, "DSA_do_verify");
        DynSSL.DSA_new       = (DSA_new_Ptr) GetProcAddress(LibCrypto, "DSA_new");
        DynSSL.DSA_free      = (DSA_free_Ptr) GetProcAddress(LibCrypto, "DSA_free");

        DynSSL.RSA_size      = (RSA_size_Ptr) GetProcAddress(LibCrypto, "RSA_size");
        DynSSL.RSA_new       = (RSA_new_Ptr) GetProcAddress(LibCrypto, "RSA_new");
        DynSSL.RSA_free      = (RSA_free_Ptr) GetProcAddress(LibCrypto, "RSA_free");

        DynSSL.BN_new        = (BN_new_Ptr) GetProcAddress(LibCrypto, "BN_new");
        DynSSL.BN_bin2bn     = (BN_bin2bn_Ptr) GetProcAddress(LibCrypto, "BN_bin2bn");
        DynSSL.BN_num_bits   = (BN_num_bits_Ptr) GetProcAddress(LibCrypto, "BN_num_bits");
        DynSSL.BN_cmp        = (BN_cmp_Ptr) GetProcAddress(LibCrypto, "BN_cmp");

        DynSSL.RSA_public_decrypt = (RSA_public_decrypt_Ptr) GetProcAddress(LibCrypto, "RSA_public_decrypt");

        DynSSL.OBJ_nid2sn = (OBJ_nid2sn_Ptr) GetProcAddress(LibCrypto, "OBJ_nid2sn");

        DynSSL.OpenSSL_add_all_digests = (OpenSSL_add_all_digests_Ptr) GetProcAddress(LibCrypto, "OpenSSL_add_all_digests");

      #endif
      
      break;
    }

    //
    // uninit package dll.
    //

    case DLL_PROCESS_DETACH:
    {
      DBG_MSG("DllMain -> DLL_PROCESS_DETACH\n");
      
      FreeModule(NtDll);


      #ifdef DYNAMIC_OPENSSL
      
        FreeModule(LibCrypto);
      
        FreeModule(LibSSL);
      
      #endif
    }
  }

  exitCode = TRUE;

fail:  
  
  if (exitCode == FALSE)
  {
    DBG_MSG("ERROR. Cannot initialize DLL (%u).\n", GetLastError());

    FreeModule(NtDll);

    
    #ifdef DYNAMIC_OPENSSL
    
      FreeModule(LibCrypto);

      FreeModule(LibSSL);
    
    #endif
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
  DBG_ENTRY("LsaApCallPackagePassthrough(");
  DBG_LEAVE("LsaApCallPackagePassthrough(");
 
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
  DBG_ENTRY("LsaApCallPackageUntrusted");
  DBG_LEAVE("LsaApCallPackageUntrusted");

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
  DBG_ENTRY("LsaApCallPackage");
  DBG_LEAVE("LsaApCallPackage");
 
  return STATUS_NOT_IMPLEMENTED;
}

#ifdef __cplusplus
}
#endif
