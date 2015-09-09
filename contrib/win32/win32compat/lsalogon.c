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

#include "lsalogon.h"
#include "Debug.h"

#include "includes.h"
#include "log.h"
#include "servconf.h"

extern ServerOptions options;

/*
 * Allocate new LsaAuth struct and initialize it with given auth data.
 * This function is needed becouse:
 *
 * a) LSA needs one continous memory block on input.
 *
 * b) We can't send pointers in auth data to LSA 'server', becouse
 *    LSA package can be 32 or 64 bit and the same to client application.
 *    Client and Server must be compatible, so all fields must have the
 *    same size in lsa 'server' and logon client application.
 *
 * So, we allocate one 'big' LsaAuth struct and copy to it all
 * needed auth data. 
 *
 * lsaauth    - new allocated LsaAuth struct (OUT)
 * user       - user name, in UTF-8 (IN)
 * pkblob     - public key blob (IN)
 * blen       - pkblob size in bytes (IN)
 * sign       - signature (IN)
 * signSize   - signature size in bytes (IN)
 * data       - ?? We copy it from ssh auth code (IN)
 * dataSize   - size of data field in bytes (IN)
 * dataFellow - ?? We pass global 'datafellow' variable from sshd here (IN)
 *
 * RETURNS: 0 if OK.
 */

int AllocLsaAuth(LsaAuth **lsaAuth, char *user, char *pkBlob, 
                    int pkBlobSize, char *sign, int signSize, 
                        char *data, int dataSize, int dataFellow)
{
  int exitCode = 1;

  LPWSTR userUTF16 = NULL;
  
  int i = 0;
  
  int authFileSize = 0;
  
  /*
   * Pointers to fields in local allocated LsaAuth struct.
   */
  
  char *userPtr = NULL;
  char *signPtr = NULL;
  char *dataPtr = NULL;
  char *blobPtr = NULL;
  char *authPtr = NULL;
  
  char *p = NULL;
  
  /*
   * Are arguments ok?
   */
    
  debug3("Checking args...");
  
  FAIL(user == NULL);
  FAIL(lsaAuth == NULL);
  FAIL(pkBlob == NULL);
  FAIL(sign == NULL);
  FAIL(signSize == 0);
  FAIL(dataSize == 0);
  FAIL(pkBlobSize == 0);
  
  *lsaAuth = NULL;
  
  /*
   * Compute total size of authorize files list.
   * For each files we need : real content + zero terminate word.
   */
   
  for (i = 0; i < options.num_authkeys_files; i++)
  {
    debug3("Adding authorized file [%s] to LsaAuth...",
               options.authorized_keys_files[i]);

    int cchLen = MultiByteToWideChar(CP_UTF8, 0,
                                         options.authorized_keys_files[i],
                                             -1, NULL, 0);
                                          
    authFileSize += (cchLen + 1) * sizeof(wchar_t);
  }
  
  /*
   * Convert username to UTF-16.
   */
   
  int userSize = MultiByteToWideChar(CP_UTF8, 0, user, -1, NULL, 0);
  
  FAIL(userSize == 0);

  userSize = 4 * userSize;

  userUTF16 = (LPWSTR) malloc(userSize);
  
  FAIL(userUTF16 == NULL);

  FAIL(0 == MultiByteToWideChar(CP_UTF8, 0, user, -1, userUTF16, userSize));
 
  /*              
   * Compute total size of LsaAuth struct.
   */
  
  debug3("Computing total size of LsaAuth...");
  
  int totalSize = sizeof(LsaAuth) + userSize + signSize + 
                      dataSize + pkBlobSize + authFileSize;
  
  /*
   * Allocate new LsaAuth struct.
   */
  
  debug3("Allocating new LsaAuth structure...");

  *lsaAuth = (LsaAuth *) malloc(totalSize);
  
  FAIL(*lsaAuth == NULL);
  
  /*
   * Store sizes of fields in LsaAuth.
   */
  
  (*lsaAuth) -> totalSize_  = totalSize;  
  (*lsaAuth) -> userSize_   = userSize;
  (*lsaAuth) -> signSize_   = signSize;  
  (*lsaAuth) -> dataSize_   = dataSize;  
  (*lsaAuth) -> pkBlobSize_ = pkBlobSize;  

  /*
   * Compute adressess of fields.
   */
  
  userPtr = (char *) &((*lsaAuth) -> buf_);
  signPtr = (char *) (userPtr + userSize);
  dataPtr = (char *) (signPtr + signSize);
  blobPtr = (char *) (dataPtr + dataSize);
  authPtr = (char *) (blobPtr + pkBlobSize);
  
  /*
   * Copy input buffers into output structure's fields.
   */
  
  debug3("Filling up LsaAuth struct...");
  
  memcpy(userPtr, userUTF16, userSize);
  memcpy(signPtr, sign, signSize);
  memcpy(dataPtr, data, dataSize);
  memcpy(blobPtr, pkBlob, pkBlobSize);
  
  (*lsaAuth) -> dataFellow_ = dataFellow;
  
  /*
   * Copy authorized files list into output struct.
   */
   
  (*lsaAuth) -> authFilesCount_ = options.num_authkeys_files;
  
  p = authPtr;
  
  for (i = 0; i < options.num_authkeys_files; i++)
  {
    char *nextFile = options.authorized_keys_files[i];

    int bytesLeft = (char *) (*lsaAuth) + totalSize - p;
    
    /*
     * Put next UTF8 string to struct.
     */

    debug3("Converting [%s] to UTF8...", nextFile);

    int writtenCch = MultiByteToWideChar(CP_UTF8, 0, nextFile, -1, 
                                             (wchar_t *) p, bytesLeft);

    FAIL(writtenCch <= 0);
 
    p += (writtenCch + 1) * sizeof(wchar_t);
  }
 
  exitCode = 0;
  
fail:

  /*
   * Clean up if function fails.
   */
  
  if (exitCode)
  {
    debug("ERROR. Cannot create LsaAuth struct (%u).", GetLastError());
    
    if (lsaAuth && *lsaAuth)
    {
      free(*lsaAuth);
      
      *lsaAuth = NULL;
    }

    if (userUTF16)
    {
      free(userUTF16);
    }
  }
  
  return exitCode;
}

/*
 * Try to logon using SSH-LSA package.
 * 
 * hToken     - user token if success (OUT)
 * user       - user name (IN)
 * pkblob     - public key blob (IN)
 * blen       - pkblob size in bytes (IN)
 * sign       - signature (IN)
 * signSize   - signature size in bytes (IN)
 * data       - ?? We copy it from ssh auth code (IN)
 * dataSize   - size of data field in bytes (IN)
 * dataFellow - ?? We copy it from ssh auth code (IN)
 *
 * RETURNS: 0 if OK.
 */

int LsaLogon(HANDLE *hToken, char homeDir[MAX_PATH], char *user, 
                 char *pkBlob, int pkBlobSize, char *sign, int signSize, 
                     char *data, int dataSize, int dataFellow)
{
  int exitCode = 1;
  
  NTSTATUS ntStat = 0;
  
  LSA_STRING logonProcName;
  LSA_STRING originName;
  LSA_STRING authPckgName;
  
  HANDLE hLsa = NULL;
  
  LSA_OPERATIONAL_MODE securityMode;
  
  /*
   * Impersonation, "weak" token returned from network logon.
   * We can't create process as other user via this token.
   */
  
  HANDLE hWeakToken = NULL;
  
  /*
   * Login data.
   */
  
  LsaAuth *lsaAuth = NULL;

  ULONG lsaAuthSize = 0;

  ULONG authPckgId  = 0;
  
  TOKEN_SOURCE srcToken;
  
  PVOID profile = NULL;

  ULONG profileSize;
  
  LUID  logonId;
  
  QUOTA_LIMITS quotas;
  
  NTSTATUS loginStat;
  

  debug("-> LsaLogon()...");

  /*
   * We check only hToken arg, becouse other args are tested in AllocLsaAuth().
   */
  
  debug("Checking args...");
  
  FAIL(hToken == NULL);
  
  /*
   * Setup lsa strings.
   */

  debug("Setting up LSA Strings...");
  
  FAIL(InitLsaString(&logonProcName, "sshd-logon"));
  FAIL(InitLsaString(&originName, "NTLM"));
  FAIL(InitLsaString(&authPckgName, "SSH-LSA"));

  /*
   * Enable needed privilege to current running process.
   */

  EnablePrivilege("SeTcbPrivilege", 1);
  
  /*
   * Register new logon process.
   */
  
  debug("LsaRegisterLogonProcess()...");

  NTFAIL(LsaRegisterLogonProcess(&logonProcName, &hLsa, &securityMode));
  
  /*
   * Retrieve Authenticated Package ID.
   */
  
  debug("Retrieving Authentification Package ID...");
  
  NTFAIL(LsaLookupAuthenticationPackage(hLsa, &authPckgName, &authPckgId));
  
  /*
   * Allocate LsaAuth struct.
   */

  debug("Allocating LsaAuth struct...");
  
  FAIL(AllocLsaAuth(&lsaAuth, user, pkBlob, pkBlobSize,
                       sign, signSize, data, dataSize, dataFellow));
                       
  lsaAuthSize = lsaAuth -> totalSize_;                       

  /*
   * Create TOKEN_SOURCE part
   */
  
  debug("Setting up TOKEN_SOURCE...");
  
  FAIL(AllocateLocallyUniqueId(&srcToken.SourceIdentifier) == FALSE);
  
  memcpy(srcToken.SourceName, "**sshd**", 8);

  /*
   * Try to login using LsaAuth struct.
   */

  debug("Login attemp...");
  
  NTFAIL(LsaLogonUser(hLsa, &originName, Network,
                          authPckgId, lsaAuth, lsaAuthSize, NULL,
                              &srcToken, &profile, &profileSize,
                                  &logonId, &hWeakToken, &quotas, &loginStat));

  debug("login status: %x...", loginStat);
  
  
  //FAIL(WideCharToMultiByte( CP_UTF8, 0, profile, -1, homeDir, MAX_PATH, NULL, NULL)==0);
  //memcpy(homeDir, profile, MAX_PATH*sizeof(wchar_t));

  lstrcpyW(homeDir, profile);
  
  debug("homedir = [%ls]", (char *) homeDir);

  //strcpy(homeDir, profile);
  
  //PrintToken(hToken);
  
  /*
   * Duplicate 'weak' impersonation token into Primary Key token.
   * We can create process using duplicated token.
   */
  
  debug("Duplicating token...");
  
  FAIL(DuplicateTokenEx(hWeakToken, MAXIMUM_ALLOWED,
                            NULL, SecurityImpersonation,
                                TokenPrimary, hToken) == 0);
  
  exitCode = 0;
  
fail:

  if (exitCode)
  {
    switch(ntStat)
    {
      case STATUS_LOGON_FAILURE:
      {
        debug("SSH-LSA authorization failed. " 
                  "(err = %u, ntStat = %x).", GetLastError(), ntStat);

        exitCode = 0;

        break;
      }
      
      case STATUS_NO_SUCH_PACKAGE:
      {
        debug("SSH-LSA package not found. "
                  "(err = %u, ntStat = %x).", GetLastError(), ntStat);
                  
        break;          
      }
      
      default:
      {
        debug("Cannot logon using LSA package (err = %u, ntStat = %x).",
                  GetLastError(), ntStat);
      }
    }        
            
    hToken = NULL;
  }
  else
  {
    debug("LsaLogon : OK.");
  }

  /*
   * Clean up.
   */
  
  CloseHandle(hWeakToken);
  
  LsaFreeReturnBuffer(profile);
   
  EnablePrivilege("SeTcbPrivilege", 0);
  
  LsaDeregisterLogonProcess(hLsa);
  
  ClearLsaString(&logonProcName);
  ClearLsaString(&originName);
  ClearLsaString(&authPckgName);
         
  debug("<- LsaLogon()...");
  
  return exitCode;
}
