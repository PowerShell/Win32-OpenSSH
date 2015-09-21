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

#include "includes.h"

#ifdef WIN32_FIXME

/*
 * Includes.
 */
 
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#if defined(HAVE_STRNVIS) && defined(HAVE_VIS_H)
#include <vis.h>
#endif

#include "openbsd-compat/sys-queue.h"

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "buffer.h"
#include "packet.h"
#include "compat.h"
#include "cipher.h"
#include "key.h"
#include "kex.h"
#include "myproposal.h"
#include "sshconnect.h"
#include "authfile.h"
#include "dh.h"
#include "authfd.h"
#include "log.h"
#include "readconf.h"
#include "misc.h"
#include "match.h"
#include "dispatch.h"
#include "canohost.h"
#include "msg.h"
#include "pathnames.h"
#include "uidswap.h"
#include "hostfile.h"
#include "schnorr.h"
#include "jpake.h"
#include "ssh-gss.h"

#include "kerberos-sspi.h"

/*
 * Defines.
 */
 
#define FAIL(X) if (X) goto fail
#define FAILEX(X, ...) if (X) {error(__VA_ARGS__); goto fail;}
#define SSPI_FAIL(X) if ((sspiCode = (X)) != SEC_E_OK) goto fail

/*
 * Structs.
 */
 
typedef struct Authctxt Authctxt;
typedef struct Authmethod Authmethod;

struct Authmethod
{
  char *name;

  void *userauth;
  void *cleanup;

  int *enabled;
  int *batch_flag;
};

struct Authctxt 
{
  const char *server_user;
  const char *local_user;
  const char *host;
  const char *service;
  
  Authmethod *method;
  
  sig_atomic_t success;
  
  char *authlist;
  
  void *keys;
  void *agent;
  void *sensitive;

  int info_req_seen;
  
  void *methoddata;
};

/*
 * Hardcoded, kerberos5 OID in <type><len><OID> format.
 */
  
static unsigned char KRB5_OID[] =
{
  SSH_GSS_OIDTYPE,
  9,
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02
};

void input_sspi_kerberos_token(int type, u_int32_t plen, void *ctxt);
void input_sspi_kerberos_error(int type, u_int32_t plen, void *ctxt);
void input_sspi_kerberos_errtok(int type, u_int32_t plen, void *ctxt); 

int SspiProcessToken(void *input, int inputSize, Authctxt *auth);

void input_sspi_kerberos_response(int type, u_int32_t plen, void *ctxt);

/*
 * Convert SECURITY_STATUS code into human readable string.
 *
 * RETURNS: Human readable string or "UNKNOWN" if unknown code.
 */
 
const char *SspiGetCodeName(DWORD code)
{
  struct
  {
    DWORD code_;
    
    const char *name_;
  }
  map[] =
  {
    {SEC_E_OK,                          "SEC_E_OK"},
    {SEC_E_CERT_EXPIRED,                "SEC_E_CERT_EXPIRED"},
    {SEC_E_INCOMPLETE_MESSAGE,          "SEC_E_INCOMPLETE_MESSAGE"},
    {SEC_E_INSUFFICIENT_MEMORY,         "SEC_E_INSUFFICIENT_MEMORY"},
    {SEC_E_INTERNAL_ERROR,              "SEC_E_INTERNAL_ERROR"},
    {SEC_E_INVALID_HANDLE,              "SEC_E_INTERNAL_ERROR"},
    {SEC_E_INVALID_TOKEN,               "SEC_E_INTERNAL_ERROR"},
    {SEC_E_LOGON_DENIED,                "SEC_E_INTERNAL_ERROR"},
    {SEC_E_NO_AUTHENTICATING_AUTHORITY, "SEC_E_INTERNAL_ERROR"},
    {SEC_E_NO_CREDENTIALS,              "SEC_E_INTERNAL_ERROR"},
    {SEC_E_TARGET_UNKNOWN,              "SEC_E_TARGET_UNKNOWN"},
    {SEC_E_UNSUPPORTED_FUNCTION,        "SEC_E_UNSUPPORTED_FUNCTION"},
    {SEC_E_UNTRUSTED_ROOT,              "SEC_E_UNTRUSTED_ROOT"},
    {SEC_E_WRONG_PRINCIPAL,             "SEC_E_WRONG_PRINCIPAL"},
    {SEC_E_SECPKG_NOT_FOUND,            "SEC_E_SECPKG_NOT_FOUND"},
    {SEC_E_QOP_NOT_SUPPORTED,           "SEC_E_QOP_NOT_SUPPORTED"},
    {SEC_E_UNKNOWN_CREDENTIALS,         "SEC_E_UNKNOWN_CREDENTIALS"},
    {SEC_E_NOT_OWNER,                   "SEC_E_NOT_OWNER"},
    {SEC_I_RENEGOTIATE,                 "SEC_I_RENEGOTIATE"},
    {SEC_I_COMPLETE_AND_CONTINUE,       "SEC_I_COMPLETE_AND_CONTINUE"},
    {SEC_I_COMPLETE_NEEDED,             "SEC_I_COMPLETE_NEEDED"},
    {SEC_I_CONTINUE_NEEDED,             "SEC_I_CONTINUE_NEEDED"},
    {SEC_I_INCOMPLETE_CREDENTIALS,      "SEC_I_INCOMPLETE_CREDENTIALS"},
    {0,                                 NULL}
  };
  
  int i = 0;
  
  for (i = 0; map[i].name_ != NULL; i++)
  {
    if (map[i].code_ == code)
    {
      return map[i].name_;
    }
  }

  return "UNKNOWN";
}

/*
 * Free SSPI context allocated in userauth_sspi_kerberos().
 * This struct is stored inside AuthCtx as 'methoddata'.
 */                       
 
void userauth_sspi_kerberos_cleanup(Authctxt *authctxt)
{
  debug3("-> userauth_sspi_kerberos_cleanup()...");
     
  if (authctxt != NULL)
  {
    SspiContext *sspi = authctxt -> methoddata;

    if (sspi != NULL)
    {
      if (FreeCredentialsHandle(&sspi -> credHandle) != SEC_E_OK)
      {
        error("WARNING: Cannot free SSPI credentials.");
      }
     
      if (DeleteSecurityContext(&sspi -> context) != SEC_E_OK)
      {
        error("WARNING: Cannot delete SSPI context.");
      }
    
      if (sspi -> targetName != NULL)
      {
        free(sspi -> targetName);
      }

      if (sspi -> oidOut != NULL)
      {
        free(sspi -> oidOut);
      }
      
      free(sspi);
      
      authctxt -> methoddata = NULL;
    }
  }  
    
  debug3("<- userauth_sspi_kerberos_cleanup()...");
}

/*
 * Perform Kerberos authentication via native SSPI.
 */
 
int userauth_sspi_kerberos(Authctxt *authctxt)
{
  static int alreadyCalled = 0;
  
  /*
   * If this auth was tried before, it means
   * one of futher step fails.
   * Don't try once again.
   */
   
  if (alreadyCalled == 1)
  {
    return 0;
  }

  debug3("-> userauth_sspi_kerberos()...");
  
  int exitCode = 0;

  SspiContext *sspi = NULL;
  
  
  alreadyCalled = 1;
  
  /*
   * Allocate new SSPI context.
   */
   
  debug3("Allocating new SSPI auth context...");
  
  sspi = calloc(sizeof(SspiContext), 1);
  
  FAILEX(sspi == NULL, "ERROR: Out of memory.");
  
  authctxt -> methoddata = sspi;
  
  debug3("Set auth context to [%p].", sspi);
  
  /*
   * Add 'host/' prefix to server name.
   */
   
  sspi -> targetName = malloc(sizeof("host/") + strlen(authctxt -> host));

  FAILEX(sspi -> targetName == NULL, "ERROR: Out of memory");
  
  strcpy(sspi -> targetName, "host/");
  strcat(sspi -> targetName, authctxt -> host);

  /*
   * Set kerberos5 as outgoing OID.
   */
   
  debug3("Setting up KRB5 mechanism as outgoing OID...");
  
  sspi -> oidOutLen = sizeof(KRB5_OID);
  sspi -> oidOut    = malloc(sizeof(KRB5_OID));

  FAILEX(sspi -> oidOut == NULL, "ERROR: Out of memory.");
  
  memcpy(sspi -> oidOut, KRB5_OID, sizeof(KRB5_OID));
  
  /*
   * Send SSH2_MSG_USERAUTH_REQUEST packet to server.
   * We declare that we want kerberos authentication here.
   */

  debug3("Sending SSH2_MSG_USERAUTH_REQUEST:");
  debug3("  Server user : [%s].", authctxt -> server_user);
  debug3("  Service     : [%s].", authctxt -> service);
  debug3("  Method      : [%s].", authctxt -> method -> name);
  
  packet_start(SSH2_MSG_USERAUTH_REQUEST);
  
  packet_put_cstring(authctxt -> server_user);
  packet_put_cstring(authctxt -> service);
  packet_put_cstring(authctxt -> method -> name);

  /* 
   * Declare 1 Kerberos5 mechanism.
   *
   * 0  4   number of OIDs (hardcoded to 1)
   * 4  4   total len in bytes
   * 8 ...  OID's data
   */
   
  packet_put_int(1);

  packet_put_int(sspi -> oidOutLen);
  packet_put_raw(sspi -> oidOut, sspi -> oidOutLen);

  packet_send();        

  /*
   * Set callbacks to handle auth specific packets.
   */
  
  dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_RESPONSE, &input_sspi_kerberos_response);
  dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, &input_sspi_kerberos_token);
  dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERROR, &input_sspi_kerberos_error);
  dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, &input_sspi_kerberos_errtok);

  exitCode = 1;
  
  /*
   * Error handler.
   */
   
  fail:
  
  if (exitCode == 0)
  {
    error("ERROR: Cannot perform kerberos SSPI authentication.\n"
              "WINAPI error code is : %u.", GetLastError());
  }
  
  debug3("<- userauth_sspi_kerberos()...");
  
  return exitCode;
}

/*
 * Parse incoming SSH2_MSG_USERAUTH_GSSAPI_TOKEN packet.
 * Called as long as handshake process finished.
 *
 * One incoming SSH2_MSG_USERAUTH_GSSAPI_TOKEN means:
 *
 * - one outcoming SSH2_MSG_USERAUTH_GSSAPI_TOKEN sent if handshake not 
 *   finished.
 *
 * - one outcoming SSH2_MSG_USERAUTH_GSSAPI_MIC if handshake finished.
 *
 * - one outcoming SSH2_MSG_USERAUTH_GSSAPI_ERRTOK if error.
 *
 * type - UNUSED.
 * plen - UNUSED.
 * ctxt - User auth context (IN/OUT).
 */

void input_sspi_kerberos_token(int type, u_int32_t plen, void *ctxt)
{
  debug3("-> input_sspi_kerberos_token()...");

  Authctxt *auth = ctxt;

  SspiContext *sspi = NULL;
  
  int exitCode = -1;
  
  char *buf = NULL;
  
  int bufLen = 0;
  
  SECURITY_STATUS sspiCode = SEC_E_OK;
  
  debug3("Received [SSH2_MSG_USERAUTH_GSSAPI_TOKEN] packet.");

  /*
   * Get back SSPI context created in userauth_sspi_kerberos() call.
   */
   
  FAILEX(auth == NULL, "ERROR: Auth context cannot be NULL in '%s'.", __FUNCTION__);

  sspi = auth -> methoddata;
  
  FAILEX(sspi == NULL, "ERROR: SSPI context cannot be NULL in '%s'.", __FUNCTION__);
   
  /*
   * Receive token from server.
   */

  buf = packet_get_string(&bufLen);
  
  debug3("Received [%d] bytes token.", bufLen);
  
  /*
   * Eat remaining packet's data if any.
   * Must called to save integrity on incoming network data.
   */

  packet_check_eom();

  /*
   * Process token received from server.
   */
   
  FAIL(SspiProcessToken(buf, bufLen, auth));
  
  /*
   * Clean up.
   */

  exitCode = 0;
   
  fail:
  
  if (exitCode)
  {
    error("ERROR: Cannot process SSH2_MSG_USERAUTH_GSSAPI_TOKEN packet.");
  }
  
  free(buf);
  
  debug3("<- input_sspi_kerberos_token()...");
}

/*
 * Process server side fault.
 *
 * type - UNUSED.
 * plen - UNUSED.
 * ctxt - UNUSED.
 */

void input_sspi_kerberos_error(int type, u_int32_t plen, void *ctxt)
{
  debug3("-> input_sspi_kerberos_error()...");

  OM_uint32 maj = 0;
  OM_uint32 min = 0;
  
  char *msg  = NULL;
  char *lang = NULL;

  maj  = packet_get_int();
  min  = packet_get_int();
  msg  = packet_get_string(NULL);
  lang = packet_get_string(NULL);

  error("Server GSSAPI Error:\n%s", msg);

  packet_check_eom();

  /*
   * Eat remaining packet's data if any.
   * Must called to save integrity on incoming network data.
   */

  packet_check_eom();

  free(msg);
  free(lang);

  debug3("<- input_sspi_kerberos_error()...");
}

void input_sspi_kerberos_errtok(int type, u_int32_t plen, void *ctxt)
{
  debug3("-> input_sspi_kerberos_errtok()...");
  
  input_sspi_kerberos_token(type, plen, ctxt);
  
  debug3("<- input_sspi_kerberos_errtok()...");
}

/*
 * Process input token (i.e. message, being part of handshake protocol)
 * received from server and send answer (outgoing token) back to server
 * if needed.
 *
 * input     - input token received from server or NULL if first time 
 *             called (IN).
 * 
 * inputSize - size of input buffer in bytes (IN).
 * auth      - pointer to authenticate context (IN).
 *
 * RETURNS: 0 if OK.
 */
 
int SspiProcessToken(void *input, int inputSize, Authctxt *auth)
{
  debug3("-> SspiProcessToken()...");
 
  int exitCode = -1;

  /*
   * Input (received from server) and outgoing 
   * (going be to send) tokens.
   */
   
  SecBuffer inpBuf = {inputSize, SECBUFFER_TOKEN, input};
  SecBuffer outBuf = {0,         SECBUFFER_TOKEN, NULL};
    
  SecBufferDesc inpBufDesc = {SECBUFFER_VERSION, 1, &inpBuf};
  SecBufferDesc outBufDesc = {SECBUFFER_VERSION, 1, &outBuf};
  
  /*
   * Plain message to sign at the last hanshake step.
   * This message is generated on client side and send
   * to server after sign.
   */
   
  Buffer mic;
  
  /*
   * Buffers to sign 'mic' into 'hash'.
   *
   * hash[0] = input, plain mic.
   * hash[1] = output, signed mic.
   */

  SecPkgContext_Sizes contextSizes = {0};

  SecBuffer hash[2] = {0};

  SecBufferDesc hashDesc = {SECBUFFER_VERSION, 2, &hash};
    
  unsigned long outFlags = 0;

  unsigned long inpFlags = ISC_REQ_MUTUAL_AUTH
                         | ISC_REQ_REPLAY_DETECT
                         | ISC_REQ_CONFIDENTIALITY
                         | ISC_REQ_ALLOCATE_MEMORY
                         | ISC_REQ_DELEGATE;
  
  SECURITY_STATUS sspiCode = SEC_E_OK;
  
  SspiContext *sspi = NULL;
  
  /*
   * Get back SSPI context created in userauth_sspi_kerberos() call.
   */
   
  FAILEX(auth == NULL, "ERROR: Auth context cannot be NULL in '%s'.", __FUNCTION__);
  
  sspi = auth -> methoddata;
  
  FAILEX(sspi == NULL, "ERROR: SSPI context cannot be NULL in '%s'.", __FUNCTION__);

  /*
   * Parse input token received from server.
   * This function generates output token needed to send back to server.
   */

  debug3("InitializeSecurityContext:");
  debug3("  Credentials Handle : [%p]", &sspi -> credHandle);
  debug3("  Security Context   : [%p]", sspi -> contextHandle);
  debug3("  Target name        : [%s]", sspi -> targetName);
  debug3("  ContextReq         : [%x]", inpFlags);
  debug3("  Target Data Repr.  : [%x]", SECURITY_NATIVE_DREP);
  debug3("  Input buffer len   : [%d]", inpBuf.cbBuffer);
  debug3("  Input buffer ptr   : [%p]", inpBuf.pvBuffer);
  debug3("  Output buffer len  : [%d]", outBuf.cbBuffer);
  debug3("  Output buffer ptr  : [%p]", outBuf.pvBuffer);
  
  sspiCode = InitializeSecurityContextA(&sspi -> credHandle, sspi -> contextHandle,
                                            sspi -> targetName, inpFlags,
                                                0, SECURITY_NATIVE_DREP,
                                                    &inpBufDesc, 0, 
                                                        &sspi -> context,
                                                            &outBufDesc, 
                                                                &outFlags,
                                                                    &sspi -> expiry);

  sspi -> contextHandle = &sspi -> context;
  
  debug3("InitializeSecurityContext finished with code [0x%x][%s].",
             sspiCode, SspiGetCodeName(sspiCode));             
  
  switch(sspiCode)
  {
    /*
     * Handshake completed. 
     * Prepare MIC, sign it and send to server.
     * After server will accept our hash authentication is completed.
     */
     
    case SEC_E_OK:
    {
      debug3("[SEC_E_OK]");
    
      SSPI_FAIL(QueryContextAttributesA(&sspi -> context, 
                                            SECPKG_ATTR_SIZES, &contextSizes));
    
      /*
       * Build plain message.
       */
     
      debug3("Building mic...");
    
      ssh_gssapi_buildmic(&mic, auth -> server_user, 
                              auth -> service, "gssapi-with-mic");
    
      /*
       * Sign message into hash.
       */
     
      debug3("Signing [%d] bytes mic...", buffer_len(&mic));
    
      hash[0].BufferType = SECBUFFER_DATA;
      hash[0].cbBuffer   = buffer_len(&mic);
      hash[0].pvBuffer   = buffer_ptr(&mic);;
    
      hash[1].BufferType = SECBUFFER_TOKEN;
      hash[1].cbBuffer   = contextSizes.cbMaxSignature;
      hash[1].pvBuffer   = calloc(contextSizes.cbMaxSignature, 1);

      SSPI_FAIL(MakeSignature(&sspi -> context, 0, &hashDesc, 0));
     
      /*
       * Send signed message (hash) to server.
       */

      debug3("Sending [%d] bytes hash...", hash[1].cbBuffer);
    
      packet_start(SSH2_MSG_USERAUTH_GSSAPI_MIC);
        
      packet_put_string(hash[1].pvBuffer, hash[1].cbBuffer);

      packet_send();

      buffer_free(&mic);

      break;
    }
    
    /*
     * Handshake is in progress. 
     * Send next partial packet to server.
     */
     
    case SEC_I_CONTINUE_NEEDED:
    {
      debug3("[SEC_I_CONTINUE_NEEDED]");

      packet_start(SSH2_MSG_USERAUTH_GSSAPI_TOKEN);
   
      debug3("Sending [%d] bytes token...", outBuf.cbBuffer);

      packet_put_string(outBuf.pvBuffer, outBuf.cbBuffer);
   
      packet_send();

      break;
    }

    /*
     * Unexpected code. Treat as error.
     * Tell server that something fail.
     */
     
    default:
    {
      error("Unhandled code [%x].", sspiCode);
  
      packet_start(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK);

      packet_send();
      
      goto fail;
    }
  }  
  
  /*
   * Clean up.
   */

  exitCode = 0;
   
  fail:
  
  if (exitCode)
  {
    error("ERROR: Cannot process SSH2_MSG_USERAUTH_GSSAPI_TOKEN packet.\n"
              "SSPI code is : 0x%x / [%s].\nWINAPI code is : %d.", 
                  sspiCode, SspiGetCodeName(sspiCode), GetLastError());
  }
  
  buffer_free(&mic);
  
  if (hash[1].pvBuffer)
  {
    free(hash[1].pvBuffer);
  }

  FreeContextBuffer(outBuf.pvBuffer);
  
  debug3("<- SspiProcessToken()...");
  
  return exitCode;
}

/*
 * Process SSH2_MSG_USERAUTH_GSSAPI_RESPONSE packet sent by server
 * as response for SSH2_MSG_USERAUTH_REQUEST.
 * Shoud called one time.
 *
 * type - UNUSED.
 * plen - UNUSED.
 * ctxt - User auth context (IN/OUT).
 */

void input_sspi_kerberos_response(int type, u_int32_t plen, void *ctxt)
{
  debug3("-> input_sspi_kerberos_response()...");

  debug3("SSH2_MSG_USERAUTH_REQUEST packet received.");

  Authctxt *auth = ctxt;

  SspiContext *sspi = NULL;
  
  int oidlen = 0;
  
  char *oid = NULL;

  int exitCode = -1;
  
  SECURITY_STATUS sspiCode = SEC_E_OK;
  
  /*
   * Get back SSPI context created in userauth_sspi_kerberos() call.
   */
   
  sspi = auth -> methoddata;
  
  FAILEX(sspi == NULL, 
             "ERROR: SSPI context cannot"" be NULL in '%s'.", 
                 __FUNCTION__);
   
  /*
   * Read OID from server.
   */
   
  oid = packet_get_string(&oidlen);
  
  debug3("Received [%d] bytes OID.", oidlen);

  /*
   * Verify is OID correct.
   * If all ok, server should response the same OID, which
   * we sent in userauth_sspi_kerberos() call.
   */

  FAILEX(oidlen <= 2, "ERROR: OID too short.");

  FAILEX(oid[0] != SSH_GSS_OIDTYPE, "ERROR: Wrong OID's type.");

  FAILEX(oid[1] != oidlen - 2, "ERROR: Wrong OID's len field.");

  FAILEX(oidlen != sspi -> oidOutLen, "ERROR: OID's len mismatch.");

  FAILEX(memcmp(oid, sspi -> oidOut, oidlen), "ERROR: OID's data mismatch.");

  /*
   * Eat remaining packet's data if any.
   * Must called to save integrity on incoming network data.
   */

  packet_check_eom();
  
  /*
   * Here, we know server knows and accepted request to
   * perform kerberos5 auth.
   */

  /*
   * Get creadentials ticket from local SSPI/Kerberos cache.
   */

  debug3("Acquiring SSPI/Kerberos credentials...");
    
  SSPI_FAIL(AcquireCredentialsHandleA(NULL, "Kerberos",
                                          SECPKG_CRED_OUTBOUND,
                                              NULL, NULL, NULL, NULL,
                                                  &sspi -> credHandle,
                                                      &sspi -> expiry));

  debug3("Acquired SSPI/Kerberos creentials [%p].", sspi -> credHandle);
  
  /*
   * Start auth negotiation.
   * Get first outgoing packet to set to server from SSPI.
   */
  
  FAIL(SspiProcessToken(NULL, 0, auth));
  
  /*
   * Clean up.
   */
   
  exitCode = 0;

  fail:  

  if (exitCode)
  {
    error("ERROR: Cannot process SSH2_MSG_USERAUTH_GSSAPI_RESPONSE packet.\n"
              "SSPI code is : 0x%x / [%s].\nWINAPI code is : %d.", 
                  sspiCode, SspiGetCodeName(sspiCode), GetLastError());

    /*
     * If current method fails, try next one.
     */
     
    userauth(auth, NULL);
  }  

  free(oid);
  
  debug3("<- input_sspi_kerberos_response()...");
}

#endif /* WIN32_FIXME */
