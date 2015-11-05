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

#include "kerberos.h"

/*
 * Handles to runtime loaded MIT KfW libraries.
 */
 
static HMODULE Krb5_32  = NULL;
static HMODULE Comerr32 = NULL;
static HMODULE Gssapi32 = NULL;

/*
 * Pointers to runtime loaded KfW functions.
 */

static struct _MitDispatch
{
  /*
   * gssapi32.dll.
   */
   
  gss_indicate_mechs_ptr gss_indicate_mechs;
  gss_release_buffer_ptr gss_release_buffer;
  gss_display_status_ptr gss_display_status;
  gss_delete_sec_context_ptr gss_delete_sec_context;
  gss_release_name_ptr gss_release_name;
  gss_release_cred_ptr gss_release_cred;
  gss_init_sec_context_ptr gss_init_sec_context;
  gss_import_name_ptr gss_import_name;
  gss_get_mic_ptr gss_get_mic;

  /*
   * krb5_32.dll.
   */

  krb5_free_context_ptr krb5_free_context;
  krb5_free_principal_ptr krb5_free_principal;
  krb5_cc_destroy_ptr krb5_cc_destroy;
} MitDispatch = {0};

/*
 * This global variable is exported by gssapi32.dll.
 */
 
gss_OID gss_nt_service_name;

/*
 * Try loads MIT Kerberos for Windows libraries. This function  
 * must be called before use Kerberos functions.
 *
 * RETURNS: 0 if OK.
 */
 
int InitMitKerberos()
{
  int exitCode = -1;

  void *serviceNamePtr = NULL;
  
  
  /*
   * Load functions from gssapi32.dll.
   */

  debug("Loading gssapi32.dll...");
  
  FAIL((Gssapi32 = LoadLibrary("gssapi32.dll")) == NULL);
  
  FAIL((GET_MIT_FUNCTION(Gssapi32, gss_indicate_mechs)) == NULL);
  FAIL((GET_MIT_FUNCTION(Gssapi32, gss_release_buffer)) == NULL);
  FAIL((GET_MIT_FUNCTION(Gssapi32, gss_display_status)) == NULL);
  FAIL((GET_MIT_FUNCTION(Gssapi32, gss_delete_sec_context)) == NULL);
  FAIL((GET_MIT_FUNCTION(Gssapi32, gss_release_name)) == NULL);
  FAIL((GET_MIT_FUNCTION(Gssapi32, gss_release_cred)) == NULL);
  FAIL((GET_MIT_FUNCTION(Gssapi32, gss_init_sec_context)) == NULL);
  FAIL((GET_MIT_FUNCTION(Gssapi32, gss_import_name)) == NULL);
  FAIL((GET_MIT_FUNCTION(Gssapi32, gss_get_mic)) == NULL);

  /*
   * This is global variable exported by gssapi32.dll.
   * Note, that we reveive POINTER not VALUE, so we need to
   * do memcpy in this case.
   */
   
  serviceNamePtr = GetProcAddress(Gssapi32, "gss_nt_service_name");
  
  FAIL(serviceNamePtr == NULL);
  
  memcpy(&gss_nt_service_name, serviceNamePtr, sizeof(gss_OID));
  
  /*
   * Load functions from krb5_32.dll.
   */
  
  debug("Loading krb5_32.dll...");
  
  FAIL((Krb5_32 = (HMODULE) LoadLibrary("krb5_32.dll")) == NULL);
  
  FAIL((GET_MIT_FUNCTION(Krb5_32, krb5_free_context)) == NULL);
  FAIL((GET_MIT_FUNCTION(Krb5_32, krb5_free_principal)) == NULL);
  FAIL((GET_MIT_FUNCTION(Krb5_32, krb5_cc_destroy)) == NULL);

  /*
   * Error handler.
   */
   
  exitCode = 0;

  fail:
  
  if (exitCode)
  {
    UninitMitKerberos();
    
    error("Cannot load MIT KfW libraries. Error code is: %u.\n"
              "Please ensure that path to these libraries is properly "
                  "set in your PATH variable.\n", GetLastError());
  }
  
  return exitCode;
}

/*
 * Free MIT KfW libraries if loaded before.
 */
 
void UninitMitKerberos()
{
  FreeLibrary(Krb5_32);
  FreeLibrary(Comerr32);
  FreeLibrary(Gssapi32);
}

/*
 * Fake GSSAPI functions. We pass control to runtime loaded
 * KfW libs here.
 */

OM_uint32 KRB5_CALLCONV gss_indicate_mechs(OM_uint32 *a, gss_OID_set *b)
{
  return MitDispatch.gss_indicate_mechs(a, b);
}

OM_uint32 KRB5_CALLCONV gss_release_buffer(OM_uint32 *a, gss_buffer_t b)
{
  return MitDispatch.gss_release_buffer(a, b);
}

OM_uint32 KRB5_CALLCONV gss_display_status(OM_uint32 *a, OM_uint32 b, int c, gss_OID d,
                                OM_uint32 *e, gss_buffer_t f)
{
  return MitDispatch.gss_display_status(a, b, c, d, e, f);
}

OM_uint32 KRB5_CALLCONV gss_delete_sec_context(OM_uint32 *a, gss_ctx_id_t *b, gss_buffer_t c)
{
  return MitDispatch.gss_delete_sec_context(a, b, c);
}

OM_uint32 KRB5_CALLCONV gss_release_name(OM_uint32 *a, gss_name_t *b)
{
  return MitDispatch.gss_release_name(a, b);
}

OM_uint32 KRB5_CALLCONV gss_release_cred(OM_uint32 *a, gss_cred_id_t *b)
{
  return MitDispatch.gss_release_cred(a, b);
}

OM_uint32 KRB5_CALLCONV gss_init_sec_context(OM_uint32 *a, gss_cred_id_t b,
                                  gss_ctx_id_t *c, gss_name_t d,
                                      gss_OID e, OM_uint32 f,
                                          OM_uint32 g, gss_channel_bindings_t h,
                                              gss_buffer_t i, gss_OID * j,
                                                  gss_buffer_t k, OM_uint32 *l,
                                                      OM_uint32 *m)
{
  return MitDispatch.gss_init_sec_context(a, b, c, d, e, f, g, h, i, j, k, l, m);
}

OM_uint32 KRB5_CALLCONV gss_import_name(OM_uint32 *a, gss_buffer_t b, gss_OID c, gss_name_t *d)
{
  return MitDispatch.gss_import_name(a, b, c, d);
}

OM_uint32 KRB5_CALLCONV gss_get_mic(OM_uint32 *a, gss_ctx_id_t b, gss_qop_t c,
                         gss_buffer_t d, gss_buffer_t e)
{
  return MitDispatch.gss_get_mic(a, b, c, d, e);
}

/*
 * Fake KRB5 functions. We pass control to runtime loaded
 * KfW libs here.
 */

void KRB5_CALLCONV krb5_free_context(krb5_context a)
{
  MitDispatch.krb5_free_context(a);
}

void KRB5_CALLCONV krb5_free_principal(krb5_context a, krb5_principal b)
{
  MitDispatch.krb5_free_principal(a, b);
}

krb5_error_code KRB5_CALLCONV krb5_cc_destroy(krb5_context a, krb5_ccache b)
{
  return MitDispatch.krb5_cc_destroy(a, b);
}
