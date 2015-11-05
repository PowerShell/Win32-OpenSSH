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

#ifndef Kerberos_H
#define Kerberos_H

#include "Debug.h"
#include <winsock2.h>
#include <windows.h>
#include <krb5.h>
#include <gssapi/gssapi.h>

int InitMitKerberos();
void UninitMitKerberos();

/*
 * Helper macros for load functions from KfW DLLs and
 * put it to MitDispatch table, where we store KfW API functions.
 */
 
#define GET_SYM(MODULE, F) (F ## _ptr) GetProcAddress(MODULE, #F)
#define GET_MIT_FUNCTION(MODULE, F) MitDispatch.F = GET_SYM(MODULE, F)

/*
 * Function prototypes for MIT KfW libs. We need it
 * for load libs at runtime. Note, we add only functions
 * needed by ssh client here.
 */
 
#define KFW_CALL OM_uint32 KRB5_CALLCONV

typedef KFW_CALL (*gss_indicate_mechs_ptr)(OM_uint32 *, gss_OID_set *);
typedef KFW_CALL (*gss_release_buffer_ptr)(OM_uint32 *, gss_buffer_t);

typedef KFW_CALL (*gss_display_status_ptr)(OM_uint32 *, OM_uint32, int, 
                                       gss_OID, OM_uint32 *, gss_buffer_t);

typedef KFW_CALL (*gss_delete_sec_context_ptr)(OM_uint32 *, gss_ctx_id_t *, 
                                           gss_buffer_t);

typedef KFW_CALL (*gss_release_name_ptr)(OM_uint32 *, gss_name_t *);
typedef KFW_CALL (*gss_release_cred_ptr)(OM_uint32 *, gss_cred_id_t *);

typedef KFW_CALL (*gss_init_sec_context_ptr)(OM_uint32 *, gss_cred_id_t,
                                         gss_ctx_id_t *, gss_name_t,
                                             gss_OID, OM_uint32, OM_uint32, 
                                                 gss_channel_bindings_t,
                                                     gss_buffer_t, gss_OID *,
                                                         gss_buffer_t, OM_uint32 *,
                                                             OM_uint32 *);

typedef KFW_CALL (*gss_import_name_ptr)(OM_uint32 *, gss_buffer_t, 
                                            gss_OID, gss_name_t *);

typedef OM_uint32 KRB5_CALLCONV (*gss_get_mic_ptr)(OM_uint32 *, gss_ctx_id_t, 
                                                       gss_qop_t, gss_buffer_t, 
                                                           gss_buffer_t);

typedef void KRB5_CALLCONV (*krb5_free_context_ptr)(krb5_context);

typedef void KRB5_CALLCONV (*krb5_free_principal_ptr)(krb5_context,
                                                          krb5_principal);
                                                          
typedef krb5_error_code KRB5_CALLCONV (*krb5_cc_destroy_ptr)(krb5_context, 
                                                                 krb5_ccache);

#endif
