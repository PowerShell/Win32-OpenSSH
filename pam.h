/*
 * Author: NoMachine <developers@nomachine.com>
 *
 * Copyright (c) 2012, 2012 NoMachine
 * All rights reserved
 *
 * Support functions for versatile PAM authentication.
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

#ifdef RUNTIME_LIBPAM

#ifndef PAM_H
#define PAM_H

#include <security/pam_appl.h>
#include <security/_pam_types.h>


int initPAM(const char* path);
void unloadPAM();


typedef const char* (*pam_strerror_ptr)(pam_handle_t *pamh, int errnum);


typedef int PAM_NONNULL((1,3,4)) (*pam_start_ptr)
                                 (const char *service_name,
                                      const char *user,
                                          const struct pam_conv *pam_conversation,
                                              pam_handle_t **pamh);

typedef int PAM_NONNULL((1)) (*pam_end_ptr)(pam_handle_t *pamh, int pam_status);

typedef int PAM_NONNULL((1)) (*pam_setcred_ptr)(pam_handle_t *pamh, int flags);

typedef int PAM_NONNULL((1)) (*pam_set_item_ptr)(pam_handle_t *pamh,
                                                     int item_type,
                                                         const void *item);

typedef int PAM_NONNULL((1)) (*pam_authenticate_ptr)(pam_handle_t *pamh, int flags);

typedef int PAM_NONNULL((1)) (*pam_chauthtok_ptr)(pam_handle_t *pamh, int flags);

typedef char** PAM_NONNULL((1)) (*pam_getenvlist_ptr)(pam_handle_t *pamh);

typedef int PAM_NONNULL((1)) (*pam_close_session_ptr)(pam_handle_t *pamh,
                                                          int flags);

typedef int PAM_NONNULL((1,2)) (*pam_putenv_ptr)(pam_handle_t *pamh,
                                                     const char *name_value);

typedef int PAM_NONNULL((1)) (*pam_acct_mgmt_ptr)(pam_handle_t *pamh, int flags);

typedef int PAM_NONNULL((1)) (*pam_get_item_ptr)(const pam_handle_t *pamh,
                                                     int item_type,
                                                         const void **item);

typedef int PAM_NONNULL((1)) (*pam_open_session_ptr)(pam_handle_t *pamh, int flags);



typedef struct
{
  pam_start_ptr pam_start;
  pam_end_ptr pam_end;
  pam_setcred_ptr pam_setcred;
  pam_strerror_ptr pam_strerror;
  pam_set_item_ptr pam_set_item;
  pam_authenticate_ptr pam_authenticate;
  pam_chauthtok_ptr pam_chauthtok;
  pam_getenvlist_ptr pam_getenvlist;
  pam_close_session_ptr pam_close_session;
  pam_putenv_ptr pam_putenv;
  pam_acct_mgmt_ptr pam_acct_mgmt;
  pam_get_item_ptr pam_get_item;
  pam_open_session_ptr pam_open_session;
} PamDispatch;


#endif // PAM_H

#endif /* RUNTIME_LIBPAM */
