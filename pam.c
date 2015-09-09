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

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include "includes.h"
#include "log.h"

#include "pam.h"


static PamDispatch _PamDispatch = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static void *_hLibrary = NULL;

static int symbolLoadFailed()
{
  char* serror = dlerror();

  if(serror)
  {
    error("Load PAM library: %s", serror);

    unloadPAM();
    
    return 1;
  }

  return 0;
}


int initPAM(const char *path)
{
  /*
   * Default paths if not specified.
   */
   
  #ifdef __linux__  
  char libpath[64] = "/usr/lib/libpam.so";
  #elif __APPLE__
  char libpath[64] = "/usr/lib/libpam.dylib";
  #endif

  if (path != NULL)
  {
    if (strlen(path) > 63)
    {
      error("invalid library path: the path is to long (>63)!");

      return 0;
    }
    else
    {
      strcpy(libpath, path);
    }
  }

  _hLibrary = dlopen(libpath, RTLD_LAZY);

  if (!_hLibrary)
  {
    error("%s", dlerror());

    return 0;
  }

  debug("PAM library loaded!");

  _PamDispatch.pam_start = dlsym(_hLibrary, "pam_start");
  
  if (symbolLoadFailed())
  {
    return 0;
  }
  
  debug("symbol <pam_start> loaded!");

  _PamDispatch.pam_end = dlsym(_hLibrary, "pam_end");
  
  if (symbolLoadFailed())
  {
    return 0;
  }
  debug("symbol <pam_end> loaded!");

  _PamDispatch.pam_setcred = dlsym(_hLibrary, "pam_setcred");
  
  if (symbolLoadFailed())
  {
    return 0;
  }
  debug("symbol <pam_setcred> loaded!");

  _PamDispatch.pam_strerror = dlsym(_hLibrary, "pam_strerror");
  
  if (symbolLoadFailed())
  {
    return 0;
  }
  
  debug("symbol <pam_strerror> loaded!");

  _PamDispatch.pam_set_item = dlsym(_hLibrary, "pam_set_item");
  
  if (symbolLoadFailed())
  {
    return 0;
  }
  
  debug("symbol <pam_set_item> loaded!");

  _PamDispatch.pam_authenticate = dlsym(_hLibrary, "pam_authenticate");
  
  if (symbolLoadFailed())
  {
    return 0;
  }
  debug("symbol <pam_authenticate> loaded!");

  _PamDispatch.pam_chauthtok = dlsym(_hLibrary, "pam_chauthtok");
  
  if (symbolLoadFailed())
  {
    return 0;
  }
  
  debug("symbol <pam_chauthtok> loaded!");

  _PamDispatch.pam_getenvlist = dlsym(_hLibrary, "pam_getenvlist");
  
  if (symbolLoadFailed())
  {
    return 0;
  }
  
  debug("symbol <pam_getenvlist> loaded!");

  _PamDispatch.pam_close_session = dlsym(_hLibrary, "pam_close_session");
  
  if (symbolLoadFailed())
  {
    return 0;
  }
  
  debug("symbol <pam_close_session> loaded!");

  _PamDispatch.pam_putenv = dlsym(_hLibrary, "pam_putenv");
  
  if (symbolLoadFailed())
  {
    return 0;
  }
  
  debug("symbol <pam_putenv> loaded!");

  _PamDispatch.pam_acct_mgmt = dlsym(_hLibrary, "pam_acct_mgmt");
  
  if (symbolLoadFailed())
  {
    return 0;
  }
  debug("symbol <pam_acct_mgmt> loaded!");

  _PamDispatch.pam_get_item = dlsym(_hLibrary, "pam_get_item");
  
  if (symbolLoadFailed())
  {
    return 0;
  }
  
  debug("symbol <pam_get_item> loaded!");

  _PamDispatch.pam_open_session = dlsym(_hLibrary, "pam_open_session");
  
  if (symbolLoadFailed())
  {
    return 0;
  }
  
  debug("symbol <pam_open_session> loaded!");
  
  
  return 1;
}

void unloadPAM()
{
  if(_hLibrary)
  {
    dlclose(_hLibrary);
  
    _hLibrary = NULL;
    
    debug("libpam unloaded!");
  }
}

//
// Wrapper functions for libpam symbols
//

const char* pam_strerror(pam_handle_t *pamh, int errnum)
{
  return _PamDispatch.pam_strerror(pamh,errnum);
}

int PAM_NONNULL((1,3,4)) pam_start(const char *service_name,const char *user,
                                       const struct pam_conv *pam_conversation,
                                           pam_handle_t **pamh)
{
  return _PamDispatch.pam_start(service_name,user,pam_conversation,pamh);
}

int PAM_NONNULL((1)) pam_end(pam_handle_t *pamh, int pam_status)
{
  return _PamDispatch.pam_end(pamh,pam_status);
}

int PAM_NONNULL((1)) pam_setcred(pam_handle_t *pamh, int flags)
{
  return _PamDispatch.pam_setcred(pamh,flags);
}

int PAM_NONNULL((1)) pam_set_item(pam_handle_t *pamh,int item_type,
                                      const void *item)
{
  return _PamDispatch.pam_set_item(pamh,item_type,item);
}

int PAM_NONNULL((1)) pam_authenticate(pam_handle_t *pamh, int flags)
{
  return _PamDispatch.pam_authenticate(pamh,flags);
}

int PAM_NONNULL((1)) pam_chauthtok(pam_handle_t *pamh, int flags)
{
  return _PamDispatch.pam_chauthtok(pamh,flags);
}

char** PAM_NONNULL((1)) pam_getenvlist(pam_handle_t *pamh)
{
  return _PamDispatch.pam_getenvlist(pamh);
}

int PAM_NONNULL((1)) pam_close_session(pam_handle_t *pamh, int flags)
{
  return _PamDispatch.pam_close_session(pamh,flags);
}

int PAM_NONNULL((1,2)) pam_putenv(pam_handle_t *pamh, const char *name_value)
{
  return _PamDispatch.pam_putenv(pamh,name_value);
}

int PAM_NONNULL((1)) pam_acct_mgmt(pam_handle_t *pamh, int flags)
{
  return _PamDispatch.pam_acct_mgmt(pamh,flags);
}

int PAM_NONNULL((1)) pam_get_item(const pam_handle_t *pamh,int item_type,
                                      const void **item)
{
  return _PamDispatch.pam_get_item(pamh,item_type,item);
}

int PAM_NONNULL((1)) pam_open_session(pam_handle_t *pamh, int flags)
{
  return _PamDispatch.pam_open_session(pamh,flags);
}

#endif /* RUNTIME_LIBPAM */
