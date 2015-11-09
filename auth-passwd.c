/* $OpenBSD: auth-passwd.c,v 1.44 2014/07/15 15:54:14 millert Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Password authentication.  This file contains the functions to check whether
 * the password is valid for the user.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 1999 Dug Song.  All rights reserved.
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
#include "xmalloc.h"
#endif

/*
 * We support only client side kerberos on Windows.
 */

#ifdef WIN32_FIXME
  #undef GSSAPI
  #undef KRB5
#endif

#include <sys/types.h>

#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "packet.h"
#include "buffer.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "key.h"
#include "hostfile.h"
#include "auth.h"
#include "auth-options.h"

extern Buffer loginmsg;
extern ServerOptions options;

#ifdef HAVE_LOGIN_CAP
extern login_cap_t *lc;
#endif


#define DAY		(24L * 60 * 60) /* 1 day in seconds */
#define TWO_WEEKS	(2L * 7 * DAY)	/* 2 weeks in seconds */

void
disable_forwarding(void)
{
	no_port_forwarding_flag = 1;
	no_agent_forwarding_flag = 1;
	no_x11_forwarding_flag = 1;
}

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
int
auth_password(Authctxt *authctxt, const char *password)
{
	struct passwd * pw = authctxt->pw;
	int result, ok = authctxt->valid;
#if defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	static int expire_checked = 0;
#endif

#ifndef HAVE_CYGWIN
	if (pw->pw_uid == 0 && options.permit_root_login != PERMIT_YES)
		ok = 0;
#endif
	if (*password == '\0' && options.permit_empty_passwd == 0)
		return 0;

#ifdef KRB5
	if (options.kerberos_authentication == 1) {
		int ret = auth_krb5_password(authctxt, password);
		if (ret == 1 || ret == 0)
			return ret && ok;
		/* Fall back to ordinary passwd authentication. */
	}
#endif
#ifdef HAVE_CYGWIN
	{
		HANDLE hToken = cygwin_logon_user(pw, password);

		if (hToken == INVALID_HANDLE_VALUE)
			return 0;
		cygwin_set_impersonation_token(hToken);
		return ok;
	}
#endif
#ifdef USE_PAM
	if (options.use_pam)
		return (sshpam_auth_passwd(authctxt, password) && ok);
#endif
#if defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	if (!expire_checked) {
		expire_checked = 1;
		if (auth_shadow_pwexpired(authctxt))
			authctxt->force_pwchange = 1;
	}
#endif
	result = sys_auth_passwd(authctxt, password);
	if (authctxt->force_pwchange)
		disable_forwarding();
	return (result && ok);
}

#ifdef BSD_AUTH
static void
warn_expiry(Authctxt *authctxt, auth_session_t *as)
{
	char buf[256];
	quad_t pwtimeleft, actimeleft, daysleft, pwwarntime, acwarntime;

	pwwarntime = acwarntime = TWO_WEEKS;

	pwtimeleft = auth_check_change(as);
	actimeleft = auth_check_expire(as);
#ifdef HAVE_LOGIN_CAP
	if (authctxt->valid) {
		pwwarntime = login_getcaptime(lc, "password-warn", TWO_WEEKS,
		    TWO_WEEKS);
		acwarntime = login_getcaptime(lc, "expire-warn", TWO_WEEKS,
		    TWO_WEEKS);
	}
#endif
	if (pwtimeleft != 0 && pwtimeleft < pwwarntime) {
		daysleft = pwtimeleft / DAY + 1;
		snprintf(buf, sizeof(buf),
		    "Your password will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s");
		buffer_append(&loginmsg, buf, strlen(buf));
	}
	if (actimeleft != 0 && actimeleft < acwarntime) {
		daysleft = actimeleft / DAY + 1;
		snprintf(buf, sizeof(buf),
		    "Your account will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s");
		buffer_append(&loginmsg, buf, strlen(buf));
	}
}

int
sys_auth_passwd(Authctxt *authctxt, const char *password)
{
	struct passwd *pw = authctxt->pw;
	auth_session_t *as;
	static int expire_checked = 0;

	as = auth_usercheck(pw->pw_name, authctxt->style, "auth-ssh",
	    (char *)password);
	if (as == NULL)
		return (0);
	if (auth_getstate(as) & AUTH_PWEXPIRED) {
		auth_close(as);
		disable_forwarding();
		authctxt->force_pwchange = 1;
		return (1);
	} else {
		if (!expire_checked) {
			expire_checked = 1;
			warn_expiry(authctxt, as);
		}
		return (auth_close(as));
	}
}

#elif defined(WIN32_FIXME)
int sys_auth_passwd(Authctxt *authctxt, const char *password)
{
  /* 
   * Authenticate on Windows 
   */
   
  struct passwd *pw = authctxt -> pw;

  HANDLE hToken = INVALID_HANDLE_VALUE;
  
  BOOL worked = FALSE;
  
  LPWSTR user_UTF16     = NULL;
  LPWSTR password_UTF16 = NULL;
  LPWSTR domain_UTF16   = NULL;

  int buffer_size = 0;
  
  /*
   * Identify domain or local login.
   */
   
  domain_UTF16 = strchr(authctxt -> user, '@') ? NULL : L".";
  
  authctxt -> methoddata = hToken;
 
  if (domain_UTF16 == NULL)
  {
    debug3("Using domain logon...");
  }
  
  /*
   * Convert username from UTF-8 to UTF-16
   */
 
  buffer_size = MultiByteToWideChar(CP_UTF8, 0, authctxt -> user, -1, NULL, 0);

  if (buffer_size > 0)
  {
    user_UTF16 = xmalloc(4 * buffer_size);
  }
  else
  {
    return 0;
  }
  
  if (0 == MultiByteToWideChar(CP_UTF8, 0, authctxt -> user,
                                   -1, user_UTF16, buffer_size))
  {
    free(user_UTF16);

    return 0;
  }

  /*
   * Convert password from UTF-8 to UTF-16
   */
  
  buffer_size = MultiByteToWideChar(CP_UTF8, 0, password, -1, NULL, 0);

  if (buffer_size > 0)
  {
    password_UTF16 = xmalloc(4 * buffer_size);
  }
  else
  {
    return 0;
  }
  
  if (0 == MultiByteToWideChar(CP_UTF8, 0, password, -1, 
                                   password_UTF16 , buffer_size))
  {
    free(password_UTF16 );

    return 0;
  }

  /*
   * First, try logon in INTERACTIVE mode.
   */
  
  worked = LogonUserW(user_UTF16, domain_UTF16, password_UTF16,
                         LOGON32_LOGON_INTERACTIVE, 
                             LOGON32_PROVIDER_DEFAULT, &hToken);
                             
  /*
   * If no success, try NETWORK mode.
   */
   
  if (!worked)
  {
    HANDLE weakToken = INVALID_HANDLE_VALUE;
    
    debug3("Netork login attemp [%s][%ls]...", 
               authctxt -> user, domain_UTF16);
    
    worked = LogonUserW(user_UTF16, domain_UTF16, password_UTF16,
                           LOGON32_LOGON_NETWORK,
                               LOGON32_PROVIDER_DEFAULT, &weakToken);

    if (worked)
    {
      debug("Duplicating token...");
  
      debug3(DuplicateTokenEx(weakToken, MAXIMUM_ALLOWED,
                                  NULL, SecurityImpersonation,
                                      TokenPrimary, &hToken) == 0);
    }                                  
  }
  
  free(user_UTF16);
  free(password_UTF16);
  
  /*
   * If login still fails, go out.
   */
   
  if (!worked || hToken == INVALID_HANDLE_VALUE)
  {
    return 0;
  }

  /*
   * Make sure this can be inherited for when 
   * we start shells or commands.
   */
  
  worked = SetHandleInformation(hToken, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
  
  if (!worked)
  {
    CloseHandle(hToken);
    
    hToken = INVALID_HANDLE_VALUE;
    
    authctxt -> methoddata = hToken;

    return 0;
  }

  /*
   * Save the handle (or invalid handle) as method-specific data.
   */
   
  authctxt -> methoddata = hToken;

  return 1;
}

#elif !defined(CUSTOM_SYS_AUTH_PASSWD)
int
sys_auth_passwd(Authctxt *authctxt, const char *password)
{
	struct passwd *pw = authctxt->pw;
	char *encrypted_password;

	/* Just use the supplied fake password if authctxt is invalid */
	char *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	/* Check for users with no password. */
	if (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		return (1);

	/* Encrypt the candidate password using the proper salt. */
	encrypted_password = xcrypt(password,
	    (pw_password[0] && pw_password[1]) ? pw_password : "xx");

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
	return encrypted_password != NULL &&
	    strcmp(encrypted_password, pw_password) == 0;
}
#endif
