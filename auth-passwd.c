/* $OpenBSD: auth-passwd.c,v 1.45 2016/07/21 01:39:35 dtucker Exp $ */
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
#include "authfd.h"

#ifdef WINDOWS
#include "logonuser.h"
#include "monitor_wrap.h"
#endif

extern Buffer loginmsg;
extern ServerOptions options;

#ifdef HAVE_LOGIN_CAP
extern login_cap_t *lc;
#endif


#define DAY		(24L * 60 * 60) /* 1 day in seconds */
#define TWO_WEEKS	(2L * 7 * DAY)	/* 2 weeks in seconds */

#define MAX_PASSWORD_LEN	1024

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

	if (strlen(password) > MAX_PASSWORD_LEN)
		return 0;

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
#elif !defined(CUSTOM_SYS_AUTH_PASSWD)
int
sys_auth_passwd(Authctxt *authctxt, const char *password)
{
	struct passwd *pw = authctxt->pw;
	char *encrypted_password, *salt = NULL;

	/* Just use the supplied fake password if authctxt is invalid */
	char *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	/* Check for users with no password. */
	if (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		return (1);

	/*
	 * Encrypt the candidate password using the proper salt, or pass a
	 * NULL and let xcrypt pick one.
	 */
	if (authctxt->valid && pw_password[0] && pw_password[1])
		salt = pw_password;
	encrypted_password = xcrypt(password, salt);

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
	return encrypted_password != NULL &&
	    strcmp(encrypted_password, pw_password) == 0;
}

#elif defined(WINDOWS)
HANDLE password_auth_token = NULL;
HANDLE process_custom_lsa_auth(const char*, const char*, const char*);

void 
sys_auth_passwd_lsa(Authctxt *authctxt, const char *password)
{
	char  *lsa_auth_pkg = NULL;
	wchar_t *lsa_auth_pkg_w = NULL;
	int domain_len = 0, lsa_auth_pkg_len = 0;	
	HKEY reg_key = 0;
	REGSAM mask = STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_WOW64_64KEY;
		
	if ((RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\OpenSSH", 0, mask, &reg_key) == ERROR_SUCCESS) &&
		(RegQueryValueExW(reg_key, L"LSAAuthenticationPackage", 0, NULL, NULL, &lsa_auth_pkg_len) == ERROR_SUCCESS)) {
		lsa_auth_pkg_w = (wchar_t *) malloc(lsa_auth_pkg_len); // lsa_auth_pkg_len includes the null terminating character.
		if (!lsa_auth_pkg_w)
			fatal("%s: out of memory", __func__);

		memset(lsa_auth_pkg_w, 0, lsa_auth_pkg_len);
		if (RegQueryValueExW(reg_key, L"LSAAuthenticationPackage", 0, NULL, (LPBYTE)lsa_auth_pkg_w, &lsa_auth_pkg_len) == ERROR_SUCCESS) {
			lsa_auth_pkg = utf16_to_utf8(lsa_auth_pkg_w);
			if (!lsa_auth_pkg)
				fatal("utf16_to_utf8 failed to convert lsa_auth_pkg_w:%ls", lsa_auth_pkg_w);
			
			password_auth_token = process_custom_lsa_auth(authctxt->pw->pw_name, password, lsa_auth_pkg);
		}
	}

done:
	if (lsa_auth_pkg_w)
		free(lsa_auth_pkg_w);

	if (lsa_auth_pkg)
		free(lsa_auth_pkg);

	if (reg_key)
		RegCloseKey(reg_key);
}

/*
* Authenticate on Windows 
* - Call LogonUser and retrieve user token
* - If LogonUser fails, then try the LSA (Local Security Authority) authentication.
*/
int 
sys_auth_passwd(Authctxt *authctxt, const char *password)
{
	wchar_t *user_utf16 = NULL, *udom_utf16 = NULL, *pwd_utf16 = NULL, *tmp;
	HANDLE token = NULL;
	int r = 0;

	if ((user_utf16 = utf8_to_utf16(authctxt->pw->pw_name)) == NULL ||
	    (pwd_utf16 = utf8_to_utf16(password)) == NULL) {
		fatal("out of memory");
		goto done;
	}

	if ((tmp = wcschr(user_utf16, L'@')) != NULL) {
		udom_utf16 = tmp + 1;
		*tmp = L'\0';
	}

	if (LogonUserExExWHelper(user_utf16, udom_utf16, pwd_utf16, LOGON32_LOGON_NETWORK_CLEARTEXT,
	    LOGON32_PROVIDER_DEFAULT, NULL, &token, NULL, NULL, NULL, NULL) == TRUE)
		password_auth_token = token;
	else {
		if (GetLastError() == ERROR_PASSWORD_MUST_CHANGE)
			/*
			* TODO - need to add support to force password change
			* by sending back SSH_MSG_USERAUTH_PASSWD_CHANGEREQ
			*/
			error("password for user %s has expired", authctxt->pw->pw_name);
		else {
			debug("Windows authentication failed for user: %ls domain: %ls error:%d", user_utf16, udom_utf16, GetLastError());

			/* If LSA authentication package is configured then it will return the auth_token */
			sys_auth_passwd_lsa(authctxt, password);
		}
	}
			
done:
	if (password_auth_token)
		r = 1;

	if (user_utf16)
		free(user_utf16);

	if (pwd_utf16)
		SecureZeroMemory(pwd_utf16, sizeof(wchar_t) * wcslen(pwd_utf16));

	return r;
}
#endif   /* WINDOWS */
