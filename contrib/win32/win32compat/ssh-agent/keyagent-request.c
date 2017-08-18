/*
 * Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
 * ssh-agent implementation on Windows
 * 
 * Copyright (c) 2015 Microsoft Corp.
 * All rights reserved
 *
 * Microsoft openssh win32 port
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

#include "agent.h"
#include "agent-request.h"
#include <sddl.h>

#pragma warning(push, 3)

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

/* 
 * get registry root where keys are stored 
 * user keys are stored in user's hive
 * while system keys (host keys) in HKLM
 */
static int
get_user_root(struct agent_connection* con, HKEY *root)
{
	int r = 0;
	LONG ret;
	*root = HKEY_LOCAL_MACHINE;
	
	if (con->client_type <= ADMIN_USER) {
		if (ImpersonateLoggedOnUser(con->client_impersonation_token) == FALSE)
			return -1;
		*root = NULL;
		/* 
		 * TODO - check that user profile is loaded, 
		 * otherwise, this will return default profile 
		 */
		if ((ret = RegOpenCurrentUser(KEY_ALL_ACCESS, root)) != ERROR_SUCCESS) {
			debug("unable to open user's registry hive, ERROR - %d", ret);
			r = -1;
		}
			
		RevertToSelf();
	}
	return r;
}

static int
convert_blob(struct agent_connection* con, const char *blob, DWORD blen, char **eblob, DWORD *eblen, int encrypt) {
	int success = 0;
	DATA_BLOB in, out;
	errno_t r = 0;

	if (con->client_type <= ADMIN_USER)
		if (ImpersonateLoggedOnUser(con->client_impersonation_token) == FALSE)
			return -1;

	in.cbData = blen;
	in.pbData = (char*)blob;
	out.cbData = 0;
	out.pbData = NULL;

	if (encrypt) {
		if (!CryptProtectData(&in, NULL, NULL, 0, NULL, 0, &out)) {
			debug("cannot encrypt data");
			goto done;
		}
	} else {
		if (!CryptUnprotectData(&in, NULL, NULL, 0, NULL, 0, &out)) {
			debug("cannot decrypt data");
			goto done;
		}
	}

	*eblob = malloc(out.cbData);
	if (*eblob == NULL) 
		goto done;

	if((r = memcpy_s(*eblob, out.cbData, out.pbData, out.cbData)) != 0) {
		debug("memcpy_s failed with error: %d.", r);
		goto done;
	}
	*eblen = out.cbData;
	success = 1;
done:
	if (out.pbData)
		LocalFree(out.pbData);
	if (con->client_type <= ADMIN_USER)
		RevertToSelf();
	return success? 0: -1;
}

#define REG_KEY_SDDL L"D:P(A;; GA;;; SY)(A;; GA;;; BA)"

int
process_add_identity(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	struct sshkey* key = NULL;
	int r = 0, blob_len, eblob_len, request_invalid = 0, success = 0;
	size_t comment_len, pubkey_blob_len;
	u_char *pubkey_blob = NULL;
	char *thumbprint = NULL, *comment;
	const char *blob;
	char* eblob = NULL;
	HKEY reg = 0, sub = 0, user_root = 0;
	SECURITY_ATTRIBUTES sa;

	/* parse input request */
	memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
	blob = sshbuf_ptr(request);
	if (sshkey_private_deserialize(request, &key) != 0 ||
	   (blob_len = (sshbuf_ptr(request) - blob) & 0xffffffff) == 0 ||
	    sshbuf_peek_string_direct(request, &comment, &comment_len) != 0) {
		debug("key add request is invalid");
		request_invalid = 1;
		goto done;
	}

	memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength = sizeof(sa);
	if ((!ConvertStringSecurityDescriptorToSecurityDescriptorW(REG_KEY_SDDL, SDDL_REVISION_1, &sa.lpSecurityDescriptor, &sa.nLength)) ||
	    sshkey_to_blob(key, &pubkey_blob, &pubkey_blob_len) != 0 ||
	    convert_blob(con, blob, blob_len, &eblob, &eblob_len, 1) != 0 ||
	    ((thumbprint = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL) ||
	    get_user_root(con, &user_root) != 0 ||
	    RegCreateKeyExW(user_root, SSH_KEYS_ROOT, 0, 0, 0, KEY_WRITE | KEY_WOW64_64KEY, &sa, &reg, NULL) != 0 ||
	    RegCreateKeyExA(reg, thumbprint, 0, 0, 0, KEY_WRITE | KEY_WOW64_64KEY, &sa, &sub, NULL) != 0 ||
	    RegSetValueExW(sub, NULL, 0, REG_BINARY, eblob, eblob_len) != 0 ||
	    RegSetValueExW(sub, L"pub", 0, REG_BINARY, pubkey_blob, (DWORD)pubkey_blob_len) != 0 ||
	    RegSetValueExW(sub, L"type", 0, REG_DWORD, (BYTE*)&key->type, 4) != 0 ||
	    RegSetValueExW(sub, L"comment", 0, REG_BINARY, comment, (DWORD)comment_len) != 0 ) {
		debug("failed to add key to store");
		goto done;
	}

	debug("added key to store");
	success = 1;
done:
	r = 0;
	if (request_invalid)
		r = -1;
	else if (sshbuf_put_u8(response, success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE) != 0)
		r = -1;

	/* delete created reg key if not succeeded*/
	if ((success == 0) && reg && thumbprint)
		RegDeleteKeyExA(reg, thumbprint, KEY_WOW64_64KEY, 0);

	if (eblob)
		free(eblob);
	if (sa.lpSecurityDescriptor)
		LocalFree(sa.lpSecurityDescriptor);
	if (key)
		sshkey_free(key);
	if (thumbprint)
		free(thumbprint);
	if (user_root)
		RegCloseKey(user_root);
	if (reg)
		RegCloseKey(reg);
	if (sub)
		RegCloseKey(sub);
	if (pubkey_blob)
		free(pubkey_blob);
	return r;
}

static int sign_blob(const struct sshkey *pubkey, u_char ** sig, size_t *siglen,
	const u_char *blob, size_t blen, u_int flags, struct agent_connection* con) 
{
	HKEY reg = 0, sub = 0, user_root = 0;
	int r = 0, success = 0;
	struct sshkey* prikey = NULL;
	char *thumbprint = NULL, *regdata = NULL;
	DWORD regdatalen = 0, keyblob_len = 0;
	struct sshbuf* tmpbuf = NULL;
	char *keyblob = NULL;

	*sig = NULL;
	*siglen = 0;

	if ((thumbprint = sshkey_fingerprint(pubkey, SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL ||
	    get_user_root(con, &user_root) != 0 ||
	    RegOpenKeyExW(user_root, SSH_KEYS_ROOT,
			0, STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS, &reg) != 0 ||
	    RegOpenKeyExA(reg, thumbprint, 0,
			STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &sub) != 0 ||
	    RegQueryValueExW(sub, NULL, 0, NULL, NULL, &regdatalen) != ERROR_SUCCESS ||
	    (regdata = malloc(regdatalen)) == NULL ||
	    RegQueryValueExW(sub, NULL, 0, NULL, regdata, &regdatalen) != ERROR_SUCCESS ||
	    convert_blob(con, regdata, regdatalen, &keyblob, &keyblob_len, FALSE) != 0 ||
	    (tmpbuf = sshbuf_from(keyblob, keyblob_len)) == NULL)
		goto done;

	if (sshkey_private_deserialize(tmpbuf, &prikey) != 0 ||
	    sshkey_sign(prikey, sig, siglen, blob, blen, NULL, 0) != 0) {
		debug("cannot sign using retrieved key");
		goto done;
	}

	success = 1;

done:
	if (keyblob)
		free(keyblob);
	if (regdata)
		free(regdata);
	if (tmpbuf)
		sshbuf_free(tmpbuf);
	if (prikey)
		sshkey_free(prikey);
	if (thumbprint)
		free(thumbprint);
	if (user_root)
		RegCloseKey(user_root);
	if (reg)
		RegCloseKey(reg);
	if (sub)
		RegCloseKey(sub);

	return success ? 0 : -1;
}

int
process_sign_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	u_char *blob, *data, *signature = NULL;
	size_t blen, dlen, slen = 0;
	u_int flags = 0;
	int r, request_invalid = 0, success = 0;
	struct sshkey *key = NULL;

	if (sshbuf_get_string_direct(request, &blob, &blen) != 0 ||
	    sshbuf_get_string_direct(request, &data, &dlen) != 0 ||
	    sshbuf_get_u32(request, &flags) != 0 ||
	    sshkey_from_blob(blob, blen, &key) != 0) {
		debug("sign request is invalid");
		request_invalid = 1;
		goto done;
	}

	/* TODO - flags?*/

	if (sign_blob(key, &signature, &slen, data, dlen, 0, con) != 0)
		goto done;

	success = 1;
done:
	r = 0;
	if (request_invalid)
		r = -1;
	else {
		if (success) {
			if (sshbuf_put_u8(response, SSH2_AGENT_SIGN_RESPONSE) != 0 ||
			    sshbuf_put_string(response, signature, slen) != 0) {
				r = -1;
			}
		} else
			if (sshbuf_put_u8(response, SSH_AGENT_FAILURE) != 0)
				r = -1;
	}

	if (key)
		sshkey_free(key);
	if (signature)
		free(signature);
	return r;
}

int
process_remove_key(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	HKEY user_root = 0, root = 0;
	char *blob, *thumbprint = NULL;
	size_t blen;
	int r = 0, success = 0, request_invalid = 0;
	struct sshkey *key = NULL;

	if (sshbuf_get_string_direct(request, &blob, &blen) != 0 ||
	    sshkey_from_blob(blob, blen, &key) != 0) { 
		request_invalid = 1;
		goto done;
	}

	if ((thumbprint = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL ||
	    get_user_root(con, &user_root) != 0 ||
	    RegOpenKeyExW(user_root, SSH_KEYS_ROOT, 0,
		DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &root) != 0 ||
	    RegDeleteTreeA(root, thumbprint) != 0)
		goto done;
	success = 1;
done:
	r = 0;
	if (request_invalid)
		r = -1;
	else if (sshbuf_put_u8(response, success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE) != 0)
		r = -1;

	if (key)
		sshkey_free(key);
	if (user_root)
		RegCloseKey(user_root);
	if (root)
		RegCloseKey(root);
	if (thumbprint)
		free(thumbprint);
	return r;
}
int 
process_remove_all(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	HKEY user_root = 0, root = 0;
	int r = 0;

	if (get_user_root(con, &user_root) != 0 ||
	    RegOpenKeyExW(user_root, SSH_AGENT_ROOT, 0,
		   DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &root) != 0) {
		goto done;
	}

	RegDeleteTreeW(root, SSH_KEYS_KEY);
done:
	r = 0;
	if (sshbuf_put_u8(response, SSH_AGENT_SUCCESS) != 0)
		r = -1;

	if (user_root)
		RegCloseKey(user_root);
	if (root)
		RegCloseKey(root);
	return r;
}

int
process_request_identities(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	int count = 0, index = 0, success = 0, r = 0;
	HKEY root = NULL, sub = NULL, user_root = 0;
	char* count_ptr = NULL;
	wchar_t sub_name[MAX_KEY_LENGTH];
	DWORD sub_name_len = MAX_KEY_LENGTH;
	char *pkblob = NULL, *comment = NULL;
	DWORD regdatalen = 0, commentlen = 0, key_count = 0;
	struct sshbuf* identities;

	if ((identities = sshbuf_new()) == NULL)
		goto done;

	if ( get_user_root(con, &user_root) != 0 ||
	    RegOpenKeyExW(user_root, SSH_KEYS_ROOT, 0, STANDARD_RIGHTS_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &root) != 0) {
		success = 1;
		goto done;
	}

	while (1) {
		sub_name_len = MAX_KEY_LENGTH;
		if (sub) {
			RegCloseKey(sub);
			sub = NULL;
		}
		if (RegEnumKeyExW(root, index++, sub_name, &sub_name_len, NULL, NULL, NULL, NULL) == 0) {
			if (RegOpenKeyExW(root, sub_name, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &sub) == 0 &&
				RegQueryValueExW(sub, L"pub", 0, NULL, NULL, &regdatalen) == 0 &&
				RegQueryValueExW(sub, L"comment", 0, NULL, NULL, &commentlen) == 0) {
				if (pkblob)
					free(pkblob);
				if (comment)
					free(comment);
				pkblob = NULL;
				comment = NULL;

				if ((pkblob = malloc(regdatalen)) == NULL ||
					(comment = malloc(commentlen)) == NULL ||
					RegQueryValueExW(sub, L"pub", 0, NULL, pkblob, &regdatalen) != 0 ||
					RegQueryValueExW(sub, L"comment", 0, NULL, comment, &commentlen) != 0 ||
					sshbuf_put_string(identities, pkblob, regdatalen) != 0 ||
					sshbuf_put_string(identities, comment, commentlen) != 0)
					goto done;

				key_count++;
			}
		} else
			break;

	}

	success = 1;
done:
	r = 0;
	if (success) {
		if (sshbuf_put_u8(response, SSH2_AGENT_IDENTITIES_ANSWER) != 0 ||
			sshbuf_put_u32(response, key_count) != 0 ||
			sshbuf_putb(response, identities) != 0)
			goto done;
	} else
		r = -1;

	if (pkblob)
		free(pkblob);
	if (comment)
		free(comment);
	if (identities)
		sshbuf_free(identities);
	if (user_root)
		RegCloseKey(user_root);
	if (root)
		RegCloseKey(root);
	if (sub)
		RegCloseKey(sub);
	return r;
}


int process_keyagent_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) 
{
	u_char type;

	if (sshbuf_get_u8(request, &type) != 0)
		return -1;
	debug2("process key agent request type %d", type);

	switch (type) {
	case SSH2_AGENTC_ADD_IDENTITY:
		return process_add_identity(request, response, con);
	case SSH2_AGENTC_REQUEST_IDENTITIES:
		return process_request_identities(request, response, con);
	case SSH2_AGENTC_SIGN_REQUEST:
		return process_sign_request(request, response, con);
	case SSH2_AGENTC_REMOVE_IDENTITY:
		return process_remove_key(request, response, con);
	case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		return process_remove_all(request, response, con);
	default:
		debug("unknown key agent request %d", type);
		return -1;		
	}
}

#pragma warning(pop)