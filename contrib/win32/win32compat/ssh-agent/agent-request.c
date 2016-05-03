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

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

int
process_add_identity(struct sshbuf* request, struct sshbuf* response, HANDLE client) {
	struct sshkey* key = NULL;
	int r = 0, r1 = 0, blob_len;
	size_t comment_len, pubkey_blob_len;
	u_char *pubkey_blob = NULL;
	char *thumbprint = NULL, *blob, *comment;
	HKEY reg = 0, sub = 0;

	blob = sshbuf_ptr(request);
	if ((r = sshkey_private_deserialize(request, &key)) != 0)
		goto done;
	blob_len = (sshbuf_ptr(request) - blob) & 0xffffffff;

	if ((r = sshkey_to_blob(key, &pubkey_blob, &pubkey_blob_len)) != 0) {
		goto done;
	}

	if ((r = sshbuf_peek_string_direct(request, &comment, &comment_len)) != 0)
		goto  done;

	if ((thumbprint = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL)
		goto done;

	if ((r = RegOpenKeyEx(HKEY_LOCAL_MACHINE, SSHD_HOST_KEYS_ROOT,
	    0, KEY_WRITE, &reg)) != 0)
		goto done;

	if ((r = RegCreateKeyExA(reg, thumbprint, 0, 0, 0, KEY_WRITE, NULL, &sub, NULL)) != 0)
		goto done;

	if ((r = RegSetValueEx(sub, NULL, 0, REG_BINARY, blob, blob_len)) != 0)
		goto done;

	if ((r = RegSetValueEx(sub, L"pub", 0, REG_BINARY, pubkey_blob, pubkey_blob_len)) != 0)
		goto done;

	if ((r = RegSetValueEx(sub, L"type", 0, REG_DWORD, &key->type, 4)) != 0)
		goto done;

	if ((r = RegSetValueEx(sub, L"comment", 0, REG_BINARY, comment, comment_len)) != 0)
		goto done;

done:

	r1 = sshbuf_put_u8(response, (r==0) ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);

	if (key)
		sshkey_free(key);
	if (thumbprint)
		free(thumbprint);
	if (reg)
		RegCloseKey(reg);
	if (sub)
		RegCloseKey(sub);
	if (pubkey_blob)
		free(pubkey_blob);
	return r1;
}

static int sign_blob(const struct sshkey *pubkey, u_char ** sig, size_t *siglen,
	const u_char *blob, size_t blen, u_int flags) {
	HKEY reg = 0, sub = 0;
	int r = 0;
	struct sshkey* prikey = NULL;
	char *thumbprint = NULL, *regdata = NULL;
	DWORD regdatalen = 0;
	struct sshbuf* tmpbuf;

	regdata = malloc(4);
	regdatalen = 4;

	*sig = NULL;
	*siglen = 0;

	if ((thumbprint = sshkey_fingerprint(pubkey, SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL)
		goto done;
	
	if ((r = RegOpenKeyEx(HKEY_LOCAL_MACHINE, SSHD_HOST_KEYS_ROOT,
		0, STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &reg)) != 0)
		goto done;

	if ((r = RegOpenKeyEx(reg, thumbprint, 0, 0, 0, STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, 
		NULL, &sub, NULL)) != 0)
		goto done;

	if ((RegQueryValueEx(sub, NULL, 0, NULL, regdata, &regdatalen)) != ERROR_MORE_DATA) {
		r = EOTHER;
		goto done;
	}

	if ((regdata = malloc(regdatalen)) == NULL) {
		r = ENOMEM;
		goto done;
	}

	if ((r = RegQueryValueEx(sub, NULL, 0, NULL, regdata, &regdatalen)) != 0)
		goto done;

	if ((tmpbuf = sshbuf_from(regdata, regdatalen)) == NULL) {
		r = ENOMEM;
		goto done;
	}
	
	if ( ((r = sshkey_private_deserialize(tmpbuf, &prikey)) != 0) ||
		((r = sshkey_sign(prikey, sig, siglen, blob, blen, 0)) != 0) )
		goto done;

done:
	if (regdata)
		free(regdata);
	if (tmpbuf)
		sshbuf_free(tmpbuf);
	if (prikey)
		sshkey_free(prikey);
	if (thumbprint)
		free(thumbprint);
	if (reg)
		RegCloseKey(reg);
	if (sub)
		RegCloseKey(sub);

	return r;
}

int
process_sign_request(struct sshbuf* request, struct sshbuf* response, HANDLE client) {
	u_char *blob, *data, *signature = NULL;
	size_t blen, dlen, slen = 0;
	u_int flags = 0;
	int r, r1;
	struct sshkey *key;

	if ((r = sshbuf_get_string(request, &blob, &blen)) != 0 ||
		(r = sshbuf_get_string(request, &data, &dlen)) != 0 ||
		(r = sshbuf_get_u32(request, &flags)) != 0)
		goto done;

	/* TODO - flags?*/

	if (((r = sshkey_from_blob(blob, blen, &key)) != 0)
		|| ((r = sign_blob(key, &signature, &slen,
			data, dlen, 0)) != 0))
		goto done;

done:
	if (r == 0) {
		if ((r = sshbuf_put_u8(response, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
			(r = sshbuf_put_string(response, signature, slen)) != 0) {
		}
	}
	else 
		r = sshbuf_put_u8(response, SSH_AGENT_FAILURE);

	free(data);
	free(blob);
	free(signature);
	return r;
}

int
process_request_identities(struct sshbuf* request, struct sshbuf* response, HANDLE client) {
	int r, r1, count = 0, index = 0;
	HKEY root = NULL, sub = NULL;
	char* count_ptr = NULL;
	wchar_t sub_name[MAX_KEY_LENGTH];
	DWORD sub_name_len = MAX_KEY_LENGTH;
	char *regdata = NULL;
	DWORD regdatalen = 0, key_count = 0;

	regdata = malloc(4);
	regdatalen = 4;

	if ((r = RegOpenKeyEx(HKEY_LOCAL_MACHINE, SSHD_HOST_KEYS_ROOT,
		0, STANDARD_RIGHTS_READ | KEY_ENUMERATE_SUB_KEYS, &root)) != 0)
		goto done;

	if (((r = sshbuf_put_u8(response, SSH2_AGENT_IDENTITIES_ANSWER)) != 0)
	   || ((r = sshbuf_reserve(response, 4, &count_ptr)) != 0))
		goto done;

	while (1) {
		sub_name_len = MAX_KEY_LENGTH;
		if (sub) {
			RegCloseKey(sub);
			sub = NULL;
		}
		if ((r = RegEnumKeyEx(root, index++, sub_name, &sub_name_len, NULL, NULL, NULL, NULL)) == 0) {
			if ((r = RegOpenKeyEx(root, sub_name, 0, KEY_QUERY_VALUE, &sub)) == 0) {
				if ((r = RegQueryValueEx(sub, L"pub", 0, NULL, regdata, &regdatalen)) != 0) {
					if (r == ERROR_MORE_DATA) {
						r = 0;
						if (regdata)
							free(regdata);
						if ((regdata = malloc(regdatalen)) == NULL) {
							r = ENOMEM;
							goto done;
						}
						if ((r = RegQueryValueEx(sub, L"pub", 0, NULL, regdata, &regdatalen)) != 0)
							goto done;

					}
					else {
						r = EOTHER;
						goto done;
					}
				}
				
				if ((r = sshbuf_put_string(response, regdata, regdatalen)) != 0)
					goto done;
				
				if ((r = RegQueryValueEx(sub, L"comment", 0, NULL, regdata, &regdatalen)) != 0) {
					if (r == ERROR_MORE_DATA) {
						r = 0;
						if (regdata)
							free(regdata);
						if ((regdata = malloc(regdatalen)) == NULL) {
							r = ENOMEM;
							goto done;
						}
						if ((r = RegQueryValueEx(sub, L"comment", 0, NULL, regdata, &regdatalen)) != 0)
							goto done;

					}
					else {
						r = EOTHER;
						goto done;
					}
				}
				if ((r = sshbuf_put_string(response, regdata, regdatalen)) != 0)
					goto done;
				key_count++;
				
			}
			else if (r == ERROR_FILE_NOT_FOUND) {
				r = 0;
				continue;
			}
			else
				goto done;
		}
		else if (r == ERROR_NO_MORE_ITEMS) {
			r = 0;
			break;
		}
		else
			goto done;

	}

	POKE_U32(count_ptr, key_count);

done:
	if (regdata)
		free(regdata);
	if (root)
		RegCloseKey(root);
	if (sub)
		RegCloseKey(sub);
	return r;
}