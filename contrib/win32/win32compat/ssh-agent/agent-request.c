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
	size_t comment_len;
	char *thumbprint = NULL, *blob, *comment;
	HKEY reg = 0, sub = 0;

	blob = sshbuf_ptr(request);
	if ((r = sshkey_private_deserialize(request, &key)) != 0)
		goto done;
	blob_len = (sshbuf_ptr(request) - blob) & 0xffffffff;

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

	if ((r = RegSetValueEx(sub, L"Type", 0, REG_DWORD, &key->type, 4)) != 0)
		goto done;

	if ((r = RegSetValueEx(sub, L"Comment", 0, REG_BINARY, comment, comment_len)) != 0)
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
	return r1;
}

static struct sshkey*
retrieve_key(HKEY reg) {
	char* reg_value[MAX_VALUE_NAME];
}

int
process_request_identities(struct sshbuf* request, struct sshbuf* response, HANDLE client) {
	int r, r1, count = 0, index = 0;
	HKEY root = NULL, sub = NULL;
	char* count_ptr = NULL;
	wchar_t sub_name[MAX_KEY_LENGTH];
	DWORD sub_name_len = MAX_KEY_LENGTH;

	if ((r = RegOpenKeyEx(HKEY_LOCAL_MACHINE, SSHD_HOST_KEYS_ROOT,
		0, STANDARD_RIGHTS_READ | KEY_ENUMERATE_SUB_KEYS, &root)) != 0)
		goto done;

	if ((r = sshbuf_put_u8(response, SSH2_AGENT_IDENTITIES_ANSWER)) != 0)
		goto done;

	count_ptr = sshbuf_ptr(response);

	while (1) {
		sub_name_len = MAX_KEY_LENGTH;
		if (sub) {
			RegCloseKey(sub);
			sub = NULL;
		}
		if ((r = RegEnumKeyEx(root, index++, sub_name, &sub_name_len, NULL, NULL, NULL, NULL)) == 0) {
			if ((r = RegOpenKeyEx(root, sub_name, 0, KEY_READ, &sub)) == 0) {
				//RegQueryValueEx(sub, NULL, 0,  )
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

done:
	return r1;
}