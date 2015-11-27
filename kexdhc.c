/* $OpenBSD: kexdhc.c,v 1.18 2015/01/26 06:10:03 djm Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
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

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include <openssl/dh.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "sshkey.h"
#include "cipher.h"
#include "digest.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "dh.h"
#include "ssh2.h"
#include "dispatch.h"
#include "compat.h"
#include "ssherr.h"
#include "sshbuf.h"

static int input_kex_dh(int, u_int32_t, void *);

int
kexdh_client(struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	int r;
	struct sshbuf *client_pub = NULL;
	
	kex->kexdh = kexdh_openssl_init(ssh);

	if (kex->kexdh == NULL ||
		(client_pub = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	
	debug("sending SSH2_MSG_KEXDH_INIT");
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEXDH_INIT)) != 0 ||
		(r = kex->kexdh->get_pub_key(kex->kexdh, client_pub)) != 0 ||
		(r = sshpkt_putb(ssh, client_pub)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;
	debug("expecting SSH2_MSG_KEXDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_MSG_KEXDH_REPLY, &input_kex_dh);
	r = 0;

out:
	if (client_pub)
		sshbuf_free(client_pub);
	return r;
}

static int
input_kex_dh(int type, u_int32_t seq, void *ctxt)
{
	struct ssh *ssh = ctxt;
	struct kex *kex = ssh->kex;
	struct sshkey *server_host_key = NULL;
	u_char *server_host_key_blob = NULL, *signature = NULL;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, sbloblen, hashlen;
	const u_char* server_pub_ptr = NULL;
	size_t server_pub_len = 0;
	struct sshbuf *server_pub = NULL, *client_pub = NULL, *secret = NULL;
	int r;

	if (kex->verify_host_key == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	/* key, cert */
	if ((r = sshpkt_get_string(ssh, &server_host_key_blob,
		&sbloblen)) != 0 ||
		(r = sshkey_from_blob(server_host_key_blob, sbloblen,
			&server_host_key)) != 0)
		goto out;
	if (server_host_key->type != kex->hostkey_type ||
		(kex->hostkey_type == KEY_ECDSA &&
			server_host_key->ecdsa_nid != kex->hostkey_nid)) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (kex->verify_host_key(server_host_key, ssh) == -1) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}

	/* signed H */
	if ((r = sshpkt_get_string_direct(ssh, &server_pub_ptr, &server_pub_len)) != 0 ||
		(r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
		(r = sshpkt_get_end(ssh)) != 0)
		goto out;

	if ((server_pub = sshbuf_from(server_pub_ptr - 4, server_pub_len + 4)) == NULL ||
		(secret = sshbuf_new()) == NULL ||
		(client_pub = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}


	if ((r = kex->kexdh->get_secret(kex->kexdh, server_pub, secret)) != 0 ||
		(r = kex->kexdh->get_pub_key(kex->kexdh, client_pub)) != 0)
	{
		goto out;
	}
	
	/* calc and verify H */
	hashlen = sizeof(hash);
	if ((r = kex_dh_hash_(
	    kex->client_version_string,
	    kex->server_version_string,
	    sshbuf_ptr(kex->my), sshbuf_len(kex->my),
	    sshbuf_ptr(kex->peer), sshbuf_len(kex->peer),
	    server_host_key_blob, sbloblen,
	    client_pub,
	    server_pub,
	    secret,
	    hash, &hashlen)) != 0)
		goto out;

	if ((r = sshkey_verify(server_host_key, signature, slen, hash, hashlen,
	    ssh->compat)) != 0)
		goto out;

	/* save session id */
	if (kex->session_id == NULL) {
		kex->session_id_len = hashlen;
		kex->session_id = malloc(kex->session_id_len);
		if (kex->session_id == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(kex->session_id, hash, kex->session_id_len);
	}

	if ((r = kex_derive_keys(ssh, hash, hashlen, secret)) == 0)
		r = kex_send_newkeys(ssh);
 out:
	explicit_bzero(hash, sizeof(hash));
	if (client_pub)
		sshbuf_free(client_pub);
	if (server_pub)
		sshbuf_free(server_pub);
	if (secret)
		sshbuf_free(secret);
	kex->kexdh->done(kex->kexdh);
	kex->kexdh = NULL;
	sshkey_free(server_host_key);
	free(server_host_key_blob);
	free(signature);
	return r;
}
#endif /* WITH_OPENSSL */
