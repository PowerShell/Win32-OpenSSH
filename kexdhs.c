/* $OpenBSD: kexdhs.c,v 1.22 2015/01/26 06:10:03 djm Exp $ */
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

/*
 * We support only client side kerberos on Windows.
 */


#include <sys/types.h>

#include <stdarg.h>
#include <string.h>
#include <signal.h>

#include <openssl/dh.h>

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

static int input_kex_dh_init(int, u_int32_t, void *);

int
kexdh_server(struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	int r;

	/* generate server DH public key */
	switch (kex->kex_type) {
	case KEX_DH_GRP1_SHA1:
		if ((r = dh_new_group1(&kex->dh)) != 0)
			return r;
		break;
	case KEX_DH_GRP14_SHA1:
		if ((r = dh_new_group14(&kex->dh)) != 0)
			return r;
		break;
	default:
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if (kex->dh == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = dh_gen_key(kex->dh, kex->we_need * 8)) != 0)
		return r;

	debug("expecting SSH2_MSG_KEXDH_INIT");
	ssh_dispatch_set(ssh, SSH2_MSG_KEXDH_INIT, &input_kex_dh_init);
	return 0;
}

int
input_kex_dh_init(int type, u_int32_t seq, void *ctxt)
{
	struct ssh *ssh = ctxt;
	struct kex *kex = ssh->kex;
	struct sshbn *dh_client_pub = NULL;
	struct sshbn *dh_server_pub = NULL;
	struct sshbn *shared_secret = NULL;
	struct sshkey *server_host_public, *server_host_private;
	u_char *signature = NULL, *server_host_key_blob = NULL;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t sbloblen, slen;
	size_t hashlen;
	int r;

	if (kex->load_host_public_key == NULL ||
		kex->load_host_private_key == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	server_host_public = kex->load_host_public_key(kex->hostkey_type,
		kex->hostkey_nid, ssh);
	server_host_private = kex->load_host_private_key(kex->hostkey_type,
		kex->hostkey_nid, ssh);
	if (server_host_public == NULL) {
		r = SSH_ERR_NO_HOSTKEY_LOADED;
		goto out;
	}

	/* key, cert */
	if ((dh_client_pub = sshbn_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshpkt_get_bignum2_wrap(ssh, dh_client_pub)) != 0 ||
		(r = sshpkt_get_end(ssh)) != 0)
		goto out;

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_client_pub= ");
	BN_print_fp(stderr, dh_client_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_num_bits(dh_client_pub));
#endif

#ifdef DEBUG_KEXDH
	sshdh_dump(kex->dh);
#endif
	if ((r = dh_pub_is_valid(kex->dh, dh_client_pub)) != 0) {
		sshpkt_disconnect(ssh, "bad client public DH value");
		goto out;
	}
	if ((dh_server_pub = sshdh_pubkey(kex->dh)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if ((r = sshdh_compute_key(kex->dh, dh_client_pub,
		&shared_secret)) != 0)
		goto out;
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, klen);
#endif
	if ((r = sshkey_to_blob(server_host_public, &server_host_key_blob,
		&sbloblen)) != 0)
		goto out;
	/* calc H */
	hashlen = sizeof(hash);
	if ((r = kex_dh_hash(
		kex->client_version_string,
		kex->server_version_string,
		sshbuf_ptr(kex->peer), sshbuf_len(kex->peer),
		sshbuf_ptr(kex->my), sshbuf_len(kex->my),
		server_host_key_blob, sbloblen,
		dh_client_pub,
		dh_server_pub,
		shared_secret,
		hash, &hashlen)) != 0)
		goto out;

	/* save session id := H */
	if (kex->session_id == NULL) {
		kex->session_id_len = hashlen;
		kex->session_id = malloc(kex->session_id_len);
		if (kex->session_id == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(kex->session_id, hash, kex->session_id_len);
	}

	/* sign H */
	if ((r = kex->sign(server_host_private, server_host_public,
		&signature, &slen, hash, hashlen, ssh->compat)) < 0)
		goto out;

	/* destroy_sensitive_data(); */

	/* send server hostkey, DH pubkey 'f' and singed H */
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEXDH_REPLY)) != 0 ||
		(r = sshpkt_put_string(ssh, server_host_key_blob, sbloblen)) != 0 ||
		(r = sshpkt_put_bignum2_wrap(ssh, dh_server_pub)) != 0 ||	/* f */
		(r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
		(r = sshpkt_send(ssh)) != 0)
		goto out;

	if ((r = kex_derive_keys_bn(ssh, hash, hashlen, shared_secret)) == 0)
		r = kex_send_newkeys(ssh);
out:
	explicit_bzero(hash, sizeof(hash));
	sshbn_free(shared_secret);
	sshbn_free(dh_client_pub);
	sshbn_free(dh_server_pub);
	sshdh_free(kex->dh);
	kex->dh = NULL;
	free(server_host_key_blob);
	free(signature);
	return r;
}
