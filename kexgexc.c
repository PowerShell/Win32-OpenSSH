/* $OpenBSD: kexgexc.c,v 1.22 2015/05/26 23:23:40 dtucker Exp $ */
/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
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

#include <sys/param.h>
#include <sys/types.h>

#include <openssl/dh.h>

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
#include "compat.h"
#include "dispatch.h"
#include "ssherr.h"
#include "sshbuf.h"

static int input_kex_dh_gex_group(int, u_int32_t, void *);
static int input_kex_dh_gex_reply(int, u_int32_t, void *);

int
kexgex_hash_old(
	int hash_alg,
	const char *client_version_string,
	const char *server_version_string,
	const u_char *ckexinit, size_t ckexinitlen,
	const u_char *skexinit, size_t skexinitlen,
	const u_char *serverhostkeyblob, size_t sbloblen,
	int min, int wantbits, int max,
	const BIGNUM *prime,
	const BIGNUM *gen,
	const BIGNUM *client_dh_pub,
	const BIGNUM *server_dh_pub,
	const BIGNUM *shared_secret,
	u_char *hash, size_t *hashlen);


int
kexgex_client(struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	int r;
	u_int nbits;

	nbits = dh_estimate(kex->dh_need * 8);

	kex->min = DH_GRP_MIN;
	kex->max = DH_GRP_MAX;
	kex->nbits = nbits;
	if (datafellows & SSH_BUG_DHGEX_LARGE)
		kex->nbits = MIN(kex->nbits, 4096);
	/* New GEX request */
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_DH_GEX_REQUEST)) != 0 ||
		(r = sshpkt_put_u32(ssh, kex->min)) != 0 ||
		(r = sshpkt_put_u32(ssh, kex->nbits)) != 0 ||
		(r = sshpkt_put_u32(ssh, kex->max)) != 0 ||
		(r = sshpkt_send(ssh)) != 0)
		goto out;
	debug("SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent",
		kex->min, kex->nbits, kex->max);
#ifdef DEBUG_KEXDH
	fprintf(stderr, "\nmin = %d, nbits = %d, max = %d\n",
		kex->min, kex->nbits, kex->max);
#endif
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_GROUP,
		&input_kex_dh_gex_group);
	r = 0;
out:
	return r;
}

static int
input_kex_dh_gex_group(int type, u_int32_t seq, void *ctxt)
{
	struct ssh *ssh = ctxt;
	struct kex *kex = ssh->kex;
	struct sshbn *dh_client_pub = NULL;
	struct sshbn *dh_g = NULL, *dh_p = NULL;
	int r;
	size_t bits;

	debug("got SSH2_MSG_KEX_DH_GEX_GROUP");

	if ((dh_p = sshbn_new()) == NULL ||
		(dh_g = sshbn_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshpkt_get_bignum2_wrap(ssh, dh_p)) != 0 ||
		(r = sshpkt_get_bignum2_wrap(ssh, dh_g)) != 0 ||
		(r = sshpkt_get_end(ssh)) != 0)
		goto out;
	if ((bits = sshbn_bits(dh_p)) == 0 ||
		bits < kex->min || bits > kex->max) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		goto out;
	}
	if ((kex->dh = sshdh_new_group(dh_g, dh_p)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	dh_p = dh_g = NULL; /* belong to kex->dh now */

						/* generate and send 'e', client DH public key */
	if ((r = dh_gen_key(kex->dh, kex->we_need * 8)) != 0)
		goto out;
	if ((dh_client_pub = sshdh_pubkey(kex->dh)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_DH_GEX_INIT)) != 0 ||
		(r = sshpkt_put_bignum2_wrap(ssh, dh_client_pub)) != 0 ||
		(r = sshpkt_send(ssh)) != 0)
		goto out;
	debug("SSH2_MSG_KEX_DH_GEX_INIT sent");
#ifdef DEBUG_KEXDH
	sshdh_dump(kex->dh);
#endif
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_GROUP, NULL);
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_REPLY, &input_kex_dh_gex_reply);
	r = 0;
out:
	sshbn_free(dh_p);
	sshbn_free(dh_g);
	sshbn_free(dh_client_pub);
	return r;
}

static int
input_kex_dh_gex_reply(int type, u_int32_t seq, void *ctxt)
{
	struct ssh *ssh = ctxt;
	struct kex *kex = ssh->kex;
	struct sshbn *dh_g = NULL, *dh_p = NULL;
	struct sshbn *dh_client_pub = NULL;
	struct sshbn *dh_server_pub = NULL;
	struct sshbn *shared_secret = NULL;
	struct sshkey *server_host_key = NULL;
	u_char *signature = NULL, *server_host_key_blob = NULL;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, sbloblen, hashlen;
	int r;

	debug("got SSH2_MSG_KEX_DH_GEX_REPLY");
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
	if (server_host_key->type != kex->hostkey_type) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
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
	/* DH parameter f, server public DH key */
	if ((dh_server_pub = sshbn_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* signed H */
	if ((r = sshpkt_get_bignum2_wrap(ssh, dh_server_pub)) != 0 ||
		(r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
		(r = sshpkt_get_end(ssh)) != 0)
		goto out;
#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_server_pub= ");
	BN_print_fp(stderr, dh_server_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_num_bits(dh_server_pub));
#endif
	if ((r = dh_pub_is_valid(kex->dh, dh_server_pub)) != 0) {
		sshpkt_disconnect(ssh, "bad server public DH value");
		goto out;
	}
	if ((dh_client_pub = sshdh_pubkey(kex->dh)) == NULL ||
		(dh_p = sshdh_p(kex->dh)) == NULL ||
		(dh_g = sshdh_g(kex->dh)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if ((r = sshdh_compute_key(kex->dh, dh_server_pub,
		&shared_secret)) != 0)
		goto out;
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif
	if (ssh->compat & SSH_OLD_DHGEX)
		kex->min = kex->max = -1;

	/* calc and verify H */
	hashlen = sizeof(hash);
	if ((r = kexgex_hash(
		kex->hash_alg,
		kex->client_version_string,
		kex->server_version_string,
		sshbuf_ptr(kex->my), sshbuf_len(kex->my),
		sshbuf_ptr(kex->peer), sshbuf_len(kex->peer),
		server_host_key_blob, sbloblen,
		kex->min, kex->nbits, kex->max,
		dh_p, dh_g,
		dh_client_pub,
		dh_server_pub,
		shared_secret,
		hash, &hashlen)) != 0)
		goto out;

	if ((r = sshkey_verify(server_host_key, signature, slen, hash,
		hashlen, ssh->compat)) != 0)
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

	if ((r = kex_derive_keys_bn(ssh, hash, hashlen, shared_secret)) == 0)
		r = kex_send_newkeys(ssh);
out:
	explicit_bzero(hash, sizeof(hash));
	sshbn_free(dh_p);
	sshbn_free(dh_g);
	sshbn_free(shared_secret);
	sshbn_free(dh_client_pub);
	sshbn_free(dh_server_pub);
	sshdh_free(kex->dh);
	kex->dh = NULL;
	free(server_host_key_blob);
	free(signature);
	return r;
}
