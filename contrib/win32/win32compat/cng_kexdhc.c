/* 
*  cng implementation of Diffie-Hellman Key Exchange for Oakley groups 2 and 14 (ssh group1 and group14)
*
*/

#include "includes.h"


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

#include <bcrypt.h>
#include <cng_kex.h>




static int cng_input_kex_dh(int, u_int32_t, void *);

int
cng_kexdh_client(struct ssh *ssh)
{

	// switch to standard openssl version if not supported
	if (!cng_kex_supported())
		return kexdh_client(ssh);


	struct kex *kex = ssh->kex;
	int r;
	BIGNUM	* pub_key;
	/* generate and send 'e', client DH public key */
	switch (kex->kex_type) {
	case KEX_DH_GRP1_SHA1:
		kex->dh = cng_setup_group1();
		break;
	case KEX_DH_GRP14_SHA1:
		kex->dh = cng_setup_group14();
		break;
	default:
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	if (kex->dh == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	debug("sending SSH2_MSG_KEXDH_INIT");
	if ((r = cng_dh_gen_key(kex->dh, kex->we_need * 8)) != 0 ||
		(pub_key = cng_dh_get_local_pub_key(kex->dh)) == 0 ||
		(r = sshpkt_start(ssh, SSH2_MSG_KEXDH_INIT)) != 0 ||
		(r = sshpkt_put_bignum2(ssh, pub_key)) != 0 ||
		(r = sshpkt_send(ssh)) != 0)
		goto out;
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, kex->dh->pub_key);
	fprintf(stderr, "\n");
#endif
	debug("expecting SSH2_MSG_KEXDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_MSG_KEXDH_REPLY, &cng_input_kex_dh);
	r = 0;
out:
	if (pub_key)
		BN_free(pub_key);
	return r;
}

static int
cng_input_kex_dh(int type, u_int32_t seq, void *ctxt)
{
	struct ssh *ssh = ctxt;
	struct kex *kex = ssh->kex;
	CNG_DH_CTX	*pCtx = (CNG_DH_CTX *)kex->dh;
	BIGNUM *dh_server_pub = NULL, *shared_secret = NULL,*dh_local_pub=NULL;
	struct sshkey *server_host_key = NULL;
	u_char *kbuf = NULL, *server_host_key_blob = NULL, *signature = NULL;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t klen = 0, slen, sbloblen, hashlen;
	int kout, r;

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
	/* DH parameter f, server public DH key */
	if ((dh_server_pub = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* signed H */
	if ((r = sshpkt_get_bignum2(ssh, dh_server_pub)) != 0 ||
		(r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
		(r = sshpkt_get_end(ssh)) != 0)
		goto out;

	if (!cng_dh_pub_is_valid(kex->dh, dh_server_pub)) {
		sshpkt_disconnect(ssh, "bad server public DH value");
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		goto out;
	}

	shared_secret = cng_dh_get_secret(kex->dh, dh_server_pub);
	if (shared_secret == NULL)
		goto out;

	dh_local_pub = cng_dh_get_local_pub_key(kex->dh);

	/* calc and verify H */
	hashlen = sizeof(hash);
	if ((r = kex_dh_hash(
		kex->client_version_string,
		kex->server_version_string,
		sshbuf_ptr(kex->my), sshbuf_len(kex->my),
		sshbuf_ptr(kex->peer), sshbuf_len(kex->peer),
		server_host_key_blob, sbloblen,
		dh_local_pub,
		dh_server_pub,
		shared_secret,
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

	if ((r = kex_derive_keys_bn(ssh, hash, hashlen, shared_secret)) == 0)
		r = kex_send_newkeys(ssh);
out:
	explicit_bzero(hash, sizeof(hash));
	cng_dh_free_context(kex->dh);
	kex->dh = NULL;
	if (dh_server_pub)
		BN_clear_free(dh_server_pub);
	if (dh_local_pub)
		BN_clear_free(dh_local_pub);
	if (kbuf) {
		explicit_bzero(kbuf, klen);
		free(kbuf);
	}
	if (shared_secret)
		BN_clear_free(shared_secret);
	sshkey_free(server_host_key);
	free(server_host_key_blob);
	free(signature);
	return r;
}

