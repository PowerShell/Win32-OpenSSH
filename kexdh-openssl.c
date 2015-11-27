#include "includes.h"

#ifdef WITH_OPENSSL

#include <openssl/dh.h>

#include <stdarg.h>
#include <stdio.h>

#include "kex.h"
#include "log.h"
#include "packet.h"
#include "dh.h"
#include "ssh2.h"
#include "dispatch.h"
#include "compat.h"
#include "ssherr.h"
#include "sshbuf.h"

typedef struct kexdh_openssl_
{
	kexdhi dhi;
	struct ssh* ssh;
	DH* dh;
}kexdh_openssl;


static int kexdh_get_pub_key(kexdhi* dh_, struct sshbuf* pub)
{
	int r = 0;
	kexdh_openssl* dh = (kexdh_openssl*)dh_;
	struct kex* kex = dh->ssh->kex;
	
	/* generate and send 'e', client DH public key */
	switch (kex->kex_type) {
	case KEX_DH_GRP1_SHA1:
		dh->dh = dh_new_group1();
		break;
	case KEX_DH_GRP14_SHA1:
		dh->dh = dh_new_group14();
		break;
	default:
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;	
	}

	if ((r = dh_gen_key(dh->dh, kex->we_need * 8)) != 0 ||
		(r = sshpkt_put_bignum2(pub, dh->dh->pub_key)) != 0)
		goto out;
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, dh->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, dh->dh->pub_key);
	fprintf(stderr, "\n");
#endif
	return 0;
out:
	return r;
}

static int kexdh_get_secret(kexdhi* dh_, struct sshbuf* other_pub, struct sshbuf* secret)
{
	int r = 0, kout;
	BIGNUM *dh_server_pub = NULL, *shared_secret = NULL;
	kexdh_openssl* dh = (kexdh_openssl*)dh_;
	struct kex* kex = dh->ssh->kex;
	size_t klen = 0;
	u_char *kbuf = NULL;

	/* DH parameter f, server public DH key */
	if ((dh_server_pub = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((r = sshbuf_get_bignum2(other_pub, dh_server_pub)) != 0) {
		goto out;
	}

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_server_pub= ");
	BN_print_fp(stderr, dh_server_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_num_bits(dh_server_pub));
#endif
	if (!dh_pub_is_valid(dh->dh, dh_server_pub)) {
		sshpkt_disconnect(dh->ssh, "bad server public DH value");
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		goto out;
	}

	klen = DH_size(kex->dh);
	if ((kbuf = malloc(klen)) == NULL ||
		(shared_secret = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((kout = DH_compute_key(kbuf, dh_server_pub, kex->dh)) < 0 ||
		BN_bin2bn(kbuf, kout, shared_secret) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif

	if ((r == sshbuf_put_bignum2(secret, shared_secret)) != 0) {
		goto out;
	}
out:
	if (dh_server_pub)
		BN_clear_free(dh_server_pub);
	if (kbuf) {
		explicit_bzero(kbuf, klen);
		free(kbuf);
	}
	if (shared_secret)
		BN_clear_free(shared_secret);

	return r;
}

static void kexdh_done(kexdhi* dh_)
{
	kexdh_openssl* dh = (kexdh_openssl*)dh_;
	
	if (dh->dh)
		DH_free(dh->dh);
	free(dh_);
}


kexdhi* kexdh_openssl_init(struct ssh* ssh) 
{

	kexdh_openssl *dh = malloc(sizeof(kexdh_openssl));

	if (dh)
	{		
		dh->ssh = ssh;
		dh->dhi.get_pub_key = kexdh_get_pub_key;
		dh->dhi.get_secret = kexdh_get_secret;
		dh->dhi.done = kexdh_done;
		dh->dhi.get_p_g = NULL;
		dh->dhi.read_p_g = NULL;
	}
	
	return dh;
}


#endif