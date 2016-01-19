/*
* Copyright (c) 2015 Damien Miller <djm@mindrot.org>
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
* OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#include <includes.h>


#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <openssl/dh.h>
#include <openssl/evp.h>

#include "sshbuf.h"
#include "packet.h"
#include "ssherr.h"
#include "crypto-wrap.h"

struct sshdh {
	DH *dh;
};
struct sshbn {
	BIGNUM *bn;
};


static struct sshbn *
bnwrap(BIGNUM *bn)
{
	struct sshbn *ret;

	if (bn == NULL)
		return NULL;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;
	if ((ret->bn = BN_dup(bn)) == NULL) {
		free(ret);
		return NULL;
	}
	return ret;
}

/* DH wrappers */

struct sshdh *
	sshdh_new(void)
{
	struct sshdh *ret;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;
	if ((ret->dh = DH_new()) == NULL) {
		free(ret);
		return NULL;
	}
	return ret;
}

void
sshdh_free(struct sshdh *dh)
{
	if (dh != NULL) {
		if (dh->dh != NULL)
			DH_free(dh->dh);
		explicit_bzero(dh, sizeof(*dh));
		free(dh);
	}
}

struct sshbn *
	sshdh_pubkey(struct sshdh *dh)
{
	return bnwrap(dh->dh->pub_key);
}

struct sshbn *
	sshdh_p(struct sshdh *dh)
{
	return bnwrap(dh->dh->p);
}

struct sshbn *
	sshdh_g(struct sshdh *dh)
{
	return bnwrap(dh->dh->g);
}

void
sshdh_dump(struct sshdh *dh)
{
	DHparams_print_fp(stderr, dh->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, dh->dh->pub_key);
	fprintf(stderr, "\n");
}

// XXX needed?
size_t
sshdh_shared_key_size(struct sshdh *dh)
{
	int sz;

	if (dh == NULL || dh->dh == NULL || (sz = DH_size(dh->dh)) < 0)
		return 0;
	return (size_t)sz;
}

int sshdh_compute_key(struct sshdh *dh, struct sshbn *pubkey,
struct sshbn **shared_secretp)
{
	u_char *sbuf;
	int r, slen;

	*shared_secretp = NULL;
	if ((slen = DH_size(dh->dh)) <= 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((sbuf = calloc(1, slen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = DH_compute_key(sbuf, pubkey->bn, dh->dh)) < 0 ||
		r != slen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((r = sshbn_from(sbuf, slen, shared_secretp)) != 0)
		goto out;
	/* success */
	r = 0;
out:
	explicit_bzero(sbuf, slen);
	free(sbuf);
	return r;
}

int
sshdh_generate(struct sshdh *dh, size_t len)
{
	if (len > INT_MAX)
		return SSH_ERR_INVALID_ARGUMENT;
	if (len != 0)
		dh->dh->length = (int)len;
	if (DH_generate_key(dh->dh) != 1)
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}

int
sshdh_new_group_hex(const char *gen, const char *modulus, struct sshdh **dhp)
{
	struct sshdh *ret;

	*dhp = NULL;
	if ((ret = sshdh_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (BN_hex2bn(&ret->dh->p, modulus) == 0 ||
		BN_hex2bn(&ret->dh->g, gen) == 0) {
		sshdh_free(ret);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	*dhp = ret;
	return 0;
}

/* XXX transfers ownership of gen, modulus */
struct sshdh *
	sshdh_new_group(struct sshbn *gen, struct sshbn *modulus)
{
	struct sshdh *dh;

	if ((dh = sshdh_new()) == NULL)
		return NULL;
	dh->dh->p = modulus->bn;
	dh->dh->g = gen->bn;
	modulus->bn = gen->bn = NULL;
	sshbn_free(gen);
	sshbn_free(modulus);
	return (dh);
}


DH *sshdh_dh(struct sshdh *dh)
{
	return dh->dh;
}