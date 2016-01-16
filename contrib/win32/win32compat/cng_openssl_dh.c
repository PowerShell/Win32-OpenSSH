
#include <includes.h>


#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include "sshbuf.h"
#include "packet.h"
#include "ssherr.h"
#include <bcrypt.h>
#include "crypto-wrap.h"
#include <VersionHelpers.h>


// CNG Diffie-hellman Kex context 
typedef struct cng_dh_ctx {
	int size;
	PBYTE g;
	PBYTE p;
	PBYTE pub;
	BCRYPT_KEY_HANDLE     hPrivate;
	BCRYPT_ALG_HANDLE     hAlg;
} CNG_DH_CTX;


struct sshdh {
	void *dh;
};

struct sshbn {
	BIGNUM *bn;
};


int cng_supported(void)
{
	return (IsWindows8Point1OrGreater());
}

//function to reverse the order of a byte array
static void
cng_dh_swap_bytes(void *pv, size_t n)
{
	char *p = (char*)pv;
	size_t lo, hi;
	for (lo = 0, hi = n - 1; hi>lo; lo++, hi--)
	{
		char tmp = p[lo];
		p[lo] = p[hi];
		p[hi] = tmp;
	}
}


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
	if (!cng_supported())
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

	return (struct sshdh *)(malloc(sizeof(struct sshdh)));
}

void
sshdh_free(struct sshdh *dh)
{
	if (!cng_supported())
	{
		if (dh != NULL) {
			if (dh->dh != NULL)
				DH_free(dh->dh);
			explicit_bzero(dh, sizeof(*dh));
			free(dh);
		}
		return;
	}

	if (dh != NULL) {
		if (dh->dh != NULL)
		{
			CNG_DH_CTX * pCtx = (CNG_DH_CTX*)dh->dh;

			if (pCtx->hAlg)
				BCryptCloseAlgorithmProvider(pCtx->hAlg, 0);

			if (pCtx->hPrivate)
				BCryptDestroyKey(pCtx->hPrivate);

			ZeroMemory(pCtx, sizeof(*pCtx));
			free(pCtx);
		}
		free(dh);
	}
}

struct sshbn *
	sshdh_pubkey(struct sshdh *dh)
{
	if (!cng_supported())
	{
		return bnwrap(((DH *)(dh->dh))->pub_key);
	}

	CNG_DH_CTX				*pCtx = (CNG_DH_CTX*)dh->dh;
	struct sshbn * bn = NULL;

	sshbn_from(pCtx->pub, pCtx->size, &bn);
	return bn;

}

struct sshbn *
	sshdh_p(struct sshdh *dh)
{
	if (!cng_supported())
	{
		return bnwrap(((DH *)(dh->dh))->p);
	}

	CNG_DH_CTX				*pCtx = (CNG_DH_CTX*)dh->dh;
	struct sshbn * bn = NULL;

	sshbn_from(pCtx->p, pCtx->size, &bn);

	return bn;
}

struct sshbn *
	sshdh_g(struct sshdh *dh)
{
	if (!cng_supported())
	{
		return bnwrap(((DH *)(dh->dh))->g);
	}

	CNG_DH_CTX				*pCtx = (CNG_DH_CTX*)dh->dh;
	struct sshbn * bn = NULL;

	sshbn_from(pCtx->g, pCtx->size, &bn);

	return bn;
}

void
sshdh_dump(struct sshdh *dh)
{
	if (!cng_supported())
	{
		DHparams_print_fp(stderr, dh->dh);
		fprintf(stderr, "pub= ");
		BN_print_fp(stderr, ((DH*)(dh->dh))->pub_key);
		fprintf(stderr, "\n");
	}
	return;
}

// XXX needed?
size_t
sshdh_shared_key_size(struct sshdh *dh)
{
	if (!cng_supported())
	{
		int sz;

		if (dh == NULL || dh->dh == NULL || (sz = DH_size(dh->dh)) < 0)
			return 0;
		return (size_t)sz;
	}

	int sz;
	CNG_DH_CTX				*pCtx = (CNG_DH_CTX*)dh->dh;

	if (dh == NULL || dh->dh == NULL || (sz = pCtx->size) < 0)
		return 0;
	return (size_t)sz;
}

// import a bignum public key 
static BCRYPT_KEY_HANDLE
cng_dh_set_remote_pub_key2(struct sshdh *dh, struct sshbn *b)
{

	BCRYPT_KEY_HANDLE hPub = NULL;
	CNG_DH_CTX				*pCtx = (CNG_DH_CTX*)dh->dh;

	if (sshbn_bytes(b) > pCtx->size)
		return NULL;

	DWORD cbBlob = sizeof(BCRYPT_DH_KEY_BLOB) + (pCtx->size * 3);

	PBYTE pBlob = (PBYTE)malloc(cbBlob);

	BCRYPT_DH_KEY_BLOB *pKeyBlob = (BCRYPT_DH_KEY_BLOB *)pBlob;
	pKeyBlob->cbKey = pCtx->size;
	pKeyBlob->dwMagic = BCRYPT_DH_PUBLIC_MAGIC;
	PBYTE pModulus = pBlob + sizeof(BCRYPT_DH_KEY_BLOB);
	PBYTE pGenerator = pModulus + pKeyBlob->cbKey;
	PBYTE pPublic = pGenerator + pKeyBlob->cbKey;

	memcpy(pModulus, pCtx->p, pCtx->size);
	memcpy(pGenerator, pCtx->g, pCtx->size);
	memset(pPublic, 0, pCtx->size);

	sshbn_to(b, pPublic + pCtx->size - (sshbn_bytes(b)));


	HRESULT Status = 0;

	if (S_OK != (Status = BCryptImportKeyPair(pCtx->hAlg, NULL, BCRYPT_DH_PUBLIC_BLOB, &hPub, pBlob, cbBlob, 0)))
		goto cleanup;

cleanup:
	if (pBlob) free(pBlob);

	return hPub;
}


int sshdh_compute_key(struct sshdh *dh, struct sshbn *pubkey,
struct sshbn **shared_secretp)
{
	if (!cng_supported())
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

	HRESULT hr = S_OK;
	CNG_DH_CTX				*pCtx = (CNG_DH_CTX*)dh->dh;
	PBYTE pSecret = (PBYTE)malloc(pCtx->size);
	DWORD pSecret_len = pCtx->size;
	DWORD size = pCtx->size;
	struct sshbn * bn = NULL;
	BCRYPT_SECRET_HANDLE hSecret;

	BCRYPT_KEY_HANDLE  hRemotePub = cng_dh_set_remote_pub_key2(dh, pubkey);
	if (hRemotePub != NULL)
	{

		if (S_OK == (hr = BCryptSecretAgreement(pCtx->hPrivate, hRemotePub, &hSecret, 0)))
		{

			hr = BCryptDeriveKey(hSecret, L"TRUNCATE", NULL, pSecret, pSecret_len, &size, 0);
			if (S_OK == hr)
			{
				cng_dh_swap_bytes(pSecret, size);

				sshbn_from(pSecret, size, &bn);
				memset(pSecret, 0, size);
				free(pSecret);
				*shared_secretp = bn;
			}
			BCryptDestroySecret(hSecret);
		}
	}
	return S_OK == hr ? 0 : -1;
}




int
sshdh_generate(struct sshdh *dh, size_t len)
{
	if (!cng_supported())
	{
		if (len > INT_MAX)
			return SSH_ERR_INVALID_ARGUMENT;
		if (len != 0)
			((DH*)(dh->dh))->length = (int)len;
		if (DH_generate_key(dh->dh) != 1)
			return SSH_ERR_LIBCRYPTO_ERROR;
		return 0;
	}

	HRESULT					Status;
	BCRYPT_DH_PARAMETER_HEADER  *DhParamHdrPointer = NULL;
	DWORD					DhParamBlobLength = 0;
	PBYTE					DhParamBlob = NULL;
	BCRYPT_ALG_HANDLE       hAlg = NULL;
	PBYTE                   pBlob = NULL;
	BCRYPT_KEY_HANDLE       hPriv = NULL;
	CNG_DH_CTX				*pCtx = (CNG_DH_CTX*)dh->dh;
	DWORD				    cbBlob = 0;


	DhParamBlobLength = sizeof(BCRYPT_DH_PARAMETER_HEADER) + (pCtx->size * 2);

	if (NULL == (DhParamBlob = (PBYTE)malloc(DhParamBlobLength)))
		return -1;

	DhParamHdrPointer = (BCRYPT_DH_PARAMETER_HEADER *)DhParamBlob;
	DhParamHdrPointer->cbLength = DhParamBlobLength;
	DhParamHdrPointer->cbKeyLength = pCtx->size;
	DhParamHdrPointer->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;

	memcpy(DhParamBlob + sizeof(BCRYPT_DH_PARAMETER_HEADER), pCtx->p, pCtx->size);
	memcpy(DhParamBlob + sizeof(BCRYPT_DH_PARAMETER_HEADER) + pCtx->size, pCtx->g, pCtx->size);

	if (S_OK != (Status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_DH_ALGORITHM, NULL, 0)))
		goto error;


	if (S_OK != (Status = BCryptGenerateKeyPair(hAlg, &hPriv, pCtx->size * 8, 0)))
		goto error;


	if (S_OK != (Status = BCryptSetProperty(hPriv, BCRYPT_DH_PARAMETERS, DhParamBlob, DhParamBlobLength, 0)))
		goto error;

	if (S_OK != (Status = BCryptFinalizeKeyPair(hPriv, 0)))
		goto error;

	if (S_OK != (Status = BCryptExportKey(hPriv, NULL, BCRYPT_DH_PUBLIC_BLOB, NULL, 0, &cbBlob, 0)))
		goto error;

	if (NULL == (pBlob = (PBYTE)malloc(cbBlob)))
	{
		Status = STATUS_NO_MEMORY;
		goto error;
	}

	if (S_OK != (Status = BCryptExportKey(hPriv, NULL, BCRYPT_DH_PUBLIC_BLOB, pBlob, cbBlob, &cbBlob, 0)))
		goto error;



	BCRYPT_DH_KEY_BLOB *pKeyBlob = (BCRYPT_DH_KEY_BLOB *)pBlob;
	PBYTE pModulus = pBlob + sizeof(BCRYPT_DH_KEY_BLOB);
	PBYTE pGenerator = pModulus + pKeyBlob->cbKey;
	PBYTE pPublic = pGenerator + pKeyBlob->cbKey;

	pCtx->hAlg = hAlg;
	pCtx->hPrivate = hPriv;
	memcpy(pCtx->pub, pPublic, pCtx->size);

	return 0;
error:

	return -1;
}

int
sshdh_new_group_hex(const char *gen, const char *modulus, struct sshdh **dhp)
{
	if (!cng_supported())
	{
		struct sshdh *ret;

		*dhp = NULL;
		if ((ret = sshdh_new()) == NULL)
			return SSH_ERR_ALLOC_FAIL;
		if (BN_hex2bn(&(((DH*)(ret->dh))->p), modulus) == 0 ||
			BN_hex2bn(&(((DH*)(ret->dh))->g), gen) == 0) {
			sshdh_free(ret);
			return SSH_ERR_LIBCRYPTO_ERROR;
		}
		*dhp = ret;
		return 0;
	}

	struct sshdh *ret;
	struct sshbn * g = NULL;
	struct sshbn * p = NULL;

	sshbn_from_hex(gen, &g);
	sshbn_from_hex(modulus, &p);
	*dhp = NULL;

	ret = sshdh_new_group(g, p);

	if (g != NULL)
		sshbn_free(g);
	if (p != NULL)
		sshbn_free(p);

	*dhp = ret;

	return 0;
}



/* XXX transfers ownership of gen, modulus */
struct sshdh *
	sshdh_new_group(struct sshbn *gen, struct sshbn *modulus)
{
	if (!cng_supported())
	{
		struct sshdh *dh;

		if ((dh = sshdh_new()) == NULL)
			return NULL;
		((DH*)(dh->dh))->p = modulus->bn;
		((DH*)(dh->dh))->g = gen->bn;
		modulus->bn = gen->bn = NULL;
		sshbn_free(gen);
		sshbn_free(modulus);
		return (dh);

	}

	struct sshdh *dh;

	PBYTE pBlob = NULL;
	DWORD keysize = sshbn_bytes(modulus);
	DWORD cbBlob = 0;

	dh = sshdh_new();

	pBlob = (PBYTE)malloc(sizeof(CNG_DH_CTX) + (3 * keysize));
	memset(pBlob, 0, sizeof(CNG_DH_CTX) + (3 * keysize));

	CNG_DH_CTX * pCtx = (CNG_DH_CTX *)pBlob;

	pCtx->size = keysize;
	pCtx->p = pBlob + sizeof(CNG_DH_CTX);
	pCtx->g = pCtx->p + keysize;
	pCtx->pub = pCtx->g + keysize;

	sshbn_to(gen, pCtx->g + keysize - sshbn_bytes(gen));
	sshbn_to(modulus, pCtx->p + keysize - sshbn_bytes(modulus));

	dh->dh = (void *)pCtx;
	return dh;
}




