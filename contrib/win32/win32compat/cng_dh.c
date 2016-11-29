
#include <windows.h>
#include <bcrypt.h>
#include <openssl/bn.h>
#include <VersionHelpers.h>
#include <dh.h>
#include <crypto-wrap.h>


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
	CNG_DH_CTX *dh;
};


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


/* DH wrappers */

struct sshdh *
	sshdh_new(void)
{
	return (struct sshdh *)(malloc(sizeof(struct sshdh)));
}

void
sshdh_free(struct sshdh *dh)
{
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
	CNG_DH_CTX				*pCtx = dh->dh;
	struct sshbn * bn = NULL;

	sshbn_from(pCtx->pub, pCtx->size, &bn);
	return bn;

}

struct sshbn *
	sshdh_p(struct sshdh *dh)
{
	CNG_DH_CTX				*pCtx = dh->dh;
	struct sshbn * bn = NULL;

	sshbn_from(pCtx->p, pCtx->size, &bn);

	return bn;
}

struct sshbn *
	sshdh_g(struct sshdh *dh)
{
	CNG_DH_CTX				*pCtx = dh->dh;
	struct sshbn * bn = NULL;

	sshbn_from(pCtx->g, pCtx->size, &bn);

	return bn;
}

void
sshdh_dump(struct sshdh *dh)
{
	return;
}

// XXX needed?
size_t
sshdh_shared_key_size(struct sshdh *dh)
{
	int sz;
	CNG_DH_CTX				*pCtx = dh->dh;

	if (dh == NULL || dh->dh == NULL || (sz = pCtx->size) < 0)
		return 0;
	return (size_t)sz;
}

// import a bignum public key 
static BCRYPT_KEY_HANDLE
cng_dh_set_remote_pub_key2(struct sshdh *dh, struct sshbn *b)
{
	BCRYPT_KEY_HANDLE hPub = NULL;
	CNG_DH_CTX				*pCtx = dh->dh;

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
	HRESULT hr = S_OK;
	CNG_DH_CTX				*pCtx = dh->dh;
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
	return S_OK==hr?0:-1;
}




int
sshdh_generate(struct sshdh *dh, size_t len)
{
	HRESULT					Status;
	BCRYPT_DH_PARAMETER_HEADER  *DhParamHdrPointer = NULL;
	DWORD					DhParamBlobLength = 0;
	PBYTE					DhParamBlob = NULL;
	BCRYPT_ALG_HANDLE       hAlg = NULL;
	PBYTE                   pBlob = NULL;
	BCRYPT_KEY_HANDLE       hPriv = NULL;
	CNG_DH_CTX				*pCtx = dh->dh;
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


	if (S_OK != (Status = BCryptGenerateKeyPair(hAlg, &hPriv, pCtx->size*8, 0)))
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

	dh->dh = pCtx;
	return dh;
}




