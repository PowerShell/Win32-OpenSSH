#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <openssl/bn.h>
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


DH * cng_setup_group1(void);
DH * cng_setup_group14(void);
DH * cng_dh_new_group(BIGNUM *gen, BIGNUM *modulus);
BCRYPT_KEY_HANDLE cng_dh_set_remote_pub_key(DH *pCtx, BIGNUM * b);
int cng_dh_gen_key(DH *dh, int need);
BIGNUM * cng_dh_get_secret(DH * pCtx, BIGNUM * remote_pub);
BIGNUM * cng_dh_get_local_pub_key(DH * dh);
BIGNUM * cng_dh_get_p(DH * dh);
BIGNUM * cng_dh_get_g(DH * dh);
int cng_dh_pub_is_valid(DH * dh, BIGNUM *dh_pub);
void cng_dh_swap_bytes(void *pv, size_t n);
int cng_kex_supported(void);
DH * cng_dh_new_group_asc(const char *gen, const char *modulus);
void cng_dh_free_context(DH * dh);
