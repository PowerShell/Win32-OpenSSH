/*
 * Author: Microsoft Corp.
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
/* cng_cipher.c
 *
 * Openssh ciphers implemented using Microsoft Crypto Next Generation (CNG).
 *
 */

#include <Windows.h>
#include <bcrypt.h>

#include "cng_cipher.h"

#ifdef USE_MSCNG


#define AES_BLOCK_SIZE  16


/*
* increment the aes counter (iv)
*/
static void aesctr_inc(unsigned char *ctr, unsigned int len)
{
	size_t i;

#ifndef CONSTANT_TIME_INCREMENT
	for (i = len - 1; i >= 0; i--)
		if (++ctr[i])	/* continue on overflow */
			return;
#else
	u8 x, add = 1;

	for (i = len - 1; i >= 0; i--) {
		ctr[i] += add;
		/* constant time for: x = ctr[i] ? 1 : 0 */
		x = ctr[i];
		x = (x | (x >> 4)) & 0xf;
		x = (x | (x >> 2)) & 0x3;
		x = (x | (x >> 1)) & 0x1;
		add *= (x ^ 1);
	}
#endif
}


/*
* Routine to encrypt a counter for ctr encryption.  This requries
* us to use an IV that is reset for each call to avoid cng attempting 
* to chain encryptions.  
*/
DWORD cng_counter_encrypt(const unsigned char *in, unsigned char *out, BCRYPT_KEY_HANDLE key, unsigned int blocklen)
{
	HRESULT status = S_OK;
	DWORD cbResult = 0;

	unsigned char iv[AES_BLOCK_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	status = BCryptEncrypt(
		key,
		(PUCHAR)in,
		blocklen,
		NULL,
		iv,
		blocklen,
		out,
		blocklen,
		&cbResult,
		0);

	return cbResult;
}

/*
*	Encrypt/Decrypt data using a CTR mode.  
*   In this mode, we can't call CNG encryption/decription directly.  The mode requires
*   the use of the iv as a counter that is incremented and encrypted.  The
*   encrypted counter is then XORd with the data to produce the cipher text.
*/
int cng_aesctr_encrypt_bytes(PSSH_CNG_CIPHER_CTX x, const unsigned char *m, unsigned char *c, unsigned int bytes)
{
	int			 ret = 0;
	unsigned int n = 0;
	unsigned char buf[AES_BLOCK_SIZE];

	while ((bytes--) > 0) {
		if (n == 0) {
			if (!cng_counter_encrypt(x->pbIV, buf, x->hKey, AES_BLOCK_SIZE))
			{
				ret = -1;
				break;
			}
			aesctr_inc(x->pbIV, AES_BLOCK_SIZE);
		}
		*(c++) = *(m++) ^ buf[n];
		n = (n + 1) % AES_BLOCK_SIZE;
	}
	return ret;
}


/*
*	Encrypt data using a provided cipher context
*/
unsigned int cng_cipher_encrypt(PSSH_CNG_CIPHER_CTX x, unsigned char *dest, unsigned int dest_len, const unsigned char *src, unsigned int len)
{
	DWORD cbResult = 0;
	HRESULT status = S_OK;

	if (x->flags & _CNG_MODE_CTR)
	{
		if (-1 == cng_aesctr_encrypt_bytes(x, src, dest, len))
		{
			status = GetLastError();
		}
		cbResult = len;
	}
	else
	{

		status = BCryptEncrypt(
			x->hKey,
			(PUCHAR)src,
			len,
			NULL,
			x->pbIV,
			x->cbBlockSize,
			dest,
			dest_len,
			&cbResult,
			0);
		if (S_OK != status)
		{
			cbResult = 0;
			SetLastError(status);
		}
	}
	return cbResult;
}

/*
*	Decrypt encrypted data using a provided cipher context
*/
unsigned int cng_cipher_decrypt(PSSH_CNG_CIPHER_CTX x, unsigned char *dest, unsigned int dest_len, const unsigned char *src, unsigned int len)
{
	DWORD cbResult = 0;
	HRESULT status = S_OK;

	if (x->flags & _CNG_MODE_CTR)
	{
		// ctr mode is just an XOR so encrypt=decrypt
		if (-1 == cng_aesctr_encrypt_bytes(x, src, dest, len))
		{
			status = GetLastError();
		}
		cbResult = len;
	}
	else
	{

		status = BCryptDecrypt(
			x->hKey,
			(PUCHAR)src,
			len,
			NULL,
			x->pbIV,
			x->cbBlockSize,
			dest,
			dest_len,
			&cbResult,
			0);
		if (S_OK != status)
		{
			cbResult = 0;
			SetLastError(status);
		}
	}
	return cbResult;
}


/*
*	Initialize cipher context 
*/
unsigned int cng_cipher_init(PSSH_CNG_CIPHER_CTX x, const unsigned char *key, unsigned int keylen, const unsigned char *iv, size_t ivlen, unsigned int flags)
{
	HRESULT					status = S_OK;
	BCRYPT_ALG_HANDLE       hAlg = NULL;
	DWORD					cbData = 0;
	LPCWSTR					pAlg = NULL;
	DWORD					cbBlockLen = 0;

	if ((0 == (flags & _CNG_CIPHER_AES)) || (0 == (flags & (_CNG_MODE_CBC | _CNG_MODE_CTR))))
		return STATUS_INVALID_PARAMETER;

	

	// wipe out old context
	memset(x, 0, sizeof(SSH_CNG_CIPHER_CTX));


	// initialize simple context fields
	x->flags = flags;

	// only one cipher supported right now
	if (flags & _CNG_CIPHER_AES)
		pAlg = BCRYPT_AES_ALGORITHM;


	// Generate BCrypt Key and set mode if applicable
	if (NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
		&hAlg,
		pAlg,
		NULL,
		0)))
	{

		if (NT_SUCCESS(status = BCryptGetProperty(
			hAlg,
			BCRYPT_BLOCK_LENGTH,
			(PBYTE)&cbBlockLen,
			sizeof(DWORD),
			&cbData,
			0)))
		{
			x->cbBlockSize = cbBlockLen;
			if (cbBlockLen != ivlen)
			{
				status = STATUS_INVALID_PARAMETER;
			}
			else
			{
				x->pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, ivlen);
				if (NULL == x->pbIV)
				{
					status = GetLastError();
				}
				else
				{
					memcpy(x->pbIV, iv, ivlen);
				}
			}
		}


		if (status == S_OK && flags & _CNG_MODE_CBC)
		{
			status = BCryptSetProperty(
				hAlg,
				BCRYPT_CHAINING_MODE,
				(PBYTE)BCRYPT_CHAIN_MODE_CBC,
				sizeof(BCRYPT_CHAIN_MODE_CBC),
				0);
		}

		if (status == S_OK)
		{
			status = BCryptGenerateSymmetricKey(
				hAlg,
				&(x->hKey),
				NULL,
				0,
				(PBYTE)key,
				keylen,
				0);
		}
		BCryptCloseAlgorithmProvider(hAlg, 0);

		// if we got an error along the way, free up the iv
		if (status != S_OK && x->pbIV)
		{
			HeapFree(GetProcessHeap(), 0, x->pbIV);
		}
	}
	return status;
}
/*
*  Cleanup cipher context fields
*/
void cng_cipher_cleanup(PSSH_CNG_CIPHER_CTX x)
{
	if (x->pbIV)
		HeapFree(GetProcessHeap(), 0, x->pbIV);
	if (x->hKey)
		BCryptDestroyKey(x->hKey);
}

#endif