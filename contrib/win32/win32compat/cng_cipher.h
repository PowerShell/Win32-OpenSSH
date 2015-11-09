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
/* cng_cipher.h
 *
 * Openssh ciphers implemented using Microsoft Crypto Next Generation (CNG).
 *
 */


#ifndef CNG_CIPHER_H
#define CNG_CIPHER_H

#ifdef USE_MSCNG

#ifdef __cplusplus
extern "C" {
#endif

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

/* CIPHER/MODE bits specify cipher and mode in the flags
*  field of the context
*/
#define _CNG_CIPHER_AES		0x00000001
#define _CNG_MODE_CTR       0x00010000
#define _CNG_MODE_CBC       0x00020000

#define _CNG_CIPHER_MASK    0x0000FFFF
#define _CNG_MODE_MASK      0xFFFF0000

	typedef struct ssh_cng_cipher_ctx
	{
		void *				hKey;
		unsigned char *		pbIV;
		unsigned int		cbBlockSize;
		unsigned int		flags;
		PBYTE				pKeyObject;
	} SSH_CNG_CIPHER_CTX, *PSSH_CNG_CIPHER_CTX;


	unsigned int cng_cipher_encrypt(PSSH_CNG_CIPHER_CTX x, unsigned char *dest, unsigned int dest_len, const unsigned char *src, unsigned int len);
	unsigned int cng_cipher_decrypt(PSSH_CNG_CIPHER_CTX x, unsigned char *dest, unsigned int dest_len, const unsigned char *src, unsigned int len);
	unsigned int cng_cipher_init(PSSH_CNG_CIPHER_CTX x, const unsigned char *key, unsigned int keylen, const unsigned char *iv, size_t ivlen, unsigned int flags);
	void cng_cipher_cleanup(PSSH_CNG_CIPHER_CTX x);


#ifdef __cplusplus
}
#endif

#endif

#endif 