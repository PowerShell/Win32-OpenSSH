/* cng_cipher.h
* Author: Pragma Systems, Inc. <www.pragmasys.com>
* Contribution by Pragma Systems, Inc. for Microsoft openssh win32 port
* Copyright (c) 2011, 2015 Pragma Systems, Inc.
* All rights reserved
*
* Common library for Windows Console Screen IO.
* Contains Windows console related definition so that emulation code can draw
* on Windows console screen surface.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice.
* 2. Binaries produced provide no direct or implied warranties or any
*    guarantee of performance or suitability.
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