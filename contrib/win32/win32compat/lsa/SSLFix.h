/*
 * Author: NoMachine <developers@nomachine.com>
 *
 * Copyright (c) 2009, 2013 NoMachine
 * All rights reserved
 *
 * Support functions and system calls' replacements needed to let the
 * software run on Win32 based operating systems.
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

#ifndef SSLFix_H
#define SSLFix_H

#undef STRING

//
// This code is needed for 'on the fly' load of OpenSSL DLLs.
//

//#define DYNAMIC_OPENSSL
#undef DYNAMIC_OPENSSL

#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>

#include <openssl/sha.h>
#include <openssl/md5.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>

//
// Code only for dynamic loaded OpenSSL libs (DLLs).
//

#ifdef DYNAMIC_OPENSSL

#define OPENSSL(x) DynSSL.x

  typedef int (*SSL_library_init_Ptr)(void);

  typedef void (*OpenSSL_add_all_digests_Ptr)(void);

  typedef const EVP_MD* (*EVP_sha1_Ptr)(void);

  typedef void (*DSA_SIG_free_Ptr)(DSA_SIG *);

  typedef DSA_SIG *(*DSA_SIG_new_Ptr)(void);

  typedef BIGNUM *(*BN_new_Ptr)(void);

  typedef BIGNUM *(*BN_bin2bn_Ptr)(const unsigned char *, int,BIGNUM *);

  typedef int (*EVP_DigestInit_Ptr)(EVP_MD_CTX *, const EVP_MD *);

  typedef int (*EVP_DigestFinal_Ptr)(EVP_MD_CTX *, unsigned char *, unsigned int *);

  typedef int (*EVP_DigestUpdate_Ptr)(EVP_MD_CTX *, const void *, size_t);

  typedef int (*EVP_Digest_Ptr)(const void *, size_t, unsigned char *, 
                                    unsigned int *, const EVP_MD *, ENGINE *);
                                  
  typedef int (*DSA_do_verify_Ptr)(const unsigned char *, int, DSA_SIG *, DSA *);

  typedef int (*RSA_size_Ptr)(const RSA *);

  typedef int (*RSA_public_decrypt_Ptr)(int, const unsigned char *,
                                            unsigned char *, RSA *, int);
                                          
  typedef int (*BN_num_bits_Ptr)(const BIGNUM *);

  typedef const char *(*OBJ_nid2sn_Ptr)(int);

  typedef const EVP_MD *(*EVP_get_digestbyname_Ptr)(const char *);

  typedef int (*BN_cmp_Ptr)(const BIGNUM *, const BIGNUM *);
 
  typedef RSA *(*RSA_new_Ptr)(void);

  typedef DSA *(*DSA_new_Ptr)(void);

  typedef void (*RSA_free_Ptr)(RSA *);

  typedef void (*DSA_free_Ptr)(DSA *);

  //
  // Struct with pointers to OpenSSL function exported by DLLs.
  //

  struct SSLFuncList
  {
    SSL_library_init_Ptr SSL_library_init;

    OpenSSL_add_all_digests_Ptr OpenSSL_add_all_digests;

    EVP_sha1_Ptr EVP_sha1;

    DSA_SIG_free_Ptr DSA_SIG_free;

    DSA_SIG_new_Ptr DSA_SIG_new;

    BN_new_Ptr BN_new;

    BN_bin2bn_Ptr BN_bin2bn;

    EVP_DigestInit_Ptr EVP_DigestInit;

    EVP_DigestFinal_Ptr EVP_DigestFinal;

    EVP_DigestUpdate_Ptr EVP_DigestUpdate;

    EVP_Digest_Ptr EVP_Digest;

    DSA_do_verify_Ptr DSA_do_verify;

    RSA_size_Ptr RSA_size;

    RSA_public_decrypt_Ptr RSA_public_decrypt;

    BN_num_bits_Ptr BN_num_bits;

    OBJ_nid2sn_Ptr OBJ_nid2sn;

    EVP_get_digestbyname_Ptr EVP_get_digestbyname;

    BN_cmp_Ptr BN_cmp;

    RSA_new_Ptr RSA_new;

    DSA_new_Ptr DSA_new;

    RSA_free_Ptr RSA_free;

    DSA_free_Ptr DSA_free;
  };
  
  //
  // We use static linked function here.
  //

#else

  #define OPENSSL(x) x

#endif

#endif
