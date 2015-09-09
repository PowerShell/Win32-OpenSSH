/*
 * include/kerberosIV/des.h
 *
 * Copyright 1987, 1988, 1994, 2002 by the Massachusetts Institute of
 * Technology.  All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * Include file for the Data Encryption Standard library.
 */

#if defined(__MACH__) && defined(__APPLE__)
#include <TargetConditionals.h>
#include <AvailabilityMacros.h>
#if TARGET_RT_MAC_CFM
#error "Use KfM 4.0 SDK headers for CFM compilation."
#endif
#ifdef AVAILABLE_MAC_OS_X_VERSION_10_2_AND_LATER_BUT_DEPRECATED_IN_MAC_OS_X_VERSION_10_5
#define KRB5INT_DES_DEPRECATED AVAILABLE_MAC_OS_X_VERSION_10_2_AND_LATER_BUT_DEPRECATED_IN_MAC_OS_X_VERSION_10_5
#endif
#endif /* defined(__MACH__) && defined(__APPLE__) */

/* Macro to add deprecated attribute to DES types and functions */
/* Currently only defined on Mac OS X 10.5 and later.           */
#ifndef KRB5INT_DES_DEPRECATED
#define KRB5INT_DES_DEPRECATED
#endif

#ifdef __cplusplus
#ifndef KRBINT_BEGIN_DECLS
#define KRBINT_BEGIN_DECLS	extern "C" {
#define KRBINT_END_DECLS	}
#endif
#else
#define KRBINT_BEGIN_DECLS
#define KRBINT_END_DECLS
#endif

#ifndef KRB5INT_DES_TYPES_DEFINED
#define KRB5INT_DES_TYPES_DEFINED

#include <limits.h>

KRBINT_BEGIN_DECLS

#if TARGET_OS_MAC
#	pragma pack(push,2)
#endif

#if UINT_MAX >= 0xFFFFFFFFUL
#define DES_INT32 int
#define DES_UINT32 unsigned int
#else
#define DES_INT32 long
#define DES_UINT32 unsigned long
#endif

typedef unsigned char des_cblock[8] 	/* crypto-block size */
KRB5INT_DES_DEPRECATED;

/*
 * Key schedule.
 *
 * This used to be
 *
 * typedef struct des_ks_struct {
 *     union { DES_INT32 pad; des_cblock _;} __;
 * } des_key_schedule[16];
 *
 * but it would cause trouble if DES_INT32 were ever more than 4
 * bytes.  The reason is that all the encryption functions cast it to
 * (DES_INT32 *), and treat it as if it were DES_INT32[32].  If
 * 2*sizeof(DES_INT32) is ever more than sizeof(des_cblock), the
 * caller-allocated des_key_schedule will be overflowed by the key
 * scheduling functions.  We can't assume that every platform will
 * have an exact 32-bit int, and nothing should be looking inside a
 * des_key_schedule anyway.
 */
typedef struct des_ks_struct {  DES_INT32 _[2]; } des_key_schedule[16] 
KRB5INT_DES_DEPRECATED;

#if TARGET_OS_MAC
#	pragma pack(pop)
#endif

KRBINT_END_DECLS

#endif /* KRB5INT_DES_TYPES_DEFINED */

/* only do the whole thing once	 */
#ifndef DES_DEFS
/*
 * lib/crypto/des/des_int.h defines KRB5INT_CRYPTO_DES_INT temporarily
 * to avoid including the defintions and declarations below.  The
 * reason that the crypto library needs to include this file is that
 * it needs to have its types aligned with krb4's types.
 */
#ifndef KRB5INT_CRYPTO_DES_INT
#define DES_DEFS

#if defined(_WIN32)
#ifndef KRB4
#define KRB4 1
#endif
#include <win-mac.h>
#endif
#include <stdio.h> /* need FILE for des_cblock_print_file */

KRBINT_BEGIN_DECLS

#if TARGET_OS_MAC
#	pragma pack(push,2)
#endif

/* Windows declarations */
#ifndef KRB5_CALLCONV
#define KRB5_CALLCONV
#define KRB5_CALLCONV_C
#endif

#define DES_KEY_SZ 	(sizeof(des_cblock))
#define DES_ENCRYPT	1
#define DES_DECRYPT	0

#ifndef NCOMPAT
#define C_Block des_cblock
#define Key_schedule des_key_schedule
#define ENCRYPT DES_ENCRYPT
#define DECRYPT DES_DECRYPT
#define KEY_SZ DES_KEY_SZ
#define string_to_key des_string_to_key
#define read_pw_string des_read_pw_string
#define random_key des_random_key
#define pcbc_encrypt des_pcbc_encrypt
#define key_sched des_key_sched
#define cbc_encrypt des_cbc_encrypt
#define cbc_cksum des_cbc_cksum
#define C_Block_print des_cblock_print
#define quad_cksum des_quad_cksum
typedef struct des_ks_struct bit_64;
#endif

#define des_cblock_print(x) des_cblock_print_file(x, stdout)

/*
 * Function Prototypes
 */

int KRB5_CALLCONV des_key_sched (C_Block, Key_schedule) 
KRB5INT_DES_DEPRECATED;

int KRB5_CALLCONV
des_pcbc_encrypt (C_Block *in, C_Block *out, long length,
		  const des_key_schedule schedule, C_Block *ivec,
		  int enc) 
KRB5INT_DES_DEPRECATED;

unsigned long KRB5_CALLCONV
des_quad_cksum (const unsigned char *in, unsigned DES_INT32 *out,
		long length, int out_count, C_Block *seed) 
KRB5INT_DES_DEPRECATED;

/*
 * XXX ABI change: used to return void; also, cns/kfm have signed long
 * instead of unsigned long length.
 */
unsigned long KRB5_CALLCONV
des_cbc_cksum(const des_cblock *, des_cblock *, unsigned long,
	      const des_key_schedule, const des_cblock *) 
KRB5INT_DES_DEPRECATED;

int KRB5_CALLCONV des_string_to_key (const char *, C_Block) 
KRB5INT_DES_DEPRECATED;

void afs_string_to_key(char *, char *, des_cblock) 
KRB5INT_DES_DEPRECATED;

/* XXX ABI change: used to return krb5_error_code */
int KRB5_CALLCONV des_read_password(des_cblock *, char *, int) 
KRB5INT_DES_DEPRECATED;

int KRB5_CALLCONV des_ecb_encrypt(des_cblock *, des_cblock *,
				  const des_key_schedule, int) 
KRB5INT_DES_DEPRECATED;

/* XXX kfm/cns have signed long length */
int des_cbc_encrypt(des_cblock *, des_cblock *, unsigned long,
		    const des_key_schedule, const des_cblock *, int) 
KRB5INT_DES_DEPRECATED;

void des_fixup_key_parity(des_cblock) 
KRB5INT_DES_DEPRECATED;

int des_check_key_parity(des_cblock) 
KRB5INT_DES_DEPRECATED;

int KRB5_CALLCONV des_new_random_key(des_cblock) 
KRB5INT_DES_DEPRECATED;

void des_init_random_number_generator(des_cblock) 
KRB5INT_DES_DEPRECATED;

int des_random_key(des_cblock *) 
KRB5INT_DES_DEPRECATED;

int des_is_weak_key(des_cblock) 
KRB5INT_DES_DEPRECATED;

void des_cblock_print_file(des_cblock *, FILE *fp) 
KRB5INT_DES_DEPRECATED;


#if TARGET_OS_MAC
#	pragma pack(pop)
#endif

KRBINT_END_DECLS

#endif /* KRB5INT_CRYPTO_DES_INT */
#endif	/* DES_DEFS */
