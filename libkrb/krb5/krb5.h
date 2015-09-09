/*
 * include/krb5.h
 *
 * Copyright 1989,1990,1995,2001, 2003  by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * permission.	Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * General definitions for Kerberos version 5.
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef KRB5_GENERAL__
#define KRB5_GENERAL__

/* By default, do not expose deprecated interfaces. */
#ifndef KRB5_DEPRECATED
#define KRB5_DEPRECATED 0
#endif
/* Do not expose private interfaces.  Build system will override. */
#ifndef KRB5_PRIVATE
#define KRB5_PRIVATE 0
#endif

#if defined(__MACH__) && defined(__APPLE__)
#	include <TargetConditionals.h>
#    if TARGET_RT_MAC_CFM
#	error "Use KfM 4.0 SDK headers for CFM compilation."
#    endif
#endif

#if defined(_MSDOS) || defined(_WIN32)
#include <win-mac.h>
#endif

#ifndef KRB5_CONFIG__
#ifndef KRB5_CALLCONV
#define KRB5_CALLCONV
#define KRB5_CALLCONV_C
#endif /* !KRB5_CALLCONV */
#endif /* !KRB5_CONFIG__ */

#ifndef KRB5_CALLCONV_WRONG
#define KRB5_CALLCONV_WRONG
#endif

#ifndef THREEPARAMOPEN
#define THREEPARAMOPEN(x,y,z) open(x,y,z)
#endif

#define KRB5_OLD_CRYPTO

#include <stdlib.h>
#include <limits.h>		/* for *_MAX */

#ifndef KRB5INT_BEGIN_DECLS
#if defined(__cplusplus)
#define KRB5INT_BEGIN_DECLS	extern "C" {
#define KRB5INT_END_DECLS	}
#else
#define KRB5INT_BEGIN_DECLS
#define KRB5INT_END_DECLS
#endif
#endif

KRB5INT_BEGIN_DECLS

#if TARGET_OS_MAC
#    pragma pack(push,2)
#endif

/* from profile.h */
struct _profile_t;
/* typedef struct _profile_t *profile_t; */

/*
 * begin wordsize.h
 */

/*
 * Word-size related definition.
 */

typedef	unsigned char	krb5_octet;

#if INT_MAX == 0x7fff
typedef	int	krb5_int16;
typedef	unsigned int	krb5_ui_2;
#elif SHRT_MAX == 0x7fff
typedef	short	krb5_int16;
typedef	unsigned short	krb5_ui_2;
#else
#error undefined 16 bit type
#endif

#if INT_MAX == 0x7fffffffL
typedef	int	krb5_int32;
typedef	unsigned int	krb5_ui_4;
#elif LONG_MAX == 0x7fffffffL
typedef	long	krb5_int32;
typedef	unsigned long	krb5_ui_4;
#elif SHRT_MAX == 0x7fffffffL
typedef	short	krb5_int32;
typedef	unsigned short	krb5_ui_4;
#else
#error: undefined 32 bit type
#endif

#define VALID_INT_BITS	  INT_MAX
#define VALID_UINT_BITS	  UINT_MAX

#define KRB5_INT32_MAX	2147483647
/* this strange form is necessary since - is a unary operator, not a sign
   indicator */
#define KRB5_INT32_MIN	(-KRB5_INT32_MAX-1)

#define KRB5_INT16_MAX 65535	
/* this strange form is necessary since - is a unary operator, not a sign
   indicator */
#define KRB5_INT16_MIN	(-KRB5_INT16_MAX-1)

/*
 * end wordsize.h
 */

/*
 * begin "base-defs.h"
 */

/*
 * Basic definitions for Kerberos V5 library
 */

#ifndef FALSE
#define	FALSE	0
#endif
#ifndef TRUE
#define	TRUE	1
#endif

typedef	unsigned int krb5_boolean;
typedef	unsigned int krb5_msgtype;	
typedef	unsigned int krb5_kvno;	

typedef	krb5_int32 krb5_addrtype;
typedef krb5_int32 krb5_enctype;
typedef krb5_int32 krb5_cksumtype;
typedef krb5_int32 krb5_authdatatype;
typedef krb5_int32 krb5_keyusage;

typedef krb5_int32	krb5_preauthtype; /* This may change, later on */
typedef	krb5_int32	krb5_flags;
typedef krb5_int32	krb5_timestamp;
typedef	krb5_int32	krb5_error_code;
typedef krb5_int32	krb5_deltat;

typedef krb5_error_code	krb5_magic;

typedef struct _krb5_data {
	krb5_magic magic;
	unsigned int length;
	char *data;
} krb5_data;

typedef struct _krb5_octet_data {
	krb5_magic magic;
	unsigned int length;
	krb5_octet *data;
} krb5_octet_data;

/* 
 * Hack length for crypto library to use the afs_string_to_key It is
 * equivalent to -1 without possible sign extension 
 * We also overload for an unset salt type length - which is also -1, but
 * hey, why not....
*/
#define SALT_TYPE_AFS_LENGTH UINT_MAX
#define SALT_TYPE_NO_LENGTH  UINT_MAX

typedef	void * krb5_pointer;
typedef void const * krb5_const_pointer;

typedef struct krb5_principal_data {
    krb5_magic magic;
    krb5_data realm;
    krb5_data *data;		/* An array of strings */
    krb5_int32 length;
    krb5_int32 type;
} krb5_principal_data;

typedef	krb5_principal_data * krb5_principal;

/*
 * Per V5 spec on definition of principal types
 */

/* Name type not known */
#define KRB5_NT_UNKNOWN		0
/* Just the name of the principal as in DCE, or for users */
#define KRB5_NT_PRINCIPAL	1
/* Service and other unique instance (krbtgt) */
#define KRB5_NT_SRV_INST	2
/* Service with host name as instance (telnet, rcommands) */
#define KRB5_NT_SRV_HST		3
/* Service with host as remaining components */
#define KRB5_NT_SRV_XHST	4
/* Unique ID */
#define KRB5_NT_UID		5

/* constant version thereof: */
typedef const krb5_principal_data *krb5_const_principal;

#define krb5_princ_realm(context, princ) (&(princ)->realm)
#define krb5_princ_set_realm(context, princ,value) ((princ)->realm = *(value))
#define krb5_princ_set_realm_length(context, princ,value) (princ)->realm.length = (value)
#define krb5_princ_set_realm_data(context, princ,value) (princ)->realm.data = (value)
#define	krb5_princ_size(context, princ) (princ)->length
#define	krb5_princ_type(context, princ) (princ)->type
#define	krb5_princ_name(context, princ) (princ)->data
#define	krb5_princ_component(context, princ,i)		\
	    (((i) < krb5_princ_size(context, princ))	\
	     ? (princ)->data + (i)			\
	     : NULL)

/*
 * Constants for realm referrals.
 */
#define        KRB5_REFERRAL_REALM	""

/*
 * Referral-specific functions.
 */
krb5_boolean KRB5_CALLCONV krb5_is_referral_realm(const krb5_data *);

/*
 * end "base-defs.h"
 */

/*
 * begin "hostaddr.h"
 */

/* structure for address */
typedef struct _krb5_address {
    krb5_magic magic;
    krb5_addrtype addrtype;
    unsigned int length;
    krb5_octet *contents;
} krb5_address;

/* per Kerberos v5 protocol spec */
#define	ADDRTYPE_INET		0x0002
#define	ADDRTYPE_CHAOS		0x0005
#define	ADDRTYPE_XNS		0x0006
#define	ADDRTYPE_ISO		0x0007
#define ADDRTYPE_DDP		0x0010
#define ADDRTYPE_INET6		0x0018
/* not yet in the spec... */
#define ADDRTYPE_ADDRPORT	0x0100
#define ADDRTYPE_IPPORT		0x0101

/* macros to determine if a type is a local type */
#define ADDRTYPE_IS_LOCAL(addrtype) (addrtype & 0x8000)

/*
 * end "hostaddr.h"
 */


struct _krb5_context;
typedef struct _krb5_context * krb5_context;

struct _krb5_auth_context;
typedef struct _krb5_auth_context * krb5_auth_context;

struct _krb5_cryptosystem_entry;

/*
 * begin "encryption.h"
 */

typedef struct _krb5_keyblock {
    krb5_magic magic;
    krb5_enctype enctype;
    unsigned int length;
    krb5_octet *contents;
} krb5_keyblock;

#ifdef KRB5_OLD_CRYPTO
typedef struct _krb5_encrypt_block {
    krb5_magic magic;
    krb5_enctype crypto_entry;		/* to call krb5_encrypt_size, you need
					   this.  it was a pointer, but it
					   doesn't have to be.  gross. */
    krb5_keyblock *key;
} krb5_encrypt_block;
#endif

typedef struct _krb5_checksum {
    krb5_magic magic;
    krb5_cksumtype checksum_type;	/* checksum type */
    unsigned int length;
    krb5_octet *contents;
} krb5_checksum;

typedef struct _krb5_enc_data {
    krb5_magic magic;
    krb5_enctype enctype;
    krb5_kvno kvno;
    krb5_data ciphertext;
} krb5_enc_data;

/* per Kerberos v5 protocol spec */
#define	ENCTYPE_NULL		0x0000
#define	ENCTYPE_DES_CBC_CRC	0x0001	/* DES cbc mode with CRC-32 */
#define	ENCTYPE_DES_CBC_MD4	0x0002	/* DES cbc mode with RSA-MD4 */
#define	ENCTYPE_DES_CBC_MD5	0x0003	/* DES cbc mode with RSA-MD5 */
#define	ENCTYPE_DES_CBC_RAW	0x0004	/* DES cbc mode raw */
/* XXX deprecated? */
#define	ENCTYPE_DES3_CBC_SHA	0x0005	/* DES-3 cbc mode with NIST-SHA */
#define	ENCTYPE_DES3_CBC_RAW	0x0006	/* DES-3 cbc mode raw */
#define ENCTYPE_DES_HMAC_SHA1	0x0008
#define ENCTYPE_DES3_CBC_SHA1	0x0010
#define ENCTYPE_AES128_CTS_HMAC_SHA1_96	0x0011
#define ENCTYPE_AES256_CTS_HMAC_SHA1_96	0x0012
#define ENCTYPE_ARCFOUR_HMAC	0x0017
#define ENCTYPE_ARCFOUR_HMAC_EXP 0x0018
#define ENCTYPE_UNKNOWN		0x01ff

#define	CKSUMTYPE_CRC32		0x0001
#define	CKSUMTYPE_RSA_MD4	0x0002
#define	CKSUMTYPE_RSA_MD4_DES	0x0003
#define	CKSUMTYPE_DESCBC	0x0004
/* des-mac-k */
/* rsa-md4-des-k */
#define	CKSUMTYPE_RSA_MD5	0x0007
#define	CKSUMTYPE_RSA_MD5_DES	0x0008
#define CKSUMTYPE_NIST_SHA	0x0009
#define CKSUMTYPE_HMAC_SHA1_DES3	0x000c
#define CKSUMTYPE_HMAC_SHA1_96_AES128	0x000f
#define CKSUMTYPE_HMAC_SHA1_96_AES256	0x0010
#define CKSUMTYPE_HMAC_MD5_ARCFOUR -138 /*Microsoft md5 hmac cksumtype*/

/* The following are entropy source designations. Whenever
 * krb5_C_random_add_entropy is called, one of these source  ids is passed
 * in.  This  allows the library  to better estimate bits of
 * entropy in the sample and to keep track of what sources of entropy have
 * contributed enough entropy.  Sources marked internal MUST NOT be
 * used by applications outside the Kerberos library
*/

enum {
  KRB5_C_RANDSOURCE_OLDAPI = 0, /*calls to krb5_C_RANDOM_SEED (INTERNAL)*/
  KRB5_C_RANDSOURCE_OSRAND = 1, /* /dev/random or equivalent (internal)*/
  KRB5_C_RANDSOURCE_TRUSTEDPARTY = 2, /* From KDC or other trusted party*/
  /*This source should be used carefully; data in this category
   * should be from a third party trusted to give random bits
   * For example keys issued by the KDC in the application server.
   */
  KRB5_C_RANDSOURCE_TIMING = 3, /* Timing of operations*/
  KRB5_C_RANDSOURCE_EXTERNAL_PROTOCOL = 4, /*Protocol data possibly from attacker*/
  KRB5_C_RANDSOURCE_MAX = 5 /*Do not use; maximum source ID*/
};

#ifndef krb5_roundup
/* round x up to nearest multiple of y */
#define krb5_roundup(x, y) ((((x) + (y) - 1)/(y))*(y))
#endif /* roundup */

/* macro function definitions to help clean up code */

#if 1
#define krb5_x(ptr,args) ((ptr)?((*(ptr)) args):(abort(),1))
#define krb5_xc(ptr,args) ((ptr)?((*(ptr)) args):(abort(),(char*)0))
#else
#define krb5_x(ptr,args) ((*(ptr)) args)
#define krb5_xc(ptr,args) ((*(ptr)) args)
#endif

krb5_error_code KRB5_CALLCONV
    krb5_c_encrypt
    (krb5_context context, const krb5_keyblock *key,
		    krb5_keyusage usage, const krb5_data *cipher_state,
		    const krb5_data *input, krb5_enc_data *output);

krb5_error_code KRB5_CALLCONV
    krb5_c_decrypt
    (krb5_context context, const krb5_keyblock *key,
		    krb5_keyusage usage, const krb5_data *cipher_state,
		    const krb5_enc_data *input, krb5_data *output);

krb5_error_code KRB5_CALLCONV
    krb5_c_encrypt_length
    (krb5_context context, krb5_enctype enctype,
		    size_t inputlen, size_t *length);

krb5_error_code KRB5_CALLCONV
    krb5_c_block_size
    (krb5_context context, krb5_enctype enctype,
		    size_t *blocksize);

krb5_error_code KRB5_CALLCONV
    krb5_c_keylengths
    (krb5_context context, krb5_enctype enctype,
		    size_t *keybytes, size_t *keylength);

krb5_error_code KRB5_CALLCONV
	krb5_c_init_state
(krb5_context context,
const krb5_keyblock *key, krb5_keyusage usage,
krb5_data *new_state);

krb5_error_code KRB5_CALLCONV
	krb5_c_free_state
(krb5_context context, const krb5_keyblock *key, krb5_data *state);

krb5_error_code KRB5_CALLCONV
    krb5_c_prf (krb5_context, const krb5_keyblock *,
		krb5_data *in, krb5_data *out);

krb5_error_code KRB5_CALLCONV
    krb5_c_prf_length (krb5_context, krb5_enctype, size_t *outlen);

krb5_error_code KRB5_CALLCONV
    krb5_c_make_random_key
    (krb5_context context, krb5_enctype enctype,
		    krb5_keyblock *k5_random_key);

krb5_error_code KRB5_CALLCONV
    krb5_c_random_to_key
    (krb5_context context, krb5_enctype enctype,
		    krb5_data *random_data, krb5_keyblock *k5_random_key);

/* Register a new entropy sample  with the PRNG. may cause
* the PRNG to be reseeded, although this is not guaranteed.  See previous randsource definitions
* for information on how each source should be used.
*/
krb5_error_code KRB5_CALLCONV
	krb5_c_random_add_entropy
(krb5_context context, unsigned int  randsource_id, const krb5_data *data);


krb5_error_code KRB5_CALLCONV
    krb5_c_random_make_octets
    (krb5_context context, krb5_data *data);

/*
* Collect entropy from the OS if possible. strong requests that as strong 
* of a source of entropy  as available be used.  Setting strong may 
* increase the probability of blocking and should not  be used for normal 
* applications.  Good uses include seeding the PRNG for kadmind
* and realm setup.
* If successful is non-null, then successful is set to 1 if the OS provided
* entropy else zero.
*/
krb5_error_code KRB5_CALLCONV
krb5_c_random_os_entropy
(krb5_context context, int strong, int *success);

/*deprecated*/ krb5_error_code KRB5_CALLCONV
    krb5_c_random_seed
    (krb5_context context, krb5_data *data);

krb5_error_code KRB5_CALLCONV
    krb5_c_string_to_key
    (krb5_context context, krb5_enctype enctype,
		    const krb5_data *string, const krb5_data *salt,
		    krb5_keyblock *key);
krb5_error_code KRB5_CALLCONV
krb5_c_string_to_key_with_params(krb5_context context,
				 krb5_enctype enctype,
				 const krb5_data *string,
				 const krb5_data *salt,
				 const krb5_data *params,
				 krb5_keyblock *key);

krb5_error_code KRB5_CALLCONV
    krb5_c_enctype_compare
    (krb5_context context, krb5_enctype e1, krb5_enctype e2,
		    krb5_boolean *similar);

krb5_error_code KRB5_CALLCONV
    krb5_c_make_checksum
    (krb5_context context, krb5_cksumtype cksumtype,
		    const krb5_keyblock *key, krb5_keyusage usage,
		    const krb5_data *input, krb5_checksum *cksum);
    
krb5_error_code KRB5_CALLCONV
    krb5_c_verify_checksum
    (krb5_context context, 
		    const krb5_keyblock *key, krb5_keyusage usage,
		    const krb5_data *data,
		    const krb5_checksum *cksum,
		    krb5_boolean *valid);
    
krb5_error_code KRB5_CALLCONV
    krb5_c_checksum_length
    (krb5_context context, krb5_cksumtype cksumtype,
		    size_t *length);

krb5_error_code KRB5_CALLCONV
    krb5_c_keyed_checksum_types
    (krb5_context context, krb5_enctype enctype, 
		    unsigned int *count, krb5_cksumtype **cksumtypes);

#define KRB5_KEYUSAGE_AS_REQ_PA_ENC_TS		1
#define KRB5_KEYUSAGE_KDC_REP_TICKET		2
#define KRB5_KEYUSAGE_AS_REP_ENCPART		3
#define KRB5_KEYUSAGE_TGS_REQ_AD_SESSKEY	4
#define KRB5_KEYUSAGE_TGS_REQ_AD_SUBKEY		5
#define KRB5_KEYUSAGE_TGS_REQ_AUTH_CKSUM	6
#define KRB5_KEYUSAGE_TGS_REQ_AUTH		7
#define KRB5_KEYUSAGE_TGS_REP_ENCPART_SESSKEY	8
#define KRB5_KEYUSAGE_TGS_REP_ENCPART_SUBKEY	9
#define KRB5_KEYUSAGE_AP_REQ_AUTH_CKSUM		10
#define KRB5_KEYUSAGE_AP_REQ_AUTH		11
#define KRB5_KEYUSAGE_AP_REP_ENCPART		12
#define KRB5_KEYUSAGE_KRB_PRIV_ENCPART		13
#define KRB5_KEYUSAGE_KRB_CRED_ENCPART		14
#define KRB5_KEYUSAGE_KRB_SAFE_CKSUM		15
#define KRB5_KEYUSAGE_APP_DATA_ENCRYPT		16
#define KRB5_KEYUSAGE_APP_DATA_CKSUM		17
#define KRB5_KEYUSAGE_KRB_ERROR_CKSUM		18
#define KRB5_KEYUSAGE_AD_KDCISSUED_CKSUM	19
#define KRB5_KEYUSAGE_AD_MTE			20
#define KRB5_KEYUSAGE_AD_ITE			21

/* XXX need to register these */

#define KRB5_KEYUSAGE_GSS_TOK_MIC		22
#define KRB5_KEYUSAGE_GSS_TOK_WRAP_INTEG	23
#define KRB5_KEYUSAGE_GSS_TOK_WRAP_PRIV		24

/* Defined in hardware preauth draft */

#define KRB5_KEYUSAGE_PA_SAM_CHALLENGE_CKSUM	25
#define KRB5_KEYUSAGE_PA_SAM_CHALLENGE_TRACKID	26
#define KRB5_KEYUSAGE_PA_SAM_RESPONSE		27

/* Defined in KDC referrals draft */
#define KRB5_KEYUSAGE_PA_REFERRAL		26 /* XXX note conflict with above */

krb5_boolean KRB5_CALLCONV krb5_c_valid_enctype
	(krb5_enctype ktype);
krb5_boolean KRB5_CALLCONV krb5_c_valid_cksumtype
	(krb5_cksumtype ctype);
krb5_boolean KRB5_CALLCONV krb5_c_is_coll_proof_cksum
	(krb5_cksumtype ctype);
krb5_boolean KRB5_CALLCONV krb5_c_is_keyed_cksum
	(krb5_cksumtype ctype);

#if KRB5_PRIVATE
/* Use the above four instead.  */
krb5_boolean KRB5_CALLCONV valid_enctype
	(krb5_enctype ktype);
krb5_boolean KRB5_CALLCONV valid_cksumtype
	(krb5_cksumtype ctype);
krb5_boolean KRB5_CALLCONV is_coll_proof_cksum
	(krb5_cksumtype ctype);
krb5_boolean KRB5_CALLCONV is_keyed_cksum
	(krb5_cksumtype ctype);
#endif

#ifdef KRB5_OLD_CRYPTO
/*
 * old cryptosystem routine prototypes.  These are now layered
 * on top of the functions above.
 */
krb5_error_code KRB5_CALLCONV krb5_encrypt
	(krb5_context context,
		krb5_const_pointer inptr,
		krb5_pointer outptr,
		size_t size,
		krb5_encrypt_block * eblock,
		krb5_pointer ivec);
krb5_error_code KRB5_CALLCONV krb5_decrypt
	(krb5_context context,
		krb5_const_pointer inptr,
		krb5_pointer outptr,
		size_t size,
		krb5_encrypt_block * eblock,
		krb5_pointer ivec);
krb5_error_code KRB5_CALLCONV krb5_process_key
	(krb5_context context,
		krb5_encrypt_block * eblock,
		const krb5_keyblock * key);
krb5_error_code KRB5_CALLCONV krb5_finish_key
	(krb5_context context,
		krb5_encrypt_block * eblock);
krb5_error_code KRB5_CALLCONV krb5_string_to_key
	(krb5_context context,
		const krb5_encrypt_block * eblock,
		krb5_keyblock * keyblock,
		const krb5_data * data,
		const krb5_data * salt);
krb5_error_code KRB5_CALLCONV krb5_init_random_key
	(krb5_context context,
		const krb5_encrypt_block * eblock,
		const krb5_keyblock * keyblock,
		krb5_pointer * ptr);
krb5_error_code KRB5_CALLCONV krb5_finish_random_key
	(krb5_context context,
		const krb5_encrypt_block * eblock,
		krb5_pointer * ptr);
krb5_error_code KRB5_CALLCONV krb5_random_key
	(krb5_context context,
		const krb5_encrypt_block * eblock,
		krb5_pointer ptr,
		krb5_keyblock ** keyblock);
krb5_enctype KRB5_CALLCONV krb5_eblock_enctype
	(krb5_context context,
		const krb5_encrypt_block * eblock);
krb5_error_code KRB5_CALLCONV krb5_use_enctype
	(krb5_context context,
		krb5_encrypt_block * eblock,
		krb5_enctype enctype);
size_t KRB5_CALLCONV krb5_encrypt_size
	(size_t length,
		krb5_enctype crypto);
size_t KRB5_CALLCONV krb5_checksum_size
	(krb5_context context,
		krb5_cksumtype ctype);
krb5_error_code KRB5_CALLCONV krb5_calculate_checksum
	(krb5_context context,
		krb5_cksumtype ctype,
		krb5_const_pointer in, size_t in_length,
		krb5_const_pointer seed, size_t seed_length,
		krb5_checksum * outcksum);
krb5_error_code KRB5_CALLCONV krb5_verify_checksum
	(krb5_context context,
		krb5_cksumtype ctype,
		const krb5_checksum * cksum,
		krb5_const_pointer in, size_t in_length,
		krb5_const_pointer seed, size_t seed_length);

#if KRB5_PRIVATE
krb5_error_code KRB5_CALLCONV krb5_random_confounder
	(size_t, krb5_pointer);

krb5_error_code krb5_encrypt_data
	(krb5_context context, krb5_keyblock *key, 
		krb5_pointer ivec, krb5_data *data, 
		krb5_enc_data *enc_data);

krb5_error_code krb5_decrypt_data
	(krb5_context context, krb5_keyblock *key, 
		krb5_pointer ivec, krb5_enc_data *data, 
		krb5_data *enc_data);
#endif

#endif /* KRB5_OLD_CRYPTO */

/*
 * end "encryption.h"
 */

/*
 * begin "fieldbits.h"
 */

/* kdc_options for kdc_request */
/* options is 32 bits; each host is responsible to put the 4 bytes
   representing these bits into net order before transmission */
/* #define	KDC_OPT_RESERVED	0x80000000 */
#define	KDC_OPT_FORWARDABLE		0x40000000
#define	KDC_OPT_FORWARDED		0x20000000
#define	KDC_OPT_PROXIABLE		0x10000000
#define	KDC_OPT_PROXY			0x08000000
#define	KDC_OPT_ALLOW_POSTDATE		0x04000000
#define	KDC_OPT_POSTDATED		0x02000000
/* #define	KDC_OPT_UNUSED		0x01000000 */
#define	KDC_OPT_RENEWABLE		0x00800000
/* #define	KDC_OPT_UNUSED		0x00400000 */
/* #define	KDC_OPT_RESERVED	0x00200000 */
/* #define	KDC_OPT_RESERVED	0x00100000 */
/* #define	KDC_OPT_RESERVED	0x00080000 */
/* #define	KDC_OPT_RESERVED	0x00040000 */
#define	KDC_OPT_REQUEST_ANONYMOUS	0x00020000
#define	KDC_OPT_CANONICALIZE		0x00010000
/* #define	KDC_OPT_RESERVED	0x00008000 */
/* #define	KDC_OPT_RESERVED	0x00004000 */
/* #define	KDC_OPT_RESERVED	0x00002000 */
/* #define	KDC_OPT_RESERVED	0x00001000 */
/* #define	KDC_OPT_RESERVED	0x00000800 */
/* #define	KDC_OPT_RESERVED	0x00000400 */
/* #define	KDC_OPT_RESERVED	0x00000200 */
/* #define	KDC_OPT_RESERVED	0x00000100 */
/* #define	KDC_OPT_RESERVED	0x00000080 */
/* #define	KDC_OPT_RESERVED	0x00000040 */
#define	KDC_OPT_DISABLE_TRANSITED_CHECK	0x00000020
#define	KDC_OPT_RENEWABLE_OK		0x00000010
#define	KDC_OPT_ENC_TKT_IN_SKEY		0x00000008
/* #define	KDC_OPT_UNUSED		0x00000004 */
#define	KDC_OPT_RENEW			0x00000002
#define	KDC_OPT_VALIDATE		0x00000001

/*
 * Mask of ticket flags in the TGT which should be converted into KDC
 * options when using the TGT to get derivitive tickets.
 * 
 *  New mask = KDC_OPT_FORWARDABLE | KDC_OPT_PROXIABLE |
 *	       KDC_OPT_ALLOW_POSTDATE | KDC_OPT_RENEWABLE
 */
#define KDC_TKT_COMMON_MASK		0x54800000

/* definitions for ap_options fields */
/* ap_options are 32 bits; each host is responsible to put the 4 bytes
   representing these bits into net order before transmission */
#define	AP_OPTS_RESERVED		0x80000000
#define	AP_OPTS_USE_SESSION_KEY		0x40000000
#define	AP_OPTS_MUTUAL_REQUIRED		0x20000000
/* #define	AP_OPTS_RESERVED	0x10000000 */
/* #define	AP_OPTS_RESERVED	0x08000000 */
/* #define	AP_OPTS_RESERVED	0x04000000 */
/* #define	AP_OPTS_RESERVED	0x02000000 */
/* #define	AP_OPTS_RESERVED	0x01000000 */
/* #define	AP_OPTS_RESERVED	0x00800000 */
/* #define	AP_OPTS_RESERVED	0x00400000 */
/* #define	AP_OPTS_RESERVED	0x00200000 */
/* #define	AP_OPTS_RESERVED	0x00100000 */
/* #define	AP_OPTS_RESERVED	0x00080000 */
/* #define	AP_OPTS_RESERVED	0x00040000 */
/* #define	AP_OPTS_RESERVED	0x00020000 */
/* #define	AP_OPTS_RESERVED	0x00010000 */
/* #define	AP_OPTS_RESERVED	0x00008000 */
/* #define	AP_OPTS_RESERVED	0x00004000 */
/* #define	AP_OPTS_RESERVED	0x00002000 */
/* #define	AP_OPTS_RESERVED	0x00001000 */
/* #define	AP_OPTS_RESERVED	0x00000800 */
/* #define	AP_OPTS_RESERVED	0x00000400 */
/* #define	AP_OPTS_RESERVED	0x00000200 */
/* #define	AP_OPTS_RESERVED	0x00000100 */
/* #define	AP_OPTS_RESERVED	0x00000080 */
/* #define	AP_OPTS_RESERVED	0x00000040 */
/* #define	AP_OPTS_RESERVED	0x00000020 */
/* #define	AP_OPTS_RESERVED	0x00000010 */
/* #define	AP_OPTS_RESERVED	0x00000008 */
/* #define	AP_OPTS_RESERVED	0x00000004 */
/* #define	AP_OPTS_RESERVED	0x00000002 */
#define AP_OPTS_USE_SUBKEY	0x00000001

#define AP_OPTS_WIRE_MASK	0xfffffff0

/* definitions for ad_type fields. */
#define	AD_TYPE_RESERVED	0x8000
#define	AD_TYPE_EXTERNAL	0x4000
#define	AD_TYPE_REGISTERED	0x2000

#define AD_TYPE_FIELD_TYPE_MASK	0x1fff

/* Ticket flags */
/* flags are 32 bits; each host is responsible to put the 4 bytes
   representing these bits into net order before transmission */
/* #define	TKT_FLG_RESERVED	0x80000000 */
#define	TKT_FLG_FORWARDABLE		0x40000000
#define	TKT_FLG_FORWARDED		0x20000000
#define	TKT_FLG_PROXIABLE		0x10000000
#define	TKT_FLG_PROXY			0x08000000
#define	TKT_FLG_MAY_POSTDATE		0x04000000
#define	TKT_FLG_POSTDATED		0x02000000
#define	TKT_FLG_INVALID			0x01000000
#define	TKT_FLG_RENEWABLE		0x00800000
#define	TKT_FLG_INITIAL			0x00400000
#define	TKT_FLG_PRE_AUTH		0x00200000
#define	TKT_FLG_HW_AUTH			0x00100000
#define	TKT_FLG_TRANSIT_POLICY_CHECKED	0x00080000
#define	TKT_FLG_OK_AS_DELEGATE		0x00040000
#define	TKT_FLG_ANONYMOUS		0x00020000
/* #define	TKT_FLG_RESERVED	0x00010000 */
/* #define	TKT_FLG_RESERVED	0x00008000 */
/* #define	TKT_FLG_RESERVED	0x00004000 */
/* #define	TKT_FLG_RESERVED	0x00002000 */
/* #define	TKT_FLG_RESERVED	0x00001000 */
/* #define	TKT_FLG_RESERVED	0x00000800 */
/* #define	TKT_FLG_RESERVED	0x00000400 */
/* #define	TKT_FLG_RESERVED	0x00000200 */
/* #define	TKT_FLG_RESERVED	0x00000100 */
/* #define	TKT_FLG_RESERVED	0x00000080 */
/* #define	TKT_FLG_RESERVED	0x00000040 */
/* #define	TKT_FLG_RESERVED	0x00000020 */
/* #define	TKT_FLG_RESERVED	0x00000010 */
/* #define	TKT_FLG_RESERVED	0x00000008 */
/* #define	TKT_FLG_RESERVED	0x00000004 */
/* #define	TKT_FLG_RESERVED	0x00000002 */
/* #define	TKT_FLG_RESERVED	0x00000001 */

/* definitions for lr_type fields. */
#define	LR_TYPE_THIS_SERVER_ONLY	0x8000

#define LR_TYPE_INTERPRETATION_MASK	0x7fff

/* definitions for ad_type fields. */
#define	AD_TYPE_EXTERNAL	0x4000
#define	AD_TYPE_REGISTERED	0x2000

#define AD_TYPE_FIELD_TYPE_MASK	0x1fff
#define AD_TYPE_INTERNAL_MASK	0x3fff

/* definitions for msec direction bit for KRB_SAFE, KRB_PRIV */
#define	MSEC_DIRBIT		0x8000
#define	MSEC_VAL_MASK		0x7fff

/*
 * end "fieldbits.h"
 */

/*
 * begin "proto.h"
 */

/* Protocol version number */
#define	KRB5_PVNO	5

/* Message types */

#define	KRB5_AS_REQ	((krb5_msgtype)10) /* Req for initial authentication */
#define	KRB5_AS_REP	((krb5_msgtype)11) /* Response to KRB_AS_REQ request */
#define	KRB5_TGS_REQ	((krb5_msgtype)12) /* TGS request to server */
#define	KRB5_TGS_REP	((krb5_msgtype)13) /* Response to KRB_TGS_REQ req */
#define	KRB5_AP_REQ	((krb5_msgtype)14) /* application request to server */
#define	KRB5_AP_REP	((krb5_msgtype)15) /* Response to KRB_AP_REQ_MUTUAL */
#define	KRB5_SAFE	((krb5_msgtype)20) /* Safe application message */
#define	KRB5_PRIV	((krb5_msgtype)21) /* Private application message */
#define	KRB5_CRED	((krb5_msgtype)22) /* Credential forwarding message */
#define	KRB5_ERROR	((krb5_msgtype)30) /* Error response */

/* LastReq types */
#define KRB5_LRQ_NONE			0
#define KRB5_LRQ_ALL_LAST_TGT		1
#define KRB5_LRQ_ONE_LAST_TGT		(-1)
#define KRB5_LRQ_ALL_LAST_INITIAL	2
#define KRB5_LRQ_ONE_LAST_INITIAL	(-2)
#define KRB5_LRQ_ALL_LAST_TGT_ISSUED	3
#define KRB5_LRQ_ONE_LAST_TGT_ISSUED	(-3)
#define KRB5_LRQ_ALL_LAST_RENEWAL	4
#define KRB5_LRQ_ONE_LAST_RENEWAL	(-4)
#define KRB5_LRQ_ALL_LAST_REQ		5
#define KRB5_LRQ_ONE_LAST_REQ		(-5)
#define KRB5_LRQ_ALL_PW_EXPTIME		6
#define KRB5_LRQ_ONE_PW_EXPTIME		(-6)

/* PADATA types */
#define KRB5_PADATA_NONE		0
#define	KRB5_PADATA_AP_REQ		1
#define	KRB5_PADATA_TGS_REQ		KRB5_PADATA_AP_REQ
#define KRB5_PADATA_ENC_TIMESTAMP	2
#define	KRB5_PADATA_PW_SALT		3
#if 0				/* Not used */
#define KRB5_PADATA_ENC_ENCKEY		4  /* Key encrypted within itself */
#endif
#define KRB5_PADATA_ENC_UNIX_TIME	5  /* timestamp encrypted in key */
#define KRB5_PADATA_ENC_SANDIA_SECURID	6  /* SecurId passcode */
#define KRB5_PADATA_SESAME		7  /* Sesame project */
#define KRB5_PADATA_OSF_DCE		8  /* OSF DCE */
#define KRB5_CYBERSAFE_SECUREID		9  /* Cybersafe */
#define	KRB5_PADATA_AFS3_SALT		10 /* Cygnus */
#define KRB5_PADATA_ETYPE_INFO		11 /* Etype info for preauth */
#define KRB5_PADATA_SAM_CHALLENGE	12 /* draft challenge system */
#define KRB5_PADATA_SAM_RESPONSE	13 /* draft challenge system response */
#define KRB5_PADATA_PK_AS_REQ_OLD	14 /* PKINIT */
#define KRB5_PADATA_PK_AS_REP_OLD	15 /* PKINIT */
#define KRB5_PADATA_PK_AS_REQ		16 /* PKINIT */
#define KRB5_PADATA_PK_AS_REP		17 /* PKINIT */
#define KRB5_PADATA_ETYPE_INFO2		19
#define KRB5_PADATA_USE_SPECIFIED_KVNO	20
#define KRB5_PADATA_SAM_REDIRECT	21
#define KRB5_PADATA_GET_FROM_TYPED_DATA	22
#define KRB5_PADATA_REFERRAL		25 /* draft referral system */
#define KRB5_PADATA_SAM_CHALLENGE_2	30 /* draft challenge system, updated */
#define KRB5_PADATA_SAM_RESPONSE_2	31 /* draft challenge system, updated */
    
#define	KRB5_SAM_USE_SAD_AS_KEY		0x80000000
#define	KRB5_SAM_SEND_ENCRYPTED_SAD	0x40000000
#define	KRB5_SAM_MUST_PK_ENCRYPT_SAD	0x20000000 /* currently must be zero */

/* Reserved for SPX pre-authentication. */
#define KRB5_PADATA_DASS		16

/* Transited encoding types */
#define	KRB5_DOMAIN_X500_COMPRESS	1

/* alternate authentication types */
#define	KRB5_ALTAUTH_ATT_CHALLENGE_RESPONSE	64

/* authorization data types */
#define KRB5_AUTHDATA_IF_RELEVANT   1
#define KRB5_AUTHDATA_KDC_ISSUED    4
#define KRB5_AUTHDATA_AND_OR	    5
#define KRB5_AUTHDATA_MANDATORY_FOR_KDC	8
#define KRB5_AUTHDATA_INITIAL_VERIFIED_CAS	9
#define	KRB5_AUTHDATA_OSF_DCE	64
#define KRB5_AUTHDATA_SESAME	65

/* password change constants */

#define KRB5_KPASSWD_SUCCESS		0
#define KRB5_KPASSWD_MALFORMED		1
#define KRB5_KPASSWD_HARDERROR		2
#define KRB5_KPASSWD_AUTHERROR		3
#define KRB5_KPASSWD_SOFTERROR		4
/* These are Microsoft's extensions in RFC 3244, and it looks like
   they'll become standardized, possibly with other additions.  */
#define KRB5_KPASSWD_ACCESSDENIED	5	/* unused */
#define KRB5_KPASSWD_BAD_VERSION	6
#define KRB5_KPASSWD_INITIAL_FLAG_NEEDED 7	/* unused */

/*
 * end "proto.h"
 */

/* Time set */
typedef struct _krb5_ticket_times {
    krb5_timestamp authtime; /* XXX ? should ktime in KDC_REP == authtime
				in ticket? otherwise client can't get this */ 
    krb5_timestamp starttime;		/* optional in ticket, if not present,
					   use authtime */
    krb5_timestamp endtime;
    krb5_timestamp renew_till;
} krb5_ticket_times;

/* structure for auth data */
typedef struct _krb5_authdata {
    krb5_magic magic;
    krb5_authdatatype ad_type;
    unsigned int length;
    krb5_octet *contents;
} krb5_authdata;

/* structure for transited encoding */
typedef struct _krb5_transited {
    krb5_magic magic;
    krb5_octet tr_type;
    krb5_data tr_contents;
} krb5_transited;

typedef struct _krb5_enc_tkt_part {
    krb5_magic magic;
    /* to-be-encrypted portion */
    krb5_flags flags;			/* flags */
    krb5_keyblock *session;		/* session key: includes enctype */
    krb5_principal client;		/* client name/realm */
    krb5_transited transited;		/* list of transited realms */
    krb5_ticket_times times;		/* auth, start, end, renew_till */
    krb5_address **caddrs;	/* array of ptrs to addresses */
    krb5_authdata **authorization_data; /* auth data */
} krb5_enc_tkt_part;

typedef struct _krb5_ticket {
    krb5_magic magic;
    /* cleartext portion */
    krb5_principal server;		/* server name/realm */
    krb5_enc_data enc_part;		/* encryption type, kvno, encrypted
					   encoding */
    krb5_enc_tkt_part *enc_part2;	/* ptr to decrypted version, if
					   available */
} krb5_ticket;

/* the unencrypted version */
typedef struct _krb5_authenticator {
    krb5_magic magic;
    krb5_principal client;		/* client name/realm */
    krb5_checksum *checksum;	/* checksum, includes type, optional */
    krb5_int32 cusec;			/* client usec portion */
    krb5_timestamp ctime;		/* client sec portion */
    krb5_keyblock *subkey;		/* true session key, optional */
    krb5_ui_4 seq_number;		/* sequence #, optional */
    krb5_authdata **authorization_data; /* New add by Ari, auth data */
} krb5_authenticator;

typedef struct _krb5_tkt_authent {
    krb5_magic magic;
    krb5_ticket *ticket;
    krb5_authenticator *authenticator;
    krb5_flags ap_options;
} krb5_tkt_authent;

/* credentials:	 Ticket, session key, etc. */
typedef struct _krb5_creds {
    krb5_magic magic;
    krb5_principal client;		/* client's principal identifier */
    krb5_principal server;		/* server's principal identifier */
    krb5_keyblock keyblock;		/* session encryption key info */
    krb5_ticket_times times;		/* lifetime info */
    krb5_boolean is_skey;		/* true if ticket is encrypted in
					   another ticket's skey */
    krb5_flags ticket_flags;		/* flags in ticket */
    krb5_address **addresses;	/* addrs in ticket */
    krb5_data ticket;			/* ticket string itself */
    krb5_data second_ticket;		/* second ticket, if related to
					   ticket (via DUPLICATE-SKEY or
					   ENC-TKT-IN-SKEY) */
    krb5_authdata **authdata;	/* authorization data */
} krb5_creds;

/* Last request fields */
typedef struct _krb5_last_req_entry {
    krb5_magic magic;
    krb5_int32 lr_type;
    krb5_timestamp value;
} krb5_last_req_entry;

/* pre-authentication data */
typedef struct _krb5_pa_data {
    krb5_magic magic;
    krb5_preauthtype  pa_type;
    unsigned int length;
    krb5_octet *contents;
} krb5_pa_data;

typedef struct _krb5_kdc_req {
    krb5_magic magic;
    krb5_msgtype msg_type;		/* AS_REQ or TGS_REQ? */
    krb5_pa_data **padata;	/* e.g. encoded AP_REQ */
    /* real body */
    krb5_flags kdc_options;		/* requested options */
    krb5_principal client;		/* includes realm; optional */
    krb5_principal server;		/* includes realm (only used if no
					   client) */
    krb5_timestamp from;		/* requested starttime */
    krb5_timestamp till;		/* requested endtime */
    krb5_timestamp rtime;		/* (optional) requested renew_till */
    krb5_int32 nonce;			/* nonce to match request/response */
    int nktypes;			/* # of ktypes, must be positive */
    krb5_enctype *ktype;		/* requested enctype(s) */
    krb5_address **addresses;	/* requested addresses, optional */
    krb5_enc_data authorization_data;	/* encrypted auth data; OPTIONAL */
    krb5_authdata **unenc_authdata; /* unencrypted auth data,
					   if available */
    krb5_ticket **second_ticket;/* second ticket array; OPTIONAL */
} krb5_kdc_req;

typedef struct _krb5_enc_kdc_rep_part {
    krb5_magic magic;
    /* encrypted part: */
    krb5_msgtype msg_type;		/* krb5 message type */
    krb5_keyblock *session;		/* session key */
    krb5_last_req_entry **last_req; /* array of ptrs to entries */
    krb5_int32 nonce;			/* nonce from request */
    krb5_timestamp key_exp;		/* expiration date */
    krb5_flags flags;			/* ticket flags */
    krb5_ticket_times times;		/* lifetime info */
    krb5_principal server;		/* server's principal identifier */
    krb5_address **caddrs;	/* array of ptrs to addresses,
					   optional */
} krb5_enc_kdc_rep_part;

typedef struct _krb5_kdc_rep {
    krb5_magic magic;
    /* cleartext part: */
    krb5_msgtype msg_type;		/* AS_REP or KDC_REP? */
    krb5_pa_data **padata;	/* preauthentication data from KDC */
    krb5_principal client;		/* client's principal identifier */
    krb5_ticket *ticket;		/* ticket */
    krb5_enc_data enc_part;		/* encryption type, kvno, encrypted
					   encoding */
    krb5_enc_kdc_rep_part *enc_part2;/* unencrypted version, if available */
} krb5_kdc_rep;

/* error message structure */
typedef struct _krb5_error {
    krb5_magic magic;
    /* some of these may be meaningless in certain contexts */
    krb5_timestamp ctime;		/* client sec portion; optional */
    krb5_int32 cusec;			/* client usec portion; optional */
    krb5_int32 susec;			/* server usec portion */
    krb5_timestamp stime;		/* server sec portion */
    krb5_ui_4 error;			/* error code (protocol error #'s) */
    krb5_principal client;		/* client's principal identifier;
					   optional */
    krb5_principal server;		/* server's principal identifier */
    krb5_data text;			/* descriptive text */
    krb5_data e_data;			/* additional error-describing data */
} krb5_error;

typedef struct _krb5_ap_req {
    krb5_magic magic;
    krb5_flags ap_options;		/* requested options */
    krb5_ticket *ticket;		/* ticket */
    krb5_enc_data authenticator;	/* authenticator (already encrypted) */
} krb5_ap_req;

typedef struct _krb5_ap_rep {
    krb5_magic magic;
    krb5_enc_data enc_part;
} krb5_ap_rep;

typedef struct _krb5_ap_rep_enc_part {
    krb5_magic magic;
    krb5_timestamp ctime;		/* client time, seconds portion */
    krb5_int32 cusec;			/* client time, microseconds portion */
    krb5_keyblock *subkey;		/* true session key, optional */
    krb5_ui_4 seq_number;		/* sequence #, optional */
} krb5_ap_rep_enc_part;

typedef struct _krb5_response {
    krb5_magic magic;
    krb5_octet message_type;
    krb5_data response;
    krb5_int32 expected_nonce;	/* The expected nonce for KDC_REP messages */
    krb5_timestamp request_time;   /* When we made the request */
} krb5_response;

typedef struct _krb5_cred_info {
    krb5_magic magic;
    krb5_keyblock *session;		/* session key used to encrypt */
					/* ticket */
    krb5_principal client;		/* client name/realm, optional */
    krb5_principal server;		/* server name/realm, optional */
    krb5_flags flags;			/* ticket flags, optional */
    krb5_ticket_times times;		/* auth, start, end, renew_till, */
					/* optional */
    krb5_address **caddrs;	/* array of ptrs to addresses */
} krb5_cred_info;

typedef struct _krb5_cred_enc_part {
    krb5_magic magic;
    krb5_int32 nonce;			/* nonce, optional */
    krb5_timestamp timestamp;		/* client time */
    krb5_int32 usec;			/* microsecond portion of time */
    krb5_address *s_address;	/* sender address, optional */
    krb5_address *r_address;	/* recipient address, optional */
    krb5_cred_info **ticket_info;
} krb5_cred_enc_part;	 

typedef struct _krb5_cred {
    krb5_magic magic;
    krb5_ticket **tickets;	/* tickets */
    krb5_enc_data enc_part;		/* encrypted part */
    krb5_cred_enc_part *enc_part2;	/* unencrypted version, if available*/
} krb5_cred;

/* Sandia password generation structures */
typedef struct _passwd_phrase_element {
    krb5_magic magic;
    krb5_data *passwd;
    krb5_data *phrase;
} passwd_phrase_element;

typedef struct _krb5_pwd_data {
    krb5_magic magic;
    int sequence_count;
    passwd_phrase_element **element;
} krb5_pwd_data;

/* these need to be here so the typedefs are available for the prototypes */

/*
 * begin "safepriv.h"
 */

#define KRB5_AUTH_CONTEXT_DO_TIME	0x00000001
#define KRB5_AUTH_CONTEXT_RET_TIME	0x00000002
#define KRB5_AUTH_CONTEXT_DO_SEQUENCE	0x00000004
#define KRB5_AUTH_CONTEXT_RET_SEQUENCE	0x00000008
#define KRB5_AUTH_CONTEXT_PERMIT_ALL	0x00000010
#define KRB5_AUTH_CONTEXT_USE_SUBKEY	0x00000020
 
typedef struct krb5_replay_data { 
    krb5_timestamp	timestamp; 
    krb5_int32		usec;
    krb5_ui_4		seq; 
} krb5_replay_data;

/* flags for krb5_auth_con_genaddrs() */
#define KRB5_AUTH_CONTEXT_GENERATE_LOCAL_ADDR		0x00000001
#define KRB5_AUTH_CONTEXT_GENERATE_REMOTE_ADDR		0x00000002
#define KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR	0x00000004
#define KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR	0x00000008

/* type of function used as a callback to generate checksum data for
 * mk_req */

typedef krb5_error_code 
(KRB5_CALLCONV * krb5_mk_req_checksum_func) (krb5_context, krb5_auth_context , void *,
			       krb5_data **);

/*
 * end "safepriv.h"
 */


/*
 * begin "ccache.h"
 */

typedef	krb5_pointer	krb5_cc_cursor;	/* cursor for sequential lookup */

struct _krb5_ccache;
typedef struct _krb5_ccache *krb5_ccache;
struct _krb5_cc_ops;
typedef struct _krb5_cc_ops krb5_cc_ops;

/*
 * Cursor for iterating over all ccaches
 */
struct _krb5_cccol_cursor;
typedef struct _krb5_cccol_cursor *krb5_cccol_cursor;

/* for retrieve_cred */
#define	KRB5_TC_MATCH_TIMES		0x00000001
#define	KRB5_TC_MATCH_IS_SKEY		0x00000002
#define	KRB5_TC_MATCH_FLAGS		0x00000004
#define	KRB5_TC_MATCH_TIMES_EXACT	0x00000008
#define	KRB5_TC_MATCH_FLAGS_EXACT	0x00000010
#define	KRB5_TC_MATCH_AUTHDATA		0x00000020
#define	KRB5_TC_MATCH_SRV_NAMEONLY	0x00000040
#define	KRB5_TC_MATCH_2ND_TKT		0x00000080
#define	KRB5_TC_MATCH_KTYPE		0x00000100
#define KRB5_TC_SUPPORTED_KTYPES	0x00000200

/* for set_flags and other functions */
#define KRB5_TC_OPENCLOSE		0x00000001
#define KRB5_TC_NOTICKET                0x00000002

const char * KRB5_CALLCONV
krb5_cc_get_name (krb5_context context, krb5_ccache cache);

krb5_error_code KRB5_CALLCONV
krb5_cc_gen_new (krb5_context context, krb5_ccache *cache);

krb5_error_code KRB5_CALLCONV
krb5_cc_initialize(krb5_context context, krb5_ccache cache,
		   krb5_principal principal);

krb5_error_code KRB5_CALLCONV
krb5_cc_destroy (krb5_context context, krb5_ccache cache);

krb5_error_code KRB5_CALLCONV
krb5_cc_close (krb5_context context, krb5_ccache cache);

krb5_error_code KRB5_CALLCONV
krb5_cc_store_cred (krb5_context context, krb5_ccache cache,
		    krb5_creds *creds);

krb5_error_code KRB5_CALLCONV
krb5_cc_retrieve_cred (krb5_context context, krb5_ccache cache,
		       krb5_flags flags, krb5_creds *mcreds,
		       krb5_creds *creds);

krb5_error_code KRB5_CALLCONV
krb5_cc_get_principal (krb5_context context, krb5_ccache cache,
		       krb5_principal *principal);

krb5_error_code KRB5_CALLCONV
krb5_cc_start_seq_get (krb5_context context, krb5_ccache cache,
		       krb5_cc_cursor *cursor);

krb5_error_code KRB5_CALLCONV
krb5_cc_next_cred (krb5_context context, krb5_ccache cache,
		   krb5_cc_cursor *cursor, krb5_creds *creds);

krb5_error_code KRB5_CALLCONV
krb5_cc_end_seq_get (krb5_context context, krb5_ccache cache,
		     krb5_cc_cursor *cursor);

krb5_error_code KRB5_CALLCONV
krb5_cc_remove_cred (krb5_context context, krb5_ccache cache, krb5_flags flags,
		     krb5_creds *creds);

krb5_error_code KRB5_CALLCONV
krb5_cc_set_flags (krb5_context context, krb5_ccache cache, krb5_flags flags);

krb5_error_code KRB5_CALLCONV
krb5_cc_get_flags (krb5_context context, krb5_ccache cache, krb5_flags *flags);

const char * KRB5_CALLCONV
krb5_cc_get_type (krb5_context context, krb5_ccache cache);

krb5_error_code KRB5_CALLCONV
krb5_cccol_cursor_new(krb5_context context, krb5_cccol_cursor *cursor);

krb5_error_code KRB5_CALLCONV
krb5_cccol_cursor_next(
    krb5_context context,
    krb5_cccol_cursor cursor,
    krb5_ccache *ccache);

krb5_error_code KRB5_CALLCONV
krb5_cccol_cursor_free(krb5_context context, krb5_cccol_cursor *cursor);

krb5_error_code KRB5_CALLCONV
krb5_cc_new_unique(
    krb5_context context,
    const char *type,
    const char *hint,
    krb5_ccache *id);

/*
 * end "ccache.h"
 */

/*
 * begin "rcache.h"
 */

struct krb5_rc_st;
typedef struct krb5_rc_st *krb5_rcache;

/*
 * end "rcache.h"
 */

/*
 * begin "keytab.h"
 */


/* XXX */
#define MAX_KEYTAB_NAME_LEN 1100 /* Long enough for MAXPATHLEN + some extra */

typedef krb5_pointer krb5_kt_cursor;	/* XXX */

typedef struct krb5_keytab_entry_st {
    krb5_magic magic;
    krb5_principal principal;	/* principal of this key */
    krb5_timestamp timestamp;	/* time entry written to keytable */
    krb5_kvno vno;		/* key version number */
    krb5_keyblock key;		/* the secret key */
} krb5_keytab_entry;

#if KRB5_PRIVATE
struct _krb5_kt_ops;
typedef struct _krb5_kt {	/* should move into k5-int.h */
    krb5_magic magic;
    const struct _krb5_kt_ops *ops;
    krb5_pointer data;
} *krb5_keytab;
#else
struct _krb5_kt;
typedef struct _krb5_kt *krb5_keytab;
#endif

char * KRB5_CALLCONV
krb5_kt_get_type (krb5_context, krb5_keytab keytab);
krb5_error_code KRB5_CALLCONV
krb5_kt_get_name(krb5_context context, krb5_keytab keytab, char *name,
		 unsigned int namelen);
krb5_error_code KRB5_CALLCONV
krb5_kt_close(krb5_context context, krb5_keytab keytab);
krb5_error_code KRB5_CALLCONV
krb5_kt_get_entry(krb5_context context, krb5_keytab keytab,
		  krb5_const_principal principal, krb5_kvno vno,
		  krb5_enctype enctype, krb5_keytab_entry *entry);
krb5_error_code KRB5_CALLCONV
krb5_kt_start_seq_get(krb5_context context, krb5_keytab keytab,
		      krb5_kt_cursor *cursor);
krb5_error_code KRB5_CALLCONV
krb5_kt_next_entry(krb5_context context, krb5_keytab keytab,
		   krb5_keytab_entry *entry, krb5_kt_cursor *cursor);
krb5_error_code KRB5_CALLCONV
krb5_kt_end_seq_get(krb5_context context, krb5_keytab keytab,
		    krb5_kt_cursor *cursor);

/*
 * end "keytab.h"
 */

/*
 * begin "func-proto.h"
 */

krb5_error_code KRB5_CALLCONV krb5_init_context
	(krb5_context *);
krb5_error_code KRB5_CALLCONV krb5_init_secure_context
	(krb5_context *);
void KRB5_CALLCONV krb5_free_context
	(krb5_context);
krb5_error_code KRB5_CALLCONV krb5_copy_context
	(krb5_context, krb5_context *);

#if KRB5_PRIVATE
krb5_error_code krb5_set_default_in_tkt_ktypes
	(krb5_context,
		const krb5_enctype *);
krb5_error_code krb5_get_default_in_tkt_ktypes
	(krb5_context,
		krb5_enctype **);

krb5_error_code krb5_set_default_tgs_ktypes
	(krb5_context,
		const krb5_enctype *);
#endif

krb5_error_code KRB5_CALLCONV 
krb5_set_default_tgs_enctypes
	(krb5_context,
		const krb5_enctype *);
#if KRB5_PRIVATE
krb5_error_code KRB5_CALLCONV krb5_get_tgs_ktypes
	(krb5_context,
		krb5_const_principal,
		krb5_enctype **);
#endif

krb5_error_code KRB5_CALLCONV krb5_get_permitted_enctypes
	(krb5_context, krb5_enctype **);

#if KRB5_PRIVATE
void KRB5_CALLCONV krb5_free_ktypes
	(krb5_context, krb5_enctype *);

krb5_boolean krb5_is_permitted_enctype
	(krb5_context, krb5_enctype);
#endif

krb5_boolean KRB5_CALLCONV krb5_is_thread_safe(void);

/* libkrb.spec */
#if KRB5_PRIVATE
krb5_error_code krb5_kdc_rep_decrypt_proc
	(krb5_context,
		const krb5_keyblock *,
		krb5_const_pointer,
		krb5_kdc_rep * );
krb5_error_code KRB5_CALLCONV krb5_decrypt_tkt_part
	(krb5_context,
		const krb5_keyblock *,
		krb5_ticket * );
krb5_error_code krb5_get_cred_from_kdc
	(krb5_context,
		krb5_ccache,		/* not const, as reading may save
					   state */
		krb5_creds *,
		krb5_creds **,
		krb5_creds *** );
krb5_error_code krb5_get_cred_from_kdc_validate
	(krb5_context,
		krb5_ccache,		/* not const, as reading may save
					   state */
		krb5_creds *,
		krb5_creds **,
		krb5_creds *** );
krb5_error_code krb5_get_cred_from_kdc_renew
	(krb5_context,
		krb5_ccache,		/* not const, as reading may save
					   state */
		krb5_creds *,
		krb5_creds **,
		krb5_creds *** );

krb5_error_code KRB5_CALLCONV
krb5int_server_decrypt_ticket_keyblock
  	(krb5_context context,
                const krb5_keyblock *key,
                krb5_ticket  *ticket);
#endif

krb5_error_code KRB5_CALLCONV
krb5_server_decrypt_ticket_keytab
  	(krb5_context context,
                const krb5_keytab kt,
                krb5_ticket  *ticket);

void KRB5_CALLCONV krb5_free_tgt_creds
	(krb5_context,
	 krb5_creds **); /* XXX too hard to do with const */

#define	KRB5_GC_USER_USER	1	/* want user-user ticket */
#define	KRB5_GC_CACHED		2	/* want cached ticket only */

krb5_error_code KRB5_CALLCONV krb5_get_credentials
	(krb5_context,
		krb5_flags,
		krb5_ccache,
		krb5_creds *,
		krb5_creds **);
krb5_error_code KRB5_CALLCONV krb5_get_credentials_validate
	(krb5_context,
		krb5_flags,
		krb5_ccache,
		krb5_creds *,
		krb5_creds **);
krb5_error_code KRB5_CALLCONV krb5_get_credentials_renew
	(krb5_context,
		krb5_flags,
		krb5_ccache,
		krb5_creds *,
		krb5_creds **);
#if KRB5_PRIVATE
krb5_error_code krb5_get_cred_via_tkt
	(krb5_context,
		   krb5_creds *,
		   krb5_flags,
		   krb5_address * const *,
		   krb5_creds *,
		   krb5_creds **);
#endif
krb5_error_code KRB5_CALLCONV krb5_mk_req
	(krb5_context,
		krb5_auth_context *,
		krb5_flags,
		char *,
		char *,
		krb5_data *,
		krb5_ccache,
		krb5_data * );
krb5_error_code KRB5_CALLCONV krb5_mk_req_extended
	(krb5_context,
		krb5_auth_context *,
		krb5_flags,
		krb5_data *,
		krb5_creds *,
		krb5_data * );
krb5_error_code KRB5_CALLCONV krb5_mk_rep
	(krb5_context,
		krb5_auth_context,
		krb5_data *);
krb5_error_code KRB5_CALLCONV krb5_rd_rep
	(krb5_context,
		krb5_auth_context,
		const krb5_data *,
		krb5_ap_rep_enc_part **);
krb5_error_code KRB5_CALLCONV krb5_mk_error
	(krb5_context,
		const krb5_error *,
		krb5_data * );
krb5_error_code KRB5_CALLCONV krb5_rd_error
	(krb5_context,
		const krb5_data *,
		krb5_error ** );
krb5_error_code KRB5_CALLCONV krb5_rd_safe
	(krb5_context,
		krb5_auth_context,
		const krb5_data *,
		krb5_data *,
		krb5_replay_data *);
krb5_error_code KRB5_CALLCONV krb5_rd_priv
	(krb5_context,
		krb5_auth_context,
		const krb5_data *,
		krb5_data *,
		krb5_replay_data *);
krb5_error_code KRB5_CALLCONV krb5_parse_name
	(krb5_context,
		const char *,
		krb5_principal * );
krb5_error_code KRB5_CALLCONV krb5_unparse_name
	(krb5_context,
		krb5_const_principal,
		char ** );
krb5_error_code KRB5_CALLCONV krb5_unparse_name_ext
	(krb5_context,
		krb5_const_principal,
		char **,
		unsigned int *);

krb5_error_code KRB5_CALLCONV krb5_set_principal_realm
	(krb5_context, krb5_principal, const char *);

krb5_boolean KRB5_CALLCONV_WRONG krb5_address_search
	(krb5_context,
		const krb5_address *,
		krb5_address * const *);
krb5_boolean KRB5_CALLCONV krb5_address_compare
	(krb5_context,
		const krb5_address *,
		const krb5_address *);
int KRB5_CALLCONV krb5_address_order
	(krb5_context,
		const krb5_address *,
		const krb5_address *);
krb5_boolean KRB5_CALLCONV krb5_realm_compare
	(krb5_context,
		krb5_const_principal,
		krb5_const_principal);
krb5_boolean KRB5_CALLCONV krb5_principal_compare
	(krb5_context,
		krb5_const_principal,
		krb5_const_principal);
krb5_error_code KRB5_CALLCONV  krb5_init_keyblock
		(krb5_context, krb5_enctype enctype,
		size_t length, krb5_keyblock **out); 
  		/* Initialize a new keyblock and allocate storage
		 * for the contents of the key, which will be freed along
		 * with the keyblock when krb5_free_keyblock is called.
		 * It is legal to pass in a length of 0, in which
		 * case contents are left unallocated.
		 */
krb5_error_code KRB5_CALLCONV krb5_copy_keyblock
	(krb5_context,
		const krb5_keyblock *,
		krb5_keyblock **);
krb5_error_code KRB5_CALLCONV krb5_copy_keyblock_contents
	(krb5_context,
		const krb5_keyblock *,
		krb5_keyblock *);
krb5_error_code KRB5_CALLCONV krb5_copy_creds
	(krb5_context,
		const krb5_creds *,
		krb5_creds **);
krb5_error_code KRB5_CALLCONV krb5_copy_data
	(krb5_context,
		const krb5_data *,
		krb5_data **);
krb5_error_code KRB5_CALLCONV krb5_copy_principal
	(krb5_context,
		krb5_const_principal,
		krb5_principal *);
#if KRB5_PRIVATE
krb5_error_code KRB5_CALLCONV krb5_copy_addr
	(krb5_context,
		const krb5_address *,
		krb5_address **);
#endif
krb5_error_code KRB5_CALLCONV krb5_copy_addresses
	(krb5_context,
		krb5_address * const *,
		krb5_address ***);
krb5_error_code KRB5_CALLCONV krb5_copy_ticket
	(krb5_context,
		const krb5_ticket *,
		krb5_ticket **);
krb5_error_code KRB5_CALLCONV krb5_copy_authdata
	(krb5_context,
		krb5_authdata * const *,
		krb5_authdata ***);
krb5_error_code KRB5_CALLCONV krb5_copy_authenticator
	(krb5_context,
		const krb5_authenticator *,
		krb5_authenticator **);
krb5_error_code KRB5_CALLCONV krb5_copy_checksum
	(krb5_context,
		const krb5_checksum *,
		krb5_checksum **);
#if KRB5_PRIVATE
void krb5_init_ets
	(krb5_context);
void krb5_free_ets
	(krb5_context);
krb5_error_code krb5_generate_subkey
	(krb5_context,
		const krb5_keyblock *, krb5_keyblock **);
krb5_error_code krb5_generate_seq_number
	(krb5_context,
		const krb5_keyblock *, krb5_ui_4 *);
#endif
krb5_error_code KRB5_CALLCONV krb5_get_server_rcache
	(krb5_context,
		const krb5_data *, krb5_rcache *);
krb5_error_code KRB5_CALLCONV_C krb5_build_principal_ext
	(krb5_context, krb5_principal *, unsigned int, const char *, ...);
krb5_error_code KRB5_CALLCONV_C krb5_build_principal
	(krb5_context, krb5_principal *, unsigned int, const char *, ...);
#ifdef va_start
/* XXX depending on varargs include file defining va_start... */
krb5_error_code KRB5_CALLCONV krb5_build_principal_va
	(krb5_context,
		krb5_principal, unsigned int, const char *, va_list);
#endif

krb5_error_code KRB5_CALLCONV krb5_425_conv_principal
	(krb5_context,
		const char *name,
		const char *instance, const char *realm,
		krb5_principal *princ);

krb5_error_code KRB5_CALLCONV krb5_524_conv_principal
	(krb5_context context, krb5_const_principal princ, 
		char *name, char *inst, char *realm);

struct credentials;
int KRB5_CALLCONV krb5_524_convert_creds
	(krb5_context context, krb5_creds *v5creds,
	 struct credentials *v4creds);
#if KRB5_DEPRECATED
#define krb524_convert_creds_kdc krb5_524_convert_creds
#define krb524_init_ets(x) (0)
#endif

/* libkt.spec */
#if KRB5_PRIVATE
krb5_error_code KRB5_CALLCONV krb5_kt_register
	(krb5_context,
		const struct _krb5_kt_ops * );
#endif

krb5_error_code KRB5_CALLCONV krb5_kt_resolve
	(krb5_context,
		const char *,
		krb5_keytab * );
krb5_error_code KRB5_CALLCONV krb5_kt_default_name
	(krb5_context,
		char *,
		int );
krb5_error_code KRB5_CALLCONV krb5_kt_default
	(krb5_context,
		krb5_keytab * );
krb5_error_code KRB5_CALLCONV krb5_free_keytab_entry_contents
	(krb5_context,
		krb5_keytab_entry * );
#if KRB5_PRIVATE
/* use krb5_free_keytab_entry_contents instead */
krb5_error_code KRB5_CALLCONV krb5_kt_free_entry
	(krb5_context,
		krb5_keytab_entry * );
#endif
/* remove and add are functions, so that they can return NOWRITE
   if not a writable keytab */
krb5_error_code KRB5_CALLCONV krb5_kt_remove_entry
	(krb5_context,
		krb5_keytab,
		krb5_keytab_entry * );
krb5_error_code KRB5_CALLCONV krb5_kt_add_entry
	(krb5_context,
		krb5_keytab,
		krb5_keytab_entry * );
krb5_error_code KRB5_CALLCONV_WRONG krb5_principal2salt
	(krb5_context,
		krb5_const_principal, krb5_data *);
#if KRB5_PRIVATE
krb5_error_code krb5_principal2salt_norealm
	(krb5_context,
		krb5_const_principal, krb5_data *);
#endif
/* librc.spec--see rcache.h */

/* libcc.spec */
krb5_error_code KRB5_CALLCONV krb5_cc_resolve
	(krb5_context,
		const char *,
		krb5_ccache * );
const char * KRB5_CALLCONV krb5_cc_default_name
	(krb5_context);
krb5_error_code KRB5_CALLCONV krb5_cc_set_default_name
	(krb5_context, const char *);
krb5_error_code KRB5_CALLCONV krb5_cc_default
	(krb5_context,
		krb5_ccache *);
#if KRB5_PRIVATE
unsigned int KRB5_CALLCONV krb5_get_notification_message
	(void);
#endif

krb5_error_code KRB5_CALLCONV krb5_cc_copy_creds
	(krb5_context context,
			krb5_ccache incc,
			krb5_ccache outcc);


/* chk_trans.c */
#if KRB5_PRIVATE
krb5_error_code krb5_check_transited_list
	(krb5_context, const krb5_data *trans,
	 const krb5_data *realm1, const krb5_data *realm2);
#endif

/* free_rtree.c */
#if KRB5_PRIVATE
void krb5_free_realm_tree
	(krb5_context,
		krb5_principal *);
#endif

/* krb5_free.c */
void KRB5_CALLCONV krb5_free_principal
	(krb5_context, krb5_principal );
void KRB5_CALLCONV krb5_free_authenticator
	(krb5_context, krb5_authenticator * );
#if KRB5_PRIVATE
void KRB5_CALLCONV krb5_free_authenticator_contents
	(krb5_context, krb5_authenticator * );
#endif
void KRB5_CALLCONV krb5_free_addresses
	(krb5_context, krb5_address ** );
#if KRB5_PRIVATE
void KRB5_CALLCONV krb5_free_address
	(krb5_context, krb5_address * );
#endif
void KRB5_CALLCONV krb5_free_authdata
	(krb5_context, krb5_authdata ** );
#if KRB5_PRIVATE
void KRB5_CALLCONV krb5_free_enc_tkt_part
	(krb5_context, krb5_enc_tkt_part * );
#endif
void KRB5_CALLCONV krb5_free_ticket
	(krb5_context, krb5_ticket * );
#if KRB5_PRIVATE
void KRB5_CALLCONV krb5_free_tickets
	(krb5_context, krb5_ticket ** );
void KRB5_CALLCONV krb5_free_kdc_req
	(krb5_context, krb5_kdc_req * );
void KRB5_CALLCONV krb5_free_kdc_rep
	(krb5_context, krb5_kdc_rep * );
void KRB5_CALLCONV krb5_free_last_req
	(krb5_context, krb5_last_req_entry ** );
void KRB5_CALLCONV krb5_free_enc_kdc_rep_part
	(krb5_context, krb5_enc_kdc_rep_part * );
#endif
void KRB5_CALLCONV krb5_free_error
	(krb5_context, krb5_error * );
#if KRB5_PRIVATE
void KRB5_CALLCONV krb5_free_ap_req
	(krb5_context, krb5_ap_req * );
void KRB5_CALLCONV krb5_free_ap_rep
	(krb5_context, krb5_ap_rep * );
void KRB5_CALLCONV krb5_free_cred
	(krb5_context, krb5_cred *);
#endif
void KRB5_CALLCONV krb5_free_creds
	(krb5_context, krb5_creds *);
void KRB5_CALLCONV krb5_free_cred_contents
	(krb5_context, krb5_creds *);
#if KRB5_PRIVATE
void KRB5_CALLCONV krb5_free_cred_enc_part
	(krb5_context, krb5_cred_enc_part *);
#endif
void KRB5_CALLCONV krb5_free_checksum
	(krb5_context, krb5_checksum *);
void KRB5_CALLCONV krb5_free_checksum_contents
	(krb5_context, krb5_checksum *);
void KRB5_CALLCONV krb5_free_keyblock
	(krb5_context, krb5_keyblock *);
void KRB5_CALLCONV krb5_free_keyblock_contents
	(krb5_context, krb5_keyblock *);
#if KRB5_PRIVATE
void KRB5_CALLCONV krb5_free_pa_data
	(krb5_context, krb5_pa_data **);
#endif
void KRB5_CALLCONV krb5_free_ap_rep_enc_part
	(krb5_context, krb5_ap_rep_enc_part *);
#if KRB5_PRIVATE
void KRB5_CALLCONV krb5_free_tkt_authent
	(krb5_context, krb5_tkt_authent *);
void KRB5_CALLCONV krb5_free_pwd_data
	(krb5_context, krb5_pwd_data *);
void KRB5_CALLCONV krb5_free_pwd_sequences
	(krb5_context, passwd_phrase_element **);
#endif
void KRB5_CALLCONV krb5_free_data
	(krb5_context, krb5_data *);
void KRB5_CALLCONV krb5_free_data_contents
	(krb5_context, krb5_data *);
void KRB5_CALLCONV krb5_free_unparsed_name
	(krb5_context, char *);
void KRB5_CALLCONV krb5_free_cksumtypes
	(krb5_context, krb5_cksumtype *);

/* From krb5/os but needed but by the outside world */
krb5_error_code KRB5_CALLCONV krb5_us_timeofday
	(krb5_context,
		krb5_timestamp *,
		krb5_int32 * );
krb5_error_code KRB5_CALLCONV krb5_timeofday
	(krb5_context,
		krb5_timestamp * );
		 /* get all the addresses of this host */
krb5_error_code KRB5_CALLCONV krb5_os_localaddr
	(krb5_context,
		krb5_address ***);
krb5_error_code KRB5_CALLCONV krb5_get_default_realm
	(krb5_context,
		 char ** );
krb5_error_code KRB5_CALLCONV krb5_set_default_realm
	(krb5_context,
		   const char * );
void KRB5_CALLCONV krb5_free_default_realm
	(krb5_context,
		   char * );
krb5_error_code KRB5_CALLCONV krb5_sname_to_principal
	(krb5_context,
		const char *,
		   const char *,
		   krb5_int32,
		   krb5_principal *);
krb5_error_code KRB5_CALLCONV
krb5_change_password
	(krb5_context context, krb5_creds *creds, char *newpw,
			int *result_code, krb5_data *result_code_string,
			krb5_data *result_string);
krb5_error_code KRB5_CALLCONV
krb5_set_password
	(krb5_context context, krb5_creds *creds, char *newpw, krb5_principal change_password_for,
			int *result_code, krb5_data *result_code_string, krb5_data *result_string);
krb5_error_code KRB5_CALLCONV
krb5_set_password_using_ccache
	(krb5_context context, krb5_ccache ccache, char *newpw, krb5_principal change_password_for,
			int *result_code, krb5_data *result_code_string, krb5_data *result_string);

#if KRB5_PRIVATE
krb5_error_code krb5_set_config_files
	(krb5_context, const char **);

krb5_error_code KRB5_CALLCONV krb5_get_default_config_files
	(char ***filenames);

void KRB5_CALLCONV krb5_free_config_files
	(char **filenames);
#endif

krb5_error_code KRB5_CALLCONV
krb5_get_profile
	(krb5_context, struct _profile_t * /* profile_t */ *);

#if KRB5_PRIVATE
krb5_error_code krb5_send_tgs
	(krb5_context,
		krb5_flags,
		const krb5_ticket_times *,
		const krb5_enctype *,
		krb5_const_principal,
		krb5_address * const *,
		krb5_authdata * const *,
		krb5_pa_data * const *,
		const krb5_data *,
		krb5_creds *,
		krb5_response * );
#endif

#if KRB5_DEPRECATED
krb5_error_code KRB5_CALLCONV krb5_get_in_tkt
	(krb5_context,
		krb5_flags,
		krb5_address * const *,
		krb5_enctype *,
		krb5_preauthtype *,
		krb5_error_code ( * )(krb5_context,
					krb5_enctype,
					krb5_data *,
					krb5_const_pointer,
					krb5_keyblock **),
		krb5_const_pointer,
		krb5_error_code ( * )(krb5_context,
					const krb5_keyblock *,
					krb5_const_pointer,
					krb5_kdc_rep * ),
		krb5_const_pointer,
		krb5_creds *,
		krb5_ccache,
		krb5_kdc_rep ** );

krb5_error_code KRB5_CALLCONV krb5_get_in_tkt_with_password
	(krb5_context,
		krb5_flags,
		krb5_address * const *,
		krb5_enctype *,
		krb5_preauthtype *,
		const char *,
		krb5_ccache,
		krb5_creds *,
		krb5_kdc_rep ** );

krb5_error_code KRB5_CALLCONV krb5_get_in_tkt_with_skey
	(krb5_context,
		krb5_flags,
		krb5_address * const *,
		krb5_enctype *,
		krb5_preauthtype *,
		const krb5_keyblock *,
		krb5_ccache,
		krb5_creds *,
		krb5_kdc_rep ** );

krb5_error_code KRB5_CALLCONV krb5_get_in_tkt_with_keytab
	(krb5_context,
		krb5_flags,
		krb5_address * const *,
		krb5_enctype *,
		krb5_preauthtype *,
		krb5_keytab,
		krb5_ccache,
		krb5_creds *,
		krb5_kdc_rep ** );
#endif /* KRB5_DEPRECATED */

#if KRB5_PRIVATE
krb5_error_code krb5_decode_kdc_rep
	(krb5_context,
		krb5_data *,
		const krb5_keyblock *,
		krb5_kdc_rep ** );
#endif

krb5_error_code KRB5_CALLCONV krb5_rd_req
	(krb5_context,
		krb5_auth_context *,
		const krb5_data *,
		krb5_const_principal,
		krb5_keytab,
		krb5_flags *,
		krb5_ticket **);

#if KRB5_PRIVATE
krb5_error_code krb5_rd_req_decoded
	(krb5_context,
		krb5_auth_context *,
		const krb5_ap_req *,
		krb5_const_principal,
		krb5_keytab,
		krb5_flags *,
		krb5_ticket **);

krb5_error_code krb5_rd_req_decoded_anyflag
	(krb5_context,
		krb5_auth_context *,
		const krb5_ap_req *,
		krb5_const_principal,
		krb5_keytab,
		krb5_flags *,
		krb5_ticket **);
#endif

krb5_error_code KRB5_CALLCONV krb5_kt_read_service_key
	(krb5_context,
		krb5_pointer,
		krb5_principal,
		krb5_kvno,
		krb5_enctype,
		krb5_keyblock **);
krb5_error_code KRB5_CALLCONV krb5_mk_safe
	(krb5_context,
		krb5_auth_context,
		const krb5_data *,
		krb5_data *,
		krb5_replay_data *);
krb5_error_code KRB5_CALLCONV krb5_mk_priv
	(krb5_context,
		krb5_auth_context,
		const krb5_data *,
		krb5_data *,
		krb5_replay_data *);
#if KRB5_PRIVATE
krb5_error_code KRB5_CALLCONV krb5_cc_register
	(krb5_context,
		krb5_cc_ops *,
		krb5_boolean );
#endif

krb5_error_code KRB5_CALLCONV krb5_sendauth 
	(krb5_context,
		krb5_auth_context *,
		krb5_pointer,
		char *,
		krb5_principal,
		krb5_principal,
		krb5_flags,
		krb5_data *,
		krb5_creds *,
		krb5_ccache,
		krb5_error **,
		krb5_ap_rep_enc_part **,
		krb5_creds **);
	
krb5_error_code KRB5_CALLCONV krb5_recvauth
	(krb5_context,
		krb5_auth_context *,
		krb5_pointer,
		char *,
		krb5_principal,
		krb5_int32, 
		krb5_keytab,
		krb5_ticket **);
krb5_error_code KRB5_CALLCONV krb5_recvauth_version
	(krb5_context,
		krb5_auth_context *,
		krb5_pointer,
		krb5_principal,
		krb5_int32, 
		krb5_keytab,
		krb5_ticket **,
		krb5_data *);

#if KRB5_PRIVATE
krb5_error_code krb5_walk_realm_tree
	(krb5_context,
		const krb5_data *,
		const krb5_data *,
		krb5_principal **,
		int);
#endif

krb5_error_code KRB5_CALLCONV krb5_mk_ncred
	(krb5_context,
		krb5_auth_context,
		krb5_creds **,
		krb5_data **,
		krb5_replay_data *);

krb5_error_code KRB5_CALLCONV krb5_mk_1cred
	(krb5_context,
		krb5_auth_context,
		krb5_creds *,
		krb5_data **,
		krb5_replay_data *);

krb5_error_code KRB5_CALLCONV krb5_rd_cred
	(krb5_context,
		krb5_auth_context,
		krb5_data *,
		krb5_creds ***,
		krb5_replay_data *);

krb5_error_code KRB5_CALLCONV krb5_fwd_tgt_creds
	(krb5_context, 
		krb5_auth_context,
		char *,
		krb5_principal, 
		krb5_principal, 
		krb5_ccache,
		int forwardable,
		krb5_data *);	

krb5_error_code KRB5_CALLCONV krb5_auth_con_init
	(krb5_context,
		krb5_auth_context *);

krb5_error_code KRB5_CALLCONV krb5_auth_con_free
	(krb5_context,
		krb5_auth_context);

krb5_error_code KRB5_CALLCONV krb5_auth_con_setflags
	(krb5_context,
		krb5_auth_context,
		krb5_int32);

krb5_error_code KRB5_CALLCONV krb5_auth_con_getflags
	(krb5_context,
		krb5_auth_context,
		krb5_int32 *);

krb5_error_code KRB5_CALLCONV
krb5_auth_con_set_checksum_func (krb5_context, krb5_auth_context,
				 krb5_mk_req_checksum_func, void *);

krb5_error_code KRB5_CALLCONV
krb5_auth_con_get_checksum_func( krb5_context, krb5_auth_context,
				 krb5_mk_req_checksum_func *, void **);

krb5_error_code KRB5_CALLCONV_WRONG krb5_auth_con_setaddrs
	(krb5_context,
		krb5_auth_context,
		krb5_address *,
		krb5_address *);

krb5_error_code KRB5_CALLCONV krb5_auth_con_getaddrs
	(krb5_context,
		krb5_auth_context,
		krb5_address **,
		krb5_address **);

krb5_error_code KRB5_CALLCONV krb5_auth_con_setports
	(krb5_context,
		krb5_auth_context,
		krb5_address *,
		krb5_address *);

krb5_error_code KRB5_CALLCONV krb5_auth_con_setuseruserkey
	(krb5_context,
		krb5_auth_context,
		krb5_keyblock *);

krb5_error_code KRB5_CALLCONV krb5_auth_con_getkey
	(krb5_context,
		krb5_auth_context,
		krb5_keyblock **);

krb5_error_code KRB5_CALLCONV krb5_auth_con_getsendsubkey(
    krb5_context, krb5_auth_context, krb5_keyblock **);

krb5_error_code KRB5_CALLCONV krb5_auth_con_getrecvsubkey(
    krb5_context, krb5_auth_context, krb5_keyblock **);

krb5_error_code KRB5_CALLCONV krb5_auth_con_setsendsubkey(
    krb5_context, krb5_auth_context, krb5_keyblock *);

krb5_error_code KRB5_CALLCONV krb5_auth_con_setrecvsubkey(
    krb5_context, krb5_auth_context, krb5_keyblock *);

#if KRB5_DEPRECATED
krb5_error_code KRB5_CALLCONV krb5_auth_con_getlocalsubkey
	(krb5_context,
		krb5_auth_context,
		krb5_keyblock **);

krb5_error_code KRB5_CALLCONV krb5_auth_con_getremotesubkey
	(krb5_context,
		krb5_auth_context,
		krb5_keyblock **);
#endif

#if KRB5_PRIVATE
krb5_error_code KRB5_CALLCONV krb5_auth_con_set_req_cksumtype
	(krb5_context,
		krb5_auth_context,
		krb5_cksumtype);

krb5_error_code krb5_auth_con_set_safe_cksumtype
	(krb5_context,
		krb5_auth_context,
		krb5_cksumtype);
#endif

krb5_error_code KRB5_CALLCONV krb5_auth_con_getlocalseqnumber
	(krb5_context,
		krb5_auth_context,
		krb5_int32 *);

krb5_error_code KRB5_CALLCONV krb5_auth_con_getremoteseqnumber
	(krb5_context,
		krb5_auth_context,
		krb5_int32 *);

#if KRB5_DEPRECATED
krb5_error_code KRB5_CALLCONV krb5_auth_con_initivector
	(krb5_context,
		krb5_auth_context);
#endif

#if KRB5_PRIVATE
krb5_error_code krb5_auth_con_setivector
	(krb5_context,
		krb5_auth_context,
		krb5_pointer);

krb5_error_code krb5_auth_con_getivector
	(krb5_context,
		krb5_auth_context,
		krb5_pointer *);
#endif

krb5_error_code KRB5_CALLCONV krb5_auth_con_setrcache
	(krb5_context,
		krb5_auth_context,
		krb5_rcache);

krb5_error_code KRB5_CALLCONV_WRONG krb5_auth_con_getrcache
	(krb5_context,
		krb5_auth_context,
		krb5_rcache *);

#if KRB5_PRIVATE
krb5_error_code krb5_auth_con_setpermetypes
	(krb5_context,
	    krb5_auth_context,
	    const krb5_enctype *);

krb5_error_code krb5_auth_con_getpermetypes
	(krb5_context,
	    krb5_auth_context,
	    krb5_enctype **);
#endif

krb5_error_code KRB5_CALLCONV krb5_auth_con_getauthenticator
	(krb5_context,
		krb5_auth_context,
		krb5_authenticator **);

#define KRB5_REALM_BRANCH_CHAR '.'

/*
 * end "func-proto.h"
 */

/*
 * begin stuff from libos.h
 */

#if KRB5_PRIVATE
krb5_error_code krb5_read_message (krb5_context, krb5_pointer, krb5_data *);
krb5_error_code krb5_write_message (krb5_context, krb5_pointer, krb5_data *);
int krb5_net_read (krb5_context, int , char *, int);
int krb5_net_write (krb5_context, int , const char *, int);
#endif

krb5_error_code KRB5_CALLCONV krb5_read_password
	(krb5_context,
		const char *,
		const char *,
		char *,
		unsigned int * );
krb5_error_code KRB5_CALLCONV krb5_aname_to_localname
	(krb5_context,
		krb5_const_principal,
		int,
		char * );
krb5_error_code KRB5_CALLCONV krb5_get_host_realm
	(krb5_context,
		const char *,
		char *** );
krb5_error_code KRB5_CALLCONV krb5_get_fallback_host_realm
	(krb5_context,
		krb5_data *,
		char *** );
krb5_error_code KRB5_CALLCONV krb5_free_host_realm
	(krb5_context,
		char * const * );
#if KRB5_PRIVATE
krb5_error_code KRB5_CALLCONV krb5_get_realm_domain
	(krb5_context,
		const char *,
		char ** );
#endif
krb5_boolean KRB5_CALLCONV krb5_kuserok
	(krb5_context,
		krb5_principal, const char *);
krb5_error_code KRB5_CALLCONV krb5_auth_con_genaddrs
	(krb5_context,
		krb5_auth_context,
		int, int);
#if KRB5_PRIVATE
krb5_error_code krb5_gen_portaddr
	(krb5_context,
		const krb5_address *,
		krb5_const_pointer,
		krb5_address **);
krb5_error_code krb5_gen_replay_name
	(krb5_context,
		const krb5_address *,
		const char *,
		char **);
krb5_error_code krb5_make_fulladdr
	(krb5_context,
		krb5_address *,
		krb5_address *,
		krb5_address *);
#endif

krb5_error_code KRB5_CALLCONV krb5_set_real_time
	(krb5_context, krb5_timestamp, krb5_int32);

#if KRB5_PRIVATE
krb5_error_code krb5_set_debugging_time
	(krb5_context, krb5_timestamp, krb5_int32);
krb5_error_code krb5_use_natural_time
	(krb5_context);
#endif
krb5_error_code KRB5_CALLCONV krb5_get_time_offsets
	(krb5_context, krb5_timestamp *, krb5_int32 *);
#if KRB5_PRIVATE
krb5_error_code krb5_set_time_offsets
	(krb5_context, krb5_timestamp, krb5_int32);
#endif

/* str_conv.c */
krb5_error_code KRB5_CALLCONV krb5_string_to_enctype
	(char *, krb5_enctype *);
krb5_error_code KRB5_CALLCONV krb5_string_to_salttype
	(char *, krb5_int32 *);
krb5_error_code KRB5_CALLCONV krb5_string_to_cksumtype
	(char *, krb5_cksumtype *);
krb5_error_code KRB5_CALLCONV krb5_string_to_timestamp
	(char *, krb5_timestamp *);
krb5_error_code KRB5_CALLCONV krb5_string_to_deltat
	(char *, krb5_deltat *);
krb5_error_code KRB5_CALLCONV krb5_enctype_to_string
	(krb5_enctype, char *, size_t);
krb5_error_code KRB5_CALLCONV krb5_salttype_to_string
	(krb5_int32, char *, size_t);
krb5_error_code KRB5_CALLCONV krb5_cksumtype_to_string
	(krb5_cksumtype, char *, size_t);
krb5_error_code KRB5_CALLCONV krb5_timestamp_to_string
	(krb5_timestamp, char *, size_t);
krb5_error_code KRB5_CALLCONV krb5_timestamp_to_sfstring
	(krb5_timestamp, char *, size_t, char *);
krb5_error_code KRB5_CALLCONV krb5_deltat_to_string
	(krb5_deltat, char *, size_t);



/* The name of the Kerberos ticket granting service... and its size */
#define	KRB5_TGS_NAME		"krbtgt"
#define KRB5_TGS_NAME_SIZE	6

/* flags for recvauth */
#define KRB5_RECVAUTH_SKIP_VERSION	0x0001
#define KRB5_RECVAUTH_BADAUTHVERS	0x0002
/* initial ticket api functions */

typedef struct _krb5_prompt {
    char *prompt;
    int hidden;
    krb5_data *reply;
} krb5_prompt;

typedef krb5_error_code (KRB5_CALLCONV *krb5_prompter_fct)(krb5_context context,
					     void *data,
					     const char *name,
					     const char *banner,
					     int num_prompts,
					     krb5_prompt prompts[]);


krb5_error_code KRB5_CALLCONV
krb5_prompter_posix (krb5_context context,
		void *data,
		const char *name,
		const char *banner,
		int num_prompts,
		krb5_prompt prompts[]);

typedef struct _krb5_get_init_creds_opt {
    krb5_flags flags;
    krb5_deltat tkt_life;
    krb5_deltat renew_life;
    int forwardable;
    int proxiable;
    krb5_enctype *etype_list;
    int etype_list_length;
    krb5_address **address_list;
    krb5_preauthtype *preauth_list;
    int preauth_list_length;
    krb5_data *salt;
} krb5_get_init_creds_opt;

#define KRB5_GET_INIT_CREDS_OPT_TKT_LIFE	0x0001
#define KRB5_GET_INIT_CREDS_OPT_RENEW_LIFE	0x0002
#define KRB5_GET_INIT_CREDS_OPT_FORWARDABLE	0x0004
#define KRB5_GET_INIT_CREDS_OPT_PROXIABLE	0x0008
#define KRB5_GET_INIT_CREDS_OPT_ETYPE_LIST	0x0010
#define KRB5_GET_INIT_CREDS_OPT_ADDRESS_LIST	0x0020
#define KRB5_GET_INIT_CREDS_OPT_PREAUTH_LIST	0x0040
#define KRB5_GET_INIT_CREDS_OPT_SALT		0x0080
#define KRB5_GET_INIT_CREDS_OPT_CHG_PWD_PRMPT	0x0100

krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_opt_alloc
(krb5_context context,
		krb5_get_init_creds_opt **opt);

void KRB5_CALLCONV
krb5_get_init_creds_opt_free
(krb5_context context,
		krb5_get_init_creds_opt *opt);

void KRB5_CALLCONV
krb5_get_init_creds_opt_init
(krb5_get_init_creds_opt *opt);

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_tkt_life
(krb5_get_init_creds_opt *opt,
		krb5_deltat tkt_life);

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_renew_life
(krb5_get_init_creds_opt *opt,
		krb5_deltat renew_life);

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_forwardable
(krb5_get_init_creds_opt *opt,
		int forwardable);

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_proxiable
(krb5_get_init_creds_opt *opt,
		int proxiable);

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_etype_list
(krb5_get_init_creds_opt *opt,
		krb5_enctype *etype_list,
		int etype_list_length);

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_address_list
(krb5_get_init_creds_opt *opt,
		krb5_address **addresses);

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_preauth_list
(krb5_get_init_creds_opt *opt,
		krb5_preauthtype *preauth_list,
		int preauth_list_length);

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_salt
(krb5_get_init_creds_opt *opt,
		krb5_data *salt);

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_change_password_prompt
(krb5_get_init_creds_opt *opt,
		int prompt);

/* Generic preauth option attribute/value pairs */
typedef struct _krb5_gic_opt_pa_data {
    char *attr;
    char *value;
} krb5_gic_opt_pa_data;

/*
 * This function allows the caller to supply options to preauth
 * plugins.  Preauth plugin modules are given a chance to look
 * at each option at the time this function is called in ordre
 * to check the validity of the option.
 * The 'opt' pointer supplied to this function must have been
 * obtained using krb5_get_init_creds_opt_alloc()
 */
krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_opt_set_pa
		(krb5_context context,
		krb5_get_init_creds_opt *opt,
		const char *attr,
		const char *value);

krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_password
(krb5_context context,
		krb5_creds *creds,
		krb5_principal client,
		char *password,
		krb5_prompter_fct prompter,
		void *data,
		krb5_deltat start_time,
		char *in_tkt_service,
		krb5_get_init_creds_opt *k5_gic_options);

krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_keytab
(krb5_context context,
		krb5_creds *creds,
		krb5_principal client,
		krb5_keytab arg_keytab,
		krb5_deltat start_time,
		char *in_tkt_service,
		krb5_get_init_creds_opt *k5_gic_options);

typedef struct _krb5_verify_init_creds_opt {
    krb5_flags flags;
    int ap_req_nofail;
} krb5_verify_init_creds_opt;

#define KRB5_VERIFY_INIT_CREDS_OPT_AP_REQ_NOFAIL	0x0001

void KRB5_CALLCONV
krb5_verify_init_creds_opt_init
(krb5_verify_init_creds_opt *k5_vic_options);
void KRB5_CALLCONV
krb5_verify_init_creds_opt_set_ap_req_nofail
(krb5_verify_init_creds_opt *k5_vic_options,
		int ap_req_nofail);

krb5_error_code KRB5_CALLCONV
krb5_verify_init_creds
(krb5_context context,
		krb5_creds *creds,
		krb5_principal ap_req_server,
		krb5_keytab ap_req_keytab,
		krb5_ccache *ccache,
		krb5_verify_init_creds_opt *k5_vic_options);

krb5_error_code KRB5_CALLCONV
krb5_get_validated_creds
(krb5_context context,
		krb5_creds *creds,
		krb5_principal client,
		krb5_ccache ccache,
		char *in_tkt_service);

krb5_error_code KRB5_CALLCONV
krb5_get_renewed_creds
(krb5_context context,
		krb5_creds *creds,
		krb5_principal client,
		krb5_ccache ccache,
		char *in_tkt_service);

krb5_error_code KRB5_CALLCONV
krb5_decode_ticket
(const krb5_data *code, 
		krb5_ticket **rep);

void KRB5_CALLCONV
krb5_appdefault_string
(krb5_context context,
		const char *appname,  
	        const krb5_data *realm,
 		const char *option,
		const char *default_value,
		char ** ret_value);

void KRB5_CALLCONV
krb5_appdefault_boolean
(krb5_context context,
		const char *appname,  
	        const krb5_data *realm,
 		const char *option,
		int default_value,
		int *ret_value);

#if KRB5_PRIVATE
/*
 * The realm iterator functions
 */

krb5_error_code KRB5_CALLCONV krb5_realm_iterator_create
	(krb5_context context, void **iter_p);

krb5_error_code KRB5_CALLCONV krb5_realm_iterator
	(krb5_context context, void **iter_p, char **ret_realm);

void KRB5_CALLCONV krb5_realm_iterator_free
	(krb5_context context, void **iter_p);

void KRB5_CALLCONV krb5_free_realm_string
	(krb5_context context, char *str);
#endif

/*
 * Prompter enhancements
 */

#define KRB5_PROMPT_TYPE_PASSWORD            0x1
#define KRB5_PROMPT_TYPE_NEW_PASSWORD        0x2
#define KRB5_PROMPT_TYPE_NEW_PASSWORD_AGAIN  0x3
#define KRB5_PROMPT_TYPE_PREAUTH             0x4

typedef krb5_int32 krb5_prompt_type;

krb5_prompt_type* KRB5_CALLCONV krb5_get_prompt_types
	(krb5_context context);

/* Error reporting */
void KRB5_CALLCONV_C
krb5_set_error_message (krb5_context, krb5_error_code, const char *, ...);
#ifdef va_start
void KRB5_CALLCONV
krb5_vset_error_message (krb5_context, krb5_error_code, const char *, va_list);
#endif
/*
 * The behavior of krb5_get_error_message is only defined the first
 * time it is called after a failed call to a krb5 function using the
 * same context, and only when the error code passed in is the same as
 * that returned by the krb5 function.  Future versions may return the
 * same string for the second and following calls.
 *
 * The string returned by this function must be freed using
 * krb5_free_error_message.
 */
const char * KRB5_CALLCONV
krb5_get_error_message (krb5_context, krb5_error_code);
void KRB5_CALLCONV
krb5_free_error_message (krb5_context, const char *);
void KRB5_CALLCONV
krb5_clear_error_message (krb5_context);


#if TARGET_OS_MAC
#    pragma pack(pop)
#endif

KRB5INT_END_DECLS

/* Don't use this!  We're going to phase it out.  It's just here to keep
   applications from breaking right away.  */
#define krb5_const const

#endif /* KRB5_GENERAL__ */

/*
 * include/krb5_err.h:
 * This file is automatically generated; please do not edit it.
 */

#include <com_err.h>

#define KRB5KDC_ERR_NONE                         (-1765328384L)
#define KRB5KDC_ERR_NAME_EXP                     (-1765328383L)
#define KRB5KDC_ERR_SERVICE_EXP                  (-1765328382L)
#define KRB5KDC_ERR_BAD_PVNO                     (-1765328381L)
#define KRB5KDC_ERR_C_OLD_MAST_KVNO              (-1765328380L)
#define KRB5KDC_ERR_S_OLD_MAST_KVNO              (-1765328379L)
#define KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN          (-1765328378L)
#define KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN          (-1765328377L)
#define KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE         (-1765328376L)
#define KRB5KDC_ERR_NULL_KEY                     (-1765328375L)
#define KRB5KDC_ERR_CANNOT_POSTDATE              (-1765328374L)
#define KRB5KDC_ERR_NEVER_VALID                  (-1765328373L)
#define KRB5KDC_ERR_POLICY                       (-1765328372L)
#define KRB5KDC_ERR_BADOPTION                    (-1765328371L)
#define KRB5KDC_ERR_ETYPE_NOSUPP                 (-1765328370L)
#define KRB5KDC_ERR_SUMTYPE_NOSUPP               (-1765328369L)
#define KRB5KDC_ERR_PADATA_TYPE_NOSUPP           (-1765328368L)
#define KRB5KDC_ERR_TRTYPE_NOSUPP                (-1765328367L)
#define KRB5KDC_ERR_CLIENT_REVOKED               (-1765328366L)
#define KRB5KDC_ERR_SERVICE_REVOKED              (-1765328365L)
#define KRB5KDC_ERR_TGT_REVOKED                  (-1765328364L)
#define KRB5KDC_ERR_CLIENT_NOTYET                (-1765328363L)
#define KRB5KDC_ERR_SERVICE_NOTYET               (-1765328362L)
#define KRB5KDC_ERR_KEY_EXP                      (-1765328361L)
#define KRB5KDC_ERR_PREAUTH_FAILED               (-1765328360L)
#define KRB5KDC_ERR_PREAUTH_REQUIRED             (-1765328359L)
#define KRB5KDC_ERR_SERVER_NOMATCH               (-1765328358L)
#define KRB5PLACEHOLD_27                         (-1765328357L)
#define KRB5PLACEHOLD_28                         (-1765328356L)
#define KRB5KDC_ERR_SVC_UNAVAILABLE              (-1765328355L)
#define KRB5PLACEHOLD_30                         (-1765328354L)
#define KRB5KRB_AP_ERR_BAD_INTEGRITY             (-1765328353L)
#define KRB5KRB_AP_ERR_TKT_EXPIRED               (-1765328352L)
#define KRB5KRB_AP_ERR_TKT_NYV                   (-1765328351L)
#define KRB5KRB_AP_ERR_REPEAT                    (-1765328350L)
#define KRB5KRB_AP_ERR_NOT_US                    (-1765328349L)
#define KRB5KRB_AP_ERR_BADMATCH                  (-1765328348L)
#define KRB5KRB_AP_ERR_SKEW                      (-1765328347L)
#define KRB5KRB_AP_ERR_BADADDR                   (-1765328346L)
#define KRB5KRB_AP_ERR_BADVERSION                (-1765328345L)
#define KRB5KRB_AP_ERR_MSG_TYPE                  (-1765328344L)
#define KRB5KRB_AP_ERR_MODIFIED                  (-1765328343L)
#define KRB5KRB_AP_ERR_BADORDER                  (-1765328342L)
#define KRB5KRB_AP_ERR_ILL_CR_TKT                (-1765328341L)
#define KRB5KRB_AP_ERR_BADKEYVER                 (-1765328340L)
#define KRB5KRB_AP_ERR_NOKEY                     (-1765328339L)
#define KRB5KRB_AP_ERR_MUT_FAIL                  (-1765328338L)
#define KRB5KRB_AP_ERR_BADDIRECTION              (-1765328337L)
#define KRB5KRB_AP_ERR_METHOD                    (-1765328336L)
#define KRB5KRB_AP_ERR_BADSEQ                    (-1765328335L)
#define KRB5KRB_AP_ERR_INAPP_CKSUM               (-1765328334L)
#define KRB5KRB_AP_PATH_NOT_ACCEPTED             (-1765328333L)
#define KRB5KRB_ERR_RESPONSE_TOO_BIG             (-1765328332L)
#define KRB5PLACEHOLD_53                         (-1765328331L)
#define KRB5PLACEHOLD_54                         (-1765328330L)
#define KRB5PLACEHOLD_55                         (-1765328329L)
#define KRB5PLACEHOLD_56                         (-1765328328L)
#define KRB5PLACEHOLD_57                         (-1765328327L)
#define KRB5PLACEHOLD_58                         (-1765328326L)
#define KRB5PLACEHOLD_59                         (-1765328325L)
#define KRB5KRB_ERR_GENERIC                      (-1765328324L)
#define KRB5KRB_ERR_FIELD_TOOLONG                (-1765328323L)
#define KRB5KDC_ERR_CLIENT_NOT_TRUSTED           (-1765328322L)
#define KRB5KDC_ERR_KDC_NOT_TRUSTED              (-1765328321L)
#define KRB5KDC_ERR_INVALID_SIG                  (-1765328320L)
#define KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED (-1765328319L)
#define KRB5KDC_ERR_CERTIFICATE_MISMATCH         (-1765328318L)
#define KRB5PLACEHOLD_67                         (-1765328317L)
#define KRB5PLACEHOLD_68                         (-1765328316L)
#define KRB5PLACEHOLD_69                         (-1765328315L)
#define KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE      (-1765328314L)
#define KRB5KDC_ERR_INVALID_CERTIFICATE          (-1765328313L)
#define KRB5KDC_ERR_REVOKED_CERTIFICATE          (-1765328312L)
#define KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN    (-1765328311L)
#define KRB5KDC_ERR_REVOCATION_STATUS_UNAVAILABLE (-1765328310L)
#define KRB5KDC_ERR_CLIENT_NAME_MISMATCH         (-1765328309L)
#define KRB5KDC_ERR_KDC_NAME_MISMATCH            (-1765328308L)
#define KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE     (-1765328307L)
#define KRB5KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED  (-1765328306L)
#define KRB5KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED (-1765328305L)
#define KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED (-1765328304L)
#define KRB5KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED (-1765328303L)
#define KRB5PLACEHOLD_82                         (-1765328302L)
#define KRB5PLACEHOLD_83                         (-1765328301L)
#define KRB5PLACEHOLD_84                         (-1765328300L)
#define KRB5PLACEHOLD_85                         (-1765328299L)
#define KRB5PLACEHOLD_86                         (-1765328298L)
#define KRB5PLACEHOLD_87                         (-1765328297L)
#define KRB5PLACEHOLD_88                         (-1765328296L)
#define KRB5PLACEHOLD_89                         (-1765328295L)
#define KRB5PLACEHOLD_90                         (-1765328294L)
#define KRB5PLACEHOLD_91                         (-1765328293L)
#define KRB5PLACEHOLD_92                         (-1765328292L)
#define KRB5PLACEHOLD_93                         (-1765328291L)
#define KRB5PLACEHOLD_94                         (-1765328290L)
#define KRB5PLACEHOLD_95                         (-1765328289L)
#define KRB5PLACEHOLD_96                         (-1765328288L)
#define KRB5PLACEHOLD_97                         (-1765328287L)
#define KRB5PLACEHOLD_98                         (-1765328286L)
#define KRB5PLACEHOLD_99                         (-1765328285L)
#define KRB5PLACEHOLD_100                        (-1765328284L)
#define KRB5PLACEHOLD_101                        (-1765328283L)
#define KRB5PLACEHOLD_102                        (-1765328282L)
#define KRB5PLACEHOLD_103                        (-1765328281L)
#define KRB5PLACEHOLD_104                        (-1765328280L)
#define KRB5PLACEHOLD_105                        (-1765328279L)
#define KRB5PLACEHOLD_106                        (-1765328278L)
#define KRB5PLACEHOLD_107                        (-1765328277L)
#define KRB5PLACEHOLD_108                        (-1765328276L)
#define KRB5PLACEHOLD_109                        (-1765328275L)
#define KRB5PLACEHOLD_110                        (-1765328274L)
#define KRB5PLACEHOLD_111                        (-1765328273L)
#define KRB5PLACEHOLD_112                        (-1765328272L)
#define KRB5PLACEHOLD_113                        (-1765328271L)
#define KRB5PLACEHOLD_114                        (-1765328270L)
#define KRB5PLACEHOLD_115                        (-1765328269L)
#define KRB5PLACEHOLD_116                        (-1765328268L)
#define KRB5PLACEHOLD_117                        (-1765328267L)
#define KRB5PLACEHOLD_118                        (-1765328266L)
#define KRB5PLACEHOLD_119                        (-1765328265L)
#define KRB5PLACEHOLD_120                        (-1765328264L)
#define KRB5PLACEHOLD_121                        (-1765328263L)
#define KRB5PLACEHOLD_122                        (-1765328262L)
#define KRB5PLACEHOLD_123                        (-1765328261L)
#define KRB5PLACEHOLD_124                        (-1765328260L)
#define KRB5PLACEHOLD_125                        (-1765328259L)
#define KRB5PLACEHOLD_126                        (-1765328258L)
#define KRB5PLACEHOLD_127                        (-1765328257L)
#define KRB5_ERR_RCSID                           (-1765328256L)
#define KRB5_LIBOS_BADLOCKFLAG                   (-1765328255L)
#define KRB5_LIBOS_CANTREADPWD                   (-1765328254L)
#define KRB5_LIBOS_BADPWDMATCH                   (-1765328253L)
#define KRB5_LIBOS_PWDINTR                       (-1765328252L)
#define KRB5_PARSE_ILLCHAR                       (-1765328251L)
#define KRB5_PARSE_MALFORMED                     (-1765328250L)
#define KRB5_CONFIG_CANTOPEN                     (-1765328249L)
#define KRB5_CONFIG_BADFORMAT                    (-1765328248L)
#define KRB5_CONFIG_NOTENUFSPACE                 (-1765328247L)
#define KRB5_BADMSGTYPE                          (-1765328246L)
#define KRB5_CC_BADNAME                          (-1765328245L)
#define KRB5_CC_UNKNOWN_TYPE                     (-1765328244L)
#define KRB5_CC_NOTFOUND                         (-1765328243L)
#define KRB5_CC_END                              (-1765328242L)
#define KRB5_NO_TKT_SUPPLIED                     (-1765328241L)
#define KRB5KRB_AP_WRONG_PRINC                   (-1765328240L)
#define KRB5KRB_AP_ERR_TKT_INVALID               (-1765328239L)
#define KRB5_PRINC_NOMATCH                       (-1765328238L)
#define KRB5_KDCREP_MODIFIED                     (-1765328237L)
#define KRB5_KDCREP_SKEW                         (-1765328236L)
#define KRB5_IN_TKT_REALM_MISMATCH               (-1765328235L)
#define KRB5_PROG_ETYPE_NOSUPP                   (-1765328234L)
#define KRB5_PROG_KEYTYPE_NOSUPP                 (-1765328233L)
#define KRB5_WRONG_ETYPE                         (-1765328232L)
#define KRB5_PROG_SUMTYPE_NOSUPP                 (-1765328231L)
#define KRB5_REALM_UNKNOWN                       (-1765328230L)
#define KRB5_SERVICE_UNKNOWN                     (-1765328229L)
#define KRB5_KDC_UNREACH                         (-1765328228L)
#define KRB5_NO_LOCALNAME                        (-1765328227L)
#define KRB5_MUTUAL_FAILED                       (-1765328226L)
#define KRB5_RC_TYPE_EXISTS                      (-1765328225L)
#define KRB5_RC_MALLOC                           (-1765328224L)
#define KRB5_RC_TYPE_NOTFOUND                    (-1765328223L)
#define KRB5_RC_UNKNOWN                          (-1765328222L)
#define KRB5_RC_REPLAY                           (-1765328221L)
#define KRB5_RC_IO                               (-1765328220L)
#define KRB5_RC_NOIO                             (-1765328219L)
#define KRB5_RC_PARSE                            (-1765328218L)
#define KRB5_RC_IO_EOF                           (-1765328217L)
#define KRB5_RC_IO_MALLOC                        (-1765328216L)
#define KRB5_RC_IO_PERM                          (-1765328215L)
#define KRB5_RC_IO_IO                            (-1765328214L)
#define KRB5_RC_IO_UNKNOWN                       (-1765328213L)
#define KRB5_RC_IO_SPACE                         (-1765328212L)
#define KRB5_TRANS_CANTOPEN                      (-1765328211L)
#define KRB5_TRANS_BADFORMAT                     (-1765328210L)
#define KRB5_LNAME_CANTOPEN                      (-1765328209L)
#define KRB5_LNAME_NOTRANS                       (-1765328208L)
#define KRB5_LNAME_BADFORMAT                     (-1765328207L)
#define KRB5_CRYPTO_INTERNAL                     (-1765328206L)
#define KRB5_KT_BADNAME                          (-1765328205L)
#define KRB5_KT_UNKNOWN_TYPE                     (-1765328204L)
#define KRB5_KT_NOTFOUND                         (-1765328203L)
#define KRB5_KT_END                              (-1765328202L)
#define KRB5_KT_NOWRITE                          (-1765328201L)
#define KRB5_KT_IOERR                            (-1765328200L)
#define KRB5_NO_TKT_IN_RLM                       (-1765328199L)
#define KRB5DES_BAD_KEYPAR                       (-1765328198L)
#define KRB5DES_WEAK_KEY                         (-1765328197L)
#define KRB5_BAD_ENCTYPE                         (-1765328196L)
#define KRB5_BAD_KEYSIZE                         (-1765328195L)
#define KRB5_BAD_MSIZE                           (-1765328194L)
#define KRB5_CC_TYPE_EXISTS                      (-1765328193L)
#define KRB5_KT_TYPE_EXISTS                      (-1765328192L)
#define KRB5_CC_IO                               (-1765328191L)
#define KRB5_FCC_PERM                            (-1765328190L)
#define KRB5_FCC_NOFILE                          (-1765328189L)
#define KRB5_FCC_INTERNAL                        (-1765328188L)
#define KRB5_CC_WRITE                            (-1765328187L)
#define KRB5_CC_NOMEM                            (-1765328186L)
#define KRB5_CC_FORMAT                           (-1765328185L)
#define KRB5_CC_NOT_KTYPE                        (-1765328184L)
#define KRB5_INVALID_FLAGS                       (-1765328183L)
#define KRB5_NO_2ND_TKT                          (-1765328182L)
#define KRB5_NOCREDS_SUPPLIED                    (-1765328181L)
#define KRB5_SENDAUTH_BADAUTHVERS                (-1765328180L)
#define KRB5_SENDAUTH_BADAPPLVERS                (-1765328179L)
#define KRB5_SENDAUTH_BADRESPONSE                (-1765328178L)
#define KRB5_SENDAUTH_REJECTED                   (-1765328177L)
#define KRB5_PREAUTH_BAD_TYPE                    (-1765328176L)
#define KRB5_PREAUTH_NO_KEY                      (-1765328175L)
#define KRB5_PREAUTH_FAILED                      (-1765328174L)
#define KRB5_RCACHE_BADVNO                       (-1765328173L)
#define KRB5_CCACHE_BADVNO                       (-1765328172L)
#define KRB5_KEYTAB_BADVNO                       (-1765328171L)
#define KRB5_PROG_ATYPE_NOSUPP                   (-1765328170L)
#define KRB5_RC_REQUIRED                         (-1765328169L)
#define KRB5_ERR_BAD_HOSTNAME                    (-1765328168L)
#define KRB5_ERR_HOST_REALM_UNKNOWN              (-1765328167L)
#define KRB5_SNAME_UNSUPP_NAMETYPE               (-1765328166L)
#define KRB5KRB_AP_ERR_V4_REPLY                  (-1765328165L)
#define KRB5_REALM_CANT_RESOLVE                  (-1765328164L)
#define KRB5_TKT_NOT_FORWARDABLE                 (-1765328163L)
#define KRB5_FWD_BAD_PRINCIPAL                   (-1765328162L)
#define KRB5_GET_IN_TKT_LOOP                     (-1765328161L)
#define KRB5_CONFIG_NODEFREALM                   (-1765328160L)
#define KRB5_SAM_UNSUPPORTED                     (-1765328159L)
#define KRB5_SAM_INVALID_ETYPE                   (-1765328158L)
#define KRB5_SAM_NO_CHECKSUM                     (-1765328157L)
#define KRB5_SAM_BAD_CHECKSUM                    (-1765328156L)
#define KRB5_KT_NAME_TOOLONG                     (-1765328155L)
#define KRB5_KT_KVNONOTFOUND                     (-1765328154L)
#define KRB5_APPL_EXPIRED                        (-1765328153L)
#define KRB5_LIB_EXPIRED                         (-1765328152L)
#define KRB5_CHPW_PWDNULL                        (-1765328151L)
#define KRB5_CHPW_FAIL                           (-1765328150L)
#define KRB5_KT_FORMAT                           (-1765328149L)
#define KRB5_NOPERM_ETYPE                        (-1765328148L)
#define KRB5_CONFIG_ETYPE_NOSUPP                 (-1765328147L)
#define KRB5_OBSOLETE_FN                         (-1765328146L)
#define KRB5_EAI_FAIL                            (-1765328145L)
#define KRB5_EAI_NODATA                          (-1765328144L)
#define KRB5_EAI_NONAME                          (-1765328143L)
#define KRB5_EAI_SERVICE                         (-1765328142L)
#define KRB5_ERR_NUMERIC_REALM                   (-1765328141L)
#define KRB5_ERR_BAD_S2K_PARAMS                  (-1765328140L)
#define KRB5_ERR_NO_SERVICE                      (-1765328139L)
#define KRB5_CC_READONLY                         (-1765328138L)
#define KRB5_CC_NOSUPP                           (-1765328137L)
#define KRB5_DELTAT_BADFORMAT                    (-1765328136L)
#define KRB5_PLUGIN_NO_HANDLE                    (-1765328135L)
#define KRB5_PLUGIN_OP_NOTSUPP                   (-1765328134L)
#define ERROR_TABLE_BASE_krb5 (-1765328384L)

extern const struct error_table et_krb5_error_table;

#if !defined(_WIN32)
/* for compatibility with older versions... */
extern void initialize_krb5_error_table (void) /*@modifies internalState@*/;
#else
#define initialize_krb5_error_table()
#endif

#if !defined(_WIN32)
#define init_krb5_err_tbl initialize_krb5_error_table
#define krb5_err_base ERROR_TABLE_BASE_krb5
#endif
/*
 * include/kdb5_err.h:
 * This file is automatically generated; please do not edit it.
 */

#include <com_err.h>

#define KRB5_KDB_RCSID                           (-1780008448L)
#define KRB5_KDB_INUSE                           (-1780008447L)
#define KRB5_KDB_UK_SERROR                       (-1780008446L)
#define KRB5_KDB_UK_RERROR                       (-1780008445L)
#define KRB5_KDB_UNAUTH                          (-1780008444L)
#define KRB5_KDB_NOENTRY                         (-1780008443L)
#define KRB5_KDB_ILL_WILDCARD                    (-1780008442L)
#define KRB5_KDB_DB_INUSE                        (-1780008441L)
#define KRB5_KDB_DB_CHANGED                      (-1780008440L)
#define KRB5_KDB_TRUNCATED_RECORD                (-1780008439L)
#define KRB5_KDB_RECURSIVELOCK                   (-1780008438L)
#define KRB5_KDB_NOTLOCKED                       (-1780008437L)
#define KRB5_KDB_BADLOCKMODE                     (-1780008436L)
#define KRB5_KDB_DBNOTINITED                     (-1780008435L)
#define KRB5_KDB_DBINITED                        (-1780008434L)
#define KRB5_KDB_ILLDIRECTION                    (-1780008433L)
#define KRB5_KDB_NOMASTERKEY                     (-1780008432L)
#define KRB5_KDB_BADMASTERKEY                    (-1780008431L)
#define KRB5_KDB_INVALIDKEYSIZE                  (-1780008430L)
#define KRB5_KDB_CANTREAD_STORED                 (-1780008429L)
#define KRB5_KDB_BADSTORED_MKEY                  (-1780008428L)
#define KRB5_KDB_CANTLOCK_DB                     (-1780008427L)
#define KRB5_KDB_DB_CORRUPT                      (-1780008426L)
#define KRB5_KDB_BAD_VERSION                     (-1780008425L)
#define KRB5_KDB_BAD_SALTTYPE                    (-1780008424L)
#define KRB5_KDB_BAD_ENCTYPE                     (-1780008423L)
#define KRB5_KDB_BAD_CREATEFLAGS                 (-1780008422L)
#define KRB5_KDB_NO_PERMITTED_KEY                (-1780008421L)
#define KRB5_KDB_NO_MATCHING_KEY                 (-1780008420L)
#define KRB5_KDB_DBTYPE_NOTFOUND                 (-1780008419L)
#define KRB5_KDB_DBTYPE_NOSUP                    (-1780008418L)
#define KRB5_KDB_DBTYPE_INIT                     (-1780008417L)
#define KRB5_KDB_SERVER_INTERNAL_ERR             (-1780008416L)
#define KRB5_KDB_ACCESS_ERROR                    (-1780008415L)
#define KRB5_KDB_INTERNAL_ERROR                  (-1780008414L)
#define KRB5_KDB_CONSTRAINT_VIOLATION            (-1780008413L)
#define ERROR_TABLE_BASE_kdb5 (-1780008448L)

extern const struct error_table et_kdb5_error_table;

#if !defined(_WIN32)
/* for compatibility with older versions... */
extern void initialize_kdb5_error_table (void) /*@modifies internalState@*/;
#else
#define initialize_kdb5_error_table()
#endif

#if !defined(_WIN32)
#define init_kdb5_err_tbl initialize_kdb5_error_table
#define kdb5_err_base ERROR_TABLE_BASE_kdb5
#endif
/*
 * include/kv5m_err.h:
 * This file is automatically generated; please do not edit it.
 */

#include <com_err.h>

#define KV5M_NONE                                (-1760647424L)
#define KV5M_PRINCIPAL                           (-1760647423L)
#define KV5M_DATA                                (-1760647422L)
#define KV5M_KEYBLOCK                            (-1760647421L)
#define KV5M_CHECKSUM                            (-1760647420L)
#define KV5M_ENCRYPT_BLOCK                       (-1760647419L)
#define KV5M_ENC_DATA                            (-1760647418L)
#define KV5M_CRYPTOSYSTEM_ENTRY                  (-1760647417L)
#define KV5M_CS_TABLE_ENTRY                      (-1760647416L)
#define KV5M_CHECKSUM_ENTRY                      (-1760647415L)
#define KV5M_AUTHDATA                            (-1760647414L)
#define KV5M_TRANSITED                           (-1760647413L)
#define KV5M_ENC_TKT_PART                        (-1760647412L)
#define KV5M_TICKET                              (-1760647411L)
#define KV5M_AUTHENTICATOR                       (-1760647410L)
#define KV5M_TKT_AUTHENT                         (-1760647409L)
#define KV5M_CREDS                               (-1760647408L)
#define KV5M_LAST_REQ_ENTRY                      (-1760647407L)
#define KV5M_PA_DATA                             (-1760647406L)
#define KV5M_KDC_REQ                             (-1760647405L)
#define KV5M_ENC_KDC_REP_PART                    (-1760647404L)
#define KV5M_KDC_REP                             (-1760647403L)
#define KV5M_ERROR                               (-1760647402L)
#define KV5M_AP_REQ                              (-1760647401L)
#define KV5M_AP_REP                              (-1760647400L)
#define KV5M_AP_REP_ENC_PART                     (-1760647399L)
#define KV5M_RESPONSE                            (-1760647398L)
#define KV5M_SAFE                                (-1760647397L)
#define KV5M_PRIV                                (-1760647396L)
#define KV5M_PRIV_ENC_PART                       (-1760647395L)
#define KV5M_CRED                                (-1760647394L)
#define KV5M_CRED_INFO                           (-1760647393L)
#define KV5M_CRED_ENC_PART                       (-1760647392L)
#define KV5M_PWD_DATA                            (-1760647391L)
#define KV5M_ADDRESS                             (-1760647390L)
#define KV5M_KEYTAB_ENTRY                        (-1760647389L)
#define KV5M_CONTEXT                             (-1760647388L)
#define KV5M_OS_CONTEXT                          (-1760647387L)
#define KV5M_ALT_METHOD                          (-1760647386L)
#define KV5M_ETYPE_INFO_ENTRY                    (-1760647385L)
#define KV5M_DB_CONTEXT                          (-1760647384L)
#define KV5M_AUTH_CONTEXT                        (-1760647383L)
#define KV5M_KEYTAB                              (-1760647382L)
#define KV5M_RCACHE                              (-1760647381L)
#define KV5M_CCACHE                              (-1760647380L)
#define KV5M_PREAUTH_OPS                         (-1760647379L)
#define KV5M_SAM_CHALLENGE                       (-1760647378L)
#define KV5M_SAM_CHALLENGE_2                     (-1760647377L)
#define KV5M_SAM_KEY                             (-1760647376L)
#define KV5M_ENC_SAM_RESPONSE_ENC                (-1760647375L)
#define KV5M_ENC_SAM_RESPONSE_ENC_2              (-1760647374L)
#define KV5M_SAM_RESPONSE                        (-1760647373L)
#define KV5M_SAM_RESPONSE_2                      (-1760647372L)
#define KV5M_PREDICTED_SAM_RESPONSE              (-1760647371L)
#define KV5M_PASSWD_PHRASE_ELEMENT               (-1760647370L)
#define KV5M_GSS_OID                             (-1760647369L)
#define KV5M_GSS_QUEUE                           (-1760647368L)
#define ERROR_TABLE_BASE_kv5m (-1760647424L)

extern const struct error_table et_kv5m_error_table;

#if !defined(_WIN32)
/* for compatibility with older versions... */
extern void initialize_kv5m_error_table (void) /*@modifies internalState@*/;
#else
#define initialize_kv5m_error_table()
#endif

#if !defined(_WIN32)
#define init_kv5m_err_tbl initialize_kv5m_error_table
#define kv5m_err_base ERROR_TABLE_BASE_kv5m
#endif
/*
 * include/krb524_err.h:
 * This file is automatically generated; please do not edit it.
 */

#include <com_err.h>

#define KRB524_BADKEY                            (-1750206208L)
#define KRB524_BADADDR                           (-1750206207L)
#define KRB524_BADPRINC                          (-1750206206L)
#define KRB524_BADREALM                          (-1750206205L)
#define KRB524_V4ERR                             (-1750206204L)
#define KRB524_ENCFULL                           (-1750206203L)
#define KRB524_DECEMPTY                          (-1750206202L)
#define KRB524_NOTRESP                           (-1750206201L)
#define KRB524_KRB4_DISABLED                     (-1750206200L)
#define ERROR_TABLE_BASE_k524 (-1750206208L)

extern const struct error_table et_k524_error_table;

#if !defined(_WIN32)
/* for compatibility with older versions... */
extern void initialize_k524_error_table (void) /*@modifies internalState@*/;
#else
#define initialize_k524_error_table()
#endif

#if !defined(_WIN32)
#define init_k524_err_tbl initialize_k524_error_table
#define k524_err_base ERROR_TABLE_BASE_k524
#endif
/*
 * include/asn1_err.h:
 * This file is automatically generated; please do not edit it.
 */

#include <com_err.h>

#define ASN1_BAD_TIMEFORMAT                      (1859794432L)
#define ASN1_MISSING_FIELD                       (1859794433L)
#define ASN1_MISPLACED_FIELD                     (1859794434L)
#define ASN1_TYPE_MISMATCH                       (1859794435L)
#define ASN1_OVERFLOW                            (1859794436L)
#define ASN1_OVERRUN                             (1859794437L)
#define ASN1_BAD_ID                              (1859794438L)
#define ASN1_BAD_LENGTH                          (1859794439L)
#define ASN1_BAD_FORMAT                          (1859794440L)
#define ASN1_PARSE_ERROR                         (1859794441L)
#define ASN1_BAD_GMTIME                          (1859794442L)
#define ASN1_MISMATCH_INDEF                      (1859794443L)
#define ASN1_MISSING_EOC                         (1859794444L)
#define ERROR_TABLE_BASE_asn1 (1859794432L)

extern const struct error_table et_asn1_error_table;

#if !defined(_WIN32)
/* for compatibility with older versions... */
extern void initialize_asn1_error_table (void) /*@modifies internalState@*/;
#else
#define initialize_asn1_error_table()
#endif

#if !defined(_WIN32)
#define init_asn1_err_tbl initialize_asn1_error_table
#define asn1_err_base ERROR_TABLE_BASE_asn1
#endif
