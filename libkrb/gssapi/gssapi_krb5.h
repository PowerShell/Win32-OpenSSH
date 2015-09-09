/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _GSSAPI_KRB5_H_
#define _GSSAPI_KRB5_H_

#include <gssapi/gssapi.h>
#include <krb5.h>

/* C++ friendlyness */
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Reserved static storage for GSS_oids.  See rfc 1964 for more details. */

/* 2.1.1. Kerberos Principal Name Form: */
GSS_DLLIMP extern const gss_OID_desc * const GSS_KRB5_NT_PRINCIPAL_NAME;
/* This name form shall be represented by the Object Identifier {iso(1)
 * member-body(2) United States(840) mit(113554) infosys(1) gssapi(2)
 * krb5(2) krb5_name(1)}.  The recommended symbolic name for this type
 * is "GSS_KRB5_NT_PRINCIPAL_NAME". */

/* 2.1.2. Host-Based Service Name Form */
#define GSS_KRB5_NT_HOSTBASED_SERVICE_NAME GSS_C_NT_HOSTBASED_SERVICE
/* This name form shall be represented by the Object Identifier {iso(1)
 * member-body(2) United States(840) mit(113554) infosys(1) gssapi(2)
 * generic(1) service_name(4)}.  The previously recommended symbolic
 * name for this type is "GSS_KRB5_NT_HOSTBASED_SERVICE_NAME".  The
 * currently preferred symbolic name for this type is
 * "GSS_C_NT_HOSTBASED_SERVICE". */

/* 2.2.1. User Name Form */
#define GSS_KRB5_NT_USER_NAME GSS_C_NT_USER_NAME    
/* This name form shall be represented by the Object Identifier {iso(1)
 * member-body(2) United States(840) mit(113554) infosys(1) gssapi(2)
 * generic(1) user_name(1)}.  The recommended symbolic name for this
 * type is "GSS_KRB5_NT_USER_NAME". */

/* 2.2.2. Machine UID Form */
#define GSS_KRB5_NT_MACHINE_UID_NAME GSS_C_NT_MACHINE_UID_NAME
/* This name form shall be represented by the Object Identifier {iso(1)
 * member-body(2) United States(840) mit(113554) infosys(1) gssapi(2)
 * generic(1) machine_uid_name(2)}.  The recommended symbolic name for
 * this type is "GSS_KRB5_NT_MACHINE_UID_NAME". */

/* 2.2.3. String UID Form */
#define GSS_KRB5_NT_STRING_UID_NAME GSS_C_NT_STRING_UID_NAME
/* This name form shall be represented by the Object Identifier {iso(1)
 * member-body(2) United States(840) mit(113554) infosys(1) gssapi(2)
 * generic(1) string_uid_name(3)}.  The recommended symbolic name for
 * this type is "GSS_KRB5_NT_STRING_UID_NAME". */ 

GSS_DLLIMP extern const gss_OID_desc * const gss_mech_krb5;
GSS_DLLIMP extern const gss_OID_desc * const gss_mech_krb5_old;
GSS_DLLIMP extern const gss_OID_desc * const gss_mech_krb5_wrong;
GSS_DLLIMP extern const gss_OID_set_desc * const gss_mech_set_krb5;
GSS_DLLIMP extern const gss_OID_set_desc * const gss_mech_set_krb5_old;
GSS_DLLIMP extern const gss_OID_set_desc * const gss_mech_set_krb5_both;

GSS_DLLIMP extern const gss_OID_desc * const gss_nt_krb5_name;
GSS_DLLIMP extern const gss_OID_desc * const gss_nt_krb5_principal;

GSS_DLLIMP extern const gss_OID_desc krb5_gss_oid_array[];

#define gss_krb5_nt_general_name	gss_nt_krb5_name
#define gss_krb5_nt_principal		gss_nt_krb5_principal
#define gss_krb5_nt_service_name	gss_nt_service_name
#define gss_krb5_nt_user_name		gss_nt_user_name
#define gss_krb5_nt_machine_uid_name	gss_nt_machine_uid_name
#define gss_krb5_nt_string_uid_name	gss_nt_string_uid_name


#if defined(_WIN32)
typedef  unsigned __int64 gss_uint64;
#else /*windows*/
#include <inttypes.h>
typedef  uint64_t gss_uint64;
#endif


typedef struct gss_krb5_lucid_key {
	OM_uint32	type;		/* key encryption type */
	OM_uint32	length;		/* length of key data */
	void *		data;		/* actual key data */
} gss_krb5_lucid_key_t;

typedef struct gss_krb5_rfc1964_keydata {
	OM_uint32	sign_alg;	/* signing algorthm */
	OM_uint32	seal_alg;	/* seal/encrypt algorthm */
	gss_krb5_lucid_key_t	ctx_key;
					/* Context key
					   (Kerberos session key or subkey) */
} gss_krb5_rfc1964_keydata_t;

typedef struct gss_krb5_cfx_keydata {
	OM_uint32		have_acceptor_subkey;
					/* 1 if there is an acceptor_subkey
					   present, 0 otherwise */
	gss_krb5_lucid_key_t	ctx_key;
					/* Context key
					   (Kerberos session key or subkey) */
	gss_krb5_lucid_key_t	acceptor_subkey;
					/* acceptor-asserted subkey or
					   0's if no acceptor subkey */
} gss_krb5_cfx_keydata_t;

typedef struct gss_krb5_lucid_context_v1 {
	OM_uint32	version;	/* Structure version number (1)
					   MUST be at beginning of struct! */
	OM_uint32	initiate;	/* Are we the initiator? */
	OM_uint32	endtime;	/* expiration time of context */
	gss_uint64	send_seq;	/* sender sequence number */
	gss_uint64	recv_seq;	/* receive sequence number */
	OM_uint32	protocol;	/* 0: rfc1964,
					   1: draft-ietf-krb-wg-gssapi-cfx-07 */
	/*
	 * if (protocol == 0) rfc1964_kd should be used
	 * and cfx_kd contents are invalid and should be zero
	 * if (protocol == 1) cfx_kd should be used
	 * and rfc1964_kd contents are invalid and should be zero
	 */
	gss_krb5_rfc1964_keydata_t rfc1964_kd;
	gss_krb5_cfx_keydata_t	   cfx_kd;
} gss_krb5_lucid_context_v1_t;

/*
 * Mask for determining the returned structure version.
 * See example below for usage.
 */
typedef struct gss_krb5_lucid_context_version {
	OM_uint32	version;	/* Structure version number */
} gss_krb5_lucid_context_version_t;




/* Alias for Heimdal compat. */
#define gsskrb5_register_acceptor_identity krb5_gss_register_acceptor_identity

OM_uint32 KRB5_CALLCONV krb5_gss_register_acceptor_identity(const char *);

OM_uint32 KRB5_CALLCONV gss_krb5_get_tkt_flags 
	(OM_uint32 *minor_status,
		   gss_ctx_id_t context_handle,
		   krb5_flags *ticket_flags);

OM_uint32 KRB5_CALLCONV gss_krb5_copy_ccache
	(OM_uint32 *minor_status,
		   gss_cred_id_t cred_handle,
		   krb5_ccache out_ccache);

OM_uint32 KRB5_CALLCONV gss_krb5_ccache_name
	(OM_uint32 *minor_status, const char *name,
		   const char **out_name);

/*
 * gss_krb5_set_allowable_enctypes
 *
 * This function may be called by a context initiator after calling
 * gss_acquire_cred(), but before calling gss_init_sec_context(),
 * to restrict the set of enctypes which will be negotiated during
 * context establishment to those in the provided array.
 *
 * 'cred' must be a valid credential handle obtained via
 * gss_acquire_cred().  It may not be GSS_C_NO_CREDENTIAL.
 * gss_acquire_cred() may have been called to get a handle to
 * the default credential.
 *
 * The purpose of this function is to limit the keys that may
 * be exported via gss_krb5_export_lucid_sec_context(); thus it
 * should limit the enctypes of all keys that will be needed
 * after the security context has been established.
 * (i.e. context establishment may use a session key with a
 * stronger enctype than in the provided array, however a
 * subkey must be established within the enctype limits
 * established by this function.)
 *
 */
OM_uint32 KRB5_CALLCONV
gss_krb5_set_allowable_enctypes(OM_uint32 *minor_status, 
				gss_cred_id_t cred,
				OM_uint32 num_ktypes,
				krb5_enctype *ktypes);

/*
 * Returns a non-opaque (lucid) version of the internal context
 * information.  
 *
 * Note that context_handle must not be used again by the caller
 * after this call.  The GSS implementation is free to release any
 * resources associated with the original context.  It is up to the
 * GSS implementation whether it returns pointers to existing data,
 * or copies of the data.  The caller should treat the returned
 * lucid context as read-only.
 * 
 * The caller must call gss_krb5_free_lucid_context() to free
 * the context and allocated resources when it is finished with it.
 *
 * 'version' is an integer indicating the highest version of lucid
 * context understood by the caller.  The highest version
 * understood by both the caller and the GSS implementation must
 * be returned.  The caller can determine which version of the
 * structure was actually returned by examining the version field
 * of the returned structure.  gss_krb5_lucid_context_version_t
 * may be used as a mask to examine the returned structure version.
 *
 * If there are no common versions, an error should be returned.
 * (XXX Need error definition(s))
 *
 * For example:
 *	void *return_ctx;
 *	gss_krb5_lucid_context_v1_t *ctx;
 *	OM_uint32 min_stat, maj_stat;
 *	OM_uint32 vers;
 *	gss_ctx_id_t *ctx_handle;
 *
 *	maj_stat = gss_krb5_export_lucid_sec_context(&min_stat,
 *			ctx_handle, 1, &return_ctx);
 *	// Verify success 
 *
 *	vers = ((gss_krb5_lucid_context_version_t *)return_ctx)->version;
 *	switch (vers) {
 *	case 1:
 *		ctx = (gss_krb5_lucid_context_v1_t *) return_ctx;
 *		break;
 *	default:
 *		// Error, unknown version returned
 *		break;
 *	}
 *
 */

OM_uint32 KRB5_CALLCONV
gss_krb5_export_lucid_sec_context(OM_uint32 *minor_status,
				  gss_ctx_id_t *context_handle,
				  OM_uint32 version,
				  void **kctx);

/*
 * Frees the allocated storage associated with an
 * exported struct gss_krb5_lucid_context.
 */
OM_uint32 KRB5_CALLCONV
gss_krb5_free_lucid_sec_context(OM_uint32 *minor_status,
				void *kctx);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _GSSAPI_KRB5_H_ */
