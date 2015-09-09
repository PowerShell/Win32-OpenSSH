/*
 * include/kerberosIV/krb.h
 *
 * Copyright 1987, 1988, 1994, 2001, 2002 by the Massachusetts
 * Institute of Technology.  All Rights Reserved.
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
 * Include file for the Kerberos V4 library. 
 */

/* Only one time, please */
#ifndef	KRB_DEFS
#define KRB_DEFS

/*
 * For MacOS, don't expose prototypes of various private functions.
 * Unfortuantely, they've leaked out everywhere else.
 */
#if defined(__MACH__) && defined(__APPLE__)
#include <TargetConditionals.h>
#include <AvailabilityMacros.h>
#if TARGET_RT_MAC_CFM
#error "Use KfM 4.0 SDK headers for CFM compilation."
#endif
#ifndef KRB_PRIVATE
#define KRB_PRIVATE 0
#endif
#ifdef DEPRECATED_IN_MAC_OS_X_VERSION_10_5
#define KRB5INT_KRB4_DEPRECATED DEPRECATED_IN_MAC_OS_X_VERSION_10_5
#endif
#else
#ifndef KRB_PRIVATE
#define KRB_PRIVATE 1
#endif
#endif /* defined(__MACH__) && defined(__APPLE__) */

/* Macro to add deprecated attribute to KRB4 types and functions */
/* Currently only defined on Mac OS X 10.5 and later.            */
#ifndef KRB5INT_KRB4_DEPRECATED
#define KRB5INT_KRB4_DEPRECATED
#endif

/* Define u_char, u_short, u_int, and u_long. */
/* XXX these typdef names are not standardized! */
#include <sys/types.h>

/* Need some defs from des.h	 */
#include <kerberosIV/des.h>
#include <kerberosIV/krb_err.h>
#include <profile.h>

#ifdef _WIN32
#include <time.h>
#endif /* _WIN32 */

#ifdef __cplusplus
#ifndef KRBINT_BEGIN_DECLS
#define KRBINT_BEGIN_DECLS	extern "C" {
#define KRBINT_END_DECLS	}
#endif
#else
#define KRBINT_BEGIN_DECLS
#define KRBINT_END_DECLS
#endif
KRBINT_BEGIN_DECLS

#if TARGET_OS_MAC
#	pragma pack(push,2)
#endif

#define KRB4_32		DES_INT32
#define KRB_INT32	DES_INT32
#define KRB_UINT32	DES_UINT32

#define		MAX_KRB_ERRORS	256

#if TARGET_OS_MAC
/* ABI divergence on Mac for backwards compatibility. */
extern const char * const * const krb_err_txt 
KRB5INT_KRB4_DEPRECATED;
#else
extern const char * const krb_err_txt[MAX_KRB_ERRORS] 
KRB5INT_KRB4_DEPRECATED;
#endif

/* General definitions */
#define		KSUCCESS	0
#define		KFAILURE	255

/*
 * Kerberos specific definitions 
 *
 * KRBLOG is the log file for the kerberos master server. KRB_CONF is
 * the configuration file where different host machines running master
 * and slave servers can be found. KRB_MASTER is the name of the
 * machine with the master database.  The admin_server runs on this
 * machine, and all changes to the db (as opposed to read-only
 * requests, which can go to slaves) must go to it. KRB_HOST is the
 * default machine * when looking for a kerberos slave server.  Other
 * possibilities are * in the KRB_CONF file. KRB_REALM is the name of
 * the realm. 
 */

#define		KRB_CONF	"/etc/krb.conf"
#define		KRB_RLM_TRANS	"/etc/krb.realms"
#define		KRB_MASTER	"kerberos"
#define		KRB_HOST	 KRB_MASTER
#define		KRB_REALM	"ATHENA.MIT.EDU"

/* The maximum sizes for aname, realm, sname, and instance +1 */
#define 	ANAME_SZ	40
#define		REALM_SZ	40
#define		SNAME_SZ	40
#define		INST_SZ		40
#define     ADDR_SZ     40
/*
 * NB: This overcounts due to NULs.
 */
/* include space for '.' and '@' */
#define		MAX_K_NAME_SZ	(ANAME_SZ + INST_SZ + REALM_SZ + 2)
#define		KKEY_SZ		100
#define		VERSION_SZ	1
#define		MSG_TYPE_SZ	1
#define		DATE_SZ		26	/* RTI date output */

#define		MAX_HSTNM	100

#ifndef DEFAULT_TKT_LIFE		/* allow compile-time override */
#define DEFAULT_TKT_LIFE	120	/* default lifetime for krb_mk_req */
#endif

#define		KRB_TICKET_GRANTING_TICKET	"krbtgt"

/* Definition of text structure used to pass text around */
#define		MAX_KTXT_LEN	1250

struct ktext {
    int     length;		/* Length of the text */
    unsigned char dat[MAX_KTXT_LEN];	/* The data itself */
    unsigned long mbz;		/* zero to catch runaway strings */
} KRB5INT_KRB4_DEPRECATED;

typedef struct ktext *KTEXT KRB5INT_KRB4_DEPRECATED;
typedef struct ktext KTEXT_ST KRB5INT_KRB4_DEPRECATED;


/* Definitions for send_to_kdc */
#define	CLIENT_KRB_TIMEOUT	4	/* time between retries */
#define CLIENT_KRB_RETRY	5	/* retry this many times */
#define	CLIENT_KRB_BUFLEN	512	/* max unfragmented packet */

/* Definitions for ticket file utilities */
#define	R_TKT_FIL	0
#define	W_TKT_FIL	1

/* Definitions for cl_get_tgt */
#ifdef PC
#define CL_GTGT_INIT_FILE		"\\kerberos\\k_in_tkts"
#else
#define CL_GTGT_INIT_FILE		"/etc/k_in_tkts"
#endif /* PC */

/* Parameters for rd_ap_req */
/* Maximum allowable clock skew in seconds */
#define 	CLOCK_SKEW	5*60
/* Filename for readservkey */
#define		KEYFILE		((char*)krb__get_srvtabname("/etc/srvtab"))

/* Structure definition for rd_ap_req */

struct auth_dat {
    unsigned char k_flags;	/* Flags from ticket */
    char    pname[ANAME_SZ];	/* Principal's name */
    char    pinst[INST_SZ];	/* His Instance */
    char    prealm[REALM_SZ];	/* His Realm */
    unsigned KRB4_32 checksum;	/* Data checksum (opt) */
    C_Block session;		/* Session Key */
    int     life;		/* Life of ticket */
    unsigned KRB4_32 time_sec;	/* Time ticket issued */
    unsigned KRB4_32 address;	/* Address in ticket */
    KTEXT_ST reply;		/* Auth reply (opt) */
} KRB5INT_KRB4_DEPRECATED;

typedef struct auth_dat AUTH_DAT KRB5INT_KRB4_DEPRECATED;

/* Structure definition for credentials returned by get_cred */

struct credentials {
    char    service[ANAME_SZ];	/* Service name */
    char    instance[INST_SZ];	/* Instance */
    char    realm[REALM_SZ];	/* Auth domain */
    C_Block session;		/* Session key */
    int     lifetime;		/* Lifetime */
    int     kvno;		/* Key version number */
    KTEXT_ST ticket_st;		/* The ticket itself */
    KRB4_32 issue_date;		/* The issue time */
    char    pname[ANAME_SZ];	/* Principal's name */
    char    pinst[INST_SZ];	/* Principal's instance */
#if TARGET_OS_MAC
    KRB_UINT32 address;			/* Address in ticket */
    KRB_UINT32 stk_type;		/* string_to_key function needed */
#endif
#ifdef _WIN32
    char    address[ADDR_SZ];   /* Address in ticket */
#endif
} KRB5INT_KRB4_DEPRECATED;

typedef struct credentials CREDENTIALS KRB5INT_KRB4_DEPRECATED;

/* Structure definition for rd_private_msg and rd_safe_msg */

struct msg_dat {
    unsigned char *app_data;	/* pointer to appl data */
    unsigned KRB4_32 app_length;	/* length of appl data */
    unsigned KRB4_32 hash;		/* hash to lookup replay */
    int     swap;			/* swap bytes? */
    KRB4_32  time_sec;			/* msg timestamp seconds */
    unsigned char time_5ms;		/* msg timestamp 5ms units */
} KRB5INT_KRB4_DEPRECATED;

typedef struct msg_dat MSG_DAT KRB5INT_KRB4_DEPRECATED;


/* Location of ticket file for save_cred and get_cred */
#ifdef _WIN32
#define TKT_FILE        "\\kerberos\\ticket.ses"
#else
#define TKT_FILE        tkt_string()
#define TKT_ROOT        "/tmp/tkt"
#endif /* _WIN32 */

/*
 * Error codes are now defined as offsets from com_err (krb_err.et)
 * values.
 */
#define KRB_ET(x)	((KRBET_ ## x) - ERROR_TABLE_BASE_krb)

/* Error codes returned from the KDC */
#define	KDC_OK		KRB_ET(KSUCCESS)	/*  0 - Request OK */
#define	KDC_NAME_EXP	KRB_ET(KDC_NAME_EXP)	/*  1 - Principal expired */
#define	KDC_SERVICE_EXP	KRB_ET(KDC_SERVICE_EXP)	/*  2 - Service expired */
#define	KDC_AUTH_EXP	KRB_ET(KDC_AUTH_EXP)	/*  3 - Auth expired */
#define	KDC_PKT_VER	KRB_ET(KDC_PKT_VER)	/*  4 - Prot version unknown */
#define	KDC_P_MKEY_VER	KRB_ET(KDC_P_MKEY_VER)	/*  5 - Wrong mkey version */
#define	KDC_S_MKEY_VER 	KRB_ET(KDC_S_MKEY_VER)	/*  6 - Wrong mkey version */
#define	KDC_BYTE_ORDER	KRB_ET(KDC_BYTE_ORDER)	/*  7 - Byte order unknown */
#define	KDC_PR_UNKNOWN	KRB_ET(KDC_PR_UNKNOWN)	/*  8 - Princ unknown */
#define	KDC_PR_N_UNIQUE KRB_ET(KDC_PR_N_UNIQUE)	/*  9 - Princ not unique */
#define	KDC_NULL_KEY	KRB_ET(KDC_NULL_KEY)	/* 10 - Princ has null key */
#define	KDC_GEN_ERR	KRB_ET(KDC_GEN_ERR)	/* 20 - Generic err frm KDC */

/* Values returned by get_credentials */
#define	GC_OK		KRB_ET(KSUCCESS)	/*  0 - Retrieve OK */
#define	RET_OK		KRB_ET(KSUCCESS)	/*  0 - Retrieve OK */
#define	GC_TKFIL	KRB_ET(GC_TKFIL)	/* 21 - Can't rd tkt file */
#define	RET_TKFIL	KRB_ET(GC_TKFIL)	/* 21 - Can't rd tkt file */
#define	GC_NOTKT	KRB_ET(GC_NOTKT)	/* 22 - Can't find tkt|TGT */
#define	RET_NOTKT	KRB_ET(GC_NOTKT)	/* 22 - Can't find tkt|TGT */

/* Values returned by mk_ap_req	 */
#define	MK_AP_OK	KRB_ET(KSUCCESS)	/*  0 - Success */
#define	MK_AP_TGTEXP	KRB_ET(MK_AP_TGTEXP)	/* 26 - TGT Expired */

/* Values returned by rd_ap_req */
#define	RD_AP_OK	KRB_ET(KSUCCESS)	/*  0 - Request authentic */
#define	RD_AP_UNDEC	KRB_ET(RD_AP_UNDEC)	/* 31 - Can't decode authent */
#define	RD_AP_EXP	KRB_ET(RD_AP_EXP)	/* 32 - Ticket expired */
#define	RD_AP_NYV	KRB_ET(RD_AP_NYV)	/* 33 - Ticket not yet valid */
#define	RD_AP_REPEAT	KRB_ET(RD_AP_REPEAT)	/* 34 - Repeated request */
#define	RD_AP_NOT_US	KRB_ET(RD_AP_NOT_US)	/* 35 - Ticket isn't for us */
#define	RD_AP_INCON	KRB_ET(RD_AP_INCON)	/* 36 - Request inconsistent */
#define	RD_AP_TIME	KRB_ET(RD_AP_TIME)	/* 37 - delta_t too big */
#define	RD_AP_BADD	KRB_ET(RD_AP_BADD)	/* 38 - Incorrect net addr */
#define	RD_AP_VERSION	KRB_ET(RD_AP_VERSION)	/* 39 - prot vers mismatch */
#define	RD_AP_MSG_TYPE	KRB_ET(RD_AP_MSG_TYPE)	/* 40 - invalid msg type */
#define	RD_AP_MODIFIED	KRB_ET(RD_AP_MODIFIED)	/* 41 - msg stream modified */
#define	RD_AP_ORDER	KRB_ET(RD_AP_ORDER)	/* 42 - message out of order */
#define	RD_AP_UNAUTHOR	KRB_ET(RD_AP_UNAUTHOR)	/* 43 - unauthorized request */

/* Values returned by get_pw_tkt */
#define	GT_PW_OK	KRB_ET(KSUCCESS)	/*  0 - Got passwd chg tkt */
#define	GT_PW_NULL	KRB_ET(GT_PW_NULL)	/* 51 - Current PW is null */
#define	GT_PW_BADPW	KRB_ET(GT_PW_BADPW)	/* 52 - Wrong passwd */
#define	GT_PW_PROT	KRB_ET(GT_PW_PROT)	/* 53 - Protocol Error */
#define	GT_PW_KDCERR	KRB_ET(GT_PW_KDCERR)	/* 54 - Error ret by KDC */
#define	GT_PW_NULLTKT	KRB_ET(GT_PW_NULLTKT)	/* 55 - Null tkt ret by KDC */

/* Values returned by send_to_kdc */
#define	SKDC_OK		KRB_ET(KSUCCESS)	/*  0 - Response received */
#define	SKDC_RETRY	KRB_ET(SKDC_RETRY)	/* 56 - Retry count exceeded */
#define	SKDC_CANT	KRB_ET(SKDC_CANT)	/* 57 - Can't send request */

/*
 * Values returned by get_intkt
 * (can also return SKDC_* and KDC errors)
 */

#define	INTK_OK		KRB_ET(KSUCCESS)	/*  0 - Ticket obtained */
#define	INTK_PW_NULL	KRB_ET(GT_PW_NULL)	/* 51 - Current PW is null */
#define	INTK_W_NOTALL	KRB_ET(INTK_W_NOTALL)	/* 61 - Not ALL tkts retd */
#define	INTK_BADPW	KRB_ET(INTK_BADPW)	/* 62 - Incorrect password */
#define	INTK_PROT	KRB_ET(INTK_PROT)	/* 63 - Protocol Error */
#define	INTK_ERR	KRB_ET(INTK_ERR)	/* 70 - Other error */

/* Values returned by get_adtkt */
#define AD_OK		KRB_ET(KSUCCESS)	/*  0 - Ticket Obtained */
#define AD_NOTGT	KRB_ET(AD_NOTGT)	/* 71 - Don't have tgt */

/* Error codes returned by ticket file utilities */
#define	NO_TKT_FIL	KRB_ET(NO_TKT_FIL)	/* 76 - No ticket file found */
#define	TKT_FIL_ACC	KRB_ET(TKT_FIL_ACC)	/* 77 - Can't acc tktfile */
#define	TKT_FIL_LCK	KRB_ET(TKT_FIL_LCK)	/* 78 - Can't lck tkt file */
#define	TKT_FIL_FMT	KRB_ET(TKT_FIL_FMT)	/* 79 - Bad tkt file format */
#define	TKT_FIL_INI	KRB_ET(TKT_FIL_INI)	/* 80 - tf_init not called */

/* Error code returned by kparse_name */
#define	KNAME_FMT	KRB_ET(KNAME_FMT)	/* 81 - Bad krb name fmt */

/* Error code returned by krb_mk_safe */
#define	SAFE_PRIV_ERROR	(-1)			/* syscall error */

/* Kerberos ticket flag field bit definitions */
#define K_FLAG_ORDER    0       /* bit 0 --> lsb */
#define K_FLAG_1                /* reserved */
#define K_FLAG_2                /* reserved */
#define K_FLAG_3                /* reserved */
#define K_FLAG_4                /* reserved */
#define K_FLAG_5                /* reserved */
#define K_FLAG_6                /* reserved */
#define K_FLAG_7                /* reserved, bit 7 --> msb */

/* Are these needed anymore? */
#ifdef	OLDNAMES
#define krb_mk_req	mk_ap_req
#define krb_rd_req	rd_ap_req
#define krb_kntoln	an_to_ln
#define krb_set_key	set_serv_key
#define krb_get_cred	get_credentials
#define krb_mk_priv	mk_private_msg
#define krb_rd_priv	rd_private_msg
#define krb_mk_safe	mk_safe_msg
#define krb_rd_safe	rd_safe_msg
#define krb_mk_err	mk_appl_err_msg
#define krb_rd_err	rd_appl_err_msg
#define krb_ck_repl	check_replay
#define	krb_get_pw_in_tkt	get_in_tkt
#define krb_get_svc_in_tkt	get_svc_in_tkt
#define krb_get_pw_tkt		get_pw_tkt
#define krb_realmofhost		krb_getrealm
#define krb_get_phost		get_phost
#define krb_get_krbhst		get_krbhst
#define krb_get_lrealm		get_krbrlm
#endif	/* OLDNAMES */

/* Defines for krb_sendauth and krb_recvauth */

#define	KOPT_DONT_MK_REQ 0x00000001 /* don't call krb_mk_req */
#define	KOPT_DO_MUTUAL   0x00000002 /* do mutual auth */
#define	KOPT_DONT_CANON  0x00000004 /* don't canonicalize inst as a host */

#define	KRB_SENDAUTH_VLEN 8	    /* length for version strings */

#ifdef ATHENA_COMPAT
#define	KOPT_DO_OLDSTYLE 0x00000008 /* use the old-style protocol */
#endif /* ATHENA_COMPAT */


#ifdef _WIN32
#define	TIME_GMT_UNIXSEC	win_time_gmt_unixsec((unsigned KRB4_32 *)0)
#define	TIME_GMT_UNIXSEC_US(us)	win_time_gmt_unixsec((us))
#define	CONVERT_TIME_EPOCH	win_time_get_epoch()
#else
/* until we do V4 compat under DOS, just turn this off */
#define	_fmemcpy	memcpy
#define	_fstrncpy	strncpy
#define	far_fputs	fputs
/* and likewise, just drag in the unix time interface */
#define	TIME_GMT_UNIXSEC	unix_time_gmt_unixsec((unsigned KRB4_32 *)0)
#define	TIME_GMT_UNIXSEC_US(us)	unix_time_gmt_unixsec((us))
#define	CONVERT_TIME_EPOCH	((long)0)	/* Unix epoch is Krb epoch */
#endif /* _WIN32 */

/* Constants for KerberosProfileLib */
#define	REALMS_V4_PROF_REALMS_SECTION		"v4 realms"
#define	REALMS_V4_PROF_KDC			"kdc"
#define	REALMS_V4_PROF_ADMIN_KDC		"admin_server"
#define	REALMS_V4_PROF_KPASSWD_KDC		"kpasswd_server"
#define	REALMS_V4_PROF_DOMAIN_SECTION		"v4 domain_realm"
#define	REALMS_V4_PROF_LIBDEFAULTS_SECTION	"libdefaults"
#define	REALMS_V4_PROF_LOCAL_REALM		"default_realm"
#define	REALMS_V4_PROF_STK			"string_to_key_type"
#define	REALMS_V4_MIT_STK			"mit_string_to_key"
#define	REALMS_V4_AFS_STK			"afs_string_to_key"
#define	REALMS_V4_COLUMBIA_STK			"columbia_string_to_key"
#define	REALMS_V4_DEFAULT_REALM			"default_realm"
#define	REALMS_V4_NO_ADDRESSES			"noaddresses"

/* ask to disable IP address checking in the library */
extern int krb_ignore_ip_address;

/* Debugging printfs shouldn't even be compiled on many systems that don't
   support printf!  Use it like  DEB (("Oops - %s\n", string));  */

#ifdef DEBUG
#define	DEB(x)	if (krb_debug) printf x
extern int krb_debug;
#else
#define	DEB(x)	/* nothing */
#endif

/* Define a couple of function types including parameters.  These
   are needed on MS-Windows to convert arguments of the function pointers
   to the proper types during calls.  */

typedef int (KRB5_CALLCONV *key_proc_type)
	(char *, char *, char *,
		    char *, C_Block)
KRB5INT_KRB4_DEPRECATED;

#define KEY_PROC_TYPE_DEFINED

typedef int (KRB5_CALLCONV *decrypt_tkt_type)
	(char *, char *, char *,
		    char *, key_proc_type, KTEXT *)
KRB5INT_KRB4_DEPRECATED;

#define DECRYPT_TKT_TYPE_DEFINED

extern struct _krb5_context * krb5__krb4_context;

/*
 * Function Prototypes for Kerberos V4.
 */

struct sockaddr_in;

/* dest_tkt.c */
int KRB5_CALLCONV dest_tkt
	(void)
KRB5INT_KRB4_DEPRECATED;

/* err_txt.c */
const char * KRB5_CALLCONV krb_get_err_text
	(int errnum)
KRB5INT_KRB4_DEPRECATED;

/* g_ad_tkt.c */
/* Previously not KRB5_CALLCONV */
int KRB5_CALLCONV get_ad_tkt
	(char *service, char *sinst, char *realm, int lifetime)
KRB5INT_KRB4_DEPRECATED;

/* g_admhst.c */
int KRB5_CALLCONV krb_get_admhst
	(char *host, char *realm, int idx)
KRB5INT_KRB4_DEPRECATED;

/* g_cred.c */
int KRB5_CALLCONV krb_get_cred
	(char *service, char *instance, char *realm,
		   CREDENTIALS *c)
KRB5INT_KRB4_DEPRECATED;

/* g_in_tkt.c */
/* Previously not KRB5_CALLCONV */
int KRB5_CALLCONV krb_get_in_tkt
	(char *k_user, char *instance, char *realm,
		   char *service, char *sinst, int life,
		   key_proc_type, decrypt_tkt_type, char *arg)
KRB5INT_KRB4_DEPRECATED;

#if KRB_PRIVATE
/* Previously not KRB5_CALLCONV */
int KRB5_CALLCONV krb_get_in_tkt_preauth
	(char *k_user, char *instance, char *realm,
		   char *service, char *sinst, int life,
		   key_proc_type, decrypt_tkt_type, char *arg,
		   char *preauth_p, int preauth_len)
KRB5INT_KRB4_DEPRECATED;
#endif

/* From KfM */
int KRB5_CALLCONV krb_get_in_tkt_creds(char *, char *, char *, char *, char *,
    int, key_proc_type, decrypt_tkt_type, char *, CREDENTIALS *)
KRB5INT_KRB4_DEPRECATED;


/* g_krbhst.c */
int KRB5_CALLCONV krb_get_krbhst
	(char *host, const char *realm, int idx)
KRB5INT_KRB4_DEPRECATED;

/* g_krbrlm.c */
int KRB5_CALLCONV krb_get_lrealm
	(char *realm, int idx)
KRB5INT_KRB4_DEPRECATED;

/* g_phost.c */
char * KRB5_CALLCONV krb_get_phost
	(char * alias)
KRB5INT_KRB4_DEPRECATED;

/* get_pw_tkt */
int KRB5_CALLCONV get_pw_tkt 
        (char *, char *, char *, char *)
KRB5INT_KRB4_DEPRECATED;

/* g_pw_in_tkt.c */
int KRB5_CALLCONV krb_get_pw_in_tkt
	(char *k_user, char *instance, char *realm,
		   char *service, char *sinstance,
		   int life, char *password)
KRB5INT_KRB4_DEPRECATED;

#if KRB_PRIVATE
int KRB5_CALLCONV krb_get_pw_in_tkt_preauth
	(char *k_user, char *instance, char *realm,
		   char *service, char *sinstance,
		   int life, char *password)
KRB5INT_KRB4_DEPRECATED;
#endif

int KRB5_CALLCONV
krb_get_pw_in_tkt_creds(char *, char *, char *,
	char *, char *, int, char *, CREDENTIALS *)
KRB5INT_KRB4_DEPRECATED;

/* g_svc_in_tkt.c */
int KRB5_CALLCONV krb_get_svc_in_tkt
	(char *k_user, char *instance, char *realm,
		   char *service, char *sinstance,
		   int life, char *srvtab)
KRB5INT_KRB4_DEPRECATED;

/* g_tf_fname.c */
int KRB5_CALLCONV krb_get_tf_fullname
	(const char *ticket_file, char *name, char *inst, char *realm)
KRB5INT_KRB4_DEPRECATED;

/* g_tf_realm.c */
int KRB5_CALLCONV krb_get_tf_realm
	(const char *ticket_file, char *realm)
KRB5INT_KRB4_DEPRECATED;

/* g_tkt_svc.c */
int KRB5_CALLCONV krb_get_ticket_for_service
	(char *serviceName,
		   char *buf, unsigned KRB4_32 *buflen,
		   int checksum, des_cblock, Key_schedule,
		   char *version, int includeVersion)
KRB5INT_KRB4_DEPRECATED;

#if KRB_PRIVATE
/* in_tkt.c */
int KRB5_CALLCONV in_tkt
	(char *name, char *inst)
KRB5INT_KRB4_DEPRECATED;

int KRB5_CALLCONV krb_in_tkt
        (char *pname, char *pinst, char *realm)
KRB5INT_KRB4_DEPRECATED;
#endif

/* kname_parse.c */
int KRB5_CALLCONV kname_parse
	(char *name, char *inst, char *realm,
		   char *fullname)
KRB5INT_KRB4_DEPRECATED;

/* Merged from KfM */
int KRB5_CALLCONV kname_unparse
	(char *, const char *, const char *, const char *)
KRB5INT_KRB4_DEPRECATED;

int KRB5_CALLCONV k_isname
        (char *)
KRB5INT_KRB4_DEPRECATED;

int KRB5_CALLCONV k_isinst
        (char *)
KRB5INT_KRB4_DEPRECATED;

int KRB5_CALLCONV k_isrealm
        (char *)
KRB5INT_KRB4_DEPRECATED;


/* kuserok.c */
int KRB5_CALLCONV kuserok
	(AUTH_DAT *kdata, char *luser)
KRB5INT_KRB4_DEPRECATED;

/* lifetime.c */
KRB4_32 KRB5_CALLCONV krb_life_to_time
	(KRB4_32 start, int life)
KRB5INT_KRB4_DEPRECATED;

int KRB5_CALLCONV krb_time_to_life
	(KRB4_32 start, KRB4_32 end)
KRB5INT_KRB4_DEPRECATED;

/* mk_auth.c */
int KRB5_CALLCONV krb_check_auth
	(KTEXT, unsigned KRB4_32 cksum, MSG_DAT *,
		   C_Block, Key_schedule,
		   struct sockaddr_in * local_addr,
		   struct sockaddr_in * foreign_addr)
KRB5INT_KRB4_DEPRECATED;

int KRB5_CALLCONV krb_mk_auth
	(long k4_options, KTEXT ticket,
		   char *service, char *inst, char *realm,
		   unsigned KRB4_32 checksum, char *version, KTEXT buf)
KRB5INT_KRB4_DEPRECATED;

/* mk_err.c */
long KRB5_CALLCONV krb_mk_err
	(u_char *out, KRB4_32 k4_code, char *text)
KRB5INT_KRB4_DEPRECATED;

#if KRB_PRIVATE
/* mk_preauth.c */
int krb_mk_preauth
	(char **preauth_p, int *preauth_len, key_proc_type,
		   char *name, char *inst, char *realm, char *password,
		   C_Block)
KRB5INT_KRB4_DEPRECATED;

void krb_free_preauth
	(char * preauth_p, int len)
KRB5INT_KRB4_DEPRECATED;
#endif

/* mk_priv.c */
long KRB5_CALLCONV krb_mk_priv
	(u_char *in, u_char *out,
		   unsigned KRB4_32 length,
		   Key_schedule, C_Block *,
		   struct sockaddr_in * sender,
		   struct sockaddr_in * receiver)
KRB5INT_KRB4_DEPRECATED;

/* mk_req.c */
int KRB5_CALLCONV krb_mk_req
	(KTEXT authent,
		   char *service, char *instance, char *realm,
		   KRB4_32 checksum)
KRB5INT_KRB4_DEPRECATED;

/* Merged from KfM */
int KRB5_CALLCONV krb_mk_req_creds(KTEXT, CREDENTIALS *, KRB_INT32)
KRB5INT_KRB4_DEPRECATED;

/* Added CALLCONV (KfM exports w/o INTERFACE, but KfW doesn't export?) */
int KRB5_CALLCONV krb_set_lifetime(int newval)
KRB5INT_KRB4_DEPRECATED;

/* mk_safe.c */
long KRB5_CALLCONV krb_mk_safe
	(u_char *in, u_char *out, unsigned KRB4_32 length,
		   C_Block *,
		   struct sockaddr_in *sender,
		   struct sockaddr_in *receiver)
KRB5INT_KRB4_DEPRECATED;

#if KRB_PRIVATE
/* netread.c */
int krb_net_read
	(int fd, char *buf, int len)
KRB5INT_KRB4_DEPRECATED;

/* netwrite.c */
int krb_net_write
	(int fd, char *buf, int len)
KRB5INT_KRB4_DEPRECATED;

/* pkt_clen.c */
int pkt_clen
	(KTEXT)
KRB5INT_KRB4_DEPRECATED;
#endif

/* put_svc_key.c */
int KRB5_CALLCONV put_svc_key
	(char *sfile,
		   char *name, char *inst, char *realm,
		   int newvno, char *key)
KRB5INT_KRB4_DEPRECATED;

/* rd_err.c */
int KRB5_CALLCONV krb_rd_err
	(u_char *in, u_long in_length,
		   long *k4_code, MSG_DAT *m_data)
KRB5INT_KRB4_DEPRECATED;

/* rd_priv.c */
long KRB5_CALLCONV krb_rd_priv
	(u_char *in,unsigned KRB4_32 in_length,
		   Key_schedule, C_Block *,
		   struct sockaddr_in *sender,
		   struct sockaddr_in *receiver,
		   MSG_DAT *m_data)
KRB5INT_KRB4_DEPRECATED;

/* rd_req.c */
int KRB5_CALLCONV krb_rd_req
	(KTEXT, char *service, char *inst,
		   unsigned KRB4_32 from_addr, AUTH_DAT *,
		   char *srvtab)
KRB5INT_KRB4_DEPRECATED;

/* Merged from KfM */
int KRB5_CALLCONV
krb_rd_req_int(KTEXT, char *, char *, KRB_UINT32, AUTH_DAT *, C_Block)
KRB5INT_KRB4_DEPRECATED;

/* rd_safe.c */
long KRB5_CALLCONV krb_rd_safe
	(u_char *in, unsigned KRB4_32 in_length,
		   C_Block *,
		   struct sockaddr_in *sender,
		   struct sockaddr_in *receiver,
		   MSG_DAT *m_data)
KRB5INT_KRB4_DEPRECATED;

/* rd_svc_key.c */
int KRB5_CALLCONV read_service_key
	(char *service, char *instance, char *realm,
		   int kvno, char *file, char *key)
KRB5INT_KRB4_DEPRECATED;

int KRB5_CALLCONV get_service_key
	(char *service, char *instance, char *realm,
		   int *kvno, char *file, char *key)
KRB5INT_KRB4_DEPRECATED;

/* realmofhost.c */
char * KRB5_CALLCONV krb_realmofhost
	(char *host)
KRB5INT_KRB4_DEPRECATED;

/* recvauth.c */
int KRB5_CALLCONV krb_recvauth
	(long k4_options, int fd, KTEXT ticket,
		   char *service, char *instance,
		   struct sockaddr_in *foreign_addr,
		   struct sockaddr_in *local_addr,
		   AUTH_DAT *kdata, char *srvtab,
		   Key_schedule schedule, char *version)
KRB5INT_KRB4_DEPRECATED;

/* sendauth.c */
int KRB5_CALLCONV krb_sendauth
        (long k4_options, int fd, KTEXT ticket,
	 char *service, char *inst, char *realm,
	 unsigned KRB4_32 checksum, MSG_DAT *msg_data,
	 CREDENTIALS *cred, Key_schedule schedule, 
	 struct sockaddr_in *laddr, struct sockaddr_in *faddr, 
	 char *version)
KRB5INT_KRB4_DEPRECATED;

#if KRB_PRIVATE
/* save_creds.c */
int KRB5_CALLCONV krb_save_credentials
	(char *service, char *instance, char *realm,
		   C_Block session, int lifetime, int kvno,
		   KTEXT ticket, long issue_date)
KRB5INT_KRB4_DEPRECATED;

/* send_to_kdc.c */
/* XXX PRIVATE? KfM doesn't export. */
int send_to_kdc
	(KTEXT pkt, KTEXT rpkt, char *realm)
KRB5INT_KRB4_DEPRECATED;
#endif

/* tkt_string.c */
/* Used to return pointer to non-const char */
const char * KRB5_CALLCONV tkt_string
	(void)
KRB5INT_KRB4_DEPRECATED;

/* Previously not KRB5_CALLCONV, and previously took pointer to non-const. */
void KRB5_CALLCONV krb_set_tkt_string
	(const char *)
KRB5INT_KRB4_DEPRECATED;

#if KRB_PRIVATE
/* tf_util.c */
int KRB5_CALLCONV tf_init (const char *tf_name, int rw)
KRB5INT_KRB4_DEPRECATED;

int KRB5_CALLCONV tf_get_pname (char *p)
KRB5INT_KRB4_DEPRECATED;

int KRB5_CALLCONV tf_get_pinst (char *p)
KRB5INT_KRB4_DEPRECATED;

int KRB5_CALLCONV tf_get_cred (CREDENTIALS *c)
KRB5INT_KRB4_DEPRECATED;

void KRB5_CALLCONV tf_close (void)
KRB5INT_KRB4_DEPRECATED;
#endif

#if KRB_PRIVATE
/* unix_time.c */
unsigned KRB4_32 KRB5_CALLCONV unix_time_gmt_unixsec 
        (unsigned KRB4_32 *)
KRB5INT_KRB4_DEPRECATED;

/*
 * Internal prototypes
 */
extern int krb_set_key
	(char *key, int cvt)
KRB5INT_KRB4_DEPRECATED;

/* This is exported by KfM.  It was previously not KRB5_CALLCONV. */
extern int KRB5_CALLCONV decomp_ticket
	(KTEXT tkt, unsigned char *flags, char *pname,
		   char *pinstance, char *prealm, unsigned KRB4_32 *paddress,
		   C_Block session, int *life, unsigned KRB4_32 *time_sec,
		   char *sname, char *sinstance, C_Block,
		   Key_schedule key_s)
KRB5INT_KRB4_DEPRECATED;


extern void cr_err_reply(KTEXT pkt, char *pname, char *pinst, char *prealm,
			 u_long time_ws, u_long e, char *e_string)
KRB5INT_KRB4_DEPRECATED;

extern int create_ciph(KTEXT c, C_Block session, char *service, 
		       char *instance, char *realm, unsigned long life,
		       int kvno, KTEXT tkt, unsigned long kdc_time, 
		       C_Block key)
KRB5INT_KRB4_DEPRECATED;


extern int krb_create_ticket(KTEXT tkt, unsigned int flags, char *pname,
			     char *pinstance, char *prealm, long paddress,
			     char *session, int life, long time_sec, 
			     char *sname, char *sinstance, C_Block key)
KRB5INT_KRB4_DEPRECATED;

#endif /* KRB_PRIVATE */

/* This function is used by KEYFILE above.  Do not call it directly */
extern char * krb__get_srvtabname(const char *)
KRB5INT_KRB4_DEPRECATED;

#if KRB_PRIVATE

extern int krb_kntoln(AUTH_DAT *, char *)
KRB5INT_KRB4_DEPRECATED;

#ifdef KRB5_GENERAL__
extern int krb_cr_tkt_krb5(KTEXT tkt, unsigned int flags, char *pname,
			   char *pinstance, char *prealm, long paddress,
			   char *session, int life, long time_sec, 
			   char *sname, char *sinstance,  
			   krb5_keyblock *k5key)
KRB5INT_KRB4_DEPRECATED;

extern int krb_set_key_krb5(krb5_context ctx, krb5_keyblock *key)
KRB5INT_KRB4_DEPRECATED;

#endif

#endif /* KRB_PRIVATE */

/*
 * krb_change_password -- merged from KfM
 */
/* change_password.c */
int KRB5_CALLCONV krb_change_password(char *, char *, char *, char *, char *)
KRB5INT_KRB4_DEPRECATED;

/*
 * RealmsConfig-glue.c -- merged from KfM
 */
int KRB5_CALLCONV krb_get_profile(profile_t *)
KRB5INT_KRB4_DEPRECATED;

#ifdef _WIN32
HINSTANCE get_lib_instance(void)
KRB5INT_KRB4_DEPRECATED;
unsigned int krb_get_notification_message(void)
KRB5INT_KRB4_DEPRECATED;
char * KRB5_CALLCONV krb_get_default_user(void)
KRB5INT_KRB4_DEPRECATED;
int KRB5_CALLCONV krb_set_default_user(char *)
KRB5INT_KRB4_DEPRECATED;
unsigned KRB4_32 win_time_gmt_unixsec(unsigned KRB4_32 *)
KRB5INT_KRB4_DEPRECATED;
long win_time_get_epoch(void)
KRB5INT_KRB4_DEPRECATED;
#endif

#if TARGET_OS_MAC
#	pragma pack(pop)
#endif

KRBINT_END_DECLS

#endif	/* KRB_DEFS */
