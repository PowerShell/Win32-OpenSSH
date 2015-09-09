/*
 * This file is now only used on Windows
 */

/*
 * type functions split out of here to make things look nicer in the
 * various include files which need these definitions, as well as in
 * the util/ directories.
 */

#ifndef _KRB5_WIN_MAC_H
#define _KRB5_WIN_MAC_H

#ifdef _WIN32

#define ID_READ_PWD_DIALOG  10000
#define ID_READ_PWD_PROMPT  10001
#define ID_READ_PWD_PROMPT2 10002
#define ID_READ_PWD_PWD     10003

#ifdef RES_ONLY

#define APSTUDIO_HIDDEN_SYMBOLS
#include <windows.h>

#else /* ! RES_ONLY */

/* To ensure backward compatibility of the ABI use 32-bit time_t on 
 * 32-bit Windows. 
 */
#ifdef _KRB5_INT_H
#ifdef KRB5_GENERAL__
#error krb5.h included before k5-int.h
#endif /* KRB5_GENERAL__ */
#if _INTEGRAL_MAX_BITS >= 64 && _MSC_VER >= 1400 && !defined(_WIN64) && !defined(_USE_32BIT_TIME_T)
#if defined(_TIME_T_DEFINED) || defined(_INC_IO) || defined(_INC_TIME) || defined(_INC_WCHAR)
#error time_t has been defined as a 64-bit integer which is incompatible with Kerberos on this platform.
#endif /* _TIME_T_DEFINED */
#define _USE_32BIT_TIME_T
#endif 
#endif

#define SIZEOF_INT      4
#define SIZEOF_SHORT    2
#define SIZEOF_LONG     4

#include <windows.h>
#include <limits.h>

#ifndef SIZE_MAX    /* in case Microsoft defines max size of size_t */
#ifdef  MAX_SIZE    /* Microsoft defines MAX_SIZE as max size of size_t */
#define SIZE_MAX MAX_SIZE
#else
#define SIZE_MAX UINT_MAX
#endif
#endif

#ifndef KRB5_CALLCONV
#  define KRB5_CALLCONV __stdcall
#  define KRB5_CALLCONV_C __cdecl

/*
 * Use this to mark an incorrect calling convention that has been
 * "immortalized" because it was incorrectly exported in a previous
 * release.
 */

#  define KRB5_CALLCONV_WRONG KRB5_CALLCONV_C

#endif /* !KRB5_CALLCONV */

#ifndef KRB5_SYSTYPES__
#define KRB5_SYSTYPES__
#include <sys/types.h>
typedef unsigned long	 u_long;      /* Not part of sys/types.h on the pc */
typedef unsigned int	 u_int;
typedef unsigned short	 u_short;
typedef unsigned char	 u_char;
typedef unsigned int     uint32_t;
typedef int              int32_t;
#if _INTEGRAL_MAX_BITS >= 64
typedef unsigned __int64 uint64_t;
typedef __int64          int64_t;
#endif
#ifndef SSIZE_T_DEFINED
#ifdef ssize_t
#undef ssize_t
#endif
#ifdef _WIN64
typedef __int64		 ssize_t;
//#else
//typedef _W64 int 	 ssize_t;
#endif
#define SSIZE_T_DEFINED
#endif
#endif /* KRB5_SYSTYPES__ */

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN  512
#endif

#ifndef MAXPATHLEN
#define MAXPATHLEN      256            /* Also for Windows temp files */
#endif

#ifndef HAVE_NETINET_IN_H
#define HAVE_NETINET_IN_H
#endif

#ifndef MSDOS_FILESYSTEM
#define MSDOS_FILESYSTEM
#endif

#ifndef HAVE_STRING_H
#define HAVE_STRING_H
#endif

#ifndef HAVE_SRAND
#define HAVE_SRAND
#endif

#ifndef HAVE_ERRNO
#define HAVE_ERRNO
#endif

#ifndef HAVE_STRDUP
#define HAVE_STRDUP
#endif

#ifndef HAVE_GETADDRINFO
#define HAVE_GETADDRINFO
#endif

#ifndef HAVE_GETNAMEINFO
#define HAVE_GETNAMEINFO
#endif

#ifndef NO_USERID
#define NO_USERID
#endif

#ifndef NO_PASSWORD
#define NO_PASSWORD
#endif

#ifndef HAVE_STRERROR
#define HAVE_STRERROR
#endif

#ifndef SYS_ERRLIST_DECLARED
#define SYS_ERRLIST_DECLARED
#endif

/* if __STDC_VERSION__ >= 199901L this shouldn't be needed */
#define inline __inline
#define KRB5_USE_INET6
#define NEED_INSIXADDR_ANY
#define ENABLE_THREADS

#define WM_KERBEROS5_CHANGED "Kerberos5 Changed"
#ifdef KRB4
#define WM_KERBEROS_CHANGED "Kerberos Changed"
#endif

/* Kerberos Windows initialization file */
#define KERBEROS_INI    "kerberos.ini"
#ifdef CYGNUS
#define KERBEROS_HLP    "kerbnet.hlp"
#else
#define KERBEROS_HLP	"krb5clnt.hlp"
#endif
#define INI_DEFAULTS    "Defaults"
#define   INI_USER        "User"          /* Default user */
#define   INI_INSTANCE    "Instance"      /* Default instance */
#define   INI_REALM       "Realm"         /* Default realm */
#define   INI_POSITION    "Position"
#define   INI_OPTIONS     "Options"
#define   INI_DURATION    "Duration"   /* Ticket duration in minutes */
#define INI_EXPIRATION  "Expiration" /* Action on expiration (alert or beep) */
#define   INI_ALERT       "Alert"
#define   INI_BEEP        "Beep"
#define   INI_FILES       "Files"
#ifdef KRB4
#define   INI_KRB_CONF    "krb.conf"     /* Location of krb.conf file */
#define   DEF_KRB_CONF    "krb.conf"      /* Default name for krb.conf file */
#else
#define INI_KRB5_CONF   "krb5.ini"	/* From k5-config.h */
#define INI_KRB_CONF    INI_KRB5_CONF	/* Location of krb.conf file */
#define DEF_KRB_CONF    INI_KRB5_CONF	/* Default name for krb.conf file */
#define INI_TICKETOPTS  "TicketOptions" /* Ticket options */
#define   INI_FORWARDABLE  "Forwardable" /* get forwardable tickets */
#define INI_KRB_CCACHE  "krb5cc"       	/* From k5-config.h */
#endif
#define INI_KRB_REALMS  "krb.realms"    /* Location of krb.realms file */
#define DEF_KRB_REALMS  "krb.realms"    /* Default name for krb.realms file */
#define INI_RECENT_LOGINS "Recent Logins"    
#define INI_LOGIN       "Login"

#ifndef HAS_VOID_TYPE
#define HAS_VOID_TYPE
#endif

#ifndef HAVE_STDARG_H
#define HAVE_STDARG_H
#endif

#ifndef HAVE_SYS_TYPES_H
#define HAVE_SYS_TYPES_H
#endif

#ifndef HAVE_STDLIB_H
#define HAVE_STDLIB_H
#endif

/* This controls which encryption routines libcrypto will provide */
#define PROVIDE_DES_CBC_MD5
#define PROVIDE_DES_CBC_CRC
#define PROVIDE_DES_CBC_RAW
#define PROVIDE_DES_CBC_CKSUM
#define PROVIDE_CRC32
#define PROVIDE_RSA_MD4
#define PROVIDE_RSA_MD5
/* #define PROVIDE_DES3_CBC_SHA */
/* #define PROVIDE_DES3_CBC_RAW */
/* #define PROVIDE_NIST_SHA */

/* Ugly. Microsoft, in stdc mode, doesn't support the low-level i/o
 * routines directly. Rather, they only export the _<function> version.
 * The following defines works around this problem. 
 */
#include <sys\types.h>
#include <sys\stat.h>
#include <fcntl.h>
#include <io.h>
//#include <process.h>

#ifdef NEED_SYSERROR
/* Only needed by util/et/error_message.c but let's keep the source clean */
#define sys_nerr        _sys_nerr
#define sys_errlist     _sys_errlist
#endif

/*
 * Functions with slightly different names on the PC
 */
#ifndef strcasecmp
#define strcasecmp   stricmp
#endif
#ifndef strncasecmp
#define strncasecmp  strnicmp
#endif

HINSTANCE get_lib_instance(void);

#define GETSOCKNAME_ARG2_TYPE	struct sockaddr
#define GETSOCKNAME_ARG3_TYPE	size_t
#define GETPEERNAME_ARG2_TYPE	GETSOCKNAME_ARG2_TYPE
#define GETPEERNAME_ARG3_TYPE	GETSOCKNAME_ARG3_TYPE

#endif /* !RES_ONLY */

#endif /* _WIN32 */

#define THREEPARAMOPEN(x,y,z) open(x,y,z)

#ifndef KRB5_CALLCONV
#define KRB5_CALLCONV
#endif

#ifndef KRB5_CALLCONV_C
#define KRB5_CALLCONV_C
#endif

#endif /* _KRB5_WIN_MAC_H */
