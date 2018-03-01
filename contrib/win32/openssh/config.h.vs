#pragma once

/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* Define if you have a getaddrinfo that fails
 for the all-zeros IPv6 address
   */
/* #undef AIX_GETNAMEINFO_HACK */

/* Define if your AIX loginfailed() function
 takes 4 arguments (AIX >= 5.2)
   */
/* #undef AIX_LOGINFAILED_4ARG */

/* System only supports IPv4 audit records */
/* #undef AU_IPv4 */

/* Define if your resolver libs need this for getrrsetbyname */
/* #undef BIND_8_COMPAT */

/* Define if cmsg_type is not passed correctly */
/* #undef BROKEN_CMSG_TYPE */

/* getaddrinfo is broken (if present) */
/* #undef BROKEN_GETADDRINFO */

/* getgroups(0,NULL) will return -1 */
/* #undef BROKEN_GETGROUPS */

/* FreeBSD glob does not do what we need */
/* #undef BROKEN_GLOB */

/* Define if you system's inet_ntoa is busted
 (e.g. Irix gcc issue) */
/* #undef BROKEN_INET_NTOA */

/* ia_uinfo routines not supported by OS yet */
/* #undef BROKEN_LIBIAF */

/* Ultrix mmap can't map files */
/* #undef BROKEN_MMAP */

/* Define if your struct dirent expects you to
 allocate extra space for
   d_name */
/* #undef BROKEN_ONE_BYTE_DIRENT_D_NAME */

/* Can't do comparisons on readv */
/* #undef BROKEN_READV_COMPARISON */

/* Define if you have a broken realpath. */
/* #undef BROKEN_REALPATH */

/* Needed for NeXT */
/* #undef BROKEN_SAVED_UIDS */

/* Define if your setregid() is broken */
/* #undef BROKEN_SETREGID */

/* Define if your setresgid() is broken */
/* #undef BROKEN_SETRESGID */

/* Define if your setresuid() is broken */
/* #undef BROKEN_SETRESUID */

/* Define if your setreuid() is broken */
/* #undef BROKEN_SETREUID */

/* LynxOS has broken setvbuf() implementation */
/* #undef BROKEN_SETVBUF */

/* QNX shadow support is broken */
/* #undef BROKEN_SHADOW_EXPIRE */

/* Define if your snprintf is busted */
/* #undef BROKEN_SNPRINTF */

/* tcgetattr with ICANON may hang */
#define BROKEN_TCGETATTR_ICANON 1

/* updwtmpx is broken (if present) */
/* #undef BROKEN_UPDWTMPX */

/* Define if you have BSD auth support */
/* #undef BSD_AUTH */

/* Define if you want to specify the path to your lastlog file */
#define CONF_LASTLOG_FILE "/var/log/lastlog"

/* Define if you want to specify the path to your utmp file */
#define CONF_UTMP_FILE "/var/run/utmp"

/* Define if you want to specify the path to your wtmpx file */
/* #undef CONF_WTMPX_FILE */

/* Define if you want to specify the path to your wtmp file */
/* #undef CONF_WTMP_FILE */

/* Define if your platform needs to skip post auth
 file descriptor passing */
/* #undef DISABLE_FD_PASSING */

/* Define if you don't want to use lastlog */
/* #undef DISABLE_LASTLOG */

/* Define if you don't want to use your
 system's login() call */
/* #undef DISABLE_LOGIN */

/* Define if you don't want to use pututline()
 etc. to write [uw]tmp */
/* #undef DISABLE_PUTUTLINE */

/* Define if you don't want to use pututxline()
 etc. to write [uw]tmpx */
/* #undef DISABLE_PUTUTXLINE */

/* Define if you want to disable shadow passwords */
#define DISABLE_SHADOW 1

/* Define if you don't want to use utmp */
#define DISABLE_UTMP 1

/* Define if you don't want to use utmpx */
#define DISABLE_UTMPX 1

/* Define if you don't want to use wtmp */
#define DISABLE_WTMP 1

/* Define if you don't want to use wtmpx */
#define DISABLE_WTMPX 1

/* Enable for PKCS#11 support */
/* #undef ENABLE_PKCS11 */

/* File names may not contain backslash characters */
/* #undef FILESYSTEM_NO_BACKSLASH */

/* fsid_t has member val */
/* #undef FSID_HAS_VAL */

/* fsid_t has member __val */
/* #undef FSID_HAS___VAL */

/* Define to 1 if the `getpgrp' function requires zero arguments. */
/* #undef GETPGRP_VOID */

/* Conflicting defs for getspnam */
/* #undef GETSPNAM_CONFLICTING_DEFS */

/* Define if your system glob() function has
 the GLOB_ALTDIRFUNC extension */
/* #undef GLOB_HAS_ALTDIRFUNC */

/* Define if your system glob() function has
 gl_matchc options in glob_t */
#define GLOB_HAS_GL_MATCHC 1

/* Define if your system glob() function has
 gl_statv options in glob_t */
#define GLOB_HAS_GL_STATV 1

/* Define this if you want GSSAPI
 support in the version 2 protocol */
/* #undef GSSAPI */

/* Define if you want to use shadow password expire field */
/* #undef HAS_SHADOW_EXPIRE */

/* Define if your system uses access rights style
 file descriptor passing */
/* #undef HAVE_ACCRIGHTS_IN_MSGHDR */

/* Define if you have ut_addr in utmp.h */
/* #undef HAVE_ADDR_IN_UTMP */

/* Define if you have ut_addr in utmpx.h */
/* #undef HAVE_ADDR_IN_UTMPX */

/* Define if you have ut_addr_v6 in utmp.h */
/* #undef HAVE_ADDR_V6_IN_UTMP */

/* Define if you have ut_addr_v6 in utmpx.h */
/* #undef HAVE_ADDR_V6_IN_UTMPX */

/* Define to 1 if you have the `arc4random' function. */
/* #undef HAVE_ARC4RANDOM */

/* Define to 1 if you have the `arc4random_buf' function. */
/* #undef HAVE_ARC4RANDOM_BUF */

/* Define to 1 if you have the `arc4random_uniform' function. */
/* #undef HAVE_ARC4RANDOM_UNIFORM */

/* Define to 1 if you have the `asprintf' function. */
/* #undef HAVE_ASPRINTF */

/* OpenBSD's gcc has bounded */
/* #undef HAVE_ATTRIBUTE__BOUNDED__ */

/* Have attribute nonnull */
#define HAVE_ATTRIBUTE__NONNULL__ 1

/* OpenBSD's gcc has sentinel */
/* #undef HAVE_ATTRIBUTE__SENTINEL__ */

/* Define to 1 if you have the `aug_get_machine' function. */
/* #undef HAVE_AUG_GET_MACHINE */

/* Define to 1 if you have the `b64_ntop' function. */
/* #undef HAVE_B64_NTOP */

/* Define to 1 if you have the `b64_pton' function. */
/* #undef HAVE_B64_PTON */

/* Define if you have the basename function. */
#define HAVE_BASENAME 1

/* Define to 1 if you have the `bcopy' function. */
/* #undef HAVE_BCOPY */

/* Define to 1 if you have the `bindresvport_sa' function. */
/* #undef HAVE_BINDRESVPORT_SA */

/* Define to 1 if you have the `BN_is_prime_ex' function. */
#define HAVE_BN_IS_PRIME_EX 1

/* Define to 1 if you have the <bsm/audit.h> header file. */
/* #undef HAVE_BSM_AUDIT_H */

/* Define to 1 if you have the <bstring.h> header file. */
/* #undef HAVE_BSTRING_H */

/* Define to 1 if you have the `clock' function. */
#define HAVE_CLOCK 1

/* define if you have clock_t data type */
#define HAVE_CLOCK_T 1

/* Define to 1 if you have the `closefrom' function. */
/* #undef HAVE_CLOSEFROM */

/* Define if gai_strerror() returns const char * */
/* #undef HAVE_CONST_GAI_STRERROR_PROTO */

/* Define if your system uses ancillary data style
 file descriptor passing */
/* #undef HAVE_CONTROL_IN_MSGHDR */

/* Define to 1 if you have the <crypto/sha2.h> header file. */
/* #undef HAVE_CRYPTO_SHA2_H */

/* Define to 1 if you have the <crypt.h> header file. */
/* #undef HAVE_CRYPT_H */

/* Define if you are on Cygwin */
/* #undef HAVE_CYGWIN */

/* Define if your libraries define daemon() */
/* #undef HAVE_DAEMON */

/* Define to 1 if you have the declaration of `authenticate', and to 0 if you
   don't. */
/* #undef HAVE_DECL_AUTHENTICATE */

/* Define to 1 if you have the declaration of `GLOB_NOMATCH', and to 0 if you
   don't. */
#define HAVE_DECL_GLOB_NOMATCH 1

/* Define to 1 if you have the declaration of `h_errno', and to 0 if you
   don't. */
#define HAVE_DECL_H_ERRNO 0

/* Define to 1 if you have the declaration of `loginfailed', and to 0 if you
   don't. */
/* #undef HAVE_DECL_LOGINFAILED */

/* Define to 1 if you have the declaration of `loginrestrictions', and to 0 if
   you don't. */
/* #undef HAVE_DECL_LOGINRESTRICTIONS */

/* Define to 1 if you have the declaration of `loginsuccess', and to 0 if you
   don't. */
/* #undef HAVE_DECL_LOGINSUCCESS */

/* Define to 1 if you have the declaration of `MAXSYMLINKS', and to 0 if you
   don't. */
#define HAVE_DECL_MAXSYMLINKS 0

/* Define to 1 if you have the declaration of `offsetof', and to 0 if you
   don't. */
#define HAVE_DECL_OFFSETOF 1

/* Define to 1 if you have the declaration of `O_NONBLOCK', and to 0 if you
   don't. */
#define HAVE_DECL_O_NONBLOCK 1

/* Define to 1 if you have the declaration of `passwdexpired', and to 0 if you
   don't. */
/* #undef HAVE_DECL_PASSWDEXPIRED */

/* Define to 1 if you have the declaration of `setauthdb', and to 0 if you
   don't. */
/* #undef HAVE_DECL_SETAUTHDB */

/* Define to 1 if you have the declaration of `SHUT_RD', and to 0 if you
   don't. */
#define HAVE_DECL_SHUT_RD 1

/* Define to 1 if you have the declaration of `writev', and to 0 if you don't.
   */
#define HAVE_DECL_WRITEV 0

/* Define to 1 if you have the declaration of `_getlong', and to 0 if you
   don't. */
/* #undef HAVE_DECL__GETLONG */

/* Define to 1 if you have the declaration of `_getshort', and to 0 if you
   don't. */
/* #undef HAVE_DECL__GETSHORT */

/* Define if you have /dev/ptmx */
#define HAVE_DEV_PTMX 1

/* Define if you have /dev/ptc */
/* #undef HAVE_DEV_PTS_AND_PTC */

/* Define to 1 if you have the <dirent.h> header file. */
/* #undef HAVE_DIRENT_H

/* Define to 1 if you have the `dirfd' function. */
/* #undef HAVE_DIRFD */

/* Define to 1 if you have the `dirname' function. */
/* #define HAVE_DIRNAME 1 */

/* Define to 1 if you have the `DSA_generate_parameters_ex' function. */
#define HAVE_DSA_GENERATE_PARAMETERS_EX 1

/* Define to 1 if you have the <endian.h> header file. */
/* #undef HAVE_ENDIAN_H */

/* Define to 1 if you have the `endutent' function. */
/* #undef HAVE_ENDUTENT */

/* Define to 1 if you have the `endutxent' function. */
/* #undef HAVE_ENDUTXENT */

/* Define if your system has /etc/default/login */
/* #undef HAVE_ETC_DEFAULT_LOGIN */

/* Define to 1 if you have the `EVP_sha256' function. */
#define HAVE_EVP_SHA256 1

/* Define if you have ut_exit in utmp.h */
/* #undef HAVE_EXIT_IN_UTMP */

/* Define to 1 if you have the `fchmod' function. */
/* #undef HAVE_FCHMOD */

/* Define to 1 if you have the `fchown' function. */
/* #undef HAVE_FCHOWN */

/* Use F_CLOSEM fcntl for closefrom */
/* #undef HAVE_FCNTL_CLOSEM */

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the <features.h> header file. */
/* #undef HAVE_FEATURES_H */

/* Define to 1 if you have the <floatingpoint.h> header file. */
/* #undef HAVE_FLOATINGPOINT_H */

/* Define to 1 if you have the `fmt_scaled' function. */
/* #undef HAVE_FMT_SCALED */

/* Define to 1 if you have the `freeaddrinfo' function. */
/* #undef HAVE_FREEADDRINFO */

/* Define to 1 if the system has the type `fsblkcnt_t'. */
/* #undef HAVE_FSBLKCNT_T */

/* Define to 1 if the system has the type `fsfilcnt_t'. */
/* #undef HAVE_FSFILCNT_T */

/* Define to 1 if you have the `fstatvfs' function. */
#define HAVE_FSTATVFS 1

/* Define to 1 if you have the `futimes' function. */
/* #undef HAVE_FUTIMES */

/* Define to 1 if you have the `gai_strerror' function. */
/* #undef HAVE_GAI_STRERROR */

/* Define to 1 if you have the `getaddrinfo' function. */
/* #undef HAVE_GETADDRINFO */

/* Define to 1 if you have the `getaudit' function. */
/* #undef HAVE_GETAUDIT */

/* Define to 1 if you have the `getaudit_addr' function. */
/* #undef HAVE_GETAUDIT_ADDR */

/* Define to 1 if you have the `getcwd' function. */
#define HAVE_GETCWD 1

/* Define to 1 if you have the `getgrouplist' function. */
/* #undef HAVE_GETGROUPLIST */

/* Define to 1 if you have the `getgrset' function. */
/* #undef HAVE_GETGRSET */

/* Define to 1 if you have the `getlastlogxbyname' function. */
/* #undef HAVE_GETLASTLOGXBYNAME */

/* Define to 1 if you have the `getluid' function. */
/* #undef HAVE_GETLUID */

/* Define to 1 if you have the `getnameinfo' function. */
/* #undef HAVE_GETNAMEINFO */

/* Define to 1 if you have the `getopt' function. */
#define HAVE_GETOPT 1

/* Define to 1 if you have the <getopt.h> header file. */
#define HAVE_GETOPT_H 1

/* Define if your getopt(3) defines and uses optreset */
/* #undef HAVE_GETOPT_OPTRESET */

/* Define if your libraries define getpagesize() */
/* #undef HAVE_GETPAGESIZE */

/* Define to 1 if you have the `getpeereid' function. */
/* #undef HAVE_GETPEEREID */

/* Define to 1 if you have the `getpeerucred' function. */
/* #undef HAVE_GETPEERUCRED */

/* Define to 1 if you have the `getpwanam' function. */
/* #undef HAVE_GETPWANAM */

/* Define to 1 if you have the `getrlimit' function. */
/* #undef HAVE_GETRLIMIT */

/* Define if getrrsetbyname() exists */
/* #undef HAVE_GETRRSETBYNAME */

/* Define to 1 if you have the `getrusage' function. */
/* #undef HAVE_GETRUSAGE */

/* Define to 1 if you have the `getseuserbyname' function. */
/* #undef HAVE_GETSEUSERBYNAME */

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the `getttyent' function. */
/* #undef HAVE_GETTTYENT */

/* Define to 1 if you have the `getutent' function. */
/* #undef HAVE_GETUTENT */

/* Define to 1 if you have the `getutid' function. */
/* #undef HAVE_GETUTID */

/* Define to 1 if you have the `getutline' function. */
/* #undef HAVE_GETUTLINE */

/* Define to 1 if you have the `getutxent' function. */
/* #undef HAVE_GETUTXENT */

/* Define to 1 if you have the `getutxid' function. */
/* #undef HAVE_GETUTXID */

/* Define to 1 if you have the `getutxline' function. */
/* #undef HAVE_GETUTXLINE */

/* Define to 1 if you have the `getutxuser' function. */
/* #undef HAVE_GETUTXUSER */

/* Define to 1 if you have the `get_default_context_with_level' function. */
/* #undef HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL */

/* Define to 1 if you have the `glob' function. */
/* #undef HAVE_GLOB */

/* Define to 1 if you have the <glob.h> header file. */
#define HAVE_GLOB_H 1

/* Define to 1 if you have the `group_from_gid' function. */
/* #undef HAVE_GROUP_FROM_GID */

/* Define to 1 if you have the <gssapi_generic.h> header file. */
/* #undef HAVE_GSSAPI_GENERIC_H */

/* Define to 1 if you have the <gssapi/gssapi_generic.h> header file. */
#define HAVE_GSSAPI_GSSAPI_GENERIC_H 1

/* Define to 1 if you have the <gssapi/gssapi.h> header file. */
#define HAVE_GSSAPI_GSSAPI_H 1

/* Define to 1 if you have the <gssapi/gssapi_krb5.h> header file. */
#define HAVE_GSSAPI_GSSAPI_KRB5_H 1

/* Define to 1 if you have the <gssapi.h> header file. */
/* #undef HAVE_GSSAPI_H */

/* Define to 1 if you have the <gssapi_krb5.h> header file. */
/* #undef HAVE_GSSAPI_KRB5_H */

/* Define if HEADER.ad exists in arpa/nameser.h */
/* #undef HAVE_HEADER_AD */

/* Define if you have ut_host in utmp.h */
/* #undef HAVE_HOST_IN_UTMP */

/* Define if you have ut_host in utmpx.h */
/* #undef HAVE_HOST_IN_UTMPX */

/* Define to 1 if you have the <iaf.h> header file. */
/* #undef HAVE_IAF_H */

/* Define to 1 if you have the <ia.h> header file. */
/* #undef HAVE_IA_H */

/* Define if you have ut_id in utmp.h */
/* #undef HAVE_ID_IN_UTMP */

/* Define if you have ut_id in utmpx.h */
/* #undef HAVE_ID_IN_UTMPX */

/* Define to 1 if you have the `inet_aton' function. */
/* #undef HAVE_INET_ATON */

/* Define to 1 if you have the `inet_ntoa' function. */
/* #undef HAVE_INET_NTOA */

/* Define to 1 if you have the `inet_ntop' function. */
#define HAVE_INET_NTOP 1

/* Define to 1 if you have the `innetgr' function. */
/* #undef HAVE_INNETGR */

/* define if you have int64_t data type */
#define HAVE_INT64_T 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* define if you have intxx_t data type */
#define HAVE_INTXX_T 1

/* Define to 1 if the system has the type `in_addr_t'. */
/* #undef HAVE_IN_ADDR_T */

/* Define to 1 if the system has the type `in_port_t'. */
/* #undef HAVE_IN_PORT_T */

/* Define if you have isblank(3C). */
#define HAVE_ISBLANK 1

/* Define to 1 if you have the <lastlog.h> header file. */
/* #undef HAVE_LASTLOG_H */

/* Define to 1 if you have the <libaudit.h> header file. */
/* #undef HAVE_LIBAUDIT_H */

/* Define to 1 if you have the `bsm' library (-lbsm). */
/* #undef HAVE_LIBBSM */

/* Define to 1 if you have the `crypt' library (-lcrypt). */
/* #undef HAVE_LIBCRYPT */

/* Define to 1 if you have the `dl' library (-ldl). */
/* #undef HAVE_LIBDL */

/* Define to 1 if you have the <libgen.h> header file. */
#define HAVE_LIBGEN_H 1

/* Define if system has libiaf that supports set_id */
/* #undef HAVE_LIBIAF */

/* Define to 1 if you have the `network' library (-lnetwork). */
/* #undef HAVE_LIBNETWORK */

/* Define to 1 if you have the `nsl' library (-lnsl). */
/* #undef HAVE_LIBNSL */

/* Define to 1 if you have the `pam' library (-lpam). */
/* #undef HAVE_LIBPAM */

/* Define to 1 if you have the `socket' library (-lsocket). */
/* #undef HAVE_LIBSOCKET */

/* Define to 1 if you have the <libutil.h> header file. */
/* #undef HAVE_LIBUTIL_H */

/* Define to 1 if you have the `xnet' library (-lxnet). */
/* #undef HAVE_LIBXNET */

/* Define to 1 if you have the `z' library (-lz). */
#define HAVE_LIBZ 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the <linux/if_tun.h> header file. */
/* #undef HAVE_LINUX_IF_TUN_H */

/* Define if your libraries define login() */
/* #undef HAVE_LOGIN */

/* Define to 1 if you have the <login_cap.h> header file. */
/* #undef HAVE_LOGIN_CAP_H */

/* Define to 1 if you have the `login_getcapbool' function. */
/* #undef HAVE_LOGIN_GETCAPBOOL */

/* Define to 1 if you have the <login.h> header file. */
/* #undef HAVE_LOGIN_H */

/* Define to 1 if you have the `logout' function. */
/* #undef HAVE_LOGOUT */

/* Define to 1 if you have the `logwtmp' function. */
/* #undef HAVE_LOGWTMP */

/* Define to 1 if the system has the type `long double'. */
#define HAVE_LONG_DOUBLE 1

/* Define to 1 if the system has the type `long long'. */
#define HAVE_LONG_LONG 1

/* Define to 1 if you have the <maillock.h> header file. */
/* #undef HAVE_MAILLOCK_H */

/* Define to 1 if you have the `md5_crypt' function. */
/* #undef HAVE_MD5_CRYPT */

/* Define if you want to allow MD5 passwords */
/* #undef HAVE_MD5_PASSWORDS */

/* Define to 1 if you have the `memmove' function. */
#define HAVE_MEMMOVE 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `mkdtemp' function. */
/* #undef HAVE_MKDTEMP */

/* Define to 1 if you have the `mmap' function. */
/* #undef HAVE_MMAP */

/* define if you have mode_t data type */
#define HAVE_MODE_T 1

/* Some systems put nanosleep outside of libc */
/* #undef HAVE_NANOSLEEP */

/* Define to 1 if you have the <ndir.h> header file. */
/* #undef HAVE_NDIR_H */

/* Define to 1 if you have the <netdb.h> header file. */
/* #undef HAVE_NETDB_H */

/* Define to 1 if you have the <netgroup.h> header file. */
/* #undef HAVE_NETGROUP_H */

/* Define to 1 if you have the <net/if_tun.h> header file. */
/* #undef HAVE_NET_IF_TUN_H */

/* Define if you are on NeXT */
/* #undef HAVE_NEXT */

/* Define to 1 if you have the `ngetaddrinfo' function. */
/* #undef HAVE_NGETADDRINFO */

/* Define to 1 if you have the `nsleep' function. */
/* #undef HAVE_NSLEEP */

/* Define to 1 if you have the `ogetaddrinfo' function. */
/* #undef HAVE_OGETADDRINFO */

/* Define if you have an old version of PAM
 which takes only one argument to
   pam_strerror */
/* #undef HAVE_OLD_PAM */

/* Define to 1 if you have the `openlog_r' function. */
/* #undef HAVE_OPENLOG_R */

/* Define to 1 if you have the `openpty' function. */
/* #undef HAVE_OPENPTY */

/* Define if your ssl headers are included
 with #include <openssl/header.h>
   */
#define HAVE_OPENSSL 1

/* Define if you have Digital Unix Security
 Integration Architecture */
/* #undef HAVE_OSF_SIA */

/* Define to 1 if you have the `pam_getenvlist' function. */
/* #undef HAVE_PAM_GETENVLIST */

/* Define to 1 if you have the <pam/pam_appl.h> header file. */
/* #undef HAVE_PAM_PAM_APPL_H */

/* Define to 1 if you have the `pam_putenv' function. */
/* #undef HAVE_PAM_PUTENV */

/* Define to 1 if you have the <paths.h> header file. */
/* #undef HAVE_PATHS_H */

/* Define if you have ut_pid in utmp.h */
/* #undef HAVE_PID_IN_UTMP */

/* define if you have pid_t data type */
#define HAVE_PID_T 1

/* Define to 1 if you have the `poll' function. */
/* #undef HAVE_POLL */

/* Define to 1 if you have the <poll.h> header file. */
#define HAVE_POLL_H 1

/* Define to 1 if you have the `prctl' function. */
/* #undef HAVE_PRCTL */

/* Define to 1 if you have priveleged-port concept */
/* #undef HAVE_PRIV_CONCEPT */

/* Define if you have /proc/$pid/fd */
#define HAVE_PROC_PID 1

/* Define to 1 if you have the `pstat' function. */
/* #undef HAVE_PSTAT */

/* Define to 1 if you have the <pty.h> header file. */
/* #undef HAVE_PTY_H */

/* Define to 1 if you have the `pututline' function. */
/* #undef HAVE_PUTUTLINE */

/* Define to 1 if you have the `pututxline' function. */
/* #undef HAVE_PUTUTXLINE */

/* Define if your password has a pw_change field */
/* #undef HAVE_PW_CHANGE_IN_PASSWD */

/* Define if your password has a pw_class field */
/* #undef HAVE_PW_CLASS_IN_PASSWD */

/* Define if your password has a pw_expire field */
/* #undef HAVE_PW_EXPIRE_IN_PASSWD */

/* Define to 1 if you have the `readpassphrase' function. */
/* #undef HAVE_READPASSPHRASE */

/* Define to 1 if you have the <readpassphrase.h> header file. */
/* #undef HAVE_READPASSPHRASE_H */

/* Define to 1 if you have the `realpath' function. */
/* #define HAVE_REALPATH 1 */

/* Define to 1 if you have the `recvmsg' function. */
/* #undef HAVE_RECVMSG */

/* sys/resource.h has RLIMIT_NPROC */
/* #undef HAVE_RLIMIT_NPROC */

/* Define to 1 if you have the <rpc/types.h> header file. */
/* #undef HAVE_RPC_TYPES_H */

/* Define to 1 if you have the `rresvport_af' function. */
/* #undef HAVE_RRESVPORT_AF */

/* Define to 1 if you have the `RSA_generate_key_ex' function. */
#define HAVE_RSA_GENERATE_KEY_EX 1

/* Define to 1 if you have the `RSA_get_default_method' function. */
#define HAVE_RSA_GET_DEFAULT_METHOD 1

/* Define to 1 if you have the <sandbox.h> header file. */
/* #undef HAVE_SANDBOX_H */

/* Define to 1 if you have the `sandbox_init' function. */
/* #undef HAVE_SANDBOX_INIT */

/* define if you have sa_family_t data type */
/* #undef HAVE_SA_FAMILY_T */

/* Define if you have SecureWare-based
 protected password database */
/* #undef HAVE_SECUREWARE */

/* Define to 1 if you have the <security/pam_appl.h> header file. */
/* #undef HAVE_SECURITY_PAM_APPL_H */

/* Define to 1 if you have the `sendmsg' function. */
/* #undef HAVE_SENDMSG */

/* Define to 1 if you have the `setauthdb' function. */
/* #undef HAVE_SETAUTHDB */

/* Define to 1 if you have the `setdtablesize' function. */
/* #undef HAVE_SETDTABLESIZE */

/* Define to 1 if you have the `setegid' function. */
/* #undef HAVE_SETEGID */

/* Define to 1 if you have the `setenv' function. */
/* #undef HAVE_SETENV */

/* Define to 1 if you have the `seteuid' function. */
/* #undef HAVE_SETEUID */

/* Define to 1 if you have the `setgroupent' function. */
/* #undef HAVE_SETGROUPENT */

/* Define to 1 if you have the `setgroups' function. */
/* #undef HAVE_SETGROUPS */

/* Define to 1 if you have the `setlogin' function. */
/* #undef HAVE_SETLOGIN */

/* Define to 1 if you have the `setluid' function. */
/* #undef HAVE_SETLUID */

/* Define to 1 if you have the `setpcred' function. */
/* #undef HAVE_SETPCRED */

/* Define to 1 if you have the `setproctitle' function. */
/* #undef HAVE_SETPROCTITLE */

/* Define to 1 if you have the `setregid' function. */
/* #undef HAVE_SETREGID */

/* Define to 1 if you have the `setresgid' function. */
/* #undef HAVE_SETRESGID */

/* Define to 1 if you have the `setresuid' function. */
/* #undef HAVE_SETRESUID */

/* Define to 1 if you have the `setreuid' function. */
/* #undef HAVE_SETREUID */

/* Define to 1 if you have the `setrlimit' function. */
/* #undef HAVE_SETRLIMIT */

/* Define to 1 if you have the `setsid' function. */
#define HAVE_SETSID 1

/* Define to 1 if you have the `setutent' function. */
/* #undef HAVE_SETUTENT */

/* Define to 1 if you have the `setutxdb' function. */
/* #undef HAVE_SETUTXDB */

/* Define to 1 if you have the `setutxent' function. */
/* #undef HAVE_SETUTXENT */

/* Define to 1 if you have the `setvbuf' function. */
#define HAVE_SETVBUF 1

/* Define to 1 if you have the `set_id' function. */
/* #undef HAVE_SET_ID */

/* Define to 1 if you have the `SHA256_Update' function. */
/* #undef HAVE_SHA256_UPDATE */

/* Define to 1 if you have the <sha2.h> header file. */
/* #undef HAVE_SHA2_H */

/* Define to 1 if you have the <shadow.h> header file. */
/* #undef HAVE_SHADOW_H */

/* Define to 1 if you have the `sigaction' function. */
/* #undef HAVE_SIGACTION */

/* Define to 1 if you have the `sigvec' function. */
/* #undef HAVE_SIGVEC */

/* Define to 1 if the system has the type `sig_atomic_t'. */
#define HAVE_SIG_ATOMIC_T 1

/* define if you have size_t data type */
#define HAVE_SIZE_T 1

/* Define to 1 if you have the `snprintf' function. */
#define HAVE_SNPRINTF 1

/* Define to 1 if you have the `socketpair' function. */
/* #undef HAVE_SOCKETPAIR */

/* Have PEERCRED socket option */
/* #undef HAVE_SO_PEERCRED */

/* define if you have ssize_t data type */
#define HAVE_SSIZE_T 1

/* Fields in struct sockaddr_storage */
#define HAVE_SS_FAMILY_IN_SS 1

/* Define to 1 if you have the `statfs' function. */
/* #undef HAVE_STATFS */

/* Define to 1 if you have the `statvfs' function. */
#define HAVE_STATVFS 1

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the `strftime' function. */
#define HAVE_STRFTIME 1

/* Silly mkstemp() */
/* #undef HAVE_STRICT_MKSTEMP */

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
/* #undef HAVE_STRLCAT */

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the `strmode' function. */
/* #undef HAVE_STRMODE */

/* Define to 1 if you have the `strnvis' function. */
/* #undef HAVE_STRNVIS */

/* Define to 1 if you have the `strptime' function. */
/* #undef HAVE_STRPTIME */

/* Define to 1 if you have the `strsep' function. */
/* #undef HAVE_STRSEP */

/* Define to 1 if you have the `strtoll' function. */
#define HAVE_STRTOLL 1

/* Define to 1 if you have the `strtonum' function. */
/* #undef HAVE_STRTONUM */

/* Define to 1 if you have the `strtoul' function. */
#define HAVE_STRTOUL 1

/* define if you have struct addrinfo data type */
#define HAVE_STRUCT_ADDRINFO 1

/* define if you have struct in6_addr data type */
/* #undef HAVE_STRUCT_IN6_ADDR */

/* define if you have struct sockaddr_in6 data type */
/* #undef HAVE_STRUCT_SOCKADDR_IN6 */

/* Define to 1 if `sin6_scope_id' is a member of `struct sockaddr_in6'. */
/* #undef HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID */

/* define if you have struct sockaddr_storage data type */
#define HAVE_STRUCT_SOCKADDR_STORAGE 1

/* Define to 1 if `st_blksize' is a member of `struct stat'. */
/* #undef HAVE_STRUCT_STAT_ST_BLKSIZE */

/* Define to 1 if the system has the type `struct timespec'. */
/* #undef HAVE_STRUCT_TIMESPEC */

/* define if you have struct timeval */
#define HAVE_STRUCT_TIMEVAL 1

/* Define to 1 if you have the `swap32' function. */
/* #undef HAVE_SWAP32 */

/* Define to 1 if you have the `sysconf' function. */
/* #undef HAVE_SYSCONF */

/* Define if you have syslen in utmpx.h */
/* #undef HAVE_SYSLEN_IN_UTMPX */

/* Define to 1 if you have the <sys/audit.h> header file. */
/* #undef HAVE_SYS_AUDIT_H */

/* Define to 1 if you have the <sys/bitypes.h> header file. */
/* #undef HAVE_SYS_BITYPES_H */

/* Define to 1 if you have the <sys/bsdtty.h> header file. */
/* #undef HAVE_SYS_BSDTTY_H */

/* Define to 1 if you have the <sys/cdefs.h> header file. */
/* #undef HAVE_SYS_CDEFS_H */

/* Define to 1 if you have the <sys/dir.h> header file. */
/* #undef HAVE_SYS_DIR_H */

/* Define if your system defines sys_errlist[] */
/* #undef HAVE_SYS_ERRLIST */

/* Define to 1 if you have the <sys/mman.h> header file. */
/* #undef HAVE_SYS_MMAN_H */

/* Define to 1 if you have the <sys/mount.h> header file. */
/* #undef HAVE_SYS_MOUNT_H */

/* Define to 1 if you have the <sys/ndir.h> header file. */
/* #undef HAVE_SYS_NDIR_H */

/* Define if your system defines sys_nerr */
/* #undef HAVE_SYS_NERR */

/* Define to 1 if you have the <sys/poll.h> header file. */
/* #undef HAVE_SYS_POLL_H */

/* Define to 1 if you have the <sys/prctl.h> header file. */
/* #undef HAVE_SYS_PRCTL_H */

/* Define to 1 if you have the <sys/pstat.h> header file. */
/* #undef HAVE_SYS_PSTAT_H */

/* Define to 1 if you have the <sys/ptms.h> header file. */
/* #undef HAVE_SYS_PTMS_H */

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/statvfs.h> header file. */
#define HAVE_SYS_STATVFS_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/stream.h> header file. */
/* #undef HAVE_SYS_STREAM_H */

/* Define to 1 if you have the <sys/stropts.h> header file. */
/* #undef HAVE_SYS_STROPTS_H */

/* Define to 1 if you have the <sys/strtio.h> header file. */
/* #undef HAVE_SYS_STRTIO_H */

/* Force use of sys/syslog.h on Ultrix */
/* #undef HAVE_SYS_SYSLOG_H */

/* Define to 1 if you have the <sys/sysmacros.h> header file. */
/* #undef HAVE_SYS_SYSMACROS_H */

/* Define to 1 if you have the <sys/timers.h> header file. */
/* #undef HAVE_SYS_TIMERS_H */

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H  1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/un.h> header file. */
#define HAVE_SYS_UN_H 1

/* Define to 1 if you have the `tcgetpgrp' function. */
/* #undef HAVE_TCGETPGRP */

/* Define to 1 if you have the `tcsendbreak' function. */
/* #undef HAVE_TCSENDBREAK */

/* Define to 1 if you have the `time' function. */
#define HAVE_TIME 1

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define if you have ut_time in utmp.h */
/* #undef HAVE_TIME_IN_UTMP */

/* Define if you have ut_time in utmpx.h */
/* #undef HAVE_TIME_IN_UTMPX */

/* Define to 1 if you have the `timingsafe_bcmp' function. */
/* #undef HAVE_TIMINGSAFE_BCMP */

/* Define to 1 if you have the <tmpdir.h> header file. */
/* #undef HAVE_TMPDIR_H */

/* Define to 1 if you have the `truncate' function. */
/* #undef HAVE_TRUNCATE */

/* Define to 1 if you have tty support */
/* #undef HAVE_TTY */

/* Define to 1 if you have the <ttyent.h> header file. */
/* #undef HAVE_TTYENT_H */

/* Define if you have ut_tv in utmp.h */
/* #undef HAVE_TV_IN_UTMP */

/* Define if you have ut_tv in utmpx.h */
/* #undef HAVE_TV_IN_UTMPX */

/* Define if you have ut_type in utmp.h */
/* #undef HAVE_TYPE_IN_UTMP */

/* Define if you have ut_type in utmpx.h */
/* #undef HAVE_TYPE_IN_UTMPX */

/* Define to 1 if you have the <ucred.h> header file. */
/* #undef HAVE_UCRED_H */

/* define if you have uintxx_t data type */
#define HAVE_UINTXX_T 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `unsetenv' function. */
/* #undef HAVE_UNSETENV */

/* Define to 1 if the system has the type `unsigned long long'. */
#define HAVE_UNSIGNED_LONG_LONG 1

/* Define to 1 if you have the `updwtmp' function. */
/* #undef HAVE_UPDWTMP */

/* Define to 1 if you have the `updwtmpx' function. */
/* #undef HAVE_UPDWTMPX */

/* Define to 1 if you have the <usersec.h> header file. */
/* #undef HAVE_USERSEC_H */

/* Define to 1 if you have the `user_from_uid' function. */
#define HAVE_USER_FROM_UID 1

/* Define to 1 if you have the <util.h> header file. */
/* #undef HAVE_UTIL_H */

/* Define to 1 if you have the `utimes' function. */
#define HAVE_UTIMES 1

/* Define to 1 if you have the <utime.h> header file. */
/* #undef HAVE_UTIME_H */

/* Define to 1 if you have the `utmpname' function. */
/* #undef HAVE_UTMPNAME */

/* Define to 1 if you have the `utmpxname' function. */
/* #undef HAVE_UTMPXNAME */

/* Define to 1 if you have the <utmpx.h> header file. */
/* #undef HAVE_UTMPX_H */

/* Define to 1 if you have the <utmp.h> header file. */
/* #undef HAVE_UTMP_H */

/* define if you have u_char data type */
/* #undef HAVE_U_CHAR */

/* define if you have u_int data type */
/* #undef HAVE_U_INT */

/* define if you have u_int64_t data type */
/* #undef HAVE_U_INT64_T */

/* define if you have u_intxx_t data type */
/* #undef HAVE_U_INTXX_T */

/* Define to 1 if you have the `vasprintf' function. */
/* #undef HAVE_VASPRINTF */

/* Define if va_copy exists */
#define HAVE_VA_COPY 1

/* Define to 1 if you have the `vhangup' function. */
/* #undef HAVE_VHANGUP */

/* Define to 1 if you have the <vis.h> header file. */
/* #undef HAVE_VIS_H */

/* Define to 1 if you have the `vsnprintf' function. */
#define HAVE_VSNPRINTF 1

/* Define to 1 if you have the `waitpid' function. */
#define HAVE_WAITPID 1

/* Define to 1 if you have the `_getlong' function. */
/* #undef HAVE__GETLONG */

/* Define to 1 if you have the `_getpty' function. */
/* #undef HAVE__GETPTY */

/* Define to 1 if you have the `_getshort' function. */
/* #undef HAVE__GETSHORT */

/* Define if you have struct __res_state _res as an extern */
#define HAVE__RES_EXTERN 1

/* Define to 1 if you have the `__b64_ntop' function. */
/* #undef HAVE___B64_NTOP */

/* Define to 1 if you have the `__b64_pton' function. */
/* #undef HAVE___B64_PTON */

/* Define if compiler implements __FUNCTION__ */
#define HAVE___FUNCTION__ 1

/* Define if libc defines __progname */
/* #undef HAVE___PROGNAME */

/* Fields in struct sockaddr_storage */
/* #undef HAVE___SS_FAMILY_IN_SS */

/* Define if __va_copy exists */
#define HAVE___VA_COPY 1

/* Define if compiler implements __func__ */
#define HAVE___func__ 1

/* Define this if you are using the Heimdal
 version of Kerberos V5 */
/* #undef HEIMDAL */

/* Define if you need to use IP address
 instead of hostname in $DISPLAY */
/* #undef IPADDR_IN_DISPLAY */

/* Detect IPv4 in IPv6 mapped addresses
 and treat as IPv4 */
/* #undef IPV4_IN_IPV6 */

/* Define if your system choked on IP TOS setting */
#define IP_TOS_IS_BROKEN 1

/* Define if you want Kerberos 5 support */
/* #undef KRB5 */

/* Define if pututxline updates lastlog too */
/* #undef LASTLOG_WRITE_PUTUTXLINE */

/* Define if you want
 TCP Wrappers support */
/* #undef LIBWRAP */

/* Define to whatever link() returns for "not supported"
 if it doesn't return
   EOPNOTSUPP. */
/* #undef LINK_OPNOTSUPP_ERRNO */

/* Adjust Linux out-of-memory killer */
/* #undef LINUX_OOM_ADJUST */

/* max value of long long calculated by configure */
/* #undef LLONG_MAX */

/* min value of long long calculated by configure */
/* #undef LLONG_MIN */

/* Account locked with pw(1) */
/* #undef LOCKED_PASSWD_PREFIX */

/* String used in /etc/passwd to denote locked account */
/* #undef LOCKED_PASSWD_STRING */

/* String used in /etc/passwd to denote locked account */
/* #undef LOCKED_PASSWD_SUBSTR */

/* Some versions of /bin/login need the TERM supplied
 on the commandline */
/* #undef LOGIN_NEEDS_TERM */

/* Some systems need a utmpx entry for /bin/login to work */
/* #undef LOGIN_NEEDS_UTMPX */

/* Define if your login program cannot handle end of options ("--") */
/* #undef LOGIN_NO_ENDOPT */

/* If your header files don't define LOGIN_PROGRAM,
 then use this (detected)
   from environment and PATH */
#define LOGIN_PROGRAM_FALLBACK "/usr/bin/login"

/* Set this to your mail directory if you do not have _PATH_MAILDIR */
#define MAIL_DIRECTORY "/var/spool/mail"

/* Define on *nto-qnx systems */
/* #undef MISSING_FD_MASK */

/* Define on *nto-qnx systems */
/* #undef MISSING_HOWMANY */

/* Define on *nto-qnx systems */
/* #undef MISSING_NFDBITS */

/* Need setpgrp to acquire controlling tty */
/* #undef NEED_SETPGRP */

/* Define if the concept of ports only accessible to
 superusers isn't known
   */
#define NO_IPPORT_RESERVED_CONCEPT 1

/* Define if you don't want to use lastlog in session.c */
/* #undef NO_SSH_LASTLOG */

/* Define if X11 doesn't support AF_UNIX sockets on that system */
#define NO_X11_UNIX_SOCKETS 1

/* Define if EVP_DigestUpdate returns void */
/* #undef OPENSSL_EVP_DIGESTUPDATE_VOID */

/* libcrypto includes complete ECC support */
#define OPENSSL_HAS_ECC 1
#define OPENSSL_HAS_NISTP521 1

/* libcrypto is missing AES 192 and 256 bit functions */
/* #undef OPENSSL_LOBOTOMISED_AES */

/* Define if you want OpenSSL's internally seeded PRNG only */
#define OPENSSL_PRNG_ONLY 1

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "openssh-unix-dev@mindrot.org"

/* Define to the full name of this package. */
#define PACKAGE_NAME "OpenSSH"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "OpenSSH Portable"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "openssh"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "Portable"

/* Define if you are using Solaris-derived PAM which
 passes pam_messages to
   the conversation function
 with an extra level of indirection */
/* #undef PAM_SUN_CODEBASE */

/* Work around problematic Linux PAM modules handling of PAM_TTY */
/* #undef PAM_TTY_KLUDGE */

/* must supply username to passwd */
/* #undef PASSWD_NEEDS_USERNAME */

/* Port number of PRNGD/EGD random number socket */
/* #undef PRNGD_PORT */

/* Location of PRNGD/EGD random number socket */
/* #undef PRNGD_SOCKET */

/* read(1) can return 0 for a non-closed fd */
/* #undef PTY_ZEROREAD */

/* Sandbox using Darwin sandbox_init(3) */
/* #undef SANDBOX_DARWIN */

/* no privsep sandboxing */
#define SANDBOX_NULL 1

/* Sandbox using setrlimit(2) */
/* #undef SANDBOX_RLIMIT */

/* Sandbox using systrace(4) */
/* #undef SANDBOX_SYSTRACE */

/* Define if your platform breaks doing a seteuid before a setuid */
/* #undef SETEUID_BREAKS_SETUID */

/* The size of `char', as computed by sizeof. */
#define SIZEOF_CHAR 1

/* The size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of `long int', as computed by sizeof. */
#define SIZEOF_LONG_INT 4

/* The size of `long long int', as computed by sizeof. */
#define SIZEOF_LONG_LONG_INT 8

/* The size of `short int', as computed by sizeof. */
#define SIZEOF_SHORT_INT 2

/* Define if you want S/Key support */
/* #undef SKEY */

/* Define if your skeychallenge()
 function takes 4 arguments (NetBSD) */
/* #undef SKEYCHALLENGE_4ARG */

/* Define as const if snprintf() can declare const char *fmt */
#define SNPRINTF_CONST const

/* Define to a Set Process Title type if your system is
 supported by
   bsd-setproctitle.c */
/* #undef SPT_TYPE */

/* Define if sshd somehow reacquires a controlling TTY
 after setsid() */
/* #undef SSHD_ACQUIRES_CTTY */

/* Define if pam_chauthtok wants real uid set
 to the unpriv'ed user */
/* #undef SSHPAM_CHAUTHTOK_NEEDS_RUID */

/* Use audit debugging module */
/* #undef SSH_AUDIT_EVENTS */

/* Windows is sensitive to read buffer size */
/* #undef SSH_IOBUFSZ */

/* non-privileged user for privilege separation */
#define SSH_PRIVSEP_USER "sshd"

/* Use tunnel device compatibility to OpenBSD */
/* #undef SSH_TUN_COMPAT_AF */

/* Open tunnel devices the FreeBSD way */
/* #undef SSH_TUN_FREEBSD */

/* Open tunnel devices the Linux tun/tap way */
/* #undef SSH_TUN_LINUX */

/* No layer 2 tunnel support */
/* #undef SSH_TUN_NO_L2 */

/* Open tunnel devices the OpenBSD way */
/* #undef SSH_TUN_OPENBSD */

/* Prepend the address family to IP tunnel traffic */
/* #undef SSH_TUN_PREPEND_AF */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define if you want a different $PATH
 for the superuser */
/* #undef SUPERUSER_PATH */

/* syslog_r function is safe to use in in a signal handler */
/* #undef SYSLOG_R_SAFE_IN_SIGHAND */

/* Support passwords > 8 chars */
/* #undef UNIXWARE_LONG_PASSWORDS */

/* Specify default $PATH */
#define USER_PATH "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin"

/* Define this if you want to use libkafs' AFS support */
/* #undef USE_AFS */

/* Use BSM audit module */
/* #undef USE_BSM_AUDIT */

/* Use btmp to log bad logins */
/* #undef USE_BTMP */

/* Use libedit for sftp */
/* #undef USE_LIBEDIT */

/* Use Linux audit module */
/* #undef USE_LINUX_AUDIT */

/* Enable OpenSSL engine support */
/* #undef USE_OPENSSL_ENGINE */

/* Define if you want to enable PAM support */
/* #undef USE_PAM */

/* Use PIPES instead of a socketpair() */
#define USE_PIPES 1

/* Define if you want to sanitize fds */
/* #undef USE_SANITISE_STDFD */

/* Define if you have Solaris process contracts */
/* #undef USE_SOLARIS_PROCESS_CONTRACTS */

/* Define if you have Solaris projects */
/* #undef USE_SOLARIS_PROJECTS */

/* Define if you shouldn't strip 'tty' from your
 ttyname in [uw]tmp */
/* #undef WITH_ABBREV_NO_TTY */

/* Define if you want to enable AIX4's authenticate function */
/* #undef WITH_AIXAUTHENTICATE */

/* Define if you have/want arrays
 (cluster-wide session managment, not C
   arrays) */
/* #undef WITH_IRIX_ARRAY */

/* Define if you want IRIX audit trails */
/* #undef WITH_IRIX_AUDIT */

/* Define if you want IRIX kernel jobs */
/* #undef WITH_IRIX_JOBS */

/* Define if you want IRIX project management */
/* #undef WITH_IRIX_PROJECT */

/* Define if you want SELinux support. */
/* #undef WITH_SELINUX */

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Define if xauth is found in your path */
/* #undef XAUTH_PATH */

/* Enable large inode numbers on Mac OS X 10.5.  */
#ifndef _DARWIN_USE_64_BIT_INODE
# define _DARWIN_USE_64_BIT_INODE 1
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* log for bad login attempts */
/* #undef _PATH_BTMP */

/* Full path of your "passwd" program */
#define _PATH_PASSWD_PROG "/usr/bin/passwd"

/* Specify location of ssh.pid */
/* #undef _PATH_SSH_PIDDIR */

/* Define if we don't have struct __res_state in resolv.h */
#define __res_state state

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* type to use in place of socklen_t if not defined */
/* #undef socklen_t */
#define WIN32_LEAN_AND_MEAN 1
#define WINDOWS 1

#define BROKEN_READV_COMPARISON

/* Override detection of some headers and functions on MinGW */
#undef BROKEN_SNPRINTF
#define GETPGRP_VOID 1
#undef HAVE_CRYPT_H
#define HAVE_DAEMON 1
#undef HAVE_ENDIAN_H
#undef HAVE_FCNTL_H
#define HAVE_FREEADDRINFO 1
#define HAVE_GAI_STRERROR 1
#define HAVE_GETADDRINFO 1
#define HAVE_GETGROUPLIST 1
#define HAVE_GETNAMEINFO 1
#undef HAVE_ID_IN_UTMPX
#define HAVE_INET_ATON 1
#define HAVE_INET_NTOA 1
#define HAVE_INNETGR 1
#undef HAVE_LIBCRYPT
#define HAVE_NANOSLEEP 1
#undef HAVE_PATHS_H
#undef HAVE_PROC_PID
#undef HAVE_PTY_H
#define HAVE_NANOSLEEP 1
#define HAVE_READPASSPHRASE 1
#undef HAVE_SIG_ATOMIC_T
#define HAVE_SIZE_T 1
#undef HAVE_STRERROR
#define HAVE_STRMODE 1
#undef __USE_W32_SOCKETS

#ifdef __MINGW32__ /* FIXME: Use autoconf to set this correctly */
/* Define to 1 if you have the `strcasecmp' function. */
#define HAVE_STRCASECMP 1

/* Define to 1 if you have the `strncasecmp' function. */
#define HAVE_STRNCASECMP 1
#endif

/* Define to 1 if you have the locale.h header. */
#define HAVE_LOCALE_H 1

#define HAVE_STRUCT_IN6_ADDR 1
#define HAVE_STRUCT_SOCKADDR_IN6 1
#define HAVE_STRUCT_TIMEVAL 1
#undef HAVE_SYS_CDEFS_H
#undef HAVE_SYS_SYSMACROS_H
#undef HAVE_SYS_MMAN_H
#define _STRUCT_WINSIZE 1

#define HAVE_TCGETPGRP 1

#undef HAVE_TIME

#define HAVE_VIS_H 1

#define MISSING_FD_MASK 1
#define MISSING_HOWMANY 1
#define MISSING_NFDBITS 1

#undef SSH_PRIVSEP_USER

#define HAVE_OPENPTY 1

/* Fixes for loginrec.c */
#undef CONF_UTMP_FILE
#undef CONF_WTMPX_FILE
#undef CONF_WTMP_FILE
#undef CONF_UTMPX_FILE
#undef CONF_LASTLOG_FILE

#define BROKEN_SYS_TERMIO_H


#define WITH_OPENSSL 1
#define HAVE_DECL_NFDBITS 0
#define HAVE_DECL_HOWMANY 0
#define HAVE_STRTOULL 1
#define HAVE_USLEEP 1
#define HAVE_EVP_RIPEMD160 1

#if defined ( WIN32 )
#define __func__ __FUNCTION__
#endif

/* Windows specific macro added to workaround mysignal implementaion in bsd-misc.c */
#define HAVE_MYSIGNAL 1


#define PATH_MAX MAX_PATH
#define S_IFIFO        0x1000  
#define HAVE_EXPLICIT_BZERO
#define HAVE_MBTOWC 1
#define HAVE_LLABS 1

#include <signal.h>
#include <io.h>

#define __attribute__(A)

/* disable inclusion of compatability definitions in CRT headers */
#define __STDC__ 1

#define umac128_new umac_new
#define umac128_update umac_update 
#define umac_final umac128_final
#define umac_delete umac128_delete

#define HAVE_MBLEN 1

#define _PATH_PRIVSEP_CHROOT_DIR "."
#define SSHDIR "__PROGRAMDATA__\\ssh"
#define _PATH_SSH_PIDDIR SSHDIR
#define _PATH_SFTP_SERVER "sftp-server.exe"
#define _PATH_SSH_PROGRAM "ssh.exe"
#define _PATH_LS			"dir"
#define FORK_NOT_SUPPORTED 1