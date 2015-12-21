/* $OpenBSD: ssh.c,v 1.420 2015/07/30 00:01:34 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Ssh client program.  This program can be used to log into a remote machine.
 * The software supports strong authentication, encryption, and forwarding
 * of X11, TCP/IP, and authentication connections.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 1999 Niels Provos.  All rights reserved.
 * Copyright (c) 2000, 2001, 2002, 2003 Markus Friedl.  All rights reserved.
 *
 * Modified to work with SSL by Niels Provos <provos@citi.umich.edu>
 * in Canada (German citizen).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#include "includes.h"

#include <sys/types.h>
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef WITH_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>
#endif
#include "openbsd-compat/openssl-compat.h"
#include "openbsd-compat/sys-queue.h"

#include "xmalloc.h"
#include "ssh.h"
#include "ssh1.h"
#include "ssh2.h"
#include "canohost.h"
#include "compat.h"
#include "cipher.h"
#include "digest.h"
#include "packet.h"
#include "buffer.h"
#include "channels.h"
#include "key.h"
#include "authfd.h"
#include "authfile.h"
#include "pathnames.h"
#include "dispatch.h"
#include "clientloop.h"
#include "log.h"
#include "misc.h"
#include "readconf.h"
#include "sshconnect.h"
#include "kex.h"
#include "mac.h"
#include "sshpty.h"
#include "match.h"
#include "msg.h"
#include "uidswap.h"
#include "roaming.h"
#include "version.h"
#include "ssherr.h"
#include "myproposal.h"

#ifdef ENABLE_PKCS11
#include "ssh-pkcs11.h"
#endif

#ifdef WIN32_FIXME

  #include <sys/stat.h>
  #define isatty(a) WSHELPisatty(a)
  #define mkdir(a, b) _mkdir(a)

  extern HANDLE proxy_command_handle;
  extern DWORD proxy_command_pid;
  
  extern int PassInputFd;
  extern int PassOutputFd;

  char dotsshdir[MAX_PATH];

#endif /* WIN32_FIXME */

extern char *__progname;

/* Saves a copy of argv for setproctitle emulation */
#ifndef HAVE_SETPROCTITLE
static char **saved_av;
#endif

/* Flag indicating whether debug mode is on.  May be set on the command line. */
int debug_flag = 0;

/* Flag indicating whether a tty should be requested */
int tty_flag = 0;

/* don't exec a shell */
int no_shell_flag = 0;

/*
 * Flag indicating that nothing should be read from stdin.  This can be set
 * on the command line.
 */
int stdin_null_flag = 0;

/*
 * Flag indicating that the current process should be backgrounded and
 * a new slave launched in the foreground for ControlPersist.
 */
int need_controlpersist_detach = 0;

/* Copies of flags for ControlPersist foreground slave */
int ostdin_null_flag, ono_shell_flag, otty_flag, orequest_tty;

/*
 * Flag indicating that ssh should fork after authentication.  This is useful
 * so that the passphrase can be entered manually, and then ssh goes to the
 * background.
 */
int fork_after_authentication_flag = 0;

/* forward stdio to remote host and port */
char *stdio_forward_host = NULL;
int stdio_forward_port = 0;

/*
 * General data structure for command line options and options configurable
 * in configuration files.  See readconf.h.
 */
Options options;

/* optional user configfile */
char *config = NULL;

/*
 * Name of the host we are connecting to.  This is the name given on the
 * command line, or the HostName specified for the user-supplied name in a
 * configuration file.
 */
char *host;

/* socket address the host resolves to */
struct sockaddr_storage hostaddr;

/* Private host keys. */
Sensitive sensitive_data;

/* Original real UID. */
uid_t original_real_uid;
uid_t original_effective_uid;

/* command to be executed */
Buffer command;

/* Should we execute a command or invoke a subsystem? */
int subsystem_flag = 0;

/* # of replies received for global requests */
static int remote_forward_confirms_received = 0;

/* mux.c */
extern int muxserver_sock;
extern u_int muxclient_command;

/* Prints a help message to the user.  This function never returns. */

static void
usage(void)
{
	fprintf(stderr,
"usage: ssh [-1246AaCfGgKkMNnqsTtVvXxYy] [-b bind_address] [-c cipher_spec]\n"
"           [-D [bind_address:]port] [-E log_file] [-e escape_char]\n"
"           [-F configfile] [-I pkcs11] [-i identity_file]\n"
"           [-L address] [-l login_name] [-m mac_spec]\n"
"           [-O ctl_cmd] [-o option] [-p port]\n"
"           [-Q cipher | cipher-auth | mac | kex | key]\n"
"           [-R address] [-S ctl_path] [-W host:port]\n"
"           [-w local_tun[:remote_tun]] [user@]hostname [command]\n"
	);
	exit(255);
}

static int ssh_session(void);
static int ssh_session2(void);
static void load_public_identity_files(void);
static void main_sigchld_handler(int);

/* from muxclient.c */
void muxclient(const char *);
void muxserver_listen(void);

/* ~/ expand a list of paths. NB. assumes path[n] is heap-allocated. */
static void
tilde_expand_paths(char **paths, u_int num_paths)
{
	u_int i;
	char *cp;

	for (i = 0; i < num_paths; i++) {
		cp = tilde_expand_filename(paths[i], original_real_uid);
		free(paths[i]);
		paths[i] = cp;
	}
}

#ifdef WIN32_FIXME

/*
 * This function send CTRL_BREAK_EVENT (equivalent of SIGINT) to
 * child proxy process.
 *
 * If process still alive terminates it.
 */

static void CleanUpProxyProcess()
{
  if (proxy_command_handle)
  {
    if (GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, proxy_command_pid) == FALSE)
    {
      debug("ERROR. Cannot send exit signal to childs (%u).", 
                (unsigned int) GetLastError());
    }

    /*
     * Try wait up to 100 ms until proxy process finished.
     */

    if (WaitForSingleObject(proxy_command_handle, 100) == WAIT_TIMEOUT)
    {
      /*
       * If still not closed, kill proxy process.
       */
    
      if (TerminateProcess(proxy_command_handle, 1) == TRUE)
      {
        debug("Process %u terminated.", (unsigned int) proxy_command_pid);
      }
      else
      {
        debug("ERROR. Cannot terminate proxy process (pid = %u).", 
                  (unsigned int) proxy_command_pid);
      }
    }

    CloseHandle(proxy_command_handle);
  }
}

extern Buffer stdin_buffer;	/* Buffer for stdin data. */
/*
 * This function handles exit signal.
 */

BOOL WINAPI CtrlHandlerRoutine(DWORD dwCtrlType)
{

  switch( dwCtrlType ) 
  { 
    // Handle the CTRL-C signal. 
    case CTRL_C_EVENT: 
	  // send CTRL_C code to the remote app via sshd server
      //buffer_put_char(&stdin_buffer, 0x3); // control-c is decimal 3
      //Beep( 750, 300 ); 
      //return( TRUE ); // we have handled it. FALSE would be go to next handler

    case CTRL_BREAK_EVENT: 
 	  // send CTRL_BREAK to the remote side ?
	  //return TRUE;

    case CTRL_CLOSE_EVENT: 
    case CTRL_LOGOFF_EVENT: 
    case CTRL_SHUTDOWN_EVENT: 
	  // send SHELL_CODE_TERMINATE to the remote side
	  //return FALSE ; // go to next handler

	default:
	   break;
      //return FALSE;
  }
  
  debug("Exit signal received...");

  CleanUpProxyProcess();
  
  UninitMitKerberos();
  
  cleanup_exit(0);
  
  return TRUE;

}

#endif /* WIN32_FIXME */


/*
 * Attempt to resolve a host name / port to a set of addresses and
 * optionally return any CNAMEs encountered along the way.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
static struct addrinfo *
resolve_host(const char *name, int port, int logerr, char *cname, size_t clen)
{
	char strport[NI_MAXSERV];
	struct addrinfo hints, *res;
	int gaierr, loglevel = SYSLOG_LEVEL_DEBUG1;

	if (port <= 0)
		port = default_ssh_port();

	snprintf(strport, sizeof strport, "%u", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	if (cname != NULL)
		hints.ai_flags = AI_CANONNAME;
	if ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		if (logerr || (gaierr != EAI_NONAME && gaierr != EAI_NODATA))
			loglevel = SYSLOG_LEVEL_ERROR;
		do_log2(loglevel, "%s: Could not resolve hostname %.100s: %s",
		    __progname, name, ssh_gai_strerror(gaierr));
		return NULL;
	}
	if (cname != NULL && res->ai_canonname != NULL) {
		if (strlcpy(cname, res->ai_canonname, clen) >= clen) {
			error("%s: host \"%s\" cname \"%s\" too long (max %lu)",
			    __func__, name,  res->ai_canonname, (u_long)clen);
			if (clen > 0)
				*cname = '\0';
		}
	}
	return res;
}

/*
 * Attempt to resolve a numeric host address / port to a single address.
 * Returns a canonical address string.
 * Returns NULL on failure.
 * NB. this function must operate with a options having undefined members.
 */
static struct addrinfo *
resolve_addr(const char *name, int port, char *caddr, size_t clen)
{
	char addr[NI_MAXHOST], strport[NI_MAXSERV];
	struct addrinfo hints, *res;
	int gaierr;

	if (port <= 0)
		port = default_ssh_port();
	snprintf(strport, sizeof strport, "%u", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = options.address_family == -1 ?
	    AF_UNSPEC : options.address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	if ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
		debug2("%s: could not resolve name %.100s as address: %s",
		    __func__, name, ssh_gai_strerror(gaierr));
		return NULL;
	}
	if (res == NULL) {
		debug("%s: getaddrinfo %.100s returned no addresses",
		 __func__, name);
		return NULL;
	}
	if (res->ai_next != NULL) {
		debug("%s: getaddrinfo %.100s returned multiple addresses",
		    __func__, name);
		goto fail;
	}
	if ((gaierr = getnameinfo(res->ai_addr, res->ai_addrlen,
	    addr, sizeof(addr), NULL, 0, NI_NUMERICHOST)) != 0) {
		debug("%s: Could not format address for name %.100s: %s",
		    __func__, name, ssh_gai_strerror(gaierr));
		goto fail;
	}
	if (strlcpy(caddr, addr, clen) >= clen) {
		error("%s: host \"%s\" addr \"%s\" too long (max %lu)",
		    __func__, name,  addr, (u_long)clen);
		if (clen > 0)
			*caddr = '\0';
 fail:
		freeaddrinfo(res);
		return NULL;
	}
	return res;
}

/*
 * Check whether the cname is a permitted replacement for the hostname
 * and perform the replacement if it is.
 * NB. this function must operate with a options having undefined members.
 */
static int
check_follow_cname(char **namep, const char *cname)
{
	int i;
	struct allowed_cname *rule;

	if (*cname == '\0' || options.num_permitted_cnames == 0 ||
	    strcmp(*namep, cname) == 0)
		return 0;
	if (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		return 0;
	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy unless the user specifically requests so.
	 */
	if (!option_clear_or_none(options.proxy_command) &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		return 0;
	debug3("%s: check \"%s\" CNAME \"%s\"", __func__, *namep, cname);
	for (i = 0; i < options.num_permitted_cnames; i++) {
		rule = options.permitted_cnames + i;
		if (match_pattern_list(*namep, rule->source_list, 1) != 1 ||
		    match_pattern_list(cname, rule->target_list, 1) != 1)
			continue;
		verbose("Canonicalized DNS aliased hostname "
		    "\"%s\" => \"%s\"", *namep, cname);
		free(*namep);
		*namep = xstrdup(cname);
		return 1;
	}
	return 0;
}

/*
 * Attempt to resolve the supplied hostname after applying the user's
 * canonicalization rules. Returns the address list for the host or NULL
 * if no name was found after canonicalization.
 * NB. this function must operate with a options having undefined members.
 */
static struct addrinfo *
resolve_canonicalize(char **hostp, int port)
{
	int i, ndots;
	char *cp, *fullhost, newname[NI_MAXHOST];
	struct addrinfo *addrs;

	if (options.canonicalize_hostname == SSH_CANONICALISE_NO)
		return NULL;

	/*
	 * Don't attempt to canonicalize names that will be interpreted by
	 * a proxy unless the user specifically requests so.
	 */
	if (!option_clear_or_none(options.proxy_command) &&
	    options.canonicalize_hostname != SSH_CANONICALISE_ALWAYS)
		return NULL;

	/* Try numeric hostnames first */
	if ((addrs = resolve_addr(*hostp, port,
	    newname, sizeof(newname))) != NULL) {
		debug2("%s: hostname %.100s is address", __func__, *hostp);
		if (strcasecmp(*hostp, newname) != 0) {
			debug2("%s: canonicalised address \"%s\" => \"%s\"",
			    __func__, *hostp, newname);
			free(*hostp);
			*hostp = xstrdup(newname);
		}
		return addrs;
	}

	/* Don't apply canonicalization to sufficiently-qualified hostnames */
	ndots = 0;
	for (cp = *hostp; *cp != '\0'; cp++) {
		if (*cp == '.')
			ndots++;
	}
	if (ndots > options.canonicalize_max_dots) {
		debug3("%s: not canonicalizing hostname \"%s\" (max dots %d)",
		    __func__, *hostp, options.canonicalize_max_dots);
		return NULL;
	}
	/* Attempt each supplied suffix */
	for (i = 0; i < options.num_canonical_domains; i++) {
		*newname = '\0';
		xasprintf(&fullhost, "%s.%s.", *hostp,
		    options.canonical_domains[i]);
		debug3("%s: attempting \"%s\" => \"%s\"", __func__,
		    *hostp, fullhost);
		if ((addrs = resolve_host(fullhost, port, 0,
		    newname, sizeof(newname))) == NULL) {
			free(fullhost);
			continue;
		}
		/* Remove trailing '.' */
		fullhost[strlen(fullhost) - 1] = '\0';
		/* Follow CNAME if requested */
		if (!check_follow_cname(&fullhost, newname)) {
			debug("Canonicalized hostname \"%s\" => \"%s\"",
			    *hostp, fullhost);
		}
		free(*hostp);
		*hostp = fullhost;
		return addrs;
	}
	if (!options.canonicalize_fallback_local)
		fatal("%s: Could not resolve host \"%s\"", __progname, *hostp);
	debug2("%s: host %s not found in any suffix", __func__, *hostp);
	return NULL;
}

/*
 * Read per-user configuration file.  Ignore the system wide config
 * file if the user specifies a config file on the command line.
 */
static void
process_config_files(const char *host_arg, struct passwd *pw, int post_canon)
{
	char buf[PATH_MAX];
	int r;

	if (config != NULL) {
		if (strcasecmp(config, "none") != 0 &&
		    !read_config_file(config, pw, host, host_arg, &options,
		    SSHCONF_USERCONF | (post_canon ? SSHCONF_POSTCANON : 0)))
			fatal("Can't open user config file %.100s: "
			    "%.100s", config, strerror(errno));
	} else {
		r = snprintf(buf, sizeof buf, "%s/%s", pw->pw_dir,
		    _PATH_SSH_USER_CONFFILE);
		if (r > 0 && (size_t)r < sizeof(buf))
			(void)read_config_file(buf, pw, host, host_arg,
			    &options, SSHCONF_CHECKPERM | SSHCONF_USERCONF |
			    (post_canon ? SSHCONF_POSTCANON : 0));

		/* Read systemwide configuration file after user config. */
		(void)read_config_file(_PATH_HOST_CONFIG_FILE, pw,
		    host, host_arg, &options,
		    post_canon ? SSHCONF_POSTCANON : 0);
	}
}

/* Rewrite the port number in an addrinfo list of addresses */
static void
set_addrinfo_port(struct addrinfo *addrs, int port)
{
	struct addrinfo *addr;

	for (addr = addrs; addr != NULL; addr = addr->ai_next) {
		switch (addr->ai_family) {
		case AF_INET:
			((struct sockaddr_in *)addr->ai_addr)->
			    sin_port = htons(port);
			break;
		case AF_INET6:
			((struct sockaddr_in6 *)addr->ai_addr)->
			    sin6_port = htons(port);
			break;
		}
	}
}

/*
 * Main program for the ssh client.
 */

int
main(int ac, char **av)
{
	int i, r, opt, exit_status, use_syslog, config_test = 0;
	char *p, *cp, *line, *argv0, buf[PATH_MAX], *host_arg, *logfile;
	char thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	char cname[NI_MAXHOST];
	struct stat st;
	struct passwd *pw;

	int timeout_ms;
	extern int optind, optreset;
	extern char *optarg;
	struct Forward fwd;
	struct addrinfo *addrs = NULL;
	struct ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_LENGTH];
	char *conn_hash_hex;
	
  #ifdef WIN32_FIXME
  
    /*
     * Setup exit signal handler for receiving signal, when 
     * parent server is stopped.
     */

    SetConsoleCtrlHandler(CtrlHandlerRoutine, TRUE);

    /*
     * Initialize wrapped stdio.
     */

    WSHELPinitialize();
   
    allocate_standard_descriptor(STDIN_FILENO);
    allocate_standard_descriptor(STDOUT_FILENO);
    allocate_standard_descriptor(STDERR_FILENO);
    
  #endif

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(av[0]);

#ifndef HAVE_SETPROCTITLE
	/* Prepare for later setproctitle emulation */
	/* Save argv so it isn't clobbered by setproctitle() emulation */
	saved_av = xcalloc(ac + 1, sizeof(*saved_av));
	for (i = 0; i < ac; i++)
		saved_av[i] = xstrdup(av[i]);
	saved_av[i] = NULL;
	compat_init_setproctitle(ac, av);
	av = saved_av;
#endif

	/*
	 * Discard other fds that are hanging around. These can cause problem
	 * with backgrounded ssh processes started by ControlPersist.
	 */
	closefrom(STDERR_FILENO + 1);

	/*
	 * Save the original real uid.  It will be needed later (uid-swapping
	 * may clobber the real uid).
	 */
	original_real_uid = getuid();
	original_effective_uid = geteuid();

	/*
	 * Use uid-swapping to give up root privileges for the duration of
	 * option processing.  We will re-instantiate the rights when we are
	 * ready to create the privileged port, and will permanently drop
	 * them when the port has been created (actually, when the connection
	 * has been made, as we may need to create the port several times).
	 */
	PRIV_END;

#ifdef HAVE_SETRLIMIT
	/* If we are installed setuid root be careful to not drop core. */
	if (original_real_uid != original_effective_uid) {
		struct rlimit rlim;
		rlim.rlim_cur = rlim.rlim_max = 0;
		if (setrlimit(RLIMIT_CORE, &rlim) < 0)
			fatal("setrlimit failed: %.100s", strerror(errno));
	}
#endif
	/* Get user data. */
	pw = getpwuid(original_real_uid);
	if (!pw) {
		logit("No user exists for uid %lu", (u_long)original_real_uid);
		exit(255);
	}
	/* Take a copy of the returned structure. */
	pw = pwcopy(pw);

	/*
	 * Set our umask to something reasonable, as some files are created
	 * with the default umask.  This will make them world-readable but
	 * writable only by the owner, which is ok for all files for which we
	 * don't set the modes explicitly.
	 */
	umask(022);

	/*
	 * Initialize option structure to indicate that no values have been
	 * set.
	 */
	initialize_options(&options);

	/* Parse command-line arguments. */
	host = NULL;
	use_syslog = 0;
	logfile = NULL;
	argv0 = av[0];

 again:
	while ((opt = getopt(ac, av, "1246ab:c:e:fgi:kl:m:no:p:qstvx"
	    "ACD:E:F:GI:KL:MNO:PQ:R:S:TVw:W:XYy")) != -1) {
		switch (opt) {
		case '1':
			options.protocol = SSH_PROTO_1;
			break;
		case '2':
			options.protocol = SSH_PROTO_2;
			break;
		case '4':
			options.address_family = AF_INET;
			break;
		case '6':
			options.address_family = AF_INET6;
			break;
		case 'n':
			stdin_null_flag = 1;
			break;
		case 'f':
			fork_after_authentication_flag = 1;
			stdin_null_flag = 1;
			break;
		case 'x':
			options.forward_x11 = 0;
			break;
		case 'X':
			options.forward_x11 = 1;
			break;
		case 'y':
			use_syslog = 1;
			break;
		case 'E':
			logfile = xstrdup(optarg);
			break;
		case 'G':
			config_test = 1;
			break;
		case 'Y':
			options.forward_x11 = 1;
			options.forward_x11_trusted = 1;
			break;
		case 'g':
			options.fwd_opts.gateway_ports = 1;
			break;
		case 'O':
			if (stdio_forward_host != NULL)
				fatal("Cannot specify multiplexing "
				    "command with -W");
			else if (muxclient_command != 0)
				fatal("Multiplexing command already specified");
			if (strcmp(optarg, "check") == 0)
				muxclient_command = SSHMUX_COMMAND_ALIVE_CHECK;
			else if (strcmp(optarg, "forward") == 0)
				muxclient_command = SSHMUX_COMMAND_FORWARD;
			else if (strcmp(optarg, "exit") == 0)
				muxclient_command = SSHMUX_COMMAND_TERMINATE;
			else if (strcmp(optarg, "stop") == 0)
				muxclient_command = SSHMUX_COMMAND_STOP;
			else if (strcmp(optarg, "cancel") == 0)
				muxclient_command = SSHMUX_COMMAND_CANCEL_FWD;
			else
				fatal("Invalid multiplex command.");
			break;
		case 'P':	/* deprecated */
			options.use_privileged_port = 0;
			break;
		case 'Q':
			cp = NULL;
			if (strcmp(optarg, "cipher") == 0)
				cp = cipher_alg_list('\n', 0);
			else if (strcmp(optarg, "cipher-auth") == 0)
				cp = cipher_alg_list('\n', 1);
			else if (strcmp(optarg, "mac") == 0)
				cp = mac_alg_list('\n');
			else if (strcmp(optarg, "kex") == 0)
				cp = kex_alg_list('\n');
			else if (strcmp(optarg, "key") == 0)
				cp = key_alg_list(0, 0);
			else if (strcmp(optarg, "key-cert") == 0)
				cp = key_alg_list(1, 0);
			else if (strcmp(optarg, "key-plain") == 0)
				cp = key_alg_list(0, 1);
			else if (strcmp(optarg, "protocol-version") == 0) {
#ifdef WITH_SSH1
				cp = xstrdup("1\n2");
#else
				cp = xstrdup("2");
#endif
			}
			if (cp == NULL)
				fatal("Unsupported query \"%s\"", optarg);
			printf("%s\n", cp);
			free(cp);
			exit(0);
			break;
		case 'a':
			options.forward_agent = 0;
			break;
		case 'A':
			options.forward_agent = 1;
			break;
		case 'k':
			options.gss_deleg_creds = 0;
			break;
		case 'K':
			options.gss_authentication = 1;
			options.gss_deleg_creds = 1;
			break;
		case 'i':
			if (stat(optarg, &st) < 0) {
				fprintf(stderr, "Warning: Identity file %s "
				    "not accessible: %s.\n", optarg,
				    strerror(errno));
				break;
			}
#ifdef WIN32_FIXME
			add_identity_file(&options, NULL, optarg, 1, pw);
#else
			add_identity_file(&options, NULL, optarg, 1);
#endif
			break;
		case 'I':
#ifdef ENABLE_PKCS11
			options.pkcs11_provider = xstrdup(optarg);
#else
			fprintf(stderr, "no support for PKCS#11.\n");
#endif
			break;
		case 't':
			if (options.request_tty == REQUEST_TTY_YES)
				options.request_tty = REQUEST_TTY_FORCE;
			else
				options.request_tty = REQUEST_TTY_YES;
			break;
		case 'v':
			if (debug_flag == 0) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} else {
				if (options.log_level < SYSLOG_LEVEL_DEBUG3)
					options.log_level++;
			}
			break;
		case 'V':
			#ifndef WIN32_FIXME
			fprintf(stderr, "%s, %s\n",
			    SSH_RELEASE,
			#else
			fprintf(stderr, "%s %s, %s\n",
			    SSH_RELEASE, __DATE__ ,
			#endif
#ifdef WITH_OPENSSL
			    SSLeay_version(SSLEAY_VERSION)
#else
			    "without OpenSSL"
#endif
			);
			if (opt == 'V')
				exit(0);
			break;
		case 'w':
			if (options.tun_open == -1)
				options.tun_open = SSH_TUNMODE_DEFAULT;
			options.tun_local = a2tun(optarg, &options.tun_remote);
			if (options.tun_local == SSH_TUNID_ERR) {
				fprintf(stderr,
				    "Bad tun device '%s'\n", optarg);
				exit(255);
			}
			break;
		case 'W':
			if (stdio_forward_host != NULL)
				fatal("stdio forward already specified");
			if (muxclient_command != 0)
				fatal("Cannot specify stdio forward with -O");
			if (parse_forward(&fwd, optarg, 1, 0)) {
				stdio_forward_host = fwd.listen_host;
				stdio_forward_port = fwd.listen_port;
				free(fwd.connect_host);
			} else {
				fprintf(stderr,
				    "Bad stdio forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			options.request_tty = REQUEST_TTY_NO;
			no_shell_flag = 1;
			options.clear_forwardings = 1;
			options.exit_on_forward_failure = 1;
			break;
		case 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			break;
		case 'e':
			if (optarg[0] == '^' && optarg[2] == 0 &&
			    (u_char) optarg[1] >= 64 &&
			    (u_char) optarg[1] < 128)
				options.escape_char = (u_char) optarg[1] & 31;
			else if (strlen(optarg) == 1)
				options.escape_char = (u_char) optarg[0];
			else if (strcmp(optarg, "none") == 0)
				options.escape_char = SSH_ESCAPECHAR_NONE;
			else {
				fprintf(stderr, "Bad escape character '%s'.\n",
				    optarg);
				exit(255);
			}
			break;
		case 'c':
			if (ciphers_valid(*optarg == '+' ?
			    optarg + 1 : optarg)) {
				/* SSH2 only */
				options.ciphers = xstrdup(optarg);
				options.cipher = SSH_CIPHER_INVALID;
				break;
			}
			/* SSH1 only */
			options.cipher = cipher_number(optarg);
			if (options.cipher == -1) {
				fprintf(stderr, "Unknown cipher type '%s'\n",
				    optarg);
				exit(255);
			}
			if (options.cipher == SSH_CIPHER_3DES)
				options.ciphers = xstrdup("3des-cbc");
			else if (options.cipher == SSH_CIPHER_BLOWFISH)
				options.ciphers = xstrdup("blowfish-cbc");
			else
				options.ciphers = xstrdup(KEX_CLIENT_ENCRYPT);
			break;
		case 'm':
			if (mac_valid(optarg))
				options.macs = xstrdup(optarg);
			else {
				fprintf(stderr, "Unknown mac type '%s'\n",
				    optarg);
				exit(255);
			}
			break;
		case 'M':
			if (options.control_master == SSHCTL_MASTER_YES)
				options.control_master = SSHCTL_MASTER_ASK;
			else
				options.control_master = SSHCTL_MASTER_YES;
			break;
		case 'p':
			options.port = a2port(optarg);
			if (options.port <= 0) {
				fprintf(stderr, "Bad port '%s'\n", optarg);
				exit(255);
			}
			break;
		case 'l':
			options.user = optarg;
			break;

		case 'L':
			if (parse_forward(&fwd, optarg, 0, 0))
				add_local_forward(&options, &fwd);
			else {
				fprintf(stderr,
				    "Bad local forwarding specification '%s'\n",
				    optarg);
				exit(255);
			}
			break;

		case 'R':
			if (parse_forward(&fwd, optarg, 0, 1)) {
				add_remote_forward(&options, &fwd);
			} else {
				fprintf(stderr,
				    "Bad remote forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			break;

		case 'D':
			if (parse_forward(&fwd, optarg, 1, 0)) {
				add_local_forward(&options, &fwd);
			} else {
				fprintf(stderr,
				    "Bad dynamic forwarding specification "
				    "'%s'\n", optarg);
				exit(255);
			}
			break;

		case 'C':
			options.compression = 1;
			break;
		case 'N':
			no_shell_flag = 1;
			options.request_tty = REQUEST_TTY_NO;
			break;
		case 'T':
			options.request_tty = REQUEST_TTY_NO;
			break;
		case 'o':
			line = xstrdup(optarg);
			if (process_config_line(&options, pw,
			    host ? host : "", host ? host : "", line,
			    "command-line", 0, NULL, SSHCONF_USERCONF) != 0)
				exit(255);
			free(line);
			break;
		case 's':
			subsystem_flag = 1;
			break;
		case 'S':
			if (options.control_path != NULL)
				free(options.control_path);
			options.control_path = xstrdup(optarg);
			break;
		case 'b':
			options.bind_address = optarg;
			break;
		case 'F':
			config = optarg;
			break;
		default:
			usage();
		}
	}

	ac -= optind;
	av += optind;

	if (ac > 0 && !host) {
		if (strrchr(*av, '@')) {
			p = xstrdup(*av);
			cp = strrchr(p, '@');
			if (cp == NULL || cp == p)
				usage();
			options.user = p;
			*cp = '\0';
			host = xstrdup(++cp);
		} else
			host = xstrdup(*av);
		if (ac > 1) {
			optind = optreset = 1;
			goto again;
		}
		ac--, av++;
	}
  #ifdef WIN32_FIXME
  
    /*
     * Redirect stdin/stdout for password read. This trick allow
     * use of all auth procedures from ssh client in sftp without
     * additional code in parent.
     */
     
    if (options.passInputHandle_)
    {
      debug3("Redirecting pass input to %d...\n", options.passInputHandle_);
    
      PassInputFd = _open_osfhandle(options.passInputHandle_, O_RDONLY);
    }

    if (options.passOutputHandle_)
    { 
      debug3("Redirecting pass prompt output to %d...\n", options.passOutputHandle_);
    
      PassOutputFd = _open_osfhandle(options.passOutputHandle_, O_WRONLY);
    }

 	// create various Windows user home directory based file names
    sprintf(dotsshdir,"%s\\%s", pw->pw_dir, _PATH_SSH_USER_DIR );
    _mkdir(dotsshdir); //this base directory for the user is needed

  #endif

	/* Check that we got a host name. */
	if (!host)
		usage();

	host_arg = xstrdup(host);

#ifdef WITH_OPENSSL
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
#endif

	/* Initialize the command to execute on remote host. */
	buffer_init(&command);

	/*
	 * Save the command to execute on the remote host in a buffer. There
	 * is no limit on the length of the command, except by the maximum
	 * packet size.  Also sets the tty flag if there is no command.
	 */
	if (!ac) {
		/* No command specified - execute shell on a tty. */
		if (subsystem_flag) {
			fprintf(stderr,
			    "You must specify a subsystem to invoke.\n");
			usage();
		}
	} else {
		/* A command has been specified.  Store it into the buffer. */
		for (i = 0; i < ac; i++) {
			if (i)
				buffer_append(&command, " ", 1);
			buffer_append(&command, av[i], strlen(av[i]));
		}
	}

	/* Cannot fork to background if no command. */
	if (fork_after_authentication_flag && buffer_len(&command) == 0 &&
	    !no_shell_flag)
		fatal("Cannot fork into background without a command "
		    "to execute.");

	/*
	 * Initialize "log" output.  Since we are the client all output
	 * goes to stderr unless otherwise specified by -y or -E.
	 */
	if (use_syslog && logfile != NULL)
		fatal("Can't specify both -y and -E");
	if (logfile != NULL) {
		log_redirect_stderr_to(logfile);
		free(logfile);
	}
	log_init(argv0,
	    options.log_level == -1 ? SYSLOG_LEVEL_INFO : options.log_level,
	    SYSLOG_FACILITY_USER, !use_syslog);

	if (debug_flag)
		logit("%s, %s", SSH_RELEASE,
#ifdef WITH_OPENSSL
		    SSLeay_version(SSLEAY_VERSION)
#else
		    "without OpenSSL"
#endif
		);

	/* Parse the configuration files */
	process_config_files(host_arg, pw, 0);

	/* Hostname canonicalisation needs a few options filled. */
	fill_default_options_for_canonicalization(&options);

	/* If the user has replaced the hostname then take it into use now */
	if (options.hostname != NULL) {
		/* NB. Please keep in sync with readconf.c:match_cfg_line() */
		cp = percent_expand(options.hostname,
		    "h", host, (char *)NULL);
		free(host);
		host = cp;
		free(options.hostname);
		options.hostname = xstrdup(host);
	}

	/* If canonicalization requested then try to apply it */
	lowercase(host);
	if (options.canonicalize_hostname != SSH_CANONICALISE_NO)
		addrs = resolve_canonicalize(&host, options.port);

	/*
	 * If CanonicalizePermittedCNAMEs have been specified but
	 * other canonicalization did not happen (by not being requested
	 * or by failing with fallback) then the hostname may still be changed
	 * as a result of CNAME following. 
	 *
	 * Try to resolve the bare hostname name using the system resolver's
	 * usual search rules and then apply the CNAME follow rules.
	 *
	 * Skip the lookup if a ProxyCommand is being used unless the user
	 * has specifically requested canonicalisation for this case via
	 * CanonicalizeHostname=always
	 */
	if (addrs == NULL && options.num_permitted_cnames != 0 &&
	    (option_clear_or_none(options.proxy_command) ||
            options.canonicalize_hostname == SSH_CANONICALISE_ALWAYS)) {
		if ((addrs = resolve_host(host, options.port,
		    option_clear_or_none(options.proxy_command),
		    cname, sizeof(cname))) == NULL) {
			/* Don't fatal proxied host names not in the DNS */
			if (option_clear_or_none(options.proxy_command))
				cleanup_exit(255); /* logged in resolve_host */
		} else
			check_follow_cname(&host, cname);
	}

	/*
	 * If canonicalisation is enabled then re-parse the configuration
	 * files as new stanzas may match.
	 */
	if (options.canonicalize_hostname != 0) {
		debug("Re-reading configuration after hostname "
		    "canonicalisation");
		free(options.hostname);
		options.hostname = xstrdup(host);
		process_config_files(host_arg, pw, 1);
		/*
		 * Address resolution happens early with canonicalisation
		 * enabled and the port number may have changed since, so
		 * reset it in address list
		 */
		if (addrs != NULL && options.port > 0)
			set_addrinfo_port(addrs, options.port);
	}

	/* Fill configuration defaults. */
	#ifndef WIN32_FIXME
	fill_default_options(&options);
	#else
	fill_default_options(&options, pw);
	#endif

	if (options.port == 0)
		options.port = default_ssh_port();
	channel_set_af(options.address_family);

	/* Tidy and check options */
	if (options.host_key_alias != NULL)
		lowercase(options.host_key_alias);
	if (options.proxy_command != NULL &&
	    strcmp(options.proxy_command, "-") == 0 &&
	    options.proxy_use_fdpass)
		fatal("ProxyCommand=- and ProxyUseFDPass are incompatible");
	if (options.control_persist &&
	    options.update_hostkeys == SSH_UPDATE_HOSTKEYS_ASK) {
		debug("UpdateHostKeys=ask is incompatible with ControlPersist; "
		    "disabling");
		options.update_hostkeys = 0;
	}
#ifndef HAVE_CYGWIN
	if (original_effective_uid != 0)
		options.use_privileged_port = 0;
#endif

	/* reinit */
	log_init(argv0, options.log_level, SYSLOG_FACILITY_USER, !use_syslog);

	if (options.request_tty == REQUEST_TTY_YES ||
	    options.request_tty == REQUEST_TTY_FORCE)
		tty_flag = 1;

	/* Allocate a tty by default if no command specified. */
	if (buffer_len(&command) == 0)
		tty_flag = options.request_tty != REQUEST_TTY_NO;

	/* Force no tty */
	if (options.request_tty == REQUEST_TTY_NO || muxclient_command != 0)
		tty_flag = 0;
	/* Do not allocate a tty if stdin is not a tty. */
	if ((!isatty(fileno(stdin)) || stdin_null_flag) &&
	    options.request_tty != REQUEST_TTY_FORCE) {
		if (tty_flag)
			logit("Pseudo-terminal will not be allocated because "
			    "stdin is not a terminal.");
		tty_flag = 0;
	}

	seed_rng();

	if (options.user == NULL)
		options.user = xstrdup(pw->pw_name);

	if (gethostname(thishost, sizeof(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	strlcpy(shorthost, thishost, sizeof(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, sizeof(portstr), "%d", options.port);

	if ((md = ssh_digest_start(SSH_DIGEST_SHA1)) == NULL ||
	    ssh_digest_update(md, thishost, strlen(thishost)) < 0 ||
	    ssh_digest_update(md, host, strlen(host)) < 0 ||
	    ssh_digest_update(md, portstr, strlen(portstr)) < 0 ||
	    ssh_digest_update(md, options.user, strlen(options.user)) < 0 ||
	    ssh_digest_final(md, conn_hash, sizeof(conn_hash)) < 0)
		fatal("%s: mux digest failed", __func__);
	ssh_digest_free(md);
	conn_hash_hex = tohex(conn_hash, ssh_digest_bytes(SSH_DIGEST_SHA1));

	if (options.local_command != NULL) {
		debug3("expanding LocalCommand: %s", options.local_command);
		cp = options.local_command;
		options.local_command = percent_expand(cp,
		    "C", conn_hash_hex,
		    "L", shorthost,
		    "d", pw->pw_dir,
		    "h", host,
		    "l", thishost,
		    "n", host_arg,
		    "p", portstr,
		    "r", options.user,
		    "u", pw->pw_name,
		    (char *)NULL);
		debug3("expanded LocalCommand: %s", options.local_command);
		free(cp);
	}

	if (options.control_path != NULL) {
		cp = tilde_expand_filename(options.control_path,
		    original_real_uid);
		free(options.control_path);
		options.control_path = percent_expand(cp,
		    "C", conn_hash_hex,
		    "L", shorthost,
		    "h", host,
		    "l", thishost,
		    "n", host_arg,
		    "p", portstr,
		    "r", options.user,
		    "u", pw->pw_name,
		    (char *)NULL);
		free(cp);
	}
	free(conn_hash_hex);

	if (config_test) {
		dump_client_config(&options, host);
		exit(0);
	}

	if (muxclient_command != 0 && options.control_path == NULL)
		fatal("No ControlPath specified for \"-O\" command");
	if (options.control_path != NULL)
		muxclient(options.control_path);

	/*
	 * If hostname canonicalisation was not enabled, then we may not
	 * have yet resolved the hostname. Do so now.
	 */
	if (addrs == NULL && options.proxy_command == NULL) {
		if ((addrs = resolve_host(host, options.port, 1,
		    cname, sizeof(cname))) == NULL)
			cleanup_exit(255); /* resolve_host logs the error */
	}

	timeout_ms = options.connection_timeout * 1000;

	/* Open a connection to the remote host. */
	if (ssh_connect(host, addrs, &hostaddr, options.port,
	    options.address_family, options.connection_attempts,
	    &timeout_ms, options.tcp_keep_alive,
	    options.use_privileged_port) != 0)
 		exit(255);

	if (addrs != NULL)
		freeaddrinfo(addrs);

	packet_set_timeout(options.server_alive_interval,
	    options.server_alive_count_max);

	if (timeout_ms > 0)
		debug3("timeout: %d ms remain after connect", timeout_ms);

	/*
	 * If we successfully made the connection, load the host private key
	 * in case we will need it later for combined rsa-rhosts
	 * authentication. This must be done before releasing extra
	 * privileges, because the file is only readable by root.
	 * If we cannot access the private keys, load the public keys
	 * instead and try to execute the ssh-keysign helper instead.
	 */
	sensitive_data.nkeys = 0;
	sensitive_data.keys = NULL;
	sensitive_data.external_keysign = 0;
	if (options.rhosts_rsa_authentication ||
	    options.hostbased_authentication) {
		sensitive_data.nkeys = 9;
		sensitive_data.keys = xcalloc(sensitive_data.nkeys,
		    sizeof(Key));
		for (i = 0; i < sensitive_data.nkeys; i++)
			sensitive_data.keys[i] = NULL;

		PRIV_START;
		sensitive_data.keys[0] = key_load_private_type(KEY_RSA1,
		    _PATH_HOST_KEY_FILE, "", NULL, NULL);
#ifdef OPENSSL_HAS_ECC
		sensitive_data.keys[1] = key_load_private_cert(KEY_ECDSA,
		    _PATH_HOST_ECDSA_KEY_FILE, "", NULL);
#endif
		sensitive_data.keys[2] = key_load_private_cert(KEY_ED25519,
		    _PATH_HOST_ED25519_KEY_FILE, "", NULL);
		sensitive_data.keys[3] = key_load_private_cert(KEY_RSA,
		    _PATH_HOST_RSA_KEY_FILE, "", NULL);
		sensitive_data.keys[4] = key_load_private_cert(KEY_DSA,
		    _PATH_HOST_DSA_KEY_FILE, "", NULL);
#ifdef OPENSSL_HAS_ECC
		sensitive_data.keys[5] = key_load_private_type(KEY_ECDSA,
		    _PATH_HOST_ECDSA_KEY_FILE, "", NULL, NULL);
#endif
		sensitive_data.keys[6] = key_load_private_type(KEY_ED25519,
		    _PATH_HOST_ED25519_KEY_FILE, "", NULL, NULL);
		sensitive_data.keys[7] = key_load_private_type(KEY_RSA,
		    _PATH_HOST_RSA_KEY_FILE, "", NULL, NULL);
		sensitive_data.keys[8] = key_load_private_type(KEY_DSA,
		    _PATH_HOST_DSA_KEY_FILE, "", NULL, NULL);
		PRIV_END;

		if (options.hostbased_authentication == 1 &&
		    sensitive_data.keys[0] == NULL &&
		    sensitive_data.keys[5] == NULL &&
		    sensitive_data.keys[6] == NULL &&
		    sensitive_data.keys[7] == NULL &&
		    sensitive_data.keys[8] == NULL) {
#ifdef OPENSSL_HAS_ECC
			sensitive_data.keys[1] = key_load_cert(
			    _PATH_HOST_ECDSA_KEY_FILE);
#endif
			sensitive_data.keys[2] = key_load_cert(
			    _PATH_HOST_ED25519_KEY_FILE);
			sensitive_data.keys[3] = key_load_cert(
			    _PATH_HOST_RSA_KEY_FILE);
			sensitive_data.keys[4] = key_load_cert(
			    _PATH_HOST_DSA_KEY_FILE);
#ifdef OPENSSL_HAS_ECC
			sensitive_data.keys[5] = key_load_public(
			    _PATH_HOST_ECDSA_KEY_FILE, NULL);
#endif
			sensitive_data.keys[6] = key_load_public(
			    _PATH_HOST_ED25519_KEY_FILE, NULL);
			sensitive_data.keys[7] = key_load_public(
			    _PATH_HOST_RSA_KEY_FILE, NULL);
			sensitive_data.keys[8] = key_load_public(
			    _PATH_HOST_DSA_KEY_FILE, NULL);
			sensitive_data.external_keysign = 1;
		}
	}
	/*
	 * Get rid of any extra privileges that we may have.  We will no
	 * longer need them.  Also, extra privileges could make it very hard
	 * to read identity files and other non-world-readable files from the
	 * user's home directory if it happens to be on a NFS volume where
	 * root is mapped to nobody.
	 */
	if (original_effective_uid == 0) {
		PRIV_START;
		permanently_set_uid(pw);
	}

	/*
	 * Now that we are back to our own permissions, create ~/.ssh
	 * directory if it doesn't already exist.
	 */
	if (config == NULL) {
#ifdef WIN32_FIXME
  r = snprintf(buf, sizeof(buf), "%ls%s%s", pw -> pw_dir,
                   wcscmp(pw -> pw_dir, L"/") ? "/" : "", 
                       _PATH_SSH_USER_DIR);
#else
	r = snprintf(buf, sizeof buf, "%s%s%s", pw->pw_dir,
		    strcmp(pw->pw_dir, "/") ? "/" : "", _PATH_SSH_USER_DIR);
#endif

		if (r > 0 && (size_t)r < sizeof(buf) && stat(buf, &st) < 0) {
#ifdef WITH_SELINUX
			ssh_selinux_setfscreatecon(buf);
#endif
			if (mkdir(buf, 0700) < 0)
				error("Could not create directory '%.200s'.",
				    buf);
#ifdef WITH_SELINUX
			ssh_selinux_setfscreatecon(NULL);
#endif
		}
	}
#ifdef WIN32_FIXME
  SetFileAttributes(buf, FILE_ATTRIBUTE_HIDDEN);
#endif
	/* load options.identity_files */
	load_public_identity_files();

	/* Expand ~ in known host file names. */
	tilde_expand_paths(options.system_hostfiles,
	    options.num_system_hostfiles);
	tilde_expand_paths(options.user_hostfiles, options.num_user_hostfiles);
	
#ifndef WIN32_FIXME
	signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE early */
	signal(SIGCHLD, main_sigchld_handler);
#endif

	/* Log into the remote system.  Never returns if the login fails. */
	ssh_login(&sensitive_data, host, (struct sockaddr *)&hostaddr,
	    options.port, pw, timeout_ms);

	if (packet_connection_is_on_socket()) {
		verbose("Authenticated to %s ([%s]:%d).", host,
		    get_remote_ipaddr(), get_remote_port());
	} else {
		verbose("Authenticated to %s (via proxy).", host);
	}

	/* We no longer need the private host keys.  Clear them now. */
	if (sensitive_data.nkeys != 0) {
		for (i = 0; i < sensitive_data.nkeys; i++) {
			if (sensitive_data.keys[i] != NULL) {
				/* Destroys contents safely */
				debug3("clear hostkey %d", i);
				key_free(sensitive_data.keys[i]);
				sensitive_data.keys[i] = NULL;
			}
		}
		free(sensitive_data.keys);
	}
	for (i = 0; i < options.num_identity_files; i++) {
		free(options.identity_files[i]);
		options.identity_files[i] = NULL;
		if (options.identity_keys[i]) {
			key_free(options.identity_keys[i]);
			options.identity_keys[i] = NULL;
		}
	}

	#ifdef WIN32_FIXME
	if (tty_flag) {
		//AllocConsole();
	    ConInputInitParams(); // init the Console input side with global parameters
		HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
	    ConInit( STD_OUTPUT_HANDLE, TRUE ); //init the output console surface for us to write
	}
	else {
		extern int glob_itissshclient;
		glob_itissshclient = 1; // tell our contrib/win32/win32compat/socket.c code it is for ssh client side
	}
	#endif

	exit_status = compat20 ? ssh_session2() : ssh_session();
	packet_close();

	if (options.control_path != NULL && muxserver_sock != -1)
		unlink(options.control_path);

  /*
   * Windows specific Cleanup.
   */
   
  #ifdef WIN32_FIXME
  
	if (tty_flag)
		ConUnInitWithRestore(); // restore terminal to previous settings if it was a tty session

    CleanUpProxyProcess();

    UninitMitKerberos();

  #else

	/* Kill ProxyCommand if it is running. */
	ssh_kill_proxy_command();
#endif

	return exit_status;
}

static void
control_persist_detach(void)
{
#ifndef WIN32_FIXME
	pid_t pid;
	int devnull;

	debug("%s: backgrounding master process", __func__);

 	/*
 	 * master (current process) into the background, and make the
 	 * foreground process a client of the backgrounded master.
 	 */
	switch ((pid = fork())) {
	case -1:
		fatal("%s: fork: %s", __func__, strerror(errno));
	case 0:
		/* Child: master process continues mainloop */
 		break;
 	default:
		/* Parent: set up mux slave to connect to backgrounded master */
		debug2("%s: background process is %ld", __func__, (long)pid);
		stdin_null_flag = ostdin_null_flag;
		options.request_tty = orequest_tty;
		tty_flag = otty_flag;
 		close(muxserver_sock);
 		muxserver_sock = -1;
		options.control_master = SSHCTL_MASTER_NO;
 		muxclient(options.control_path);
		/* muxclient() doesn't return on success. */
 		fatal("Failed to connect to new control master");
 	}
	if ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1) {
		error("%s: open(\"/dev/null\"): %s", __func__,
		    strerror(errno));
	} else {
		if (dup2(devnull, STDIN_FILENO) == -1 ||
		    dup2(devnull, STDOUT_FILENO) == -1)
			error("%s: dup2: %s", __func__, strerror(errno));
		if (devnull > STDERR_FILENO)
			close(devnull);
	}
	daemon(1, 1);
	setproctitle("%s [mux]", options.control_path);
#endif
}

/* Do fork() after authentication. Used by "ssh -f" */
static void
fork_postauth(void)
{
	if (need_controlpersist_detach)
		control_persist_detach();
	debug("forking to background");
	fork_after_authentication_flag = 0;
	if (daemon(1, 1) < 0)
		fatal("daemon() failed: %.200s", strerror(errno));
}

/* Callback for remote forward global requests */
static void
ssh_confirm_remote_forward(int type, u_int32_t seq, void *ctxt)
{
	struct Forward *rfwd = (struct Forward *)ctxt;

	/* XXX verbose() on failure? */
	debug("remote forward %s for: listen %s%s%d, connect %s:%d",
	    type == SSH2_MSG_REQUEST_SUCCESS ? "success" : "failure",
	    rfwd->listen_path ? rfwd->listen_path :
	    rfwd->listen_host ? rfwd->listen_host : "",
	    (rfwd->listen_path || rfwd->listen_host) ? ":" : "",
	    rfwd->listen_port, rfwd->connect_path ? rfwd->connect_path :
	    rfwd->connect_host, rfwd->connect_port);
	if (rfwd->listen_path == NULL && rfwd->listen_port == 0) {
		if (type == SSH2_MSG_REQUEST_SUCCESS) {
			rfwd->allocated_port = packet_get_int();
			logit("Allocated port %u for remote forward to %s:%d",
			    rfwd->allocated_port,
			    rfwd->connect_host, rfwd->connect_port);
			channel_update_permitted_opens(rfwd->handle,
			    rfwd->allocated_port);
		} else {
			channel_update_permitted_opens(rfwd->handle, -1);
		}
	}
	
	if (type == SSH2_MSG_REQUEST_FAILURE) {
		if (options.exit_on_forward_failure) {
			if (rfwd->listen_path != NULL)
				fatal("Error: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			else
				fatal("Error: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		} else {
			if (rfwd->listen_path != NULL)
				logit("Warning: remote port forwarding failed "
				    "for listen path %s", rfwd->listen_path);
			else
				logit("Warning: remote port forwarding failed "
				    "for listen port %d", rfwd->listen_port);
		}
	}
	if (++remote_forward_confirms_received == options.num_remote_forwards) {
		debug("All remote forwarding requests processed");
		if (fork_after_authentication_flag)
			fork_postauth();
	}
}

static void
client_cleanup_stdio_fwd(int id, void *arg)
{
	debug("stdio forwarding: done");
	cleanup_exit(0);
}

static void
ssh_stdio_confirm(int id, int success, void *arg)
{
	if (!success)
		fatal("stdio forwarding failed");
}

static void
ssh_init_stdio_forwarding(void)
{
	Channel *c;
	int in, out;

	if (stdio_forward_host == NULL)
		return;
	if (!compat20)
		fatal("stdio forwarding require Protocol 2");

	debug3("%s: %s:%d", __func__, stdio_forward_host, stdio_forward_port);

	if ((in = dup(STDIN_FILENO)) < 0 ||
	    (out = dup(STDOUT_FILENO)) < 0)
		fatal("channel_connect_stdio_fwd: dup() in/out failed");
	if ((c = channel_connect_stdio_fwd(stdio_forward_host,
	    stdio_forward_port, in, out)) == NULL)
		fatal("%s: channel_connect_stdio_fwd failed", __func__);
	channel_register_cleanup(c->self, client_cleanup_stdio_fwd, 0);
	channel_register_open_confirm(c->self, ssh_stdio_confirm, NULL);
}

static void
ssh_init_forwarding(void)
{
	int success = 0;
	int i;

	/* Initiate local TCP/IP port forwardings. */
	for (i = 0; i < options.num_local_forwards; i++) {
		debug("Local connections to %.200s:%d forwarded to remote "
		    "address %.200s:%d",
		    (options.local_forwards[i].listen_path != NULL) ?
		    options.local_forwards[i].listen_path :
		    (options.local_forwards[i].listen_host == NULL) ?
		    (options.fwd_opts.gateway_ports ? "*" : "LOCALHOST") :
		    options.local_forwards[i].listen_host,
		    options.local_forwards[i].listen_port,
		    (options.local_forwards[i].connect_path != NULL) ?
		    options.local_forwards[i].connect_path :
		    options.local_forwards[i].connect_host,
		    options.local_forwards[i].connect_port);
		success += channel_setup_local_fwd_listener(
		    &options.local_forwards[i], &options.fwd_opts);
	}
	if (i > 0 && success != i && options.exit_on_forward_failure)
		fatal("Could not request local forwarding.");
	if (i > 0 && success == 0)
		error("Could not request local forwarding.");

	/* Initiate remote TCP/IP port forwardings. */
	for (i = 0; i < options.num_remote_forwards; i++) {
		debug("Remote connections from %.200s:%d forwarded to "
		    "local address %.200s:%d",
		    (options.remote_forwards[i].listen_path != NULL) ?
		    options.remote_forwards[i].listen_path :
		    (options.remote_forwards[i].listen_host == NULL) ?
		    "LOCALHOST" : options.remote_forwards[i].listen_host,
		    options.remote_forwards[i].listen_port,
		    (options.remote_forwards[i].connect_path != NULL) ?
		    options.remote_forwards[i].connect_path :
		    options.remote_forwards[i].connect_host,
		    options.remote_forwards[i].connect_port);
		options.remote_forwards[i].handle =
		    channel_request_remote_forwarding(
		    &options.remote_forwards[i]);
		if (options.remote_forwards[i].handle < 0) {
			if (options.exit_on_forward_failure)
				fatal("Could not request remote forwarding.");
			else
				logit("Warning: Could not request remote "
				    "forwarding.");
		} else {
			client_register_global_confirm(ssh_confirm_remote_forward,
			    &options.remote_forwards[i]);
		}
	}

	/* Initiate tunnel forwarding. */
	if (options.tun_open != SSH_TUNMODE_NO) {
		if (client_request_tun_fwd(options.tun_open,
		    options.tun_local, options.tun_remote) == -1) {
			if (options.exit_on_forward_failure)
				fatal("Could not request tunnel forwarding.");
			else
				error("Could not request tunnel forwarding.");
		}
	}			
}

static void
check_agent_present(void)
{
	int r;

	if (options.forward_agent) {
		/* Clear agent forwarding if we don't have an agent. */
		if ((r = ssh_get_authentication_socket(NULL)) != 0) {
			options.forward_agent = 0;
			if (r != SSH_ERR_AGENT_NOT_PRESENT)
				debug("ssh_get_authentication_socket: %s",
				    ssh_err(r));
		}
	}
}

static int
ssh_session(void)
{
	int type;
	int interactive = 0;
	int have_tty = 0;
	struct winsize ws;
	char *cp;
	const char *display;

	/* Enable compression if requested. */
	if (options.compression) {
		debug("Requesting compression at level %d.",
		    options.compression_level);

		if (options.compression_level < 1 ||
		    options.compression_level > 9)
			fatal("Compression level must be from 1 (fast) to "
			    "9 (slow, best).");

		/* Send the request. */
		packet_start(SSH_CMSG_REQUEST_COMPRESSION);
		packet_put_int(options.compression_level);
		packet_send();
		packet_write_wait();
		type = packet_read();
		if (type == SSH_SMSG_SUCCESS)
			packet_start_compression(options.compression_level);
		else if (type == SSH_SMSG_FAILURE)
			logit("Warning: Remote host refused compression.");
		else
			packet_disconnect("Protocol error waiting for "
			    "compression response.");
	}
	/* Allocate a pseudo tty if appropriate. */
	if (tty_flag) {
		debug("Requesting pty.");

		/* Start the packet. */
		packet_start(SSH_CMSG_REQUEST_PTY);

		/* Store TERM in the packet.  There is no limit on the
		   length of the string. */
		cp = getenv("TERM");
		if (!cp)
			cp = "";
		packet_put_cstring(cp);

		/* Store window size in the packet. */

  #ifdef WIN32_FIXME
  
    packet_put_int((u_int) 25);  /*row*/
    packet_put_int((u_int) 80);  /*col*/
    packet_put_int((u_int) 640); /*xpixel*/
    packet_put_int((u_int) 480); /*ypixel*/

  #else
		if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) < 0)
			memset(&ws, 0, sizeof(ws));
		packet_put_int((u_int)ws.ws_row);
		packet_put_int((u_int)ws.ws_col);
		packet_put_int((u_int)ws.ws_xpixel);
		packet_put_int((u_int)ws.ws_ypixel);
#endif

		/* Store tty modes in the packet. */
		tty_make_modes(fileno(stdin), NULL);

		/* Send the packet, and wait for it to leave. */
		packet_send();
		packet_write_wait();

		/* Read response from the server. */
		type = packet_read();
		if (type == SSH_SMSG_SUCCESS) {
			interactive = 1;
			have_tty = 1;
		} else if (type == SSH_SMSG_FAILURE)
			logit("Warning: Remote host failed or refused to "
			    "allocate a pseudo tty.");
		else
			packet_disconnect("Protocol error waiting for pty "
			    "request response.");
	}
	/* Request X11 forwarding if enabled and DISPLAY is set. */
	display = getenv("DISPLAY");
	if (display == NULL && options.forward_x11)
		debug("X11 forwarding requested but DISPLAY not set");
	if (options.forward_x11 && display != NULL) {
		char *proto, *data;
		/* Get reasonable local authentication information. */
		client_x11_get_proto(display, options.xauth_location,
		    options.forward_x11_trusted,
		    options.forward_x11_timeout,
		    &proto, &data);
		/* Request forwarding with authentication spoofing. */
		debug("Requesting X11 forwarding with authentication "
		    "spoofing.");
		x11_request_forwarding_with_spoofing(0, display, proto,
		    data, 0);
		/* Read response from the server. */
		type = packet_read();
		if (type == SSH_SMSG_SUCCESS) {
			interactive = 1;
		} else if (type == SSH_SMSG_FAILURE) {
			logit("Warning: Remote host denied X11 forwarding.");
		} else {
			packet_disconnect("Protocol error waiting for X11 "
			    "forwarding");
		}
	}
	/* Tell the packet module whether this is an interactive session. */
	packet_set_interactive(interactive,
	    options.ip_qos_interactive, options.ip_qos_bulk);

	/* Request authentication agent forwarding if appropriate. */
	check_agent_present();

	if (options.forward_agent) {
		debug("Requesting authentication agent forwarding.");
		auth_request_forwarding();

		/* Read response from the server. */
		type = packet_read();
		packet_check_eom();
		if (type != SSH_SMSG_SUCCESS)
			logit("Warning: Remote host denied authentication agent forwarding.");
	}

	/* Initiate port forwardings. */
	ssh_init_stdio_forwarding();
	ssh_init_forwarding();

	/* Execute a local command */
	if (options.local_command != NULL &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	if (fork_after_authentication_flag) {
		if (options.exit_on_forward_failure &&
		    options.num_remote_forwards > 0) {
			debug("deferring postauth fork until remote forward "
			    "confirmation received");
		} else
			fork_postauth();
	}

	/*
	 * If a command was specified on the command line, execute the
	 * command now. Otherwise request the server to start a shell.
	 */
	if (buffer_len(&command) > 0) {
		int len = buffer_len(&command);
		if (len > 900)
			len = 900;
		debug("Sending command: %.*s", len,
		    (u_char *)buffer_ptr(&command));
		packet_start(SSH_CMSG_EXEC_CMD);
		packet_put_string(buffer_ptr(&command), buffer_len(&command));
		packet_send();
		packet_write_wait();
	} else {
		debug("Requesting shell.");
		packet_start(SSH_CMSG_EXEC_SHELL);
		packet_send();
		packet_write_wait();
	}

	/* Enter the interactive session. */
	return client_loop(have_tty, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, 0);
}

/* request pty/x11/agent/tcpfwd/shell for channel */
static void
ssh_session2_setup(int id, int success, void *arg)
{
	extern char **environ;
	const char *display;
	int interactive = tty_flag;

	if (!success)
		return; /* No need for error message, channels code sens one */

	display = getenv("DISPLAY");
	if (display == NULL && options.forward_x11)
		debug("X11 forwarding requested but DISPLAY not set");
	if (options.forward_x11 && display != NULL) {
		char *proto, *data;
		/* Get reasonable local authentication information. */
		client_x11_get_proto(display, options.xauth_location,
		    options.forward_x11_trusted,
		    options.forward_x11_timeout, &proto, &data);
		/* Request forwarding with authentication spoofing. */
		debug("Requesting X11 forwarding with authentication "
		    "spoofing.");
		x11_request_forwarding_with_spoofing(id, display, proto,
		    data, 1);
		client_expect_confirm(id, "X11 forwarding", CONFIRM_WARN);
		/* XXX exit_on_forward_failure */
		interactive = 1;
	}

	check_agent_present();
	if (options.forward_agent) {
		debug("Requesting authentication agent forwarding.");
		channel_request_start(id, "auth-agent-req@openssh.com", 0);
		packet_send();
	}

	/* Tell the packet module whether this is an interactive session. */
	packet_set_interactive(interactive,
	    options.ip_qos_interactive, options.ip_qos_bulk);

	client_session2_setup(id, tty_flag, subsystem_flag, getenv("TERM"),
	    NULL, fileno(stdin), &command, environ);
}

/* open new channel for a session */
static int
ssh_session2_open(void)
{
	Channel *c;
	int window, packetmax, in, out, err;

	if (stdin_null_flag) {
		in = open(_PATH_DEVNULL, O_RDONLY);
	} else {
		in = dup(STDIN_FILENO);
	}
	out = dup(STDOUT_FILENO);
	err = dup(STDERR_FILENO);

	if (in < 0 || out < 0 || err < 0)
		fatal("dup() in/out/err failed");

	/* enable nonblocking unless tty */
	if (!isatty(in))
		set_nonblock(in);
	if (!isatty(out))
		set_nonblock(out);
	if (!isatty(err))
		set_nonblock(err);

	window = CHAN_SES_WINDOW_DEFAULT;
	packetmax = CHAN_SES_PACKET_DEFAULT;
	if (tty_flag) {
		window >>= 1;
		packetmax >>= 1;
	}
	#ifdef WIN32_FIXME
	else {
		// make stdio duplicated ports of above binary mode so no CRLF xlate
		_setmode(sfd_to_fd(in), O_BINARY);
		_setmode(sfd_to_fd(out), O_BINARY);
	}
	#endif
	
	c = channel_new(
	    "session", SSH_CHANNEL_OPENING, in, out, err,
	    window, packetmax, CHAN_EXTENDED_WRITE,
	    "client-session", /*nonblock*/0);

	debug3("ssh_session2_open: channel_new: %d", c->self);

	channel_send_open(c->self);
	if (!no_shell_flag)
		channel_register_open_confirm(c->self,
		    ssh_session2_setup, NULL);

	return c->self;
}

static int
ssh_session2(void)
{
	int id = -1;

	/* XXX should be pre-session */
	if (!options.control_persist)
		ssh_init_stdio_forwarding();
	ssh_init_forwarding();

	/* Start listening for multiplex clients */
	muxserver_listen();

 	/*
	 * If we are in control persist mode and have a working mux listen
	 * socket, then prepare to background ourselves and have a foreground
	 * client attach as a control slave.
	 * NB. we must save copies of the flags that we override for
	 * the backgrounding, since we defer attachment of the slave until
	 * after the connection is fully established (in particular,
	 * async rfwd replies have been received for ExitOnForwardFailure).
	 */
 	if (options.control_persist && muxserver_sock != -1) {
		ostdin_null_flag = stdin_null_flag;
		ono_shell_flag = no_shell_flag;
		orequest_tty = options.request_tty;
		otty_flag = tty_flag;
 		stdin_null_flag = 1;
 		no_shell_flag = 1;
 		tty_flag = 0;
		if (!fork_after_authentication_flag)
			need_controlpersist_detach = 1;
		fork_after_authentication_flag = 1;
 	}
	/*
	 * ControlPersist mux listen socket setup failed, attempt the
	 * stdio forward setup that we skipped earlier.
	 */
	if (options.control_persist && muxserver_sock == -1)
		ssh_init_stdio_forwarding();

	if (!no_shell_flag || (datafellows & SSH_BUG_DUMMYCHAN))
		id = ssh_session2_open();
	else {
		packet_set_interactive(
		    options.control_master == SSHCTL_MASTER_NO,
		    options.ip_qos_interactive, options.ip_qos_bulk);
	}

	/* If we don't expect to open a new session, then disallow it */
	if (options.control_master == SSHCTL_MASTER_NO &&
	    (datafellows & SSH_NEW_OPENSSH)) {
		debug("Requesting no-more-sessions@openssh.com");
		packet_start(SSH2_MSG_GLOBAL_REQUEST);
		packet_put_cstring("no-more-sessions@openssh.com");
		packet_put_char(0);
		packet_send();
	}

	/* Execute a local command */
	if (options.local_command != NULL &&
	    options.permit_local_command)
		ssh_local_cmd(options.local_command);

	/*
	 * If requested and we are not interested in replies to remote
	 * forwarding requests, then let ssh continue in the background.
	 */
	if (fork_after_authentication_flag) {
		if (options.exit_on_forward_failure &&
		    options.num_remote_forwards > 0) {
			debug("deferring postauth fork until remote forward "
			    "confirmation received");
		} else
			fork_postauth();
	}

	if (options.use_roaming)
		request_roaming();

	return client_loop(tty_flag, tty_flag ?
	    options.escape_char : SSH_ESCAPECHAR_NONE, id);
}

static void
load_public_identity_files(void)
{
	char *filename, *cp, thishost[NI_MAXHOST];
	char *pwdir = NULL, *pwname = NULL;
	int i = 0;
	Key *public;
	struct passwd *pw;
	u_int n_ids;
	char *identity_files[SSH_MAX_IDENTITY_FILES];
	Key *identity_keys[SSH_MAX_IDENTITY_FILES];
#ifdef ENABLE_PKCS11
	Key **keys;
	int nkeys;
#endif /* PKCS11 */

	n_ids = 0;
	memset(identity_files, 0, sizeof(identity_files));
	memset(identity_keys, 0, sizeof(identity_keys));

#ifdef ENABLE_PKCS11
	if (options.pkcs11_provider != NULL &&
	    options.num_identity_files < SSH_MAX_IDENTITY_FILES &&
	    (pkcs11_init(!options.batch_mode) == 0) &&
	    (nkeys = pkcs11_add_provider(options.pkcs11_provider, NULL,
	    &keys)) > 0) {
		for (i = 0; i < nkeys; i++) {
			if (n_ids >= SSH_MAX_IDENTITY_FILES) {
				key_free(keys[i]);
				continue;
			}
			identity_keys[n_ids] = keys[i];
			identity_files[n_ids] =
			    xstrdup(options.pkcs11_provider); /* XXX */
			n_ids++;
		}
		free(keys);
	}
#endif /* ENABLE_PKCS11 */
	if ((pw = getpwuid(original_real_uid)) == NULL)
		fatal("load_public_identity_files: getpwuid failed");
	pwname = xstrdup(pw->pw_name);
#ifdef WIN32_FIXME
  pwdir = _wcsdup(pw -> pw_dir);
  
  if (pwdir)
  {
    sprintf(pwdir, "%ls", pw -> pw_dir);
  }
#else
	pwdir = xstrdup(pw->pw_dir);
#endif
	if (gethostname(thishost, sizeof(thishost)) == -1)
		fatal("load_public_identity_files: gethostname: %s",
		    strerror(errno));
	for (i = 0; i < options.num_identity_files; i++) {
		if (n_ids >= SSH_MAX_IDENTITY_FILES ||
		    strcasecmp(options.identity_files[i], "none") == 0) {
			free(options.identity_files[i]);
			continue;
		}
		cp = tilde_expand_filename(options.identity_files[i],
		    original_real_uid);
		filename = percent_expand(cp, "d", pwdir,
		    "u", pwname, "l", thishost, "h", host,
		    "r", options.user, (char *)NULL);
		free(cp);
		public = key_load_public(filename, NULL);
		debug("identity file %s type %d", filename,
		    public ? public->type : -1);
		free(options.identity_files[i]);
		identity_files[n_ids] = filename;
		identity_keys[n_ids] = public;

		if (++n_ids >= SSH_MAX_IDENTITY_FILES)
			continue;

		/* Try to add the certificate variant too */
		xasprintf(&cp, "%s-cert", filename);
		public = key_load_public(cp, NULL);
		debug("identity file %s type %d", cp,
		    public ? public->type : -1);
		if (public == NULL) {
			free(cp);
			continue;
		}
		if (!key_is_cert(public)) {
			debug("%s: key %s type %s is not a certificate",
			    __func__, cp, key_type(public));
			key_free(public);
			free(cp);
			continue;
		}
		identity_keys[n_ids] = public;
		/* point to the original path, most likely the private key */
		identity_files[n_ids] = xstrdup(filename);
		n_ids++;
	}
	options.num_identity_files = n_ids;
	memcpy(options.identity_files, identity_files, sizeof(identity_files));
	memcpy(options.identity_keys, identity_keys, sizeof(identity_keys));

	explicit_bzero(pwname, strlen(pwname));
	free(pwname);
	explicit_bzero(pwdir, strlen(pwdir));
	free(pwdir);
}

#ifndef WIN32_FIXME
static void
main_sigchld_handler(int sig)
{
	int save_errno = errno;
	pid_t pid;
	int status;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
	    (pid < 0 && errno == EINTR))
		;

	signal(sig, main_sigchld_handler);
	errno = save_errno;
}
#endif


