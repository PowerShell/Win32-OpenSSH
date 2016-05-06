/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Copyright (c) 2015 Microsoft Corp.
* All rights reserved
*
* Client side utility to manage authorized public keys for 
* key based authentication
* Code borrowed from ssh-add
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

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include "openbsd-compat/openssl-compat.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "xmalloc.h"
#include "ssh.h"
#include "rsa.h"
#include "log.h"
#include "sshkey.h"
#include "sshbuf.h"
#include "authfd.h"
#include "pubkeyfd.h"
#include "authfile.h"
#include "pathnames.h"
#include "misc.h"
#include "ssherr.h"
#include "digest.h"

/* argv0 */
extern char *__progname;

/* Default files to add */
static char *default_files[] = {
#ifdef WITH_OPENSSL
	_PATH_SSH_CLIENT_ID_RSA,
	_PATH_SSH_CLIENT_ID_DSA,
#ifdef OPENSSL_HAS_ECC
	_PATH_SSH_CLIENT_ID_ECDSA,
#endif
#endif /* WITH_OPENSSL */
	_PATH_SSH_CLIENT_ID_ED25519,
	NULL
};

static int fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Send a request to remove all identities. */
static int
delete_all(int agent_fd)
{
	int ret = -1;

	if (ssh_remove_all_pubkeys(agent_fd) == 0)
		ret = 0;

	if (ret == 0)
		fprintf(stderr, "All identities removed.\n");
	else
		fprintf(stderr, "Failed to remove all identities.\n");

	return ret;
}

static int
list_all_keys(int agent_fd, int do_fp)
{
	char *fp;
	int r, had_identities = 0;
	struct ssh_identitylist *idlist;
	size_t i;

	if ((r = ssh_list_pubkeys(agent_fd, &idlist)) != 0) 
		fprintf(stderr, "error fetching public keys: %s (%s)\n");
	else
	{
		for (i = 0; i < idlist->nkeys; i++) {
			had_identities = 1;
			if (do_fp) {
				fp = sshkey_fingerprint(idlist->keys[i],
				    fingerprint_hash, SSH_FP_DEFAULT);
				printf("%d %s %s (%s)\n",
				    sshkey_size(idlist->keys[i]),
				    fp == NULL ? "(null)" : fp,
				    idlist->comments[i],
				    sshkey_type(idlist->keys[i]));
				free(fp);
			} else {
				if ((r = sshkey_write(idlist->keys[i],
				    stdout)) != 0) {
					fprintf(stderr, "sshkey_write: %s\n",
					    ssh_err(r));
					continue;
				}
				fprintf(stdout, " %s\n", idlist->comments[i]);
			}
		}
		ssh_free_identitylist(idlist);
	}
	if (!had_identities) {
		printf("The agent has no identities.\n");
		return -1;
	}
	return 0;
}

static int
do_file(int agent_fd, int deleting, char *filename)
{
	struct sshkey *public;
	char *comment = NULL, *password = NULL;
	int r, ret = -1;

	if ((r = sshkey_load_public(filename, &public, &comment)) != 0) {
		printf("Bad key file %s: %s\n", filename, ssh_err(r));
		return -1;
	}

	if (deleting) {
		if ((r = ssh_remove_pubkey(agent_fd, public)) == 0) {
			fprintf(stderr, "Identity removed: %s (%s)\n", filename, comment);
			ret = 0;
		}
		else
			fprintf(stderr, "Could not remove public key \"%s\": %s\n",
				filename, ssh_err(r));
	}
	else {
		if ((password = read_passphrase("Enter your password: ",
			RP_ALLOW_STDIN)) == NULL) {
			ret = ENOMEM;
			goto out;
		}

		if ((r = ssh_add_pubkey(agent_fd, public, comment, password)) == 0) {
			fprintf(stderr, "Public key added: %s (%s)\n", filename, comment);
			ret = 0;
		}
		else
			fprintf(stderr, "Could not add public key \"%s\": %s\n",
				filename, ssh_err(r));
	}

out:
	if (public != NULL)
		sshkey_free(public);
	free(comment);

	return ret;
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [options] [file ...]\n", __progname);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -l          List fingerprints of all public keys.\n");
	fprintf(stderr, "  -L          List all public keys.\n");
	fprintf(stderr, "  -d          Delete a public key.\n");
	fprintf(stderr, "  -D          Delete all public keys.\n");	
}

int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;
	int agent_fd;
	int r, i, ch, deleting = 0, ret = 0;
	int lflag = 0, Dflag = 0;
	

  #ifdef WIN32_FIXME
    
    /*
     * Allocate stdio inside our wrapper function.
     */
     
	w32posix_initialize();

  #endif

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

#ifdef WITH_OPENSSL
	OpenSSL_add_all_algorithms();
#endif

	#ifndef WIN32_FIXME
	setvbuf(stdout, NULL, _IOLBF, 0);
	#endif

	/* First, get a connection to the authentication agent. */
	switch (r = ssh_get_authentication_socket(&agent_fd)) {
	case 0:
		break;
	case SSH_ERR_AGENT_NOT_PRESENT:
		fprintf(stderr, "Could not open a connection to your "
		    "authentication agent.\n");
		exit(2);
	default:
		fprintf(stderr, "Error connecting to agent: %s\n", ssh_err(r));
		exit(2);
	}

	while ((ch = getopt(argc, argv, "lLdD")) != -1) {
		switch (ch) {
		case 'l':
		case 'L':
			if (lflag != 0)
				fatal("-%c flag already specified", lflag);
			lflag = ch;
			break;
		case 'd':
			deleting = 1;
			break;
		case 'D':
			Dflag = 1;
			break;
		default:
			usage();
			ret = 1;
			goto done;
		}
	}

	if ((lflag != 0) + (Dflag != 0) > 1)
		fatal("Invalid combination of actions");
	else if (lflag) {
		if (list_all_keys(agent_fd, lflag == 'l' ? 1 : 0) == -1)
			ret = 1;
		goto done;
	} else if (Dflag) {
		if (delete_all(agent_fd) == -1)
			ret = 1;
		goto done;
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		char buf[PATH_MAX];
		struct passwd *pw;
		struct stat st;
		int count = 0;

		if ((pw = getpwuid(getuid())) == NULL) {
			fprintf(stderr, "No user found with uid %u\n",
			    (u_int)getuid());
			ret = 1;
			goto done;
		}

		for (i = 0; default_files[i]; i++) {
			snprintf(buf, sizeof(buf), "%s/%s", pw->pw_dir,
			    default_files[i]);
			if (stat(buf, &st) < 0)
				continue;
			if (do_file(agent_fd, deleting, buf) == -1)
				ret = 1;
			else
				count++;
		}
		if (count == 0)
			ret = 1;
	} else {
		for (i = 0; i < argc; i++) {
			if (do_file(agent_fd, deleting, argv[i]) == -1)
				ret = 1;
		}
	}

done:
	ssh_close_authentication_socket(agent_fd);
	return ret;
}
