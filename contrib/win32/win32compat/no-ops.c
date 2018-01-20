/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Copyright (c) 2015 Microsoft Corp.
* All rights reserved
*
* Definitions of all SSH/POSIX calls that are otherwise no-ops in Windows
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

#include "inc\sys\types.h"

/* uuidswap.c defs */
void
temporarily_use_uid(struct passwd *pw)
{
	return;
}

void
permanently_drop_suid(uid_t uid)
{
	return;
}

void
restore_uid(void)
{
	return;
}

void
permanently_set_uid(struct passwd *pw)
{
	return;
}


/* mux.c defs */
int muxserver_sock = -1;
typedef struct Channel Channel;
unsigned int muxclient_command = 0;
void
muxserver_listen(void)
{
	return;
}

void
mux_exit_message(Channel *c, int exitval)
{
	return;
}

void
mux_tty_alloc_failed(Channel *c)
{
	return;
}

void
muxclient(const char *path)
{
	return;
}

int
innetgr(const char *netgroup, const char *host, const char *user, const char *domain)
{
	return -1;
}

int
chroot(const char *path)
{
	return 0;
}

int
initgroups(const char *user, gid_t group)
{
	return -1;
}

/* sshd.c */
int
setgroups(gid_t group, char* name)
{
	return 0;
}

int
setsid(void)
{
	return 0;
}

int
startup_handler(void)
{
	return 0;
}

