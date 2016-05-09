/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
* ssh-agent implementation on Windows
*
* Copyright (c) 2015 Microsoft Corp.
* All rights reserved
*
* Microsoft openssh win32 port
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

#include "agent.h"
#include "agent-request.h"
#include "ssh-pubkeydefs.h"


static int
process_add_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) {
	return -1;
}



int process_pubkeyagent_request(struct sshbuf* request, struct sshbuf* response, struct agent_connection* con) {
	int r = 0;
	const u_char *op;
	size_t op_len;
	
	if ((r = sshbuf_get_string_direct(request, &op, &op_len)) != 0)
		goto done;

	if (op_len > 10) {
		r = EINVAL;
		goto done;
	}

	if ((op_len == 3) && (strncmp(op, PK_REQUEST_ADD, 3) == 0))
		r = 0;
	

done:
	return r;
}