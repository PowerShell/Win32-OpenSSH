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

int process_request(struct agent_connection*);

#define ABORT_CONNECTION_RETURN(c) do {	\
	c->state = DONE;		\
	agent_cleanup_connection(c);	\
	return;				\
} while (0)

void 
agent_connection_on_error(struct agent_connection* con, DWORD error) 
{
	ABORT_CONNECTION_RETURN(con);
}

void 
agent_connection_on_io(struct agent_connection* con, DWORD bytes, OVERLAPPED* ol) 
{
	/* process error */
	debug3("connection io %p #bytes:%d state:%d", con, bytes, con->state);
	if ((bytes == 0) && (GetOverlappedResult(con->pipe_handle, ol, &bytes, FALSE) == FALSE))
		ABORT_CONNECTION_RETURN(con);
	if (con->state == DONE)
		DebugBreak();

	switch (con->state) {		
	case LISTENING:
	case WRITING:
		/* Writing is done, read next request */
		/* assert on assumption that write always completes on sending all bytes*/
		if (bytes != con->io_buf.num_bytes)
			DebugBreak();
		con->state = READING_HEADER;
		ZeroMemory(&con->io_buf, sizeof(con->io_buf));
		if (!ReadFile(con->pipe_handle, con->io_buf.buf,
			HEADER_SIZE,  NULL, &con->ol) && (GetLastError() != ERROR_IO_PENDING)) 
			ABORT_CONNECTION_RETURN(con);
		break;
	case READING_HEADER:
		con->io_buf.transferred += bytes;
		if (con->io_buf.transferred == HEADER_SIZE) {
			con->io_buf.num_bytes = PEEK_U32(con->io_buf.buf);
			con->io_buf.transferred = 0;
			if (con->io_buf.num_bytes > MAX_MESSAGE_SIZE)
				ABORT_CONNECTION_RETURN(con);

			con->state = READING;
			if (!ReadFile(con->pipe_handle, con->io_buf.buf,
				con->io_buf.num_bytes, NULL, &con->ol)&&(GetLastError() != ERROR_IO_PENDING)) 
				ABORT_CONNECTION_RETURN(con);
		} else {
			if (!ReadFile(con->pipe_handle, con->io_buf.buf + con->io_buf.num_bytes,
				HEADER_SIZE - con->io_buf.num_bytes, NULL, &con->ol)&& (GetLastError() != ERROR_IO_PENDING)) 
				ABORT_CONNECTION_RETURN(con);
		}
		break;
	case READING:
		con->io_buf.transferred += bytes;
		if (con->io_buf.transferred == con->io_buf.num_bytes) {
			if (process_request(con) != 0) {
				ABORT_CONNECTION_RETURN(con);
			}
			con->state = WRITING;
			if (!WriteFile(con->pipe_handle, con->io_buf.buf,
				con->io_buf.num_bytes, NULL, &con->ol)&& (GetLastError() != ERROR_IO_PENDING) )
				ABORT_CONNECTION_RETURN(con);
		} else {
			if (!ReadFile(con->pipe_handle, con->io_buf.buf + con->io_buf.transferred,
				con->io_buf.num_bytes - con->io_buf.transferred, NULL, &con->ol)&& (GetLastError() != ERROR_IO_PENDING)) 
				ABORT_CONNECTION_RETURN(con);
		}
		break;
	default:
		DebugBreak();
	}		
}

void 
agent_connection_disconnect(struct agent_connection* con) 
{
	CancelIoEx(con->pipe_handle, NULL);
	DisconnectNamedPipe(con->pipe_handle);
}

static int
get_con_client_type(struct agent_connection* con) 
{
	int r = -1;
	char system_sid[SECURITY_MAX_SID_SIZE];
	char ns_sid[SECURITY_MAX_SID_SIZE];
	char ls_sid[SECURITY_MAX_SID_SIZE];
	DWORD reg_dom_len = 0, info_len = 0, sid_size;
	SID_NAME_USE nuse;
	HANDLE token;
	TOKEN_USER* info = NULL;
	HANDLE pipe = con->pipe_handle;

	if (ImpersonateNamedPipeClient(pipe) == FALSE)
		return -1;

	if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &token) == FALSE ||
	    GetTokenInformation(token, TokenUser, NULL, 0, &info_len) == TRUE ||
	    (info = (TOKEN_USER*)malloc(info_len)) == NULL ||
	    GetTokenInformation(token, TokenUser, info, info_len, &info_len) == FALSE)
		goto done;

	sid_size = SECURITY_MAX_SID_SIZE;
	if (CreateWellKnownSid(WinLocalSystemSid, NULL, system_sid, &sid_size) == FALSE)
		goto done;
	sid_size = SECURITY_MAX_SID_SIZE;
	if (CreateWellKnownSid(WinNetworkServiceSid, NULL, ns_sid, &sid_size) == FALSE)
		goto done;
	sid_size = SECURITY_MAX_SID_SIZE;
	if (CreateWellKnownSid(WinLocalServiceSid, NULL, ls_sid, &sid_size) == FALSE)
		goto done;

	if (EqualSid(info->User.Sid, system_sid) ||
	    EqualSid(info->User.Sid, ls_sid) ||
	    EqualSid(info->User.Sid, ns_sid))
		con->client_type = MACHINE;
	else
		con->client_type = USER;

	debug2("client type: %s", con->client_type == MACHINE? "machine" : "user");
	r = 0;
done:
	if (info)
		free(info);
	RevertToSelf();
	return r;
}

static int
process_request(struct agent_connection* con) 
{
	int r = -1;
	struct sshbuf *request = NULL, *response = NULL;
	u_char type;

	if (con->client_type == UNKNOWN && get_con_client_type(con) == -1) {
		debug("unable to get client process type");
		goto done;
	}

	request = sshbuf_from(con->io_buf.buf, con->io_buf.num_bytes);
	response = sshbuf_new();
	if ((request == NULL) || (response == NULL))
		goto done;

	if (sshbuf_get_u8(request, &type) != 0)
		return -1;
	debug("process agent request type %d", type);

	switch (type) {
	case SSH2_AGENTC_ADD_IDENTITY:
		r =  process_add_identity(request, response, con);
		break;
	case SSH2_AGENTC_REQUEST_IDENTITIES:
		r = process_request_identities(request, response, con);
		break;
	case SSH2_AGENTC_SIGN_REQUEST:
		r = process_sign_request(request, response, con);
		break;
	case SSH2_AGENTC_REMOVE_IDENTITY:
		r = process_remove_key(request, response, con);
		break;
	case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		r = process_remove_all(request, response, con);
		break;
	case SSH_AGENT_AUTHENTICATE:
		r = process_authagent_request(request, response, con);
		break;
	default:
		debug("unknown agent request %d", type);
		r = -1;
		break;
	}

done:
	if (request)
		sshbuf_free(request);

	ZeroMemory(&con->io_buf, sizeof(con->io_buf));
	if (r == 0) {
		POKE_U32(con->io_buf.buf, sshbuf_len(response));
		memcpy(con->io_buf.buf + 4, sshbuf_ptr(response), sshbuf_len(response));
		con->io_buf.num_bytes = sshbuf_len(response) + 4;
	}
	
	if (response)
		sshbuf_free(response);

	return r;
}