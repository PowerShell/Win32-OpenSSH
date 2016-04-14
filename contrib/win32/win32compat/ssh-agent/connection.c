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

void agent_connection_on_io(struct agent_connection* con, DWORD bytes, OVERLAPPED* ol) {
	
	/* process error */
	if ( (bytes == 0) && (GetOverlappedResult(con->connection, ol, &bytes, FALSE) == FALSE)) {
		con->state = DONE;
		agent_cleanup_connection(con);
		return;
	}

	if (con->state == DONE)
		DebugBreak();

	while (1) {
		switch (con->state) {
		case WRITING:
			/* Writing is done, read next request */
		case LISTENING:
			con->state = READING_HEADER;
			if (con->state == LISTENING)
				agent_listen();
			ZeroMemory(&con->request, sizeof(con->request));
			if (ReadFile(con->connection, con->request.buf,
				HEADER_SIZE,  NULL, &con->ol)) {
				bytes = HEADER_SIZE;
				continue;
			}
			if (GetLastError() != ERROR_IO_PENDING) {
				con->state = DONE;
				agent_cleanup_connection(con);
				return;
			}
			break;
		case READING_HEADER:
			con->request.read += bytes;
			if (con->request.read == HEADER_SIZE) {
				con->request.size = *((DWORD*)con->request.buf);
				con->state = READING;
				if (ReadFile(con->connection, con->request.buf,
					con->request.size, NULL, &con->ol)) {
					bytes = con->request.size;
					continue;
				}
				if (GetLastError() != ERROR_IO_PENDING) {
					con->state = DONE;
					agent_cleanup_connection(con);
					return;
				}
			}
			else {
				if (ReadFile(con->connection, con->request.buf + con->request.read,
					HEADER_SIZE - con->request.read, NULL, &con->ol)) {
					bytes = HEADER_SIZE - con->request.read;
					continue;
				}
				if (GetLastError() != ERROR_IO_PENDING) {
					con->state = DONE;
					agent_cleanup_connection(con);
					return;
				}
			}
			break;
		case READING:
			con->request.read += bytes;
			if (con->request.read == con->request.size) {
				/* process request and get response */
				con->state = WRITING;
				if (WriteFile(con->connection, con->request.buf,
					con->request.size, NULL, &con->ol)) {
					bytes = con->request.size;
					continue;
				}
				if (GetLastError() != ERROR_IO_PENDING) {
					con->state = DONE;
					agent_cleanup_connection(con);
					return;
				}
			}
			else {
				if (ReadFile(con->connection, con->request.buf + con->request.read,
					con->request.size - con->request.read, NULL, &con->ol)) {
					bytes = con->request.size - con->request.read;
					continue;
				}
				if (GetLastError() != ERROR_IO_PENDING) {
					con->state = DONE;
					agent_cleanup_connection(con);
					return;
				}
			}
			break;
		default:
			DebugBreak();
		}		
	}
}

void agent_connection_disconnect(struct agent_connection* con) {
	CancelIoEx(con->connection, NULL);
	DisconnectNamedPipe(con->connection);
}
