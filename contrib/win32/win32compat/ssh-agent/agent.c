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
#include <sddl.h>
#define BUFSIZE 5 * 1024

static HANDLE ioc_port = NULL;
static BOOL debug_mode = FALSE;

#define NUM_LISTENERS 3
#define KEY_AGENT_PIPE_ID L"\\\\.\\pipe\\ssh-keyagent"
#define PUBKEY_AGENT_PIPE_ID L"\\\\.\\pipe\\ssh-pubkeyagent"
#define AUTH_AGENT_PIPE_ID L"\\\\.\\pipe\\ssh-authagent"

static wchar_t *pipe_ids[NUM_LISTENERS] = { KEY_AGENT_PIPE_ID, PUBKEY_AGENT_PIPE_ID, AUTH_AGENT_PIPE_ID };
static enum agent_type pipe_types[NUM_LISTENERS] = { KEY_AGENT, PUBKEY_AGENT, PUBKEY_AUTH_AGENT};
static wchar_t *pipe_sddls[NUM_LISTENERS] = { L"D:P(A;; GA;;; AU)", L"D:P(A;; GA;;; AU)", L"D:P(A;; GA;;; AU)" };
HANDLE event_stop_agent;

struct listener {
	OVERLAPPED ol;
	HANDLE pipe;
	wchar_t *pipe_id;
	enum agent_type type;
	SECURITY_ATTRIBUTES sa;
} listeners[NUM_LISTENERS];

static int
init_listeners() {
	int i;
	memset(listeners, 0, sizeof(listeners));
	for (i = 0; i < NUM_LISTENERS; i++) {
		if ((listeners[i].ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL) {
			debug("cannot create event ERROR:%d", GetLastError());
			return GetLastError();
		}
		listeners[i].pipe_id = pipe_ids[i];
		listeners[i].type = pipe_types[i];
		listeners[i].pipe = INVALID_HANDLE_VALUE;
		listeners[i].sa.bInheritHandle = TRUE;
		if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(pipe_sddls[i], SDDL_REVISION_1,
			&listeners[i].sa.lpSecurityDescriptor, &listeners[i].sa.nLength)) {
			debug("cannot convert sddl ERROR:%d", GetLastError());
			return GetLastError();
		}
	}

	return 0;
}

static void
agent_cleanup() {
	int i;
	for (i = 0; i < NUM_LISTENERS; i++) {
		if (listeners[i].ol.hEvent != NULL)
			CloseHandle(listeners[i].ol.hEvent);
		if (listeners[i].pipe != INVALID_HANDLE_VALUE)
			CloseHandle(listeners[i].pipe);
	}
	if (ioc_port)
		CloseHandle(ioc_port);
	return;
}

static DWORD WINAPI 
iocp_work(LPVOID lpParam) {
	DWORD bytes;
	struct agent_connection* con = NULL;
	OVERLAPPED *p_ol;
	while (1) {
		con = NULL;
		p_ol = NULL;
		if (GetQueuedCompletionStatus(ioc_port, &bytes, &(ULONG_PTR)con, &p_ol, INFINITE) == FALSE) {
			debug("iocp error: %d on %p \n", GetLastError(), con);
			if (con)
				agent_connection_on_error(con, GetLastError());
			else
				return 0;
		}
		else
			agent_connection_on_io(con, bytes, p_ol);

	}
}


static void
process_connection(HANDLE pipe, int type) {
	struct agent_connection* con;

	if ((con = malloc(sizeof(struct agent_connection))) == NULL)
		fatal("failed to alloc");

	memset(con, 0, sizeof(struct agent_connection));
	con->connection = pipe;
	con->type = type;
	if (CreateIoCompletionPort(pipe, ioc_port, (ULONG_PTR)con, 0) != ioc_port)
		fatal("failed to assign pipe to ioc_port");
	
	agent_connection_on_io(con, 0, &con->ol);
	return iocp_work(NULL);
}

static void 
agent_listen_loop() {
	DWORD i, r;
	HANDLE wait_events[NUM_LISTENERS + 1];

	wait_events[0] = event_stop_agent;
	for (i = 0; i < NUM_LISTENERS; i++)
		wait_events[i + 1] = listeners[i].ol.hEvent;

	while (1) {
		for (i = 0; i < NUM_LISTENERS; i++) {
			if (listeners[i].pipe == INVALID_HANDLE_VALUE) {
				listeners[i].pipe = CreateNamedPipeW(
					listeners[i].pipe_id,		  // pipe name 
					PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,       // read/write access 
					PIPE_TYPE_BYTE |       // message type pipe 
					PIPE_READMODE_BYTE |   // message-read mode 
					PIPE_WAIT,                // blocking mode 
					PIPE_UNLIMITED_INSTANCES, // max. instances  
					BUFSIZE,                  // output buffer size 
					BUFSIZE,                  // input buffer size 
					0,                        // client time-out 
					&listeners[i].sa);

				if (listeners[i].pipe == INVALID_HANDLE_VALUE) {
					verbose("cannot create listener pipe ERROR:%d", GetLastError());
					SetEvent(event_stop_agent);
				}
				else if (ConnectNamedPipe(listeners[i].pipe, &listeners[i].ol) != FALSE) {
					verbose("ConnectNamedPipe returned TRUE unexpectedly ");
					SetEvent(event_stop_agent);
				}
				
				if (GetLastError() == ERROR_PIPE_CONNECTED) {
					debug("Client has already connection to %d", i);
					SetEvent(listeners[i].ol.hEvent);
				}
				
				if (GetLastError() != ERROR_IO_PENDING) {
					debug("ConnectNamedPipe failed ERROR: %d", GetLastError());
					SetEvent(event_stop_agent);
				}

			}
		}

		r = WaitForMultipleObjects(NUM_LISTENERS + 1, wait_events, FALSE, INFINITE);
		if (r == WAIT_OBJECT_0) {
			//received signal to shutdown
			debug("shutting down");
			agent_cleanup();
			return;
		}
		else if ((r > WAIT_OBJECT_0) && (r <= (WAIT_OBJECT_0 + NUM_LISTENERS))) {
			/* process incoming connection */
			HANDLE con = listeners[r - 1].pipe;
			listeners[r - 1].pipe = INVALID_HANDLE_VALUE;
			verbose("client connected on %ls", pipe_ids[r-1]);
			if (debug_mode) {
				process_connection(con, listeners[r - 1].type);
				agent_cleanup();
				return;
			}
			else {
				/* todo - spawn a child to take care of this*/
				wchar_t path[MAX_PATH], module_path[MAX_PATH];
				PROCESS_INFORMATION pi;
				STARTUPINFOW si;

				si.cb = sizeof(STARTUPINFOW);
				memset(&si, 0, sizeof(STARTUPINFOW));
				GetModuleFileNameW(NULL, module_path, MAX_PATH);
				if ((swprintf_s(path, MAX_PATH, L"%s %d %d", module_path, con, listeners[r - 1].type) == -1 ) ||
				    (CreateProcessW(NULL, path, NULL, NULL, TRUE,
					DETACHED_PROCESS, NULL, NULL,
					&si, &pi) == FALSE)) {
					verbose("Failed to create child process %ls ERROR:%d", module_path, GetLastError());
				}
				else {
					debug("spawned child %d to process %d", pi.dwProcessId, i);
					CloseHandle(pi.hProcess);
					CloseHandle(pi.hThread);
				}
				CloseHandle(con);				
			}
			
		}
		else {
			fatal("wait on events ended with %d ERROR:%d", r, GetLastError());
		}

	}
}

void agent_cleanup_connection(struct agent_connection* con) {
	debug("connection %p clean up", con);
	CloseHandle(con->connection);
	free(con);
	CloseHandle(ioc_port);
	ioc_port = NULL;
}

void agent_shutdown() {
	verbose("shutdown");
	SetEvent(event_stop_agent);
}

void
agent_start(BOOL dbg_mode, BOOL child, HANDLE pipe, enum agent_type type) {
	int i, r;
	HKEY agent_root = NULL;
	DWORD process_id = GetCurrentProcessId();

	verbose("agent_start pid:%d, dbg:%d, child:%d, pipe:%d", process_id, dbg_mode, child, pipe);
	debug_mode = dbg_mode;

	if ((ioc_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, (ULONG_PTR)NULL, 0)) == NULL)
		fatal("cannot create ioc port ERROR:%d", GetLastError());

	if (child == FALSE) {
		if ((r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, SSH_AGENT_ROOT, 0, 0, 0, KEY_WRITE, 0, &agent_root, 0)) != ERROR_SUCCESS)
			fatal("cannot create agent root reg key, ERROR:%d", r);
		if ((r = RegSetValueExW(agent_root, L"ProcessID", 0, REG_DWORD, (BYTE*)&process_id, 4)) != ERROR_SUCCESS)
			fatal("cannot publish agent master process id ERROR:%d", r);
		if ((event_stop_agent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL)
			fatal("cannot create global stop event ERROR:%d", GetLastError());
		if ((r = init_listeners()) != 0)
			fatal("failed to create server pipes ERROR:%d", r);
		agent_listen_loop();
	}
	else { /* this is a child process that processes one connection */
		process_connection(pipe, type);
	}
	
	return 0;
}

