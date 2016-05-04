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
#define AGENT_PIPE_ID L"\\\\.\\pipe\\ssh-agent"
#define BUFSIZE 5 * 1024

static HANDLE ioc_port;
static volatile long action_queue;
static struct agent_connection* list;

#define ACTION_LISTEN	0x80000000
#define ACTION_SHUTDOWN 0x40000000

void agent_sm_process_action_queue() {

	do {
		if (action_queue & ACTION_SHUTDOWN) {
			/* go through the list and disconect each connection */
			struct agent_connection* tmp = list;
			while (tmp) {
				agent_connection_disconnect(tmp);
				tmp = tmp->next;
			}

			/* remove unwanted queued actions */
			InterlockedAnd(&action_queue, ~ACTION_LISTEN);
			if (InterlockedAnd(&action_queue, ~ACTION_SHUTDOWN) == ACTION_SHUTDOWN)
				break;
		}
		else if (action_queue & ACTION_LISTEN) {
			HANDLE h;
			long prev_queue;
			SECURITY_ATTRIBUTES sa;
			struct agent_connection* con = 
				(struct agent_connection*)malloc(sizeof(struct agent_connection));
			memset(con, 0, sizeof(struct agent_connection));
			memset(&sa, 0, sizeof(sa));
			sa.bInheritHandle = FALSE;
			sa.lpSecurityDescriptor = NULL;
			h = CreateNamedPipeW(
				AGENT_PIPE_ID,		  // pipe name 
				PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,       // read/write access 
				PIPE_TYPE_BYTE |       // message type pipe 
				PIPE_READMODE_BYTE |   // message-read mode 
				PIPE_WAIT,                // blocking mode 
				PIPE_UNLIMITED_INSTANCES, // max. instances  
				BUFSIZE,                  // output buffer size 
				BUFSIZE,                  // input buffer size 
				0,                        // client time-out 
				&sa);

			/* remove action from queue before assigning iocp port*/
			con->connection = h;
			con->next = list;
			list = con;
			prev_queue = InterlockedAnd(&action_queue, ~ACTION_LISTEN);
			CreateIoCompletionPort(h, ioc_port, (ULONG_PTR)con, 0);
			ConnectNamedPipe(h, &con->ol);
			if (prev_queue == ACTION_LISTEN)
				break;
		}
		else {
			/* cleanup up a done connection*/
			struct agent_connection *prev = NULL, *tmp = list;
			while (tmp) {
				if (tmp->state == DONE) {
					if (prev == NULL)
						list = tmp->next;
					else
						prev->next = tmp->next;
					CloseHandle(tmp->connection);
					printf("deleting %p\n", tmp);
					free(tmp);
					break;
				}
				prev = tmp;
				tmp = tmp->next;
			}
			if (InterlockedDecrement(&action_queue) == 0)
				break;
		}
	} while (1);
}

void 
agent_cleanup_connection(struct agent_connection* con) {
	if (InterlockedIncrement(&action_queue) == 1)
		agent_sm_process_action_queue();
}

void 
agent_listen() {
	if (InterlockedOr(&action_queue, ACTION_LISTEN) == 0)
		agent_sm_process_action_queue();
}


void agent_shutdown() {
	if (InterlockedOr(&action_queue, ACTION_SHUTDOWN) == 0)
		agent_sm_process_action_queue();
	while (list != NULL)
		Sleep(100);
	CloseHandle(ioc_port);
}

HANDLE  iocp_workers[4];

DWORD WINAPI iocp_work(LPVOID lpParam) {
	DWORD bytes;
	struct agent_connection* con = NULL;
	OVERLAPPED *p_ol;
	while (1) {
		con = NULL;
		p_ol = NULL;
		if (GetQueuedCompletionStatus(ioc_port, &bytes, &(ULONG_PTR)con, &p_ol, INFINITE) == FALSE) {
			printf("error: %d on %p \n", GetLastError(), con);
			if (con) 
				agent_connection_on_error(con, GetLastError());
			else
				return 0;
		}
		//printf("io on %p state %d bytes %d\n", con, con->state, bytes);
		agent_connection_on_io(con, bytes, p_ol);

	}
}

int agent_start() {
	int i;
	HKEY agent_root;
	DWORD process_id = GetCurrentProcessId();
	action_queue = 0;
	list = NULL;
	ioc_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, (ULONG_PTR)NULL, 0);

	for (i = 0; i < 3; i++)
		QueueUserWorkItem(iocp_work, NULL, 0);
	
	agent_listen();
	RegCreateKeyExW(HKEY_LOCAL_MACHINE, SSH_AGENT_ROOT, 0, 0, 0, KEY_WRITE, 0, &agent_root, 0);
	RegSetValueExW(agent_root, L"ProcessID", 0, REG_DWORD, (BYTE*)&process_id, 4);
	iocp_work(NULL);
	return 1;
}

