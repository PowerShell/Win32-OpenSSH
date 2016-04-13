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

enum agent_sm_event {
	NEW_CLIENT_CONNECTION = 1,
	CONNECTION_DONE = 2,
	SHUTDOWN = 3
};

#define ACTION_LISTEN	0x80000000
#define ACTION_SHUTDOWN 0x40000000

void agent_sm_process_action_queue() {
	long actions_remaining = 0;
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
			actions_remaining = InterlockedAnd(&action_queue, ~ACTION_SHUTDOWN);
		}
		else if (action_queue & ACTION_LISTEN) {
			HANDLE h;
			struct agent_connection* con = 
				(struct agent_connection*)malloc(sizeof(struct agent_connection));
			memset(con, 0, sizeof(struct agent_connection));
			h = CreateNamedPipe(
				AGENT_PIPE_ID,		  // pipe name 
				PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,       // read/write access 
				PIPE_TYPE_MESSAGE |       // message type pipe 
				PIPE_READMODE_MESSAGE |   // message-read mode 
				PIPE_WAIT,                // blocking mode 
				PIPE_UNLIMITED_INSTANCES, // max. instances  
				BUFSIZE,                  // output buffer size 
				BUFSIZE,                  // input buffer size 
				0,                        // client time-out 
				NULL);

			/* remove action from queue before the assigining iocp port*/
			actions_remaining = InterlockedAnd(&action_queue, ~ACTION_LISTEN);
			CreateIoCompletionPort(h, ioc_port, con, 0);

			con->next = list;
			list = con;
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
					free(tmp);
					break;
				}
				prev = tmp;
				tmp = tmp->next;
			}
			actions_remaining = InterlockedDecrement(&action_queue);
		}
	} while (actions_remaining);
}

void agent_sm_raise(enum agent_sm_event event) {
	long ret = 0;
	switch (event) {
	case NEW_CLIENT_CONNECTION:
		ret = InterlockedOr(&action_queue, ACTION_LISTEN);
		if (ret == 0)
			agent_sm_process_action_queue();
		break;
	case SHUTDOWN:
		ret = InterlockedOr(&action_queue, ACTION_SHUTDOWN);
		if (ret == 0)
			agent_sm_process_action_queue();
		break;
	case CONNECTION_DONE:
		ret = InterlockedIncrement(&action_queue);
		if (ret == 1)
			agent_sm_process_action_queue();
		break;
	default:
		DebugBreak();
	}

	/* is this the first action queued */

}

int agent_start() {
	action_queue = 0;
	list = NULL;
	ioc_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, 0);
	action_queue = ACTION_LISTEN;
	agent_sm_process_action_queue();
}

void agent_listen();
void agent_shutdown();
void agent_cleanup_connection(struct agent_connection*);

int agent_listen() {

	ioc_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, 0);

	
	BOOL ret;
	HANDLE temp;
	DWORD err, bytes;
	ULONG_PTR ptr;
	HANDLE h = CreateNamedPipe(
		pipe_name,		  // pipe name 
		PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,       // read/write access 
		PIPE_TYPE_MESSAGE |       // message type pipe 
		PIPE_READMODE_MESSAGE |   // message-read mode 
		PIPE_WAIT,                // blocking mode 
		PIPE_UNLIMITED_INSTANCES, // max. instances  
		BUFSIZE,                  // output buffer size 
		BUFSIZE,                  // input buffer size 
		0,                        // client time-out 
		NULL);

	temp = CreateIoCompletionPort(h, ioc_port, NULL, 0);

	OVERLAPPED ol, *pol;
	ZeroMemory(&ol, sizeof(ol));
	ret = ConnectNamedPipe(h, &ol);
	err = GetLastError();

	GetQueuedCompletionStatus(ioc_port, &bytes, &ptr, &pol, INFINITE);

	//Sleep(INFINITE);
	return 1;
}
