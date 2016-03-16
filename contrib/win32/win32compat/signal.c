/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
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

#include "w32fd.h"
#include <errno.h>

/* signal handlers */

/* signal queue */

/* child processes */
#define MAX_CHILDREN 50
struct _children {
	HANDLE handles[MAX_CHILDREN];
	DWORD num_children;
} children;

void 
signalio_initialize() {
	memset(&children, 0, sizeof(children));
}

int
signalio_add_child(HANDLE child) {
	if (children.num_children == MAX_CHILDREN) {
		errno = ENOTSUP;
		return -1;
	}
	children.handles[children.num_children++] = child;
	return 0;
}

int
signalio_remove_child_at_index(DWORD index) {
	if (index >= children.num_children) {
		errno = EINVAL;
		return -1;
	}
	
	CloseHandle(children.handles[index]);
	if ((children.num_children > 1) && (index != (children.num_children - 1))) {
		children.handles[index] = children.handles[children.num_children - 1];
	}

	children.num_children--;
	return 0;
}


int
signalio_remove_child(HANDLE child) {
	HANDLE* handles = children.handles;
	DWORD num_children = children.num_children;

	while (num_children) {
		if (*handles == child)
			return signalio_remove_child_at_index(children.num_children - num_children);
		handles++;
		num_children--;
	}

	errno = EINVAL;
	return -1;
}


/*
 * Main wait routine used by all blocking calls. 
 * It wakes up on 
 * - any signals (errno = EINTR ) - TODO
 * - any of the supplied events set 
 * - any APCs caused by IO completions 
 * - time out 
 * - Returns 0 on IO completion, timeout -1 on rest
 *  if milli_seconds is 0, this function returns 0, its called with 0 
 *  to execute any scheduled APCs
*/
int 
wait_for_any_event(HANDLE* events, int num_events, DWORD milli_seconds)
{
	HANDLE all_events[MAXIMUM_WAIT_OBJECTS];
	DWORD num_all_events = num_events + children.num_children;

	if (num_all_events > MAXIMUM_WAIT_OBJECTS) {
		errno = ENOTSUP;
		return -1;
	}

	memcpy(all_events, children.handles, children.num_children * sizeof(HANDLE));
	memcpy(all_events + children.num_children, events, num_events * sizeof(HANDLE));

	/* TODO - implement signal catching and handling */
	if (num_all_events) {
		DWORD ret = WaitForMultipleObjectsEx(num_all_events, all_events, FALSE,
		    milli_seconds, TRUE);
		if ((ret >= WAIT_OBJECT_0) && (ret <= WAIT_OBJECT_0 + num_all_events - 1)) {
			//woken up by event signalled
			/* is this due to a child process going down*/
			if (children.num_children && ((ret - WAIT_OBJECT_0) < children.num_children)) {
				/* TODO - enable this once all direct closes are removed in core code*/
				//signalio_remove_child(ret - WAIT_OBJECT_0);
				errno = EINTR;
				return -1;
			}

			return 0;
		}
		else if (ret == WAIT_IO_COMPLETION) {
			return 0;
		}
		else if (ret == WAIT_TIMEOUT) {
			return 0;
		}
		/* some other error*/
		else { 
			errno = EOTHER;
			debug("ERROR: unxpected wait end: %d", ret);
			return -1;
		}
	}
	else {
		DWORD ret = SleepEx(milli_seconds, TRUE);
		if (ret == WAIT_IO_COMPLETION) {
			return 0;
		}
		else if (ret == 0) {
			return 0;
		}
		else { //some other error
			errno = EOTHER;
			debug("ERROR: unxpected SleepEx error: %d", ret);
			return -1;
		}
	}
}