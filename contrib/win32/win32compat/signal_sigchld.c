/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Copyright(c) 2015 Microsoft Corp.
* All rights reserved
*
* Helper routines to support SIGCLD and related routines implementation
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met :
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and / or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES(INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "signal_internal.h"

struct _children children;

int
sw_add_child(HANDLE child, DWORD pid) {
	DWORD first_zombie_index;

	debug("Register child %p pid %d, %d zombies of %d", child, pid,
		children.num_zombies, children.num_children);
	if (children.num_children == MAX_CHILDREN) {
		errno = ENOMEM;
		return -1;
	}
	if (children.num_zombies) {
		first_zombie_index = children.num_children - children.num_zombies;
		children.handles[children.num_children] = children.handles[first_zombie_index];
		children.process_id[children.num_children] = children.process_id[first_zombie_index];

		children.handles[first_zombie_index] = child;
		children.process_id[first_zombie_index] = pid;
	}
	else {
		children.handles[children.num_children] = child;
		children.process_id[children.num_children] = pid;
	}


	children.num_children++;
	return 0;
}

int
sw_remove_child_at_index(DWORD index) {
	DWORD last_non_zombie;

	debug("Unregister child at index %d, %d zombies of %d", index,
		children.num_zombies, children.num_children);

	if ((index >= children.num_children)
		|| (children.num_children == 0)) {
		errno = EINVAL;
		return -1;
	}

	CloseHandle(children.handles[index]);
	if (children.num_zombies == 0) {
		children.handles[index] = children.handles[children.num_children - 1];
		children.process_id[index] = children.process_id[children.num_children - 1];
	}
	else {
		/* if its a zombie */
		if (index >= (children.num_children - children.num_zombies)) {
			children.handles[index] = children.handles[children.num_children - 1];
			children.process_id[index] = children.process_id[children.num_children - 1];
			children.num_zombies--;
		}
		else {
			last_non_zombie = children.num_children - children.num_zombies - 1;
			children.handles[index] = children.handles[last_non_zombie];
			children.process_id[index] = children.process_id[last_non_zombie];

			children.handles[last_non_zombie] = children.handles[children.num_children - 1];
			children.process_id[last_non_zombie] = children.process_id[children.num_children - 1];
		}
	}

	children.num_children--;
	return 0;
}

int
sw_child_to_zombie(DWORD index) {
	DWORD last_non_zombie, last_child, zombie_pid;
	HANDLE zombie_handle;

	debug("zombie'ing child at index %d, %d zombies of %d", index,
		children.num_zombies, children.num_children);

	if (index >= children.num_children) {
		errno = EINVAL;
		return -1;
	}

	zombie_pid = children.process_id[index];
	zombie_handle = children.handles[index];
	last_non_zombie = children.num_children - children.num_zombies - 1;
	last_child = children.num_children - 1;

	children.handles[index] = children.handles[last_non_zombie];
	children.process_id[index] = children.process_id[last_non_zombie];

	children.handles[last_non_zombie] = children.handles[index];
	children.process_id[last_non_zombie] = children.process_id[index];

	children.num_zombies++;
	return 0;
}

int
sw_kill(int pid, int sig) {
	int child_index, i;
	if (pid == GetCurrentProcessId())
		return sw_raise(sig);

	/*  for child processes - only SIGTERM supported*/
	child_index = -1;
	for (i = 0; i < children.num_children; i++)
		if (children.process_id[i] == pid) {
			child_index = i;
			break;
		}

	if (child_index != -1)
		TerminateProcess(children.handles[child_index], 0);
	return 0;
}


int waitpid(int pid, int *status, int options) {
	DWORD index, ret, ret_id, exit_code, timeout = 0;
	HANDLE process = NULL;

	debug3("waitpid - pid:%d, options:%d", pid, options);
	if (options & (~WNOHANG)) {
		errno = ENOTSUP;
		DebugBreak();
		return -1;
	}

	if ((pid < -1) || (pid == 0)) {
		errno = ENOTSUP;
		DebugBreak();
		return -1;
	}

	if (children.num_children == 0) {
		errno = ECHILD;
		return -1;
	}

	if (pid > 0) {
		if (options != 0) {
			errno = ENOTSUP;
			DebugBreak();
			return -1;
		}
		/* find entry in table */
		for (index = 0; index < children.num_children; index++)
			if (children.process_id[index] == pid)
				break;

		if (index == children.num_children) {
			errno = ECHILD;
			return -1;
		}

		process = children.handles[index];
		ret = WaitForSingleObject(process, INFINITE);
		if (ret != WAIT_OBJECT_0)
			DebugBreak();//fatal

		ret_id = children.process_id[index];
		GetExitCodeProcess(process, &exit_code);
		/* process handle will be closed when its removed from list */
		sw_remove_child_at_index(index);
		if (status)
			*status = exit_code;
		return ret_id;
	}

	/* pid = -1*/
	timeout = INFINITE;
	if (options & WNOHANG)
		timeout = 0;
	ret = WaitForMultipleObjects(children.num_children, children.handles, FALSE, timeout);
	if ((ret >= WAIT_OBJECT_0) && (ret < (WAIT_OBJECT_0 + children.num_children))) {
		index = ret - WAIT_OBJECT_0;
		process = children.handles[index];
		ret_id = children.process_id[index];
		GetExitCodeProcess(process, &exit_code);
		/* process handle will be closed when its removed from list */
		sw_remove_child_at_index(index);
		if (status)
			*status = exit_code;
		return ret_id;
	}
	else if (ret == WAIT_TIMEOUT) {
		/* TODO - assert that WNOHANG  was specified*/
		return 0;
	}

	DebugBreak();//fatal
	return -1;
}

void
sw_cleanup_child_zombies() {
	int pid = 1;
	while (pid > 0) {
		pid = waitpid(-1, NULL, WNOHANG);
	}
}