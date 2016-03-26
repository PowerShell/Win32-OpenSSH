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
#include <signal.h>
#include "inc\defs.h"

/* pending signals to be processed */
sigset_t pending_signals;

/* signal handler table*/
sighandler_t sig_handlers[W32_SIGMAX];

static VOID CALLBACK 
sigint_APCProc(
	_In_ ULONG_PTR dwParam
	) {
	sigaddset(&pending_signals, W32_SIGINT);
}

static void 
native_sig_handler(int signal)
{
	if (signal == SIGINT) {
		/* Queue signint APC */
		QueueUserAPC(sigint_APCProc, main_thread, (ULONG_PTR)NULL);
	}
}

void 
sw_init_signal_handler_table() {
	int i;

	/* TODO SetConsoleCtrlHandler */
	//signal(SIGINT, native_sig_handler);
	sigemptyset(&pending_signals);
	/* this automatically sets all to SIG_DFL (0)*/
	memset(sig_handlers, 0, sizeof(sig_handlers));
}

/* child processes */
#define MAX_CHILDREN 50
struct _children {
	HANDLE handles[MAX_CHILDREN];
	DWORD process_id[MAX_CHILDREN];
	DWORD num_children;
} children;

int
sw_add_child(HANDLE child, DWORD pid) {
	if (children.num_children == MAX_CHILDREN) {
		errno = ENOTSUP;
		return -1;
	}
	children.handles[children.num_children] = child;
	children.process_id[children.num_children] = pid;
	children.num_children++;
	return 0;
}

int
sw_remove_child_at_index(DWORD index) {
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
sw_remove_child(HANDLE child) {
	HANDLE* handles = children.handles;
	DWORD num_children = children.num_children;

	while (num_children) {
		if (*handles == child)
			return sw_remove_child_at_index(children.num_children - num_children);
		handles++;
		num_children--;
	}

	errno = EINVAL;
	return -1;
}

int waitpid(int pid, int *status, int options) {
	DWORD index, ret, ret_id, exit_code, timeout = 0;
	HANDLE process = NULL;

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
		CloseHandle(process);
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
		CloseHandle(process);
		sw_remove_child_at_index(index);
		if (status)
			*status = exit_code;
		return ret_id;
	}
	else if (ret == WAIT_TIMEOUT) {
		/* assert that WNOHANG  was specified*/
		return 0;
	}

	DebugBreak();//fatal
	return -1;
}

static void
sw_cleanup_child_zombies() {
	int pid = 1;
	while (pid > 0) {
		pid = waitpid(-1, NULL, WNOHANG);
	}
}

struct {
	HANDLE timer;
	ULONGLONG ticks_at_start; /* 0 if timer is not live */
	__int64 run_time_sec; /* time in seconds, timer is set to go off from ticks_at_start */
} timer_info;


VOID CALLBACK 
sigalrm_APC(
	_In_opt_ LPVOID lpArgToCompletionRoutine,
	_In_     DWORD  dwTimerLowValue,
	_In_     DWORD  dwTimerHighValue
	) {
	sigaddset(&pending_signals, W32_SIGALRM);
}

unsigned int 
sw_alarm(unsigned int sec) {
	LARGE_INTEGER due;
	ULONGLONG sec_passed;
	int ret = 0;

	errno = 0;
	/* cancel any live timer if seconds is 0*/
	if (sec == 0) {
		CancelWaitableTimer(timer_info.timer);
		timer_info.ticks_at_start = 0;
		timer_info.run_time_sec = 0;
		return 0;
	}

	due.QuadPart = -10000000LL; //1 sec in 100 nanosec intervals
	due.QuadPart *= sec;
	/* this call resets the timer if it is already active */
	if (!SetWaitableTimer(timer_info.timer, &due, 0, sigalrm_APC, NULL, FALSE)) {
		debug("alram() - ERROR SetWaitableTimer() %d", GetLastError());
		return 0;;
	}

	/* if timer was already ative, return when it was due */
	if (timer_info.ticks_at_start) {
		sec_passed = (GetTickCount64() - timer_info.ticks_at_start) / 1000;
		if (sec_passed < timer_info.run_time_sec)
			ret = timer_info.run_time_sec - sec_passed;
	}
	timer_info.ticks_at_start = GetTickCount64();
	timer_info.run_time_sec = sec;
	return ret;
}

static int
sw_init_timer() {
	memset(&timer_info, 0, sizeof(timer_info));
	timer_info.timer = CreateWaitableTimer(NULL, TRUE, NULL);
	if (timer_info.timer == NULL) {
		errno = ENOMEM;
		return -1;
	}
	return 0;
}

sighandler_t 
sw_signal(int signum, sighandler_t handler) {
	sighandler_t prev;
	if (signum >= W32_SIGMAX) {
		errno = EINVAL;
		return W32_SIG_ERR;
	}

	prev = sig_handlers[signum]; 
	sig_handlers[signum] = handler;
	return prev;
}

int 
sw_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
	/* this is only used by sshd to block SIGCHLD while doing waitpid() */
	/* our implementation of waidpid() is never interrupted, so no need to implement this for now*/
	return 0;
}



int 
sw_raise(int sig) {
	if (sig == W32_SIGSEGV)
		raise(SIGSEGV); /* raise native exception handler*/

	if (sig >= W32_SIGMAX) {
		errno = EINVAL;
		return -1;
	}

	/* execute user specified disposition */
	if (sig_handlers[sig] > W32_SIG_IGN) {
		sig_handlers[sig](sig);
		return 0;
	}

	/* if set to ignore, nothing to do */
	if (sig_handlers[sig] == W32_SIG_IGN)
		return 0;
		
	/* execute any default handlers */
	switch (sig) {
	case W32_SIGCHLD:
		sw_cleanup_child_zombies();
		break;
	case W32_SIGINT:
		/* TODO - execute sigint default handler */
		break;
	default:
		break;
	}

	return 0;
}

int 
sw_kill(int pid, int sig) {

	if (pid == GetCurrentProcessId())
		return sw_raise(sig);

	/*  for child processes - only SIGTERM supported*/
	/* TODO implement kill(SIGTERM) for child processes */
	return 0;
}


/* processes pending signals, return EINTR if any are processed*/
static int 
sw_process_pending_signals() {
	sigset_t pending_tmp = pending_signals;
	BOOL sig_int = FALSE; /* has any signal actually interrupted */

	int i, exp[] = { W32_SIGCHLD , W32_SIGINT , W32_SIGALRM };

	/* check for expected signals*/
	for (i = 0; i < (sizeof(exp) / sizeof(exp[0])); i++)
		sigdelset(&pending_tmp, exp[i]);
	if (pending_tmp) {
		/* unexpected signals queued up */
		errno = ENOTSUP;
		DebugBreak();
		return -1;
	}

	/* take pending_signals local to prevent recursion in wait_for_any* loop */
	pending_tmp = pending_signals;
	pending_signals = 0;
	for (i = 0; i < (sizeof(exp) / sizeof(exp[0])); i++) {
		if (sigismember(&pending_tmp, exp[i])) {
			if (sig_handlers[exp[i]] != W32_SIG_IGN) {
				sw_raise(exp[i]);
				sig_int = TRUE;
			}

			sigdelset(&pending_tmp, exp[i]);
		}
	}
		

	/* by now all pending signals should have been taken care of*/
	if (pending_tmp)
		DebugBreak();

	if (sig_int) {
		/* processed a signal that was set not to be ignored */
		debug("process_queued_signals: WARNING - A signal has interrupted and was processed");
		/* there are parts of code that do not tolerate EINT during IO, so returning 0 here*/
		//errno = EINTR;
		//return -1;
	}

	return 0;
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
	DWORD num_all_events;

	num_all_events = num_events + children.num_children;

	if (num_all_events > MAXIMUM_WAIT_OBJECTS) {
		errno = ENOTSUP;
		return -1;
	}

	/* TODO assert that there are no pending signals - signals are only caught during waits*/
	if (pending_signals)
		DebugBreak();

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
				sigaddset(&pending_signals, W32_SIGCHLD);
				//errno = EINTR;
				//return -1;
			}
		}
		else if (ret == WAIT_IO_COMPLETION) {
			/* APC processed due to IO or signal*/
		}
		else if (ret == WAIT_TIMEOUT) {
			/* timed out */
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
			/* APC processed due to IO or signal*/
		}
		else if (ret == 0) {
			/* timed out */
			return 0;
		}
		else { //some other error
			errno = EOTHER;
			debug("ERROR: unxpected SleepEx error: %d", ret);
			return -1;
		}
	}

	if (pending_signals) {
		return sw_process_pending_signals();
	}
	return 0;
}


int
sw_initialize() {
	memset(&children, 0, sizeof(children));
	sw_init_signal_handler_table();
	if (sw_init_timer() != 0)
		return -1;
	return 0;
}
