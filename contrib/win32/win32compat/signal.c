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

/* pending signals to be processed s*/
sigset_t pending_signals;

/* signal handler table*/
struct {
	sighandler_t handler;
	sighandler_t default_handler;
	DWORD disposition;

} signal_info[W32_SIGMAX];

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
		QueueUserAPC(sigint_APCProc, main_thread, NULL);
	}
}

void 
sw_init_signal_handler_table() {
	int i;

	/* TODO SetConsoleCtrlHandler */
	//signal(SIGINT, native_sig_handler);
	sigemptyset(&pending_signals);
	memset(&signal_info, 0, sizeof(signal_info));
	for (i = 0; i < W32_SIGMAX; i++) {

	}

}

/* child processes */
#define MAX_CHILDREN 50
struct _children {
	HANDLE handles[MAX_CHILDREN];
	//DWORD process_id[MAX_CHILDREN];
	DWORD num_children;
} children;

int
sw_add_child(HANDLE child) {
	if (children.num_children == MAX_CHILDREN) {
		errno = ENOTSUP;
		return -1;
	}
	children.handles[children.num_children++] = child;
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
sw_alarm(unsigned int seconds) {
	LARGE_INTEGER due;
	ULONGLONG sec_passed;
	int ret = 0;

	errno = 0;
	/* cancel any live timer if seconds is 0*/
	if (seconds == 0) {
		CancelWaitableTimer(timer_info.timer);
		timer_info.ticks_at_start = 0;
		timer_info.run_time_sec = 0;
		return 0;
	}

	due.QuadPart = (-1) * seconds * 1000 * 1000 *10; //100 nanosec intervals
	/* this call resets the timer if it is already active */
	if (!SetWaitableTimer(timer_info.timer, &due, 0, sigalrm_APC, NULL, FALSE)) {
		errno = EOTHER;
		return -1;
	}

	/* if timer was already ative, return when it was due */
	if (timer_info.ticks_at_start) {
		sec_passed = (GetTickCount64() - timer_info.ticks_at_start) / 1000;
		if (sec_passed < timer_info.run_time_sec)
			ret = timer_info.run_time_sec - sec_passed;
	}
	timer_info.ticks_at_start = GetTickCount64();
	timer_info.run_time_sec = seconds;
	return ret;
}

static int
sw_init_timer() {
	memset(&timer_info, 0, sizeof(timer_info));
	timer_info.timer = CreateWaitableTimer(NULL, FALSE, NULL);
	if (timer_info.timer == NULL) {
		errno = ENOMEM;
		return -1;
	}
}

sighandler_t 
sw_signal(int signum, sighandler_t handler) {
	sighandler_t prev;
	if (signum >= W32_SIGMAX) {
		errno = EINVAL;
		return SIG_ERR;
	}

	prev = signal_info[signum].disposition;
	if (prev == W32_SIG_USR)
		prev = signal_info[signum].handler;

	/* standard dispositions */
	if ((handler == W32_SIG_DFL) || (handler == W32_SIG_DFL)) {
		signal_info[signum].disposition = handler;
		signal_info[signum].handler = NULL;
	}
	else { /* user defined handler*/
		signal_info[signum].disposition = W32_SIG_USR;
		signal_info[signum].handler = handler;
	}
	return prev;
}

int 
sw_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
	/* this is only used by sshd to block SIGCHLD while doing waitpid() */
	/* our implementation of waidpid() is never interrupted, so no need to implement this*/
	return 0;
}

int 
sw_raise(int sig) {
	if (sig == W32_SIGSEGV)
		raise(SIGSEGV); /* raise native exception handler*/
	
	if (signal_info[sig].disposition == W32_SIG_IGN)
		return 0;
	else if (signal_info[sig].disposition == W32_SIG_DFL)
		signal_info[sig].default_handler(sig);
	else
		signal_info[sig].handler(sig);

	return 0;
}

int 
sw_kill(int pid, int sig) {

	if (pid == GetCurrentProcessId())
		return sw_raise(sig);

	/* only SIGTERM supported for child processes*/
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

	for (i = 0; i < (sizeof(exp) / sizeof(exp[0])); i++) {
		if (signal_info[exp[i]].disposition != W32_SIG_IGN) {
			raise(exp[i]);
			sig_int = TRUE;
		}
	}
		
	if (sig_int) {
		/* processed a signal that was not set to be ignored */
		errno = SIGINT;
		return -1;
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
	DWORD num_all_events = num_events + children.num_children;

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
			if (children.num_children && ((ret - WAIT_OBJECT_0) < children.num_children)) 
				sigaddset(&pending_signals, W32_SIGCHLD);
				/* TODO - enable this once all direct closes are removed in core code*/
				//sw_remove_child(ret - WAIT_OBJECT_0);
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
	return;
}


int
sw_initialize() {
	memset(&children, 0, sizeof(children));
	sw_init_signal_handler_table();
	if (sw_init_timer() != 0)
		return -1;
	return 0;
}
