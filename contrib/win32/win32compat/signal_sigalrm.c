/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Copyright(c) 2015 Microsoft Corp.
* All rights reserved
*
* Helper routines to support SIGALRM 
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
#include "inc\signal.h"
#include "debug.h"

struct _timer_info timer_info;
extern sigset_t pending_signals;

static VOID CALLBACK
sigalrm_APC(_In_opt_ LPVOID lpArgToCompletionRoutine,
	    _In_ DWORD dwTimerLowValue,
	    _In_ DWORD dwTimerHighValue)
{
	sigaddset(&pending_signals, W32_SIGALRM);
}

unsigned int
w32_alarm(unsigned int sec)
{
	LARGE_INTEGER due;
	ULONGLONG sec_passed;
	int ret = 0;

	debug5("alarm() %d secs", sec);
	errno = 0;
	/* cancel any live timer if seconds is 0*/
	if (sec == 0) {
		CancelWaitableTimer(timer_info.timer);
		timer_info.ticks_at_start = 0;
		timer_info.run_time_sec = 0;
		return 0;
	}

	due.QuadPart = -10000000LL; /* 1 sec in 100 nanosec intervals */
	due.QuadPart *= sec;
	/* this call resets the timer if it is already active */
	if (!SetWaitableTimer(timer_info.timer, &due, 0, sigalrm_APC, NULL, FALSE)) {
		debug3("alram() - ERROR SetWaitableTimer() %d", GetLastError());
		return 0;;
	}

	/* if timer was already ative, return when it was due */
	if (timer_info.ticks_at_start) {
		sec_passed = (GetTickCount64() - timer_info.ticks_at_start) / 1000;
		if (sec_passed < (ULONGLONG)timer_info.run_time_sec)
			ret = (int) (timer_info.run_time_sec - sec_passed);
	}
	timer_info.ticks_at_start = GetTickCount64();
	timer_info.run_time_sec = sec;
	
	return ret;
}

int
sw_init_timer()
{
	memset(&timer_info, 0, sizeof(timer_info));
	timer_info.timer = CreateWaitableTimer(NULL, TRUE, NULL);
	if (timer_info.timer == NULL) {
		errno = ENOMEM;
		return -1;
	}

	return 0;
}