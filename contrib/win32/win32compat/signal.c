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
	/* TODO - implement signal catching and handling */
	if (num_events) {
		DWORD ret = WaitForMultipleObjectsEx(num_events, events, FALSE, 
		    milli_seconds, TRUE);
		if ((ret >= WAIT_OBJECT_0) && (ret <= WAIT_OBJECT_0 + num_events - 1)) {
			//woken up by event signalled
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