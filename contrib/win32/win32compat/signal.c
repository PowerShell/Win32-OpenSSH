/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
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