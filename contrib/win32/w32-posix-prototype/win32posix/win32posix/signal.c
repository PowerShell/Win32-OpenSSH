#include "w32fd.h"
#include <errno.h>

//signal handlers

//signal queue

//wakes on
// - any signals (errno = EINTR )
// - any of the supplied events set 
// - any APCs caused by IO completions 
int wait_for_any_event(HANDLE* events, int num_events, DWORD milli_seconds)
{
    //todo - implement signal catching and handling
    if (num_events)
    {
        DWORD ret = WaitForMultipleObjectsEx(num_events, events, FALSE, milli_seconds, TRUE);
        if ((ret >= WAIT_OBJECT_0) && (ret <= WAIT_OBJECT_0 + num_events - 1)) {
            //woken up by event signalled
            return 0;
        }
        else if (ret == WAIT_IO_COMPLETION) {
            return 0;
        }
        else if (ret == WAIT_TIMEOUT) {
            errno = ETIMEDOUT;
            return -1;
        }
        else { //some other error
            errno = EOTHER;
            return -1;
        }
    }
    else
    {
        DWORD ret = SleepEx(milli_seconds, TRUE);
        if (ret == WAIT_IO_COMPLETION) {
            return 0;
        }
        else if (ret == 0) {
            //timed out
            errno =  ETIMEDOUT;
            return -1;
        }
        else { //some other error
            errno = EOTHER;
            return -1;
        }
    }
}