/*
 * Author: NoMachine <developers@nomachine.com>
 *
 * Copyright (c) 2009, 2010 NoMachine
 * All rights reserved
 *
 * Support functions and system calls' replacements needed to let the
 * software run on Win32 based operating systems.
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

#include "includes.h"

#include <windows.h>

/* Difference in us between UNIX Epoch and Win32 Epoch */
#define EPOCH_DELTA_US  11644473600000000ULL

int
gettimeofday (struct timeval *tv, void *tz)
{
	union
	{
		FILETIME ft;
		unsigned long long ns;
	} timehelper;
	unsigned long long us;

	/* Fetch time since Jan 1, 1601 in 100ns increments */
	GetSystemTimeAsFileTime(&timehelper.ft);

	/* Convert to microseconds from 100 ns units */
	us = timehelper.ns / 10;

	/* Remove the epoch difference */
	us -= EPOCH_DELTA_US;

	/* Stuff result into the timeval */
	tv->tv_sec = (long) (us / 1000000ULL);
	tv->tv_usec = (long) (us % 1000000ULL);

	return 0;
}
