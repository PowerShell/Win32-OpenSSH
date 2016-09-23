/*
 * Author: Microsoft Corp.
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
/* tnnet.c
 * 
 * Contains terminal emulation related network calls to invoke ANSI parsing engine
 *
 */
 
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <windows.h>

#include <ansiprsr.h>

#define dwBuffer 4096

// Server will always be returning a sequence of ANSI control characters which the client
// protocol can either passthru directly to the console or transform based on an output terminal
// type. We're not using termcap so we're only supporting the ANSI (vt100) sequences that
// are hardcoded in the server and will be transformed to Windows Console commands.

size_t telProcessNetwork(char *buf, size_t len, unsigned char **respbuf, size_t *resplen)
{
	unsigned char szBuffer[dwBuffer + 8];

	unsigned char* pszNewHead = NULL;

    unsigned char* pszHead = NULL;
    unsigned char* pszTail = NULL;

    char *term = NULL;

    if (len == 0)
        return len;

    term = getenv("TERM");

    if (term != NULL && _stricmp(term, "passthru") == 0)
        return len;

    // Transform a single carriage return into a single linefeed before
    // continuing.
	if ((len == 1) && (buf[0] == 13))
		buf[0] = 10;

	pszTail = (unsigned char *)buf;
	pszHead = (unsigned char *)buf;

	pszTail += len;

	pszNewHead = pszHead;

    // Loop through the network buffer transforming characters as necessary.
    // The buffer will be empty after the transformation
    // process since the buffer will contain only commands that are handled by the console API.
	do {
		pszHead = pszNewHead;
		pszNewHead = ParseBuffer(pszHead, pszTail, respbuf, resplen);

	} while ((pszNewHead != pszHead) && (pszNewHead < pszTail) && (resplen == NULL || (resplen != NULL && *resplen == 0)));

    len = 0;

	return len;
}
