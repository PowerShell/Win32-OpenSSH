/*
 * Author: Microsoft Corp.
 *
 * Copyright (c) 2017 Microsoft Corp.
 * All rights reserved
 *
 * This file is responsible for terminal emulation related network calls to 
 * invoke ANSI parsing engine.
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

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <windows.h>
#include "ansiprsr.h"
#include "inc\utf.h"
#include "console.h"

#define dwBuffer 4096

extern BOOL isAnsiParsingRequired;
extern bool gbVTAppMode;
BOOL isFirstPacket = TRUE;

/*
 * Server will always be returning a sequence of ANSI control characters which the client
 * protocol can either passthru directly to the console or transform based on an output terminal
 * type. We're not using termcap so we're only supporting the ANSI (vt100) sequences that
 * are hardcoded in the server and will be transformed to Windows Console commands.
 */
void
processBuffer(HANDLE handle, char *buf, size_t len, unsigned char **respbuf, size_t *resplen)
{
	unsigned char *pszNewHead = NULL;
	unsigned char *pszHead = NULL;
	unsigned char *pszTail = NULL;
	const char *applicationModeSeq = "\x1b[?1h";
	const int applicationModeSeqLen = (int)strlen(applicationModeSeq);
	const char *normalModeSeq = "\x1b[?1l";
	const int normalModeSeqLen = (int)strlen(normalModeSeq);
	const char *clsSeq = "\x1b[2J";

	if (len == 0)
		return;

	if (false == isAnsiParsingRequired) {
		if(isFirstPacket) {
			isFirstPacket = FALSE;
			/* Windows server at first sends the "cls" after the connection is established.
			 * There is a bug in the conhost which causes the visible window data to loose so to
			 * mitigate that issue we need to first move the visible window so that the cursor is at the top of the visible window.
			 */
			if (strstr(buf, clsSeq))
				ConMoveCursorTopOfVisibleWindow();
		}

		if(len >= applicationModeSeqLen && strstr(buf, applicationModeSeq))
			gbVTAppMode = true;
		else if(len >= normalModeSeqLen && strstr(buf, normalModeSeq))
			gbVTAppMode = false;

		/* Console has the capability to parse so pass the raw buffer to console directly */
		ConRestoreViewRect(); /* Restore the visible window, otherwise WriteConsoleW() gets messy */
		wchar_t* t = utf8_to_utf16(buf);
		WriteConsoleW(handle, t, (DWORD)wcslen(t), 0, 0);
		free(t);		
		ConSaveViewRect();
		return;
	}

	/* Transform a single carriage return into a single linefeed before continuing */
	if ((len == 1) && (buf[0] == 13))
		buf[0] = 10;

	pszTail = (unsigned char *)buf;
	pszHead = (unsigned char *)buf;
	pszTail += len;
	pszNewHead = pszHead;

	/*
	 * Loop through the network buffer transforming characters as necessary.
	 * The buffer will be empty after the transformation
	 * process since the buffer will contain only commands that are handled by the console API.
	 */
	do {
		pszHead = pszNewHead;
		pszNewHead = ParseBuffer(pszHead, pszTail, respbuf, resplen);

	} while ((pszNewHead != pszHead) && (pszNewHead < pszTail) && (resplen == NULL || (resplen != NULL && *resplen == 0)));
}
