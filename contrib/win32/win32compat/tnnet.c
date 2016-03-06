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

#include "ansiprsr.h"
#include "tncon.h"

#define dwBuffer 4096
 
int NetWriteString( char* pszString, size_t cbString)
{
	//return send_output_to_remote_client( sock, pszString, (int)cbString, 0 );
	return (int)cbString ;
}

size_t telProcessNetwork ( char *buf, size_t len )
{
	unsigned char szBuffer[dwBuffer + 8];
	unsigned char* pszHead = szBuffer;
	unsigned char* pszTail = szBuffer;
	size_t Result;
	unsigned char* pszNewHead;

	if (1)
	{
		Result = len ;
		pszTail = (unsigned char *)buf ;
		pszHead = (unsigned char *)buf ;

		pszTail += Result;

		pszNewHead = pszHead;

		do 
		{
			pszHead = pszNewHead;
			pszNewHead = ParseBuffer(pszHead, pszTail);
		} while ((pszNewHead != pszHead) && (pszNewHead < pszTail));

		if ( pszNewHead >= pszTail )
		{
			// Everything is okay and we will reset variables and continue
			pszTail = pszHead = szBuffer;
		} 
		else 
		{
			MoveMemory(szBuffer, pszNewHead, pszTail - pszNewHead);
			pszTail = szBuffer + (pszTail - pszNewHead);
			pszHead = szBuffer;
		}
	}

	return len;
}
