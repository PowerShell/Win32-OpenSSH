/* tnnet.c
 * Author: Pragma Systems, Inc. <www.pragmasys.com>
 * Contribution by Pragma Systems, Inc. for Microsoft openssh win32 port
 * Copyright (c) 2011, 2015 Pragma Systems, Inc.
 * All rights reserved
 * 
 * Contains terminal emulation related network calls to invoke ANSI parsing engine
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice.
 * 2. Binaries produced provide no direct or implied warranties or any
 *    guarantee of performance or suitability.
 */
 
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include <winsock2.h>
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
