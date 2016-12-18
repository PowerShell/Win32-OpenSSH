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
/* conio.c
 *
 * Inserts data into Windows Console Input. Needed WriteToConsole() API implemented.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>

#include "console.h"
#include <conio.h>

COORD	lastCursorLoc = { 0, 0 };
BYTE KeyboardState[256];
INPUT_RECORD srec;
DWORD	dwGlobalConsoleMode ;

int WriteToConsole(HANDLE fd, unsigned char *buf, size_t len, size_t *dwWritten, void *flag)
{
	static KEY_EVENT_RECORD *pkey;
	static KEY_EVENT_RECORD *pkey2;
	static INPUT_RECORD irec[2];
	static BOOL bInitKeyboard = TRUE;
	size_t ctr;
	int rc;
	DWORD dwRecords;
	DWORD vkey;
	BOOL	bNeedToWait = TRUE;
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	int scr_width = 80; /* screen horizontal width, e.g. 80 */
	int scr_height = 25; /* screen vertical length, e.g. 25 */
	char tmpbuf[2];
	int local_echo = 0;

	/*
	* Need to set pkey and pkey2 which we use below. Initialize the keyboard state table.
	*/
	if (bInitKeyboard)
	{
		GetKeyboardState(KeyboardState);
		bInitKeyboard = FALSE;
		srec.EventType = KEY_EVENT;
		srec.Event.KeyEvent.bKeyDown = TRUE;
		srec.Event.KeyEvent.wRepeatCount = 1;
		srec.Event.KeyEvent.wVirtualKeyCode = 0x10;
		srec.Event.KeyEvent.wVirtualScanCode = 0x2a;
		srec.Event.KeyEvent.uChar.AsciiChar = 0;
		srec.Event.KeyEvent.uChar.UnicodeChar = 0;
		srec.Event.KeyEvent.dwControlKeyState = 0x10;

		irec[0].EventType = KEY_EVENT; /* init key down message */
		pkey = &(irec[0].Event.KeyEvent);
		pkey->wRepeatCount = 1;
		pkey->bKeyDown = TRUE;

		irec[1].EventType = KEY_EVENT; /* init key up message */
		pkey2 = &(irec[1].Event.KeyEvent);
		pkey2->wRepeatCount = 1;
		pkey2->bKeyDown = FALSE;
	}

	// Stream mode processing
	if (local_echo)
	{
		GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
	}

	GetConsoleMode(fd, &dwGlobalConsoleMode);

	ctr = 0;
	while (ctr < len)
	{
		if (local_echo)
		{
			GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
			lastCursorLoc.Y = csbi.dwCursorPosition.Y;
			lastCursorLoc.X = csbi.dwCursorPosition.X;
		}
		{
			pkey->dwControlKeyState = 0x00000000;
			pkey->uChar.AsciiChar = buf[ctr]; /* next char in ascii */

			mbtowc(&(pkey->uChar.UnicodeChar), (const char *)&(buf[ctr]), 1);
			vkey = VkKeyScan(pkey->uChar.AsciiChar);

			if ((BYTE)(vkey >> 8) != 0xFF) // high order word
			{
				if (vkey & 0x0100 || (KeyboardState[VK_LSHIFT] & 0x80)) /* high word gives shift, ctrl, alt status */
					pkey->dwControlKeyState |= SHIFT_PRESSED; /* shift key presssed*/
				if (vkey & 0x0200 || (KeyboardState[VK_LCONTROL] & 0x80))
					pkey->dwControlKeyState |= LEFT_CTRL_PRESSED; /* any ctrl really*/
				if ((vkey & 0x0400) || (KeyboardState[VK_LMENU] & 0x80))
					pkey->dwControlKeyState |= LEFT_ALT_PRESSED; /* any ALT really*/
			}
			if ((BYTE)vkey != 0xFF) // low order word
			{
				pkey->wVirtualKeyCode = (BYTE)vkey;
				pkey->wVirtualScanCode = MapVirtualKey(pkey->wVirtualKeyCode, 0);
				if (pkey->uChar.UnicodeChar == 0x1b)	// stream mode fix for Admark ESC sequences
					pkey->wVirtualKeyCode = 0x00db;


			}

			/* we need to mimic key up and key down */
			if (pkey->dwControlKeyState & 0x0100)
			{
				srec.Event.KeyEvent.bKeyDown = TRUE;
				srec.Event.KeyEvent.dwControlKeyState = 0x10;
				WriteConsoleInput(fd, &srec, 1, &dwRecords); /* write shift down */
				tmpbuf[0] = irec[0].Event.KeyEvent.uChar.AsciiChar;
				tmpbuf[1] = '\0';
			}

			pkey->bKeyDown = TRUE; /*since pkey is mucked by others we do it again*/

			/* dup these into key up message structure from key down message */
			pkey2->wVirtualKeyCode = pkey->wVirtualKeyCode;
			pkey2->wVirtualScanCode = pkey->wVirtualScanCode;
			pkey2->uChar.AsciiChar = pkey->uChar.AsciiChar;
			pkey2->uChar.UnicodeChar = pkey->uChar.UnicodeChar;
			pkey2->dwControlKeyState = pkey->dwControlKeyState;

			WriteConsoleInput(fd, irec, 2, &dwRecords); /* key down,up msgs */
			tmpbuf[0] = irec[0].Event.KeyEvent.uChar.AsciiChar;
			tmpbuf[1] = '\0';
			if (pkey->dwControlKeyState & 0x0100)
			{
				srec.Event.KeyEvent.bKeyDown = FALSE;
				srec.Event.KeyEvent.dwControlKeyState = 0x0;
				WriteConsoleInput(fd, &srec, 1, &dwRecords); /* write shift up */

			}
			//if ((local_echo))
			//{
			//	bNeedToWait = EchoInputCharacter(buf[ctr], &csbi.dwCursorPosition, dwGlobalConsoleMode);
			//}
		}
		ctr++;
		Sleep(0);
	}

	*dwWritten = len;

	//netflush();

	return 0;
}

	
