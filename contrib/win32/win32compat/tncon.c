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
/* tncon.c
 *
 * Console reading calls for building an emulator over Windows Console. MS win32 port of ssh.exe client uses it.
 *
*/
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>


#include <windows.h>

#include "ansiprsr.h"
#include "tncon.h"
#include "tnnet.h"

extern bool gbVTAppMode;

char *glob_out = NULL ;
int   glob_outlen = 0;
int	  glob_space = 0;

unsigned char  NAWSSTR[] = { "\xff\xfa\x1f\x00\x00\x00\x00\xff\xf0" };

extern int ScreenY;
extern int ScreenX;

extern int ScrollTop;
extern int ScrollBottom;

TelParams Parameters;
TelParams* pParams = &Parameters;

// For our case, in NetWriteString2(), we do not use socket, but write the out going data to
// a global buffer setup by ReadConsoleForTermEmul() function below
int NetWriteString2(SOCKET sock, char* source, size_t len, int options)
{
	while (len > 0) {
		if (glob_outlen >= glob_space)
			return glob_outlen;
		*glob_out++ = *source++ ;
		len--;
		glob_outlen++;
	}

	return glob_outlen;
}

void ConInputInitParams(void)
{
    DWORD	dwMode = 0;

    memset(&Parameters, '\0', sizeof(TelParams));

	// Default values
	Parameters.szDebugInputFile = NULL;
	Parameters.fDebugWait = FALSE;
	Parameters.nReceiveCRLF = ENUM_LF;
	Parameters.sleepChar = '`';
	Parameters.menuChar = '\035'; // CTRL-]
	Parameters.pAltKey = "\x01";		// default 
	
	HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);

    if (hInput && hInput != INVALID_HANDLE_VALUE) {

        GetConsoleMode(hInput, &dwMode);
        SetConsoleMode(hInput, (dwMode & ~(ENABLE_LINE_INPUT |
            ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_MOUSE_INPUT)) | ENABLE_WINDOW_INPUT);
    }
}

BOOL DataAvailable(HANDLE h)
{
    INPUT_RECORD irec;
    DWORD events_read = 0;

    if (!PeekConsoleInput(h, &irec, 1, &events_read)) {
        return FALSE;
    }

    if (events_read) {
        return TRUE;
    }

	return FALSE;
}

int ReadConsoleForTermEmul(HANDLE hInput, char *destin, int destinlen)
{
    HANDLE hHandle[] = { hInput, NULL };
    DWORD nHandle = 1;
    DWORD dwInput = 0;
    DWORD dwControlKeyState = 0;
    DWORD rc = 0;

    unsigned char szResponse[50];
    unsigned char octets[20];

    char aChar = 0;

    INPUT_RECORD InputRecord;

    BOOL bCapsOn = FALSE;
    BOOL bShift = FALSE;

    glob_out = destin;
    glob_space = destinlen;
    glob_outlen = 0;

    while (DataAvailable(hInput))
    {
        if (glob_outlen >= destinlen)
            return glob_outlen; 

        ReadConsoleInput(hInput, &InputRecord, 1, &dwInput);

        switch (InputRecord.EventType)
        {
            case WINDOW_BUFFER_SIZE_EVENT:
                memcpy(szResponse, NAWSSTR, 9);
                szResponse[4] = ConScreenSizeX();
                szResponse[6] = ConWindowSizeY();
                ScreenX = ConScreenSizeX();
                ScreenY = ConWindowSizeY();	
                break;

            case FOCUS_EVENT:
            case MENU_EVENT:
                break;

            case KEY_EVENT:
                bCapsOn = (InputRecord.Event.KeyEvent.dwControlKeyState & CAPSLOCK_ON);
                bShift = (InputRecord.Event.KeyEvent.dwControlKeyState & SHIFT_PRESSED);
                dwControlKeyState = InputRecord.Event.KeyEvent.dwControlKeyState & 
                    ~(CAPSLOCK_ON | ENHANCED_KEY | NUMLOCK_ON | SCROLLLOCK_ON);

                if (InputRecord.Event.KeyEvent.bKeyDown)
                {
                    int n = WideCharToMultiByte(
                        GetConsoleCP(), 
                        0, 
                        &(InputRecord.Event.KeyEvent.uChar.UnicodeChar), 
                        1, 
                        (LPSTR)octets, 
                        20, 
                        NULL, 
                        NULL);

                    if (pParams->fLocalEcho) {
                        ConWriteString((char *)octets, n);
                    }

                    if (dwControlKeyState == LEFT_ALT_PRESSED ||
                        dwControlKeyState == RIGHT_ALT_PRESSED)
                        NetWriteString2(pParams->Socket, (char *)pParams->pAltKey, 1, 0);

                    switch (InputRecord.Event.KeyEvent.uChar.UnicodeChar)
                    {
                        case 0xd:
                            if (pParams->nReceiveCRLF == ENUM_LF)
                                NetWriteString2(pParams->Socket, "\r", 1, 0);
                            else
                                NetWriteString2(pParams->Socket, "\r\n", 2, 0);
                            break;
  
                        case VK_ESCAPE:
                            NetWriteString2(pParams->Socket, (char *)ESCAPE_KEY, 1, 0);
                            break;

                        default:
                            switch (InputRecord.Event.KeyEvent.wVirtualKeyCode)
                            {
                                case VK_UP:
                                    NetWriteString2(pParams->Socket, (char *)(gbVTAppMode ? APP_UP_ARROW : UP_ARROW), 3, 0);
                                    break;
                                case VK_DOWN:
                                    NetWriteString2(pParams->Socket, (char *)(gbVTAppMode ? APP_DOWN_ARROW : DOWN_ARROW), 3, 0);
                                    break;
                                case VK_RIGHT:
                                    NetWriteString2(pParams->Socket, (char *)(gbVTAppMode ? APP_RIGHT_ARROW : RIGHT_ARROW), 3, 0);
                                    break;
                                case VK_LEFT:
                                    NetWriteString2(pParams->Socket, (char *)(gbVTAppMode ? APP_LEFT_ARROW : LEFT_ARROW), 3, 0);
                                    break;
                                case VK_F1:
                                    if (dwControlKeyState == 0)
                                    {
                                        if (pParams->bVT100Mode)
                                            NetWriteString2(pParams->Socket, (char *)VT100_PF1_KEY, strlen(VT100_PF1_KEY), 0);
                                        else
                                            NetWriteString2(pParams->Socket, (char *)PF1_KEY, strlen(PF1_KEY), 0);
                                    }
                                    else if (dwControlKeyState == SHIFT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_PF1_KEY, strlen(SHIFT_PF1_KEY), 0);
                                    else if (dwControlKeyState == LEFT_CTRL_PRESSED ||
                                             dwControlKeyState == RIGHT_CTRL_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)CTRL_PF1_KEY, strlen(CTRL_PF1_KEY), 0);
                                    else if (dwControlKeyState == LEFT_ALT_PRESSED ||
                                             dwControlKeyState == RIGHT_ALT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)ALT_PF1_KEY, strlen(ALT_PF1_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_CTRL_PF1_KEY, strlen(SHIFT_ALT_CTRL_PF1_KEY), 0);
                                    else if ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)ALT_CTRL_PF1_KEY, strlen(ALT_CTRL_PF1_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_PF1_KEY, strlen(SHIFT_ALT_PF1_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_CTRL_PF1_KEY, strlen(SHIFT_CTRL_PF1_KEY), 0);
                                    break;
                                case VK_F2:
                                    if (dwControlKeyState == 0)
                                    {
                                        if (pParams->bVT100Mode)
                                            NetWriteString2(pParams->Socket, (char *)VT100_PF2_KEY, strlen(VT100_PF2_KEY), 0);
                                        else
                                            NetWriteString2(pParams->Socket, (char *)PF2_KEY, strlen(PF2_KEY), 0);
                                    }
                                    else if (dwControlKeyState == SHIFT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_PF2_KEY, strlen(SHIFT_PF2_KEY), 0);
                                    else if (dwControlKeyState == LEFT_CTRL_PRESSED ||
                                             dwControlKeyState == RIGHT_CTRL_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)CTRL_PF2_KEY, strlen(CTRL_PF2_KEY), 0);
                                    else if (dwControlKeyState == LEFT_ALT_PRESSED ||
                                             dwControlKeyState == RIGHT_ALT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)ALT_PF2_KEY, strlen(ALT_PF2_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_CTRL_PF2_KEY, strlen(SHIFT_ALT_CTRL_PF2_KEY), 0);
                                    else if ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)ALT_CTRL_PF2_KEY, strlen(ALT_CTRL_PF2_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_PF2_KEY, strlen(SHIFT_ALT_PF2_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_CTRL_PF2_KEY, strlen(SHIFT_CTRL_PF2_KEY), 0);
                                    break;
                                case VK_F3:
                                    if (dwControlKeyState == 0)
                                    {
                                        if (pParams->bVT100Mode)
                                            NetWriteString2(pParams->Socket, (char *)VT100_PF3_KEY, strlen(VT100_PF3_KEY), 0);
                                        else
                                            NetWriteString2(pParams->Socket, (char *)PF3_KEY, strlen(PF3_KEY), 0);
                                    }
                                    else if (dwControlKeyState == SHIFT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_PF3_KEY, strlen(SHIFT_PF3_KEY), 0);
                                    else if (dwControlKeyState == LEFT_CTRL_PRESSED ||
                                             dwControlKeyState == RIGHT_CTRL_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)CTRL_PF3_KEY, strlen(CTRL_PF3_KEY), 0);
                                    else if (dwControlKeyState == LEFT_ALT_PRESSED ||
                                             dwControlKeyState == RIGHT_ALT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)ALT_PF3_KEY, strlen(ALT_PF3_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_CTRL_PF3_KEY, strlen(SHIFT_ALT_CTRL_PF3_KEY), 0);
                                    else if ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)ALT_CTRL_PF3_KEY, strlen(ALT_CTRL_PF3_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_PF3_KEY, strlen(SHIFT_ALT_PF3_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_CTRL_PF3_KEY, strlen(SHIFT_CTRL_PF3_KEY), 0);
                                    break;
                                case VK_F4:
                                    if (dwControlKeyState == 0)
                                    {
                                        if (pParams->bVT100Mode)
                                            NetWriteString2(pParams->Socket, (char *)VT100_PF4_KEY, strlen(VT100_PF4_KEY), 0);
                                        else
                                            NetWriteString2(pParams->Socket, (char *)PF4_KEY, strlen(PF4_KEY), 0);
                                    }
                                    else if (dwControlKeyState == SHIFT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_PF4_KEY, strlen(SHIFT_PF4_KEY), 0);
                                    else if (dwControlKeyState == LEFT_CTRL_PRESSED ||
                                             dwControlKeyState == RIGHT_CTRL_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)CTRL_PF4_KEY, strlen(CTRL_PF4_KEY), 0);
                                    else if (dwControlKeyState == LEFT_ALT_PRESSED ||
                                             dwControlKeyState == RIGHT_ALT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)ALT_PF4_KEY, strlen(ALT_PF4_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_CTRL_PF4_KEY, strlen(SHIFT_ALT_CTRL_PF4_KEY), 0);
                                    else if ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)ALT_CTRL_PF4_KEY, strlen(ALT_CTRL_PF4_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_PF4_KEY, strlen(SHIFT_ALT_PF4_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_CTRL_PF4_KEY, strlen(SHIFT_CTRL_PF4_KEY), 0);
                                    break;
                                case VK_F5:
                                    if (dwControlKeyState == 0)
                                    {
                                        NetWriteString2(pParams->Socket, (char *)PF5_KEY, strlen(PF5_KEY), 0);
                                    }
                                    else if (dwControlKeyState == SHIFT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_PF5_KEY, strlen(SHIFT_PF5_KEY), 0);
                                    else if (dwControlKeyState == LEFT_CTRL_PRESSED ||
                                             dwControlKeyState == RIGHT_CTRL_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)CTRL_PF5_KEY, strlen(CTRL_PF5_KEY), 0);
                                    else if (dwControlKeyState == LEFT_ALT_PRESSED ||
                                             dwControlKeyState == RIGHT_ALT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)ALT_PF5_KEY, strlen(ALT_PF5_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_CTRL_PF5_KEY, strlen(SHIFT_ALT_CTRL_PF5_KEY), 0);
                                    else if ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)ALT_CTRL_PF5_KEY, strlen(ALT_CTRL_PF5_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_PF5_KEY, strlen(SHIFT_ALT_PF5_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_CTRL_PF5_KEY, strlen(SHIFT_CTRL_PF5_KEY), 0);
                                    break;
                                case VK_F6:
                                    if (dwControlKeyState == 0)
                                        NetWriteString2(pParams->Socket, (char *)PF6_KEY, strlen(PF6_KEY), 0);
                                    else if (dwControlKeyState == SHIFT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_PF6_KEY, strlen(SHIFT_PF6_KEY), 0);
                                    else if (dwControlKeyState == LEFT_CTRL_PRESSED ||
                                             dwControlKeyState == RIGHT_CTRL_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)CTRL_PF6_KEY, strlen(CTRL_PF6_KEY), 0);
                                    else if (dwControlKeyState == LEFT_ALT_PRESSED ||
                                             dwControlKeyState == RIGHT_ALT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)ALT_PF6_KEY, strlen(ALT_PF6_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_CTRL_PF6_KEY, strlen(SHIFT_ALT_CTRL_PF6_KEY), 0);
                                    else if ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)ALT_CTRL_PF6_KEY, strlen(ALT_CTRL_PF6_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_PF6_KEY, strlen(SHIFT_ALT_PF6_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_CTRL_PF6_KEY, strlen(SHIFT_CTRL_PF6_KEY), 0);
                                    break;
                                case VK_F7:
                                    if (dwControlKeyState == 0)
                                        NetWriteString2(pParams->Socket, (char *)PF7_KEY, strlen(PF7_KEY), 0);
                                    else if (dwControlKeyState == SHIFT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_PF7_KEY, strlen(SHIFT_PF7_KEY), 0);
                                    else if (dwControlKeyState == LEFT_CTRL_PRESSED ||
                                             dwControlKeyState == RIGHT_CTRL_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)CTRL_PF7_KEY, strlen(CTRL_PF7_KEY), 0);
                                    else if (dwControlKeyState == LEFT_ALT_PRESSED ||
                                             dwControlKeyState == RIGHT_ALT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)ALT_PF7_KEY, strlen(ALT_PF7_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_CTRL_PF7_KEY, strlen(SHIFT_ALT_CTRL_PF7_KEY), 0);
                                    else if ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)ALT_CTRL_PF7_KEY, strlen(ALT_CTRL_PF7_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_PF7_KEY, strlen(SHIFT_ALT_PF7_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_CTRL_PF7_KEY, strlen(SHIFT_CTRL_PF7_KEY), 0);
                                    break;
                                case VK_F8:
                                    if (dwControlKeyState == 0)
                                        NetWriteString2(pParams->Socket, (char *)PF8_KEY, strlen(PF8_KEY), 0);
                                    else if (dwControlKeyState == SHIFT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_PF8_KEY, strlen(SHIFT_PF8_KEY), 0);
                                    else if (dwControlKeyState == LEFT_CTRL_PRESSED ||
                                             dwControlKeyState == RIGHT_CTRL_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)CTRL_PF8_KEY, strlen(CTRL_PF8_KEY), 0);
                                    else if (dwControlKeyState == LEFT_ALT_PRESSED ||
                                             dwControlKeyState == RIGHT_ALT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)ALT_PF8_KEY, strlen(ALT_PF8_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_CTRL_PF8_KEY, strlen(SHIFT_ALT_CTRL_PF8_KEY), 0);
                                    else if ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)ALT_CTRL_PF8_KEY, strlen(ALT_CTRL_PF8_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_PF8_KEY, strlen(SHIFT_ALT_PF8_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_CTRL_PF8_KEY, strlen(SHIFT_CTRL_PF8_KEY), 0);
                                    break;
                                case VK_F9:
                                    if (dwControlKeyState == 0)
                                        NetWriteString2(pParams->Socket, (char *)PF9_KEY, strlen(PF9_KEY), 0);
                                    else if (dwControlKeyState == SHIFT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_PF9_KEY, strlen(SHIFT_PF9_KEY), 0);
                                    else if (dwControlKeyState == LEFT_CTRL_PRESSED ||
                                             dwControlKeyState == RIGHT_CTRL_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)CTRL_PF9_KEY, strlen(CTRL_PF9_KEY), 0);
                                    else if (dwControlKeyState == LEFT_ALT_PRESSED ||
                                             dwControlKeyState == RIGHT_ALT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)ALT_PF9_KEY, strlen(ALT_PF9_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_CTRL_PF9_KEY, strlen(SHIFT_ALT_CTRL_PF9_KEY), 0);
                                    else if ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)ALT_CTRL_PF9_KEY, strlen(ALT_CTRL_PF9_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_PF9_KEY, strlen(SHIFT_ALT_PF9_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_CTRL_PF9_KEY, strlen(SHIFT_CTRL_PF9_KEY), 0);
                                    break;
                                case VK_F10:
                                    if (dwControlKeyState == 0)
                                        NetWriteString2(pParams->Socket, (char *)PF10_KEY, strlen(PF10_KEY), 0);
                                    else if (dwControlKeyState == SHIFT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_PF10_KEY, strlen(SHIFT_PF10_KEY), 0);
                                    else if (dwControlKeyState == LEFT_CTRL_PRESSED ||
                                             dwControlKeyState == RIGHT_CTRL_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)CTRL_PF10_KEY, strlen(CTRL_PF10_KEY), 0);
                                    else if (dwControlKeyState == LEFT_ALT_PRESSED ||
                                             dwControlKeyState == RIGHT_ALT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)ALT_PF10_KEY, strlen(ALT_PF10_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_CTRL_PF10_KEY, strlen(SHIFT_ALT_CTRL_PF10_KEY), 0);
                                    else if ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)ALT_CTRL_PF10_KEY, strlen(ALT_CTRL_PF10_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_PF10_KEY, strlen(SHIFT_ALT_PF10_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_CTRL_PF10_KEY, strlen(SHIFT_CTRL_PF10_KEY), 0);
                                    break;
                                case VK_F11:
                                    if (dwControlKeyState == 0)
                                        NetWriteString2(pParams->Socket, (char *)PF11_KEY, strlen(PF11_KEY), 0);
                                    else if (dwControlKeyState == SHIFT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_PF11_KEY, strlen(SHIFT_PF11_KEY), 0);
                                    else if (dwControlKeyState == LEFT_CTRL_PRESSED ||
                                             dwControlKeyState == RIGHT_CTRL_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)CTRL_PF11_KEY, strlen(CTRL_PF11_KEY), 0);
                                    else if (dwControlKeyState == LEFT_ALT_PRESSED ||
                                             dwControlKeyState == RIGHT_ALT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)ALT_PF11_KEY, strlen(ALT_PF11_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_CTRL_PF11_KEY, strlen(SHIFT_ALT_CTRL_PF11_KEY), 0);
                                    else if ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)ALT_CTRL_PF11_KEY, strlen(ALT_CTRL_PF11_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_PF11_KEY, strlen(SHIFT_ALT_PF11_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_CTRL_PF11_KEY, strlen(SHIFT_CTRL_PF11_KEY), 0);
                                    break;
                                case VK_F12:
                                    if (dwControlKeyState == 0)
                                        NetWriteString2(pParams->Socket, (char *)PF12_KEY, strlen(PF12_KEY), 0);
                                    else if (dwControlKeyState == SHIFT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_PF12_KEY, strlen(SHIFT_PF12_KEY), 0);
                                    else if (dwControlKeyState == LEFT_CTRL_PRESSED ||
                                             dwControlKeyState == RIGHT_CTRL_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)CTRL_PF12_KEY, strlen(CTRL_PF12_KEY), 0);
                                    else if (dwControlKeyState == LEFT_ALT_PRESSED ||
                                             dwControlKeyState == RIGHT_ALT_PRESSED)
                                        NetWriteString2(pParams->Socket, (char *)ALT_PF12_KEY, strlen(ALT_PF12_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_CTRL_PF12_KEY, strlen(SHIFT_ALT_CTRL_PF12_KEY), 0);
                                    else if ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)ALT_CTRL_PF12_KEY, strlen(ALT_CTRL_PF12_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & RIGHT_ALT_PRESSED) ||
                                             (dwControlKeyState & LEFT_ALT_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_ALT_PF12_KEY, strlen(SHIFT_ALT_PF12_KEY), 0);
                                    else if ((dwControlKeyState & SHIFT_PRESSED) &&
                                            ((dwControlKeyState & LEFT_CTRL_PRESSED) ||
                                             (dwControlKeyState & RIGHT_CTRL_PRESSED)))
                                        NetWriteString2(pParams->Socket, (char *)SHIFT_CTRL_PF12_KEY, strlen(SHIFT_CTRL_PF12_KEY), 0);
                                    break;
                                case VK_PRIOR:
#ifdef PHYS_KEY_MAP
                                    NetWriteString2(pParams->Socket, (char *)REMOVE_KEY, 4, 0);
#else
                                    NetWriteString2(pParams->Socket, (char *)PREV_KEY, 4, 0);
#endif
                                    break;
                                case VK_NEXT:
                                    NetWriteString2(pParams->Socket, (char *)NEXT_KEY, 4, 0);
                                    break;
                                case VK_END:
#ifdef PHYS_KEY_MAP
                                    NetWriteString2(pParams->Socket, (char *)PREV_KEY, 4, 0);
#else
                                    NetWriteString2(pParams->Socket, (char *)SELECT_KEY, 4, 0);
#endif
                                    break;

                                case VK_HOME:
#ifdef PHYS_KEY_MAP
                                    NetWriteString2(pParams->Socket, (char *)INSERT_KEY, 4, 0);
#else
                                    NetWriteString2(pParams->Socket, (char *)FIND_KEY, 4, 0);
#endif
                                    break;
                                case VK_INSERT:
#ifdef PHYS_KEY_MAP
                                    NetWriteString2(pParams->Socket, (char *)FIND_KEY, 4, 0);
#else
                                    NetWriteString2(pParams->Socket, (char *)INSERT_KEY, 4, 0);
#endif
                                    break;
                                case VK_DELETE:
#ifdef PHYS_KEY_MAP
                                    NetWriteString2(pParams->Socket, (char *)SELECT_KEY, 4, 0);
#else
                                    NetWriteString2(pParams->Socket, (char *)REMOVE_KEY, 4, 0);
#endif
                                    break;
                                case VK_BACK:
                                    NetWriteString2(pParams->Socket, (char *)BACKSPACE_KEY, 1, 0);
                                    break;
                                case VK_TAB:
                                        if (dwControlKeyState == SHIFT_PRESSED)
                                                NetWriteString2(pParams->Socket, (char *)SHIFT_TAB_KEY, 3, 0);
                                        else
                                                NetWriteString2(pParams->Socket, (char *)octets, n, 0);
                                        break;
                                case VK_ESCAPE:
                                    NetWriteString2(pParams->Socket, (char *)ESCAPE_KEY, 1, 0);
                                    break;
                                case VK_SHIFT:
                                case VK_CONTROL:
                                case VK_CAPITAL:
                                    // NOP on these
                                    break;
                                default:
                                {
                                    NetWriteString2(pParams->Socket, (char *)octets, n, 0);
                                    break;
                                }
                            }
                    }
                }
                break;
            }
            break;
    }

	return glob_outlen ;
}


