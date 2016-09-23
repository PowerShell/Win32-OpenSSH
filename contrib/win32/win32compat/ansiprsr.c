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
/* ansiprsr.c
 * 
 * ANSI Parser to run on Win32 based operating systems.
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

#define TS_IS			  0
#define TS_SEND			  1

// items used from other modules
TelParams Parameters;

extern int ScreenX;
extern  int ScreenY;
extern int ScrollTop;
extern int ScrollBottom;
// end of imports from outside module 

bool	gbVTAppMode		= false;

// private message for port printing to
unsigned char VT_ST[]					= { 0x1b, '/', '\0' };

static int	AutoWrap = 1;

BOOL	bAtEOLN = FALSE;

static int term_mode;

// ParseANSI globals - these need to be here, because sometimes blocks are sent
// in mid ANSI sequence
int iParam[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
int iCurrentParam = 0;
int bDelimiter = 0;
int	bMode = 0;
int	fcompletion = 1;
int bExtMode = 0;
int	bCS0 = 0;
int bCS1 = 0;
int	bBkMode = 0;
int	bCharMode = 0;


BOOL	fShiftOut = FALSE;
BOOL	InPrintMode = FALSE;
BOOL	fPcMode = FALSE;

char	printErr[] = "Unable to Print: Printer not assigned.  Press any key to continue...";
char    cursor_report[255];

#define MODE_CURSORAPP		0x0001
#define MODE_ANSIVT52		0x0002
#define MODE_COL132			0x0004
#define MODE_SMOOTHSCROLL	0x0008
#define MODE_REVERSESCREEN	0x0010
#define MODE_ORIGINREL		0x0020
#define MODE_WRAPAROUND		0x0040
#define MODE_AUTOREPEAT		0x0080
#define MODE_APPMODE		0x0100
#define MODE_LNM		    0x0200
#define MODE_IRM_INSERT		0x0400

int VTMode = 0;

#define MODE_CURSORAPP		0x0001
#define MODE_ANSIVT52		0x0002
#define MODE_COL132			0x0004
#define MODE_SMOOTHSCROLL	0x0008
#define MODE_REVERSESCREEN	0x0010
#define MODE_ORIGINREL		0x0020
#define MODE_WRAPAROUND		0x0040
#define MODE_AUTOREPEAT		0x0080
#define MODE_APPMODE		0x0100
#define MODE_LNM		    0x0200

char *GetTerminalId()
{
	return TERMINAL_ID;
}

char * GetStatusReport()
{
	return STATUS_REPORT;
}

char * GetCursorPositionReport()
{
    DWORD wr = 0;
    DWORD out = 0;

    out = _snprintf_s(cursor_report, sizeof(cursor_report), _TRUNCATE,
        CURSOR_REPORT_FORMAT_STRING, ConGetCursorY() + 1, ConGetCursorX() + 1);

    if (out > 0) {
        return cursor_report;
    }

    return NULL;
}

void	BufConvertToG2(char * pszBuffer, int length)
{
	int	i;

	for (i=0;i<length;i++)
		pszBuffer[i]='|';
		//*(pszBuffer+i) += 20;
}


void GoToNextLine()
{
	if (ConGetCursorY() >= (ConWindowSizeY()-1))
	{
		ConScrollDown(ScrollTop,ScrollBottom);
		ConMoveCursorPosition(-ConGetCursorX(),0);
	}
	else
		ConMoveCursorPosition(-ConGetCursorX(),1);
	bAtEOLN = FALSE;
}

unsigned char* ParseBuffer(unsigned char* pszBuffer, unsigned char* pszBufferEnd, unsigned char **respbuf, size_t *resplen)
{
	int CurrentX;
	int CurrentY;
	int bufLen, cmpLen, i;

	if (!fcompletion)
	{
		if (pszBuffer < pszBufferEnd - 1)
		{
			unsigned char * pszCurrent = pszBuffer+1;
			unsigned char * pszNewCurrent = pszCurrent;

			if (term_mode == TERM_ANSI)
			{
				pszNewCurrent = ParseANSI(pszCurrent, pszBufferEnd, respbuf, resplen);
			}
			else if (term_mode == TERM_VT52)
			{
				pszNewCurrent = ParseVT52(pszCurrent, pszBufferEnd, respbuf, resplen);
			}

			if (pszCurrent == pszNewCurrent) // Pointer didn't move inside Parse function
			{
				pszNewCurrent += ConWriteString( (char *)pszCurrent, 1);
				return pszBuffer + 1;
			}
			if (pszNewCurrent > pszCurrent)
				pszBuffer = pszNewCurrent;
		}
	}

    // This is handling special characters including locating the ESC which starts a
    // terminal control sequence.
	switch ((unsigned char) (*pszBuffer)) 
	{
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 11:
		    pszBuffer++;
		    break;

		case 7:
			Beep(1000, 400);
			pszBuffer++;
			break;

		case 8:
			pszBuffer++;
			if (!bAtEOLN)
			{
				CurrentX = ConGetCursorX();
				if (CurrentX == 0)
				{
					ConMoveCursorPosition(ScreenX-1,-1);
					ConWriteString(" ",1);
				}
				else
				{
					ConClearNFromCursorLeft(1);
					ConMoveCursorPosition(-1, 0);
				}
			}
			bAtEOLN = FALSE;
		    break;

		case 9:
			{
				if (bAtEOLN) GoToNextLine();
				int	i, MoveRight = 8 - (ConGetCursorX() % 8);

				for ( i = 0; i < MoveRight; i++ )
					ConWriteString( " ", 1 );
				pszBuffer++;
				AutoWrap = 1;
				bAtEOLN = FALSE;
			}
	        break;

		case 10:
			pszBuffer++;
			AutoWrap = 1;
		    bAtEOLN = TRUE;
		    break;
				
		case 12:
		    pszBuffer++;
		    ConSetCursorPosition(0, 0);
		    ConClearScreen();
		    AutoWrap = 1;
		    bAtEOLN = FALSE;
		    break;

		case 13:
			pszBuffer++;
			AutoWrap = 1;
		    bAtEOLN = FALSE;
		    break;

		case 14:
			pszBuffer++;
			fShiftOut = TRUE;
		    break;

		case 15:
			fShiftOut = FALSE;
			pszBuffer++;
		    break;

		case 27:
			if (pszBuffer < pszBufferEnd -1)
			{
				unsigned char * pszCurrent = pszBuffer + 1;
				unsigned char * pszNewCurrent = pszCurrent;

				if (*pszCurrent == 27)
				{
					pszNewCurrent += ConWriteString( (char *)pszCurrent, 1);
					return pszBuffer + 1;
				}
				else
				{
					if (term_mode == TERM_ANSI)
					{
						pszNewCurrent = ParseANSI(pszCurrent, pszBufferEnd, respbuf, resplen);
					}
					else if (term_mode == TERM_VT52)
					{
						pszNewCurrent = ParseVT52(pszCurrent, pszBufferEnd, respbuf, resplen);
					}
				}
				if (pszNewCurrent > pszCurrent)
					pszBuffer = pszNewCurrent;
			}
		    break;

		default: 
            {
                if (bAtEOLN) GoToNextLine();

                unsigned char* pszCurrent = pszBuffer;
                CurrentX = ConGetCursorX();

                while ((pszCurrent < pszBufferEnd) && (*pszCurrent != (unsigned char)27)
                    && (*pszCurrent > (unsigned char)15) && (*pszCurrent != (unsigned char)255)
                    && (CurrentX++ < ScreenX))
                    pszCurrent++;

                if (fShiftOut)
                    memset(pszBuffer, '|', pszCurrent - pszBuffer);

                pszBuffer += ConWriteString((char *)pszBuffer, (int)(pszCurrent - pszBuffer));

                if ((CurrentX >= ScreenX) && AutoWrap && !(VTMode & MODE_CURSORAPP))
                {
                    bAtEOLN = TRUE;
                }
            }
		    break;
	}

	return pszBuffer;
}


unsigned char * GetNextChar(unsigned char *pszBuffer, unsigned char *pszBufferEnd)
{
	if (++pszBuffer > pszBufferEnd)
		return NULL;
	else
		return pszBuffer;
}

void ConSetExtendedMode(int iFunction, BOOL bEnable)
{
	switch(iFunction)
	{
		case 1:
			if (bEnable){
				VTMode |= MODE_CURSORAPP;
				gbVTAppMode = true;
			}else{
				VTMode &= ~MODE_CURSORAPP;
				gbVTAppMode = false;
			}
			break;
		case 2:
			if (!bEnable)
				VTMode |= MODE_ANSIVT52;
			break;
		case 3:
			if (bEnable)
				VTMode |= MODE_COL132;
			else
				VTMode &= ~MODE_COL132;
			break;
		case 4:
			if (bEnable)
				VTMode |= MODE_SMOOTHSCROLL;
			else
				VTMode &= ~MODE_SMOOTHSCROLL;
			break;
		case 5:
			if (bEnable)
				VTMode |= MODE_REVERSESCREEN;
			else
				VTMode &= ~MODE_REVERSESCREEN;
			break;
		case 6:
			if (bEnable)
				VTMode |= MODE_ORIGINREL;
			else
				VTMode &= ~MODE_ORIGINREL;
			break;
		case 7:
			if (bEnable)
				VTMode |= MODE_WRAPAROUND;
			else
				VTMode &= ~MODE_WRAPAROUND;
			break;
		case 8:
			if (bEnable)
				VTMode |= MODE_AUTOREPEAT;
			else
				VTMode &= ~MODE_AUTOREPEAT;
			break;
		case 20:   // LNM Mode CSI 20h
			if (bEnable){
				VTMode |= MODE_LNM;
				Parameters.nReceiveCRLF = ENUM_CRLF;
			}else{
				VTMode &= ~MODE_LNM;
				Parameters.nReceiveCRLF = ENUM_LF;
			}
			break;
		case 25:
			ConDisplayCursor(bEnable);
			break;

	}

	if ((iFunction == 2) && (bEnable))
	{
		term_mode = TERM_VT52;
	}
}

#define MODE_EXT	0x00000001
#define MODE_CS0	0x00000002
#define MODE_CS1	0x00000004
#define MODE_CS2	0x00000008
#define MODE_CS3	0x00000010
#define MODE_BRK	0x00000020
#define MODE_CHAR	0x00000040
#define MODE_K		0x00000080

#define DIGI_MASK   (MODE_CS0 | MODE_CS1 | MODE_CS2 | MODE_CS3 | MODE_CHAR)

unsigned char * ParseANSI(unsigned char * pszBuffer, unsigned char * pszBufferEnd, unsigned char **respbuf, size_t *resplen)
{
    const int nParam = 10;	// Maximum number of parameters

	static int SavedX = 0;
	static int SavedY = 0;

    unsigned char *	pszCurrent = pszBuffer;

    if (pszCurrent == NULL || pszBufferEnd == NULL)
        return NULL;

    fcompletion = 0;
	do 
	{
		switch ((unsigned char) *pszCurrent) 
		{
// Delimiter
			case ';':		
				bDelimiter = TRUE;
				break;
// Modifiers
			case '?':		// Extended Mode
				bMode |= MODE_EXT;
				break;
			case '(':
				bMode |= MODE_CS0;
				break;
			case ')':
				bMode |= MODE_CS1;
				break;
			case '*':
				bMode |= MODE_CS2;
				break;
			case '+':
				bMode |= MODE_CS3;
				break;
			case '[':
				bMode |= MODE_BRK;
				break;
			case '#':
				bMode |= MODE_CHAR;
				break;

// Termination Options
			case 0:
				fcompletion = 1;
				break;

			case '}':
				fcompletion = 1;
				break;

			case '<':		// Character set
				fcompletion = 1;
				break;

			case '\\':
				fcompletion = 1;
				break;

			case '~':
				fcompletion = 1;
				break;

			case '^':	    // Private message
				while (pszCurrent && pszCurrent < pszBufferEnd && 
                    _strnicmp((const char *)pszCurrent, (const char *)VT_ST, strlen((const char *)VT_ST) )	) // while not stop
				{
					if (pszCurrent && pszCurrent < pszBufferEnd && 
                        _strnicmp((const char *)pszCurrent, (const char *)VT_ST, strlen((const char *)VT_ST) ) )
						pszCurrent++;
				}
				pszCurrent += strlen((const char *)VT_ST) - 1;
				fcompletion = 1;
				break;
			
			case 'A':       // Character Set change or Cursor Up
				if (bMode & MODE_CHAR)
				{
				}
				else if (bMode & MODE_BRK)
				{
					// Cursor UP
					ConMoveCursorPosition(0, -iParam[0]);
				}
				fcompletion = 1;
				break;

			case 'B':       // Character set change or Cursor down
				if (bMode & MODE_CHAR)
				{
					// Character Set
				}
				else if (bMode & MODE_BRK)
				{
					// Cursor DOWN
					ConMoveCursorPosition(0, iParam[0]);
				}
				fcompletion = 1;
				break;

			case 'C':       // Character Set change or Cursor right
				if (bMode & MODE_CHAR)
				{
					// Character Set
				}
				else if (bMode & MODE_BRK)
				{
					// Cursor right
					ConMoveCursorPosition(iParam[0], 0);

                }
				fcompletion = 1;
				break;

            case 'D':       //  Cursor left
				if (bMode & MODE_BRK)
				{
					// Cursor left
					ConMoveCursorPosition(-iParam[0], 0);
				}
				else if (bMode == 0)
				{
					// Index 
					ConScrollDown(ScrollTop,ScrollBottom);
				}
				fcompletion = 1;
				bAtEOLN = FALSE;
				break;

			case '=':       // Application mode
				VTMode |= MODE_APPMODE;
				fcompletion = 1;
				break;

			case '>':       // Numeric mode
				VTMode &= ~MODE_APPMODE;
				fcompletion = 1;
				break;

			case '%':		// Character set definitions
				fcompletion = 1;
				break;

			case 'h':
			case 'l': // ^[?25h
				if (bMode & MODE_EXT)
				{
					if (iParam[0] == 4) {
						VTMode |= MODE_IRM_INSERT;
					}
					int i;
					for ( i = 0; i < iCurrentParam; i++ )
						ConSetExtendedMode(iParam[i], *pszCurrent=='h' ? 1 : 0); 
				}
				else if (bMode & MODE_BRK)
				{
					// Possible set Line feed (option 20)
					if (iParam[0] == 20)
						ConSetExtendedMode(iParam[0], *pszCurrent=='h' ? 1 : 0);
					if (iParam[0] == 4){
						VTMode &= ~MODE_IRM_INSERT;
					}
				}
				fcompletion = 1;
				break;

			case 'L':
				if (iParam[0])
				{
					int i;
					for (i=0; i<iParam[0]; i++)
						ConScrollUp(ConGetCursorY()-1,ScrollTop + ConWindowSizeY()-2);
				}
				else
				{
					if (ConGetCursorY() <= ScrollTop + ConWindowSizeY()-2)
					{
						ConScrollUp(ConGetCursorY()-1,ScrollTop + ConWindowSizeY()-2);
					}
				}
				fcompletion = 1;
				bAtEOLN = FALSE;
				break;

			case 'N':
			case 'O':
				fcompletion =1;
				break;
			case 'm':
				ConSetAttribute(iParam, iCurrentParam);
				fcompletion = 1;
				break;

			case 'r':
				fcompletion = 1;
				break;

			case 'H':
			case 'f':
				if (bMode & MODE_BRK)
				{
					ConSetCursorPosition((iParam[1] > 0) ? iParam[1] - 1 : 0, (iParam[0] > 0) ? iParam[0] - 1 : 0);
				} 
				else if (bMode == 0)
				{
					//Set tab
				}
				fcompletion = 1;
				bAtEOLN = FALSE;
				break;

			case 'M':
				if (iParam[0])
				{
					int i ;
					for (i=0; i<iParam[0]; i++)
						ConScrollUp(ConGetCursorY(), ScrollTop - ConGetCursorY());
				}
				else
				{
					if (ConGetCursorY() <= ScrollTop + ConWindowSizeY() - 2)
					{
						ConScrollUp(ConGetCursorY(), ScrollTop - ConGetCursorY());
					}
				}
				fcompletion = 1;
				bAtEOLN = FALSE;
				break;

			case 'E':
            case 'G':
            case 'g':
				fcompletion = 1;
				break;

			case 'i':	    // ANSI or VTXXX Print
				if ( iParam[0] == 5 )
				{
				}
				else if ( iParam[0] == 4 )
					InPrintMode = FALSE;
                fcompletion = 1;
				break;

			case 'K':
				if (bMode & MODE_BRK)
				{
					switch (iParam[0]) 
					{
						case 0:
							ConClearEOLine();
							break;
						case 1:
							ConClearBOLine();
							break;
						case 2:
							ConClearLine();
							break;
					}
				}
				else if (bMode == 0)
				{
					bMode |= MODE_K;
				}

				fcompletion = 1;
				break;

			case 'J':
				switch (iParam[0]) 
				{
				  case 0:
					ConClearEOScreen();
					break;
				  case 1:
					ConClearBOScreen();
					break;
				  case 2:
					ConClearScreen();
					break;
				}
				fcompletion = 1;
				break;

			case 'n':
				if (iCurrentParam == 1)
				{
					if (iParam[0] == 5)
					{
						char * szStatus = GetStatusReport();
                        if (respbuf != NULL)
                        {
                            *respbuf = szStatus;
                            if (resplen != NULL)
                            {
                                *resplen = strlen(szStatus);
                            }
                        }
					}
					else if ( iParam[0] == 6 )
					{
                        char * szStatus = GetCursorPositionReport();
                        if (respbuf != NULL)
                        {
                            *respbuf = szStatus;
                            if (resplen != NULL)
                            {
                                *resplen = strlen(szStatus);
                            }
                        }
					}
				}
				fcompletion = 1;
				break;

			case 'c':
				if (bMode == (MODE_BRK & MODE_EXT))
				{
					// What is your response?
				}
				else if (bMode == MODE_BRK)
				{
					char* szTerminalId = GetTerminalId();
                    if (szTerminalId) {
                        if (respbuf != NULL)
                        {
                            *respbuf = szTerminalId;
                            if (resplen != NULL)
                            {
                                *resplen = strlen(szTerminalId);
                            }
                        }
                    }
				}
				fcompletion = 1;
				break;

			case 'y':
			case 'q':
				fcompletion = 1;
				break;

			case 'Z':       // Identify - This is really a VT52 command
				{
					char* szTerminalId = GetTerminalId();
                    if (szTerminalId) {
                        *respbuf = szTerminalId;
                        if (resplen != NULL)
                        {
                            *resplen = strlen(szTerminalId);
                        }
                    }
				}
				fcompletion = 1;
			    break;

			case 'P':
				ConDeleteChars(iParam[0]);
				fcompletion = 1;
				break;

		default:
		
		    // pszHead should point to digit now. Otherwise we got a bad escape
		    // sequence, so we just get out of here!
            if(*pszCurrent) {
				if (!isdigit(*pszCurrent))
				{
					pszCurrent = pszBuffer;
					return pszCurrent;
				}

				iParam[iCurrentParam] = strtoul((const char *)pszCurrent, (char **)&pszCurrent, 10);
		
				pszCurrent--;

				if (iCurrentParam < nParam)
					iCurrentParam++;

				// Check for digit completion
				if (bMode & DIGI_MASK)
					fcompletion = 1;
				
				if (bMode == 0)
				{
					switch(iParam[0])
					{
						case 7:
							SavedX = ConGetCursorX();
							SavedY = ConGetCursorY();
							break;
						case 8:
							ConSetCursorPosition(SavedX, SavedY);
							break;
					}
					fcompletion = 1;
				}
            }
            else {
                pszCurrent = pszBuffer;
                return pszCurrent;
            }

			break;
		}

 	} 	while ((++pszCurrent < pszBufferEnd) && !fcompletion);

	if (fcompletion)
	{
		memset(iParam, '\0', sizeof(iParam));
		iCurrentParam = 0;
		bDelimiter = 0;
		bMode = 0;
		bExtMode = 0;
		bCS0 = 0;
		bCS1 = 0;
		bBkMode = 0;
		bCharMode = 0;
		return pszCurrent;
	}
	else
		return pszBuffer;
}

unsigned char * ParseVT52(unsigned char * pszBuffer, unsigned char * pszBufferEnd, unsigned char **respbuf, size_t *resplen)
{
	unsigned char *	pszCurrent = pszBuffer;
	int		iLine;
	int		iColumn;

	switch ((unsigned char) *pszCurrent) 
	{
		case 'A':  // Cursor Up
			ConMoveCursorPosition(0, -1);
			pszCurrent++;
				bAtEOLN = FALSE;
			break;

		case 'B': // Cursor Down
			ConMoveCursorPosition(0, 1);
			pszCurrent++;
				bAtEOLN = FALSE;
			break;

		case 'C':  // Cursor Right
			ConMoveCursorPosition(1, 0);
			pszCurrent++;
			break;

		case 'D':  // Cursor Left
			ConMoveCursorPosition(-1, 0);
			pszCurrent++;
				bAtEOLN = FALSE;
			break;

		case 'F':  // Special Graphics Character Set
		case 'G':  // ASCII Character Set
			pszCurrent++;
			break;

		case 'H':  // Cursor Home
			ConSetCursorPosition(1, 1);
			pszCurrent++;
				bAtEOLN = FALSE;
			break;
		case 'I':  // Reverse Line Feed
			pszCurrent++;
			break;

		case 'J':  // Erase to End of Screen
			ConClearEOScreen();
			pszCurrent++;
			break;

		case 'K':  // Erase to End of Line
			ConClearEOLine();
			pszCurrent++;
			break;

		case 'Y':  // Direct Cursor Addressing
			pszCurrent = GetNextChar(pszCurrent, pszBufferEnd);
			if (pszCurrent != NULL)
			{
				iLine = *pszCurrent - 31;

				pszCurrent = GetNextChar(pszCurrent, pszBufferEnd);
				if (pszCurrent != NULL)
				{
						iColumn = *pszCurrent - 31;
						ConSetCursorPosition(iLine,iColumn);
						pszCurrent++;
				}
				else 
					pszCurrent = pszBuffer;
			}
			else
				pszCurrent = pszBuffer;
			break;

		case 'Z':  // Identify
            *respbuf = VT52_TERMINAL_ID;
            if (resplen != NULL)
            {
                *resplen = 3;
            }
			pszCurrent++;
			break;

		case '=':  // Enter Alt Keypad mode
		case '>':  // Exit Alt Keypad mode
		case '1':  // Graphics processor on
		case '2':  // Graphics processor off
			pszCurrent++;
			break;

		case '<':  // Enter ANSI mode
			term_mode = TERM_ANSI;
			pszCurrent++;
			break;

		default:
			pszCurrent++;
            break;
	}

	return pszCurrent;
	
}
