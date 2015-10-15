/* ansiprsr.c
 * Author: Pragma Systems, Inc. <www.pragmasys.com>
 * Contribution by Pragma Systems, Inc. for Microsoft openssh win32 port
 * Copyright (c) 2011, 2015 Pragma Systems, Inc.
 * All rights reserved
 * 
 * ANSI Parser to run on Win32 based operating systems.
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
#include "tnnet.h"

#define TS_IS			  0
#define TS_SEND			  1

// items used from other modules
int NetWriteString(char* pszString, size_t cbString);
TelParams Parameters;
extern int lftocrlf;

extern int ScreenX;
extern  int ScreenY;
extern int ScrollTop;
extern int ScrollBottom;
// end of imports from outside module 

bool	gbVTAppMode		= false;

// private message for port printing to
unsigned char VT_ST[]					= { 0x1b, '/', '\0' };

static int	AutoWrap = 1;

int marginTop, marginBottom;
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
	return "\033[?1;2c";
}

char * GetStatusReport()
{
	return "\033[2;5R";
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

unsigned char* ParseBuffer(unsigned char* pszBuffer, unsigned char* pszBufferEnd)
{
	int CurrentX;
	int CurrentY;
	int rc = 0, bufLen, cmpLen, i;


			if (!fcompletion)
			{
				if (pszBuffer < pszBufferEnd -1)
				{
					unsigned char * pszCurrent = pszBuffer+1;
					unsigned char * pszNewCurrent = pszCurrent;

					if (term_mode == TERM_ANSI)
					{
						pszNewCurrent = ParseANSI(pszCurrent, pszBufferEnd);
					}
					else if (term_mode == TERM_VT52)
					{
						pszNewCurrent = ParseVT52(pszCurrent, pszBufferEnd);
					}
					if ( pszCurrent == pszNewCurrent ) // didn't move inside Parsefunction
					{
						pszNewCurrent += ConWriteString( (char *)pszCurrent, 1);
						return pszBuffer + 1;
					}
					if (pszNewCurrent > pszCurrent )
						pszBuffer = pszNewCurrent;
				}
			}
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
					Beep( 1000, 400);
					pszBuffer++;
					break;

				case 8:
						pszBuffer++;
						if (!bAtEOLN)
						{
							CurrentX = ConGetCursorX();
							if (CurrentX == 0)
							{
								ConMoveCursorPosition( ScreenX-1,-1);
								ConWriteString(" ",1);
							//	ConMoveCursorPosition(-1,0);
							}
							else
							{
								ConClearNFromCursorLeft(1);
								ConMoveCursorPosition( -1, 0 );
							}
						}
						bAtEOLN = FALSE;
						
						//ConWriteString( " ", 1 );
						//ConMoveCursorPosition( -1, 0 );
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
						CurrentY = ConGetCursorY();

						
						if (CurrentY >= marginBottom )
						{
							if (VTMode & MODE_APPMODE)
								ConScrollDown(marginTop,marginBottom);
							else
								printf("\n");
							ConMoveCursorPosition(-ConGetCursorX(),0);
						}
						else
						{
							ConMoveCursorPosition(0,1);
						}
						if ( Parameters.nReceiveCRLF == ENUM_LF )
							ConMoveCursorPosition(-ConGetCursorX(),0);
						AutoWrap = 1;
				bAtEOLN = FALSE;
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
						ConMoveCursorPosition(-ConGetCursorX(),0);
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
							unsigned char * pszCurrent = pszBuffer+1;
							unsigned char * pszNewCurrent = pszCurrent;

							if ( *pszCurrent == 27 )
							{
								pszNewCurrent += ConWriteString( (char *)pszCurrent, 1);
								return pszBuffer + 1;
							}
							else
							{
								if (term_mode == TERM_ANSI)
								{
									pszNewCurrent = ParseANSI(pszCurrent, pszBufferEnd);
								}
								else if (term_mode == TERM_VT52)
								{
									pszNewCurrent = ParseVT52(pszCurrent, pszBufferEnd);
								}
							}
							if (pszNewCurrent > pszCurrent )
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
							&& (CurrentX++ < ScreenX ))
							// (*pszCurrent != (char)15) && (*pszCurrent != (char)14) &&
							// (*pszCurrent != (char)12) && (*pszCurrent != (char)13) && (*pszCurrent != (char)8) &&
							// (*pszCurrent != (char)9))
							pszCurrent++;

					if (fShiftOut)
						memset( pszBuffer, '|', pszCurrent-pszBuffer );
					
					pszBuffer += ConWriteString((char *)pszBuffer, (int)(pszCurrent - pszBuffer));
				
					if ((CurrentX >= ScreenX) && AutoWrap && !(VTMode & MODE_CURSORAPP) )
					{
						bAtEOLN = TRUE;
					}

				break;
				}
			}

	return pszBuffer;
}


unsigned char * GetNextChar(unsigned char * pszBuffer, unsigned char *pszBufferEnd)
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
				Parameters.nReceiveCRLF = ENUM_LF;
				lftocrlf = 1;
			}else{
				VTMode &= ~MODE_LNM;
				Parameters.nReceiveCRLF = ENUM_CRLF;
				lftocrlf = 0;
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

unsigned char * ParseANSI(unsigned char * pszBuffer, unsigned char * pszBufferEnd)
{
	unsigned char *	pszCurrent = pszBuffer;
	const int nParam = 10;	// Maximum number of parameters
	int rc = 0;
	static int	SavedX = 0;
	static int	SavedY = 0;
	SCREEN_HANDLE	hScreen = NULL;
	char		anyKey[2] = " ";
	WORD		BytesRead;
	char		pszServerPort[10];
	int			indx;
	char jobName[40];

	fcompletion = 0;
	do 
	{
		switch ((unsigned char) *pszCurrent) 
		{
			case ';':		// delimiter
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

			case '<':			// character set
				fcompletion = 1;
				break;

			case '\\':
				fcompletion = 1;
				break;

			case '~':
				fcompletion = 1;
				break;
			case '^':	// private message				pszCurrent++;
				while (_strnicmp((const char *)pszCurrent, (const char *)VT_ST, strlen((const char *)VT_ST) )	)// while not stop
				{
					if (_strnicmp((const char *)pszCurrent, (const char *)VT_ST, strlen((const char *)VT_ST) )	)
						pszCurrent++;
				}
				pszCurrent += strlen((const char *)VT_ST) - 1;
				fcompletion = 1;
				break;
			
			case 'A':   // British Character Set or Cursor Up
				if (bMode & MODE_CHAR)
				{
					// Britsh Character Set
				}
				else if (bMode & MODE_BRK)
				{
					// Cursor UP
					if (iCurrentParam < 1)
						iParam[0] = 1;
					ConMoveCursorPosition(0, -iParam[0]);
//					AutoWrap = 0;
				}
				fcompletion = 1;
				break;
			case 'B':   // US ASCII or Cursor down
				if (bMode & MODE_CHAR)
				{
					// US ASCII Character Set
				}
				else if (bMode & MODE_BRK)
				{
					// Cursor DOWN
					if (iCurrentParam < 1)
						iParam[0] = 1;
					ConMoveCursorPosition(0, iParam[0]);
//					AutoWrap = 0;
				}
				fcompletion = 1;
				break;
			case 'C':   // Finish Character Set or Cursor right
				if (bMode & MODE_CHAR)
				{
					// Britsh Character Set
				}
				else if (bMode & MODE_BRK)
				{
					// Cursor right
					if (iCurrentParam < 1)
						iParam[0] = 1;
					ConMoveCursorPosition(iParam[0], 0);
//					AutoWrap = 0;
				}
				fcompletion = 1;
				break;
			case 'D':   //  Cursor left
				if (bMode & MODE_BRK)
				{
					// Cursor left
					if (iCurrentParam < 1)
						iParam[0] = 1;
					ConMoveCursorPosition(-iParam[0], 0);
//					AutoWrap = 0;
				}
				else if (bMode == 0)
				{
					// Index 
					ConScrollDown(ScrollTop,ScrollBottom);
				}
				fcompletion = 1;
				bAtEOLN = FALSE;
				break;


			case '=':  // application mode
				VTMode |= MODE_APPMODE;
				fcompletion = 1;
				break;
			case '>':  // numeric mode
				VTMode &= ~MODE_APPMODE;
				fcompletion = 1;
				break;

			case '%':			// character set definitions

				fcompletion = 1;
				break;
			case 'h':
			case 'l': // ^[?25h
				if (bMode & MODE_EXT)
				{
					if (iParam[0] == 4){
						VTMode |= MODE_IRM_INSERT;
					}
//					iParam[0] = atoi( (pszCurrent - iCurrentParam) ); 
					int i;
					for ( i = 0; i < iCurrentParam; i++ )
						ConSetExtendedMode(iParam[i], *pszCurrent=='h'?1:0); 
				}
				else if (bMode & MODE_BRK)
				{
					// Possible set Line feed (option 20)
					// Possible set Line feed (option 20)
					if (iParam[0] == 20)
						ConSetExtendedMode(iParam[0], *pszCurrent=='h'?1:0);
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
				if (iCurrentParam < 1)
					iParam[0] = 0;
				ConSetAttribute(iParam, iCurrentParam);
				fcompletion = 1;
				break;

			case 'r':
				marginTop = (iParam[0] > 0) ? iParam[0] - 1 : 0;
				marginBottom = (iParam[1] > 0) ? iParam[1] - 1 : 0;

				fcompletion = 1;
				break;
			case 'H':
			case 'f':
				if (bMode & MODE_BRK)
				{
					if ((iParam[0]-1) > ConWindowSizeY())
						ConSetScreenRect(ConWindowSizeX(), iParam[0]-1);
					ConSetCursorPosition((iParam[1] > 0) ? iParam[1] - 1 : 0, (iParam[0] > 0) ? iParam[0] - 1 : 0);
					//AutoWrap = 0;
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
						ConScrollUp(ConGetCursorY(),ScrollTop + marginBottom - ConGetCursorY());
				}
				else
				{
					if (ConGetCursorY() <= ScrollTop + ConWindowSizeY()-2)
					{
						ConScrollUp(ConGetCursorY(),ScrollTop + marginBottom - ConGetCursorY());
					}
				}
				fcompletion = 1;
				bAtEOLN = FALSE;
				break;
			case 'E':
			case 'g':
				fcompletion = 1;
				break;
			case 'i':	// ANSI or VTXXX Print
				fcompletion = 1;// 
				if ( iParam[0] == 5 )
				{
				}
				else if ( iParam[0] == 4 )
					InPrintMode = FALSE;
				break;
			case 'K':
				if (bMode & MODE_BRK)
				{
					if (iCurrentParam < 1)
						iParam[0] = 0;
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
				if (iCurrentParam < 1)
					iParam[0] = 0;
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
				if (iCurrentParam < 1)
				{
					if (iParam[0] == 5)
					{
						char * szStatus = GetStatusReport();
						NetWriteString(szStatus, strlen(szStatus));
					}
					else if ( iParam[0] == 6 )
					{
						char * szStatus = GetStatusReport();
						NetWriteString(szStatus, strlen(szStatus));
					}
				}
				fcompletion = 1;
				break;

			case 'c':

				if (bMode == (MODE_BRK & MODE_EXT))
				{
					// What are you response
				}
				else if (bMode == MODE_BRK)
				{
					char* szTerminalId = GetTerminalId();
					NetWriteString(szTerminalId, strlen(szTerminalId));
				}
				fcompletion = 1;
				break;

			case 'y':
			case 'q':
				fcompletion = 1;
				break;

			case 'Z':  // Identify - This is really a VT52 command
				{
					char* szTerminalId = GetTerminalId();
					NetWriteString(szTerminalId, strlen(szTerminalId));
				}
				fcompletion = 1;
			break;

			case 'P':
				ConDeleteChars(iParam[0]);
				fcompletion = 1;

				break;

		default:
		
		// pszHead should point to digit now. Otherwise we got bad escape
		// sequence, so we just get out of here!
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
							ConSetCursorPosition(SavedX,SavedY);
							break;
					}
					fcompletion = 1;
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
	//	fcompletion = 0;
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

unsigned char * ParseVT52(unsigned char * pszBuffer, unsigned char * pszBufferEnd)
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
			pszCurrent = GetNextChar(pszCurrent,pszBufferEnd);
			if (pszCurrent != NULL)
			{
					iLine = *pszCurrent - 31;

				pszCurrent = GetNextChar(pszCurrent,pszBufferEnd);
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
			NetWriteString("\033/Z",3);
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
	}

	return pszCurrent;
	
}
