/*
 * Author: Microsoft Corp.
 *
 * Copyright (c) 2015 Microsoft Corp.
 * All rights reserved
 *
 * Common library for Windows Console Screen IO.
 * Contains Windows console related definition so that emulation code can draw
 * on Windows console screen surface.
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
#include <string.h>
#include <windows.h>
#include <conio.h>
#include <io.h>

#include "debug.h"
#include "console.h"
#include "ansiprsr.h"

HANDLE	hOutputConsole = NULL;
DWORD	stdin_dwSavedAttributes = 0;
DWORD	stdout_dwSavedAttributes = 0;
WORD	wStartingAttributes = 0;

int ScreenX;
int ScreenY;
int ScrollTop;
int ScrollBottom;
int LastCursorX;
int LastCursorY;
BOOL isAnsiParsingRequired = FALSE;
char *pSavedScreen = NULL;
static COORD ZeroCoord = { 0,0 };
COORD SavedScreenSize = { 0,0 };
COORD SavedScreenCursor = { 0, 0 };
SMALL_RECT SavedViewRect = { 0,0,0,0 };
CONSOLE_SCREEN_BUFFER_INFOEX SavedWindowState;
BOOL isConHostParserEnabled = TRUE;

typedef struct _SCREEN_RECORD {
	PCHAR_INFO pScreenBuf;
	COORD ScreenSize;
	COORD ScreenCursor;
	SMALL_RECT  srWindowRect;
}SCREEN_RECORD, *PSCREEN_RECORD;

PSCREEN_RECORD pSavedScreenRec = NULL;
int in_raw_mode = 0;
char *consoleTitle = "OpenSSH SSH client";

/* Used to enter the raw mode */
void 
ConEnterRawMode()
{
	DWORD dwAttributes = 0;
	DWORD dwRet = 0;
	BOOL bRet = FALSE;
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	static bool bFirstConInit = true;

	hOutputConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hOutputConsole == INVALID_HANDLE_VALUE) {
		dwRet = GetLastError();
		error("GetStdHandle on OutputHandle failed with %d\n", dwRet);
		return;
	}

	if (!GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &stdin_dwSavedAttributes)) {
		dwRet = GetLastError();
		error("GetConsoleMode on STD_INPUT_HANDLE failed with %d\n", dwRet);
		return;
	}

	SetConsoleTitle(consoleTitle);

	dwAttributes = stdin_dwSavedAttributes;
	dwAttributes &= ~(ENABLE_LINE_INPUT |
		ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_MOUSE_INPUT);
	dwAttributes |= ENABLE_WINDOW_INPUT;

	if (!SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), dwAttributes)) { /* Windows NT */
		dwRet = GetLastError();
		error("SetConsoleMode on STD_INPUT_HANDLE failed with %d\n", dwRet);
		return;
	}

	if (!GetConsoleMode(hOutputConsole, &stdout_dwSavedAttributes)) {
		dwRet = GetLastError();
		error("GetConsoleMode on hOutputConsole failed with %d\n", dwRet);
		return;
	}

	dwAttributes = stdout_dwSavedAttributes;
	dwAttributes |= (DWORD)ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;

	char *envValue = NULL;
	size_t len = 0;	
	_dupenv_s(&envValue, &len, "SSH_TERM_CONHOST_PARSER");
	
	if (NULL != envValue) {
		isConHostParserEnabled = atoi(envValue);
		free(envValue);
	}		

	/* We use our custom ANSI parser when
	 * a) User sets the environment variable "SSH_TERM_CONHOST_PARSER" to 0
	 * b) or when the console doesn't have the inbuilt capability to parse the ANSI/Xterm raw buffer.
	 */	 
	if (FALSE == isConHostParserEnabled || !SetConsoleMode(hOutputConsole, dwAttributes)) /* Windows NT */
		isAnsiParsingRequired = TRUE;
			
	GetConsoleScreenBufferInfo(hOutputConsole, &csbi);
	
	/* if we are passing rawbuffer to console then we need to move the cursor to top 
	 *  so that the clearscreen will not erase any lines.
	 */
	if (TRUE == isAnsiParsingRequired) {
		SavedViewRect = csbi.srWindow;
		debug("console doesn't support the ansi parsing");
	} else {
		ConSaveViewRect();
		debug("console supports the ansi parsing");
	}		

	ConSetScreenX();
	ConSetScreenY();
	ScrollTop = 0;
	ScrollBottom = ConVisibleWindowHeight();		
	
	in_raw_mode = 1;
}

/* Used to Uninitialize the Console */
void 
ConExitRawMode()
{
	SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), stdin_dwSavedAttributes);
	SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), stdout_dwSavedAttributes);
}

/* Used to exit the raw mode */
void 
ConUnInitWithRestore()
{
	DWORD dwWritten;
	COORD Coord;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (hOutputConsole == NULL)
		return;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;

	SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), stdin_dwSavedAttributes);
	SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), stdout_dwSavedAttributes);
	Coord = consoleInfo.dwCursorPosition;
	Coord.X = 0;
	DWORD dwNumChar = (consoleInfo.dwSize.Y - consoleInfo.dwCursorPosition.Y) * consoleInfo.dwSize.X;
	FillConsoleOutputCharacter(hOutputConsole, ' ', dwNumChar, Coord, &dwWritten);
	FillConsoleOutputAttribute(hOutputConsole, wStartingAttributes, dwNumChar, Coord, &dwWritten);
	SetConsoleTextAttribute(hOutputConsole, wStartingAttributes);
}

BOOL 
ConSetScreenRect(int xSize, int ySize)
{
	BOOL bSuccess = TRUE;
	CONSOLE_SCREEN_BUFFER_INFO csbi; /* hold current console buffer info */
	SMALL_RECT srWindowRect; /* hold the new console size */
	COORD coordScreen;

	bSuccess = GetConsoleScreenBufferInfo(hOutputConsole, &csbi);
	if (!bSuccess)
		return bSuccess;

	/* get the largest size we can size the console window to */
	coordScreen = GetLargestConsoleWindowSize(hOutputConsole);

	/* define the new console window size and scroll position */
	srWindowRect.Top = csbi.srWindow.Top;
	srWindowRect.Left = csbi.srWindow.Left;
	srWindowRect.Right = xSize - 1 + srWindowRect.Left;
	srWindowRect.Bottom = ySize - 1 + srWindowRect.Top;

	/* define the new console buffer size */
	coordScreen.X = max(csbi.dwSize.X, xSize);
	coordScreen.Y = max(csbi.dwSize.Y, ySize);

	/* if the current buffer is larger than what we want, resize the */
	/* console window first, then the buffer */
	if (csbi.dwSize.X < coordScreen.X || csbi.dwSize.Y < coordScreen.Y) {
		bSuccess = SetConsoleScreenBufferSize(hOutputConsole, coordScreen);
		if (bSuccess)
			bSuccess = SetConsoleWindowInfo(hOutputConsole, TRUE, &srWindowRect);
	} else {
		bSuccess = SetConsoleWindowInfo(hOutputConsole, TRUE, &srWindowRect);
		if (bSuccess)
			bSuccess = SetConsoleScreenBufferSize(hOutputConsole, coordScreen);
	}

	if (bSuccess)
		ConSaveViewRect();

	/* if the current buffer *is* the size we want, don't do anything! */
	return bSuccess;
}

BOOL 
ConSetScreenSize(int xSize, int ySize)
{
	BOOL bSuccess = TRUE;
	CONSOLE_SCREEN_BUFFER_INFO csbi; /* hold current console buffer info */
	SMALL_RECT srWindowRect; /* hold the new console size */
	COORD coordScreen;

	bSuccess = GetConsoleScreenBufferInfo(hOutputConsole, &csbi);
	if (!bSuccess)
		return bSuccess;

	/* get the largest size we can size the console window to */
	coordScreen = GetLargestConsoleWindowSize(hOutputConsole);

	/* define the new console window size and scroll position */
	srWindowRect.Right = (SHORT)(min(xSize, coordScreen.X) - 1);
	srWindowRect.Bottom = (SHORT)(min(ySize, coordScreen.Y) - 1);
	srWindowRect.Left = srWindowRect.Top = (SHORT)0;

	/* define the new console buffer size */
	coordScreen.X = xSize;
	coordScreen.Y = ySize;

	/* if the current buffer is larger than what we want, resize the */
	/* console window first, then the buffer */
	if ((DWORD)csbi.dwSize.X * csbi.dwSize.Y > (DWORD)xSize * ySize) {
		bSuccess = SetConsoleWindowInfo(hOutputConsole, TRUE, &srWindowRect);
		if (bSuccess)
			bSuccess = SetConsoleScreenBufferSize(hOutputConsole, coordScreen);
	}

	/* if the current buffer is smaller than what we want, resize the */
	/* buffer first, then the console window */
	if ((DWORD)csbi.dwSize.X * csbi.dwSize.Y < (DWORD)xSize * ySize) {
		bSuccess = SetConsoleScreenBufferSize(hOutputConsole, coordScreen);
		if (bSuccess)
			bSuccess = SetConsoleWindowInfo(hOutputConsole, TRUE, &srWindowRect);
	}

	if (bSuccess)
		ConSaveViewRect();

	/* if the current buffer *is* the size we want, don't do anything! */
	return bSuccess;
}

/* Used to set the Color of the console and other attributes */
void 
ConSetAttribute(int *iParam, int iParamCount)
{
	static int iAttr = 0;
	int i = 0;
	BOOL bRet = TRUE;

	if (iParamCount < 1) {
		iAttr |= FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
		iAttr = iAttr & ~BACKGROUND_INTENSITY;
		iAttr = iAttr & ~FOREGROUND_INTENSITY;
		iAttr = iAttr & ~COMMON_LVB_UNDERSCORE;
		iAttr = iAttr & ~COMMON_LVB_REVERSE_VIDEO;

		SetConsoleTextAttribute(hOutputConsole, (WORD)iAttr);
	} else {
		for (i = 0; i < iParamCount; i++) {
			switch (iParam[i]) {
			case ANSI_ATTR_RESET:
				iAttr |= FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
				iAttr = iAttr & ~BACKGROUND_RED;
				iAttr = iAttr & ~BACKGROUND_BLUE;
				iAttr = iAttr & ~BACKGROUND_GREEN;
				iAttr = iAttr & ~BACKGROUND_INTENSITY;
				iAttr = iAttr & ~FOREGROUND_INTENSITY;
				iAttr = iAttr & ~COMMON_LVB_UNDERSCORE;
				iAttr = iAttr & ~COMMON_LVB_REVERSE_VIDEO;
				break;
			case ANSI_BRIGHT:
				iAttr |= FOREGROUND_INTENSITY;
				break;
			case ANSI_DIM:
				break;
			case ANSI_NOUNDERSCORE:
				iAttr = iAttr & ~COMMON_LVB_UNDERSCORE;
				break;
			case ANSI_UNDERSCORE:
				iAttr |= COMMON_LVB_UNDERSCORE;
				break;
			case ANSI_BLINK:
				break;
			case ANSI_REVERSE:
				iAttr |= COMMON_LVB_REVERSE_VIDEO;
				break;
			case ANSI_HIDDEN:
				break;
			case ANSI_NOREVERSE:
				iAttr = iAttr & ~COMMON_LVB_REVERSE_VIDEO;
				break;
			case ANSI_DEFAULT_FOREGROUND:
				/* White */
				iAttr |= FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
				break;
			case ANSI_FOREGROUND_BLACK:
				iAttr = iAttr & ~FOREGROUND_RED;
				iAttr = iAttr & ~FOREGROUND_BLUE;
				iAttr = iAttr & ~FOREGROUND_GREEN;
				iAttr |= 0;
				break;
			case ANSI_FOREGROUND_RED:
				iAttr = iAttr & ~FOREGROUND_GREEN;
				iAttr = iAttr & ~FOREGROUND_BLUE;
				iAttr |= FOREGROUND_RED;
				break;
			case ANSI_FOREGROUND_GREEN:
				iAttr = iAttr & ~FOREGROUND_BLUE;
				iAttr = iAttr & ~FOREGROUND_RED;
				iAttr |= FOREGROUND_GREEN;
				break;
			case ANSI_FOREGROUND_YELLOW:
				iAttr = iAttr & ~FOREGROUND_BLUE;
				iAttr |= FOREGROUND_RED | FOREGROUND_GREEN;
				break;
			case ANSI_FOREGROUND_BLUE:
				iAttr = iAttr & ~FOREGROUND_GREEN;
				iAttr = iAttr & ~FOREGROUND_RED;
				iAttr |= FOREGROUND_BLUE;
				break;
			case ANSI_FOREGROUND_MAGENTA:
				iAttr = iAttr & ~FOREGROUND_GREEN;
				iAttr |= FOREGROUND_BLUE | FOREGROUND_RED;
				break;
			case ANSI_FOREGROUND_CYAN:
				iAttr = iAttr & ~FOREGROUND_RED;
				iAttr |= FOREGROUND_BLUE | FOREGROUND_GREEN;
				break;
			case ANSI_FOREGROUND_WHITE:
				iAttr |= FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN;
				break;
			case ANSI_DEFAULT_BACKGROUND:
				/* Black */
				iAttr = iAttr & ~BACKGROUND_RED;
				iAttr = iAttr & ~BACKGROUND_BLUE;
				iAttr = iAttr & ~BACKGROUND_GREEN;
				iAttr |= 0;
				break;
			case ANSI_BACKGROUND_BLACK:
				iAttr = iAttr & ~BACKGROUND_RED;
				iAttr = iAttr & ~BACKGROUND_BLUE;
				iAttr = iAttr & ~BACKGROUND_GREEN;
				iAttr |= 0;
				break;
			case ANSI_BACKGROUND_RED:
				iAttr = iAttr & ~BACKGROUND_GREEN;
				iAttr = iAttr & ~BACKGROUND_BLUE;
				iAttr |= BACKGROUND_RED;
				break;
			case ANSI_BACKGROUND_GREEN:
				iAttr = iAttr & ~BACKGROUND_RED;
				iAttr = iAttr & ~BACKGROUND_BLUE;
				iAttr |= BACKGROUND_GREEN;
				break;
			case ANSI_BACKGROUND_YELLOW:
				iAttr = iAttr & ~BACKGROUND_BLUE;
				iAttr |= BACKGROUND_RED | BACKGROUND_GREEN;
				break;
			case ANSI_BACKGROUND_BLUE:
				iAttr = iAttr & ~BACKGROUND_GREEN;
				iAttr = iAttr & ~BACKGROUND_RED;
				iAttr |= BACKGROUND_BLUE;
				break;
			case ANSI_BACKGROUND_MAGENTA:
				iAttr = iAttr & ~BACKGROUND_GREEN;
				iAttr |= BACKGROUND_BLUE | BACKGROUND_RED;
				break;
			case ANSI_BACKGROUND_CYAN:
				iAttr = iAttr & ~BACKGROUND_RED;
				iAttr |= BACKGROUND_BLUE | BACKGROUND_GREEN;
				break;
			case ANSI_BACKGROUND_WHITE:
				iAttr |= BACKGROUND_BLUE | BACKGROUND_RED | BACKGROUND_GREEN;
				break;
			case ANSI_BACKGROUND_BRIGHT:
				iAttr |= BACKGROUND_INTENSITY;
				break;
			default:
				continue;
			}
		}

		if (iAttr)
			bRet = SetConsoleTextAttribute(hOutputConsole, (WORD)iAttr);
	}
}

/* Returns the width of current screen */
int
ConScreenSizeX()
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return (-1);

	return (consoleInfo.dwSize.X);
}

/* Sets the width of the screen */
int
ConSetScreenX()
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return (-1);

	ScreenX = (consoleInfo.dwSize.X);
	return 0;
}

/* returns actual size of screen buffer */
int
ConScreenSizeY()
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return (-1);

	return (consoleInfo.srWindow.Bottom - consoleInfo.srWindow.Top + 1);
}

/* returns width of visible window */
int
ConVisibleWindowWidth()
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return (-1);

	return (consoleInfo.srWindow.Right - consoleInfo.srWindow.Left + 1);
}

/* returns height of visible window */
int
ConVisibleWindowHeight()
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return (-1);

	return (consoleInfo.srWindow.Bottom - consoleInfo.srWindow.Top + 1);
}

int
ConSetScreenY()
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return (-1);

	ScreenY = consoleInfo.dwSize.Y - 1;

	return 0;
}

void 
ConFillToEndOfLine()
{
	DWORD rc = 0;

	int size = ConScreenSizeX();
	for (int i = ConGetCursorX(); i < size; i++)
		WriteConsole(hOutputConsole, (char *)" ", 1, &rc, 0);
}

int 
ConWriteString(char* pszString, int cbString)
{
	DWORD Result = 0;
	int needed = 0;
	int cnt = 0;
	wchar_t* utf16 = NULL;

	if (pszString == NULL)
		return 0;

	if ((needed = MultiByteToWideChar(CP_UTF8, 0, pszString, cbString, NULL, 0)) == 0 ||
	    (utf16 = malloc(needed * sizeof(wchar_t))) == NULL ||
	    (cnt = MultiByteToWideChar(CP_UTF8, 0, pszString, cbString, utf16, needed)) == 0) {
		Result = (DWORD)printf_s(pszString);
	} else {
		if (hOutputConsole)
			WriteConsoleW(hOutputConsole, utf16, cnt, &Result, 0);
		else
			Result = (DWORD)wprintf_s(utf16);
	}

	if (utf16)
		free(utf16);

	return cbString;
}

int 
ConTranslateAndWriteString(char* pszString, int cbString)
{
	DWORD Result = 0;

	if (pszString == NULL)
		return 0;

	if (hOutputConsole)
		WriteConsole(hOutputConsole, pszString, cbString, &Result, 0);
	else
		Result = (DWORD)printf_s(pszString);

	return Result;
}

BOOL 
ConWriteChar(CHAR ch)
{
	int X, Y, Result;
	BOOL fOkay = TRUE;

	Y = ConGetCursorY();
	X = ConGetCursorX();

	switch (ch) {
	case 0x8: /* BackSpace */
		if (X == 0) {
			ConSetCursorPosition(ScreenX - 1, --Y);
			WriteConsole(hOutputConsole, " ", 1, (LPDWORD)&Result, 0);
			ConSetCursorPosition(ScreenX - 1, Y);
		} else {
			ConSetCursorPosition(X - 1, Y);
			WriteConsole(hOutputConsole, " ", 1, (LPDWORD)&Result, 0);
			ConSetCursorPosition(X - 1, Y);
		}

		break;
	case '\r':
		ConSetCursorPosition(0, Y);

		break;
	case '\n':
		Y++;
		if (Y > ScrollBottom - 1) {
			ConScrollDown(ScrollTop, ScrollBottom);
			ConSetCursorPosition(0, ScrollBottom);
		} else
			ConSetCursorPosition(0, Y);
		break;
	default:
		fOkay = (BOOL)WriteConsole(hOutputConsole, &ch, 1, (LPDWORD)&Result, 0);

		/* last coord */
		if (X >= ScreenX - 1) {
			if (Y >= ScrollBottom - 1) { /* last coord */
				ConScrollDown(ScrollTop, ScrollBottom);
				ConMoveCursorPosition(-ConGetCursorX(), 0);
			} else
				ConMoveCursorPosition(-ConGetCursorX(), 1);
		}
		break;
	}

	return fOkay;
}

BOOL 
ConWriteCharW(WCHAR ch)
{
	int X, Y, Result;
	BOOL fOkay = TRUE;

	Y = ConGetCursorY();
	X = ConGetCursorX();

	switch (ch) {
	case 0x8: /* BackSpace */
		if (X == 0) {
			ConSetCursorPosition(ScreenX - 1, --Y);
			WriteConsole(hOutputConsole, " ", 1, (LPDWORD)&Result, 0);
			ConSetCursorPosition(ScreenX - 1, Y);
		} else {
			ConSetCursorPosition(X - 1, Y);
			WriteConsole(hOutputConsole, " ", 1, (LPDWORD)&Result, 0);
			ConSetCursorPosition(X - 1, Y);
		}
		break;
	case L'\r':
		ConSetCursorPosition(0, Y);
		break;

	case L'\n':
		Y++;
		if (Y > ScrollBottom - 1) {
			ConScrollDown(ScrollTop, ScrollBottom);
			ConSetCursorPosition(0, ScrollBottom);
		}
		else
			ConSetCursorPosition(0, Y);
		break;

	default:
		fOkay = (BOOL)WriteConsoleW(hOutputConsole, &ch, 1, (LPDWORD)&Result, 0);

		if (X >= ScreenX - 1) { /* last coord */
			if (Y >= ScrollBottom - 1) { /* last coord */
				ConScrollDown(ScrollTop, ScrollBottom);
				ConMoveCursorPosition(-ConGetCursorX(), 0);
			} else
				ConMoveCursorPosition(-ConGetCursorX(), 1);
		}
		break;
	}
	return fOkay;
}


/* Special Function for handling TABS and other bad control chars */
int 
ConWriteConsole(char *pData, int NumChars)
{
	int X, CurrentY, CurrentX, Result;

	for (X = 0; (X < NumChars) && (pData[X] != '\0'); X++) {
		switch (pData[X]) {
		case 0: /* FALLTHROUGH */
		case 1: /* FALLTHROUGH */
		case 2: /* FALLTHROUGH */
		case 3: /* FALLTHROUGH */
		case 4: /* FALLTHROUGH */
		case 5: /* FALLTHROUGH */
		case 6: /* FALLTHROUGH */
		case 11: /* FALLTHROUGH */
			break;

		case 7:
			Beep(1000, 400);
			break;

		case 8:
			ConMoveCursorPosition(-1, 0);
			WriteConsole(hOutputConsole, " ", 1, (LPDWORD)&Result, 0);
			ConMoveCursorPosition(-1, 0);
			break;

		case 9:
		{
			int i, MoveRight = TAB_LENGTH - (ConGetCursorX() % TAB_LENGTH);

			for (i = 0; i < MoveRight; i++)
				WriteConsole(hOutputConsole, " ", 1, (LPDWORD)&Result, 0);
		}
		break;

		case 10:
			CurrentY = ConGetCursorY() + 1;
			if (CurrentY >= ScrollBottom) {
				ConScrollDown(ScrollTop, ScrollBottom);
				ConMoveCursorPosition(-ConGetCursorX(), 0);
			} else
				ConMoveCursorPosition(0, 1);
			break;

		case 12:
			ConClearScreen();
			ConSetCursorPosition(0, 0);
			break;

		case 13:
			ConMoveCursorPosition(-ConGetCursorX(), 0);
			break;

		case 14: /* FALLTHROUGH */
		case 15:
			break;

		default:
		{
			CurrentY = ConGetCursorY();
			CurrentX = ConGetCursorX();

			WriteConsole(hOutputConsole, &pData[X], 1, (LPDWORD)&Result, 0);

			if (CurrentX >= ScreenX - 1) { /* last coord */
				if (CurrentY >= ScrollBottom - 1) { /* last coord */
					ConScrollDown(ScrollTop, ScrollBottom);
					ConMoveCursorPosition(-ConGetCursorX(), 0);
				} else
					ConMoveCursorPosition(-ConGetCursorX(), 1);
			}
		}
		}
	}

	return X;
}

PCHAR 
ConWriteLine(char* pData)
{
	PCHAR pCurrent, pNext, pTab;
	DWORD Result;
	size_t distance, tabCount, pos;
	size_t tabLength, charCount;

	pCurrent = pData;
	pNext = strchr(pCurrent, '\r');
	if (pNext != NULL) {
		distance = pNext - pCurrent;

		if (distance > (size_t)ScreenX)
			distance = (size_t)ScreenX;

		pos = 0;
		tabCount = 0;
		pTab = strchr(pCurrent, TAB_CHAR);
		if ((pTab != NULL) && (pTab < pNext)) {
			/* Tab exists in string So we use our WriteString */
			while ((pTab != NULL) && (pTab < pNext) && (pos < (size_t)ScreenX)) {
				tabCount++;
				charCount = (pTab - pCurrent) - 1;	/* Ignore actual TAB since we add 8 for it */
				pos = charCount + (tabCount * TAB_LENGTH);
				pTab++;	/* increment past last tab */
				pTab = strchr(pTab, TAB_CHAR);
			}

			tabLength = (tabCount * TAB_LENGTH);

			distance = ConWriteConsole(pCurrent, (int)distance); /* Special routine for handling TABS */

		} else
			WriteConsole(hOutputConsole, pCurrent, (DWORD)distance, &Result, 0);

		ConSetCursorPosition(0, ConGetCursorY() + 1);

		pCurrent += (distance + 2);  /* Add one to always skip last char printed */
	} else {
		distance = strlen(pCurrent);
		if (distance > (size_t)ScreenX)
			distance = (size_t)ScreenX;
		WriteConsole(hOutputConsole, pCurrent, (DWORD)distance, &Result, 0);
		pCurrent += distance;
	}

	return pCurrent;
}

PCHAR
ConDisplayData(char* pData, int NumLines)
{
	PCHAR pCurrent, pNext, pTab;
	DWORD Result;
	size_t Y, distance, pos, add;
	int linecnt = 0;

	pCurrent = pData;
	for (; (pCurrent) && ((Y = (size_t)ConGetCursorY()) <= (size_t)ScrollBottom) && (*pCurrent != '\0'); ) {
		pNext = strchr(pCurrent, '\n');
		if (pNext != NULL) {
			--pNext;
			if (*pNext != '\r') {
				pNext++;
				add = 1;
			}
			else
				add = 2;
			distance = pNext - pCurrent;

			if (distance > 0 && linecnt < NumLines) {
				pos = 0;
				pTab = strchr(pCurrent, TAB_CHAR);
				if ((distance > (size_t)ScreenX) || ((pTab != NULL) && (pTab < pNext)))
					ConWriteConsole(pCurrent, (int)distance); /* Special routine for handling TABS */
				else
					WriteConsole(hOutputConsole, pCurrent, (DWORD)distance, &Result, 0);
			}
			ConMoveCursorPosition(-ConGetCursorX(), 1);
			pCurrent += (distance + add);  /* Add one to always skip last char printed */
			linecnt++;
		} else {
			distance = strlen(pCurrent);
			if (distance > (size_t)ScreenX)
				distance = ScreenX;
			if (linecnt < NumLines)
				WriteConsole(hOutputConsole, pCurrent, (DWORD)distance, &Result, 0);
			return pCurrent + distance;
		}
	}
	return pCurrent;
}

int 
Con_printf(const char *Format, ...)
{
	va_list va_data;
	int len;
	char temp[4096];

	memset(temp, '\0', sizeof(temp));
	va_start(va_data, Format);
	len = vsnprintf_s(temp, sizeof(temp), _TRUNCATE, Format, va_data);
	if (len == -1) {
		error("Error from vsnprintf_s!");
		return -1;
	}
	ConWriteConsole(temp, len);
	va_end(va_data);

	return len;
}

BOOL 
ConDisplayCursor(BOOL bVisible)
{
	CONSOLE_CURSOR_INFO ConsoleCursorInfo;

	if (GetConsoleCursorInfo(hOutputConsole, &ConsoleCursorInfo)) {
		ConsoleCursorInfo.bVisible = bVisible;
		return SetConsoleCursorInfo(hOutputConsole, &ConsoleCursorInfo);
	}

	return FALSE;
}

void 
ConClearScreen()
{
	DWORD dwWritten;
	COORD Coord;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	SMALL_RECT srcWindow;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;

	Coord.X = 0;
	Coord.Y = 0;

	DWORD dwNumChar = (consoleInfo.dwSize.Y) * (consoleInfo.dwSize.X);
	FillConsoleOutputCharacter(hOutputConsole, ' ', dwNumChar, Coord, &dwWritten);
	FillConsoleOutputAttribute(hOutputConsole, consoleInfo.wAttributes, dwNumChar, Coord, &dwWritten);
	srcWindow = consoleInfo.srWindow;
	ConSetCursorPosition(0, 0);
}

void
ConClearScrollRegion()
{
	DWORD dwWritten;
	COORD Coord;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;

	Coord.X = 0;
	Coord.Y = ScrollTop + consoleInfo.srWindow.Top;
	FillConsoleOutputCharacter(hOutputConsole, ' ', (DWORD)consoleInfo.dwSize.X * (DWORD)ScrollBottom,
		Coord, &dwWritten);

	FillConsoleOutputAttribute(hOutputConsole, consoleInfo.wAttributes,
		(DWORD)consoleInfo.dwSize.X * (DWORD)ScrollBottom, Coord, &dwWritten);

	ConSetCursorPosition(0, ScrollTop);
}

void
ConClearEOScreen()
{
	DWORD dwWritten;
	COORD Coord;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;

	Coord.X = 0;
	Coord.Y = (short)(ConGetCursorY() + 1) + consoleInfo.srWindow.Top;
	FillConsoleOutputCharacter(hOutputConsole, ' ',
		(DWORD)(consoleInfo.dwSize.X)*
		(DWORD)(consoleInfo.srWindow.Bottom - Coord.Y + 1),
		Coord, &dwWritten);
	FillConsoleOutputAttribute(hOutputConsole, consoleInfo.wAttributes,
		(DWORD)(consoleInfo.dwSize.X)*
		(DWORD)(consoleInfo.srWindow.Bottom - Coord.Y + 1),
		Coord, &dwWritten);

	ConClearEOLine();
}

void 
ConClearBOScreen()
{
	DWORD dwWritten;
	COORD Coord;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;

	Coord.X = 0;
	Coord.Y = 0;
	FillConsoleOutputCharacter(hOutputConsole, ' ',
		(DWORD)(consoleInfo.dwSize.X)*
		(DWORD)(consoleInfo.dwSize.Y - ConGetCursorY() - 1),
		Coord, &dwWritten);
	FillConsoleOutputAttribute(hOutputConsole, consoleInfo.wAttributes,
		(DWORD)(consoleInfo.dwSize.X)*
		(DWORD)(consoleInfo.dwSize.Y - ConGetCursorY() - 1),
		Coord, &dwWritten);

	ConClearBOLine();
}

void 
ConClearLine()
{
	DWORD dwWritten;
	COORD Coord;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;

	Coord.X = 0;
	Coord.Y = ConGetCursorY();
	FillConsoleOutputAttribute(hOutputConsole, consoleInfo.wAttributes, ScreenX, Coord, &dwWritten);
	FillConsoleOutputCharacter(hOutputConsole, ' ', ScreenX, Coord, &dwWritten);
}

void 
ConClearEOLine()
{
	DWORD dwWritten;
	COORD Coord;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;;

	Coord.X = ConGetCursorX() + consoleInfo.srWindow.Left;
	Coord.Y = ConGetCursorY() + consoleInfo.srWindow.Top;

	FillConsoleOutputCharacter(hOutputConsole, ' ',
		(DWORD)(ScreenX - ConGetCursorX()),
		Coord, &dwWritten);
	FillConsoleOutputAttribute(hOutputConsole, consoleInfo.wAttributes,
		(DWORD)(ScreenX - ConGetCursorX()),
		Coord, &dwWritten);
}

void
ConClearNFromCursorRight(int n)
{
	DWORD dwWritten;
	COORD Coord;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;

	Coord.X = ConGetCursorX() + consoleInfo.srWindow.Left;
	Coord.Y = ConGetCursorY() + consoleInfo.srWindow.Top;
	FillConsoleOutputCharacter(hOutputConsole, ' ', (DWORD)n, Coord, &dwWritten);
	FillConsoleOutputAttribute(hOutputConsole, consoleInfo.wAttributes, (DWORD)n, Coord, &dwWritten);
}

void 
ConClearNFromCursorLeft(int n)
{
	DWORD dwWritten;
	COORD Coord;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;

	Coord.X = ConGetCursorX() + consoleInfo.srWindow.Left - n;
	Coord.Y = ConGetCursorY() + consoleInfo.srWindow.Top;
	FillConsoleOutputCharacter(hOutputConsole, ' ', (DWORD)n, Coord, &dwWritten);
	FillConsoleOutputAttribute(hOutputConsole, consoleInfo.wAttributes, (DWORD)n, Coord, &dwWritten);
}

void 
ConScrollDownEntireBuffer()
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;
	ConScrollDown(0, consoleInfo.dwSize.Y - 1);
	return;
}

void 
ConScrollUpEntireBuffer()
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;
	ConScrollUp(0, consoleInfo.dwSize.Y - 1);
	return;
}

void 
ConScrollUp(int topline, int botline)
{
	SMALL_RECT ScrollRect;
	SMALL_RECT ClipRect;
	COORD destination;
	CHAR_INFO Fill;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;

	if ((botline - topline) == consoleInfo.dwSize.Y - 1) { /* scrolling whole buffer */
		ScrollRect.Top = topline;
		ScrollRect.Bottom = botline;
	} else {
		ScrollRect.Top = topline + consoleInfo.srWindow.Top;
		ScrollRect.Bottom = botline + consoleInfo.srWindow.Top;
	}

	ScrollRect.Left = 0;
	ScrollRect.Right = ConScreenSizeX() - 1;

	ClipRect.Top = ScrollRect.Top;
	ClipRect.Bottom = ScrollRect.Bottom;
	ClipRect.Left = ScrollRect.Left;
	ClipRect.Right = ScrollRect.Right;

	destination.X = 0;
	destination.Y = ScrollRect.Top + 1;

	Fill.Attributes = consoleInfo.wAttributes;
	Fill.Char.AsciiChar = ' ';

	BOOL bRet = ScrollConsoleScreenBuffer(hOutputConsole,
		&ScrollRect,
		&ClipRect,
		destination,
		&Fill
	);
}

void
ConMoveVisibleWindow(int offset)
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	SMALL_RECT visibleWindowRect;
	errno_t r = 0;

	memset(&visibleWindowRect, 0, sizeof(SMALL_RECT));
	if (GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo)) {
		/* Check if applying the offset results in console buffer overflow.
		* if yes, then scrolldown the console buffer.
		*/
		if ((consoleInfo.srWindow.Bottom + offset) >= (consoleInfo.dwSize.Y - 1)) {
			for (int i = 0; i < offset; i++)
				ConScrollDown(0, consoleInfo.dwSize.Y - 1);

			if (GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo) == FALSE) {
				error("GetConsoleScreenBufferInfo failed with %d", GetLastError());
				return;
			}
			if ((r = memcpy_s(&visibleWindowRect, sizeof(visibleWindowRect), &consoleInfo.srWindow, sizeof(visibleWindowRect))) != 0) {
				error("memcpy_s failed with error: %d.", r);
				return;
			}
		} else {
			if ((r = memcpy_s(&visibleWindowRect, sizeof(visibleWindowRect), &consoleInfo.srWindow, sizeof(visibleWindowRect))) != 0) {
				error("memcpy_s failed with error: %d.", r);
				return;
			}
			visibleWindowRect.Top += offset;
			visibleWindowRect.Bottom += offset;
		}

		SetConsoleWindowInfo(hOutputConsole, TRUE, &visibleWindowRect);
	}
}

void 
ConScrollDown(int topline, int botline)
{
	SMALL_RECT ScrollRect;	
	COORD destination;
	CHAR_INFO Fill;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;

	if ((botline - topline) == consoleInfo.dwSize.Y - 1) { /* scrolling whole buffer */
		ScrollRect.Top = topline;
		ScrollRect.Bottom = botline;
	} else {
		ScrollRect.Top = topline + consoleInfo.srWindow.Top + 1;
		ScrollRect.Bottom = botline + consoleInfo.srWindow.Top;
	}

	ScrollRect.Left = 0;
	ScrollRect.Right = ConScreenSizeX() - 1;

	destination.X = 0;
	destination.Y = ScrollRect.Top - 1;

	Fill.Attributes = consoleInfo.wAttributes;
	Fill.Char.AsciiChar = ' ';

	BOOL bRet = ScrollConsoleScreenBuffer(hOutputConsole,
		&ScrollRect,
		NULL,
		destination,
		&Fill
	);
}

void
ConClearBOLine()
{
	DWORD dwWritten;
	COORD Coord;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;

	Coord.X = 0;
	Coord.Y = (short)(ConGetCursorY());
	FillConsoleOutputAttribute(hOutputConsole, consoleInfo.wAttributes,
		(DWORD)(ConGetCursorX()),
		Coord, &dwWritten);
	FillConsoleOutputCharacter(hOutputConsole, ' ',
		(DWORD)(ConGetCursorX()),
		Coord, &dwWritten);
}

void
ConSetCursorPosition(int x, int y)
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	COORD Coord;
	int rc;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;

	Coord.X = (short)(x);
	Coord.Y = (short)(y);

	if ((y > consoleInfo.dwSize.Y - 1) && y > LastCursorY) {
		for (int n = LastCursorY; n < y; n++)
			GoToNextLine();
	}

	if (y >= consoleInfo.dwSize.Y) {
		Coord.Y = consoleInfo.dwSize.Y - 1;
	}

	if (!SetConsoleCursorPosition(hOutputConsole, Coord))
		rc = GetLastError();

	LastCursorX = x;
	LastCursorY = y;
}

BOOL 
ConChangeCursor(CONSOLE_CURSOR_INFO *pCursorInfo)
{
	return SetConsoleCursorInfo(hOutputConsole, pCursorInfo);
}

void
ConGetCursorPosition(int *x, int *y)
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo)) {
		*x = consoleInfo.dwCursorPosition.X;
		*y = consoleInfo.dwCursorPosition.Y;
	}
}

int 
ConGetCursorX()
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return 0;

	return consoleInfo.dwCursorPosition.X;
}

int
is_cursor_at_lastline_of_visible_window()
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	int return_val = 0;

	if (GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo)) {
		int cursor_linenum_in_visible_window = consoleInfo.dwCursorPosition.Y - consoleInfo.srWindow.Top;
		if (cursor_linenum_in_visible_window >= ConVisibleWindowHeight() - 1)
			return_val = 1;
	}

	return return_val;
}

int 
ConGetCursorY()
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return 0;

	return (consoleInfo.dwCursorPosition.Y - consoleInfo.srWindow.Top);
}

int 
ConGetBufferHeight()
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return 0;

	return (consoleInfo.dwSize.Y - 1);
}

void 
ConMoveCursorPosition(int x, int y)
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	COORD Coord;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;

	Coord.X = (short)(consoleInfo.dwCursorPosition.X + x);
	Coord.Y = (short)(consoleInfo.dwCursorPosition.Y + y);

	SetConsoleCursorPosition(hOutputConsole, Coord);
}

void 
ConGetRelativeCursorPosition(int *x, int *y)
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;

	*x -= consoleInfo.srWindow.Left;
	*y -= consoleInfo.srWindow.Top;
}

void 
ConDeleteChars(int n)
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	COORD coord;
	CHAR_INFO chiBuffer[256];   // 1 row, 256 characters
	SMALL_RECT sr;
	COORD temp;
	int result;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return;

	coord.X = (short)(consoleInfo.dwCursorPosition.X);
	coord.Y = (short)(consoleInfo.dwCursorPosition.Y);

	sr.Left = coord.X + n;
	sr.Top = coord.Y;
	sr.Bottom = coord.Y;
	sr.Right = consoleInfo.srWindow.Right;

	temp.X = 256;
	temp.Y = 1;
	result = ReadConsoleOutput(hOutputConsole,		/* console screen buffer handle */
				   (PCHAR_INFO)chiBuffer,	/* address of buffer that receives data */
				   temp,			/* column-row size of destination buffer */
				   ZeroCoord,			/* upper-left cell to write to */
				   &sr				/* address of rectangle to read from */
	);
	ConClearEOLine();

	sr.Left = coord.X;
	temp.X = 256;
	temp.Y = 1;

	sr.Right -= n;
	result = WriteConsoleOutput(hOutputConsole, (PCHAR_INFO)chiBuffer, temp, ZeroCoord, &sr);
}


SCREEN_HANDLE 
ConSaveScreenHandle(SCREEN_HANDLE hScreen)
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	PSCREEN_RECORD pScreenRec = (PSCREEN_RECORD)hScreen;
	int result, width, height;

	if (hOutputConsole == NULL)
		return NULL;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return (NULL);

	if (pScreenRec == NULL) {
		pScreenRec = (PSCREEN_RECORD)malloc(sizeof(SCREEN_RECORD));
		if (pScreenRec == NULL)
			fatal("out of memory");
		
		pScreenRec->pScreenBuf = NULL;
	}

	pScreenRec->srWindowRect = consoleInfo.srWindow;
	width = consoleInfo.srWindow.Right - consoleInfo.srWindow.Left + 1;
	height = consoleInfo.srWindow.Bottom - consoleInfo.srWindow.Top + 1;
	pScreenRec->ScreenSize.X = width;
	pScreenRec->ScreenSize.Y = height;
	pScreenRec->ScreenCursor.X = consoleInfo.dwCursorPosition.X - consoleInfo.srWindow.Left;
	pScreenRec->ScreenCursor.Y = consoleInfo.dwCursorPosition.Y - consoleInfo.srWindow.Top;

	if (pScreenRec->pScreenBuf == NULL)
		pScreenRec->pScreenBuf = (PCHAR_INFO)malloc(sizeof(CHAR_INFO) * width * height);

	if (!pScreenRec->pScreenBuf) {
		if (pScreenRec != (PSCREEN_RECORD)hScreen)
			free(pScreenRec);
		
		return NULL;
	}

	result = ReadConsoleOutput(hOutputConsole,			/* console screen buffer handle */
				   (PCHAR_INFO)(pScreenRec->pScreenBuf),/* address of buffer that receives data */ 
				   pScreenRec->ScreenSize,		/* column-row size of destination buffer */
				   ZeroCoord,				/* upper-left cell to write to */
				   &consoleInfo.srWindow		/* address of rectangle to read from */
	);

	return((SCREEN_HANDLE)pScreenRec);
}

BOOL 
ConRestoreScreenHandle(SCREEN_HANDLE hScreen)
{
	BOOL fOkay = FALSE;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	COORD beginOfScreen = { 0, 0 };
	PCHAR_INFO pSavedCharInfo;
	DWORD dwWritten;
	PSCREEN_RECORD pScreenRec = (PSCREEN_RECORD)hScreen;
	int  width, height;

	if (hOutputConsole == NULL)
		return FALSE;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return (FALSE);

	width = consoleInfo.srWindow.Right - consoleInfo.srWindow.Left + 1;
	height = consoleInfo.srWindow.Bottom - consoleInfo.srWindow.Top + 1;

	beginOfScreen.X = consoleInfo.srWindow.Left;
	beginOfScreen.Y = consoleInfo.srWindow.Top;
	FillConsoleOutputCharacter(hOutputConsole, ' ', (DWORD)width*height, beginOfScreen, &dwWritten);

	pSavedCharInfo = (PCHAR_INFO)(pScreenRec->pScreenBuf);
	SetConsoleTextAttribute(hOutputConsole, pSavedCharInfo->Attributes);

	FillConsoleOutputAttribute(hOutputConsole, pSavedCharInfo->Attributes,
		(DWORD)width*height,
		beginOfScreen, &dwWritten);

	fOkay = WriteConsoleOutput(hOutputConsole,			/* handle to a console screen buffer */
				  (PCHAR_INFO)(pScreenRec->pScreenBuf),	/* pointer to buffer with data to write  */
				  pScreenRec->ScreenSize,		/* column-row size of source buffer */
				  ZeroCoord,				/* upper-left cell to write from */
				  &consoleInfo.srWindow			/* pointer to rectangle to write to */
	);
	
	SetConsoleWindowInfo(hOutputConsole, TRUE, &pScreenRec->srWindowRect);
	ConSetCursorPosition(pScreenRec->ScreenCursor.X, pScreenRec->ScreenCursor.Y);
	
	return fOkay;
}

BOOL 
ConRestoreScreenColors()
{
	SCREEN_HANDLE hScreen = pSavedScreenRec;
	BOOL fOkay = FALSE;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	COORD beginOfScreen = { 0, 0 };
	PCHAR_INFO pSavedCharInfo;
	DWORD dwWritten;
	PSCREEN_RECORD pScreenRec = (PSCREEN_RECORD)hScreen;

	if (hOutputConsole == NULL)
		return FALSE;

	if (pSavedScreen == NULL)
		return FALSE;

	if (!GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo))
		return (FALSE);

	beginOfScreen.X = consoleInfo.srWindow.Left;
	beginOfScreen.Y = consoleInfo.srWindow.Top;

	FillConsoleOutputCharacter(hOutputConsole, ' ',
		(DWORD)pScreenRec->ScreenSize.X*pScreenRec->ScreenSize.Y,
		beginOfScreen, &dwWritten);

	pSavedCharInfo = (PCHAR_INFO)(pScreenRec->pScreenBuf);
	SetConsoleTextAttribute(hOutputConsole, pSavedCharInfo->Attributes);

	FillConsoleOutputAttribute(hOutputConsole, pSavedCharInfo->Attributes,
		(DWORD)pScreenRec->ScreenSize.X*pScreenRec->ScreenSize.Y,
		beginOfScreen, &dwWritten);

	return fOkay;
}

void 
ConDeleteScreenHandle(SCREEN_HANDLE hScreen)
{
	PSCREEN_RECORD pScreenRec = (PSCREEN_RECORD)hScreen;

	free(pScreenRec->pScreenBuf);
	free(pScreenRec);
}

/* Restores Previous Saved screen info and buffer */
BOOL
ConRestoreScreen()
{
	return ConRestoreScreenHandle(pSavedScreenRec);
}

/* Saves current screen info and buffer */
void
ConSaveScreen()
{
	pSavedScreenRec = (PSCREEN_RECORD)ConSaveScreenHandle(pSavedScreenRec);	
}

void
ConSaveViewRect()
{
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	if (GetConsoleScreenBufferInfo(hOutputConsole, &csbi))
		SavedViewRect = csbi.srWindow;
}

void
ConRestoreViewRect()
{
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	HWND hwnd = FindWindow(NULL, consoleTitle);

	WINDOWPLACEMENT wp;
	wp.length = sizeof(WINDOWPLACEMENT);
	GetWindowPlacement(hwnd, &wp);

	if (GetConsoleScreenBufferInfo(hOutputConsole, &consoleInfo) &&
	    ((consoleInfo.srWindow.Top != SavedViewRect.Top ||
	      consoleInfo.srWindow.Bottom != SavedViewRect.Bottom))) {
		if ((SavedViewRect.Right - SavedViewRect.Left > consoleInfo.dwSize.X) ||
		    (wp.showCmd == SW_SHOWMAXIMIZED)) {
			COORD coordScreen;
			coordScreen.X = SavedViewRect.Right - SavedViewRect.Left;
			coordScreen.Y = consoleInfo.dwSize.Y;
			SetConsoleScreenBufferSize(hOutputConsole, coordScreen);
			
			ShowWindow(hwnd, SW_SHOWMAXIMIZED);
		} else
			ShowWindow(hwnd, SW_RESTORE);

		SetConsoleWindowInfo(hOutputConsole, TRUE, &SavedViewRect);
	}
}

BOOL
ConIsRedirected(HANDLE hInput)
{
	DWORD dwMode;
	return !GetConsoleMode(hInput, &dwMode);
}

HANDLE
GetConsoleOutputHandle()
{
	SECURITY_ATTRIBUTES sa;

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	HANDLE hTemp = GetStdHandle(STD_OUTPUT_HANDLE);

	if (ConIsRedirected(hTemp))
		hTemp = CreateFile(TEXT("CONOUT$"), GENERIC_READ | GENERIC_WRITE,
				   FILE_SHARE_WRITE | FILE_SHARE_READ,
				   &sa, OPEN_EXISTING, 0, NULL);

	return hTemp;
}

HANDLE
GetConsoleInputHandle()
{
	SECURITY_ATTRIBUTES sa;

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	HANDLE hTemp = GetStdHandle(STD_INPUT_HANDLE);

	if (ConIsRedirected(hTemp))
		hTemp = CreateFile(TEXT("CONIN$"), GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_WRITE | FILE_SHARE_READ,
			&sa, OPEN_EXISTING, 0, NULL);

	return hTemp;
}

void
ConSaveWindowsState()
{
	CONSOLE_SCREEN_BUFFER_INFOEX csbiex;
	csbiex.cbSize = sizeof(CONSOLE_SCREEN_BUFFER_INFOEX);

	if (!GetConsoleScreenBufferInfoEx(hOutputConsole, &csbiex))
		return;

	SavedWindowState = csbiex;
}

void
ConMoveCursorTopOfVisibleWindow()
{
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	int offset;

	if (GetConsoleScreenBufferInfo(hOutputConsole, &csbi)) {
		offset = csbi.dwCursorPosition.Y - csbi.srWindow.Top;
		ConMoveVisibleWindow(offset);

		ConSaveViewRect();
	}
}

HANDLE
get_console_handle(FILE *stream, DWORD * mode)
{
	int file_num = 0, ret = 0;
	intptr_t lHandle = 0;
	HANDLE hFile = NULL;
	DWORD type = 0;

	file_num = (_fileno)(stream);
	if (file_num == -1) {
		return INVALID_HANDLE_VALUE;
	}

	lHandle = _get_osfhandle(file_num);
	if (lHandle == -1 && errno == EBADF) {
		return INVALID_HANDLE_VALUE;
	}

	type = GetFileType((HANDLE)lHandle);
	if (type == FILE_TYPE_CHAR && file_num >= 0 && file_num <= 2) {
		if (file_num == 0)
			hFile = GetStdHandle(STD_INPUT_HANDLE);
		else if (file_num == 1)
			hFile = GetStdHandle(STD_OUTPUT_HANDLE);
		else if (file_num == 2)
			hFile = GetStdHandle(STD_ERROR_HANDLE);

		if ((hFile != NULL) &&
			(hFile != INVALID_HANDLE_VALUE) &&
			(GetFileType(hFile) == FILE_TYPE_CHAR) &&
			GetConsoleMode(hFile, mode))
			return hFile;
	}
	return INVALID_HANDLE_VALUE;
}
