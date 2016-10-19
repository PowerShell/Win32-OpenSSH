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
/* console.c
 * 
 * Common library for Windows Console Screen IO.
 * Contains Windows console related definition so that emulation code can draw
 * on Windows console screen surface.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <console.h>
#include <conio.h>

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING  0x4
#endif

HANDLE	hOutputConsole = NULL;
DWORD	dwSavedAttributes = 0;
WORD	wStartingAttributes = 0;

int ScreenX;
int ScreenY;
int ScrollTop;
int ScrollBottom;
int LastCursorX;
int LastCursorY;

char *pSavedScreen = NULL;
static COORD ZeroCoord = {0,0};
COORD SavedScreenSize = {0,0};
COORD SavedScreenCursor = {0, 0 };
SMALL_RECT SavedViewRect = {0,0,0,0};
CONSOLE_SCREEN_BUFFER_INFOEX SavedWindowState;

typedef struct _SCREEN_RECORD{
    PCHAR_INFO pScreenBuf;
    COORD ScreenSize;
    COORD ScreenCursor;
    SMALL_RECT  srWindowRect;
}SCREEN_RECORD,*PSCREEN_RECORD;

PSCREEN_RECORD pSavedScreenRec = NULL;

/* ************************************************************ */
/* Function: ConInit         									*/
/* Used to Initialize the Console for output                	*/
/* ************************************************************ */
int ConInit( DWORD OutputHandle, BOOL fSmartInit ) 
{
    OSVERSIONINFO os;
    DWORD dwAttributes = 0;
    DWORD dwRet = 0;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    static bool bFirstConInit = true;

    os.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );
    GetVersionEx( &os );

    hOutputConsole = GetStdHandle(OutputHandle);
    if (hOutputConsole == INVALID_HANDLE_VALUE) {
        dwRet = GetLastError();
        printf("GetStdHandle failed with %d\n", dwRet);
        return dwRet;
    }

    if (!GetConsoleMode(hOutputConsole, &dwSavedAttributes)) {
        dwRet = GetLastError();
        printf("GetConsoleMode failed with %d\n", GetLastError());
        return dwRet;
    }

    dwAttributes = dwSavedAttributes;

    if ( os.dwPlatformId == VER_PLATFORM_WIN32_NT )
    {
        char *term = getenv("TERM");
        dwAttributes = (DWORD)ENABLE_PROCESSED_OUTPUT;  // PERFECT in NT

        if (term != NULL && (_stricmp(term, "ansi") == 0 || _stricmp(term, "passthru")))
            dwAttributes |= (DWORD)ENABLE_VIRTUAL_TERMINAL_PROCESSING;

        SetConsoleMode(hOutputConsole, dwAttributes); // Windows NT
    }
    else
    {
        dwAttributes = (DWORD)ENABLE_WRAP_AT_EOL_OUTPUT;	// Doesn't always print last column & doesn't handle CRLF
        SetConsoleMode(hOutputConsole, dwAttributes);	// Windows 95
    }

    ConSetScreenX();
    ConSetScreenY();
    ScrollTop = 0;
    ScrollBottom = ConWindowSizeY();

    if (GetConsoleScreenBufferInfo(hOutputConsole, &csbi))
        SavedViewRect = csbi.srWindow;

    return 0;
}


/* ************************************************************ */
/* Function: ConUnInit         									*/
/* Used to Uninitialize the Console                         	*/
/* ************************************************************ */
int ConUnInit( void ) 
{
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if ( hOutputConsole == NULL )
        return 0;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return 0;

    SetConsoleMode(hOutputConsole, dwSavedAttributes);

    return 0;
}

/* ************************************************************ */
/* Function: ConUnInit         									*/
/* Used to Uninitialize the Console                         	*/
/* ************************************************************ */
int ConUnInitWithRestore( void ) 
{
    DWORD dwWritten;
    COORD Coord ;
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if ( hOutputConsole == NULL )
        return 0;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return 0;

    SetConsoleMode(hOutputConsole, dwSavedAttributes);

    Coord = ConsoleInfo.dwCursorPosition;
    Coord.X = 0;

    DWORD dwNumChar = (ConsoleInfo.dwSize.Y - ConsoleInfo.dwCursorPosition.Y) *
        ConsoleInfo.dwSize.X;

    FillConsoleOutputCharacter(hOutputConsole, ' ', dwNumChar,
        Coord, &dwWritten);
    FillConsoleOutputAttribute(hOutputConsole, wStartingAttributes, dwNumChar,
        Coord, &dwWritten);

    SetConsoleTextAttribute(hOutputConsole, wStartingAttributes);

    return 0;
}

BOOL ConSetScreenRect( int xSize, int ySize )
{
    BOOL bSuccess = TRUE;

    CONSOLE_SCREEN_BUFFER_INFO csbi; /* hold current console buffer info */
    SMALL_RECT srWindowRect; /* hold the new console size */
    COORD coordScreen;

    bSuccess = GetConsoleScreenBufferInfo(hOutputConsole, &csbi);
    if (!bSuccess) {
        return bSuccess;
    }

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
    if (csbi.dwSize.X < coordScreen.X ||
        csbi.dwSize.Y < coordScreen.Y)
    {
        bSuccess = SetConsoleScreenBufferSize(hOutputConsole, coordScreen);
        if (bSuccess)
            bSuccess = SetConsoleWindowInfo(hOutputConsole, TRUE, &srWindowRect);
    }
    else
    {
        bSuccess = SetConsoleWindowInfo(hOutputConsole, TRUE, &srWindowRect);
        if (bSuccess)
            bSuccess = SetConsoleScreenBufferSize(hOutputConsole, coordScreen);		
    }

    if (bSuccess)
        ConSaveViewRect();

    /* if the current buffer *is* the size we want, don't do anything! */
    return bSuccess;
}

BOOL ConSetScreenSize( int xSize, int ySize )
{
    BOOL bSuccess = TRUE;

    CONSOLE_SCREEN_BUFFER_INFO csbi; /* hold current console buffer info */
    SMALL_RECT srWindowRect; /* hold the new console size */
    COORD coordScreen;

    bSuccess = GetConsoleScreenBufferInfo(hOutputConsole, &csbi);
    if (!bSuccess) {
        return bSuccess;
    }

    /* get the largest size we can size the console window to */
    coordScreen = GetLargestConsoleWindowSize(hOutputConsole);

    /* define the new console window size and scroll position */
    srWindowRect.Right = (SHORT) (min(xSize, coordScreen.X) - 1);
    srWindowRect.Bottom = (SHORT) (min(ySize, coordScreen.Y) - 1);
    srWindowRect.Left = srWindowRect.Top = (SHORT) 0;
    
    /* define the new console buffer size */
    coordScreen.X = xSize;
    coordScreen.Y = ySize;
    
    /* if the current buffer is larger than what we want, resize the */
    /* console window first, then the buffer */
    if ((DWORD) csbi.dwSize.X * csbi.dwSize.Y > (DWORD) xSize * ySize)
    {
        bSuccess = SetConsoleWindowInfo(hOutputConsole, TRUE, &srWindowRect);
        if (bSuccess)
        {
            bSuccess = SetConsoleScreenBufferSize(hOutputConsole, coordScreen);
        }
    }

    /* if the current buffer is smaller than what we want, resize the */
    /* buffer first, then the console window */
    if ((DWORD) csbi.dwSize.X * csbi.dwSize.Y < (DWORD) xSize * ySize)
    {
        bSuccess = SetConsoleScreenBufferSize(hOutputConsole, coordScreen);
        if (bSuccess)
            bSuccess = SetConsoleWindowInfo(hOutputConsole, TRUE, &srWindowRect);
    }

    if (bSuccess)
        ConSaveViewRect();

    /* if the current buffer *is* the size we want, don't do anything! */
    return bSuccess;
}

/* ************************************************************ */
/* Function: ConSetAttributes									*/
/* Used to set the Color of the console and other attributes	*/
/* ************************************************************ */
void ConSetAttribute(int *iParam, int iParamCount)
{
    static int	iAttr = 0;
    int		i = 0;
    BOOL    bRet = TRUE;

    if (iParamCount < 1)
    {
        iAttr |= FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

        iAttr = iAttr & ~BACKGROUND_INTENSITY;
        iAttr = iAttr & ~FOREGROUND_INTENSITY;
        iAttr = iAttr & ~COMMON_LVB_UNDERSCORE;
        iAttr = iAttr & ~COMMON_LVB_REVERSE_VIDEO;

        SetConsoleTextAttribute(hOutputConsole, (WORD)iAttr);
    }
    else
    {
        for (i=0;i<iParamCount;i++)
        {
            switch (iParam[i])
            {
                case ANSI_ATTR_RESET:
                    iAttr |= FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

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
                    // White
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
                    iAttr |=  FOREGROUND_BLUE | FOREGROUND_GREEN;
                    break;
                case ANSI_FOREGROUND_WHITE:
                    iAttr |= FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN;
                    break;
                case ANSI_DEFAULT_BACKGROUND:
                    //Black
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
                    iAttr |=  BACKGROUND_BLUE | BACKGROUND_GREEN;
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
} // End procedure

/* ************************************************************ */
/* Function: ConScreenSizeX										*/
/* Returns the width of current screen		                    */
/* ************************************************************ */
int	ConScreenSizeX()
{
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return (-1);

    return (ConsoleInfo.dwSize.X);
}

/* ************************************************************ */
/* Function: ConSetScreenX										*/
/* Sets the width of the screen		                            */
/* ************************************************************ */
int	ConSetScreenX()
{
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return (-1);
    
    ScreenX = (ConsoleInfo.dwSize.X);
    return 0;
}

/* ************************************************************ */
/* Function: ConScreenSizeY										*/
/* 		returns actual size of screen buffer					*/
/* ************************************************************ */
int ConScreenSizeY()
{
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return (-1);

    return (ConsoleInfo.srWindow.Bottom - ConsoleInfo.srWindow.Top + 1);
}

/* ************************************************************ */
/* Function: ConWindowSizeX  			                        */
/* 		returns visible size of screen window					*/
/* ************************************************************ */
int ConWindowSizeX()
{
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return (-1);
    
    return (ConsoleInfo.srWindow.Right - ConsoleInfo.srWindow.Left + 1);
}

/* ************************************************************ */
/* Function: ConVisibleScreenSizeY								*/
/* 		returns visible size of screen window					*/
/* ************************************************************ */
int ConWindowSizeY()
{
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return (-1);
    
    return (ConsoleInfo.srWindow.Bottom - ConsoleInfo.srWindow.Top + 1 );
}

int ConSetScreenY()
{
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return (-1);

    ScreenY = ConsoleInfo.dwSize.Y - 1;

    return 0;
}

void ConFillToEndOfLine()
{
    DWORD rc = 0;

    int size = ConScreenSizeX();

    for(int i = ConGetCursorX(); i<size; i++)
        WriteConsole(hOutputConsole, (char *)" ", 1, &rc, 0);
}

int ConWriteString(char* pszString, int cbString)
{
    DWORD Result = 0;

    if (hOutputConsole)
        WriteConsole(hOutputConsole, pszString, cbString, &Result, 0);
    else
        Result = (DWORD) printf(pszString);
                
    return cbString;
}

int ConTranslateAndWriteString(char* pszString, int cbString)
{
    DWORD Result = 0;

    if (hOutputConsole)
        WriteConsole(hOutputConsole, pszString, cbString, &Result, 0);
    else
        Result = (DWORD) printf(pszString);

    //ConSaveViewRect(); // save current window
                
    return Result;
}

BOOL ConWriteChar(CHAR ch)
{
    int		X, Y, Result;
    BOOL	fOkay = TRUE;

    Y = ConGetCursorY();
    X = ConGetCursorX();

    switch ( ch )
    {
    case 0x8:	// BackSpace
        if ( X == 0 )
        {
            ConSetCursorPosition( ScreenX - 1, --Y );
            WriteConsole( hOutputConsole, " ", 1, (LPDWORD)&Result, 0 );
            ConSetCursorPosition( ScreenX - 1, Y );
        }
        else
        {
            ConSetCursorPosition( X - 1, Y );
            WriteConsole( hOutputConsole, " ", 1, (LPDWORD)&Result, 0 );
            ConSetCursorPosition( X - 1, Y );
        }

        break;
    case '\r':
        ConSetCursorPosition( 0, Y );

        break;
    case '\n':
        Y++;
        if ( Y > ScrollBottom-1)
        {
            ConScrollDown( ScrollTop, ScrollBottom );
            ConSetCursorPosition( 0, ScrollBottom );
        }
        else
            ConSetCursorPosition( 0, Y );
       break;

    default:

        fOkay = (BOOL)WriteConsole( hOutputConsole, &ch, 1, (LPDWORD)&Result, 0 );

        if ( X >= ScreenX-1 )	// last coord
        {
            if (Y >= ScrollBottom-1)	// last coord
            {
                ConScrollDown(ScrollTop,ScrollBottom);
                ConMoveCursorPosition(-ConGetCursorX(),0);
            }
            else
            {
                ConMoveCursorPosition(-ConGetCursorX(),1);
            }
        }
        break;
    }

    return fOkay;
}


BOOL ConWriteCharW(WCHAR ch)
{
    int		X, Y, Result;
    BOOL	fOkay = TRUE;

    Y = ConGetCursorY();
    X = ConGetCursorX();

    switch ( ch )
    {
    case 0x8:	// BackSpace
        if ( X == 0 )
        {
            ConSetCursorPosition( ScreenX - 1, --Y );
            WriteConsole( hOutputConsole, " ", 1, (LPDWORD)&Result, 0 );
            ConSetCursorPosition( ScreenX - 1, Y );
        }
        else
        {
            ConSetCursorPosition( X - 1, Y );
            WriteConsole( hOutputConsole, " ", 1, (LPDWORD)&Result, 0 );
            ConSetCursorPosition( X - 1, Y );
        }

        break;
    case L'\r':
        ConSetCursorPosition( 0, Y );
        break;

    case L'\n':
        Y++;
        if ( Y > ScrollBottom-1)
        {
            ConScrollDown( ScrollTop, ScrollBottom );
            ConSetCursorPosition( 0, ScrollBottom );
        }
        else
            ConSetCursorPosition( 0, Y );
        break;

    default:
        fOkay = (BOOL)WriteConsoleW( hOutputConsole, &ch, 1, (LPDWORD)&Result, 0 );

        if ( X >= ScreenX-1 )	// last coord
        {
            if (Y >= ScrollBottom-1)	// last coord
            {
                ConScrollDown(ScrollTop,ScrollBottom);
                ConMoveCursorPosition(-ConGetCursorX(),0);
            }
            else
            {
                ConMoveCursorPosition(-ConGetCursorX(),1);
            }
        }
        break;
    }

    return fOkay;
}


/* Special Function for handling TABS and other bad control chars */
int ConWriteConsole( char *pData, int NumChars )
{
    int	X, CurrentY, CurrentX, Result;

    for( X = 0; (X < NumChars) && (pData[X] != '\0') ; X++ )
    {
        switch (pData[X]) 
        {

        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 11:
        break;

        case 7:
            Beep( 1000, 400);
            break;

        case 8:
            ConMoveCursorPosition( -1, 0 );
            WriteConsole(hOutputConsole, " ", 1, (LPDWORD)&Result, 0);
            ConMoveCursorPosition( -1, 0 );
        break;

        case 9:
            {
                int	i, MoveRight = TAB_LENGTH - (ConGetCursorX() % TAB_LENGTH);

                for ( i = 0; i < MoveRight; i++ )
                    WriteConsole(hOutputConsole, " ", 1, (LPDWORD)&Result, 0);
            }
        break;

        case 10:
            CurrentY = ConGetCursorY()+1;
            if (CurrentY >= ScrollBottom)
            {
                ConScrollDown(ScrollTop,ScrollBottom);
                ConMoveCursorPosition(-ConGetCursorX(),0);
            }
            else
            {
                ConMoveCursorPosition(0,1);
            }
        break;
        
        case 12:
            ConClearScreen();
            ConSetCursorPosition(0, 0);
        break;

        case 13:
            ConMoveCursorPosition(-ConGetCursorX(),0);
        break;

        case 14:
        break;

        case 15:
        break;

        default: 
            {

                CurrentY = ConGetCursorY();
                CurrentX = ConGetCursorX();

                WriteConsole(hOutputConsole,  &pData[X], 1, (LPDWORD)&Result, 0);
                
                if ( CurrentX >= ScreenX-1)	// last coord
                {
                    if (CurrentY >= ScrollBottom-1)	// last coord
                    {
                        ConScrollDown(ScrollTop,ScrollBottom);
                        ConMoveCursorPosition(-ConGetCursorX(),0);
                    }
                    else
                    {
                        ConMoveCursorPosition(-ConGetCursorX(),1);
                    }
                }
            }
        }
    }

    return X;
}

PCHAR ConWriteLine(char* pData)
{
    PCHAR	pCurrent, pNext, pTab;
    DWORD	Result;
    size_t	distance, tabCount, pos;
    size_t		tabLength, charCount;

    pCurrent = pData;

    pNext = strchr( pCurrent, '\r' );
    if ( pNext != NULL )
    {
        distance = pNext - pCurrent;

        if ( distance > (size_t)ScreenX )
            distance = (size_t)ScreenX;

        pos = 0;
        tabCount = 0;
        pTab = strchr( pCurrent, TAB_CHAR );
        if ( (pTab != NULL) && (pTab < pNext) )
        {									
            // Tab exists in string
            // So we use our WriteString
            while ( (pTab != NULL) && (pTab < pNext) && (pos < (size_t)ScreenX) )
            {
                tabCount++;
                charCount = (pTab - pCurrent) - 1;	// Ignore actual TAB since we add 8 for it
                pos = charCount + (tabCount * TAB_LENGTH);
                pTab++;		// increment past last tab
                pTab = strchr( pTab, TAB_CHAR );
            }

            tabLength = (tabCount * TAB_LENGTH);

//			if ( pos >= ScreenX ) 
            distance = ConWriteConsole( pCurrent, (int)distance );// Special routine for handling TABS

        }
        else
            WriteConsole( hOutputConsole,pCurrent, (DWORD)distance, &Result, 0 );

        ConSetCursorPosition( 0, ConGetCursorY() + 1 );

        pCurrent+= (distance + 2);  // Add one to always skip last char printed
    }
    else
    {
        distance = strlen( pCurrent );
        if ( distance > (size_t)ScreenX )
            distance = (size_t)ScreenX;
        WriteConsole( hOutputConsole, pCurrent, (DWORD)distance, &Result, 0 );
        pCurrent += distance;
    }

    return pCurrent;
}

PCHAR ConDisplayData(char* pData, int NumLines)
{
    PCHAR	pCurrent, pNext, pTab;
    DWORD	Result;
    size_t		Y, distance, pos, add;
    int		linecnt = 0;

    pCurrent = pData;

    for ( ;(pCurrent) && 
        ((Y = (size_t)ConGetCursorY()) <= (size_t)ScrollBottom) && 
        (*pCurrent != '\0'); )
    {
        pNext = strchr( pCurrent, '\n' );
        if ( pNext != NULL )
        {
            --pNext;
            if ( *pNext != '\r' )
            {
                pNext++;
                add = 1;
            }
            else
                add = 2;
            distance = pNext - pCurrent;

            if ( distance > 0  && linecnt < NumLines)
            {
                pos = 0;
                pTab = strchr( pCurrent, TAB_CHAR );
                if ( (distance > (size_t)ScreenX) || ((pTab != NULL) && (pTab < pNext)) )
                {									
                    ConWriteConsole( pCurrent, (int)distance ); // Special routine for handling TABS
                }
                else
                {
                    WriteConsole( hOutputConsole, pCurrent, (DWORD)distance, &Result, 0 );
                }
            }
            ConMoveCursorPosition(-ConGetCursorX(),1);
            pCurrent += (distance + add);  // Add one to always skip last char printed
            linecnt++;
        }
        else
        {
            distance = strlen( pCurrent );
            if ( distance > (size_t)ScreenX )
                distance = ScreenX;
            if (linecnt < NumLines)
                WriteConsole( hOutputConsole, pCurrent, (DWORD)distance, &Result, 0 );
            return pCurrent + distance;
        }
    }
    return pCurrent;
}

int Con_printf( const char *Format, ... )
{
    va_list va_data;
    int		len;
    char	Temp[4096];

    memset( Temp, '\0', sizeof( Temp ) );

    va_start( va_data, Format );

    len = vsnprintf( Temp, sizeof(Temp), Format, va_data );

    ConWriteConsole(Temp, len);

    va_end( va_data );

    return len;
}

BOOL ConDisplayCursor( BOOL bVisible )
{
    CONSOLE_CURSOR_INFO ConsoleCursorInfo;

    if (GetConsoleCursorInfo(hOutputConsole, &ConsoleCursorInfo)) {

        ConsoleCursorInfo.bVisible = bVisible;

        return SetConsoleCursorInfo(hOutputConsole, &ConsoleCursorInfo);
    }

    return FALSE;
}

void ConClearScreen(void)
{
    DWORD dwWritten;
    COORD Coord ;
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
    SMALL_RECT	srcWindow;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;

    Coord.X = 0;
    Coord.Y = 0;

    DWORD dwNumChar = (ConsoleInfo.srWindow.Bottom + 1) *
                      (ConsoleInfo.srWindow.Right + 1);

    FillConsoleOutputCharacter(hOutputConsole, ' ', 
        dwNumChar,
        Coord, &dwWritten);
    FillConsoleOutputAttribute(hOutputConsole, ConsoleInfo.wAttributes,
        dwNumChar,
        Coord, &dwWritten);

    srcWindow = ConsoleInfo.srWindow;

    ConSetCursorPosition(0, 0);
}

void ConClearScrollRegion()
{
    DWORD dwWritten;
    COORD Coord ;
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;

    Coord.X = 0;
    Coord.Y = ScrollTop+ConsoleInfo.srWindow.Top;
    FillConsoleOutputCharacter(hOutputConsole, ' ', (DWORD)ConsoleInfo.dwSize.X * (DWORD)ScrollBottom,
        Coord, &dwWritten);

    FillConsoleOutputAttribute(hOutputConsole, ConsoleInfo.wAttributes,
        (DWORD)ConsoleInfo.dwSize.X * (DWORD)ScrollBottom,
        Coord, &dwWritten);

    ConSetCursorPosition( 0, ScrollTop );
}

void ConClearEOScreen()
{
    DWORD dwWritten;
    COORD Coord ;
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;

    Coord.X = 0;
    Coord.Y = (short)(ConGetCursorY() + 1) + ConsoleInfo.srWindow.Top;
    FillConsoleOutputCharacter(hOutputConsole, ' ',
        (DWORD)(ConsoleInfo.dwSize.X)*
        (DWORD)(ConsoleInfo.srWindow.Bottom - Coord.Y + 1),
        Coord, &dwWritten);
    FillConsoleOutputAttribute(hOutputConsole, ConsoleInfo.wAttributes,
        (DWORD)(ConsoleInfo.dwSize.X)*
        (DWORD)(ConsoleInfo.srWindow.Bottom - Coord.Y + 1),
        Coord, &dwWritten);

    ConClearEOLine();
}

void ConClearBOScreen()
{
    DWORD dwWritten;
    COORD Coord;
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;

    Coord.X = 0;
    Coord.Y = 0;
    FillConsoleOutputCharacter(hOutputConsole, ' ',
        (DWORD)(ConsoleInfo.dwSize.X)*
        (DWORD)(ConsoleInfo.dwSize.Y - ConGetCursorY() - 1),
        Coord, &dwWritten);
    FillConsoleOutputAttribute(hOutputConsole, ConsoleInfo.wAttributes, 
        (DWORD)(ConsoleInfo.dwSize.X)*
        (DWORD)(ConsoleInfo.dwSize.Y - ConGetCursorY() - 1),
        Coord, &dwWritten);

    ConClearBOLine();
}

void ConClearLine()
{
    DWORD dwWritten;
    COORD Coord;
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;

    Coord.X = 0;
    Coord.Y =  ConGetCursorY();

    FillConsoleOutputAttribute(hOutputConsole, ConsoleInfo.wAttributes, ScreenX,
        Coord, &dwWritten);
    FillConsoleOutputCharacter(hOutputConsole, ' ',ScreenX,
        Coord, &dwWritten);
}

void ConClearEOLine()
{
    DWORD dwWritten;
    COORD Coord;
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;;

    Coord.X = ConGetCursorX()+ConsoleInfo.srWindow.Left;
    Coord.Y = ConGetCursorY()+ConsoleInfo.srWindow.Top;

    FillConsoleOutputCharacter(hOutputConsole, ' ',
        (DWORD)(ScreenX - ConGetCursorX()),
        Coord, &dwWritten);
    FillConsoleOutputAttribute(hOutputConsole, ConsoleInfo.wAttributes,
        (DWORD)(ScreenX - ConGetCursorX()),
        Coord, &dwWritten);
}

void ConClearNFromCursorRight(int n)
{
    DWORD dwWritten;
    COORD Coord;
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;


    Coord.X = ConGetCursorX()+ConsoleInfo.srWindow.Left;
    Coord.Y = ConGetCursorY()+ConsoleInfo.srWindow.Top;
    FillConsoleOutputCharacter(hOutputConsole, ' ',
        (DWORD)n,
        Coord, &dwWritten);
    FillConsoleOutputAttribute(hOutputConsole, ConsoleInfo.wAttributes,
        (DWORD)n,
        Coord, &dwWritten);
}

void ConClearNFromCursorLeft(int n)
{
    DWORD dwWritten;
    COORD Coord;
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;

    Coord.X = ConGetCursorX()+ConsoleInfo.srWindow.Left-n;
    Coord.Y = ConGetCursorY()+ConsoleInfo.srWindow.Top;
    FillConsoleOutputCharacter(hOutputConsole, ' ',
        (DWORD)n,
        Coord, &dwWritten);
    FillConsoleOutputAttribute(hOutputConsole, ConsoleInfo.wAttributes,
        (DWORD)n,
        Coord, &dwWritten);
}

void ConScrollDownEntireBuffer()
{
    CONSOLE_SCREEN_BUFFER_INFO	ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;
    ConScrollDown(0, ConsoleInfo.dwSize.Y - 1);
    return;
}

void ConScrollUpEntireBuffer()
{
    CONSOLE_SCREEN_BUFFER_INFO	ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;
    ConScrollUp(0, ConsoleInfo.dwSize.Y - 1);
    return;
}

void ConScrollUp(int topline,int botline)
{
    SMALL_RECT	ScrollRect;
    SMALL_RECT	ClipRect;
    COORD		destination;
    CHAR_INFO	Fill;
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;

    if ((botline - topline) == ConsoleInfo.dwSize.Y-1)  // scrolling whole buffer
    {
        ScrollRect.Top = topline;
        ScrollRect.Bottom = botline;
    }
    else
    {
        ScrollRect.Top = topline + ConsoleInfo.srWindow.Top;
        ScrollRect.Bottom = botline + ConsoleInfo.srWindow.Top;
    }
    ScrollRect.Left = 0;
    ScrollRect.Right = ConScreenSizeX() -1;

    ClipRect.Top = ScrollRect.Top;
    ClipRect.Bottom = ScrollRect.Bottom;
    ClipRect.Left = ScrollRect.Left;
    ClipRect.Right = ScrollRect.Right;

    destination.X = 0;
    destination.Y = ScrollRect.Top+1;

    Fill.Attributes = ConsoleInfo.wAttributes;
    Fill.Char.AsciiChar = ' ';

    BOOL bRet = ScrollConsoleScreenBuffer(	hOutputConsole,
                                &ScrollRect,
                                &ClipRect,
                                destination,
                                &Fill
                                );
}

void ConScrollDown(int topline, int botline)
{
    SMALL_RECT	ScrollRect;
    SMALL_RECT	ClipRect;
    COORD		destination;
    CHAR_INFO	Fill;
    CONSOLE_SCREEN_BUFFER_INFO	ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;

    if ((botline - topline) == ConsoleInfo.dwSize.Y - 1)  // scrolling whole buffer
    {
        ScrollRect.Top = topline;
        ScrollRect.Bottom = botline;
    }
    else
    {
        ScrollRect.Top = topline + ConsoleInfo.srWindow.Top + 1;
        ScrollRect.Bottom = botline + ConsoleInfo.srWindow.Top;
    }

    ScrollRect.Left = 0;
    ScrollRect.Right = ConScreenSizeX() - 1;

    ClipRect.Top = ScrollRect.Top;
    ClipRect.Bottom = ScrollRect.Bottom;
    ClipRect.Left = ScrollRect.Left;
    ClipRect.Right = ScrollRect.Right;

    destination.X = 0;
    destination.Y = ScrollRect.Top - 1;

    Fill.Attributes = ConsoleInfo.wAttributes;
    Fill.Char.AsciiChar = ' ';

    BOOL bRet = ScrollConsoleScreenBuffer(	hOutputConsole,
                                &ScrollRect,
                                NULL,
                                destination,
                                &Fill
                                );
}

void ConClearBOLine()
{
    DWORD dwWritten;
    COORD Coord ;
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;

    Coord.X = 0;
    Coord.Y = (short)(ConGetCursorY());
    FillConsoleOutputAttribute(hOutputConsole,  ConsoleInfo.wAttributes, 
        (DWORD)(ConGetCursorX()),
        Coord, &dwWritten);
    FillConsoleOutputCharacter(hOutputConsole, ' ',
        (DWORD)(ConGetCursorX()),
        Coord, &dwWritten);
}

void ConSetCursorPosition(int x, int y)
{
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
    COORD Coord;
    int	rc;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;

    Coord.X = (short)(x); 
    Coord.Y = (short)(y); 

    if ((y > ConsoleInfo.dwSize.Y - 1) && y > LastCursorY) {
        for(int n = LastCursorY; n < y; n++)
            GoToNextLine();
    }

    if (y >= ConsoleInfo.dwSize.Y) {
        Coord.Y = ConsoleInfo.dwSize.Y - 1;
    }

    if (!SetConsoleCursorPosition(hOutputConsole, Coord))
        rc = GetLastError();

    LastCursorX = x;
    LastCursorY = y;
}

BOOL ConChangeCursor( CONSOLE_CURSOR_INFO *pCursorInfo )
{
    return SetConsoleCursorInfo( hOutputConsole, pCursorInfo );
}

int ConGetCursorX()
{
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return 0;

    return ConsoleInfo.dwCursorPosition.X;
}

int ConGetCursorY()
{
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
    {
        return 0;
    }

    return (ConsoleInfo.dwCursorPosition.Y - ConsoleInfo.srWindow.Top);
}

int ConGetCursorInBufferY()
{
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
    {
        return 0;
    }

    return (ConsoleInfo.dwCursorPosition.Y);
}

void ConMoveCursorPosition(int x, int y)
{
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
    COORD Coord;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;

    Coord.X = (short)(ConsoleInfo.dwCursorPosition.X + x);
    Coord.Y = (short)(ConsoleInfo.dwCursorPosition.Y + y);

    SetConsoleCursorPosition(hOutputConsole, Coord);
}

void ConGetRelativeCursorPosition(int *x, int *y)
{
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;

    *x -= ConsoleInfo.srWindow.Left;
    *y -= ConsoleInfo.srWindow.Top;
}

void ConDeleteChars(int n)
{
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
    COORD Coord;
    CHAR_INFO chiBuffer[256];   // 1 row, 256 characters
    SMALL_RECT	sr;
    COORD	Temp;
    int result;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return;

    Coord.X = (short)(ConsoleInfo.dwCursorPosition.X);
    Coord.Y = (short)(ConsoleInfo.dwCursorPosition.Y);

    sr.Left = Coord.X + n;
    sr.Top = Coord.Y;
    sr.Bottom = Coord.Y;
    sr.Right = ConsoleInfo.srWindow.Right;

    Temp.X = 256;
    Temp.Y = 1;
    result = ReadConsoleOutput( hOutputConsole,				// handle of a console screen buffer 
                                (PCHAR_INFO)chiBuffer,	// address of buffer that receives data 
                                Temp,	                // column-row size of destination buffer 
                                ZeroCoord,				// upper-left cell to write to 
                                &sr	                    // address of rectangle to read from 
                                );
    ConClearEOLine();

    sr.Left = Coord.X;
    Temp.X = 256;
    Temp.Y = 1;

    sr.Right -= n;
    result = WriteConsoleOutput(hOutputConsole,(PCHAR_INFO)chiBuffer,Temp, ZeroCoord, &sr);
}


SCREEN_HANDLE ConSaveScreenHandle( SCREEN_HANDLE hScreen )
{
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

    PSCREEN_RECORD  pScreenRec = (PSCREEN_RECORD)hScreen;

    int result, width,height;

    if ( hOutputConsole == NULL )
        return NULL;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return (NULL);

    if (pScreenRec == NULL){
        pScreenRec = (PSCREEN_RECORD)malloc(sizeof(SCREEN_RECORD));
        pScreenRec->pScreenBuf = NULL;
    }
 
    pScreenRec->srWindowRect = ConsoleInfo.srWindow;
    width = ConsoleInfo.srWindow.Right - ConsoleInfo.srWindow.Left + 1;
    height = ConsoleInfo.srWindow.Bottom - ConsoleInfo.srWindow.Top + 1;
    pScreenRec->ScreenSize.X = width;
    pScreenRec->ScreenSize.Y = height;
    pScreenRec->ScreenCursor.X = ConsoleInfo.dwCursorPosition.X-ConsoleInfo.srWindow.Left;
    pScreenRec->ScreenCursor.Y = ConsoleInfo.dwCursorPosition.Y-ConsoleInfo.srWindow.Top;

    if (pScreenRec->pScreenBuf == NULL){
        pScreenRec->pScreenBuf = (PCHAR_INFO)malloc( sizeof(CHAR_INFO) * width * height  );
    }

    if ( !pScreenRec->pScreenBuf )
    {
        if ( pScreenRec != (PSCREEN_RECORD)hScreen ) {
            free(pScreenRec);
        }
        return NULL;
    }

    result =  ReadConsoleOutput( hOutputConsole,				            // handle of a console screen buffer 
                             (PCHAR_INFO)(pScreenRec->pScreenBuf),	// address of buffer that receives data 
                             pScreenRec->ScreenSize,	            // column-row size of destination buffer 
                             ZeroCoord,				                // upper-left cell to write to 
                             &ConsoleInfo.srWindow	                // address of rectangle to read from 
                             );

    return((SCREEN_HANDLE)pScreenRec);
}


BOOL ConRestoreScreenHandle( SCREEN_HANDLE hScreen )
{
    BOOL fOkay = FALSE;
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
    COORD		beginOfScreen = { 0, 0 };
    PCHAR_INFO	pSavedCharInfo;
    DWORD		dwWritten;
    PSCREEN_RECORD pScreenRec = (PSCREEN_RECORD)hScreen;
    int  width, height;

    if ( hOutputConsole == NULL )
        return FALSE;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return (FALSE);

    width = ConsoleInfo.srWindow.Right - ConsoleInfo.srWindow.Left + 1;
    height = ConsoleInfo.srWindow.Bottom - ConsoleInfo.srWindow.Top + 1;
    
    beginOfScreen.X = ConsoleInfo.srWindow.Left;
    beginOfScreen.Y = ConsoleInfo.srWindow.Top;
    FillConsoleOutputCharacter(hOutputConsole, ' ', (DWORD)width*height,
        beginOfScreen, &dwWritten);

    pSavedCharInfo = (PCHAR_INFO)(pScreenRec->pScreenBuf);
    SetConsoleTextAttribute(hOutputConsole, pSavedCharInfo->Attributes);

    FillConsoleOutputAttribute(hOutputConsole, pSavedCharInfo->Attributes,
        (DWORD)width*height,
        beginOfScreen, &dwWritten);

    fOkay = WriteConsoleOutput( hOutputConsole,	                            // handle to a console screen buffer 
                                (PCHAR_INFO)(pScreenRec->pScreenBuf),	// pointer to buffer with data to write  
                                pScreenRec->ScreenSize,	                // column-row size of source buffer 
                                ZeroCoord,	                            // upper-left cell to write from 
                                &ConsoleInfo.srWindow	                // pointer to rectangle to write to 
                                );

    SetConsoleWindowInfo(hOutputConsole,TRUE,&pScreenRec->srWindowRect);
    
    ConSetCursorPosition( pScreenRec->ScreenCursor.X, pScreenRec->ScreenCursor.Y );

    return fOkay;
}

BOOL ConRestoreScreenColors( )
{
    SCREEN_HANDLE hScreen = pSavedScreenRec;
    BOOL fOkay = FALSE;
    CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
    COORD		beginOfScreen = { 0, 0 };
    PCHAR_INFO	pSavedCharInfo;
    DWORD		dwWritten;
    PSCREEN_RECORD pScreenRec = (PSCREEN_RECORD)hScreen;

    if ( hOutputConsole == NULL )
        return FALSE;

    if ( pSavedScreen == NULL )
        return FALSE;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &ConsoleInfo))
        return (FALSE);

    beginOfScreen.X = ConsoleInfo.srWindow.Left;
    beginOfScreen.Y = ConsoleInfo.srWindow.Top;

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

void ConDeleteScreenHandle( SCREEN_HANDLE hScreen )
{
    PSCREEN_RECORD pScreenRec = (PSCREEN_RECORD)hScreen;

    free(pScreenRec->pScreenBuf);
    free(pScreenRec);

}

/* ************************************************************ */
/* Function: ConRestoreScreen								    */
/* Restores Previous Saved screen info and buffer		        */
/* ************************************************************ */
BOOL ConRestoreScreen( void )
{
    return ConRestoreScreenHandle(pSavedScreenRec);
}

void ConRestoreViewRect( void )
{
    //SetConsoleWindowInfo(hOutputConsole,TRUE,&SavedViewRect);
}

/* ************************************************************ */
/* Function: ConSaveScreen								        */
/* Saves current screen info and buffer		                    */
/* ************************************************************ */
BOOL ConSaveScreen( void )
{
    pSavedScreenRec = (PSCREEN_RECORD)ConSaveScreenHandle(pSavedScreenRec);
    return TRUE;
}

void ConSaveViewRect( void )
{
    CONSOLE_SCREEN_BUFFER_INFO	csbi;

    if (!GetConsoleScreenBufferInfo(hOutputConsole, &csbi))
        return;

    SavedViewRect = csbi.srWindow;

}

BOOL ConIsRedirected(HANDLE hInput)
{
    DWORD dwMode;

    return !GetConsoleMode(hInput, &dwMode);
}

HANDLE GetConsoleOutputHandle()
{
    SECURITY_ATTRIBUTES sa;

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    HANDLE hTemp = GetStdHandle(STD_OUTPUT_HANDLE);

    if (ConIsRedirected(hTemp))
    {
        hTemp = CreateFile(TEXT("CONOUT$"), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            &sa, OPEN_EXISTING, 0, NULL);
    }

    return hTemp;
}

HANDLE GetConsoleInputHandle()
{
    SECURITY_ATTRIBUTES sa;

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    HANDLE hTemp = GetStdHandle(STD_INPUT_HANDLE);

    if (ConIsRedirected(hTemp))
    {
        hTemp = CreateFile(TEXT("CONIN$"), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            &sa, OPEN_EXISTING, 0, NULL);
    }

    return hTemp;
}

void ConSaveWindowsState(void)
{
    CONSOLE_SCREEN_BUFFER_INFOEX csbiex;
    csbiex.cbSize = sizeof(CONSOLE_SCREEN_BUFFER_INFOEX);

    if (!GetConsoleScreenBufferInfoEx(hOutputConsole, &csbiex))
        return;

    SavedWindowState = csbiex;
}
