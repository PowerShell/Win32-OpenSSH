/* console.c
 * Author: Pragma Systems, Inc. <www.pragmasys.com>
 * Contribution by Pragma Systems, Inc. for Microsoft openssh win32 port
 * Copyright (c) 2011, 2015 Pragma Systems, Inc.
 * All rights reserved
 * 
 * Common library for Windows Console Screen IO.
 * Contains Windows console related definition so that emulation code can draw
 * on Windows console screen surface.
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
#include <string.h>

#include <windows.h>

#include <console.h>
#include <conio.h>

HANDLE	hConsole = NULL;
DWORD	dwSavedAttributes = 0;

WORD	wStartingAttributes = 0;

int ScreenX;
int ScreenY;
int ScrollTop;
int ScrollBottom;

char	*pSavedScreen = NULL;
static COORD	ZeroCoord = {0,0};
COORD	SavedScreenSize = {0,0};
COORD	SavedScreenCursor = {0, 0 };
SMALL_RECT	SavedViewRect = {0,0,0,0};

typedef struct _SCREEN_RECORD{
    PCHAR_INFO pScreenBuf;
    COORD   ScreenSize;
    COORD   ScreenCursor;
	SMALL_RECT  srWindowRect;
}SCREEN_RECORD,*PSCREEN_RECORD;

PSCREEN_RECORD   pSavedScreenRec = NULL;


/* ************************************************************ */
/* Function: ConInit         									*/
/* Used to Initialize the Console for output                	*/
/* ************************************************************ */
int ConInit( DWORD OutputHandle, bool fSmartInit ) 
{

	OSVERSIONINFO os;
	DWORD	dwAttributes = 0;
	CONSOLE_SCREEN_BUFFER_INFO	csbi;
	static bool bFirstConInit = true;

	os.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );
	GetVersionEx( &os );

	hConsole = GetStdHandle( OutputHandle );
	if (hConsole == INVALID_HANDLE_VALUE)
		printf("GetStdHandle failed with %d\n",GetLastError());

	if (!GetConsoleMode( hConsole, &dwSavedAttributes ))
		printf("GetConsoleMode failed with %d\n",GetLastError());

	dwAttributes = dwSavedAttributes;

	if ( os.dwPlatformId == VER_PLATFORM_WIN32_NT )
	{
//		dwAttributes = (DWORD)ENABLE_WRAP_AT_EOL_OUTPUT;	// Causes screen scroll in Edit
//		dwAttributes = (DWORD)(ENABLE_PROCESSED_OUTPUT & ~(ENABLE_WRAP_AT_EOL_OUTPUT));
//		dwAttributes = 0;	// Causes wrong FONTS and doesn't handle CRLF
		dwAttributes = (DWORD)ENABLE_PROCESSED_OUTPUT;  // PERFECT in NT
//		dwAttributes = (DWORD)ENABLE_PROCESSED_OUTPUT | (DWORD)ENABLE_WRAP_AT_EOL_OUTPUT;  // PERFECT in NT
		SetConsoleMode(hConsole, dwAttributes ); // Windows NT
	}
	else
	{
		dwAttributes = (DWORD)ENABLE_WRAP_AT_EOL_OUTPUT;	// Doesn't always print last column & doesn't handle CRLF
//		dwAttributes = (DWORD)(ENABLE_PROCESSED_OUTPUT & ~(ENABLE_WRAP_AT_EOL_OUTPUT));
//		dwAttributes = 0;	// Causes wrong FONTS and doesn't handle CRLF
//		dwAttributes = (DWORD)ENABLE_PROCESSED_OUTPUT;  // Scrolls in Windows 95
		SetConsoleMode(hConsole, dwAttributes );	// Windows 95
	}




	if (bFirstConInit && fSmartInit)
	{
	
		if (GetConsoleScreenBufferInfo(hConsole, &csbi))
		{
			SMALL_RECT sr;

			wStartingAttributes = csbi.wAttributes;
			
			int   ydelta = csbi.srWindow.Bottom-csbi.srWindow.Top+1;
			if (csbi.dwCursorPosition.Y+ydelta > csbi.dwSize.Y)
			{
				// not enough buffer to reposition window.. must scroll
				SMALL_RECT	ScrollRect;
				SMALL_RECT	ClipRect;
				COORD		destination;
				CHAR_INFO	Fill;
				COORD newCursorPos;

				ScrollRect.Top = (csbi.dwCursorPosition.Y+ydelta - csbi.dwSize.Y);
				ScrollRect.Bottom = csbi.dwCursorPosition.Y+1;
				ScrollRect.Left = 0;
				ScrollRect.Right = csbi.dwSize.X;

				ClipRect = ScrollRect; 
				ClipRect.Top = 0;

				destination.X = 0;
				destination.Y = 0;

				Fill.Attributes = csbi.wAttributes;
				Fill.Char.AsciiChar = ' ';

			
				ScrollConsoleScreenBuffer(	hConsole,
											&ScrollRect,
											&ClipRect,
											destination,
											&Fill
											);



		
				newCursorPos.Y = csbi.dwSize.Y-ydelta;


				newCursorPos.X = csbi.dwCursorPosition.X;
				SetConsoleCursorPosition(hConsole,newCursorPos);

				sr = csbi.srWindow;
				sr.Top = newCursorPos.Y;
				sr.Bottom = csbi.dwSize.Y-1;


				BOOL rc = SetConsoleWindowInfo(hConsole,TRUE,&sr);
				
				
			}else{
				GetConsoleScreenBufferInfo(hConsole, &csbi);

				sr = csbi.srWindow;
				sr.Top = csbi.dwCursorPosition.Y;
				sr.Bottom = sr.Top+ydelta-1;


				BOOL rc = SetConsoleWindowInfo(hConsole,TRUE,&sr);
			}

		}
		bFirstConInit = false;
	}

	ConSetScreenX();
	ConSetScreenY();
	ScrollTop = 0;
	ScrollBottom = ConWindowSizeY();

	if (GetConsoleScreenBufferInfo(hConsole, &csbi))
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

	if ( hConsole == NULL )
		return 0;



	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return 0;

	SetConsoleMode(hConsole,dwSavedAttributes);


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

	if ( hConsole == NULL )
		return 0;



	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return 0;

	SetConsoleMode(hConsole,dwSavedAttributes);

	Coord = ConsoleInfo.dwCursorPosition;
	Coord.X = 0;

	DWORD dwNumChar = (ConsoleInfo.dwSize.Y - ConsoleInfo.dwCursorPosition.Y) *
						ConsoleInfo.dwSize.X;

	FillConsoleOutputCharacter(hConsole, ' ', 
		dwNumChar,
		Coord, &dwWritten);
	FillConsoleOutputAttribute(hConsole, wStartingAttributes,
		dwNumChar,
		Coord, &dwWritten);

	SetConsoleTextAttribute( hConsole, wStartingAttributes );

	return 0;
}

// BLR - rewrite of ConSetScreenSize that doesn't alter buffer size

BOOL ConSetScreenRect( int xSize, int ySize )
{
	CONSOLE_SCREEN_BUFFER_INFO csbi; /* hold current console buffer info */
	BOOL bSuccess = TRUE;
	SMALL_RECT srWindowRect; /* hold the new console size */
	COORD coordScreen;

	bSuccess = GetConsoleScreenBufferInfo(hConsole, &csbi);

	/* get the largest size we can size the console window to */
	coordScreen = GetLargestConsoleWindowSize(hConsole);

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
		bSuccess = SetConsoleScreenBufferSize(hConsole, coordScreen);
		if (bSuccess)
			bSuccess = SetConsoleWindowInfo(hConsole, TRUE, &srWindowRect);
	}
	else
	{
		bSuccess = SetConsoleWindowInfo(hConsole, TRUE, &srWindowRect);
		if (bSuccess)
			bSuccess = SetConsoleScreenBufferSize(hConsole, coordScreen);		
	}

	if (bSuccess)
		ConSaveViewRect();

	/* if the current buffer *is* the size we want, don't do anything! */
	return bSuccess;
}

BOOL ConSetScreenSize( int xSize, int ySize )
{
	CONSOLE_SCREEN_BUFFER_INFO csbi; /* hold current console buffer info */
	BOOL bSuccess = TRUE;
	SMALL_RECT srWindowRect; /* hold the new console size */
	COORD coordScreen;

	bSuccess = GetConsoleScreenBufferInfo(hConsole, &csbi);

	/* get the largest size we can size the console window to */
	coordScreen = GetLargestConsoleWindowSize(hConsole);

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
		bSuccess = SetConsoleWindowInfo(hConsole, TRUE, &srWindowRect);
		if (bSuccess)
		{
			bSuccess = SetConsoleScreenBufferSize(hConsole, coordScreen);
		}
	}

	/* if the current buffer is smaller than what we want, resize the */
	/* buffer first, then the console window */
	if ((DWORD) csbi.dwSize.X * csbi.dwSize.Y < (DWORD) xSize * ySize)
	{
		bSuccess = SetConsoleScreenBufferSize(hConsole, coordScreen);
		if (bSuccess)
			bSuccess = SetConsoleWindowInfo(hConsole, TRUE, &srWindowRect);
	}

	if (bSuccess)
		ConSaveViewRect();

	/* if the current buffer *is* the size we want, don't do anything! */
	return bSuccess;
}

/* ************************************************************ */
/* Function: ConRedrawScreen								*/
/* Redraws the saved screen                      		*/
/* ************************************************************ */
DWORD ConRedrawScreen( void )
{
	PCHAR_INFO	pInfo;
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	int	i;

	if ( pSavedScreen == NULL )
		return 1;

	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return 1;

	pInfo = (PCHAR_INFO)pSavedScreen;

	for ( i = 0; i < (ConsoleInfo.dwSize.X * ConsoleInfo.dwSize.Y); i++ )
	{
		pInfo++;
	}
	return 0;
}

bool fFirstTime = true;
/* ************************************************************ */
/* Function: ConSetAttributes									*/
/* Used to set the Color of the console and other attributes	*/
/*	6/21/99 BLH commented out INTENSITY FLAGS for cyan, magenta, and yellow */
/*		it appears that they weren't commented out when the check for intensity
		was added - since i'm not sure why we would explicitly state high 
		intensity for those colors
/* ************************************************************ */
void ConSetAttribute( int *iParam, int iParamCount )
{
	int		iAttr;
	int		i;

	iAttr = 0;
	if (iParamCount < 1)
		SetConsoleTextAttribute(hConsole,FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	else
	{
		for (i=0;i<iParamCount;i++)
		{
			switch (iParam[i])
			{
			    case ANSI_ATTR_RESET:
					SetConsoleTextAttribute(hConsole,FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

					break;
				case ANSI_BRIGHT:
					iAttr |= FOREGROUND_INTENSITY;
					break;
				case ANSI_DIM:
					// DIM
				case ANSI_UNDERSCORE:
					// UNDERSCORE
					break;
				case ANSI_BLINK: 
					// BLINK
					iAttr = FOREGROUND_BLUE | FOREGROUND_GREEN;
					break;
				case ANSI_REVERSE: 
					// REVERSE
					iAttr = BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE;
					break;
				case ANSI_HIDDEN:
					// HIDDEN
					iAttr = BACKGROUND_RED | FOREGROUND_RED;
					break;
				case ANSI_NOREVERSE:
					// NO REVERSE
					iAttr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
					break;
				case ANSI_FOREGROUND_BLACK:
					//Black
					iAttr |= 0;
					break;
				case ANSI_FOREGROUND_RED:
					// Red
					iAttr |= FOREGROUND_RED;
					break;
				case ANSI_FOREGROUND_GREEN: 
					// Green
					iAttr |= FOREGROUND_GREEN;
					break;
				case ANSI_FOREGROUND_YELLOW:
					// Yellow
				//	iAttr |= FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
					iAttr |= FOREGROUND_RED | FOREGROUND_GREEN;
					break;
				case ANSI_FOREGROUND_BLUE:
					// Blue
					iAttr |= FOREGROUND_BLUE;
					break;

				case ANSI_FOREGROUND_MAGENTA:
					// Magenta
				//	iAttr |= FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY;
					iAttr |= FOREGROUND_BLUE | FOREGROUND_RED;
					break;
				case ANSI_FOREGROUND_CYAN:
					//Cyan
				//	iAttr |=  FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
					iAttr |=  FOREGROUND_BLUE | FOREGROUND_GREEN;
					break;
				case ANSI_FOREGROUND_WHITE:
					//white
					iAttr |= FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN;
					break;
				case ANSI_BACKGROUND_BLACK:
					//Black
					iAttr |= 0;
					break;
				case ANSI_BACKGROUND_RED:
					// Red
					iAttr |= BACKGROUND_RED;
					break;
				case ANSI_BACKGROUND_GREEN: 
					// Green
					iAttr |= BACKGROUND_GREEN;
					break;
				case ANSI_BACKGROUND_YELLOW:
					// Yellow
				//	iAttr |= BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_INTENSITY;
					iAttr |= BACKGROUND_RED | BACKGROUND_GREEN;
					break;
				case ANSI_BACKGROUND_BLUE:
					// Blue
					iAttr |= BACKGROUND_BLUE;
					break;

				case ANSI_BACKGROUND_MAGENTA:
					// Magenta
				//iAttr |= BACKGROUND_BLUE | BACKGROUND_RED | BACKGROUND_INTENSITY;
					iAttr |= BACKGROUND_BLUE | BACKGROUND_RED;
					break;
				case ANSI_BACKGROUND_CYAN:
					//Cyan
				//	iAttr |=  BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_INTENSITY;
					iAttr |=  BACKGROUND_BLUE | BACKGROUND_GREEN;
					break;
				case ANSI_BACKGROUND_WHITE:
					//white
					iAttr |= BACKGROUND_BLUE | BACKGROUND_RED | BACKGROUND_GREEN;
					break;			
				case ANSI_BACKGROUND_BRIGHT:
					iAttr |= BACKGROUND_INTENSITY;
					break;
			}
		}
		if (iAttr)
			SetConsoleTextAttribute(hConsole,(WORD)iAttr);

	}
} // End procedure

/* ************************************************************ */
/* Function: ConSetScrollRegion						*/
/* Sets the Window Scroll Area		*/
/* ************************************************************ */
void ConSetScrollRegion( int Top, int Bottom )
{
	ScrollTop = Top;
	ScrollBottom = Bottom;
}

/* ************************************************************ */
/* Function: ConScreenSizeX										*/
/* Returns the width of current screen		*/
/* ************************************************************ */
int	ConScreenSizeX()
{
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
	{
		return (-1);
	}
	return (ConsoleInfo.dwSize.X);
}

/* ************************************************************ */
/* Function: ConSetScreenX										*/
/* Sets the width of the screen		*/
/* ************************************************************ */
int	ConSetScreenX()
{
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
	{
		return (-1);
	}
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
	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return (-1);
	return (ConsoleInfo.srWindow.Bottom - ConsoleInfo.srWindow.Top + 1);
//	return (ConsoleInfo.dwSize.Y);
}

/* ************************************************************ */
/* Function: ConWindowSizeX  												 */
/* 		returns visible size of screen window						 */
/* ************************************************************ */
int ConWindowSizeX()
{
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return (-1);
	
	return (ConsoleInfo.srWindow.Right - ConsoleInfo.srWindow.Left + 1 );
}

/* ************************************************************ */
/* Function: ConVisibleScreenSizeY								*/
/* 		returns visible size of screen window					*/
/* ************************************************************ */
int ConWindowSizeY()
{
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return (-1);
	
	return (ConsoleInfo.srWindow.Bottom - ConsoleInfo.srWindow.Top + 1 );
}

/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
int ConSetScreenY()
{
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return (-1);
	ScreenY = ConsoleInfo.dwSize.Y-1;
	return 0;
}

/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
void ConFillToEndOfLine()
{
	DWORD rc = 0;
	int i;
	int size = ConScreenSizeX();
	for( i=ConGetCursorX();i<size;i++)
		WriteConsole(hConsole, (char *)" ", 1, &rc, 0 );
}

/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
int ConWriteString(char* pszString, int cbString)
{
	DWORD Result = 0;

	if (hConsole)
		WriteConsole(hConsole, pszString, cbString, &Result, 0);
	else
		Result = (DWORD) printf(pszString);

	ConSaveViewRect(); // save current window
				
	return cbString;
}

int ConTranslateAndWriteString(char* pszString, int cbString)
{
	DWORD Result = 0;

	if (hConsole)
		WriteConsole(hConsole, pszString, cbString, &Result, 0);
	else
		Result = (DWORD) printf(pszString);

	ConSaveViewRect(); // save current window
				
	return Result;
}

BOOL ConWriteChar( CHAR ch )
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
			WriteConsole( hConsole, " ", 1, (LPDWORD)&Result, 0 );
			ConSetCursorPosition( ScreenX - 1, Y );
		}
		else
		{
			ConSetCursorPosition( X - 1, Y );
			WriteConsole( hConsole, " ", 1, (LPDWORD)&Result, 0 );
			ConSetCursorPosition( X - 1, Y );
		}

	break;

	case '\r':
			ConSetCursorPosition( 0, Y );
		break;

	case '\n':
			Y++;
			//ConWriteString( "\n", 1 );
			if ( Y > ScrollBottom-1)
			{
				ConScrollDown( ScrollTop, ScrollBottom );
				ConSetCursorPosition( 0, ScrollBottom );
			}
			else
			//	ConSetCursorPosition( 0, Y + 1 );
				ConSetCursorPosition( 0, Y );
		break;

	default:

		fOkay = (BOOL)WriteConsole( hConsole, &ch, 1, (LPDWORD)&Result, 0 );

		if ( X >= ScreenX-1 )	// last coord
		{
			if (Y >= ScrollBottom-1)	// last coord
			{
				ConScrollDown(ScrollTop,ScrollBottom);
				ConMoveCursorPosition(-ConGetCursorX(),0);
				//ConMoveCursorPosition(-ConGetCursorX(),-1);
			}
			else
			{
				ConMoveCursorPosition(-ConGetCursorX(),1);
			}
		/*
			ConSetCursorPosition( 0, ++Y );

			if ( Y > ScrollBottom-1)
			{
				ConScrollDown( ScrollTop, ScrollBottom );
				ConSetCursorPosition( 0, ScrollBottom-1 );
			}
			*/
		}
		break;
	}

	return fOkay;
}


BOOL ConWriteCharW( WCHAR ch )
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
			WriteConsole( hConsole, " ", 1, (LPDWORD)&Result, 0 );
			ConSetCursorPosition( ScreenX - 1, Y );
		}
		else
		{
			ConSetCursorPosition( X - 1, Y );
			WriteConsole( hConsole, " ", 1, (LPDWORD)&Result, 0 );
			ConSetCursorPosition( X - 1, Y );
		}

	break;

	case L'\r':
			ConSetCursorPosition( 0, Y );
		break;

	case L'\n':
			Y++;
			//ConWriteString( "\n", 1 );
			if ( Y > ScrollBottom-1)
			{
				ConScrollDown( ScrollTop, ScrollBottom );
				ConSetCursorPosition( 0, ScrollBottom );
			}
			else
			//	ConSetCursorPosition( 0, Y + 1 );
				ConSetCursorPosition( 0, Y );
		break;

	default:

		fOkay = (BOOL)WriteConsoleW( hConsole, &ch, 1, (LPDWORD)&Result, 0 );

		if ( X >= ScreenX-1 )	// last coord
		{
			if (Y >= ScrollBottom-1)	// last coord
			{
				ConScrollDown(ScrollTop,ScrollBottom);
				ConMoveCursorPosition(-ConGetCursorX(),0);
				//ConMoveCursorPosition(-ConGetCursorX(),-1);
			}
			else
			{
				ConMoveCursorPosition(-ConGetCursorX(),1);
			}
		/*
			ConSetCursorPosition( 0, ++Y );

			if ( Y > ScrollBottom-1)
			{
				ConScrollDown( ScrollTop, ScrollBottom );
				ConSetCursorPosition( 0, ScrollBottom-1 );
			}
			*/
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
			WriteConsole(hConsole, " ", 1, (LPDWORD)&Result, 0);
			ConMoveCursorPosition( -1, 0 );
		break;

		case 9:
			{
				int	i, MoveRight = TAB_LENGTH - (ConGetCursorX() % TAB_LENGTH);

				for ( i = 0; i < MoveRight; i++ )
					WriteConsole(hConsole, " ", 1, (LPDWORD)&Result, 0);
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

				WriteConsole(hConsole,  &pData[X], 1, (LPDWORD)&Result, 0);
				
				if ( CurrentX >= ScreenX-1)	// last coord
				{
			//		if (CurrentY >= ScrollBottom)
				//	CurrentY++;
					if (CurrentY >= ScrollBottom-1)	// last coord
					{
						ConScrollDown(ScrollTop,ScrollBottom);
						ConMoveCursorPosition(-ConGetCursorX(),0);
						//ConMoveCursorPosition(-ConGetCursorX(),-1);
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

/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
PCHAR ConWriteLine(char* pData )
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
			WriteConsole( hConsole,pCurrent, (DWORD)distance, &Result, 0 );

		ConSetCursorPosition( 0, ConGetCursorY() + 1 );

		pCurrent+= (distance + 2);  // Add one to always skip last char printed
	}
	else
	{
		distance = strlen( pCurrent );
		if ( distance > (size_t)ScreenX )
			distance = (size_t)ScreenX;
		WriteConsole( hConsole, pCurrent, (DWORD)distance, &Result, 0 );
		pCurrent += distance;
	}

	return pCurrent;
}


/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
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
					WriteConsole( hConsole, pCurrent, (DWORD)distance, &Result, 0 );
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
				WriteConsole( hConsole, pCurrent, (DWORD)distance, &Result, 0 );
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

	GetConsoleCursorInfo( hConsole,  // handle to console screen buffer
						&ConsoleCursorInfo // address of cursor information
						);

	ConsoleCursorInfo.bVisible = bVisible;

	return SetConsoleCursorInfo( hConsole,  // handle to console screen buffer
						&ConsoleCursorInfo// address of cursor information
						);	
}





/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
void ConClearScreen(void)
{
	DWORD dwWritten;
	COORD Coord ;
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	SMALL_RECT	srcWindow;

	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return;

//	Coord.X = 0;
//	Coord.Y = ConsoleInfo.dwCursorPosition.Y;
//	Coord.Y = 0;


	Coord.X = ConsoleInfo.srWindow.Left;
	Coord.Y = ConsoleInfo.srWindow.Top;

	DWORD dwNumChar = (ConsoleInfo.dwSize.Y - ConsoleInfo.srWindow.Top+1) *
				(ConsoleInfo.srWindow.Right - ConsoleInfo.srWindow.Left +1);

//	DWORD dwNumChar = (ConsoleInfo.srWindow.Bottom - ConsoleInfo.srWindow.Top +1) *
//				(ConsoleInfo.srWindow.Right - ConsoleInfo.srWindow.Left +1);


	FillConsoleOutputCharacter(hConsole, ' ', 
		dwNumChar,
		Coord, &dwWritten);
	FillConsoleOutputAttribute(hConsole, ConsoleInfo.wAttributes,
		dwNumChar,
		Coord, &dwWritten);

//	FillConsoleOutputCharacter(hConsole, ' ', 
//		(DWORD)ConsoleInfo.dwSize.X * (DWORD)(ConsoleInfo.dwSize.Y),
//		Coord, &dwWritten);
//	FillConsoleOutputAttribute(hConsole, ConsoleInfo.wAttributes,
//		(DWORD)ConsoleInfo.dwSize.X * (DWORD)(ConsoleInfo.dwSize.Y),
//		Coord, &dwWritten);

	srcWindow = ConsoleInfo.srWindow;
//	if (srcWindow.Top > 0){				   
//		srcWindow.Top  = 0;
//		srcWindow.Bottom = ConsoleInfo.srWindow.Bottom-ConsoleInfo.srWindow.Top;
//		if (!SetConsoleWindowInfo(hConsole,TRUE,&srcWindow))
//			printf(1,"SetConsoleWindowInfo failed with %d\n",GetLastError());
//	}
	ConSetCursorPosition( 0, 0 );
}


/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
void ConClearScrollRegion()
{
	DWORD dwWritten;
	COORD Coord ;
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return;

	Coord.X = 0;
//	Coord.Y = ConsoleInfo.srWindow.Top;
	Coord.Y = ScrollTop+ConsoleInfo.srWindow.Top;
	FillConsoleOutputCharacter(hConsole, ' ', (DWORD)ConsoleInfo.dwSize.X * (DWORD)ScrollBottom,
//		(DWORD)(ConsoleInfo.srWindow.Right - ConsoleInfo.srWindow.Left)*
//		(DWORD)(ConsoleInfo.srWindow.Bottom - ConsoleInfo.srWindow.Top),
		Coord, &dwWritten);

//	FillConsoleOutputAttribute(hConsole, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_GREEN,
	FillConsoleOutputAttribute(hConsole, ConsoleInfo.wAttributes,
		(DWORD)ConsoleInfo.dwSize.X * (DWORD)ScrollBottom,
//		(DWORD)(ConsoleInfo.srWindow.Right - ConsoleInfo.srWindow.Left)*
//		(DWORD)(ConsoleInfo.srWindow.Bottom - ConsoleInfo.srWindow.Top),
		Coord, &dwWritten);

	ConSetCursorPosition( 0, ScrollTop );
}

/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
void ConClearEOScreen()
{
	DWORD dwWritten;
	COORD Coord ;
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return;

	Coord.X = 0;
	Coord.Y = (short)(ConGetCursorY() + 1) + ConsoleInfo.srWindow.Top;
	FillConsoleOutputCharacter(hConsole, ' ',
		(DWORD)(ConsoleInfo.dwSize.X)*
		(DWORD)(ConsoleInfo.srWindow.Bottom - Coord.Y),
		Coord, &dwWritten);
	FillConsoleOutputAttribute(hConsole, ConsoleInfo.wAttributes,
		(DWORD)(ConsoleInfo.dwSize.X)*
		(DWORD)(ConsoleInfo.srWindow.Bottom - Coord.Y),
		Coord, &dwWritten);

	ConClearEOLine();
}

/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
void ConClearBOScreen()
{
	DWORD dwWritten;
	COORD Coord;
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return;

	Coord.X = 0;
	Coord.Y = 0;
	FillConsoleOutputCharacter(hConsole, ' ',
		(DWORD)(ConsoleInfo.dwSize.X)*
		(DWORD)(ConsoleInfo.dwSize.Y - ConGetCursorY() - 1),
		Coord, &dwWritten);
	FillConsoleOutputAttribute(hConsole, ConsoleInfo.wAttributes, //FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_GREEN,
		(DWORD)(ConsoleInfo.dwSize.X)*
		(DWORD)(ConsoleInfo.dwSize.Y - ConGetCursorY() - 1),
//		(DWORD)(ConsoleInfo.srWindow.Right - ConsoleInfo.srWindow.Left)*
//		(DWORD)(ConsoleInfo.srWindow.Bottom - ConsoleInfo.srWindow.Top - ConGetCursorY() - 1),
		Coord, &dwWritten);

	ConClearBOLine();
}

/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
void ConClearLine()
{
	DWORD dwWritten;
	COORD Coord;
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return;

	Coord.X = 0;
	Coord.Y =  ConGetCursorY();

	FillConsoleOutputAttribute(hConsole, ConsoleInfo.wAttributes, ScreenX,
//		(DWORD)(ConsoleInfo.srWindow.Right - ConsoleInfo.srWindow.Left),
		Coord, &dwWritten);
	FillConsoleOutputCharacter(hConsole, ' ',ScreenX,
//		(DWORD)(ConsoleInfo.srWindow.Right - ConsoleInfo.srWindow.Left),
		Coord, &dwWritten);
}

/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
void ConClearEOLine()
{
	DWORD dwWritten;
	COORD Coord;
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return;;

	Coord.X = ConGetCursorX()+ConsoleInfo.srWindow.Left;
	Coord.Y = ConGetCursorY()+ConsoleInfo.srWindow.Top;

	FillConsoleOutputCharacter(hConsole, ' ',
//		(DWORD)(ConsoleInfo.srWindow.Right - ConGetCursorX()),
		(DWORD)(ScreenX - ConGetCursorX()),
		Coord, &dwWritten);
	FillConsoleOutputAttribute(hConsole, ConsoleInfo.wAttributes ,
//		(DWORD)(ConsoleInfo.srWindow.Right - ConGetCursorX()),
		(DWORD)(ScreenX - ConGetCursorX()),
		Coord, &dwWritten);
}

void ConClearNFromCursorRight(int n)
{
	DWORD dwWritten;
	COORD Coord;
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return;


	Coord.X = ConGetCursorX()+ConsoleInfo.srWindow.Left;
	Coord.Y = ConGetCursorY()+ConsoleInfo.srWindow.Top;
	FillConsoleOutputCharacter(hConsole, ' ',
//		(DWORD)(ConsoleInfo.srWindow.Right - ConGetCursorX()),
		(DWORD)n,
		Coord, &dwWritten);
	FillConsoleOutputAttribute(hConsole, ConsoleInfo.wAttributes ,
//		(DWORD)(ConsoleInfo.srWindow.Right - ConGetCursorX()),
		(DWORD)n,
		Coord, &dwWritten);
}

void ConClearNFromCursorLeft(int n)
{
	DWORD dwWritten;
	COORD Coord;
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return;


	Coord.X = ConGetCursorX()+ConsoleInfo.srWindow.Left-n;
	Coord.Y = ConGetCursorY()+ConsoleInfo.srWindow.Top;
	FillConsoleOutputCharacter(hConsole, ' ',
//		(DWORD)(ConsoleInfo.srWindow.Right - ConGetCursorX()),
		(DWORD)n,
		Coord, &dwWritten);
	FillConsoleOutputAttribute(hConsole, ConsoleInfo.wAttributes /* FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_GREEN */,
//		(DWORD)(ConsoleInfo.srWindow.Right - ConGetCursorX()),
		(DWORD)n,
		Coord, &dwWritten);
}

/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
void ConScrollDownEntireBuffer()
{

	CONSOLE_SCREEN_BUFFER_INFO	ConsoleInfo;

	GetConsoleScreenBufferInfo( hConsole, &ConsoleInfo );
	ConScrollDown(0,ConsoleInfo.dwSize.Y-1);
	return;
}

/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
void ConScrollUpEntireBuffer()
{

	CONSOLE_SCREEN_BUFFER_INFO	ConsoleInfo;

	GetConsoleScreenBufferInfo( hConsole, &ConsoleInfo );
	ConScrollUp(0,ConsoleInfo.dwSize.Y-1);
	return;
}


/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
void ConScrollUp(int topline,int botline)
{
	SMALL_RECT	ScrollRect;
	SMALL_RECT	ClipRect;
	COORD		destination;
	CHAR_INFO	Fill;
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
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

//	Fill.Attributes = FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN;
	Fill.Attributes = ConsoleInfo.wAttributes;
	Fill.Char.AsciiChar = ' ';

	ScrollConsoleScreenBuffer(	hConsole,
								&ScrollRect,
								&ClipRect,
								destination,
								&Fill
								);
	ConSaveViewRect(); // save current window
}



/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
void ConScrollDown(int	topline,int botline)
{
	SMALL_RECT	ScrollRect;
	SMALL_RECT	ClipRect;
	COORD		destination;
	CHAR_INFO	Fill;
	CONSOLE_SCREEN_BUFFER_INFO	ConsoleInfo;

	GetConsoleScreenBufferInfo( hConsole, &ConsoleInfo );

	if ((botline - topline) == ConsoleInfo.dwSize.Y-1)  // scrolling whole buffer
	{
		ScrollRect.Top = topline;
		ScrollRect.Bottom = botline;
	}
	else
	{
		ScrollRect.Top = topline + ConsoleInfo.srWindow.Top+1;
		ScrollRect.Bottom = botline + ConsoleInfo.srWindow.Top;
	}

//	if (topline == 0)
//		ScrollRect.Top = 0;

//	ScrollRect.Top = topline;
//	ScrollRect.Bottom = botline;
	ScrollRect.Left = 0;
	ScrollRect.Right = ConScreenSizeX()-1;

	ClipRect.Top = ScrollRect.Top;
	ClipRect.Bottom = ScrollRect.Bottom;
//	ClipRect.Top = topline + ConsoleInfo.srWindow.Top;
//	ClipRect.Bottom = botline + ConsoleInfo.srWindow.Top;
	ClipRect.Left = ScrollRect.Left;
	ClipRect.Right = ScrollRect.Right;

	destination.X = 0;
	destination.Y = ScrollRect.Top-1;

//	Fill.Attributes = FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN;
	Fill.Attributes = ConsoleInfo.wAttributes;
	Fill.Char.AsciiChar = ' ';

	ScrollConsoleScreenBuffer(	hConsole,
								&ScrollRect,
								NULL,
								destination,
								&Fill
								);
	ConSaveViewRect(); // save current window
}

/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
void ConClearBOLine()
{
	DWORD dwWritten;
	COORD Coord ;
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return;

	Coord.X = 0;
	Coord.Y = (short)(ConGetCursorY());
	FillConsoleOutputAttribute(hConsole,  ConsoleInfo.wAttributes, // FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_GREEN,
		(DWORD)(ConGetCursorX()),
		Coord, &dwWritten);
	FillConsoleOutputCharacter(hConsole, ' ',
		(DWORD)(ConGetCursorX()),
		Coord, &dwWritten);
}

/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
void ConSetCursorPosition(int x, int y)
{
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	COORD Coord;
	int	rc;

	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return;

	if (ConsoleInfo.srWindow.Top != SavedViewRect.Top ||
		ConsoleInfo.srWindow.Right != SavedViewRect.Right)
	{
		// window scrolled
		SetConsoleWindowInfo(hConsole, TRUE, &SavedViewRect);
		GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo);
	}
	Coord.X = (short)(x + ConsoleInfo.srWindow.Left); // + ConsoleInfo.srWindow.Top;
	Coord.Y = (short)(y + ConsoleInfo.srWindow.Top); // + ConsoleInfo.srWindow.Left;

	if (!SetConsoleCursorPosition(hConsole, Coord))
		rc = GetLastError();
	else
		ConSaveViewRect(); // save current window
}

/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
BOOL ConChangeCursor( CONSOLE_CURSOR_INFO *pCursorInfo )
{
	return SetConsoleCursorInfo( hConsole, pCursorInfo );
}

/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
int ConGetCursorX()
{
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return 0;

	return ConsoleInfo.dwCursorPosition.X;
}

/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
int ConGetCursorY()
{
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
	{
		return 0;
	}

	return (ConsoleInfo.dwCursorPosition.Y - ConsoleInfo.srWindow.Top);
}

int ConGetCursorInBufferY()
{
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
	{
		return 0;
	}

	return (ConsoleInfo.dwCursorPosition.Y);
}

/* ************************************************************ */
/* Function: 										*/
/* 		*/
/* ************************************************************ */
void ConMoveCursorPosition(int x, int y)
{
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	COORD Coord;
	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return;

	Coord.X = (short)(ConsoleInfo.dwCursorPosition.X + x);
	Coord.Y = (short)(ConsoleInfo.dwCursorPosition.Y + y);

	SetConsoleCursorPosition(hConsole, Coord);
	ConSaveViewRect();
}

void ConGetRelativeCursorPosition(int *x, int *y)
{
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;

	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
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

	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return;

	Coord.X = (short)(ConsoleInfo.dwCursorPosition.X);
	Coord.Y = (short)(ConsoleInfo.dwCursorPosition.Y);

	sr.Left = Coord.X + n;
	sr.Top = Coord.Y;
	sr.Bottom = Coord.Y;
	sr.Right = ConsoleInfo.srWindow.Right;

	Temp.X = 256;
	Temp.Y = 1;
	result = ReadConsoleOutput( hConsole,				// handle of a console screen buffer 
								(PCHAR_INFO)chiBuffer,	// address of buffer that receives data 
								Temp,	// column-row size of destination buffer 
								ZeroCoord,				// upper-left cell to write to 
								&sr	// address of rectangle to read from 
								);
	ConClearEOLine();

	sr.Left = Coord.X;
	Temp.X = 256;
	Temp.Y = 1;

	sr.Right -= n;
	result = WriteConsoleOutput(hConsole,(PCHAR_INFO)chiBuffer,Temp, ZeroCoord, &sr);
}




SCREEN_HANDLE ConSaveScreenHandle( SCREEN_HANDLE hScreen )
{
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
    PSCREEN_RECORD  pScreenRec = (PSCREEN_RECORD)hScreen;
     int            result, width,height;

	if ( hConsole == NULL )
		return NULL;

	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
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
		// if we allocated a screen within this scope, free it before returning
		if ( pScreenRec != (PSCREEN_RECORD)hScreen ) {
			free(pScreenRec);
		}
		return NULL;
	}

	result =  ReadConsoleOutput( hConsole,				// handle of a console screen buffer 
							 (PCHAR_INFO)(pScreenRec->pScreenBuf),	// address of buffer that receives data 
							 pScreenRec->ScreenSize,	// column-row size of destination buffer 
							 ZeroCoord,				// upper-left cell to write to 
							 &ConsoleInfo.srWindow	// address of rectangle to read from 
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

	if ( hConsole == NULL )
		return FALSE;

//	if ( pSavedScreen == NULL )
//		return FALSE;


	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return (FALSE);

	width = ConsoleInfo.srWindow.Right - ConsoleInfo.srWindow.Left + 1;
	height = ConsoleInfo.srWindow.Bottom - ConsoleInfo.srWindow.Top + 1;
	
	beginOfScreen.X = ConsoleInfo.srWindow.Left;
	beginOfScreen.Y = ConsoleInfo.srWindow.Top;
	FillConsoleOutputCharacter(hConsole, ' ', (DWORD)width*height,
		beginOfScreen, &dwWritten);
//	Sleep(250);  dsk- taken out 2/18/2009.. looks like this just needed because telmc lacks thread syncrhonization

	pSavedCharInfo = (PCHAR_INFO)(pScreenRec->pScreenBuf);
	SetConsoleTextAttribute(hConsole, pSavedCharInfo->Attributes);

	FillConsoleOutputAttribute(hConsole, pSavedCharInfo->Attributes,
		(DWORD)width*height,
		beginOfScreen, &dwWritten);

	fOkay = WriteConsoleOutput( hConsole,	// handle to a console screen buffer 
								(PCHAR_INFO)(pScreenRec->pScreenBuf),	// pointer to buffer with data to write  
								pScreenRec->ScreenSize,	// column-row size of source buffer 
								ZeroCoord,	// upper-left cell to write from 
								&ConsoleInfo.srWindow	// pointer to rectangle to write to 
								);

	SetConsoleWindowInfo(hConsole,TRUE,&pScreenRec->srWindowRect);
    
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

	if ( hConsole == NULL )
		return FALSE;

	if ( pSavedScreen == NULL )
		return FALSE;


	if (!GetConsoleScreenBufferInfo(hConsole, &ConsoleInfo))
		return (FALSE);

	beginOfScreen.X = ConsoleInfo.srWindow.Left;
	beginOfScreen.Y = ConsoleInfo.srWindow.Top;

	FillConsoleOutputCharacter(hConsole, ' ', 
		(DWORD)pScreenRec->ScreenSize.X*pScreenRec->ScreenSize.Y,
		beginOfScreen, &dwWritten);

	pSavedCharInfo = (PCHAR_INFO)(pScreenRec->pScreenBuf);
	SetConsoleTextAttribute(hConsole, pSavedCharInfo->Attributes);

	FillConsoleOutputAttribute(hConsole, pSavedCharInfo->Attributes,
		(DWORD)pScreenRec->ScreenSize.X*pScreenRec->ScreenSize.Y,
		beginOfScreen, &dwWritten);
/*
	fOkay = WriteConsoleOutput( hConsole,	// handle to a console screen buffer 
								(PCHAR_INFO)(pScreenRec->pScreenBuf),	// pointer to buffer with data to write  
								pScreenRec->ScreenSize,	// column-row size of source buffer 
								ZeroCoord,	// upper-left cell to write from 
								&ConsoleInfo.srWindow	// pointer to rectangle to write to 
								);


	ConSetCursorPosition( pScreenRec->ScreenCursor.X, pScreenRec->ScreenCursor.Y );
*/
	return fOkay;
}

void ConDeleteScreenHandle( SCREEN_HANDLE hScreen )
{
    PSCREEN_RECORD pScreenRec = (PSCREEN_RECORD)hScreen;

    free(pScreenRec->pScreenBuf);
    free(pScreenRec);

}


/* ************************************************************ */
/* Function: ConRestoreScreen								*/
/* Restores Previous Saved screen info and buffer		*/
/* ************************************************************ */
BOOL ConRestoreScreen( void )
{
	return ConRestoreScreenHandle(pSavedScreenRec);
}

void ConRestoreViewRect( void )
{
	SetConsoleWindowInfo(hConsole,TRUE,&SavedViewRect);
}

/* ************************************************************ */
/* Function: ConSaveScreen								*/
/* Saves current screen info and buffer		*/
/* ************************************************************ */
BOOL ConSaveScreen( void )
{
    pSavedScreenRec = (PSCREEN_RECORD)ConSaveScreenHandle(pSavedScreenRec);
	return TRUE;
}

void ConSaveViewRect( void )
{
	CONSOLE_SCREEN_BUFFER_INFO	csbi;

	if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
		return;

	SavedViewRect = csbi.srWindow;

}