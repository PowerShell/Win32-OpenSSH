/* console.h
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
 
#ifndef __PRAGMA_CONSOLE_h
#define __PRAGMA_CONSOLE_h

#define ANSI_ATTR_RESET			0
#define ANSI_BRIGHT				1
#define ANSI_DIM				2
#define ANSI_UNDERSCORE			4
#define ANSI_BLINK				5
#define ANSI_REVERSE			7
#define ANSI_HIDDEN				8
#define ANSI_NOREVERSE			27

#define ANSI_FOREGROUND_BLACK	30
#define ANSI_FOREGROUND_RED		31
#define ANSI_FOREGROUND_GREEN	32
#define ANSI_FOREGROUND_YELLOW	33
#define ANSI_FOREGROUND_BLUE	34
#define ANSI_FOREGROUND_MAGENTA	35
#define ANSI_FOREGROUND_CYAN	36
#define ANSI_FOREGROUND_WHITE	37
#define ANSI_BACKGROUND_BLACK	40
#define ANSI_BACKGROUND_RED		41
#define ANSI_BACKGROUND_GREEN	42
#define ANSI_BACKGROUND_YELLOW	43
#define ANSI_BACKGROUND_BLUE	44
#define ANSI_BACKGROUND_MAGENTA	45
#define ANSI_BACKGROUND_CYAN	46
#define ANSI_BACKGROUND_WHITE	47
#define ANSI_BACKGROUND_BRIGHT	128

#define TAB_LENGTH				4
#define TAB_CHAR				'\t'
#define TAB_SPACE				"    "

#define true TRUE
#define false FALSE
#define bool BOOL

typedef void *  SCREEN_HANDLE;

int ConInit( DWORD OutputHandle, BOOL fSmartInit);
int ConUnInitWithRestore( void );
int ConUnInit( void );
//void ConHideConsole(void);
BOOL ConSetScreenRect( int xSize, int ySize );
BOOL ConSetScreenSize( int X, int Y );
BOOL ConRestoreScreen( void );
BOOL ConSaveScreen( void );
DWORD ConRedrawScreen( void );
void ConSetAttribute( int *iParam, int iParamCount );
void ConSetScrollRegion( int Top, int Bottom );
int	ConScreenSizeX();
int	ConSetScreenX();
int ConScreenSizeY();
int ConWindowSizeX();
int ConWindowSizeY();
int ConSetScreenY();
void ConFillToEndOfLine();
int ConWriteString(char* pszString, int cbString);
int ConWriteMenu(char* pszString, int cbString);
BOOL ConWriteChar( CHAR ch );
int ConWriteConsole( char *pData, int NumChars );
PCHAR ConDisplayData(char* pData, int NumLines);
PCHAR ConWriteLine(char* pData);
int Con_printf( const char *Format, ... );
void ConClearScrollRegion();
void ConClearScreen();
void ConClearEOScreen();
void ConClearBOScreen();
void ConClearLine();
void ConClearEOLine();
void ConClearNFromCursorRight(int n);
void ConClearNFromCursorLeft(int n);
void ConScrollUpEntireBuffer();
void ConScrollDownEntireBuffer();
void ConScrollUp(int	topline,int botline);
void ConScrollDown(int	topline,int botline);
void ConClearBOLine();
BOOL ConChangeCursor( CONSOLE_CURSOR_INFO *pCursorInfo );
void ConSetCursorPosition(int x, int y);
int ConGetCursorX();
int ConGetCursorY();
int ConGetCursorInBufferY(void);
BOOL ConDisplayCursor( BOOL bVisible );
void ConMoveCursorPosition(int x, int y);
void ConGetRelativeCursorPosition(int *x, int *y);
BOOL ConRestoreScreenHandle( SCREEN_HANDLE hScreen );
BOOL ConRestoreScreenColors( void );
SCREEN_HANDLE ConSaveScreenHandle( SCREEN_HANDLE);
void ConDeleteScreenHandle( SCREEN_HANDLE hScreen );
void ConSaveViewRect( void );
void ConRestoreViewRect( void );
void ConDeleteChars(int n);


#endif
