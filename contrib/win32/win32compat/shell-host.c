/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
* Primitive shell-host to support parsing of cmd.exe input and async IO redirection
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
#include <Windows.h>
#include <Strsafe.h>
#include <stdio.h>
#include <io.h>

#define MAX_CONSOLE_COLUMNS 9999
#define MAX_CONSOLE_ROWS 9999
#define MAX_CMD_LEN 512
#define WM_APPEXIT WM_USER+1
#define MAX_EXPECTED_BUFFER_SIZE 1024

typedef struct consoleEvent {
    DWORD event;
    HWND  hwnd;
    LONG  idObject;
    LONG  idChild;
    void* prior;
    void* next;
} consoleEvent;

consoleEvent* head = NULL;
consoleEvent* tail = NULL;

BOOL isRedirected = FALSE;
BOOL istty = FALSE;
BOOL bRet = FALSE;
BOOL bNoScrollRegion = FALSE;
BOOL bStartup = TRUE;

HANDLE child_out = INVALID_HANDLE_VALUE;
HANDLE child_in = INVALID_HANDLE_VALUE;
HANDLE child_err = INVALID_HANDLE_VALUE;
HANDLE pipe_in = INVALID_HANDLE_VALUE;
HANDLE pipe_out = INVALID_HANDLE_VALUE;
HANDLE pipe_err = INVALID_HANDLE_VALUE;
HANDLE child_pipe_read = INVALID_HANDLE_VALUE;
HANDLE child_pipe_write = INVALID_HANDLE_VALUE;
HANDLE child = INVALID_HANDLE_VALUE;
HANDLE hConsoleBuffer = INVALID_HANDLE_VALUE;

HANDLE monitor_thread = INVALID_HANDLE_VALUE;
HANDLE io_thread = INVALID_HANDLE_VALUE;
HANDLE ux_thread = INVALID_HANDLE_VALUE;

DWORD hostProcessId = 0;
DWORD hostThreadId = 0;
DWORD childProcessId = 0;
DWORD dwStatus = 0;
DWORD currentLine = 0;

UINT cp = 0;

UINT ViewPortY = 0;
UINT lastViewPortY = 0;

BOOL bFullScreen = FALSE;
BOOL bUseAnsiEmulation = TRUE;

UINT savedViewPortY = 0;
UINT savedLastViewPortY = 0;

DWORD in_cmd_len = 0;
char in_cmd[MAX_CMD_LEN];

CRITICAL_SECTION criticalSection;

CONSOLE_SCREEN_BUFFER_INFOEX  consoleInfo;
CONSOLE_SCREEN_BUFFER_INFOEX  nextConsoleInfo;
STARTUPINFO inputSi;

#define GOTO_CLEANUP_ON_FALSE(exp) do {			\
	ret = (exp);					            \
	if (ret == FALSE)				            \
		goto cleanup;				            \
} while(0)						                \

#define GOTO_CLEANUP_ON_ERR(exp) do {			\
	if ((exp) != 0)				                \
		goto cleanup;				            \
} while(0)						                \

// Console keystroke handling
void SendKeyStroke(HANDLE hInput, int keyStroke, char character)
{
    DWORD wr = 0;
    INPUT_RECORD ir;

    ir.EventType = KEY_EVENT;
    ir.Event.KeyEvent.bKeyDown = TRUE;
    ir.Event.KeyEvent.wRepeatCount = 1;
    ir.Event.KeyEvent.wVirtualKeyCode = keyStroke;
    ir.Event.KeyEvent.wVirtualScanCode = 0;
    ir.Event.KeyEvent.dwControlKeyState = 0;
    if(character != 0)
        ir.Event.KeyEvent.uChar.AsciiChar = character;

    WriteConsoleInputA(hInput, &ir, 1, &wr);

    ir.Event.KeyEvent.bKeyDown = FALSE;
    WriteConsoleInputA(hInput, &ir, 1, &wr);
}

// VT output routines
void SendClearScreen(HANDLE hInput) {
    DWORD wr = 0;

    WriteFile(hInput, "\033[2J", 4, &wr, NULL);
}

void SendClearScreenFromCursor(HANDLE hInput) {
    DWORD wr = 0;

    WriteFile(hInput, "\033[1J", 4, &wr, NULL);
}

void SendCRLF(HANDLE hInput) {

    DWORD wr = 0;

    WriteFile(hInput, "\n", 2, &wr, NULL);
}

void SendHideCursor(HANDLE hInput) {
    DWORD wr = 0;

    WriteFile(hInput, "\033[?25l", 6, &wr, NULL);
}

void SendShowCursor(HANDLE hInput) {
    DWORD wr = 0;

    WriteFile(hInput, "\033[?25h", 6, &wr, NULL);
}

void SendCursorPositionRequest(HANDLE hInput) {
    DWORD wr = 0;

    WriteFile(hInput, "\033[6n", 4, &wr, NULL);    
}

void SendSetCursor(HANDLE hInput, int X, int Y) {

    DWORD wr = 0;
    DWORD out = 0;

    static int sLastX = 0;
    static int sLastY = 0;

    char formatted_output[255];

    out = _snprintf_s(formatted_output, sizeof(formatted_output), _TRUNCATE, "\033[%d;%dH", Y, X);
    //if (X != sLastX || Y != sLastY)
        if (bUseAnsiEmulation)
            WriteFile(hInput, formatted_output, out, &wr, NULL);

    sLastX = X;
    sLastY = Y;
}

void SendVerticalScroll(HANDLE hInput, int lines) {

    DWORD wr = 0;
    DWORD out = 0;
    char formatted_output[255];

    LONG vn = abs(lines);

    if (lines > 0) {

        out = snprintf(formatted_output, sizeof(formatted_output), "\033[%dT", vn);

        if (bUseAnsiEmulation)
            WriteFile(hInput, formatted_output, out, &wr, NULL);
    }
    // Not supporting the [S at the moment.
}

void SendHorizontalScroll(HANDLE hInput, int cells) {

    DWORD wr = 0;
    DWORD out = 0;
    char formatted_output[255];

    out = snprintf(formatted_output, sizeof(formatted_output), "\033[%dG", cells);

    if (bUseAnsiEmulation)
        WriteFile(hInput, formatted_output, out, &wr, NULL);
}

void SendCharacter(HANDLE hInput, WORD attributes, char character) {

    DWORD wr = 0;
    DWORD out = 0;
    DWORD current = 0;

    char formatted_output[2048];

    USHORT Color = 0;
	ULONG Status = 0;
	
	PSTR Next;
    size_t SizeLeft;

    Next = formatted_output;
    SizeLeft = sizeof formatted_output;

	//
	// Handle the foreground intensity
	//
	if ((attributes & FOREGROUND_INTENSITY) != 0) {
		Color = 1;
	}
	else {
		Color = 0;
	}

	StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, "\033[%u", Color);

    //
    // Handle the background intensity
    //
    if ((attributes & BACKGROUND_INTENSITY) != 0) {
        Color = 1;
    }
    else {
        Color = 39;
    }

    StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, ";%u", Color);

    //
    // Handle the underline
    //
    if ((attributes & COMMON_LVB_UNDERSCORE) != 0) {
        Color = 4;
    }
    else {
        Color = 24;
    }

    StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, ";%u", Color);

    //
    // Handle reverse video
    //
    if ((attributes & COMMON_LVB_REVERSE_VIDEO) != 0) {
        Color = 7;
    }
    else {
        Color = 27;
    }

    StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, ";%u", Color);

    //
    // Add background and foreground colors to buffer.
    //
    Color = 30 +
        4 * ((attributes & FOREGROUND_BLUE) != 0) +
        2 * ((attributes & FOREGROUND_GREEN) != 0) +
        1 * ((attributes & FOREGROUND_RED) != 0);

	StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, ";%u", Color);

    Color = 40 +
        4 * ((attributes & BACKGROUND_BLUE) != 0) +
        2 * ((attributes & BACKGROUND_GREEN) != 0) +
        1 * ((attributes & BACKGROUND_RED) != 0);

	StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, ";%u", Color);

	StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, "m", Color);

    if (bUseAnsiEmulation)
        WriteFile(hInput, formatted_output, (Next - formatted_output), &wr, NULL);

    WriteFile(hInput, &character, 1, &wr, NULL);

    // Reset
    if (bUseAnsiEmulation)
        WriteFile(hInput, "\033[0m", 4, &wr, NULL);
}

void SendBuffer(HANDLE hInput, CHAR_INFO *buffer, DWORD bufferSize) {

    DWORD wr = 0;
    DWORD out = 0;
    DWORD current = 0;

    char* formatted_output = NULL;

    USHORT Color = 0;
	ULONG Status = 0;
	
    if (bufferSize <= 0)
        return;

    formatted_output = (char *)malloc(bufferSize);

	PSTR Next;
    Next = formatted_output;

    for (DWORD i = 0; i < bufferSize; i++)
    { 
        // East asian languages have 2 bytes for each character, only use the first
        if (!(buffer[i].Attributes & COMMON_LVB_TRAILING_BYTE))
        {
            WideCharToMultiByte(cp,
                0,
                &buffer[i].Char.UnicodeChar,
                1,
                Next,
                1,
                NULL,
                NULL);

            SendCharacter(hInput, buffer[i].Attributes, *Next);

            Next++;
        }
    }

    if (formatted_output) {
        free(formatted_output);
    }
}

void CalculateAndSetCursor(HANDLE hInput, UINT aboveTopLine, UINT viewPortHeight, UINT x, UINT y) {

    if (aboveTopLine > 0) {
        if (y == viewPortHeight + aboveTopLine - 1) {
            if (ViewPortY == lastViewPortY && lastViewPortY > 0) {
                SendSetCursor(pipe_out, x + 1, y + 1);
            }
            else {
                SendSetCursor(pipe_out, x + 1, y + 1);
            }
            consoleInfo = nextConsoleInfo;
        }
        else {
            SendSetCursor(pipe_out, x + 1, y + 1);
        }
    }
    else {
        SendSetCursor(pipe_out, x + 1, y + 1);
    }

    currentLine = y;
}

void SizeWindow(HANDLE hInput) {

    SMALL_RECT srWindowRect;
    COORD coordScreen;
    BOOL bSuccess = FALSE;

    // The input window does not scroll currently to ease calculations
    // on the paint/draw.
    bNoScrollRegion = TRUE;

    // Set the default font to Consolas
    CONSOLE_FONT_INFOEX matchingFont;
    matchingFont.cbSize = sizeof(matchingFont);
    matchingFont.nFont = 0;
    matchingFont.dwFontSize.X = 0;
    matchingFont.dwFontSize.Y = 16;
    matchingFont.FontFamily = FF_DONTCARE;
    matchingFont.FontWeight = FW_NORMAL;
    wcscpy(matchingFont.FaceName, L"Consolas");

    bSuccess = SetCurrentConsoleFontEx(child_out, FALSE, &matchingFont);

    // This information is the live screen 
    ZeroMemory(&consoleInfo, sizeof(consoleInfo));
    consoleInfo.cbSize = sizeof(consoleInfo);

    bSuccess = GetConsoleScreenBufferInfoEx(child_out, &consoleInfo);

    // Get the largest size we can size the console window to.
    coordScreen = GetLargestConsoleWindowSize(child_out);

    // Define the new console window size and scroll position.
    if (inputSi.dwXCountChars == 0 || inputSi.dwYCountChars == 0) {
        inputSi.dwXCountChars = 80;
        inputSi.dwYCountChars = 25;
    }

    srWindowRect.Right = (SHORT)(min(inputSi.dwXCountChars, coordScreen.X) - 1);
    srWindowRect.Bottom = (SHORT)(min(inputSi.dwYCountChars, coordScreen.Y) - 1);
    srWindowRect.Left = srWindowRect.Top = (SHORT)0;

    /// Define the new console buffer size to be the maximum possible.
    coordScreen.X = 100;
    coordScreen.Y = 9999;

    if (SetConsoleWindowInfo(child_out, TRUE, &srWindowRect)) {

        bSuccess = SetConsoleScreenBufferSize(child_out, coordScreen);
    }
    else {
        if (SetConsoleScreenBufferSize(child_out, coordScreen)) {

            bSuccess = SetConsoleWindowInfo(child_out, TRUE, &srWindowRect);
        }

    }

    bSuccess = GetConsoleScreenBufferInfoEx(child_out, &consoleInfo);
}

void RepaintWindow(HANDLE hInput) {

    SMALL_RECT readRect;
    DWORD bufferSize = 0;

    CONSOLE_SCREEN_BUFFER_INFOEX  consoleInfo;
    CHAR_INFO *pBuffer = NULL;

    SendHideCursor(hInput);

    ZeroMemory(&consoleInfo, sizeof(consoleInfo));
    consoleInfo.cbSize = sizeof(consoleInfo);

    if (GetConsoleScreenBufferInfoEx(child_out, &consoleInfo)) {

        // Compute buffer size for the full window
        bufferSize = (consoleInfo.srWindow.Bottom - consoleInfo.srWindow.Top + 1) * 
            (consoleInfo.srWindow.Right - consoleInfo.srWindow.Left + 1);

        // Create the screen scrape buffer
        pBuffer = (PCHAR_INFO)malloc(sizeof(CHAR_INFO) * bufferSize);

        if (!pBuffer) {
           goto final_processing;
        }

        // Figure out the buffer size
        COORD coordBufSize;
        coordBufSize.Y = (consoleInfo.srWindow.Bottom - consoleInfo.srWindow.Top + 1);
        coordBufSize.X = (consoleInfo.srWindow.Right - consoleInfo.srWindow.Left + 1);

        if (coordBufSize.X < 0 || coordBufSize.X > MAX_CONSOLE_COLUMNS ||
            coordBufSize.Y < 0 || coordBufSize.Y > MAX_CONSOLE_ROWS)
        {
            goto final_processing;
        }

        // The top left destination cell of the temporary buffer is row 0, col 0.
        COORD coordBufCoord;
        coordBufCoord.X = 0;
        coordBufCoord.Y = 0;

        // Copy the block from the screen buffer to the temporary buffer.
        if (!ReadConsoleOutput(child_out, pBuffer, coordBufSize, coordBufCoord, &consoleInfo.srWindow))
        {
            goto final_processing;
        }

        // Set cursor location based on the reported location from the message.
        CalculateAndSetCursor(pipe_out, 0, 0, 0, 0);

        // Send the entire block.
        SendBuffer(pipe_out, pBuffer, bufferSize);

        free(pBuffer);
        pBuffer = NULL;
    }

final_processing:
    if (pBuffer)
        free(pBuffer);

    SendShowCursor(hInput);
}

// End of VT output routines

DWORD WINAPI MonitorChild(_In_ LPVOID lpParameter) {
    WaitForSingleObject(child, INFINITE);
    if (isRedirected)
        CloseHandle(pipe_in);
    PostThreadMessage(hostThreadId, WM_APPEXIT, 0, 0);
    return 0;
}

DWORD ProcessEvent(void *p) {

    char f[255];
    char chUpdate;
    WORD  wAttributes;
    WORD  wX;
    WORD  wY;

    DWORD dwProcessId;
    DWORD wr = 0;
    DWORD dwMode;

    DWORD event;
    HWND hwnd;
    LONG idObject;
    LONG idChild;

    if (!p)
    {
        return ERROR_INVALID_PARAMETER;
    }

    consoleEvent* current = (consoleEvent *)p;

    if(current) { 
        event = current->event;
        hwnd = current->hwnd;
        idObject = current->idObject;
        idChild = current->idChild;
    }
    else {
        return ERROR_INVALID_PARAMETER;
    }

    if (event < EVENT_CONSOLE_CARET || event > EVENT_CONSOLE_LAYOUT)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (child_out == INVALID_HANDLE_VALUE || child_out == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    GetWindowThreadProcessId(hwnd, &dwProcessId);

    if (childProcessId != dwProcessId)
    {
        return ERROR_SUCCESS;
    }

    ZeroMemory(&consoleInfo, sizeof(consoleInfo));
    consoleInfo.cbSize = sizeof(consoleInfo);

    GetConsoleScreenBufferInfoEx(child_out, &consoleInfo);

    UINT viewPortHeight = consoleInfo.srWindow.Bottom - consoleInfo.srWindow.Top + 1;
    UINT viewPortWidth = consoleInfo.srWindow.Right - consoleInfo.srWindow.Left + 1;

    switch (event) {
    case EVENT_CONSOLE_CARET:
    {
        COORD co;

        if (idObject == CONSOLE_CARET_SELECTION) {
            co.X = HIWORD(idChild);
            co.Y = LOWORD(idChild);
        }
        else {
            co.X = HIWORD(idChild);
            co.Y = LOWORD(idChild);
        }

        break;
    }
    case EVENT_CONSOLE_UPDATE_REGION:
    {
        SMALL_RECT readRect;

        readRect.Top = HIWORD(idObject);
        readRect.Left = LOWORD(idObject);
        readRect.Bottom = HIWORD(idChild);
        readRect.Right = LOWORD(idChild);

        // Detect a "cls" (Windows).
        if (!bStartup && 
            (readRect.Top == consoleInfo.srWindow.Top || readRect.Top == nextConsoleInfo.srWindow.Top))
        {
            BOOL isClearCommand = FALSE;
            isClearCommand = (consoleInfo.dwSize.X == readRect.Right + 1) && (consoleInfo.dwSize.Y == readRect.Bottom + 1);

            // If cls then inform app to clear its buffers and return.
            if (isClearCommand)
            {
                SendClearScreen(pipe_out);
                ViewPortY = 0;
                lastViewPortY = 0;

                return ERROR_SUCCESS;
            }
        }

        // Figure out the buffer size
        COORD coordBufSize;
        coordBufSize.Y = readRect.Bottom - readRect.Top + 1;
        coordBufSize.X = readRect.Right - readRect.Left + 1;

        // Security check:  the maximum screen buffer size is 9999 columns x 9999 lines so check
        // the computed buffer size for overflow.  since the X and Y in the COORD structure
        // are shorts they could be negative.
        if (coordBufSize.X < 0 || coordBufSize.X > MAX_CONSOLE_COLUMNS ||
            coordBufSize.Y < 0 || coordBufSize.Y > MAX_CONSOLE_ROWS)
        {
            return ERROR_INVALID_PARAMETER;
        }

        // Compute buffer size
        DWORD bufferSize = coordBufSize.X * coordBufSize.Y;

        if (bufferSize > MAX_EXPECTED_BUFFER_SIZE) {

           if (!bStartup) {
                SendClearScreen(pipe_out);
                ViewPortY = 0;
                lastViewPortY = 0;
            }

            return ERROR_SUCCESS;
        }
        
        // Create the screen scrape buffer
        CHAR_INFO *pBuffer = (PCHAR_INFO)malloc(sizeof(CHAR_INFO) * bufferSize);

        if (!pBuffer)
        {
            return ERROR_INSUFFICIENT_BUFFER;
        }

        // The top left destination cell of the temporary buffer is row 0, col 0.
        COORD coordBufCoord;
        coordBufCoord.X = 0;
        coordBufCoord.Y = 0;

        // Copy the block from the screen buffer to the temp. buffer.
        if (!ReadConsoleOutput(child_out, pBuffer, coordBufSize, coordBufCoord, &readRect))
        {
            DWORD dwError = GetLastError();

            free(pBuffer);
            return dwError;
        }

        // Set cursor location based on the reported location from the message.
        CalculateAndSetCursor(pipe_out, ViewPortY, viewPortHeight, readRect.Left, 
            readRect.Top);

        // Send the entire block.
        SendBuffer(pipe_out, pBuffer, bufferSize);

        lastViewPortY = ViewPortY;

        free(pBuffer);

        break;
    }
    case EVENT_CONSOLE_UPDATE_SIMPLE:
    {
        chUpdate = LOWORD(idChild);
        wAttributes = HIWORD(idChild);
        wX = LOWORD(idObject);
        wY = HIWORD(idObject);

        // Set cursor location based on the reported location from the message.
        CalculateAndSetCursor(pipe_out, ViewPortY, viewPortHeight, wX, wY);

        // Send the one character. Note that a CR doesn't end up here.
        SendCharacter(pipe_out, wAttributes, chUpdate);

        break;
    }
    case EVENT_CONSOLE_UPDATE_SCROLL:
    {
        DWORD out = 0;
        LONG vd = idChild;
        LONG hd = idObject;

        LONG vn = abs(vd);

        if (vd > 0) {
            if(ViewPortY > 0)
                ViewPortY -= vn;
        }
        else {
            ViewPortY += vn;
        }

        //SendVerticalScroll(pipe_out, vd);

        //SendHorizontalScroll(pipe_out, hd);

        if(vd < 0)
            SendCRLF(pipe_out);

        break;
    }
    case EVENT_CONSOLE_LAYOUT:
    {
        if (consoleInfo.dwMaximumWindowSize.X == consoleInfo.dwSize.X &&
            consoleInfo.dwMaximumWindowSize.Y == consoleInfo.dwSize.Y &&
           (consoleInfo.dwCursorPosition.X == 0 && consoleInfo.dwCursorPosition.Y == 0))
        {
            // Screen has switched to fullscreen mode
            SendClearScreen(pipe_out);

            savedViewPortY = ViewPortY;
            savedLastViewPortY = lastViewPortY;

            ViewPortY = 0;
            lastViewPortY = 0;;

            bFullScreen = TRUE;
        }
        else
        {
            // Leave full screen mode if applicable
            if (bFullScreen) {
                SendClearScreen(pipe_out);

                ViewPortY = savedViewPortY;
                lastViewPortY = savedLastViewPortY;
                bFullScreen = FALSE;
            }
        }

        break;
    }
    }

    ZeroMemory(&consoleInfo, sizeof(consoleInfo));
    consoleInfo.cbSize = sizeof(consoleInfo);

    GetConsoleScreenBufferInfoEx(child_out, &consoleInfo);

    return ERROR_SUCCESS;
}

DWORD ProcessEventQueue(void *p) {

    while (1) {

        while (head) {

            EnterCriticalSection(&criticalSection);

            consoleEvent* current = head;

            if (current) {
                if (current->next)
                {
                    head = current->next;
                    head->prior = NULL;
                }
                else
                {
                    head = NULL;
                    tail = NULL;
                }
            }

            LeaveCriticalSection(&criticalSection);

            if (current)
            {
                ProcessEvent(current);
                free(current);
            }
        }

        if (child_out != INVALID_HANDLE_VALUE && child_out != NULL)
        {
            ZeroMemory(&consoleInfo, sizeof(consoleInfo));
            consoleInfo.cbSize = sizeof(consoleInfo);

            // This information is the live buffer that's currently in use.
            GetConsoleScreenBufferInfoEx(child_out, &consoleInfo);

            // Set the cursor to the last known good location according to the live buffer.
            SendSetCursor(pipe_out, consoleInfo.dwCursorPosition.X + 1, 
                consoleInfo.dwCursorPosition.Y + 1);
        }

        Sleep(100);
    }

    return 0;
}

void QueueEvent(
    DWORD event,
    HWND hwnd,
    LONG idObject,
    LONG idChild) {

    consoleEvent* current = NULL;

    EnterCriticalSection(&criticalSection);

    current = malloc(sizeof(consoleEvent));

    if (current) {
        if (!head) {
            current->event = event;
            current->hwnd = hwnd;
            current->idChild = idChild;
            current->idObject = idObject;

            // No links head == tail
            current->next = NULL;
            current->prior = NULL;

            head = current;
            tail = current;
        }
        else {
            current->event = event;
            current->hwnd = hwnd;
            current->idChild = idChild;
            current->idObject = idObject;

            // Current tail points to new tail
            tail->next = current;

            // New tail points to old tail
            current->prior = tail;
            current->next = NULL;

            // Update the tail pointer to the new
            // last event
            tail = current;
        }
    }

    LeaveCriticalSection(&criticalSection);

    return;
}

DWORD ProcessPipes(void *p) {

    BOOL ret;
    DWORD dwStatus;

    /* process data from pipe_in and route appropriately */
    while (1) {
        char buf[128];
        DWORD rd = 0, wr = 0, i = 0;
        GOTO_CLEANUP_ON_FALSE(ReadFile(pipe_in, buf, 128, &rd, NULL));

        if (!istty) { /* no tty, just send it accross */
            GOTO_CLEANUP_ON_FALSE(WriteFile(child_pipe_write, buf, rd, &wr, NULL));
            continue;
        }

        bStartup = FALSE;

        while (i < rd) {

            INPUT_RECORD ir;

            if (buf[i] == '\r')
            {
                SendKeyStroke(child_in, VK_RETURN, buf[0]);
            }
            else if (buf[i] == '\b')
            {
                SendKeyStroke(child_in, VK_BACK, buf[0]);
            }
            else if (buf[i] == '\t')
            {
                SendKeyStroke(child_in, VK_TAB, buf[0]);
            }
            else if (buf[i] == '\x1b') 
            {                
                // These are incoming ANSI keystrokes.
                switch (rd) {
                case 1:
                    SendKeyStroke(child_in, VK_ESCAPE, buf[0]);
                    break;
                case 3:
                    switch (buf[i + 1])
                    {
                    case '[':
                        switch (buf[i + 2])
                        {
                        case 'A':
                            SendKeyStroke(child_in, VK_UP, 0);
                            i = i + 2;
                            break;
                        case 'B':
                            SendKeyStroke(child_in, VK_DOWN, 0);
                            i = i + 2;
                            break;
                        case 'C':
                            SendKeyStroke(child_in, VK_RIGHT, 0);
                            i = i + 2;
                            break;
                        case 'D':
                            SendKeyStroke(child_in, VK_LEFT, 0);
                            i = i + 2;
                            break;
                        default:
                            break;
                        }
                    default:
                        break;
                    }
                case 4:
                    switch (buf[i + 1]) {
                    case '[':
                    {
                        switch (buf[i + 2]) {
                        case '2':
                            switch (buf[i + 3]) {
                            case '~':
                            {
                                SendKeyStroke(child_in, VK_INSERT, 0);
                                i = i + 3;
                                break;
                            }
                            default:
                                break;
                            }
                        case '3':
                            switch (buf[i + 3]) {
                            case '~':
                            {
                                SendKeyStroke(child_in, VK_DELETE, 0);
                                i = i + 3;
                                break;
                            }
                            default:
                                break;
                            }
                        default:
                            break;
                        }
                    }
                    default:
                        break;
                    }
                default:
                    // Write the string to the console
                    WriteConsole(child_in, buf, rd, &wr, NULL);
                    break;
                }
            }
            else
            {
                ir.EventType = KEY_EVENT;
                ir.Event.KeyEvent.bKeyDown = TRUE;
                ir.Event.KeyEvent.wRepeatCount = 1;
                ir.Event.KeyEvent.wVirtualKeyCode = 0;
                ir.Event.KeyEvent.wVirtualScanCode = 0;
                ir.Event.KeyEvent.uChar.AsciiChar = buf[i];
                ir.Event.KeyEvent.dwControlKeyState = 0;
                WriteConsoleInputA(child_in, &ir, 1, &wr);

                ir.Event.KeyEvent.bKeyDown = FALSE;
                WriteConsoleInputA(child_in, &ir, 1, &wr);
            }

            i++;
        }
    }

cleanup:
    dwStatus = GetLastError();

    return 0;
}

void CALLBACK ConsoleEventProc(HWINEVENTHOOK hWinEventHook,
    DWORD event,
    HWND hwnd,
    LONG idObject,
    LONG idChild,
    DWORD dwEventThread,
    DWORD dwmsEventTime)
{
    QueueEvent(event, hwnd, idObject, idChild);
}

DWORD ProcessMessages(void* p)
{
    BOOL ret;
    DWORD dwMode;
    DWORD dwStatus;
    SECURITY_ATTRIBUTES sa;
    MSG msg;

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    while (child_in == (HANDLE)-1)
    {
        child_in = CreateFile(TEXT("CONIN$"), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            &sa, OPEN_EXISTING, 0, NULL);
    }

    if (child_in == (HANDLE)-1)
        goto cleanup;

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    while (child_out == (HANDLE)-1)
    {
        child_out = CreateFile(TEXT("CONOUT$"), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            &sa, OPEN_EXISTING, 0, NULL);
    }

    if (child_out == (HANDLE)-1)
        goto cleanup;

    child_err = child_out;

    SizeWindow(child_out);

    // Get the current buffer information after all the adjustments.
    GetConsoleScreenBufferInfoEx(child_out, &consoleInfo);

    // Loop for the console output events
    while (GetMessage(&msg, NULL, 0, 0))
    {
        if (msg.message == WM_APPEXIT)
        {
            break;
        }
        else
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);            
        }
    }

cleanup:
    dwStatus = GetLastError();

    if (child_in != INVALID_HANDLE_VALUE)
        CloseHandle(child_in);
    if (child_out != INVALID_HANDLE_VALUE)
        CloseHandle(child_out);
    return 0;
}

int wmain(int ac, wchar_t **av) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    wchar_t cmd[MAX_PATH];
    SECURITY_ATTRIBUTES sa;
    BOOL ret;
    DWORD dwThreadId;
    DWORD dwMode;
    DWORD dwStatus;
    HANDLE hEventHook = NULL;

    pipe_in  = GetStdHandle(STD_INPUT_HANDLE);
    pipe_out = GetStdHandle(STD_OUTPUT_HANDLE);
    pipe_err = GetStdHandle(STD_ERROR_HANDLE);

    /* copy pipe handles passed through std io*/
    if ((pipe_in  == INVALID_HANDLE_VALUE)
     || (pipe_out == INVALID_HANDLE_VALUE)
     || (pipe_err == INVALID_HANDLE_VALUE))
        return -1;

    cp = GetConsoleCP();

    isRedirected = !GetConsoleMode(pipe_in, &dwMode);

    ZeroMemory(&inputSi, sizeof(STARTUPINFO));
    GetStartupInfo(&inputSi);

    memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&child_pipe_read, &child_pipe_write, &sa, 128))
        return -1;

    /* A console is attached if a tty is requested */
    if (!AllocConsole())
        istty = TRUE;

    /* create job to hold all child processes */
    {
        /* TODO - this does not work as expected*/
        HANDLE job = CreateJobObject(NULL, NULL);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_info;
        memset(&job_info, 0, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &job_info, sizeof(job_info)))
            return -1;
        CloseHandle(job);
    }

    /* WM_APPEXIT */
    hostThreadId = GetCurrentThreadId();
    hostProcessId = GetCurrentProcessId();

    if (isRedirected)
    {
        InitializeCriticalSection(&criticalSection);

        hEventHook = SetWinEventHook(EVENT_CONSOLE_CARET, EVENT_CONSOLE_LAYOUT, NULL,
            ConsoleEventProc, 0, 0, WINEVENT_OUTOFCONTEXT);
    }

    memset(&si, 0, sizeof(STARTUPINFO));
    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    // Copy our parent buffer sizes
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = 0;

    if (isRedirected)
    {
        /* disable inheritance on child_pipe_write and pipe_in*/
        GOTO_CLEANUP_ON_FALSE(SetHandleInformation(pipe_in, HANDLE_FLAG_INHERIT, 0));
        GOTO_CLEANUP_ON_FALSE(SetHandleInformation(child_pipe_write, HANDLE_FLAG_INHERIT, 0));
    }

    /*TODO - pick this up from system32*/
    cmd[0] = L'\0';
    GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_PATH, L"cmd.exe"));
    ac--;
    av++;
    if (ac)
        GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_PATH, L" /c"));
    while (ac) {
        GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_PATH, L" "));
        GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_PATH, *av));
        ac--;
        av++;
    }

    GOTO_CLEANUP_ON_FALSE(CreateProcess(NULL, cmd, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, 
        NULL, NULL, &si, &pi));
    childProcessId = pi.dwProcessId;

    FreeConsole();
    while (!AttachConsole(pi.dwProcessId))
    {
        Sleep(1000);
    }

    /* close unwanted handles*/
    CloseHandle(child_pipe_read);
    child_pipe_read = INVALID_HANDLE_VALUE;

    /* monitor child exist */
    child = pi.hProcess;
    monitor_thread = CreateThread(NULL, 0, MonitorChild, NULL, 0, NULL);
    if (monitor_thread == INVALID_HANDLE_VALUE)
        goto cleanup;

    /* disable Ctrl+C hander in this process*/
    SetConsoleCtrlHandler(NULL, TRUE);

    io_thread = CreateThread(NULL, 0, ProcessPipes, NULL, 0, NULL);
    if (io_thread == INVALID_HANDLE_VALUE)
        goto cleanup;

    ux_thread = CreateThread(NULL, 0, ProcessEventQueue, NULL, 0, NULL);
    if (ux_thread == INVALID_HANDLE_VALUE)
        goto cleanup;

    ProcessMessages(NULL);

cleanup:
    dwStatus = GetLastError();

    DeleteCriticalSection(&criticalSection);

    if (child != INVALID_HANDLE_VALUE)
        TerminateProcess(child, 0);
    if (monitor_thread != INVALID_HANDLE_VALUE)
        WaitForSingleObject(monitor_thread, INFINITE);
    if (ux_thread != INVALID_HANDLE_VALUE)
        TerminateThread(ux_thread, S_OK);
    if (hEventHook)
        UnhookWinEvent(hEventHook);

    FreeConsole();

    return 0;
}
