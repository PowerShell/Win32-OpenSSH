/*
 * Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
 * Primitive shell-host to support parsing of cmd.exe input and async IO redirection
 *
 * Author: Ray Heyes <ray.hayes@microsoft.com>
 * PTY with ANSI emulation wrapper
 *
 * Copyright (c) 2017 Microsoft Corp.
 * All rights reserved
 *
 * Shell-host is responsible for handling all the interactive and non-interactive cmds.
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
#include <Shlobj.h>
#include <Sddl.h>
#include "misc_internal.h"
#include "inc\utf.h"

#define MAX_CONSOLE_COLUMNS 9999
#define MAX_CONSOLE_ROWS 9999
#define MAX_CMD_LEN 8191 // msdn
#define WM_APPEXIT WM_USER+1
#define MAX_EXPECTED_BUFFER_SIZE 1024
/* 4KB is the largest size for which writes are guaranteed to be atomic */
#define BUFF_SIZE 4096

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING  0x4
#endif

#ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
#define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
#endif

#define VK_A 0x41
#define VK_B 0x42
#define VK_C 0x43
#define VK_D 0x44
#define VK_E 0x45
#define VK_F 0x46
#define VK_G 0x47
#define VK_H 0x48
#define VK_I 0x49
#define VK_J 0x4A
#define VK_K 0x4B
#define VK_L 0x4C
#define VK_M 0x4D
#define VK_N 0x4E
#define VK_O 0x4F
#define VK_P 0x50
#define VK_Q 0x51
#define VK_R 0x52
#define VK_S 0x53
#define VK_T 0x54
#define VK_U 0x55
#define VK_V 0x56
#define VK_W 0x57
#define VK_X 0x58
#define VK_Y 0x59
#define VK_Z 0x5A
#define VK_0 0x30
#define VK_1 0x31
#define VK_2 0x32
#define VK_3 0x33
#define VK_4 0x34
#define VK_5 0x35
#define VK_6 0x36
#define VK_7 0x37
#define VK_8 0x38
#define VK_9 0x39

const int MAX_CTRL_SEQ_LEN = 7;
const int MIN_CTRL_SEQ_LEN = 6;

typedef BOOL(WINAPI *__t_SetCurrentConsoleFontEx)(
	_In_ HANDLE               hConsoleOutput,
	_In_ BOOL                 bMaximumWindow,
	_In_ PCONSOLE_FONT_INFOEX lpConsoleCurrentFontEx
	);
__t_SetCurrentConsoleFontEx __SetCurrentConsoleFontEx;

typedef BOOL(WINAPI *__t_UnhookWinEvent)(
	_In_ HWINEVENTHOOK hWinEventHook
	);
__t_UnhookWinEvent __UnhookWinEvent;

typedef HWINEVENTHOOK(WINAPI *__t_SetWinEventHook)(
	_In_ UINT         eventMin,
	_In_ UINT         eventMax,
	_In_ HMODULE      hmodWinEventProc,
	_In_ WINEVENTPROC lpfnWinEventProc,
	_In_ DWORD        idProcess,
	_In_ DWORD        idThread,
	_In_ UINT         dwflags
	);
__t_SetWinEventHook __SetWinEventHook;

typedef struct consoleEvent {
	DWORD event;
	HWND  hwnd;
	LONG  idObject;
	LONG  idChild;
	void* prior;
	void* next;
} consoleEvent;

struct key_translation {
	wchar_t in[8];
	int vk;
	wchar_t out;
	int in_key_len;
	DWORD ctrlState;
} key_translation;

/* All the substrings should be in the end, otherwise ProcessIncomingKeys() will not work as expected */
struct key_translation keys[] = {
    { L"\r",         VK_RETURN,  L'\r', 0, 0},
    { L"\n",         VK_RETURN,  L'\r', 0, 0 },
    { L"\b",         VK_BACK,    L'\b', 0, 0 },
    { L"\x7f",       VK_BACK,    L'\b', 0 , 0 },
    { L"\t",         VK_TAB,     L'\t' , 0 , 0},
    { L"\x1b[A",     VK_UP,       0 , 0 , 0},
    { L"\x1b[B",     VK_DOWN,     0 , 0 , 0},
    { L"\x1b[C",     VK_RIGHT,    0 , 0 , 0},
    { L"\x1b[D",     VK_LEFT,     0 , 0 , 0},
    { L"\x1b[F",     VK_END,      0 , 0 , 0},    /* KeyPad END */
    { L"\x1b[H",     VK_HOME,     0 , 0 , 0},    /* KeyPad HOME */
    { L"\x1b[Z",     0,           0 , 0 , 0},    /* ignore Shift+TAB */
    { L"\x1b[1~",    VK_HOME,     0 , 0 , 0},
    { L"\x1b[2~",    VK_INSERT,   0 , 0 , 0},
    { L"\x1b[3~",    VK_DELETE,   0 , 0 , 0},
    { L"\x1b[4~",    VK_END,      0 , 0 , 0},
    { L"\x1b[5~",    VK_PRIOR,    0 , 0 , 0},
    { L"\x1b[6~",    VK_NEXT,     0 , 0 , 0},
    { L"\x1b[11~",   VK_F1,       0 , 0 , 0},
    { L"\x1b[12~",   VK_F2,       0 , 0 , 0},
    { L"\x1b[13~",   VK_F3,       0 , 0 , 0},
    { L"\x1b[14~",   VK_F4,       0 , 0 , 0},
    { L"\x1b[15~",   VK_F5,       0 , 0 , 0},
    { L"\x1b[17~",   VK_F6,       0 , 0 , 0},
    { L"\x1b[18~",   VK_F7,       0 , 0 , 0},
    { L"\x1b[19~",   VK_F8,       0 , 0 , 0},
    { L"\x1b[20~",   VK_F9,       0 , 0 , 0},
    { L"\x1b[21~",   VK_F10,      0 , 0 , 0},
    { L"\x1b[23~",   VK_F11,      0 , 0 , 0},
    { L"\x1b[24~",   VK_F12,      0 , 0 , 0},
    { L"\x1bOA",     VK_UP,       0 , 0 , 0},
    { L"\x1bOB",     VK_DOWN,     0 , 0 , 0},
    { L"\x1bOC",     VK_RIGHT,    0 , 0 , 0},
    { L"\x1bOD",     VK_LEFT,     0 , 0 , 0},
    { L"\x1bOF",     VK_END,      0 , 0 , 0},    /* KeyPad END */
    { L"\x1bOH",     VK_HOME,     0 , 0 , 0},    /* KeyPad HOME */
    { L"\x1bOP",     VK_F1,       0 , 0 , 0},
    { L"\x1bOQ",     VK_F2,       0 , 0 , 0},
    { L"\x1bOR",     VK_F3,       0 , 0 , 0},
    { L"\x1bOS",     VK_F4,       0 , 0 , 0},
    { L"\x1",        VK_A,   L'\x1' , 0 , LEFT_CTRL_PRESSED},
    { L"\x2",        VK_B,   L'\x2' , 0 , LEFT_CTRL_PRESSED},
    //{ L"\x3",        VK_C,   L'\x3' , 0 , LEFT_CTRL_PRESSED}, /* Control + C is handled differently */
    { L"\x4",        VK_D,   L'\x4' , 0 , LEFT_CTRL_PRESSED},
    { L"\x5",        VK_E,   L'\x5' , 0 , LEFT_CTRL_PRESSED},
    { L"\x6",        VK_F,   L'\x6' , 0 , LEFT_CTRL_PRESSED},
    { L"\x7",        VK_G,   L'\x7' , 0 , LEFT_CTRL_PRESSED},
    { L"\x8",        VK_H,   L'\x8' , 0 , LEFT_CTRL_PRESSED},
    { L"\x9",        VK_I,   L'\x9' , 0 , LEFT_CTRL_PRESSED},
    { L"\xA",        VK_J,   L'\xA' , 0 , LEFT_CTRL_PRESSED},
    { L"\xB",        VK_K,   L'\xB' , 0 , LEFT_CTRL_PRESSED},
    { L"\xC",        VK_L,   L'\xC' , 0 , LEFT_CTRL_PRESSED},
    { L"\xD",        VK_M,   L'\xD' , 0 , LEFT_CTRL_PRESSED},
    { L"\xE",        VK_N,   L'\xE' , 0 , LEFT_CTRL_PRESSED},
    { L"\xF",        VK_O,   L'\xF' , 0 , LEFT_CTRL_PRESSED},
    { L"\x10",       VK_P,   L'\x10' , 0 , LEFT_CTRL_PRESSED},
    { L"\x11",       VK_Q,   L'\x11' , 0 , LEFT_CTRL_PRESSED},
    { L"\x12",       VK_R,   L'\x12' , 0 , LEFT_CTRL_PRESSED},
    { L"\x13",       VK_S,   L'\x13' , 0 , LEFT_CTRL_PRESSED},
    { L"\x14",       VK_T,   L'\x14' , 0 , LEFT_CTRL_PRESSED},
    { L"\x15",       VK_U,   L'\x15' , 0 , LEFT_CTRL_PRESSED},
    { L"\x16",       VK_V,   L'\x16' , 0 , LEFT_CTRL_PRESSED},
    { L"\x17",       VK_W,   L'\x17' , 0 , LEFT_CTRL_PRESSED},
    { L"\x18",       VK_X,   L'\x18' , 0 , LEFT_CTRL_PRESSED},
    { L"\x19",       VK_Y,   L'\x19' , 0 , LEFT_CTRL_PRESSED},
    { L"\x1A",       VK_Z,   L'\x1A' , 0 , LEFT_CTRL_PRESSED},
    { L"\033a",      VK_A,   L'a', 0, LEFT_ALT_PRESSED},
    { L"\033b",      VK_B,   L'b', 0, LEFT_ALT_PRESSED},
    { L"\033c",      VK_C,   L'c', 0, LEFT_ALT_PRESSED},
    { L"\033d",      VK_D,   L'd', 0, LEFT_ALT_PRESSED},
    { L"\033e",      VK_E,   L'e', 0, LEFT_ALT_PRESSED},
    { L"\033f",      VK_F,   L'f', 0, LEFT_ALT_PRESSED},
    { L"\033g",      VK_G,   L'g', 0, LEFT_ALT_PRESSED},
    { L"\033h",      VK_H,   L'h', 0, LEFT_ALT_PRESSED},
    { L"\033i",      VK_I,   L'i', 0, LEFT_ALT_PRESSED},
    { L"\033j",      VK_J,   L'j', 0, LEFT_ALT_PRESSED},
    { L"\033k",      VK_K,   L'k', 0, LEFT_ALT_PRESSED},
    { L"\033l",      VK_L,   L'l', 0, LEFT_ALT_PRESSED},
    { L"\033m",      VK_M,   L'm', 0, LEFT_ALT_PRESSED},
    { L"\033n",      VK_N,   L'n', 0, LEFT_ALT_PRESSED},
    { L"\033o",      VK_O,   L'o', 0, LEFT_ALT_PRESSED},
    { L"\033p",      VK_P,   L'p', 0, LEFT_ALT_PRESSED},
    { L"\033q",      VK_Q,   L'q', 0, LEFT_ALT_PRESSED},
    { L"\033r",      VK_R,   L'r', 0, LEFT_ALT_PRESSED},
    { L"\033s",      VK_S,   L's', 0, LEFT_ALT_PRESSED},
    { L"\033t",      VK_T,   L't', 0, LEFT_ALT_PRESSED},
    { L"\033u",      VK_U,   L'u', 0, LEFT_ALT_PRESSED},
    { L"\033v",      VK_V,   L'v', 0, LEFT_ALT_PRESSED},
    { L"\033w",      VK_W,   L'w', 0, LEFT_ALT_PRESSED},
    { L"\033x",      VK_X,   L'x', 0, LEFT_ALT_PRESSED},
    { L"\033y",      VK_Y,   L'y', 0, LEFT_ALT_PRESSED},
    { L"\033z",      VK_Z,   L'z', 0, LEFT_ALT_PRESSED},
    { L"\0330",      VK_0,   L'0', 0, LEFT_ALT_PRESSED},
    { L"\0331",      VK_1,   L'1', 0, LEFT_ALT_PRESSED},
    { L"\0332",      VK_2,   L'2', 0, LEFT_ALT_PRESSED},
    { L"\0333",      VK_3,   L'3', 0, LEFT_ALT_PRESSED},
    { L"\0334",      VK_4,   L'4', 0, LEFT_ALT_PRESSED},
    { L"\0335",      VK_5,   L'5', 0, LEFT_ALT_PRESSED},
    { L"\0336",      VK_6,   L'6', 0, LEFT_ALT_PRESSED},
    { L"\0337",      VK_7,   L'7', 0, LEFT_ALT_PRESSED},
    { L"\0338",      VK_8,   L'8', 0, LEFT_ALT_PRESSED},
    { L"\0339",      VK_9,   L'9', 0, LEFT_ALT_PRESSED},
    { L"\033!",      VK_1,   L'!', 0, LEFT_ALT_PRESSED | SHIFT_PRESSED },
    { L"\033@",      VK_2,   L'@', 0, LEFT_ALT_PRESSED | SHIFT_PRESSED },
    { L"\033#",      VK_3,   L'#', 0, LEFT_ALT_PRESSED | SHIFT_PRESSED },
    { L"\033$",      VK_4,   L'$', 0, LEFT_ALT_PRESSED | SHIFT_PRESSED },
    { L"\033%",      VK_5,   L'%', 0, LEFT_ALT_PRESSED | SHIFT_PRESSED },
    { L"\033^",      VK_6,   L'^', 0, LEFT_ALT_PRESSED | SHIFT_PRESSED },
    { L"\033&",      VK_7,   L'&', 0, LEFT_ALT_PRESSED | SHIFT_PRESSED },
    { L"\033*",      VK_8,   L'*', 0, LEFT_ALT_PRESSED | SHIFT_PRESSED },
    { L"\033(",      VK_9,   L'(', 0, LEFT_ALT_PRESSED | SHIFT_PRESSED },
    { L"\033)",      VK_0,   L')', 0, LEFT_ALT_PRESSED | SHIFT_PRESSED }
};

static SHORT lastX = 0;
static SHORT lastY = 0;
static wchar_t system32_path[PATH_MAX + 1] = { 0, };
static wchar_t cmd_exe_path[PATH_MAX + 1] = { 0, };
static wchar_t default_shell_path[PATH_MAX + 3] = { 0, }; /* 2 - quotes, 1 - Null terminator */
static wchar_t default_shell_cmd_option[10] = { 0, }; /* for cmd.exe/powershell it is "/c", for bash.exe it is "-c" */
static BOOL is_default_shell_configured = FALSE;

SHORT currentLine = 0;
consoleEvent* head = NULL;
consoleEvent* tail = NULL;

BOOL bRet = FALSE;
BOOL bNoScrollRegion = FALSE;
BOOL bStartup = TRUE;
BOOL bHookEvents = FALSE;
BOOL bFullScreen = FALSE;
BOOL bUseAnsiEmulation = TRUE;

HANDLE child_out = INVALID_HANDLE_VALUE;
HANDLE child_in = INVALID_HANDLE_VALUE;
HANDLE child_err = INVALID_HANDLE_VALUE;
HANDLE pipe_in = INVALID_HANDLE_VALUE;
HANDLE pipe_out = INVALID_HANDLE_VALUE;
HANDLE pipe_err = INVALID_HANDLE_VALUE;
HANDLE child = INVALID_HANDLE_VALUE;
HANDLE job = NULL;
HANDLE hConsoleBuffer = INVALID_HANDLE_VALUE;
HANDLE monitor_thread = INVALID_HANDLE_VALUE;
HANDLE io_thread = INVALID_HANDLE_VALUE;
HANDLE ux_thread = INVALID_HANDLE_VALUE;

DWORD child_exit_code = 0;
DWORD hostProcessId = 0;
DWORD hostThreadId = 0;
DWORD childProcessId = 0;
DWORD dwStatus = 0;
DWORD in_cmd_len = 0;
DWORD lastLineLength = 0;

UINT cp = 0;
UINT ViewPortY = 0;
UINT lastViewPortY = 0;
UINT savedViewPortY = 0;
UINT savedLastViewPortY = 0;

char in_cmd[MAX_CMD_LEN];

CRITICAL_SECTION criticalSection;

CONSOLE_SCREEN_BUFFER_INFOEX  consoleInfo;
CONSOLE_SCREEN_BUFFER_INFOEX  nextConsoleInfo;
STARTUPINFO inputSi;

#define GOTO_CLEANUP_ON_FALSE(exp) do {	\
	ret = (exp);			\
	if (ret == FALSE)		\
		goto cleanup;		\
} while(0)

#define GOTO_CLEANUP_ON_ERR(exp) do {	\
	if ((exp) != 0)			\
		goto cleanup;		\
} while(0)

int
ConSRWidth()
{
	CONSOLE_SCREEN_BUFFER_INFOEX  consoleBufferInfo;
	ZeroMemory(&consoleBufferInfo, sizeof(consoleBufferInfo));
	consoleBufferInfo.cbSize = sizeof(consoleBufferInfo);

	GetConsoleScreenBufferInfoEx(child_out, &consoleBufferInfo);
	return consoleBufferInfo.srWindow.Right;
}

void
my_invalid_parameter_handler(const wchar_t* expression, const wchar_t* function,
	 const wchar_t* file, unsigned int line, uintptr_t pReserved)
{
	wprintf_s(L"Invalid parameter in function: %s. File: %s Line: %d\n", function, file, line);
	wprintf_s(L"Expression: %s\n", expression);
}

struct key_translation *
FindKeyTransByMask(wchar_t prefix, const wchar_t * value, int vlen, wchar_t suffix)
{
	struct key_translation *k = NULL;
	for (int i = 0; i < ARRAYSIZE(keys); i++) {
		k = &keys[i];
		if (k->in_key_len < vlen + 2) continue;
		if (k->in[0] != L'\033') continue;
		if (k->in[1] != prefix) continue;
		if (k->in[vlen + 2] != suffix) continue;

		if (vlen <= 1 && value[0] == k->in[2])
			return k;
		if (vlen > 1 && wcsncmp(&k->in[2], value, vlen) == 0)
			return k;
	}

	return NULL;
}

int
GetVirtualKeyByMask(wchar_t prefix, const wchar_t * value, int vlen, wchar_t suffix)
{
	struct key_translation * pk = FindKeyTransByMask(prefix, value, vlen, suffix);
	return pk ? pk->vk : 0;
}

/*
 * This function will handle the console keystrokes.
 */
void
SendKeyStrokeEx(HANDLE hInput, int vKey, wchar_t character, DWORD ctrlState, BOOL keyDown)
{
	DWORD wr = 0;
	INPUT_RECORD ir;

	ir.EventType = KEY_EVENT;
	ir.Event.KeyEvent.bKeyDown = keyDown;
	ir.Event.KeyEvent.wRepeatCount = 1;
	ir.Event.KeyEvent.wVirtualKeyCode = vKey;
	ir.Event.KeyEvent.wVirtualScanCode = MapVirtualKeyA(vKey, MAPVK_VK_TO_VSC);
	ir.Event.KeyEvent.dwControlKeyState = ctrlState;
	ir.Event.KeyEvent.uChar.UnicodeChar = character;

	WriteConsoleInputW(hInput, &ir, 1, &wr);
}

void
SendKeyStroke(HANDLE hInput, int keyStroke, wchar_t character, DWORD ctrlState)
{
	SendKeyStrokeEx(hInput, keyStroke, character, ctrlState, TRUE);
	SendKeyStrokeEx(hInput, keyStroke, character, ctrlState, FALSE);
}

void
initialize_keylen()
{
	for(int i = 0; i < ARRAYSIZE(keys); i++)
		keys[i].in_key_len = (int) wcsnlen(keys[i].in, _countof(keys[i].in));
}

int
ProcessModifierKeySequence(wchar_t *buf, int buf_len)
{
	if(buf_len < MIN_CTRL_SEQ_LEN)
		return 0;

	int vkey = 0;	
	int modifier_key = _wtoi((wchar_t *)&buf[buf_len - 2]);

	if ((modifier_key < 2) && (modifier_key > 7))
		return 0;

	/* Decode special keys when pressed ALT/CTRL/SHIFT key */
	if (buf[0] == L'\033' && buf[1] == L'[' && buf[buf_len - 3] == L';') {
		if (buf[buf_len - 1] == L'~') {
			/* VK_DELETE, VK_PGDN, VK_PGUP */
			if (!vkey && buf_len == 6)
				vkey = GetVirtualKeyByMask(L'[', &buf[2], 1, L'~');

			/* VK_F1 ... VK_F12 */
			if (!vkey && buf_len == 7)
				vkey = GetVirtualKeyByMask(L'[', &buf[2], 2, L'~');
		} else {
			/* VK_LEFT, VK_RIGHT, VK_UP, VK_DOWN */
			if (!vkey && buf_len == 6 && buf[2] == L'1')
				vkey = GetVirtualKeyByMask(L'[', &buf[5], 1, 0);

			/* VK_F1 ... VK_F4 */
			if (!vkey && buf_len == 6 && buf[2] == L'1' && isalpha(buf[5]))
				vkey = GetVirtualKeyByMask(L'O', &buf[5], 1, 0);
		}
		if (vkey) {
			switch (modifier_key)
			{
				case 2:
					SendKeyStroke(child_in, vkey, 0, SHIFT_PRESSED);
					break;
				case 3:
					SendKeyStroke(child_in, vkey, 0, LEFT_ALT_PRESSED);
					break;
				case 4:
					SendKeyStroke(child_in, vkey, 0, SHIFT_PRESSED | LEFT_ALT_PRESSED);
					break;
				case 5:
					SendKeyStroke(child_in, vkey, 0, LEFT_CTRL_PRESSED);
					break;
				case 6:
					SendKeyStroke(child_in, vkey, 0, SHIFT_PRESSED | LEFT_CTRL_PRESSED);
					break;
				case 7:
					SendKeyStroke(child_in, vkey, 0, LEFT_CTRL_PRESSED | LEFT_ALT_PRESSED);
					break;				
			}
		}
			
	}

	return vkey;
}
int
CheckKeyTranslations(wchar_t *buf, int buf_len, int *index)
{
	for (int j = 0; j < ARRAYSIZE(keys); j++) {
		if ((buf_len >= keys[j].in_key_len) && (wcsncmp(buf, keys[j].in, keys[j].in_key_len) == 0)) {
			*index = j;
			return 1;
		}
	}

	return 0;
}

void 
ProcessIncomingKeys(char * ansikey)
{
	int buf_len = 0;
	const wchar_t *ESC_SEQ = L"\x1b";
	wchar_t *buf = utf8_to_utf16(ansikey);

	if (!buf) {
		printf_s("\nFailed to deserialize the client data, error:%d\n", GetLastError());
		exit(255);
	}

	loop:
	while (buf && ((buf_len=(int)wcslen(buf)) > 0)) {
		int j = 0;
		if (CheckKeyTranslations(buf, buf_len, &j)) {
			SendKeyStroke(child_in, keys[j].vk, keys[j].out, keys[j].ctrlState);				
			buf += keys[j].in_key_len;
			goto loop;
		}

		/* Decode special keys when pressed CTRL key. CTRL sequences can be of size 6 or 7. */
		if ((buf_len >= MAX_CTRL_SEQ_LEN) && ProcessModifierKeySequence(buf, MAX_CTRL_SEQ_LEN)) {
			buf += MAX_CTRL_SEQ_LEN;
			goto loop;
		}

		if ((buf_len >= (MAX_CTRL_SEQ_LEN - 1)) && ProcessModifierKeySequence(buf, MAX_CTRL_SEQ_LEN - 1)) {
			buf += (MAX_CTRL_SEQ_LEN - 1);
			goto loop;
		}

		if(wcsncmp(buf, ESC_SEQ, wcslen(ESC_SEQ)) == 0) {
			wchar_t* p = buf + wcslen(ESC_SEQ);
			/* Alt sequence */
			if (CheckKeyTranslations(p, buf_len - (int)wcslen(ESC_SEQ), &j) && !(keys[j].ctrlState & LEFT_ALT_PRESSED)) {
				SendKeyStroke(child_in, keys[j].vk, keys[j].out, keys[j].ctrlState| LEFT_ALT_PRESSED);
				buf += wcslen(ESC_SEQ) +keys[j].in_key_len;
				goto loop;
			}

			SendKeyStroke(child_in, VK_ESCAPE, L'\x1b', 0);
			buf += wcslen(ESC_SEQ);
			goto loop;
		}

		if (*buf == L'\x3') /*Ctrl+C - Raise Ctrl+C*/
			GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
		else 
			SendKeyStroke(child_in, 0, *buf, 0);

		buf++;
	}		
}

/*
 * VT output routines
 */
void 
SendLF(HANDLE hInput)
{
	DWORD wr = 0;

	if (bUseAnsiEmulation)
		WriteFile(hInput, "\n", 1, &wr, NULL);
}

void 
SendClearScreen(HANDLE hInput)
{
	DWORD wr = 0;

	if (bUseAnsiEmulation)
		WriteFile(hInput, "\033[2J", 4, &wr, NULL);
}

void 
SendClearScreenFromCursor(HANDLE hInput)
{
	DWORD wr = 0;

	if (bUseAnsiEmulation)
		WriteFile(hInput, "\033[1J", 4, &wr, NULL);
}

void 
SendHideCursor(HANDLE hInput)
{
	DWORD wr = 0;

	if (bUseAnsiEmulation)
		WriteFile(hInput, "\033[?25l", 6, &wr, NULL);
}

void 
SendShowCursor(HANDLE hInput)
{
	DWORD wr = 0;

	if (bUseAnsiEmulation)
		WriteFile(hInput, "\033[?25h", 6, &wr, NULL);
}

void 
SendCursorPositionRequest(HANDLE hInput)
{
	DWORD wr = 0;

	if (bUseAnsiEmulation)
		WriteFile(hInput, "\033[6n", 4, &wr, NULL);
}

void 
SendSetCursor(HANDLE hInput, int X, int Y)
{
	DWORD wr = 0;
	int out = 0;
	char formatted_output[255];

	out = _snprintf_s(formatted_output, sizeof(formatted_output), _TRUNCATE, "\033[%d;%dH", Y, X);
	if (out > 0 && bUseAnsiEmulation)
		WriteFile(hInput, formatted_output, out, &wr, NULL);
}

void 
SendVerticalScroll(HANDLE hInput, int lines)
{
	DWORD wr = 0;
	int out = 0;
	char formatted_output[255];

	LONG vn = abs(lines);
	/* Not supporting the [S at the moment. */
	if (lines > 0) {
		out = _snprintf_s(formatted_output, sizeof(formatted_output), _TRUNCATE, "\033[%dT", vn);

		if (out > 0 && bUseAnsiEmulation)
			WriteFile(hInput, formatted_output, out, &wr, NULL);
	}	
}

void 
SendHorizontalScroll(HANDLE hInput, int cells)
{
	DWORD wr = 0;
	int out = 0;
	char formatted_output[255];

	out = _snprintf_s(formatted_output, sizeof(formatted_output), _TRUNCATE, "\033[%dG", cells);

	if (out > 0 && bUseAnsiEmulation)
		WriteFile(hInput, formatted_output, out, &wr, NULL);
}

void 
SendCharacter(HANDLE hInput, WORD attributes, wchar_t character)
{
	DWORD wr = 0;
	DWORD out = 0;
	DWORD current = 0;
	char formatted_output[2048];
	static WORD pattributes = 0;
	USHORT Color = 0;
	ULONG Status = 0;
	PSTR Next;
	size_t SizeLeft;

	if (!character)
		return;

	Next = formatted_output;
	SizeLeft = sizeof formatted_output;

	/* Handle the foreground intensity */
	if ((attributes & FOREGROUND_INTENSITY) != 0)
		Color = 1;
	else
		Color = 0;

	StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, "\033[%u", Color);

	/* Handle the background intensity */
	if ((attributes & BACKGROUND_INTENSITY) != 0)
		Color = 1;
	else
		Color = 39;

	StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, ";%u", Color);

	/* Handle the underline */
	if ((attributes & COMMON_LVB_UNDERSCORE) != 0)
		Color = 4;
	else
		Color = 24;

	StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, ";%u", Color);

	/* Handle reverse video */
	if ((attributes & COMMON_LVB_REVERSE_VIDEO) != 0)
		Color = 7;
	else
		Color = 27;

	StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, ";%u", Color);

	/* Add background and foreground colors to buffer. */
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
	
	StringCbPrintfExA(Next, SizeLeft, &Next, &SizeLeft, 0, "%c", 'm');

	if (bUseAnsiEmulation && attributes != pattributes)
		WriteFile(hInput, formatted_output, (DWORD)(Next - formatted_output), &wr, NULL);

	/* East asian languages have 2 bytes for each character, only use the first */
	if (!(attributes & COMMON_LVB_TRAILING_BYTE)) {
		char str[10];
		int nSize = WideCharToMultiByte(CP_UTF8,
			0,
			&character,
			1,
			(LPSTR)str,
			sizeof(str),
			NULL,
			NULL);

		if (nSize > 0)
			WriteFile(hInput, str, nSize, &wr, NULL);
	}

	pattributes = attributes;
}

void 
SendBuffer(HANDLE hInput, CHAR_INFO *buffer, DWORD bufferSize)
{
	if (bufferSize <= 0)
		return;

	for (DWORD i = 0; i < bufferSize; i++)
		SendCharacter(hInput, buffer[i].Attributes, buffer[i].Char.UnicodeChar);
}

void 
CalculateAndSetCursor(HANDLE hInput, short x, short y, BOOL scroll)
{
	if (scroll && y > currentLine)
		for (short n = currentLine; n < y; n++)
			SendLF(hInput);

	SendSetCursor(hInput, x + 1, y + 1);
	currentLine = y;
}

void 
SizeWindow(HANDLE hInput)
{
	SMALL_RECT srWindowRect;
	COORD coordScreen;
	BOOL bSuccess = FALSE;
	/* The input window does not scroll currently to ease calculations on the paint/draw */
	bNoScrollRegion = TRUE;

	/* Set the default font to Consolas */
	CONSOLE_FONT_INFOEX matchingFont;
	matchingFont.cbSize = sizeof(matchingFont);
	matchingFont.nFont = 0;
	matchingFont.dwFontSize.X = 0;
	matchingFont.dwFontSize.Y = 16;
	matchingFont.FontFamily = FF_DONTCARE;
	matchingFont.FontWeight = FW_NORMAL;	
	wcscpy_s(matchingFont.FaceName, LF_FACESIZE, L"Consolas");

	bSuccess = __SetCurrentConsoleFontEx(hInput, FALSE, &matchingFont);

	/* This information is the live screen  */
	ZeroMemory(&consoleInfo, sizeof(consoleInfo));
	consoleInfo.cbSize = sizeof(consoleInfo);

	bSuccess = GetConsoleScreenBufferInfoEx(hInput, &consoleInfo);

	/* Get the largest size we can size the console window to */
	coordScreen = GetLargestConsoleWindowSize(hInput);

	/* Define the new console window size and scroll position */
	if (inputSi.dwXCountChars == 0 || inputSi.dwYCountChars == 0) {
		inputSi.dwXCountChars = 80;
		inputSi.dwYCountChars = 25;
	}

	srWindowRect.Right = min((SHORT)inputSi.dwXCountChars, coordScreen.X) - 1;
	srWindowRect.Bottom = min((SHORT)inputSi.dwYCountChars, coordScreen.Y) - 1;
	srWindowRect.Left = srWindowRect.Top = (SHORT)0;

	/* Define the new console buffer history to be the maximum possible */
	coordScreen.X = srWindowRect.Right + 1;   /* buffer width must be equ window width */
	coordScreen.Y = 9999;

	if (SetConsoleWindowInfo(hInput, TRUE, &srWindowRect))
		bSuccess = SetConsoleScreenBufferSize(hInput, coordScreen);
	else {
		if (SetConsoleScreenBufferSize(hInput, coordScreen))
			bSuccess = SetConsoleWindowInfo(hInput, TRUE, &srWindowRect);
	}

	bSuccess = GetConsoleScreenBufferInfoEx(hInput, &consoleInfo);
}

DWORD WINAPI 
MonitorChild(_In_ LPVOID lpParameter)
{
	WaitForSingleObject(child, INFINITE);
	GetExitCodeProcess(child, &child_exit_code);
	PostThreadMessage(hostThreadId, WM_APPEXIT, 0, 0);
	return 0;
}

DWORD 
ProcessEvent(void *p)
{
	wchar_t chUpdate;
	WORD  wAttributes;
	WORD  wX;
	WORD  wY;
	DWORD dwProcessId;
	DWORD wr = 0;
	DWORD event;
	HWND hwnd;
	LONG idObject;
	LONG idChild;
	CHAR_INFO pBuffer[MAX_EXPECTED_BUFFER_SIZE] = {0,};
	DWORD bufferSize;
	SMALL_RECT readRect;
	COORD coordBufSize;
	COORD coordBufCoord;

	if (!p)
		return ERROR_INVALID_PARAMETER;

	consoleEvent* current = (consoleEvent *)p;

	if (!current)
		return ERROR_INVALID_PARAMETER;

	event = current->event;
	hwnd = current->hwnd;
	idObject = current->idObject;
	idChild = current->idChild;

	if (event < EVENT_CONSOLE_CARET || event > EVENT_CONSOLE_LAYOUT)
		return ERROR_INVALID_PARAMETER;

	if (child_out == INVALID_HANDLE_VALUE || child_out == NULL)
		return ERROR_INVALID_PARAMETER;

	GetWindowThreadProcessId(hwnd, &dwProcessId);

	if (childProcessId != dwProcessId)
		return ERROR_SUCCESS;

	ZeroMemory(&consoleInfo, sizeof(consoleInfo));
	consoleInfo.cbSize = sizeof(consoleInfo);

	GetConsoleScreenBufferInfoEx(child_out, &consoleInfo);

	UINT viewPortHeight = consoleInfo.srWindow.Bottom - consoleInfo.srWindow.Top + 1;
	UINT viewPortWidth = consoleInfo.srWindow.Right - consoleInfo.srWindow.Left + 1;

	switch (event) {
	case EVENT_CONSOLE_CARET:
	{
		COORD co;
		co.X = LOWORD(idChild);
		co.Y = HIWORD(idChild);
		
		lastX = co.X;
		lastY = co.Y;

		if (lastX == 0 && lastY > currentLine)
			CalculateAndSetCursor(pipe_out, lastX, lastY, TRUE);
		else
			SendSetCursor(pipe_out, lastX + 1, lastY + 1);

		break;
	}
	case EVENT_CONSOLE_UPDATE_REGION:
	{
		readRect.Top = HIWORD(idObject);
		readRect.Left = LOWORD(idObject);
		readRect.Bottom = HIWORD(idChild);
		readRect.Right = LOWORD(idChild);

		readRect.Right = max(readRect.Right, ConSRWidth());

		/* Detect a "cls" (Windows) */
		if (!bStartup &&
		    (readRect.Top == consoleInfo.srWindow.Top || readRect.Top == nextConsoleInfo.srWindow.Top)) {
			BOOL isClearCommand = FALSE;
			isClearCommand = (consoleInfo.dwSize.X == readRect.Right + 1) && (consoleInfo.dwSize.Y == readRect.Bottom + 1);

			/* If cls then inform app to clear its buffers and return */
			if (isClearCommand) {
				SendClearScreen(pipe_out);
				ViewPortY = 0;
				lastViewPortY = 0;

				return ERROR_SUCCESS;
			}
		}

		/* Figure out the buffer size */		
		coordBufSize.Y = readRect.Bottom - readRect.Top + 1;
		coordBufSize.X = readRect.Right - readRect.Left + 1;

		/*
		 * Security check:  the maximum screen buffer size is 9999 columns x 9999 lines so check
		 * the computed buffer size for overflow.  since the X and Y in the COORD structure
		 * are shorts they could be negative.
		 */
		if (coordBufSize.X < 0 || coordBufSize.X > MAX_CONSOLE_COLUMNS ||
		    coordBufSize.Y < 0 || coordBufSize.Y > MAX_CONSOLE_ROWS)
			return ERROR_INVALID_PARAMETER;

		/* Compute buffer size */
		bufferSize = coordBufSize.X * coordBufSize.Y;
		if (bufferSize > MAX_EXPECTED_BUFFER_SIZE) {
			if (!bStartup) {
				SendClearScreen(pipe_out);
				ViewPortY = 0;
				lastViewPortY = 0;
			}
			return ERROR_SUCCESS;
		}
		
		/* The top left destination cell of the temporary buffer is row 0, col 0 */		
		coordBufCoord.X = 0;
		coordBufCoord.Y = 0;

		/* Copy the block from the screen buffer to the temp. buffer */
		if (!ReadConsoleOutput(child_out, pBuffer, coordBufSize, coordBufCoord, &readRect))
			return GetLastError();

		/* Set cursor location based on the reported location from the message */
		CalculateAndSetCursor(pipe_out, readRect.Left, readRect.Top, TRUE);

		/* Send the entire block */
		SendBuffer(pipe_out, pBuffer, bufferSize);
		lastViewPortY = ViewPortY;
		lastLineLength = readRect.Left;		
		
		break;
	}
	case EVENT_CONSOLE_UPDATE_SIMPLE:
	{
		chUpdate = LOWORD(idChild);
		wAttributes = HIWORD(idChild);
		wX = LOWORD(idObject);
		wY = HIWORD(idObject);
		
		readRect.Top = wY;
		readRect.Bottom = wY;
		readRect.Left = wX;
		readRect.Right = ConSRWidth();
		
		/* Set cursor location based on the reported location from the message */
		CalculateAndSetCursor(pipe_out, wX, wY, TRUE);
				
		coordBufSize.Y = readRect.Bottom - readRect.Top + 1;
		coordBufSize.X = readRect.Right - readRect.Left + 1;
		bufferSize = coordBufSize.X * coordBufSize.Y;

		/* The top left destination cell of the temporary buffer is row 0, col 0 */
		coordBufCoord.X = 0;
		coordBufCoord.Y = 0;

		/* Copy the block from the screen buffer to the temp. buffer */
		if (!ReadConsoleOutput(child_out, pBuffer, coordBufSize, coordBufCoord, &readRect))
			return GetLastError();

		SendBuffer(pipe_out, pBuffer, bufferSize);		

		break;
	}
	case EVENT_CONSOLE_UPDATE_SCROLL:
	{
		DWORD out = 0;
		LONG vd = idChild;
		LONG hd = idObject;
		LONG vn = abs(vd);

		if (vd > 0) {
			if (ViewPortY > 0)
				ViewPortY -= vn;
		} else {
			ViewPortY += vn;
		}

		break;
	}
	case EVENT_CONSOLE_LAYOUT:
	{
		if (consoleInfo.dwMaximumWindowSize.X == consoleInfo.dwSize.X &&
		    consoleInfo.dwMaximumWindowSize.Y == consoleInfo.dwSize.Y &&
		    (consoleInfo.dwCursorPosition.X == 0 && consoleInfo.dwCursorPosition.Y == 0)) {
			/* Screen has switched to fullscreen mode */
			SendClearScreen(pipe_out);
			savedViewPortY = ViewPortY;
			savedLastViewPortY = lastViewPortY;
			ViewPortY = 0;
			lastViewPortY = 0;;
			bFullScreen = TRUE;
		} else {
			/* Leave full screen mode if applicable */
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

	return ERROR_SUCCESS;
}

DWORD WINAPI 
ProcessEventQueue(LPVOID p)
{
	while (1) {
		while (head) {
			EnterCriticalSection(&criticalSection);
			consoleEvent* current = head;
			if (current) {
				if (current->next) {
					head = current->next;
					head->prior = NULL;
				} else {
					head = NULL;
					tail = NULL;
				}
			}

			LeaveCriticalSection(&criticalSection);
			if (current) {
				ProcessEvent(current);
				free(current);
			}
		}

		if (child_in != INVALID_HANDLE_VALUE && child_in != NULL &&
		    child_out != INVALID_HANDLE_VALUE && child_out != NULL) {
			ZeroMemory(&consoleInfo, sizeof(consoleInfo));
			consoleInfo.cbSize = sizeof(consoleInfo);

			/* This information is the live buffer that's currently in use */
			GetConsoleScreenBufferInfoEx(child_out, &consoleInfo);

			/* Set the cursor to the last known good location according to the live buffer */
			if (lastX != consoleInfo.dwCursorPosition.X ||
			    lastY != consoleInfo.dwCursorPosition.Y)
				SendSetCursor(pipe_out, consoleInfo.dwCursorPosition.X + 1, consoleInfo.dwCursorPosition.Y + 1);

			lastX = consoleInfo.dwCursorPosition.X;
			lastY = consoleInfo.dwCursorPosition.Y;
		}
		Sleep(100);
	}
	return 0;
}

void 
QueueEvent(DWORD event, HWND hwnd, LONG idObject, LONG idChild)
{
	consoleEvent* current = NULL;

	EnterCriticalSection(&criticalSection);
	current = malloc(sizeof(consoleEvent));
	if (current) {
		if (!head) {
			current->event = event;
			current->hwnd = hwnd;
			current->idChild = idChild;
			current->idObject = idObject;

			/* No links head == tail */
			current->next = NULL;
			current->prior = NULL;

			head = current;
			tail = current;
		} else {
			current->event = event;
			current->hwnd = hwnd;
			current->idChild = idChild;
			current->idObject = idObject;

			/* Current tail points to new tail */
			tail->next = current;

			/* New tail points to old tail */
			current->prior = tail;
			current->next = NULL;

			/* Update the tail pointer to the new last event */
			tail = current;
		}
	}
	LeaveCriticalSection(&criticalSection);
}

void FreeQueueEvent()
{
	EnterCriticalSection(&criticalSection);
	while (head) {
		consoleEvent* current = head;
		head = current->next;
		free(current);
	}
	head = NULL;
	tail = NULL;
	LeaveCriticalSection(&criticalSection);
}

DWORD WINAPI 
ProcessPipes(LPVOID p)
{
	BOOL ret;
	DWORD dwStatus;
	char buf[128];

	/* process data from pipe_in and route appropriately */
	while (1) {
		ZeroMemory(buf, sizeof(buf));
		int rd = 0;

		GOTO_CLEANUP_ON_FALSE(ReadFile(pipe_in, buf, sizeof(buf) - 1, &rd, NULL)); /* read bufsize-1 */
		bStartup = FALSE;
		if(rd > 0)
			ProcessIncomingKeys(buf);
	}

cleanup:
	/* pipe_in has ended */
	PostThreadMessage(hostThreadId, WM_APPEXIT, 0, 0);
	dwStatus = GetLastError();
	return 0;
}

void CALLBACK 
ConsoleEventProc(HWINEVENTHOOK hWinEventHook,
    DWORD event,
    HWND hwnd,
    LONG idObject,
    LONG idChild,
    DWORD dwEventThread,
    DWORD dwmsEventTime)
{
	QueueEvent(event, hwnd, idObject, idChild);
}

DWORD 
ProcessMessages(void* p)
{
	DWORD dwStatus;
	SECURITY_ATTRIBUTES sa;
	MSG msg;

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	while (child_in == (HANDLE)-1) {
		child_in = CreateFile(TEXT("CONIN$"), GENERIC_READ | GENERIC_WRITE,
					FILE_SHARE_WRITE | FILE_SHARE_READ,
					&sa, OPEN_EXISTING, 0, NULL);
	}
	if (child_in == (HANDLE)-1)
		goto cleanup;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;
	while (child_out == (HANDLE)-1) {
		child_out = CreateFile(TEXT("CONOUT$"), GENERIC_READ | GENERIC_WRITE,
					FILE_SHARE_WRITE | FILE_SHARE_READ,
					&sa, OPEN_EXISTING, 0, NULL);
	}
	if (child_out == (HANDLE)-1)
		goto cleanup;
	child_err = child_out;
	SizeWindow(child_out);
	/* Get the current buffer information after all the adjustments */
	GetConsoleScreenBufferInfoEx(child_out, &consoleInfo);
	/* Loop for the console output events */
	while (GetMessage(&msg, NULL, 0, 0)) {
		if (msg.message == WM_APPEXIT)
			break;
		else {
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

wchar_t *
get_default_shell_path()
{
	HKEY reg_key = 0;
	int tmp_len = PATH_MAX;
	errno_t r = 0;
	REGSAM mask = STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_WOW64_64KEY;
	wchar_t *tmp = malloc(PATH_MAX + 1);

	if (!tmp) {
		printf_s("%s: out of memory", __func__);
		exit(255);
	}

	memset(tmp, 0, PATH_MAX + 1);
	memset(default_shell_path, 0, _countof(default_shell_path));
	memset(default_shell_cmd_option, 0, _countof(default_shell_cmd_option));

	if ((RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\OpenSSH", 0, mask, &reg_key) == ERROR_SUCCESS) &&
	    (RegQueryValueExW(reg_key, L"DefaultShell", 0, NULL, (LPBYTE)tmp, &tmp_len) == ERROR_SUCCESS) &&
	    (tmp)) {
		is_default_shell_configured = TRUE;

		/* If required, add quotes to the default shell. */
		if (tmp[0] != L'"') {
			default_shell_path[0] = L'\"';
			wcscat_s(default_shell_path, _countof(default_shell_path), tmp);
			wcscat_s(default_shell_path, _countof(default_shell_path), L"\"");
		} else
			wcscat_s(default_shell_path, _countof(default_shell_path), tmp);
		
		/* Fetch the default shell command option.
		 * For cmd.exe/powershell.exe it is "/c", for bash.exe it is "-c".
		 * For cmd.exe/powershell.exe/bash.exe, verify if present otherwise auto-populate.
		 */
		memset(tmp, 0, PATH_MAX + 1);
		
		if ((RegQueryValueExW(reg_key, L"DefaultShellCommandOption", 0, NULL, (LPBYTE)tmp, &tmp_len) == ERROR_SUCCESS)) {
			wcscat_s(default_shell_cmd_option, _countof(default_shell_cmd_option), L" ");
			wcscat_s(default_shell_cmd_option, _countof(default_shell_cmd_option), tmp);
			wcscat_s(default_shell_cmd_option, _countof(default_shell_cmd_option), L" ");
		}
	}

	if (((r = wcsncpy_s(cmd_exe_path, _countof(cmd_exe_path), system32_path, wcsnlen(system32_path, _countof(system32_path)) + 1)) != 0) ||
	    ((r = wcscat_s(cmd_exe_path, _countof(cmd_exe_path), L"\\cmd.exe")) != 0)) {
		printf_s("get_default_shell_path(), wcscat_s failed with error: %d.", r);
		exit(255);
	}

	/* if default shell is not configured then use cmd.exe as the default shell */
	if (!is_default_shell_configured)
		wcscat_s(default_shell_path, _countof(default_shell_path), cmd_exe_path);
	
	if (!default_shell_cmd_option[0]) {
		if (wcsstr(default_shell_path, L"cmd.exe") || wcsstr(default_shell_path, L"powershell.exe"))
			wcscat_s(default_shell_cmd_option, _countof(default_shell_cmd_option), L" /c ");
		else if (wcsstr(default_shell_path, L"bash.exe"))
			wcscat_s(default_shell_cmd_option, _countof(default_shell_cmd_option), L" -c ");
	}

	if (tmp)
		free(tmp);
	
	if (reg_key)
		RegCloseKey(reg_key);

	return default_shell_path;
}

int 
start_with_pty(wchar_t *command)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	wchar_t *cmd = (wchar_t *)malloc(sizeof(wchar_t) * MAX_CMD_LEN);
	SECURITY_ATTRIBUTES sa;
	BOOL ret;
	DWORD dwStatus;
	HANDLE hEventHook = NULL;
	HMODULE hm_kernel32 = NULL, hm_user32 = NULL;
	wchar_t kernel32_dll_path[PATH_MAX]={0,}, user32_dll_path[PATH_MAX]={0,};

	if (cmd == NULL) {
		printf_s("ssh-shellhost is out of memory");
		exit(255);
	}

	GOTO_CLEANUP_ON_ERR(wcsncpy_s(kernel32_dll_path, _countof(kernel32_dll_path), system32_path, wcsnlen(system32_path, _countof(system32_path)) + 1));
	GOTO_CLEANUP_ON_ERR(wcscat_s(kernel32_dll_path, _countof(kernel32_dll_path), L"\\kernel32.dll"));

	GOTO_CLEANUP_ON_ERR(wcsncpy_s(user32_dll_path, _countof(user32_dll_path), system32_path, wcsnlen(system32_path, _countof(system32_path)) + 1));
	GOTO_CLEANUP_ON_ERR(wcscat_s(user32_dll_path, _countof(user32_dll_path), L"\\user32.dll"));

	if ((hm_kernel32 = LoadLibraryW(kernel32_dll_path)) == NULL ||
	    (hm_user32 = LoadLibraryW(user32_dll_path)) == NULL ||
	    (__SetCurrentConsoleFontEx = (__t_SetCurrentConsoleFontEx)GetProcAddress(hm_kernel32, "SetCurrentConsoleFontEx")) == NULL ||
	    (__UnhookWinEvent = (__t_UnhookWinEvent)GetProcAddress(hm_user32, "UnhookWinEvent")) == NULL ||
	    (__SetWinEventHook = (__t_SetWinEventHook)GetProcAddress(hm_user32, "SetWinEventHook")) == NULL) {
		printf_s("cannot support a pseudo terminal. \n");
		return -1;
	}

	pipe_in = GetStdHandle(STD_INPUT_HANDLE);
	pipe_out = GetStdHandle(STD_OUTPUT_HANDLE);
	pipe_err = GetStdHandle(STD_ERROR_HANDLE);

	/* copy pipe handles passed through std io*/
	if ((pipe_in == INVALID_HANDLE_VALUE) || (pipe_out == INVALID_HANDLE_VALUE) || (pipe_err == INVALID_HANDLE_VALUE))
		return -1;

	cp = GetConsoleCP();

	/* 
	 * Windows PTY sends cursor positions in absolute coordinates starting from <0,0>
	 * We send a clear screen upfront to simplify client 
	 */	
	SendClearScreen(pipe_out);
	ZeroMemory(&inputSi, sizeof(STARTUPINFO));
	GetStartupInfo(&inputSi);
	memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
	sa.bInheritHandle = TRUE;
	/* WM_APPEXIT */
	hostThreadId = GetCurrentThreadId();
	hostProcessId = GetCurrentProcessId();
	InitializeCriticalSection(&criticalSection);
	
	/* 
	 * Ignore the static code analysis warning C6387 
	 * as per msdn, third argument can be NULL when we specify WINEVENT_OUTOFCONTEXT
	 */
#pragma warning(suppress: 6387)
	hEventHook = __SetWinEventHook(EVENT_CONSOLE_CARET, EVENT_CONSOLE_END_APPLICATION, NULL,
					ConsoleEventProc, 0, 0, WINEVENT_OUTOFCONTEXT);
	memset(&si, 0, sizeof(STARTUPINFO));
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));
	/* Copy our parent buffer sizes */
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = 0;
	/* disable inheritance on pipe_in*/
	GOTO_CLEANUP_ON_FALSE(SetHandleInformation(pipe_in, HANDLE_FLAG_INHERIT, 0));
	
	cmd[0] = L'\0';
	GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_CMD_LEN, get_default_shell_path()));
	if (command) {
		if(default_shell_cmd_option[0])
			GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_CMD_LEN, default_shell_cmd_option));

		GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_CMD_LEN, command));
	} else {
		/* Launch the default shell through cmd.exe.
		 * If we don't launch default shell through cmd.exe then the powershell colors are rendered badly to the ssh client.
		 */
		if (is_default_shell_configured) {
			wchar_t tmp_cmd[PATH_MAX + 1] = {0,};
			wcscat_s(tmp_cmd, _countof(tmp_cmd), cmd);
			cmd[0] = L'\0';
			GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_CMD_LEN, cmd_exe_path));
			GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_CMD_LEN, L" /c "));
			GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_CMD_LEN, tmp_cmd));
		}
	}

	SetConsoleCtrlHandler(NULL, FALSE);
	GOTO_CLEANUP_ON_FALSE(CreateProcess(NULL, cmd, NULL, NULL, TRUE, CREATE_NEW_CONSOLE,
				NULL, NULL, &si, &pi));
	childProcessId = pi.dwProcessId;

	FreeConsole();
	Sleep(20);
	while (!AttachConsole(pi.dwProcessId)) {
		if (GetExitCodeProcess(pi.hProcess, &child_exit_code) && child_exit_code != STILL_ACTIVE)
			break;
		Sleep(100);
	}

	/* monitor child exist */
	child = pi.hProcess;
	monitor_thread = CreateThread(NULL, 0, MonitorChild, NULL, 0, NULL);
	if (IS_INVALID_HANDLE(monitor_thread))
		goto cleanup;

	/* disable Ctrl+C hander in this process*/
	SetConsoleCtrlHandler(NULL, TRUE);
	
	initialize_keylen();

	io_thread = CreateThread(NULL, 0, ProcessPipes, NULL, 0, NULL);
	if (IS_INVALID_HANDLE(io_thread))
		goto cleanup;

	ux_thread = CreateThread(NULL, 0, ProcessEventQueue, NULL, 0, NULL);
	if (IS_INVALID_HANDLE(ux_thread))
		goto cleanup;

	ProcessMessages(NULL);
cleanup:
	dwStatus = GetLastError();
	if (child != INVALID_HANDLE_VALUE)
		TerminateProcess(child, 0);

	if (!IS_INVALID_HANDLE(monitor_thread)) {
		WaitForSingleObject(monitor_thread, INFINITE);
		CloseHandle(monitor_thread);
	}
	if (!IS_INVALID_HANDLE(ux_thread)) {
		TerminateThread(ux_thread, S_OK);
		CloseHandle(ux_thread);
	}
	if (!IS_INVALID_HANDLE(io_thread)) {
		TerminateThread(io_thread, 0);
		CloseHandle(io_thread);
	}

	if (hEventHook)
		__UnhookWinEvent(hEventHook);
	
	FreeConsole();
	
	if (child != INVALID_HANDLE_VALUE) {
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	
	FreeQueueEvent();
	DeleteCriticalSection(&criticalSection);
	
	if(cmd != NULL)
		free(cmd);

	return child_exit_code;
}

HANDLE child_pipe_read;
HANDLE child_pipe_write;

DWORD WINAPI 
MonitorChild_nopty( _In_ LPVOID lpParameter)
{
	WaitForSingleObject(child, INFINITE);
	GetExitCodeProcess(child, &child_exit_code);
	CloseHandle(pipe_in);
	return 0;
}

int 
start_withno_pty(wchar_t *command)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	wchar_t *cmd = (wchar_t *)malloc(sizeof(wchar_t) * MAX_CMD_LEN);
	SECURITY_ATTRIBUTES sa;
	BOOL ret, process_input = FALSE, run_under_cmd = FALSE;
	size_t command_len;
	char *buf = (char *)malloc(BUFF_SIZE + 1);
	DWORD rd = 0, wr = 0, i = 0;

	if (cmd == NULL) {
		printf_s("ssh-shellhost is out of memory");
		exit(255);
	}
	pipe_in = GetStdHandle(STD_INPUT_HANDLE);
	pipe_out = GetStdHandle(STD_OUTPUT_HANDLE);
	pipe_err = GetStdHandle(STD_ERROR_HANDLE);

	/* copy pipe handles passed through std io*/
	if ((pipe_in == INVALID_HANDLE_VALUE) || (pipe_out == INVALID_HANDLE_VALUE) || (pipe_err == INVALID_HANDLE_VALUE))
		return -1;

	memset(&sa, 0, sizeof(SECURITY_ATTRIBUTES));
	sa.bInheritHandle = TRUE;
	/* use the default buffer size, 64K*/
	if (!CreatePipe(&child_pipe_read, &child_pipe_write, &sa, 0)) {
		printf_s("ssh-shellhost-can't open no pty session, error: %d", GetLastError());
		return -1;
	}

	memset(&si, 0, sizeof(STARTUPINFO));
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = child_pipe_read;
	si.hStdOutput = pipe_out;
	si.hStdError = pipe_err;

	/* disable inheritance on child_pipe_write and pipe_in*/
	GOTO_CLEANUP_ON_FALSE(SetHandleInformation(pipe_in, HANDLE_FLAG_INHERIT, 0));
	GOTO_CLEANUP_ON_FALSE(SetHandleInformation(child_pipe_write, HANDLE_FLAG_INHERIT, 0));

	/*
	* check if the input needs to be processed (ex for CRLF translation)
	* input stream needs to be processed when running the command
	* within shell processor. This is needed when
	*  - launching a interactive shell (-nopty)
	*    ssh -T user@target
	*  - launching cmd explicity
	*    ssh user@target cmd
	*  - executing a cmd command
	*    ssh user@target dir
	*  - executing a cmd command within a cmd
	*    ssh user@target cmd /c dir
	*/

	if (!command)
		process_input = TRUE;
	else {
		command_len = wcsnlen_s(command, MAX_CMD_LEN);
		if ((command_len >= 3 && _wcsnicmp(command, L"cmd", 4) == 0) ||
		    (command_len >= 7 && _wcsnicmp(command, L"cmd.exe", 8) == 0) ||
		    (command_len >= 4 && _wcsnicmp(command, L"cmd ", 4) == 0) ||
		    (command_len >= 8 && _wcsnicmp(command, L"cmd.exe ", 8) == 0))
			process_input = TRUE;
	}

	/* Try launching command as is first */
	if (command) {
		ret = CreateProcessW(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
		if (ret == FALSE) {
			/* it was probably this case - ssh user@target dir */
			if (GetLastError() == ERROR_FILE_NOT_FOUND)
				run_under_cmd = TRUE;
			else
				goto cleanup;
		}
	}
	else
		run_under_cmd = TRUE;

	/* if above failed with FILE_NOT_FOUND, try running the provided command under cmd*/
	if (run_under_cmd) {
		cmd[0] = L'\0';
		GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_CMD_LEN, get_default_shell_path()));
		if (command) {
			if (default_shell_cmd_option[0])
				GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_CMD_LEN, default_shell_cmd_option));

			GOTO_CLEANUP_ON_ERR(wcscat_s(cmd, MAX_CMD_LEN, command));
		}
	
		GOTO_CLEANUP_ON_FALSE(CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi));
		/* Create process succeeded when running under cmd. input stream needs to be processed */
		process_input = TRUE;
	}
	
	/* close unwanted handles*/
	CloseHandle(child_pipe_read);
	child_pipe_read = INVALID_HANDLE_VALUE;
	child = pi.hProcess;
	/* monitor child exist */
	monitor_thread = CreateThread(NULL, 0, MonitorChild_nopty, NULL, 0, NULL);
	if (IS_INVALID_HANDLE(monitor_thread))
		goto cleanup;

	/* disable Ctrl+C hander in this process*/
	SetConsoleCtrlHandler(NULL, TRUE);

	if (buf == NULL) {
		printf_s("ssh-shellhost is out of memory");
		exit(255);
	}
	/* process data from pipe_in and route appropriately */
	while (1) {
		rd = wr = i = 0;
		buf[0] = L'\0';
		GOTO_CLEANUP_ON_FALSE(ReadFile(pipe_in, buf, BUFF_SIZE, &rd, NULL));

		if (process_input == FALSE) {
			/* write stream directly to child stdin */
			GOTO_CLEANUP_ON_FALSE(WriteFile(child_pipe_write, buf, rd, &wr, NULL));
			continue;
		}
		/* else - process input before routing it to child */
		while (i < rd) {
			/* skip arrow keys */
			if ((rd - i >= 3) && (buf[i] == '\033') && (buf[i + 1] == '[') &&
			    (buf[i + 2] >= 'A') && (buf[i + 2] <= 'D')) {
				i += 3;
				continue;
			}

			/* skip tab */
			if (buf[i] == '\t') {
				i++;
				continue;
			}

			/* Ctrl +C */
			if (buf[i] == '\003') {
				GOTO_CLEANUP_ON_FALSE(GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0));
				in_cmd_len = 0;
				i++;
				continue;
			}

			/* for backspace, we need to send space and another backspace for visual erase */
			if (buf[i] == '\b' || buf[i] == '\x7f') {
				if (in_cmd_len > 0) {
					GOTO_CLEANUP_ON_FALSE(WriteFile(pipe_out, "\b \b", 3, &wr, NULL));
					in_cmd_len--;
				}
				i++;
				continue;
			}

			/* For CR and LF */
			if ((buf[i] == '\r') || (buf[i] == '\n')) {
				/* TODO - do a much accurate mapping */				
				if ((buf[i] == '\r') && ((i == rd - 1) || (buf[i + 1] != '\n')))
					buf[i] = '\n';
				GOTO_CLEANUP_ON_FALSE(WriteFile(pipe_out, buf + i, 1, &wr, NULL));
				in_cmd[in_cmd_len] = buf[i];
				in_cmd_len++;
				GOTO_CLEANUP_ON_FALSE(WriteFile(child_pipe_write, in_cmd, in_cmd_len, &wr, NULL));
				in_cmd_len = 0;
				i++;
				continue;
			}

			GOTO_CLEANUP_ON_FALSE(WriteFile(pipe_out, buf + i, 1, &wr, NULL));
			in_cmd[in_cmd_len] = buf[i];
			in_cmd_len++;
			if (in_cmd_len == MAX_CMD_LEN - 1) {
				GOTO_CLEANUP_ON_FALSE(WriteFile(child_pipe_write, in_cmd, in_cmd_len, &wr, NULL));
				in_cmd_len = 0;
			}
			i++;
		}
	}
cleanup:

	/* close child's stdin first */
	if(!IS_INVALID_HANDLE(child_pipe_write))
		CloseHandle(child_pipe_write);
	
	if (!IS_INVALID_HANDLE(monitor_thread)) {
		WaitForSingleObject(monitor_thread, INFINITE);
		CloseHandle(monitor_thread);
	}		
	if (!IS_INVALID_HANDLE(child))
		TerminateProcess(child, 0);

	if (buf != NULL)
		free(buf);

	if (cmd != NULL)
		free(cmd);
	
	return child_exit_code;
}

static void* xmalloc(size_t size) {
	void* ptr;
	if ((ptr = malloc(size)) == NULL) {
		printf_s("out of memory");
		exit(EXIT_FAILURE);
	}
	return ptr;
}

/* set user environment variables from user profile */
static void setup_session_user_vars()
{
	/* retrieve and set env variables. */
	HKEY reg_key = 0;
	wchar_t name[256];
	wchar_t userprofile_path[PATH_MAX + 1] = { 0, }, path[PATH_MAX + 1] = { 0, };
	wchar_t *data = NULL, *data_expanded = NULL, *path_value = NULL, *to_apply;
	DWORD type, name_chars = 256, data_chars = 0, data_expanded_chars = 0, required, i = 0;
	LONG ret;
	DWORD len = GetCurrentDirectory(_countof(userprofile_path), userprofile_path);
	if (len > 0) {
		SetEnvironmentVariableW(L"USERPROFILE", userprofile_path);
		swprintf_s(path, _countof(path), L"%s\\AppData\\Local", userprofile_path);
		SetEnvironmentVariableW(L"LOCALAPPDATA", path);
		swprintf_s(path, _countof(path), L"%s\\AppData\\Roaming", userprofile_path);
		SetEnvironmentVariableW(L"APPDATA", path);
	}

	ret = RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_QUERY_VALUE, &reg_key);
	if (ret != ERROR_SUCCESS)
		//error("Error retrieving user environment variables. RegOpenKeyExW returned %d", ret);
		return;		
	else while (1) {
		to_apply = NULL;
		required = data_chars * 2;
		name_chars = 256;
		ret = RegEnumValueW(reg_key, i++, name, &name_chars, 0, &type, (LPBYTE)data, &required);
		if (ret == ERROR_NO_MORE_ITEMS)
			break;
		else if (ret == ERROR_MORE_DATA || required > data_chars * 2) {
			if (data != NULL)
				free(data);
			data = xmalloc(required);
			data_chars = required / 2;
			i--;
			continue;
		}
		else if (ret != ERROR_SUCCESS) 
			break;

		if (type == REG_SZ)
			to_apply = data;
		else if (type == REG_EXPAND_SZ) {
			required = ExpandEnvironmentStringsW(data, data_expanded, data_expanded_chars);
			if (required > data_expanded_chars) {
				if (data_expanded)
					free(data_expanded);
				data_expanded = xmalloc(required * 2);
				data_expanded_chars = required;
				ExpandEnvironmentStringsW(data, data_expanded, data_expanded_chars);
			}
			to_apply = data_expanded;
		}

		if (_wcsicmp(name, L"PATH") == 0) {
			if ((required = GetEnvironmentVariableW(L"PATH", NULL, 0)) != 0) {
				/* "required" includes null term */
				path_value = xmalloc((wcslen(to_apply) + 1 + required) * 2);
				GetEnvironmentVariableW(L"PATH", path_value, required);
				path_value[required - 1] = L';';
				GOTO_CLEANUP_ON_ERR(memcpy_s(path_value + required, (wcslen(to_apply) + 1) * 2, to_apply, (wcslen(to_apply) + 1) * 2));
				to_apply = path_value;
			}

		}
		if (to_apply)
			SetEnvironmentVariableW(name, to_apply);
	}
cleanup:
	if (reg_key)
		RegCloseKey(reg_key);
	if (data)
		free(data);
	if (data_expanded)
		free(data_expanded);
	if (path_value)
		free(path_value);
	RevertToSelf();
}

int b64_pton(char const *src, u_char *target, size_t targsize);

int 
wmain(int ac, wchar_t **av)
{
	int pty_requested = 0;
	wchar_t *cmd = NULL, *cmd_b64 = NULL;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_info;

	_set_invalid_parameter_handler(my_invalid_parameter_handler);
	if ((ac == 1) || (ac == 2 && wcscmp(av[1], L"-nopty"))) {
		pty_requested = 1;
		cmd_b64 = ac == 2? av[1] : NULL;
	} else if (ac <= 3 && wcscmp(av[1], L"-nopty") == 0)
		cmd_b64 = ac == 3? av[2] : NULL;
	else {
		printf_s("ssh-shellhost received unexpected input arguments");
		return -1;
	}

	setup_session_user_vars();

	/* decode cmd_b64*/
	if (cmd_b64) {
		char *cmd_b64_utf8, *cmd_utf8;
		if ((cmd_b64_utf8 = utf16_to_utf8(cmd_b64)) == NULL ||
		    /* strlen(b64) should be sufficient for decoded length */
		    (cmd_utf8 = malloc(strlen(cmd_b64_utf8))) == NULL) {
			printf_s("ssh-shellhost - out of memory");
			return -1;
		}
		   
		memset(cmd_utf8, 0, strlen(cmd_b64_utf8));

		if (b64_pton(cmd_b64_utf8, cmd_utf8, strlen(cmd_b64_utf8)) == -1 ||
		    (cmd = utf8_to_utf16(cmd_utf8)) == NULL) {
			printf_s("ssh-shellhost encountered an internal error while decoding base64 cmdline");
			return -1;
		}
		free(cmd_b64_utf8);
		free(cmd_utf8);
	}

	ZeroMemory(system32_path, _countof(system32_path));
	if (!GetSystemDirectory(system32_path, _countof(system32_path))) {
		printf_s("GetSystemDirectory failed");
		exit(255);
	}

	/* assign to job object */
	if ((job = CreateJobObjectW(NULL, NULL)) == NULL) {
		printf_s("cannot create job object, error: %d", GetLastError());
		return -1;
	}

	memset(&job_info, 0, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
	job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

	if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &job_info, sizeof(job_info)) ||
		!AssignProcessToJobObject(job, GetCurrentProcess())) {
		printf_s("cannot associate job object: %d", GetLastError());
		return -1;
	}

	if (pty_requested)
		return start_with_pty(cmd);
	else
		return start_withno_pty(cmd);
}
