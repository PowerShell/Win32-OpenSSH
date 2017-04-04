/* 
 * Windows version of sshtty* routines implemented in sshtty.c 
 */

#include <Windows.h>
#include "..\..\..\sshpty.h"

static struct termios _saved_tio;
static int _in_raw_mode = 0;


/* 
 * TTY raw mode routines for Windows 
 */

int ConEnterRawMode(DWORD OutputHandle, BOOL fSmartInit);
int ConExitRawMode(void);

struct termios term_settings;

/* 
 * TODO - clean this up for Windows, ConInit should return previous terminal
 * settings that need to be stored in term_settings
 */

struct termios *
        get_saved_tio(void) {
        memset(&term_settings, 0, sizeof(term_settings));
        return &term_settings;
}

void
leave_raw_mode(int quiet) {
        ConExitRawMode();
}

void
enter_raw_mode(int quiet) {
        ConEnterRawMode(STD_OUTPUT_HANDLE, TRUE);
}
