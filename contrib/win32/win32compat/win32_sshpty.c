/* 
 * Windows version of sshpty* routines in sshpty.c
 */



#include <Windows.h>
#include "..\..\..\sshpty.h"


/* 
 * Windows versions of pty_*. Some of them are NO-OPs and should go 
 * away when pty logic is refactored and abstracted out 
 * 
 */
int
pty_allocate(int *ptyfd, int *ttyfd, char *namebuf, size_t namebuflen)
{
	/*
	* Simple console screen implementation in Win32 to give a 
	* Unix like pty for interactive sessions
	*/
	*ttyfd = 0;
	*ptyfd = 0;
	strlcpy(namebuf, "console", namebuflen);
	return 1;
}

void
pty_release(const char *tty) {
	/* NO-OP */
}

void
pty_make_controlling_tty(int *ttyfd, const char *tty) {
	/* NO-OP */
}

void
pty_change_window_size(int ptyfd, u_int row, u_int col,
    u_int xpixel, u_int ypixel) {
	/* TODO - Need to implement*/
}


void
pty_setowner(struct passwd *pw, const char *tty) {
	/* NO-OP */
}

void
disconnect_controlling_tty(void) {
	/* NO-OP */
}

