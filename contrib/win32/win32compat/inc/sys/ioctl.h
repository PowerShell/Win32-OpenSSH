#ifndef COMPAT_IOCTL_H
#define COMPAT_IOCTL_H 1


/*ioctl macros and structs*/
#define TIOCGWINSZ 1
struct winsize {
	unsigned short ws_row;          /* rows, in characters */
	unsigned short ws_col;          /* columns, in character */
	unsigned short ws_xpixel;       /* horizontal size, pixels */
	unsigned short ws_ypixel;       /* vertical size, pixels */
};

int w32_ioctl(int d, int request, ...);
#define ioctl w32_ioctl

#endif
