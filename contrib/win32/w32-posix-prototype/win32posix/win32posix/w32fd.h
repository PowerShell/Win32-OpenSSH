/*
 * Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
 *
 * Definitions for Win32 wrapper functions with POSIX like signatures
*/

#pragma once

#include <Windows.h>
#include <stdio.h>
#include "debug.h"

enum w32_io_type {
	UNKNOWN_FD = 0,
	SOCK_FD = 1,	/*maps a socket fd*/
	FILE_FD = 2,	/*maps a file fd*/
	PIPE_FD = 3,	/*maps a pipe fd*/
	STD_IO_FD = 5	/*maps a std fd*/
};

enum w32_io_sock_state {
	SOCK_INITIALIZED = 0,		
	SOCK_LISTENING = 1,	/*listen called on socket*/
	SOCK_ACCEPTED = 2,	/*socket retruned from accept()*/
	SOCK_CONNECTING = 3,	/*connect called on socket, connect is in progress*/
	SOCK_CONNECTED = 4	/*connect completed on socket*/
};

enum w32_io_pipe_state {
	PIPE_READ_END = 1,	/*read end of a pipe()*/
	PIPE_WRITE_END = 2	/*write end of a pipe()*/
};

/*
* This sturcture encapsulates the state info needed to map a File Descriptor 
* to Win32 Handle
*/
struct w32_io {
	OVERLAPPED read_overlapped;
	OVERLAPPED write_overlapped;
	struct {
		/*internal read buffer*/
		char *buf;
		DWORD buf_size;
		/*bytes in internal buffer remaining to be read by application*/
		DWORD remaining;
		/*bytes in internal buffer already read by application*/
		DWORD completed; 
		BOOL pending;	 /*waiting on a read operation to complete*/
		DWORD error;	 /*error reported on async read or accept completion*/
	}read_details;
	struct {
		/*internal write buffer*/
		char *buf;
		DWORD buf_size;
		/*bytes in internal buffer remaining to be written to network*/
		DWORD remaining;
		/*bytes in internal buffer already written to network*/
		DWORD completed; 
		BOOL pending;	 /*waiting on a write operation to complete*/
		DWORD error;	 /*error reported on async write or connect completion*/
	}write_details;
	
	/*index at which this object is stored in fd_table*/
	int table_index;		
	enum w32_io_type type;		/*hanldle type*/
	DWORD fd_flags;			/*fd flags from POSIX*/
	DWORD fd_status_flags;		/*fd status flags from POSIX*/
	
	/*underlying w32 handle*/
	union {
		SOCKET sock;
		HANDLE handle;
	};

	/*handle specific internal state context, used by sockets and pipes*/
	struct {
		enum w32_io_sock_state state;
		void* context;
	}internal;
};

BOOL w32_io_is_blocking(struct w32_io*);
BOOL w32_io_is_io_available(struct w32_io* pio, BOOL rd);
int wait_for_any_event(HANDLE* events, int num_events, DWORD milli_seconds);

/*POSIX mimic'ing socket API*/
int socketio_initialize();
int socketio_done();
BOOL socketio_is_io_available(struct w32_io* pio, BOOL rd);
int socketio_on_select(struct w32_io* pio, BOOL rd);
struct w32_io* socketio_socket(int domain, int type, int protocol);
struct w32_io* socketio_accept(struct w32_io* pio, struct sockaddr* addr, int* addrlen);
int socketio_setsockopt(struct w32_io* pio, int level, int optname, 
	const char* optval, int optlen);
int socketio_getsockopt(struct w32_io* pio, int level, int optname, 
	char* optval, int* optlen);
int socketio_getsockname(struct w32_io* pio, struct sockaddr* name, int* namelen);
int socketio_getpeername(struct w32_io* pio, struct sockaddr* name, int* namelen);
int socketio_listen(struct w32_io* pio, int backlog);
int socketio_bind(struct w32_io* pio, const struct sockaddr *name, int namelen);
int socketio_connect(struct w32_io* pio, const struct sockaddr* name, int namelen);
int socketio_recv(struct w32_io* pio, void *buf, size_t len, int flags);
int socketio_send(struct w32_io* pio, const void *buf, size_t len, int flags);
int socketio_shutdown(struct w32_io* pio, int how);
int socketio_close(struct w32_io* pio);

/*POSIX mimic'ing file API*/
BOOL fileio_is_io_available(struct w32_io* pio, BOOL rd);
int fileio_on_select(struct w32_io* pio, BOOL rd);
int fileio_close(struct w32_io* pio);
int fileio_pipe(struct w32_io* pio[2]);
struct w32_io* fileio_open(const char *pathname, int flags, int mode);
int fileio_read(struct w32_io* pio, void *dst, unsigned int max);
int fileio_write(struct w32_io* pio, const void *buf, unsigned int max);
int fileio_fstat(struct w32_io* pio, struct stat *buf);
int fileio_isatty(struct w32_io* pio);
FILE* fileio_fdopen(struct w32_io* pio, const char *mode);


