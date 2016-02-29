#pragma once

#include <Windows.h>
#include <stdio.h>
#include "debug.h"


//order to be maintained
enum w32_io_type {
    UNKOWN_FD = 0,
    LISTEN_FD = 1,
    CONNECT_FD = 2,
    SOCK_FD = 3,
    FILE_FD = 4,
    PIPE_FD = 5,
    CONSOLE_FD = 6
};

struct w32_io {
	OVERLAPPED read_overlapped;
    OVERLAPPED write_overlapped;
    struct {
        //internal buffer details
        char *buf;
        DWORD buf_size;

        //async io details
        DWORD error;  //error reported on async read completion
        DWORD remaining; //bytes in internal buffer remaining to be read by application
        DWORD completed; //bytes in internal buffer already read by application
        BOOL pending; //waiting on async io to complete 
    }read_details;
    struct {
        //internal buffer details
        char* buf;
        DWORD buf_size;

        //async io details 
        DWORD error;   //error reported on async write completion
        DWORD remaining; //bytes in internal buffer that are not yet successfully written on i/o 
        DWORD completed; //bytes in internal buffer that have been successfully written on i/o 
        BOOL pending; //waiting on async io to complete 
    }write_details;

    //-1 if not indexed
    int table_index;
	//handle type
	enum w32_io_type type;
	DWORD fd_flags;
    DWORD fd_status_flags;
	
	//underlying w32 handle
	union {
		SOCKET sock;
		HANDLE handle;
	};

	//handle specific context
	void* context;
};

BOOL w32_io_is_blocking(struct w32_io*);
BOOL w32_io_is_io_available(struct w32_io* pio, BOOL rd);

//signal
int wait_for_any_event(HANDLE* events, int num_events, DWORD milli_seconds);

//socket io
int socketio_initialize();
int socketio_done();
BOOL socketio_is_io_available(struct w32_io* pio, BOOL rd);
int socketio_on_select(struct w32_io* pio, BOOL rd);
struct w32_io* socketio_socket(int domain, int type, int protocol);
struct w32_io* socketio_accept(struct w32_io* pio, struct sockaddr* addr, int* addrlen);
int socketio_setsockopt(struct w32_io* pio, int level, int optname, const char* optval, int optlen);
int socketio_getsockopt(struct w32_io* pio, int level, int optname, char* optval, int* optlen);
int socketio_getsockname(struct w32_io* pio, struct sockaddr* name, int* namelen);
int socketio_getpeername(struct w32_io* pio, struct sockaddr* name, int* namelen);
int socketio_listen(struct w32_io* pio, int backlog);
int socketio_bind(struct w32_io* pio, const struct sockaddr *name, int namelen);
int socketio_connect(struct w32_io* pio, const struct sockaddr* name, int namelen);
int socketio_recv(struct w32_io* pio, void *buf, size_t len, int flags);
int socketio_send(struct w32_io* pio, const void *buf, size_t len, int flags);
int socketio_shutdown(struct w32_io* pio, int how);
int socketio_close(struct w32_io* pio);


//fileio
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


