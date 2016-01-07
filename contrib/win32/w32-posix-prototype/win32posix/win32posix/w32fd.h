#include <Windows.h>

enum w32_io_type {
	UNKOWN_FD,
	LISTEN_FD,
	SOCK_FD,
	FILE_FD
};

struct w32_io {
	OVERLAPPED read_overlapped;
    OVERLAPPED write_overlapped;
    struct {
        DWORD error;
        DWORD remaining;
        DWORD completed;
        BOOL pending;
    }read_details;
    struct {
        DWORD error;
        DWORD remaining;
        DWORD completed;
        BOOL pending;
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
BOOL w32_io_is_ioready(struct w32_io* pio, BOOL rd);

int fd_table_initialize();
int fd_table_add(struct w32_io*);
int fd_table_delete(struct w32_io*);

int socketio_initialize();
int socketio_done();
BOOL socketio_is_ioready(struct w32_io* pio, BOOL rd);
int socketio_start_asyncio(struct w32_io* pio, BOOL rd);
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

