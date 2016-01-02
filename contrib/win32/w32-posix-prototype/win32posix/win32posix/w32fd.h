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

int fd_table_initialize();
int fd_table_add(struct w32_io*);
int fd_table_delete(struct w32_io*);

struct w32_io* socketio_socket(int domain, int type, int protocol);

struct w32_io* socketio_accept(struct w32_io* pio, struct sockaddr* addr, int* addrlen);
int socketio_setsockopt(struct w32_io* pio, int level, int optname, const char* optval, int optlen);
int socketio_getsockopt(struct w32_io* pio, int level, int optname, char* optval, int* optlen);
int socketio_getsockname(struct w32_io* pio, struct sockaddr* name, int* namelen);
int socketio_getpeername(struct w32_io* pio, struct sockaddr* name, int* namelen);
int socketio_listen(struct w32_io* pio, int backlog);
int socketio_bind(struct w32_io* pio, const struct sockaddr *name, int namelen);
int socketio_connect(struct w32_io* pio, const struct sockaddr* name, int namelen);
int socketio_shutdown(struct w32_io* pio, int how);
int socketio_close(struct w32_io* pio);

/*non-network i/o*/
int w32_pipe(int *pfds);
int w32_open(const char *pathname, int flags, ...);
int w32_wopen(const wchar_t *pathname, int flags, ...);
int w32_creat(const char *pathname, int mode);
int w32_read(int fd, void *dst, unsigned int max);
int w32_write(int fd, const void *buf, unsigned int max);
int w32_close(int fd);

/*operations on fds*/
int w32_ioctl(int d, int request, ...);
int w32_select(int fds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval *timeout);
int w32_fcntl(int fd, int cmd, ... /* arg */);
int w32_dup(int oldfd);
int w32_dup2(int oldfd, int newfd);

