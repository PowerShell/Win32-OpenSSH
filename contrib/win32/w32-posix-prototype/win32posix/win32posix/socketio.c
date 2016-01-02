#include "w32fd.h"
#include <errno.h>


static int getWSAErrno()
{
	int wsaerrno = WSAGetLastError();

	if (wsaerrno == WSAEWOULDBLOCK)
	{
		return EAGAIN;
	}

	if (wsaerrno == WSAEFAULT)
	{
		return EFAULT;
	}

	if (wsaerrno == WSAEINVAL)
	{
		return EINVAL;
	}

	return wsaerrno;
}

struct w32_io* socketio_socket(int domain, int type, int protocol) {
	struct w32_io *pio = (struct w32_io*)malloc(sizeof(struct w32_io));
	if (!pio) {
		errno = ENOMEM;
		return NULL;
	}

	memset(pio, 0, sizeof(struct w32_io));
	pio->sock = socket(domain, type, protocol);
	if (pio->sock == INVALID_SOCKET) {
		errno = getWSAErrno(); 
		free(pio);
		return NULL;
	}
	
	return pio;
}

struct w32_io* socketio_accept(struct w32_io* pio, struct sockaddr* addr, int* addrlen) {
	struct w32_io *accept_io = (struct w32_io*)malloc(sizeof(struct w32_io));
    return accept_io;
}


int socketio_setsockopt(struct w32_io* pio, int level, int optname, const char* optval, int optlen);
int socketio_getsockopt(struct w32_io* pio, int level, int optname, char* optval, int* optlen);
int socketio_getsockname(struct w32_io* pio, struct sockaddr* name, int* namelen);
int socketio_getpeername(struct w32_io* pio, struct sockaddr* name, int* namelen);
int socketio_listen(struct w32_io* pio, int backlog);
int socketio_bind(struct w32_io* pio, const struct sockaddr *name, int namelen);
int socketio_connect(struct w32_io* pio, const struct sockaddr* name, int namelen);
int socketio_shutdown(struct w32_io* pio, int how);