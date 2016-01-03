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

int socketio_initialize()  {
    WSADATA wsaData = { 0 };
    int iResult = 0;
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        wprintf(L"WSAStartup failed: %d\n", iResult);
        return iResult;
    }
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
	
    pio->type = SOCK_FD;
	return pio;
}

struct w32_io* socketio_accept(struct w32_io* pio, struct sockaddr* addr, int* addrlen) {
    struct w32_io *accept_io = NULL;
    
    accept_io = (struct w32_io*)malloc(sizeof(struct w32_io));
    if (!accept_io)
    {
        errno = ENOMEM;
        return NULL;
    }

    accept_io->sock = accept(pio->sock, addr, addrlen);
    if (accept_io->sock == INVALID_SOCKET) {
        errno = getWSAErrno();
        free(accept_io);
        return NULL;
    }

    pio->type = SOCK_FD;
    return accept_io;
}


int socketio_setsockopt(struct w32_io* pio, int level, int optname, const char* optval, int optlen) {
    return setsockopt(pio->sock, level, optname, optval, optlen);
}

int socketio_getsockopt(struct w32_io* pio, int level, int optname, char* optval, int* optlen) {
    return getsockopt(pio->sock, level, optname, optval, optlen);
}

int socketio_getsockname(struct w32_io* pio, struct sockaddr* name, int* namelen) {
    return getsockname(pio->sock, name, namelen);
}

int socketio_getpeername(struct w32_io* pio, struct sockaddr* name, int* namelen) {
    return 0;
}

int socketio_listen(struct w32_io* pio, int backlog) {
    return listen(pio->sock, backlog);
}

int socketio_bind(struct w32_io* pio, const struct sockaddr *name, int namelen) {
    return bind(pio->sock, name, namelen);
}

int socketio_connect(struct w32_io* pio, const struct sockaddr* name, int namelen) {
    return connect(pio->sock, name, namelen);
}

int socketio_shutdown(struct w32_io* pio, int how) {
    return shutdown(pio->sock, how);
}

int socketio_close(struct w32_io* pio) {
    closesocket(pio->sock);
    //todo- wait for pending io to abort
    free(pio);
}