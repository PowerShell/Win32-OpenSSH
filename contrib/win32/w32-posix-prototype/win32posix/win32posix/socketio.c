#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <errno.h>
#include "w32fd.h"


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

static int set_errno_on_error(int ret)
{
    if (ret == SOCKET_ERROR) {
        errno = getWSAErrno();
    }
    return ret;
}

int socketio_initialize()  {
    WSADATA wsaData = { 0 };
    return WSAStartup(MAKEWORD(2, 2), &wsaData);
}

int socketio_done() {
    WSACleanup();
    return 0;
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
    return set_errno_on_error(setsockopt(pio->sock, level, optname, optval, optlen));
}

int socketio_getsockopt(struct w32_io* pio, int level, int optname, char* optval, int* optlen) {
    return set_errno_on_error(getsockopt(pio->sock, level, optname, optval, optlen));
}

int socketio_getsockname(struct w32_io* pio, struct sockaddr* name, int* namelen) {
    return set_errno_on_error(getsockname(pio->sock, name, namelen));
}

int socketio_getpeername(struct w32_io* pio, struct sockaddr* name, int* namelen) {
    return set_errno_on_error(getpeername(pio->sock, name, namelen));
}

int socketio_listen(struct w32_io* pio, int backlog) {
    pio->type = LISTEN_FD;
    return set_errno_on_error(listen(pio->sock, backlog));
}

int socketio_bind(struct w32_io* pio, const struct sockaddr *name, int namelen) {
    return set_errno_on_error(bind(pio->sock, name, namelen));
}

int socketio_connect(struct w32_io* pio, const struct sockaddr* name, int namelen) {
    return set_errno_on_error(connect(pio->sock, name, namelen));
}

int socketio_shutdown(struct w32_io* pio, int how) {
    return set_errno_on_error(shutdown(pio->sock, how));
}

int socketio_close(struct w32_io* pio) {
    closesocket(pio->sock);
    //todo- wait for pending io to abort
    free(pio);
    return 0;
}

struct acceptEx_context {
    char lpOutputBuf[1024];
    SOCKET accept_socket;
    LPFN_ACCEPTEX lpfnAcceptEx;
    DWORD bytes_received;
};

int socketio_start_asyncio(struct w32_io* pio, BOOL read) {
    if (pio->type == LISTEN_FD) {
        if (!pio->read_details.pending) {
            struct acceptEx_context *context;

            if (pio->context == NULL) {
                GUID GuidAcceptEx = WSAID_ACCEPTEX;
                DWORD dwBytes;

                context = (struct acceptEx_context*)malloc(sizeof(struct acceptEx_context));
                if (context == NULL) {
                    errno = ENOMEM;
                    return -1;
                }

                if (SOCKET_ERROR == WSAIoctl(pio->sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                    &GuidAcceptEx, sizeof (GuidAcceptEx),
                    &context->lpfnAcceptEx, sizeof (context->lpfnAcceptEx),
                    &dwBytes, NULL, NULL))
                {
                    free(context);
                    errno = getWSAErrno();
                    return -1;
                }

                context->accept_socket = INVALID_SOCKET;
                pio->context = context;
            }
            else
                context = (struct acceptEx_context *)pio->context;

            //init overlapped event
            if (pio->read_overlapped.hEvent == NULL) {
                if ((pio->read_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL) {
                    errno = ENOMEM;
                    return -1;
                }
            }
            ResetEvent(pio->read_overlapped.hEvent);

            //create accepting socket
            //todo - get socket parameters from listening socket
            context->accept_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (context->accept_socket == INVALID_SOCKET) {
                errno = getWSAErrno();
                return -1;
            }

            if (FALSE == context->lpfnAcceptEx(pio->sock,
                context->accept_socket,
                context->lpOutputBuf,
                0,
                sizeof(struct sockaddr_in) + 16,
                sizeof(struct sockaddr_in) + 16,
                &context->bytes_received,
                &pio->read_overlapped))
            {

                errno = getWSAErrno();
                return -1;
            }

            pio->read_details.pending = TRUE;
            return 0;
        }
        else //io is already pending
            return 0;

    }
    else { //type == SOCK_FD 
        return -1;
    }
}