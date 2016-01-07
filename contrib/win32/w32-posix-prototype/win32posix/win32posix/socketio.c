#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <errno.h>
#include "w32fd.h"
#include <stddef.h>


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

void CALLBACK WSARecvCompletionRoutine(
    IN DWORD dwError,
    IN DWORD cbTransferred,
    IN LPWSAOVERLAPPED lpOverlapped,
    IN DWORD dwFlags
    )
{
    struct w32_io* pio = lpOverlapped - offsetof(struct w32_io, read_overlapped);
    pio->read_details.error = dwError;
    pio->read_details.remaining = cbTransferred;
    pio->read_details.completed = 0;
    pio->read_details.pending = FALSE;
}

int socketio_recv(struct w32_io* pio, void *buf, size_t len, int flags) {
    int ret = 0;
    DWORD bytes_received;

    //if io is already pending
    if (pio->read_details.pending)
    {
        errno = EAGAIN;
        return -1;
    }

    //initialize recv buffers if needed
    if (pio->read_overlapped.hEvent == NULL)
    {
        WSABUF* wsabuf = malloc(sizeof(WSABUF));
        if (wsabuf) {
            wsabuf->len = 1024;
            wsabuf->buf = malloc(wsabuf->len);
        }
    
        if (!wsabuf || !wsabuf->buf)
        {
            if (wsabuf)
                free(wsabuf);
            errno = ENOMEM;
            return -1;
        }

        pio->read_overlapped.hEvent = (HANDLE)wsabuf;
    }

    //if we have some buffer copy it and retun #bytes copied
    if (pio->read_details.remaining)
    {
        int num_bytes_copied = min(len, pio->read_details.remaining);
        memcpy(buf, pio->read_overlapped.hEvent, num_bytes_copied);
        pio->read_details.remaining -= num_bytes_copied;
        return num_bytes_copied;
    }

    //TODO - implement flags if any needed for OpenSSH
    ret = WSARecv(pio->sock, (WSABUF*)pio->read_overlapped.hEvent, 1, &bytes_received, 0, &pio->read_overlapped, &WSARecvCompletionRoutine);
    if (ret == 0)
    {   
        //receive has completed and APC is scheduled, let it run
        pio->read_details.pending = TRUE;
        SleepEx(1, TRUE);
        if ((pio->read_details.pending == FALSE) || (pio->read_details.remaining == 0)) {
            errno = EOTHER;
            return -1;
        }

        //we should have some bytes copied to internal buffer
    }
    else if (ret == WSA_IO_PENDING) {
        //io is initiated and pending
        pio->read_details.pending = TRUE;

        if (w32_io_is_blocking(pio))
        {
            //wait until io is done
            while (pio->read_details.pending)
                SleepEx(INFINITE, TRUE);
        }
        else {
            errno = EAGAIN;
            return -1;
        }
    }
    else { //failed 
        errno = getWSAErrno();
        return -1;
    }

    //by this time we should have some bytes in internal buffer
    //if we have some buffer copy it and retun #bytes copied
    if (pio->read_details.remaining)
    {
        int num_bytes_copied = min(len, pio->read_details.remaining);
        memcpy(buf, pio->read_overlapped.hEvent, num_bytes_copied);
        pio->read_details.remaining -= num_bytes_copied;
        return num_bytes_copied;
    }
    else {
        errno = EOTHER;
        return -1;
    }

}

void CALLBACK WSASendCompletionRoutine(
    IN DWORD dwError,
    IN DWORD cbTransferred,
    IN LPWSAOVERLAPPED lpOverlapped,
    IN DWORD dwFlags
    )
{
    struct w32_io* pio = lpOverlapped - offsetof(struct w32_io, write_overlapped);
    pio->write_details.error = dwError;
    //assert that remaining == cbTransferred
    pio->write_details.remaining -= cbTransferred;
    pio->write_details.pending = FALSE;
}

int socketio_send(struct w32_io* pio, const void *buf, size_t len, int flags) {
    
    if (pio->write_overlapped.hEvent == NULL)
    {
        WSABUF* wsabuf = malloc(sizeof(WSABUF));
        if (wsabuf) {
            wsabuf->len = 1024;
            wsabuf->buf = malloc(wsabuf->len);
        }

        if (!wsabuf || !wsabuf->buf)
        {
            if (wsabuf)
                free(wsabuf);
            errno = ENOMEM;
            return -1;
        }

        pio->write_overlapped.hEvent = (HANDLE)wsabuf;
    }
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


struct w32_io* socketio_accept(struct w32_io* pio, struct sockaddr* addr, int* addrlen) {
    struct w32_io *accept_io = NULL;

    accept_io = (struct w32_io*)malloc(sizeof(struct w32_io));
    if (!accept_io)
    {
        errno = ENOMEM;
        return NULL;
    }

    if (w32_io_is_blocking(pio)) {
        accept_io->sock = accept(pio->sock, addr, addrlen);
        if (accept_io->sock == INVALID_SOCKET) {
            errno = getWSAErrno();
            free(accept_io);
            return NULL;
        }
    }
    else {
        //ensure i/o is ready
        if (FALSE == socketio_is_ioready(pio, TRUE)) {
            free(accept_io);
            errno = EAGAIN;
            return -1;
        }

        struct acceptEx_context* context = (struct acceptEx_context*)pio->context;

        accept_io->sock = context->accept_socket;
        context->accept_socket = INVALID_SOCKET;
        pio->read_details.pending = FALSE;
        ResetEvent(pio->read_overlapped.hEvent);
    }

    pio->type = SOCK_FD;
    return accept_io;
}

BOOL socketio_is_ioready(struct w32_io* pio, BOOL rd) {
    struct acceptEx_context* context = (struct acceptEx_context*)pio->context;

    if (w32_io_is_blocking(pio))
        return FALSE;

    if (pio->type == LISTEN_FD) {
        DWORD numBytes = 0;
        if (pio->read_details.pending && GetOverlappedResult(pio->read_overlapped.hEvent, &pio->read_overlapped, &numBytes, FALSE)) {
            return TRUE;
        }
        else {
            if (pio->read_details.pending && GetLastError() != ERROR_IO_INCOMPLETE) {
                //unexpected error;
            }
            return FALSE;
        }
    }
    else { //regular socket
        //todo
        return FALSE;
    }
    
}

int socketio_start_asyncio(struct w32_io* pio, BOOL rd) {

    if (w32_io_is_blocking(pio)) {
        errno = EPERM;
        return -1;
    }

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

            if (TRUE == context->lpfnAcceptEx(pio->sock,
                context->accept_socket,
                context->lpOutputBuf,
                0,
                sizeof(struct sockaddr_in) + 16,
                sizeof(struct sockaddr_in) + 16,
                &context->bytes_received,
                &pio->read_overlapped))
            {
                //we are already connected. Set event so subsequent select will catch
                SetEvent(pio->read_overlapped.hEvent);
            }
            else {
                //if overlapped io is in progress, we are good
                if (WSAGetLastError() != ERROR_IO_PENDING) {
                    errno = getWSAErrno();
                    return -1;
                }
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