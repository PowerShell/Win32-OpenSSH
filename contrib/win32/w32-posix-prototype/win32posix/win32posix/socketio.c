#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <errno.h>
#include "w32fd.h"
#include <stddef.h>

#define INTERNAL_SEND_BUFFER_SIZE 70*1024 //70KB

#define INTERNAL_RECV_BUFFER_SIZE 70*1024 //70KB

#define errno_from_WSALastError() errno_from_WSAError(WSAGetLastError())

static int errno_from_WSAError(int wsaerrno)
{

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

int socketio_initialize() {
    WSADATA wsaData = { 0 };
    return WSAStartup(MAKEWORD(2, 2), &wsaData);
}

int socketio_done() {
    WSACleanup();
    return 0;
}

struct acceptEx_context {
    char lpOutputBuf[1024];
    SOCKET accept_socket;
    LPFN_ACCEPTEX lpfnAcceptEx;
    DWORD bytes_received;
};


int socketio_acceptEx(struct w32_io* pio) {
    struct acceptEx_context *context;

    if (pio->context == NULL) {
        GUID GuidAcceptEx = WSAID_ACCEPTEX;
        DWORD dwBytes;

        context = (struct acceptEx_context*)malloc(sizeof(struct acceptEx_context));
        if (context == NULL) {
            errno = ENOMEM;
            debug("ERROR:%d, io:%p", errno, pio);
            return -1;
        }

        if (SOCKET_ERROR == WSAIoctl(pio->sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
            &GuidAcceptEx, sizeof(GuidAcceptEx),
            &context->lpfnAcceptEx, sizeof(context->lpfnAcceptEx),
            &dwBytes, NULL, NULL))
        {
            free(context);
            errno = errno_from_WSALastError();
            debug("ERROR:%d, io:%p", errno, pio);
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
            debug("ERROR:%d, io:%p", errno, pio);
            return -1;
        }
    }
    ResetEvent(pio->read_overlapped.hEvent);

    //create accepting socket
    //todo - get socket parameters from listening socket
    context->accept_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (context->accept_socket == INVALID_SOCKET) {
        errno = errno_from_WSALastError();
        debug("ERROR:%d, io:%p", errno, pio);
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
            errno = errno_from_WSALastError();
            debug("ERROR:%d, io:%p", errno, pio);
            return -1;
        }
    }

    pio->read_details.pending = TRUE;
    return 0;
}

void CALLBACK WSARecvCompletionRoutine(
    IN DWORD dwError,
    IN DWORD cbTransferred,
    IN LPWSAOVERLAPPED lpOverlapped,
    IN DWORD dwFlags
    )
{
    struct w32_io* pio = (struct w32_io*)((char*)lpOverlapped - offsetof(struct w32_io, read_overlapped));
    debug2("io:%p, pending_state:%d, remaining:%d, completed:%d, error:%d, transferred:%d",
        pio, pio->read_details.pending, pio->read_details.remaining, pio->read_details.pending, dwError, cbTransferred);
    if (!dwError && !cbTransferred)
        dwError = ERROR_GRACEFUL_DISCONNECT;
    pio->read_details.error = dwError;
    pio->read_details.remaining = cbTransferred;
    pio->read_details.completed = 0;
    pio->read_details.pending = FALSE;
}

int socketio_WSARecv(struct w32_io* pio, BOOL* completed) {
    int ret = 0;
    WSABUF wsabuf;
    DWORD recv_flags = 0;

    if (completed)
        *completed = FALSE;

    //initialize recv buffers if needed
    wsabuf.len = INTERNAL_RECV_BUFFER_SIZE;
    if (pio->read_details.buf == NULL)
    {
        wsabuf.buf = malloc(wsabuf.len);

        if (!wsabuf.buf)
        {
            errno = ENOMEM;
            debug("ERROR:%d, io:%p", errno, pio);
            return -1;
        }

        pio->read_details.buf = wsabuf.buf;
        pio->read_details.buf_size = wsabuf.len;
    }
    else
        wsabuf.buf = pio->read_details.buf;


    ret = WSARecv(pio->sock, &wsabuf, 1, NULL, &recv_flags, &pio->read_overlapped, &WSARecvCompletionRoutine);
    if (ret == 0)
    {
        pio->read_details.pending = TRUE;
        //receive has completed but APC is pending to be scheduled
        debug2("WSARecv immediate completion, io:%p", pio);
        if (completed)
            *completed = TRUE;
    }
    else { //(ret == SOCKET_ERROR) 
        if (WSAGetLastError() == WSA_IO_PENDING)
        {
            //io is initiated and pending
            pio->read_details.pending = TRUE;
        }
        else { //failed 
            errno = errno_from_WSALastError();
            debug("ERROR: io:%p %d", pio,  errno);
            return -1;
        }
    }

    return 0;
}

struct w32_io* socketio_socket(int domain, int type, int protocol) {
    struct w32_io *pio = (struct w32_io*)malloc(sizeof(struct w32_io));
    if (!pio) {
        errno = ENOMEM;
        debug("ERROR:%d, io:%p", errno, pio);
        return NULL;
    }

    memset(pio, 0, sizeof(struct w32_io));
    pio->sock = socket(domain, type, protocol);
    if (pio->sock == INVALID_SOCKET) {
        errno = errno_from_WSALastError();
        free(pio);
        debug("ERROR:%d, io:%p", errno, pio);
        return NULL;
    }

    pio->type = SOCK_FD;
    return pio;
}

#define SET_ERRNO_ON_ERROR(expr) \
do {  \
    int ret = (expr); \
    if (ret == SOCKET_ERROR) {  \
        errno = errno_from_WSALastError(); \
        debug("ERROR:%d", errno); \
    }  \
    return ret; \
} while (0) 

int socketio_setsockopt(struct w32_io* pio, int level, int optname, const char* optval, int optlen) {
    SET_ERRNO_ON_ERROR(setsockopt(pio->sock, level, optname, optval, optlen));
}

int socketio_getsockopt(struct w32_io* pio, int level, int optname, char* optval, int* optlen) {
    SET_ERRNO_ON_ERROR(getsockopt(pio->sock, level, optname, optval, optlen));
}

int socketio_getsockname(struct w32_io* pio, struct sockaddr* name, int* namelen) {
    SET_ERRNO_ON_ERROR(getsockname(pio->sock, name, namelen));
}

int socketio_getpeername(struct w32_io* pio, struct sockaddr* name, int* namelen) {
    SET_ERRNO_ON_ERROR(getpeername(pio->sock, name, namelen));
}

int socketio_listen(struct w32_io* pio, int backlog) {
    pio->type = LISTEN_FD;
    SET_ERRNO_ON_ERROR(listen(pio->sock, backlog));
}

int socketio_bind(struct w32_io* pio, const struct sockaddr *name, int namelen) {
    SET_ERRNO_ON_ERROR(bind(pio->sock, name, namelen)); 
}

int socketio_recv(struct w32_io* pio, void *buf, size_t len, int flags) {
    BOOL completed = FALSE;

    debug2("io:%p", pio);

    if ((buf == NULL) || (len == 0)) {
        errno = EINVAL;
        debug("ERROR, buf:%p, len:%d, io:%p", buf, len, pio);
        return -1;
    }

    if (flags != 0) {
        errno = ENOTSUP;
        debug("ERROR: flags are not currently supported, io:%p", pio);
        return -1;
    }

    //if io is already pending
    if (pio->read_details.pending) {
        errno = EAGAIN;
        debug2("Read is already pending, io:%p", pio);
        return -1;
    }

    //if we have some buffer copy it and return #bytes copied
    if (pio->read_details.remaining)
    {
        int num_bytes_copied = min(len, pio->read_details.remaining);
        memcpy(buf, pio->read_details.buf + pio->read_details.completed, num_bytes_copied);
        pio->read_details.remaining -= num_bytes_copied;
        pio->read_details.completed += num_bytes_copied;
        debug2("returning %d bytes from prior completed IO, remaining:%d, io:%p", num_bytes_copied, pio->read_details.remaining, pio);
        return num_bytes_copied;
    }

    //if there was an error on async call, return
    if (pio->read_details.error) {
        if (pio->read_details.error == ERROR_GRACEFUL_DISCONNECT) {
            debug2("connection closed, io:%p", pio);
            //connection is closed
            return 0;
        }
        else {
            errno = errno_from_WSAError(pio->read_details.error);
            pio->read_details.error = 0;
            debug("ERROR:%d, io:%p", errno, pio);
            return -1;
        }
    }

    if (0 != socketio_WSARecv(pio, &completed))
        return -1;

    if (completed) {
        //Let APC be scheduled
        SleepEx(1, TRUE);
        if (pio->read_details.pending) {
            //this shouldn't be happening
            errno = EOTHER;
            debug("ERROR: Unexpected IO state, io:%p", pio);
            return -1;
        }
    }

    if (w32_io_is_blocking(pio))
    {
        //wait until io is done
        while (socketio_is_io_available(pio, TRUE) == FALSE) {
            if (0 != wait_for_any_event(NULL, 0, INFINITE))
                return -1;
        }
    }
    else {
        if (socketio_is_io_available(pio, TRUE) == FALSE) {
            errno = EAGAIN;
            debug2("IO is pending, io:%p", pio);
            return -1;
        }
    }

    //by this time we should have some bytes in internal buffer or an error from callback
    if (pio->read_details.error)
    {
        if (pio->read_details.error == ERROR_GRACEFUL_DISCONNECT) {
            //connection is closed
            debug2("connection closed, io:%p", pio);
            return 0;
        }
        else {
            errno = errno_from_WSAError(pio->read_details.error);
            pio->read_details.error = 0;
            debug("ERROR:%d, io:%p", errno, pio);
            return -1;
        }
    }

    if (pio->read_details.remaining) {
        int num_bytes_copied = min(len, pio->read_details.remaining);
        memcpy(buf, pio->read_details.buf, num_bytes_copied);
        pio->read_details.remaining -= num_bytes_copied;
        pio->read_details.completed = num_bytes_copied;
        debug2("returning %d bytes from completed IO, remaining:%d, io:%p", num_bytes_copied, pio->read_details.remaining, pio);
        return num_bytes_copied;
    }
    else {
        //this should not happen
        errno = EOTHER;
        debug("ERROR:Unexpected IO stated, io:%p", pio);
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
    struct w32_io* pio = (struct w32_io*)((char*)lpOverlapped - offsetof(struct w32_io, write_overlapped));
    debug2("io:%p, pending_state:%d, error:%d, transferred:%d, remaining:%d", pio, pio->write_details.pending, dwError, cbTransferred, pio->write_details.remaining);
    pio->write_details.error = dwError;
    //assert that remaining == cbTransferred
    pio->write_details.remaining -= cbTransferred;
    pio->write_details.pending = FALSE;
}

int socketio_send(struct w32_io* pio, const void *buf, size_t len, int flags) {
    int ret = 0;
    WSABUF wsabuf;

    debug2("io:%p", pio);

    if ((buf == NULL) || (len == 0)) {
        errno = EINVAL;
        debug("ERROR, buf:%p, len:%d, io:%p", buf, len, pio);
        return -1;
    }

    if (flags != 0) {
        errno = ENOTSUP;
        debug("ERROR: flags are not currently supported, io:%p", pio);
        return -1;
    }

    //if io is already pending
    if (pio->write_details.pending)
    {
        if (w32_io_is_blocking(pio))
        {
            //this covers the scenario when the fd was previously non blocking (and hence io is still pending)
            //wait for previous io to complete
            debug2("waiting for IO on a previous nonblocking send to complete, io:%p", pio);
            while (pio->write_details.pending) {
                if (wait_for_any_event(NULL, 0, INFINITE) == -1)
                    return -1;
            }
        }
        else {
            errno = EAGAIN;
            debug2("IO pending, io:%p", pio);
            return -1;
        }
    }


    if (pio->write_details.error) {
        errno = errno_from_WSAError(pio->write_details.error);
        debug("ERROR:%d, io:%p", errno, pio);
        return -1;
    }

    //initialize buffers if needed
    wsabuf.len = INTERNAL_SEND_BUFFER_SIZE;
    if (pio->write_details.buf == NULL)
    {
        wsabuf.buf = malloc(wsabuf.len);
        if (!wsabuf.buf)
        {
            errno = ENOMEM;
            debug("ERROR:%d, io:%p", errno, pio);
            return -1;
        }

        pio->write_details.buf = wsabuf.buf;
        pio->write_details.buf_size = wsabuf.len;
    }
    else {
        wsabuf.buf = pio->write_details.buf;
    }

    wsabuf.len = min(wsabuf.len, len);
    memcpy(wsabuf.buf, buf, wsabuf.len);

    //implement flags support if needed
    ret = WSASend(pio->sock, &wsabuf, 1, NULL, 0, &pio->write_overlapped, &WSASendCompletionRoutine);

    if (ret == 0)
    {
        //send has completed and APC is scheduled, let it run
        debug2("WSASend immediate completion, io:%p", pio);
        pio->write_details.pending = TRUE;
        pio->write_details.remaining = wsabuf.len;
        SleepEx(1, TRUE);
        if ((pio->write_details.pending) || (pio->write_details.remaining != 0)) {
            errno = EOTHER;
            debug("ERROR: Unexpected IO state, io:%p", pio);
            return -1;
        }

        //return num of bytes written
        return wsabuf.len;
    }
    else { //(ret == SOCKET_ERROR) 
        if (WSAGetLastError() == WSA_IO_PENDING)
        {
            //io is initiated and pending
            debug2("IO pending, io:%p", pio);
            pio->write_details.pending = TRUE;
            pio->write_details.remaining = wsabuf.len;
            if (w32_io_is_blocking(pio))
            {
                //wait until io is done
                while (pio->write_details.pending)
                    SleepEx(INFINITE, TRUE);
            }

            return wsabuf.len;
        }
        else { //failed 
            errno = errno_from_WSALastError();
            debug("ERROR:%d, io:%p", errno, pio);
            return -1;
        }
    }

}


int socketio_shutdown(struct w32_io* pio, int how) {
    SET_ERRNO_ON_ERROR(shutdown(pio->sock, how));
}

int socketio_close(struct w32_io* pio) {
    debug2("io:%p", pio);
    closesocket(pio->sock);
    //wait for pending io to abort
    SleepEx(0, TRUE);
    if (pio->read_details.pending || pio->write_details.pending)
        debug2("IO is still pending on closed socket. read:%d, write:%d, io:%p", pio->read_details.pending, pio->write_details.pending, pio);
    if (pio->type == LISTEN_FD) {
        if (pio->read_overlapped.hEvent)
            CloseHandle(pio->read_overlapped.hEvent);
        if (pio->context)
            free(pio->context);
    }
    else {
        if (pio->read_details.buf)
            free(pio->read_details.buf);

        if (pio->write_details.buf)
            free(pio->write_details.buf);
    }

    free(pio);
    return 0;
}

struct w32_io* socketio_accept(struct w32_io* pio, struct sockaddr* addr, int* addrlen) {
    struct w32_io *accept_io = NULL;
    int iResult = 0;
    struct acceptEx_context* context;

    debug2("io:%p", pio);
    //start io if not already started
    if (pio->read_details.pending == FALSE) {
        if (socketio_acceptEx(pio) != 0) {
            return NULL;
        }
    }

    if (w32_io_is_blocking(pio)) {
        // block until accept io is complete
        while (FALSE == socketio_is_io_available(pio, TRUE))
        {
            if (0 != wait_for_any_event(&pio->read_overlapped.hEvent, 1, INFINITE))
            {
                return NULL;
            }
        }
    }
    else {
        //if i/o is not ready
        if (FALSE == socketio_is_io_available(pio, TRUE)) {
            errno = EAGAIN;
            debug2("accept is pending, io:%p", pio);
            return NULL;
        }

    }

    context = (struct acceptEx_context*)pio->context;
    pio->read_details.pending = FALSE;
    ResetEvent(pio->read_overlapped.hEvent);

    if (pio->read_details.error)
    {
        errno = errno_from_WSAError(pio->read_details.error);
        debug("ERROR: async io completed with error: %d, io:%p", errno, pio);
        goto on_error;
    }

    if (0 != setsockopt(context->accept_socket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char*)&pio->sock, sizeof(pio->sock)))
    {
        errno = errno_from_WSALastError();
        debug("ERROR: setsockopt failed:%d, io:%p", errno, pio);
        goto on_error;
    }

    accept_io = (struct w32_io*)malloc(sizeof(struct w32_io));
    if (!accept_io)
    {
        errno = ENOMEM;
        debug("ERROR:%d, io:%p", errno, pio);
        goto on_error;
    }
    memset(accept_io, 0, sizeof(struct w32_io));

    accept_io->sock = context->accept_socket;
    accept_io->type = SOCK_FD;
    context->accept_socket = INVALID_SOCKET;
    debug2("accept io:%p", accept_io);

    //TODO : fill in addr
    return accept_io;

on_error:
    if (context->accept_socket != INVALID_SOCKET) {
        closesocket(context->accept_socket);
        context->accept_socket = INVALID_SOCKET;
    }

    return NULL;
}

int socketio_connectex(struct w32_io* pio, const struct sockaddr* name, int namelen) {

    struct sockaddr_in tmp_addr4;
    struct sockaddr_in6 tmp_addr6;
    SOCKADDR* tmp_addr;
    size_t tmp_addr_len;
    DWORD tmp_bytes;
    GUID connectex_guid = WSAID_CONNECTEX;
    LPFN_CONNECTEX ConnectEx;

    if (name->sa_family == AF_INET6)  {
        ZeroMemory(&tmp_addr6, sizeof(tmp_addr6));
        tmp_addr6.sin6_family = AF_INET6;
        tmp_addr6.sin6_port = 0;
        tmp_addr = (SOCKADDR*)&tmp_addr6;
        tmp_addr_len = sizeof(tmp_addr6);
    } 
    else if (name->sa_family == AF_INET)  {
        ZeroMemory(&tmp_addr4, sizeof(tmp_addr4));
        tmp_addr4.sin_family = AF_INET;
        tmp_addr4.sin_port = 0;
        tmp_addr = (SOCKADDR*)&tmp_addr4;
        tmp_addr_len = sizeof(tmp_addr4);
    }
    else  {
        errno = ENOTSUP;
        debug("ERROR: unsuppored address family:%d, io:%p", name->sa_family, pio);
        return -1;
    }
    
    if (SOCKET_ERROR == bind(pio->sock, tmp_addr, tmp_addr_len))
    {
        errno = errno_from_WSALastError();
        debug("ERROR: bind failed :%d, io:%p", errno, pio);
        return -1;
    }

    if (SOCKET_ERROR == WSAIoctl(pio->sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &connectex_guid, sizeof(connectex_guid),
        &ConnectEx, sizeof(ConnectEx),
        &tmp_bytes, NULL, NULL))
    {
        errno = errno_from_WSALastError();
        debug("ERROR:%d, io:%p", errno, pio);
        return -1;
    }

    if ((pio->write_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL) {
        errno = ENOMEM;
        debug("ERROR:%d, io:%p", errno, pio);
        return -1;
    }

    if (TRUE == ConnectEx(pio->sock, name, namelen, NULL, 0, NULL, &pio->write_overlapped))
    {
        //set completion event
        SetEvent(pio->write_overlapped.hEvent);
    }
    else
    {
        if (WSAGetLastError() != ERROR_IO_PENDING)
        {
            CloseHandle(pio->write_overlapped.hEvent);
            pio->write_overlapped.hEvent = 0;
            errno = errno_from_WSALastError();
            debug("ERROR ConnectEx :%d, io:%p", errno, pio);
            return -1;
        }
    }

    pio->write_details.pending = TRUE;
    pio->type = CONNECT_FD;
    return 0;
}

int socketio_connect(struct w32_io* pio, const struct sockaddr* name, int namelen) {
    //SET_ERRNO_ON_ERROR(connect(pio->sock, name, namelen));

    if (pio->write_details.pending == FALSE)
    {
        if (-1 == socketio_connectex(pio, name, namelen))
            return -1;
    }

    if (w32_io_is_blocking(pio)) {
        // block until connect io is complete
        while (FALSE == socketio_is_io_available(pio, TRUE))
        {
            if (0 != wait_for_any_event(&pio->write_overlapped.hEvent, 1, INFINITE))
            {
                return -1;
            }
        }
    }
    else {
        //if i/o is not ready
        if (FALSE == socketio_is_io_available(pio, TRUE)) {
            errno = EINPROGRESS;
            debug2("connect is in progress, io:%p", pio);
            return -1;
        }

    }

    //close event handle
    CloseHandle(pio->write_overlapped.hEvent);
    pio->write_overlapped.hEvent = 0;

    if (pio->write_details.error) {
        errno = errno_from_WSAError(pio->write_details.error);
        debug("ERROR: async io completed with error: %d, io:%p", errno, pio);
        return -1;
    }

    if (0 != setsockopt(pio->sock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, NULL, 0))
    {
        errno = errno_from_WSALastError();
        debug("ERROR: setsockopt failed:%d, io:%p", errno, pio);
        return NULL;
    }


    pio->type = SOCK_FD;
    return 0;
}

BOOL socketio_is_io_available(struct w32_io* pio, BOOL rd) {
    struct acceptEx_context* context = (struct acceptEx_context*)pio->context;

    if ((pio->type == LISTEN_FD) || (pio->type == CONNECT_FD)) {
        DWORD numBytes = 0;
        DWORD flags;
        OVERLAPPED *overlapped = (pio->type == LISTEN_FD) ? &pio->read_overlapped : &pio->write_overlapped;
        BOOL pending = (pio->type == LISTEN_FD) ? pio->read_details.pending : pio->write_details.pending;

        if (pending && WSAGetOverlappedResult(pio->sock, overlapped, &numBytes, FALSE, &flags)) {
            return TRUE;
        }
        else {
            if (pending && WSAGetLastError() != WSA_IO_INCOMPLETE) {
                if (pio->type == LISTEN_FD)
                    pio->read_details.error = WSAGetLastError();
                else
                    pio->write_details.error = WSAGetLastError();
                return TRUE;
            }
            return FALSE;
        }
    }
    else if (rd) {
        if (pio->read_details.remaining || pio->read_details.error)
            return TRUE;
        else
            return FALSE;
    }
    else { //write
        return (pio->write_details.pending == FALSE) ? TRUE : FALSE;
    }

}

int socketio_on_select(struct w32_io* pio, BOOL rd) {

    debug2("io:%p", pio);
    if (rd && pio->read_details.pending)
        return 0;

    if (!rd && pio->write_details.pending)
        return 0;

    if (pio->type == LISTEN_FD) {
        if (socketio_acceptEx(pio) != 0)
            return -1;
        return 0;
    }
    else if (pio->type == CONNECT_FD) {
        //nothing to do for connect
        return 0;
    }
    else if (rd) {
        if (socketio_WSARecv(pio, NULL) != 0)
            return -1;
        return 0;
    }
    else {
        //nothing to start for write
        return 0;
    }
}