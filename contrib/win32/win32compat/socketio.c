/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Copyright (c) 2015 Microsoft Corp.
* All rights reserved
*
* Microsoft openssh win32 port
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <errno.h>
#include <VersionHelpers.h>
#include <stddef.h>
#include "w32fd.h"
#include "inc\utf.h"
#include "debug.h"

#define INTERNAL_SEND_BUFFER_SIZE 70*1024 //70KB
#define INTERNAL_RECV_BUFFER_SIZE 70*1024 //70KB
#define errno_from_WSALastError() errno_from_WSAError(WSAGetLastError())

/* state info that needs to be persisted for an inprocess acceptEx call*/
struct acceptEx_context {
	char lpOutputBuf[1024];
	SOCKET accept_socket;
	LPFN_ACCEPTEX lpfnAcceptEx;
	LPFN_GETACCEPTEXSOCKADDRS lpfnGuidGetAcceptExSockaddrs;
	DWORD bytes_received;
};

/* maps WSAError to errno */
static int
errno_from_WSAError(int wsaerrno)
{
	/* TODO - create a mapping table - more efficient */
	switch (wsaerrno) {
	case WSAEWOULDBLOCK:
		return EAGAIN;
	case WSAEFAULT:
		return EFAULT;
	case WSAEINVAL:
		return EINVAL;
	case WSAECONNABORTED:
		return ECONNABORTED;
	case WSAETIMEDOUT:
		return ETIMEDOUT;
	case WSAECONNREFUSED:
		return ECONNREFUSED;
	case WSAEINPROGRESS:
		return EINPROGRESS;
	case WSAESHUTDOWN:
		return ECONNRESET;
	case WSAENOTCONN:
		return ENOTCONN;
	case WSAECONNRESET:
		return ECONNRESET;
	default:
		return wsaerrno - 10000;
	}
}

/* called before any other calls to socketio_ functions */
int
socketio_initialize()
{
	WSADATA wsaData = { 0 };
	return WSAStartup(MAKEWORD(2, 2), &wsaData);
}

/* cleanup */
int
socketio_done()
{
	WSACleanup();
	return 0;
}

/* initiate async acceptEx*/
/* TODO - always return 0, set error in context, accept() will pick it up*/
int
socketio_acceptEx(struct w32_io* pio)
{
	struct acceptEx_context *context;
	struct sockaddr_storage addr; int addrlen = sizeof addr;
	
	debug5("acceptEx - io:%p", pio);
	context = (struct acceptEx_context *)pio->internal.context;
	ResetEvent(pio->read_overlapped.hEvent);

	if (getsockname(pio->sock, (struct sockaddr*)&addr, &addrlen) == SOCKET_ERROR) {
		errno = errno_from_WSALastError();
		debug("acceptEx - getsockname() ERROR:%d, io:%p", WSAGetLastError(), pio);
		return -1;		
	}

	/* create accepting socket */
	context->accept_socket = socket(addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (context->accept_socket == INVALID_SOCKET) {
		errno = errno_from_WSALastError();
		debug3("acceptEx - socket() ERROR:%d, io:%p", WSAGetLastError(), pio);
		return -1;
	}

	if (TRUE == context->lpfnAcceptEx(pio->sock,
					context->accept_socket,
					context->lpOutputBuf,
					0,
					sizeof(SOCKADDR_STORAGE) + 16,
					sizeof(SOCKADDR_STORAGE) + 16,
					&context->bytes_received,
					&pio->read_overlapped))
	{
		/* we are already connected. Set event so subsequent select will catch */
		SetEvent(pio->read_overlapped.hEvent);
	} else {
		/* if overlapped io is in progress, we are good */
		if (WSAGetLastError() != ERROR_IO_PENDING) {
			errno = errno_from_WSALastError();
			debug3("acceptEx - AcceptEx() ERROR:%d, io:%p", WSAGetLastError(), pio);
			return -1;
		}
	}

	pio->read_details.pending = TRUE;
	return 0;
}

void
CALLBACK WSARecvCompletionRoutine(IN DWORD dwError,
				IN DWORD cbTransferred,
				IN LPWSAOVERLAPPED lpOverlapped,
				IN DWORD dwFlags)
{
	struct w32_io* pio =
		(struct w32_io*)((char*)lpOverlapped - offsetof(struct w32_io, read_overlapped));
	debug4("WSARecvCompletionCB - io:%p, pending_state:%d, flags:%d, error:%d, received:%d",
		pio, pio->read_details.pending, dwFlags, dwError, cbTransferred);
	if (!dwError && !cbTransferred)
		dwError = ERROR_GRACEFUL_DISCONNECT;
	pio->read_details.error = dwError;
	pio->read_details.remaining = cbTransferred;
	pio->read_details.completed = 0;
	pio->read_details.pending = FALSE;
}

/* initiates async receive operation*/
/* TODO - always return 0, or make this a void func. any error should be put in context*/
int
socketio_WSARecv(struct w32_io* pio, BOOL* completed)
{
	int ret = 0;
	WSABUF wsabuf;
	DWORD recv_flags = 0;

	debug5("WSARecv - pio: %p", pio);
	if (completed)
		*completed = FALSE;

	/* initialize recv buffers if needed */
	wsabuf.len = INTERNAL_RECV_BUFFER_SIZE;
	if (pio->read_details.buf == NULL) {
		wsabuf.buf = malloc(wsabuf.len);
		if (!wsabuf.buf) {
			errno = ENOMEM;
			debug3("WSARecv - ERROR:%d, io:%p", errno, pio);
			return -1;
		}

		pio->read_details.buf = wsabuf.buf;
		pio->read_details.buf_size = wsabuf.len;
	} else
		wsabuf.buf = pio->read_details.buf;

	ret = WSARecv(pio->sock, &wsabuf, 1, NULL, &recv_flags, &pio->read_overlapped, &WSARecvCompletionRoutine);
	if (ret == 0) {
		pio->read_details.pending = TRUE;
		/* receive has completed but APC is pending to be scheduled */
		debug4("WSARecv - WSARecv() returned 0, io:%p", pio);
		if (completed)
			*completed = TRUE;
	} else { /* (ret == SOCKET_ERROR) */
		if (WSAGetLastError() == WSA_IO_PENDING) {
			/* io is initiated and pending */
			debug4("WSARecv - reported IO pending");
			pio->read_details.pending = TRUE;
		} else {
			errno = errno_from_WSALastError();
			debug3("WSARecv - WSARecv() ERROR: io:%p %d", pio, WSAGetLastError());
			return -1;
		}
	}

	return 0;
}

/* implements socket() */
struct w32_io*
socketio_socket(int domain, int type, int protocol)
{
	struct w32_io *pio = (struct w32_io*)malloc(sizeof(struct w32_io));
	if (!pio) {
		errno = ENOMEM;
		debug3("socket - ERROR:%d, io:%p", errno, pio);
		return NULL;
	}

	memset(pio, 0, sizeof(struct w32_io));
	pio->sock = socket(domain, type, protocol);
	if (pio->sock == INVALID_SOCKET) {
		errno = errno_from_WSALastError();
		debug3("socket - socket() ERROR:%d, io:%p", WSAGetLastError(), pio);
		free(pio);
		return NULL;
	}

	pio->internal.state = SOCK_INITIALIZED;
	return pio;
}

#define SET_ERRNO_ON_ERROR(expr) do {					\
    int ret = (expr);							\
    if (ret == SOCKET_ERROR) {						\
        errno = errno_from_WSALastError();				\
        debug3("%s - ERROR:%d", __FUNCTION__, WSAGetLastError());	\
    }									\
    return ret;								\
} while (0) 

/* implements setsockopt() */
int
socketio_setsockopt(struct w32_io* pio, int level, int optname, const char* optval, int optlen)
{
	if ((optname == SO_KEEPALIVE) || (optname == SO_REUSEADDR) ||
	    (optname == TCP_NODELAY) || (optname == IPV6_V6ONLY))
		SET_ERRNO_ON_ERROR(setsockopt(pio->sock, level, optname, optval, optlen));
	else {
		debug3("setsockop - ERROR: unsupported optname:%d io:%p", optname, pio);
		errno = ENOTSUP;
		return -1;
	}
}

/* implements getsockopt() */
int
socketio_getsockopt(struct w32_io* pio, int level, int optname, char* optval, int* optlen)
{
	SET_ERRNO_ON_ERROR(getsockopt(pio->sock, level, optname, optval, optlen));
}

/* implements getsockname() */
int
socketio_getsockname(struct w32_io* pio, struct sockaddr* name, int* namelen)
{
	SET_ERRNO_ON_ERROR(getsockname(pio->sock, name, namelen));
}

/* implements getpeername */
int
socketio_getpeername(struct w32_io* pio, struct sockaddr* name, int* namelen)
{
	SET_ERRNO_ON_ERROR(getpeername(pio->sock, name, namelen));
}

/* implements listen() */
int
socketio_listen(struct w32_io* pio, int backlog)
{
	struct acceptEx_context* context;

	if (SOCKET_ERROR == listen(pio->sock, backlog)) {
		errno = errno_from_WSALastError();
		debug3("listen - listen() ERROR:%d io:%p", WSAGetLastError(), pio);
		return -1;
	}

	/* prep for accept*/
	{
		GUID GuidAcceptEx = WSAID_ACCEPTEX;
		GUID GuidGetAcceptExSockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
		DWORD dwBytes;

		context = (struct acceptEx_context*)malloc(sizeof(struct acceptEx_context));
		if (context == NULL) {
			errno = ENOMEM;
			debug3("listen - ERROR:%d, io:%p", errno, pio);
			return -1;
		}
		memset(context, 0, sizeof(struct acceptEx_context));
		if (SOCKET_ERROR == WSAIoctl(pio->sock,
			SIO_GET_EXTENSION_FUNCTION_POINTER,
			&GuidAcceptEx, sizeof(GuidAcceptEx),
			&context->lpfnAcceptEx, sizeof(context->lpfnAcceptEx),
			&dwBytes, NULL, NULL)) {
			free(context);
			errno = errno_from_WSALastError();
			debug3("listen - Ioctl1 ERROR:%d, io:%p", WSAGetLastError(), pio);
			return -1;
		}

		if (SOCKET_ERROR == WSAIoctl(pio->sock,
			SIO_GET_EXTENSION_FUNCTION_POINTER,
			&GuidGetAcceptExSockaddrs, sizeof(GuidGetAcceptExSockaddrs),
			&context->lpfnGuidGetAcceptExSockaddrs, sizeof(context->lpfnGuidGetAcceptExSockaddrs),
			&dwBytes, NULL, NULL)) {
			free(context);
			errno = errno_from_WSALastError();
			debug3("listen - Ioctl2 ERROR:%d, io:%p", WSAGetLastError(), pio);
			return -1;
		}

		pio->read_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if ((pio->read_overlapped.hEvent) == NULL) {
			free(context);
			errno = ENOMEM;
			debug3("listen - CreateEvent() ERROR:%d, io:%p", errno, pio);
			return -1;
		}

		context->accept_socket = INVALID_SOCKET;
		pio->internal.context = context;
	}

	pio->internal.state = SOCK_LISTENING;
	return 0;
}

/* implements bind() */
int
socketio_bind(struct w32_io* pio, const struct sockaddr *name, int namelen)
{
	SET_ERRNO_ON_ERROR(bind(pio->sock, name, namelen));
}

/* implements recv() */
int
socketio_recv(struct w32_io* pio, void *buf, size_t len, int flags)
{
	BOOL completed = FALSE;
	errno_t r = 0;
	debug5("recv - io:%p state:%d", pio, pio->internal.state);

	if ((buf == NULL) || (len == 0)) {
		errno = EINVAL;
		debug3("recv - ERROR: invalid arguments, buf:%p, len:%d, io:%p", buf, len, pio);
		return -1;
	}

	if (flags != 0) {
		errno = ENOTSUP;
		debug3("recv - ERROR: flags are not currently supported, io:%p", pio);
		return -1;
	}

	/* TODO - ensure socket is in accepted or connected state */
	/* /io is initiated and pending */
	if (pio->read_details.pending) {
		/* if recv is now in blocking mode, wait for data to be available */
		if (w32_io_is_blocking(pio)) {
			debug4("recv - io is pending, call is blocking, io:%p", pio);
			while (socketio_is_io_available(pio, TRUE) == FALSE) {
				if (0 != wait_for_any_event(NULL, 0, INFINITE))
					return -1;
			}
		} else {
			errno = EAGAIN;
			debug4("recv - io is already pending, io:%p", pio);
			return -1;
		}
	}	

	/* if we have some buffer copy it and return #bytes copied */
	if (pio->read_details.remaining) {
		int num_bytes_copied = min((int)len, pio->read_details.remaining);
		if ((r = memcpy_s(buf, len, pio->read_details.buf + pio->read_details.completed,
			num_bytes_copied)) != 0) {
			debug4("memcpy_s failed with error: %d.", r);
			return -1;
		}
		pio->read_details.remaining -= num_bytes_copied;
		pio->read_details.completed += num_bytes_copied;
		debug5("recv - returning %d bytes from prior completed IO, remaining:%d, io:%p",
			num_bytes_copied, pio->read_details.remaining, pio);
		return num_bytes_copied;
	}

	/* if there was an error on async call, return */
	if (pio->read_details.error) {
		if (pio->read_details.error == ERROR_GRACEFUL_DISCONNECT) {
			debug4("recv - connection closed, io:%p", pio);
			/* connection is closed */
			return 0;
		} else {
			errno = errno_from_WSAError(pio->read_details.error);
			debug3("recv - from CB ERROR:%d, io:%p", pio->read_details.error, pio);
			pio->read_details.error = 0;
			return -1;
		}
	}

	if (0 != socketio_WSARecv(pio, &completed))
		return -1;

	if (completed) {
		/* Let APC be scheduled */
		debug4("recv - Letting APC to execute, io:%p", pio);
		SleepEx(0, TRUE);
		if (pio->read_details.pending) {
			/* this shouldn't be happening */
			errno = EOTHER;
			debug3("recv - ERROR: Unexpected IO state, io:%p", pio);
			return -1;
		}
	}

	if (w32_io_is_blocking(pio)) {
		/* wait until io is done */
		debug5("recv - socket in blocking mode, io:%p", pio);
		while (socketio_is_io_available(pio, TRUE) == FALSE) {
			if (0 != wait_for_any_event(NULL, 0, INFINITE))
				return -1;
		}
	} else {
		if (socketio_is_io_available(pio, TRUE) == FALSE) {
			errno = EAGAIN;
			debug4("recv - IO is pending, io:%p", pio);
			return -1;
		}
	}

	/*
	 * by this time we should have some bytes in internal buffer
	 * or an error from callback
	 */
	if (pio->read_details.error) {
		if (pio->read_details.error == ERROR_GRACEFUL_DISCONNECT) {
			/* connection is closed */
			debug4("recv - connection closed(2), io:%p", pio);
			return 0;
		} else {
			errno = errno_from_WSAError(pio->read_details.error);
			pio->read_details.error = 0;
			debug3("recv - from CB(2) ERROR:%d, io:%p", errno, pio);
			return -1;
		}
	}

	if (pio->read_details.remaining) {
		int num_bytes_copied = min((int)len, pio->read_details.remaining);
		if ((r = memcpy_s(buf, len, pio->read_details.buf, num_bytes_copied)) != 0) {
			debug3("memcpy_s failed with error: %d.", r);
			return -1;
		}
		pio->read_details.remaining -= num_bytes_copied;
		pio->read_details.completed = num_bytes_copied;
		debug4("recv - (2) returning %d bytes from completed IO, remaining:%d, io:%p",
			num_bytes_copied, pio->read_details.remaining, pio);
		return num_bytes_copied;
	} else {
		/* this should not happen */
		errno = EOTHER;
		debug3("recv - (2) ERROR:Unexpected IO state, io:%p", pio);
		return -1;
	}
}

void
CALLBACK WSASendCompletionRoutine(IN DWORD dwError,
				IN DWORD cbTransferred,
				IN LPWSAOVERLAPPED lpOverlapped,
				IN DWORD dwFlags)
{
	struct w32_io* pio = (struct w32_io*)((char*)lpOverlapped - offsetof(struct w32_io, write_overlapped));
	debug4("WSASendCB - io:%p, pending_state:%d, error:%d, sent:%d of remaining:%d",
		pio, pio->write_details.pending, dwError, cbTransferred,
		pio->write_details.remaining);
	pio->write_details.error = dwError;
	/* TODO - assert that remaining == cbTransferred */
	if ((dwError == 0) && (pio->write_details.remaining != cbTransferred)) {
		error("WSASendCB - ERROR: broken assumption, io:%p, sent:%d, remaining:%d", pio,
			cbTransferred, pio->write_details.remaining);
		DebugBreak();
	}
	pio->write_details.remaining -= cbTransferred;
	pio->write_details.pending = FALSE;
}

/* implementation of send() */
int
socketio_send(struct w32_io* pio, const void *buf, size_t len, int flags)
{
	int ret = 0;
	WSABUF wsabuf;
	errno_t r = 0;
		
	debug5("send - io:%p state:%d", pio, pio->internal.state);

	if ((buf == NULL) || (len == 0)) {
		errno = EINVAL;
		debug3("send - ERROR invalid arguments, buf:%p, len:%d, io:%p", buf, len, pio);
		return -1;
	}

	if (flags != 0) {
		errno = ENOTSUP;
		debug3("send - ERROR: flags are not currently supported, io:%p", pio);
		return -1;
	}

	/* TODO - ensure socket is in accepted or connected state */
	/* if io is already pending */
	if (pio->write_details.pending) {
		if (w32_io_is_blocking(pio)) {
			debug4("send - io is pending, call is blocking, io:%p", pio);
			while (pio->write_details.pending)
				if (wait_for_any_event(NULL, 0, INFINITE) == -1)
					return -1;
		} else {
			errno = EAGAIN;
			debug4("send - IO currently pending, EAGAIN, io:%p", pio);
			return -1;
		}
	}

	if (pio->write_details.error) {
		errno = errno_from_WSAError(pio->write_details.error);
		debug3("ERROR:%d, io:%p", pio->write_details.error, pio);
		return -1;
	}

	/* initialize buffers if needed */
	wsabuf.len = INTERNAL_SEND_BUFFER_SIZE;
	if (pio->write_details.buf == NULL) {
		wsabuf.buf = malloc(wsabuf.len);
		if (!wsabuf.buf) {
			errno = ENOMEM;
			debug3("send - ERROR:%d, io:%p", errno, pio);
			return -1;
		}

		pio->write_details.buf = wsabuf.buf;
		pio->write_details.buf_size = wsabuf.len;
	} else
		wsabuf.buf = pio->write_details.buf;

	wsabuf.len = min(wsabuf.len, (int)len);
	if ((r = memcpy_s(wsabuf.buf, wsabuf.len, buf, wsabuf.len)) != 0) {
		debug3("memcpy_s failed with error: %d.", r);
		return -1;
	}

	/* TODO - implement flags support if needed */
	ret = WSASend(pio->sock, &wsabuf, 1, NULL, 0, &pio->write_overlapped, &WSASendCompletionRoutine);

	if (ret == 0) {
		/* send has completed and APC is scheduled, let it run */
		debug4("send - WSASend() returned 0, APC scheduled io:%p", pio);
		pio->write_details.pending = TRUE;
		pio->write_details.remaining = wsabuf.len;
		SleepEx(0, TRUE);
		if ((pio->write_details.pending) || (pio->write_details.remaining != 0)) {
			errno = EOTHER;
			debug3("send - ERROR: Unexpected IO state, io:%p", pio);
			return -1;
		}

		/* return num of bytes written */
		return wsabuf.len;
	} else {
		if (WSAGetLastError() == WSA_IO_PENDING) {
			/* io is initiated and pending */
			debug4("send - WSASend reported IO pending, io:%p", pio);
			pio->write_details.pending = TRUE;
			pio->write_details.remaining = wsabuf.len;
			if (w32_io_is_blocking(pio)) {
				/* wait until io is done */
				debug5("send - waiting as socket is in blocking mode, io:%p", pio);
				while (pio->write_details.pending)
					if (wait_for_any_event(NULL, 0, INFINITE) == -1) {
						/* if interrupted but send has completed, we are good*/
						if ((errno != EINTR) || (pio->write_details.pending))
							return -1;
						errno = 0;
					}
			}

			debug5("send - returning %d, io:%p", wsabuf.len, pio);
			return wsabuf.len;
		} else {
			errno = errno_from_WSALastError();
			debug3("send - WSASend() ERROR:%d, io:%p", WSAGetLastError(), pio);
			return -1;
		}
	}
}

/* shutdown() implementation */
int
socketio_shutdown(struct w32_io* pio, int how)
{
	SET_ERRNO_ON_ERROR(shutdown(pio->sock, how));
}

/* socket close() implementation */
int
socketio_close(struct w32_io* pio)
{
	debug4("close - io:%p", pio);
	closesocket(pio->sock);
	/* wait for pending io to abort */
	SleepEx(0, TRUE);
	if ((pio->internal.state == SOCK_READY) &&
	    (pio->read_details.pending || pio->write_details.pending)) {
		error("close - IO is still pending on closed socket. read:%d, write:%d, io:%p",
			pio->read_details.pending, pio->write_details.pending, pio);
		DebugBreak();
	}
	if (pio->internal.state == SOCK_LISTENING) {
		if (pio->read_overlapped.hEvent)
			CloseHandle(pio->read_overlapped.hEvent);
		if (pio->internal.context) {
			struct acceptEx_context *ctx = (struct acceptEx_context*)pio->internal.context;
			if (ctx->accept_socket != INVALID_SOCKET)
				closesocket(ctx->accept_socket);
			free(pio->internal.context);
		}
	} else if (pio->internal.state == SOCK_CONNECTING) {
		if (pio->write_overlapped.hEvent)
			CloseHandle(pio->write_overlapped.hEvent);
	} else {
		if (pio->read_details.buf)
			free(pio->read_details.buf);

		if (pio->write_details.buf)
			free(pio->write_details.buf);
	}

	free(pio);
	return 0;
}

/* accept() implementation */
struct w32_io*
socketio_accept(struct w32_io* pio, struct sockaddr* addr, int* addrlen)
{
	struct w32_io *accept_io = NULL;
	int iResult = 0;
	struct acceptEx_context* context;
	struct sockaddr *local_address, *remote_address;
	int local_address_len, remote_address_len;
	errno_t r = 0;

	debug5("accept - io:%p", pio);
	/* start io if not already started */
	if (pio->read_details.pending == FALSE) {
		if (socketio_acceptEx(pio) != 0)
			return NULL;
	}

	if (w32_io_is_blocking(pio)) {
		/* block until accept io is complete */
		while (FALSE == socketio_is_io_available(pio, TRUE))
			if (-1 == wait_for_any_event(&pio->read_overlapped.hEvent,
				1, INFINITE))
				return NULL;
	} else {
		/* if i/o is not ready */
		if (FALSE == socketio_is_io_available(pio, TRUE)) {
			errno = EAGAIN;
			debug4("accept is pending, io:%p", pio);
			return NULL;
		}
	}

	context = (struct acceptEx_context*)pio->internal.context;
	pio->read_details.pending = FALSE;
	ResetEvent(pio->read_overlapped.hEvent);

	if (pio->read_details.error) {
		errno = errno_from_WSAError(pio->read_details.error);
		debug3("accept - ERROR: async io completed with error: %d, io:%p", pio->read_details.error, pio);
		goto on_error;
	}

	if (0 != setsockopt(context->accept_socket, SOL_SOCKET,
		SO_UPDATE_ACCEPT_CONTEXT, (char*)&pio->sock, sizeof(pio->sock))) {
		errno = errno_from_WSALastError();
		debug3("accept - ERROR: setsockopt failed:%d, io:%p", WSAGetLastError(), pio);
		goto on_error;
	}

	accept_io = (struct w32_io*)malloc(sizeof(struct w32_io));
	if (!accept_io) {
		errno = ENOMEM;
		debug3("accept - ERROR:%d, io:%p", errno, pio);
		goto on_error;
	}
	memset(accept_io, 0, sizeof(struct w32_io));

	accept_io->sock = context->accept_socket;
	accept_io->internal.state = SOCK_READY;
	context->accept_socket = INVALID_SOCKET;
	debug4("accept io:%p", accept_io);

	if ((addr != NULL) && (addrlen != NULL)) {
		context->lpfnGuidGetAcceptExSockaddrs(context->lpOutputBuf, 0,
			sizeof(SOCKADDR_STORAGE) + 16,
			sizeof(SOCKADDR_STORAGE) + 16, &local_address,
			&local_address_len, &remote_address, &remote_address_len);
		if (remote_address_len) {
			if((r = memcpy_s(addr, remote_address_len, remote_address, remote_address_len)) != 0) {
				debug3("memcpy_s failed with error: %d.", r);
				goto on_error;
			}
			*addrlen = remote_address_len;
		}
	}
	return accept_io;

on_error:
	if (context->accept_socket != INVALID_SOCKET) {
		closesocket(context->accept_socket);
		context->accept_socket = INVALID_SOCKET;
	}

	return NULL;
}

/* initiates an async connect*/
int
socketio_connectex(struct w32_io* pio, const struct sockaddr* name, int namelen)
{

	struct sockaddr_in tmp_addr4;
	struct sockaddr_in6 tmp_addr6;
	SOCKADDR* tmp_addr;
	size_t tmp_addr_len;
	DWORD tmp_bytes;
	GUID connectex_guid = WSAID_CONNECTEX;
	LPFN_CONNECTEX ConnectEx;

	debug5("connectex - io:%p", pio);
	if (name->sa_family == AF_INET6) {
		ZeroMemory(&tmp_addr6, sizeof(tmp_addr6));
		tmp_addr6.sin6_family = AF_INET6;
		tmp_addr6.sin6_port = 0;
		tmp_addr = (SOCKADDR*)&tmp_addr6;
		tmp_addr_len = sizeof(tmp_addr6);
	} else if (name->sa_family == AF_INET) {
		ZeroMemory(&tmp_addr4, sizeof(tmp_addr4));
		tmp_addr4.sin_family = AF_INET;
		tmp_addr4.sin_port = 0;
		tmp_addr = (SOCKADDR*)&tmp_addr4;
		tmp_addr_len = sizeof(tmp_addr4);
	} else {
		errno = ENOTSUP;
		debug3("connectex - ERROR: unsuppored address family:%d, io:%p", name->sa_family, pio);
		return -1;
	}

	if (SOCKET_ERROR == bind(pio->sock, tmp_addr, (int)tmp_addr_len)) {
		errno = errno_from_WSALastError();
		debug3("connectex - ERROR: bind failed :%d, io:%p", WSAGetLastError(), pio);
		return -1;
	}

	if (SOCKET_ERROR == WSAIoctl(pio->sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
		&connectex_guid, sizeof(connectex_guid),
		&ConnectEx, sizeof(ConnectEx),
		&tmp_bytes, NULL, NULL)) {
		errno = errno_from_WSALastError();
		debug3("connectex - ioctl ERROR:%d, io:%p", WSAGetLastError(), pio);
		return -1;
	}

	if ((!pio->write_overlapped.hEvent)
		&& ((pio->write_overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL)) {
		errno = ENOMEM;
		debug3("connectex - ERROR CreateEvent failed:%d, io:%p", errno, pio);
		return -1;
	}

	ResetEvent(pio->write_overlapped.hEvent);
	if (TRUE == ConnectEx(pio->sock, name, namelen, NULL, 0, NULL,
		&pio->write_overlapped)) {
		/* set completion event to indicates that async connect has completed */
		SetEvent(pio->write_overlapped.hEvent);
	} else {
		if (WSAGetLastError() != ERROR_IO_PENDING) {
			CloseHandle(pio->write_overlapped.hEvent);
			pio->write_overlapped.hEvent = 0;
			errno = errno_from_WSALastError();
			debug3("connectex - ERROR ConnectEx() :%d, io:%p", WSAGetLastError(), pio);
			return -1;
		}
	}

	pio->write_details.pending = TRUE;
	pio->internal.state = SOCK_CONNECTING;
	return 0;
}

/* connect implementation */
int
socketio_connect(struct w32_io* pio, const struct sockaddr* name, int namelen)
{

	debug5("connect - io:%p", pio);
	if (pio->write_details.pending == FALSE) {
		if (-1 == socketio_connectex(pio, name, namelen))
			return -1;
	}

	if (w32_io_is_blocking(pio)) {
		/*  block until connect io is complete */
		while (FALSE == socketio_is_io_available(pio, TRUE)) {
			if (-1 == wait_for_any_event(&pio->write_overlapped.hEvent, 1, INFINITE))
				return -1;
		}
	} else {
		/* if i/o is not ready */
		if (FALSE == socketio_is_io_available(pio, TRUE)) {
			errno = EINPROGRESS;
			debug4("connect - in progress, io:%p", pio);
			return -1;
		}
	}

	return socketio_finish_connect(pio);
}

int
socketio_finish_connect(struct w32_io* pio)
{
	DWORD wsa_error = 0;
	debug5("finish_connect, io:%p", pio);

	if (pio->write_details.error) {
		wsa_error = pio->write_details.error;
		debug3("finish_connect - ERROR: async io completed with error: %d, io:%p", wsa_error, pio);
		goto done;
	}

	if (0 != setsockopt(pio->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0)) {
		wsa_error = WSAGetLastError();
		debug3("finish_connect - ERROR: setsockopt failed:%d, io:%p", wsa_error, pio);
		goto done;
	}

done:
	CloseHandle(pio->write_overlapped.hEvent);
	pio->write_overlapped.hEvent = 0;
	pio->write_details.pending = FALSE;

	if (wsa_error) {
		pio->read_details.error = wsa_error;
		pio->write_details.error = wsa_error;
		errno = errno_from_WSAError(wsa_error);
	} else /* reset write_detail that were previously used for async connect */
		ZeroMemory(&pio->write_details, sizeof(pio->write_details));

	pio->internal.state = SOCK_READY;
	return (wsa_error? -1 : 0);
}

/* checks if a given io is ready/available */
BOOL
socketio_is_io_available(struct w32_io* pio, BOOL rd)
{
	if ((pio->internal.state == SOCK_LISTENING) ||
	    (pio->internal.state == SOCK_CONNECTING)) {
		DWORD numBytes = 0;
		DWORD flags;
		BOOL sock_listening = (pio->internal.state == SOCK_LISTENING);
		OVERLAPPED *overlapped = sock_listening ? &pio->read_overlapped : &pio->write_overlapped;
		BOOL pending = sock_listening ? pio->read_details.pending : pio->write_details.pending;

		if (pending) {
			/* if there is an error to be picked up */
			if (sock_listening) {
				if (pio->read_details.error)
					return TRUE;
			} else {
				if (pio->write_details.error)
					return TRUE;
			}
		}

		if (WSAGetOverlappedResult(pio->sock, overlapped, &numBytes, FALSE, &flags))
			return TRUE;
		else if (WSAGetLastError() != WSA_IO_INCOMPLETE) {
			if (sock_listening)
				pio->read_details.error = WSAGetLastError();
			else
				pio->write_details.error = WSAGetLastError();
			return TRUE;
		}

		return FALSE;
	} else if (rd) {
		if (pio->read_details.remaining || pio->read_details.error)
			return TRUE;
		else
			return FALSE;
	} else
		return (pio->write_details.pending == FALSE) ? TRUE : FALSE;
}

/*start async io (if needed) for accept and recv*/
void
socketio_on_select(struct w32_io* pio, BOOL rd)
{
	enum w32_io_sock_state sock_state = pio->internal.state;
	debug4("on_select - io:%p type:%d rd:%d", pio, pio->type, rd);

	/* nothing to do for writes (that includes connect) */
	if (!rd)
		return;

	/* listening socket - acceptEx if needed */
	if (sock_state == SOCK_LISTENING) {
		if (pio->read_details.pending == FALSE)
			if (socketio_acceptEx(pio) != 0) {
				/* set error, accept will pick it*/
				pio->read_details.error = errno;
				errno = 0;
				pio->read_details.pending = TRUE;
				SetEvent(pio->read_overlapped.hEvent);
				return;
			}
	} else if(sock_state == SOCK_READY) {
		/* connected socket - WSARecv if needed */
		if ((!pio->read_details.pending) && (!socketio_is_io_available(pio, rd)) && (socketio_WSARecv(pio, NULL) != 0))
		{
			/* set error, recv() will pick it */
			pio->read_details.error = errno;
			errno = 0;
			return;
		}
	}
}

int
w32_gethostname(char *name_utf8, size_t len)
{
	char* tmp_name_utf8 = NULL;

	if (IsWindows8OrGreater()) {
		/* TODO - GetHostNameW not present in Win7, do GetProcAddr on Win8+*/
	        /*
		wchar_t name_utf16[256];
		if (GetHostNameW(name_utf16, 256) == SOCKET_ERROR) {
	                errno = errno_from_WSALastError();
	                return -1;
	        }

	        if ((tmp_name_utf8 = utf16_to_utf8(name_utf16)) == NULL ||
	                strlen(tmp_name_utf8) >= len) {
	                errno = EFAULT; //??
	                return -1;
	        }

	        memcpy(name_utf8, tmp_name_utf8, strlen(tmp_name_utf8) + 1);
	        free(tmp_name_utf8);
	        return 0; */
		return gethostname(name_utf8, (int)len);
	} else
		return gethostname(name_utf8, (int)len);
}

void
w32_freeaddrinfo(struct addrinfo *ai)
{
	struct addrinfo *cur;
	while (ai) {
		cur = ai;
		ai = ai->ai_next;
		if (cur->ai_addr)
			free(cur->ai_addr);
		if (cur->ai_canonname)
			free(cur->ai_canonname);
		free(cur);
	}
}

int
w32_getaddrinfo(const char *node_utf8, const char *service_utf8,
		const struct addrinfo *hints, struct addrinfo **res)
{
	int ret = 0;
	wchar_t *node_utf16 = NULL, *service_utf16 = NULL;
	struct addrinfoW *info_w = NULL;
	*res = NULL;

	if ((node_utf8 && (node_utf16 = utf8_to_utf16(node_utf8)) == NULL) ||
		(service_utf8 && (service_utf16 = utf8_to_utf16(service_utf8)) == NULL)) {
		ret = EAI_MEMORY;
		goto done;
	}

	if ((ret = GetAddrInfoW(node_utf16, service_utf16, (ADDRINFOW*)hints, &info_w)) != 0)
		goto done;

	/* copy info_w to res */
	{
		struct addrinfoW **cur_w = &info_w;
		struct addrinfo **cur = res;

		while (*cur_w) {
			if ((*cur = malloc(sizeof(struct addrinfo))) == NULL) {
				ret = EAI_MEMORY;
				goto done;
			}
			if (memcpy_s(*cur, sizeof(struct addrinfo), *cur_w, sizeof(struct addrinfo))) {
				ret = EAI_MEMORY;
				goto done;
			}
			(*cur)->ai_next = NULL;
			if (((*cur_w)->ai_canonname && ((*cur)->ai_canonname = utf16_to_utf8((*cur_w)->ai_canonname)) == NULL) ||
			    ((*cur_w)->ai_addrlen && ((*cur)->ai_addr = malloc((*cur_w)->ai_addrlen)) == NULL)) {
				ret = EAI_MEMORY;
				goto done;

			}
			if ((*cur_w)->ai_addrlen)
				if (memcpy_s((*cur)->ai_addr, (*cur_w)->ai_addrlen, (*cur_w)->ai_addr, (*cur_w)->ai_addrlen)) {
					ret = EAI_MEMORY;
					goto done;
				}
			cur_w = &(*cur_w)->ai_next;
			cur = &(*cur)->ai_next;
		}
	}

done:
	if (node_utf16)
		free(node_utf16);
	if (service_utf16)
		free(service_utf16);
	if (info_w)
		FreeAddrInfoW(info_w);
	if (ret != 0 && *res) {
		w32_freeaddrinfo(*res);
		*res = NULL;
	}
	return ret;
}
