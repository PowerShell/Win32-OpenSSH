/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Implementation of POSIX APIs
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
#include "inc\sys\socket.h"
#include "inc\sys\select.h"
#include "inc\sys\uio.h"
#include "inc\sys\types.h"
#include "inc\unistd.h"
#include "inc\fcntl.h"
#include "inc\sys\un.h"
#include "inc\utf.h"

#include "w32fd.h"
#include "signal_internal.h"
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <direct.h>
#include <winioctl.h>
#include "Shlwapi.h"
#include <sys\utime.h>
#include "misc_internal.h"
#include "debug.h"

/* internal table that stores the fd to w32_io mapping*/
struct w32fd_table {
	w32_fd_set occupied;		/*bit map for tracking occipied table entries*/
	struct w32_io* w32_ios[MAX_FDS];/*array of references to mapped w32_io objects*/
};

/* mapping table*/
static struct w32fd_table fd_table;

/* static table entries representing std in, out and error*/
static struct w32_io w32_io_stdin, w32_io_stdout, w32_io_stderr;

/* main thread handle*/
HANDLE main_thread;

void fd_table_set(struct w32_io* pio, int index);

/* initializes mapping table*/
static int
fd_table_initialize()
{
	memset(&fd_table, 0, sizeof(fd_table));
	memset(&w32_io_stdin, 0, sizeof(w32_io_stdin));
	w32_io_stdin.std_handle = STD_INPUT_HANDLE;
	w32_io_stdin.type = NONSOCK_SYNC_FD;

	char *envValue = NULL;
	_dupenv_s(&envValue, NULL, SSH_ASYNC_STDIN);
	if (NULL != envValue) {
		if(strcmp(envValue, "1") == 0)
			w32_io_stdin.type = NONSOCK_FD;
		
		free(envValue);
	}

	_putenv_s(SSH_ASYNC_STDIN, "");
	fd_table_set(&w32_io_stdin, STDIN_FILENO);
	memset(&w32_io_stdout, 0, sizeof(w32_io_stdout));
	w32_io_stdout.std_handle = STD_OUTPUT_HANDLE;
	w32_io_stdout.type = NONSOCK_SYNC_FD;
	
	envValue = NULL;
	_dupenv_s(&envValue, NULL, SSH_ASYNC_STDOUT);
	if (NULL != envValue) {
		if(strcmp(envValue, "1") == 0)
			w32_io_stdout.type = NONSOCK_FD;

		free(envValue);
	}

	_putenv_s(SSH_ASYNC_STDOUT, "");
	fd_table_set(&w32_io_stdout, STDOUT_FILENO);
	memset(&w32_io_stderr, 0, sizeof(w32_io_stderr));
	w32_io_stderr.std_handle = STD_ERROR_HANDLE;
	w32_io_stderr.type = NONSOCK_SYNC_FD;

	envValue = NULL;
	_dupenv_s(&envValue, NULL, SSH_ASYNC_STDERR);
	if (NULL != envValue) {
		if(strcmp(envValue, "1") == 0)
			w32_io_stderr.type = NONSOCK_FD;

		free(envValue);
	}

	_putenv_s(SSH_ASYNC_STDERR, "");
	fd_table_set(&w32_io_stderr, STDERR_FILENO);
	return 0;
}

/* get a free slot in mapping table with least index*/
static int
fd_table_get_min_index()
{
	int min_index = 0;
	unsigned char* bitmap = fd_table.occupied.bitmap;
	unsigned char tmp;

	while (*bitmap == 0xff) {
		bitmap++;
		min_index += 8;
		if (min_index >= MAX_FDS) {
			errno = EMFILE;
			debug3("ERROR: MAX_FDS limit reached");
			return -1;
		}
	}

	tmp = *bitmap;
	while (tmp & 0x80) {
		tmp <<= 1;
		min_index++;
	}

	return min_index;
}

/* maps pio to fd (specified by index)*/
static void
fd_table_set(struct w32_io* pio, int index)
{
	fd_table.w32_ios[index] = pio;
	pio->table_index = index;
	assert(pio->type != UNKNOWN_FD);
	FD_SET(index, &(fd_table.occupied));
}

/* removes entry at index from mapping table*/
static void
fd_table_clear(int index)
{
	fd_table.w32_ios[index] = NULL;
	FD_CLR(index, &(fd_table.occupied));
}

void
w32posix_initialize()
{
	if ((fd_table_initialize() != 0) || (socketio_initialize() != 0))
		DebugBreak();
	main_thread = OpenThread(THREAD_SET_CONTEXT | SYNCHRONIZE, FALSE, GetCurrentThreadId());
	if ((main_thread == NULL) || (sw_initialize() != 0) || w32_programdir() == NULL) {
		DebugBreak();
		fatal("failed to initialize w32posix wrapper");
	}
}

void
w32posix_done()
{
	socketio_done();
}

/* Check if the corresponding fd is set blocking */
BOOL
w32_io_is_blocking(struct w32_io* pio)
{
	return (pio->fd_status_flags & O_NONBLOCK) ? FALSE : TRUE;
}

/*
* Check if io is ready/available. This function is primarily used by select()
* as it decides on what fds can be set.
*/
BOOL
w32_io_is_io_available(struct w32_io* pio, BOOL rd)
{
	if (pio->type == SOCK_FD)
		return socketio_is_io_available(pio, rd);
	else
		return fileio_is_io_available(pio, rd);
}

void
w32_io_on_select(struct w32_io* pio, BOOL rd)
{
	if ((pio->type == SOCK_FD))
		socketio_on_select(pio, rd);
	else
		fileio_on_select(pio, rd);
}

#define CHECK_FD(fd) do {							\
	errno = 0;                                                              \
	if ((fd < 0) || (fd > MAX_FDS - 1) || fd_table.w32_ios[fd] == NULL) {   \
		errno = EBADF;                                                  \
		debug3("%s ERROR: bad fd: %d", __FUNCTION__, fd);                \
		return -1;                                                      \
	}                                                                       \
} while (0)

#define CHECK_SOCK_IO(pio) do {                                             \
	errno = 0;                                                          \
	if (pio->type != SOCK_FD) {                                         \
		errno = ENOTSOCK;                                           \
		debug3("%s ERROR: not sock :%d", __FUNCTION__, pio->type);   \
		return -1;                                                  \
	}                                                                   \
} while (0)

int
w32_socket(int domain, int type, int protocol)
{
	int min_index = fd_table_get_min_index();
	struct w32_io* pio = NULL;

	errno = 0;
	if (min_index == -1)
		return -1;
	
	if (domain == AF_UNIX && type == SOCK_STREAM) {
		pio = fileio_afunix_socket();		
		if (pio == NULL)
			return -1;
		pio->type = NONSOCK_FD;
	} else {
		pio = socketio_socket(domain, type, protocol);
		if (pio == NULL)
			return -1;
		pio->type = SOCK_FD;
	}	

	fd_table_set(pio, min_index);
	debug4("socket:%d, socktype:%d, io:%p, fd:%d ", pio->sock, type, pio, min_index);
	return min_index;
}

int
w32_accept(int fd, struct sockaddr* addr, int* addrlen)
{
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	int min_index = fd_table_get_min_index();
	struct w32_io* pio = NULL;

	if (min_index == -1)
		return -1;

	pio = socketio_accept(fd_table.w32_ios[fd], addr, addrlen);
	if (!pio)
		return -1;

	pio->type = SOCK_FD;
	fd_table_set(pio, min_index);
	debug4("socket:%d, io:%p, fd:%d ", pio->sock, pio, min_index);
	return min_index;
}

int
w32_setsockopt(int fd, int level, int optname, const void* optval, int optlen)
{
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_setsockopt(fd_table.w32_ios[fd], level, optname, (const char*)optval, optlen);
}

int
w32_getsockopt(int fd, int level, int optname, void* optval, int* optlen)
{
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_getsockopt(fd_table.w32_ios[fd], level, optname, (char*)optval, optlen);
}

int
w32_getsockname(int fd, struct sockaddr* name, int* namelen)
{
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_getsockname(fd_table.w32_ios[fd], name, namelen);
}

int
w32_getpeername(int fd, struct sockaddr* name, int* namelen)
{
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_getpeername(fd_table.w32_ios[fd], name, namelen);
}

int
w32_listen(int fd, int backlog)
{
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_listen(fd_table.w32_ios[fd], backlog);
}

int
w32_bind(int fd, const struct sockaddr *name, int namelen)
{
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_bind(fd_table.w32_ios[fd], name, namelen);
}

int
w32_connect(int fd, const struct sockaddr* name, int namelen)
{
	CHECK_FD(fd);

	if (fd_table.w32_ios[fd]->type == NONSOCK_FD) {
		struct sockaddr_un* addr = (struct sockaddr_un*)name;
		return fileio_connect(fd_table.w32_ios[fd], addr->sun_path);
	}

	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_connect(fd_table.w32_ios[fd], name, namelen);
}

int
w32_recv(int fd, void *buf, size_t len, int flags)
{
	CHECK_FD(fd);

	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_recv(fd_table.w32_ios[fd], buf, len, flags);
}

int
w32_send(int fd, const void *buf, size_t len, int flags)
{
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_send(fd_table.w32_ios[fd], buf, len, flags);
}


int
w32_shutdown(int fd, int how)
{
	debug4("shutdown - fd:%d how:%d", fd, how);
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_shutdown(fd_table.w32_ios[fd], how);
}

int
w32_socketpair(int domain, int type, int protocol, int sv[2])
{
	errno = ENOTSUP;
	debug3("socketpair - ERROR not supported");
	return -1;
}


int
w32_pipe(int *pfds)
{
	int read_index, write_index;
	struct w32_io* pio[2];

	errno = 0;
	read_index = fd_table_get_min_index();
	if (read_index == -1)
		return -1;

	/*temporarily set occupied bit*/
	FD_SET(read_index, &fd_table.occupied);
	write_index = fd_table_get_min_index();
	FD_CLR(read_index, &fd_table.occupied);
	if (write_index == -1)
		return -1;

	if (-1 == fileio_pipe(pio))
		return -1;

	pio[0]->type = NONSOCK_FD;
	pio[1]->type = NONSOCK_FD;
	fd_table_set(pio[0], read_index);
	fd_table_set(pio[1], write_index);
	pfds[0] = read_index;
	pfds[1] = write_index;
	debug4("pipe - r-h:%d,io:%p,fd:%d  w-h:%d,io:%p,fd:%d",
		pio[0]->handle, pio[0], read_index, pio[1]->handle, pio[1], write_index);
	
	return 0;
}

int
w32_open(const char *pathname, int flags, ... /* arg */)
{
	int min_index = fd_table_get_min_index();
	struct w32_io* pio;
	va_list valist;
	mode_t mode = 0;

	errno = 0;
	if (min_index == -1)
		return -1;
	if (flags & O_CREAT) {
		va_start(valist, flags);
		mode = va_arg(valist, mode_t);
		va_end(valist);
	}

	pio = fileio_open(sanitized_path(pathname), flags, mode);
	
	if (pio == NULL)
		return -1;

	pio->type = NONSOCK_FD;
	fd_table_set(pio, min_index);
	debug4("open - handle:%p, io:%p, fd:%d", pio->handle, pio, min_index);
	debug5("open - path:%s", pathname);
	return min_index;
}

int
w32_read(int fd, void *dst, size_t max)
{
	CHECK_FD(fd);
	if (fd_table.w32_ios[fd]->type == SOCK_FD)
		return socketio_recv(fd_table.w32_ios[fd], dst, max, 0);

	return fileio_read(fd_table.w32_ios[fd], dst, max);
}

int
w32_write(int fd, const void *buf, size_t max)
{
	CHECK_FD(fd);

	if (fd_table.w32_ios[fd]->type == SOCK_FD)
		return socketio_send(fd_table.w32_ios[fd], buf, max, 0);

	return fileio_write(fd_table.w32_ios[fd], buf, max);
}

int
w32_writev(int fd, const struct iovec *iov, int iovcnt)
{
	int written = 0;
	int i = 0;

	CHECK_FD(fd);
	for (i = 0; i < iovcnt; i++) {
		int ret = w32_write(fd, iov[i].iov_base, iov[i].iov_len);
		if (ret > 0)
			written += ret;
	}

	return written;
}

int
w32_fstat(int fd, struct w32_stat *buf)
{
	CHECK_FD(fd);
	return fileio_fstat(fd_table.w32_ios[fd], (struct _stat64*)buf);
}

long
w32_lseek(int fd, unsigned __int64 offset, int origin)
{
	CHECK_FD(fd);
	return fileio_lseek(fd_table.w32_ios[fd], offset, origin);
}

int
w32_isatty(int fd)
{
	struct w32_io* pio;
	if ((fd < 0) || (fd > MAX_FDS - 1) || fd_table.w32_ios[fd] == NULL) {
		errno = EBADF;
		return 0;
	}

	pio = fd_table.w32_ios[fd];
	if (FILETYPE(pio) == FILE_TYPE_CHAR)
		return 1;
	else {
		errno = EINVAL;
		return 0;
	}
}

FILE*
w32_fdopen(int fd, const char *mode)
{
	errno = 0;
	if ((fd < 0) || (fd > MAX_FDS - 1) || fd_table.w32_ios[fd] == NULL) {
		errno = EBADF;
		debug3("fdopen - ERROR bad fd: %d", fd);
		return NULL;
	}
	return fileio_fdopen(fd_table.w32_ios[fd], mode);
}

int
w32_close(int fd)
{
	struct w32_io* pio;
	int r;
	if ((fd < 0) || (fd > MAX_FDS - 1) || fd_table.w32_ios[fd] == NULL) {
		errno = EBADF;
		return -1;
	}

	pio = fd_table.w32_ios[fd];

	debug4("close - io:%p, type:%d, fd:%d, table_index:%d", pio, pio->type, fd,
		pio->table_index);
	
	if (pio->type == SOCK_FD)
		r = socketio_close(pio);
	else
		r = fileio_close(pio);		

	fd_table_clear(fd);
	return r;
}

static int
w32_io_process_fd_flags(struct w32_io* pio, int flags)
{
	DWORD shi_flags;
	if (flags & ~FD_CLOEXEC) {
		debug3("fcntl - ERROR unsupported flags %d, io:%p", flags, pio);
		errno = ENOTSUP;
		return -1;
	}

	shi_flags = (flags & FD_CLOEXEC) ? 0 : HANDLE_FLAG_INHERIT;

	HANDLE h = WINHANDLE(pio);
	
	/*
	* Ignore if handle is not valid yet. It will not be valid for
	* UF_UNIX sockets that are not connected yet
	*/
	if (IS_VALID_HANDLE(h) && (SetHandleInformation(h, HANDLE_FLAG_INHERIT, shi_flags) == FALSE)) {
		debug3("fcntl - SetHandleInformation failed with error:%d, io:%p",
			GetLastError(), pio);
		errno = EOTHER;
		return -1;
	}

	pio->fd_flags = flags;
	return 0;
}

int
w32_fcntl(int fd, int cmd, ... /* arg */)
{
	va_list valist;
	va_start(valist, cmd);
	int ret = 0;

	CHECK_FD(fd);

	switch (cmd) {
	case F_GETFL:
		ret = fd_table.w32_ios[fd]->fd_status_flags;
		break;
	case F_SETFL:
		fd_table.w32_ios[fd]->fd_status_flags = va_arg(valist, int);
		ret = 0;
		break;
	case F_GETFD:
		ret = fd_table.w32_ios[fd]->fd_flags;
		break;
	case F_SETFD:
		ret = w32_io_process_fd_flags(fd_table.w32_ios[fd], va_arg(valist, int));
		break;
	default:
		errno = EINVAL;
		debug3("fcntl - ERROR not supported cmd:%d", cmd);
		ret = -1;
		break;
	}

	va_end(valist);
	return ret;
}

#define SELECT_EVENT_LIMIT 32
int
w32_select(int fds, w32_fd_set* readfds, w32_fd_set* writefds, w32_fd_set* exceptfds, const struct timeval *timeout)
{
	ULONGLONG ticks_start = GetTickCount64(), ticks_spent;
	w32_fd_set read_ready_fds, write_ready_fds;
	HANDLE events[SELECT_EVENT_LIMIT];
	int num_events = 0;
	int in_set_fds = 0, out_ready_fds = 0, i;
	unsigned int timeout_ms = 0, time_rem = 0;

	errno = 0;
	/* TODO - the size of these can be reduced based on fds */
	memset(&read_ready_fds, 0, sizeof(w32_fd_set));
	memset(&write_ready_fds, 0, sizeof(w32_fd_set));

	if (timeout)
		timeout_ms = timeout->tv_sec * 1000 + timeout->tv_usec / 1000;

	if (fds > MAX_FDS) {
		errno = EINVAL;
		debug3("select - ERROR: invalid fds: %d", fds);
		return -1;
	}

	if (!readfds && !writefds) {
		errno = EINVAL;
		debug3("select - ERROR: null fd_sets");
		return -1;
	}

	/* TODO - see if this needs to be supported */
	if (exceptfds) {
		for (i = 0; i < fds; i++)
			FD_CLR(i, exceptfds);
	}

	if (readfds) {
		for (i = 0; i < fds; i++)
			if (FD_ISSET(i, readfds)) {
				CHECK_FD(i);
				in_set_fds++;
			}
	}

	if (writefds) {
		for (i = 0; i < fds; i++)
			if (FD_ISSET(i, writefds)) {
				CHECK_FD(i);
				in_set_fds++;
			}
	}

	/* if none of input fds are set return error */
	if (in_set_fds == 0) {
		errno = EINVAL;
		debug3("select - ERROR: empty fd_sets");
		return -1;
	}

	debug5("Total in fds:%d", in_set_fds);
	/*
	 * start async io on selected fds if needed and pick up any events
	 * that select needs to listen on
	 */
	for (int i = 0; i < fds; i++) {
		if (readfds && FD_ISSET(i, readfds)) {
			w32_io_on_select(fd_table.w32_ios[i], TRUE);
			if ((fd_table.w32_ios[i]->type == SOCK_FD) &&
			    (fd_table.w32_ios[i]->internal.state == SOCK_LISTENING)) {
				if (num_events == SELECT_EVENT_LIMIT) {
					debug3("select - ERROR: max #events breach");
					errno = ENOMEM;
					return -1;
				}
				events[num_events++] = fd_table.w32_ios[i]->read_overlapped.hEvent;
			}
		}

		if (writefds && FD_ISSET(i, writefds)) {
			w32_io_on_select(fd_table.w32_ios[i], FALSE);
			if ((fd_table.w32_ios[i]->type == SOCK_FD) &&
			    (fd_table.w32_ios[i]->internal.state == SOCK_CONNECTING)) {
				if (num_events == SELECT_EVENT_LIMIT) {
					debug3("select - ERROR: max #events reached for select");
					errno = ENOMEM;
					return -1;
				}
				events[num_events++] = fd_table.w32_ios[i]->write_overlapped.hEvent;
			}
		}
	}

	/* excute any scheduled APCs */
	if (0 != wait_for_any_event(NULL, 0, 0))
		return -1;

	/* see if any io is ready */
	for (i = 0; i < fds; i++) {
		if (readfds && FD_ISSET(i, readfds)) {
			if (w32_io_is_io_available(fd_table.w32_ios[i], TRUE)) {
				FD_SET(i, &read_ready_fds);
				out_ready_fds++;
			}
		}

		if (writefds && FD_ISSET(i, writefds)) {
			if (w32_io_is_io_available(fd_table.w32_ios[i], FALSE)) {
				FD_SET(i, &write_ready_fds);
				out_ready_fds++;
			}
		}
	}

	/* timeout specified and both fields are 0 - polling mode*/
	/* proceed with further wait if not in polling mode*/
	if ((timeout == NULL) || (timeout_ms != 0))
		/* wait for io until any is ready */
		while (out_ready_fds == 0) {
			ticks_spent = GetTickCount64() - ticks_start;
			time_rem = 0;

			if (timeout != NULL) {
				if (timeout_ms < ticks_spent) {
					debug4("select - timing out");
					break;
				}
				time_rem = timeout_ms - (ticks_spent & 0xffffffff);
			}
			else
				time_rem = INFINITE;

			if (0 != wait_for_any_event(events, num_events, time_rem))
				return -1;

			/* check on fd status */
			out_ready_fds = 0;
			for (int i = 0; i < fds; i++) {
				if (readfds && FD_ISSET(i, readfds)) {
					if (w32_io_is_io_available(fd_table.w32_ios[i], TRUE)) {
						FD_SET(i, &read_ready_fds);
						out_ready_fds++;
					}
				}

				if (writefds && FD_ISSET(i, writefds)) {
					if (w32_io_is_io_available(fd_table.w32_ios[i], FALSE)) {
						FD_SET(i, &write_ready_fds);
						out_ready_fds++;
					}
				}
			}

			if (out_ready_fds == 0)
				debug5("select - wait ended without any IO completion, looping again");
		}

	/* clear out fds that are not ready yet */
	if (readfds)
		for (i = 0; i < fds; i++)
			if (FD_ISSET(i, readfds)) {
				if (FD_ISSET(i, &read_ready_fds)) {
					/* for connect() initiated sockets finish WSA connect process*/
					if ((fd_table.w32_ios[i]->type == SOCK_FD) &&
						((fd_table.w32_ios[i]->internal.state == SOCK_CONNECTING)))
						if (socketio_finish_connect(fd_table.w32_ios[i]) != 0) {
							/* async connect failed, error will be picked up by recv or send */
							errno = 0;
						}
				} else
					FD_CLR(i, readfds);
			}

	if (writefds)
		for (i = 0; i < fds; i++)
			if (FD_ISSET(i, writefds)) {
				if (FD_ISSET(i, &write_ready_fds)) {
					/* for connect() initiated sockets finish WSA connect process*/
					if ((fd_table.w32_ios[i]->type == SOCK_FD) &&
					    ((fd_table.w32_ios[i]->internal.state == SOCK_CONNECTING)))
						if (socketio_finish_connect(fd_table.w32_ios[i]) != 0) {
							/* async connect failed, error will be picked up by recv or send */
							errno = 0;
						}
				} else
					FD_CLR(i, writefds);
			}

	debug5("select - returning %d", out_ready_fds);
	return out_ready_fds;
}

int
w32_dup(int oldfd)
{
	int min_index;
	struct w32_io* pio;
	HANDLE src, target;
	CHECK_FD(oldfd);
	if (oldfd > STDERR_FILENO) {
		errno = EOPNOTSUPP;
		debug3("dup - ERROR: supports only std io, fd:%d", oldfd);
		return -1;
	}

	if ((min_index = fd_table_get_min_index()) == -1)
		return -1;

	src = GetStdHandle(fd_table.w32_ios[oldfd]->std_handle);
	if (src == INVALID_HANDLE_VALUE) {
		errno = EINVAL;
		debug3("dup - ERROR: unable to get underlying handle for std fd:%d", oldfd);
		return -1;
	}

	if (!DuplicateHandle(GetCurrentProcess(), src, GetCurrentProcess(), &target, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
		errno = EOTHER;
		debug3("dup - ERROR: DuplicatedHandle() :%d", GetLastError());
		return -1;
	}

	pio = (struct w32_io*) malloc(sizeof(struct w32_io));
	if (pio == NULL) {
		CloseHandle(target);
		errno = ENOMEM;
		debug3("dup - ERROR: %d", errno);
		return -1;
	}

	memset(pio, 0, sizeof(struct w32_io));
	pio->handle = target;
	pio->type = fd_table.w32_ios[oldfd]->type;
	fd_table_set(pio, min_index);
	return min_index;
}

int
w32_dup2(int oldfd, int newfd)
{
	CHECK_FD(oldfd);
	errno = EOPNOTSUPP;
	debug3("dup2 - ERROR: not implemented yet");
	return -1;
}

HANDLE
w32_fd_to_handle(int fd)
{
	HANDLE h = fd_table.w32_ios[fd]->handle;
	if (fd <= STDERR_FILENO)
		h = GetStdHandle(fd_table.w32_ios[fd]->std_handle);
	return h;
}

int 
w32_allocate_fd_for_handle(HANDLE h, BOOL is_sock)
{
	int min_index = fd_table_get_min_index();
	struct w32_io* pio;

	if (min_index == -1) {
		return -1;
	}

	pio = malloc(sizeof(struct w32_io));
	if (pio == NULL) {
		errno = ENOMEM;
		return -1;
	}
	memset(pio, 0, sizeof(struct w32_io));

	pio->type = is_sock ? SOCK_FD : NONSOCK_FD;
	pio->handle = h;

	/* TODO - get socket state and confirm that its connected */
	pio->internal.state = SOCK_READY;
	fd_table_set(pio, min_index);
	return min_index;
}


int
w32_ftruncate(int fd, off_t length)
{
	LARGE_INTEGER new_postion;
	CHECK_FD(fd);

	new_postion.QuadPart = length;
	if (!SetFilePointerEx(w32_fd_to_handle(fd), new_postion, 0, FILE_BEGIN))
		return -1;
	if (!SetEndOfFile(w32_fd_to_handle(fd)))
		return -1;

	return 0;
}

int
w32_fsync(int fd)
{
	CHECK_FD(fd);
	return FlushFileBuffers(w32_fd_to_handle(fd));
}


/*
* spawn a child process
* - specified by cmd with agruments argv
* - with std handles set to in, out, err
* - flags are passed to CreateProcess call
*
* cmd will be internally decoarated with a set of '"'
* to account for any spaces within the commandline
* this decoration is done only when additional arguments are passed in argv
*/
int
spawn_child(char* cmd, char** argv, int in, int out, int err, unsigned long flags)
{
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	BOOL b;
	char *cmdline, *t, **t1;
	DWORD cmdline_len = 0;
	wchar_t * cmdline_utf16 = NULL;
	int add_module_path = 0, ret = -1;

	/* should module path be added */
	do {
		if (!cmd)
			break;
		t = cmd;
		if (*t == '\"')
			t++;
		if (t[0] == '\0' || t[0] == '\\' || t[0] == '.' || t[1] == ':')
			break;
		add_module_path = 1;
	} while (0);

	/* compute total cmdline len*/
	if (add_module_path)
		cmdline_len += (DWORD)strlen(w32_programdir()) + 1 + (DWORD)strlen(cmd) + 1 + 2;
	else
		cmdline_len += (DWORD)strlen(cmd) + 1 + 2;

	if (argv) {
		t1 = argv;
		while (*t1)
			cmdline_len += (DWORD)strlen(*t1++) + 1 + 2;
	}

	if ((cmdline = malloc(cmdline_len)) == NULL) {
		errno = ENOMEM;
		goto cleanup;
	}

	/* add current module path to start if needed */
	t = cmdline;
	if (argv && argv[0])
		*t++ = '\"';
	if (add_module_path) {
		memcpy(t, w32_programdir(), strlen(w32_programdir()));
		t += strlen(w32_programdir());
		*t++ = '\\';
	}

	memcpy(t, cmd, strlen(cmd));
	t += strlen(cmd);

	if (argv && argv[0])
		*t++ = '\"';

	if (argv) {
		t1 = argv;
		while (*t1) {
			*t++ = ' ';
			*t++ = '\"';
			memcpy(t, *t1, strlen(*t1));
			t += strlen(*t1);
			*t++ = '\"';
			t1++;
		}
	}

	*t = '\0';

	if ((cmdline_utf16 = utf8_to_utf16(cmdline)) == NULL) {
		errno = ENOMEM;
		goto cleanup;
	}

	memset(&si, 0, sizeof(STARTUPINFOW));
	si.cb = sizeof(STARTUPINFOW);
	si.hStdInput = w32_fd_to_handle(in);
	si.hStdOutput = w32_fd_to_handle(out);
	si.hStdError = w32_fd_to_handle(err);
	si.dwFlags = STARTF_USESTDHANDLES;

	debug3("spawning %ls", cmdline_utf16);
	if (fd_table.w32_ios[in]->type != NONSOCK_SYNC_FD)
		_putenv_s(SSH_ASYNC_STDIN, "1");
	if (fd_table.w32_ios[out]->type != NONSOCK_SYNC_FD)
		_putenv_s(SSH_ASYNC_STDOUT, "1");
	if (fd_table.w32_ios[err]->type != NONSOCK_SYNC_FD)
		_putenv_s(SSH_ASYNC_STDERR, "1");
	b = CreateProcessW(NULL, cmdline_utf16, NULL, NULL, TRUE, flags, NULL, NULL, &si, &pi);
	_putenv_s(SSH_ASYNC_STDIN, "");
	_putenv_s(SSH_ASYNC_STDOUT, "");
	_putenv_s(SSH_ASYNC_STDERR, "");

	if (b) {
		if (register_child(pi.hProcess, pi.dwProcessId) == -1) {
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			goto cleanup;
		}
		CloseHandle(pi.hThread);
	}
	else {
		errno = GetLastError();
		goto cleanup;
	}

	ret = pi.dwProcessId;
cleanup:
	if (cmdline)
		free(cmdline);
	if (cmdline_utf16)
		free(cmdline_utf16);

	return ret;
}
