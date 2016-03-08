/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Implementation of POSIX APIs
*/
#include "inc\w32posix.h"
#include "w32fd.h"
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <assert.h>

/* internal table that stores the fd to w32_io mapping*/
struct w32fd_table {
	w32_fd_set occupied;		/*bit map for tracking occipied table entries*/
	struct w32_io* w32_ios[MAX_FDS];/*array of references to mapped w32_io objects*/
};

/* mapping table*/
static struct w32fd_table fd_table;

/* static table entries representing std in, out and error*/
static struct w32_io w32_io_stdin, w32_io_stdout, w32_io_stderr;

void fd_table_set(struct w32_io* pio, int index);

/* initializes mapping table*/
static int
fd_table_initialize() {
	memset(&fd_table, 0, sizeof(fd_table));
	memset(&w32_io_stdin, 0, sizeof(w32_io_stdin));
	w32_io_stdin.std_handle = STD_INPUT_HANDLE;
	w32_io_stdin.type = STD_IO_FD;
	fd_table_set(&w32_io_stdin, STDIN_FILENO);
	memset(&w32_io_stdout, 0, sizeof(w32_io_stdout));
	w32_io_stdout.std_handle = STD_OUTPUT_HANDLE;
	w32_io_stdout.type = STD_IO_FD;
	fd_table_set(&w32_io_stdout, STDOUT_FILENO);
	memset(&w32_io_stderr, 0, sizeof(w32_io_stderr));
	w32_io_stderr.std_handle = STD_ERROR_HANDLE;
	w32_io_stderr.type = STD_IO_FD;
	fd_table_set(&w32_io_stderr, STDERR_FILENO);
	return 0;
}

/* get a free slot in mapping table with least index*/
static int
fd_table_get_min_index() {
	int min_index = 0;
	unsigned char* bitmap = fd_table.occupied.bitmap;
	unsigned char tmp;

	while (*bitmap == 0xff) {
		bitmap++;
		min_index += 8;
		if (min_index >= MAX_FDS) {
			errno = EMFILE;
			debug("ERROR: MAX_FDS limit reached");
			return -1;
		}
	}

	tmp = *bitmap;

	while (tmp & 0x80)
	{
		tmp <<= 1;
		min_index++;
	}

	return min_index;
}

/* maps pio to fd (specified by index)*/
static void
fd_table_set(struct w32_io* pio, int index) {
	fd_table.w32_ios[index] = pio;
	pio->table_index = index;
	assert(pio->type != UNKNOWN_FD);
	FD_SET(index, &(fd_table.occupied));
}

/* removes entry at index from mapping table*/
static void
fd_table_clear(int index)
{
	fd_table.w32_ios[index]->table_index = -1;
	fd_table.w32_ios[index] = NULL;
	FD_CLR(index, &(fd_table.occupied));
}

void
w32posix_initialize() {
	if ( (fd_table_initialize() != 0)
	    || (socketio_initialize() != 0))
		abort();
}

void
w32posix_done() {
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
w32_io_is_io_available(struct w32_io* pio, BOOL rd) {
	if (pio->type == SOCK_FD)
		return socketio_is_io_available(pio, rd);
	else
		return fileio_is_io_available(pio, rd);
}

int
w32_io_on_select(struct w32_io* pio, BOOL rd)
{
	if ((pio->type == SOCK_FD))
		return socketio_on_select(pio, rd);
	else
		return fileio_on_select(pio, rd);
}

#define CHECK_FD(fd) do {							\
	errno = 0;                                                              \
	if ((fd < 0) || (fd > MAX_FDS - 1) || fd_table.w32_ios[fd] == NULL) {   \
		errno = EBADF;                                                  \
		debug("ERROR: bad fd: %d", fd);                                 \
		return -1;                                                      \
	}                                                                       \
} while (0)

#define CHECK_SOCK_IO(pio) do {                                             \
	errno = 0;                                                          \
	if (pio->type != SOCK_FD) {                                         \
		errno = ENOTSOCK;                                           \
		debug("ERROR: non sock fd type:%d", pio->type);             \
		return -1;                                                  \
	}                                                                   \
} while (0)

int
w32_socket(int domain, int type, int protocol) {
	int min_index = fd_table_get_min_index();
	struct w32_io* pio = NULL;

	errno = 0;
	if (min_index == -1)
		return -1;

	pio = socketio_socket(domain, type, protocol);
	if (pio == NULL)
		return -1;

	pio->type = SOCK_FD;
	fd_table_set(pio, min_index);
	debug("socket:%d, io:%p, fd:%d ", pio->sock, pio, min_index);
	return min_index;
}

int
w32_accept(int fd, struct sockaddr* addr, int* addrlen)
{
	debug3("fd:%d", fd);
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
	debug("socket:%d, io:%p, fd:%d ", pio->sock, pio, min_index);
	return min_index;
}

int
w32_setsockopt(int fd, int level, int optname, const char* optval, int optlen) {
	debug3("fd:%d", fd);
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_setsockopt(fd_table.w32_ios[fd], level, optname, optval, optlen);
}

int
w32_getsockopt(int fd, int level, int optname, char* optval, int* optlen) {
	debug3("fd:%d", fd);
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_getsockopt(fd_table.w32_ios[fd], level, optname, optval, optlen);
}

int
w32_getsockname(int fd, struct sockaddr* name, int* namelen) {
	debug3("fd:%d", fd);
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_getsockname(fd_table.w32_ios[fd], name, namelen);
}

int
w32_getpeername(int fd, struct sockaddr* name, int* namelen) {
	debug3("fd:%d", fd);
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_getpeername(fd_table.w32_ios[fd], name, namelen);
}

int
w32_listen(int fd, int backlog) {
	debug3("fd:%d", fd);
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_listen(fd_table.w32_ios[fd], backlog);
}

int
w32_bind(int fd, const struct sockaddr *name, int namelen) {
	debug3("fd:%d", fd);
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_bind(fd_table.w32_ios[fd], name, namelen);
}

int
w32_connect(int fd, const struct sockaddr* name, int namelen) {
	debug3("fd:%d", fd);
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_connect(fd_table.w32_ios[fd], name, namelen);
}

int
w32_recv(int fd, void *buf, size_t len, int flags) {
	debug3("fd:%d", fd);
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_recv(fd_table.w32_ios[fd], buf, len, flags);
}

int
w32_send(int fd, const void *buf, size_t len, int flags) {
	debug3("fd:%d", fd);
	CHECK_FD(fd);
	return socketio_send(fd_table.w32_ios[fd], buf, len, flags);
}


int
w32_shutdown(int fd, int how) {
	debug3("fd:%d how:%d", fd, how);
	CHECK_FD(fd);
	CHECK_SOCK_IO(fd_table.w32_ios[fd]);
	return socketio_shutdown(fd_table.w32_ios[fd], how);
}

int 
w32_socketpair(int domain, int type, int sv[2]) {
	errno = ENOTSUP;
	debug("ERROR:%d", errno);
	return -1;
}


int
w32_pipe(int *pfds) {
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

	pio[0]->type = PIPE_FD;
	pio[1]->type = PIPE_FD;
	fd_table_set(pio[0], read_index);
	fd_table_set(pio[1], write_index);
	pfds[0] = read_index;
	pfds[1] = write_index;
	debug("read end: handle:%p, io:%p, fd:%d", pio[0]->handle, pio[0], read_index);
	debug("write end: handle:%p, io:%p, fd:%d", pio[1]->handle, pio[1], write_index);
	return 0;
}

int
w32_open(const char *pathname, int flags, ...) {
	int min_index = fd_table_get_min_index();
	struct w32_io* pio;

	errno = 0;
	if (min_index == -1)
		return -1;

	pio = fileio_open(pathname, flags, 0);
	if (pio == NULL)
		return -1;

	pio->type = FILE_FD;
	fd_table_set(pio, min_index);
	debug("handle:%p, io:%p, fd:%d", pio->handle, pio, min_index);
	return min_index;
}

int
w32_read(int fd, void *dst, unsigned int max) {
	CHECK_FD(fd);
	if (fd_table.w32_ios[fd]->type == SOCK_FD)
		return socketio_recv(fd_table.w32_ios[fd], dst, max, 0);
	return fileio_read(fd_table.w32_ios[fd], dst, max);
}

int
w32_write(int fd, const void *buf, unsigned int max) {
	CHECK_FD(fd);
	if (fd_table.w32_ios[fd]->type == SOCK_FD)
		return socketio_send(fd_table.w32_ios[fd], buf, max, 0);
	return fileio_write(fd_table.w32_ios[fd], buf, max);
}

int
w32_fstat(int fd, struct w32_stat *buf) {
	CHECK_FD(fd);
	return fileio_fstat(fd_table.w32_ios[fd], (struct _stat64*)buf);
}

int 
w32_stat(const char *path, struct w32_stat *buf) {
	return fileio_stat(path, (struct _stat64*)buf);
}

int
w32_isatty(int fd) {
	if ((fd < 0) || (fd > MAX_FDS - 1) || fd_table.w32_ios[fd] == NULL) {
		errno = EBADF;
		return 0;
	}
	return fileio_isatty(fd_table.w32_ios[fd]);
}

FILE*
w32_fdopen(int fd, const char *mode) {
	errno = 0;
	if ((fd < 0) || (fd > MAX_FDS - 1) || fd_table.w32_ios[fd] == NULL) {
		errno = EBADF;
		debug("bad fd: %d", fd);
		return NULL;
	}
	return fileio_fdopen(fd_table.w32_ios[fd], mode);
}

int
w32_close(int fd) {
	struct w32_io* pio;

	CHECK_FD(fd);
	pio = fd_table.w32_ios[fd];

	debug("io:%p, type:%d, fd:%d, table_index:%d", pio, pio->type, fd, 
	    pio->table_index);
	fd_table_clear(pio->table_index);
	if ((pio->type == SOCK_FD))
		return socketio_close(pio);
	else
		return fileio_close(pio);
}

int
w32_fcntl(int fd, int cmd, ... /* arg */) {
	va_list valist;
	va_start(valist, cmd);

	CHECK_FD(fd);

	switch (cmd) {
	case F_GETFL:
		return fd_table.w32_ios[fd]->fd_status_flags;
	case F_SETFL:
		fd_table.w32_ios[fd]->fd_status_flags = va_arg(valist, int);
		return 0;
	case F_GETFD:
		return fd_table.w32_ios[fd]->fd_flags;
		return 0;
	case F_SETFD:
		fd_table.w32_ios[fd]->fd_flags = va_arg(valist, int);
		return 0;
	default:
		errno = EINVAL;
		debug("ERROR: cmd:%d", cmd);
		return -1;
	}
}

#define SELECT_EVENT_LIMIT 32
int
w32_select(int fds, w32_fd_set* readfds, w32_fd_set* writefds, w32_fd_set* exceptfds, 
    const struct timeval *timeout) {
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
		timeout_ms = timeout->tv_sec * 100 + timeout->tv_usec / 1000;

	if (fds > MAX_FDS) {
		errno = EINVAL;
		debug("ERROR: fds: %d", fds);
		return -1;
	}

	if (!readfds && !writefds) {
		errno = EINVAL;
		debug("ERROR: null fd_sets");
		return -1;
	}

	if (exceptfds) {
		errno = EOPNOTSUPP;
		debug("ERROR: exceptfds not supported");
		abort();
		return -1;
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
		debug("ERROR: empty fd_sets");
		return -1;
	}

	debug3("Total in fds:%d", in_set_fds);
	/*
	 * start async io on selected fds if needed and pick up any events 
	 * that select needs to listen on
	 */
	for (int i = 0; i < fds; i++) {

		if (readfds && FD_ISSET(i, readfds)) {
			if (w32_io_on_select(fd_table.w32_ios[i], TRUE) == -1)
				return -1;
			if ((fd_table.w32_ios[i]->type == SOCK_FD) 
			    && (fd_table.w32_ios[i]->internal.state == SOCK_LISTENING)) {
				if (num_events == SELECT_EVENT_LIMIT) {
					debug("ERROR: max #events reached for select");
					errno = ENOMEM;
					return -1;
				}
				events[num_events++] = fd_table.w32_ios[i]->read_overlapped.hEvent;
			}
		}

		if (writefds && FD_ISSET(i, writefds)) {
			if (w32_io_on_select(fd_table.w32_ios[i], FALSE) == -1)
				return -1;
			if ((fd_table.w32_ios[i]->type == SOCK_FD) 
			    && (fd_table.w32_ios[i]->internal.state == SOCK_CONNECTING)) {
				if (num_events == SELECT_EVENT_LIMIT) {
					debug("ERROR: max #events reached for select");
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

	/* wait for io if none is already ready */
	while (out_ready_fds == 0) {
		ticks_spent = GetTickCount64() - ticks_start;
		time_rem = 0;

		if (timeout != NULL) {
			if (timeout_ms < ticks_spent) {
				errno = ETIMEDOUT;
				debug("select timing out");
				return -1;
			}
			time_rem = timeout_ms - (ticks_spent & 0xffffffff);
		}

		if (0 != wait_for_any_event(events, num_events, time_rem))
			return -1;

		/* check on fd status */
		out_ready_fds = 0;
		for (int i = 0; i < fds; i++) {

			if (readfds && FD_ISSET(i, readfds)) {
				in_set_fds++;
				if (w32_io_is_io_available(fd_table.w32_ios[i], TRUE)) {
					FD_SET(i, &read_ready_fds);
					out_ready_fds++;
				}
			}

			if (writefds && FD_ISSET(i, writefds)) {
				in_set_fds++;
				if (w32_io_is_io_available(fd_table.w32_ios[i], FALSE)) {
					FD_SET(i, &write_ready_fds);
					out_ready_fds++;
				}
			}
		}

		if (out_ready_fds == 0) {
			if (timeout == 0) {
				/* not timeout specified, return EAGAIN if none of fds are ready */
				errno = EAGAIN;
				return -1;
			}
			debug2("wait ended without any IO completion, looping again");
		}

	};
	
	/* clear out fds that are not ready yet */
	if (readfds)
		for (i = 0; i < fds; i++)
			if (FD_ISSET(i, readfds) && (!FD_ISSET(i, &read_ready_fds)))
				FD_CLR(i, readfds);			
	
	if (writefds)
		for (i = 0; i < fds; i++)
			if (FD_ISSET(i, writefds) && (!FD_ISSET(i, &write_ready_fds)))
				FD_CLR(i, writefds);


	return out_ready_fds;

}


int
w32_dup(int oldfd) {
	int min_index;
	struct w32_io* pio;
	HANDLE src, target;
	CHECK_FD(oldfd);
	if (oldfd > STDERR_FILENO) {
		errno = EOPNOTSUPP;
		debug("ERROR: dup only supported for std io, fd:%d", oldfd);
		return -1;
	}

	if ((min_index = fd_table_get_min_index()) == -1)
		return -1;

	src = GetStdHandle(fd_table.w32_ios[oldfd]->std_handle);
	if (src == INVALID_HANDLE_VALUE) {
		errno = EINVAL;
		debug("ERROR: unable to get underlying handle for std fd:%d", oldfd);
		return -1;
	}

	if ((oldfd == STDIN_FILENO) && (GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_CHAR)) {
		target = CreateFile(L"CONIN$", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);
		if (target == INVALID_HANDLE_VALUE) {
			errno = EOTHER;
			debug("ERROR: CreateFile CONIN$ failed, error:%d", GetLastError());
			return -1;
		}
	}
	else if (!DuplicateHandle(GetCurrentProcess(), src, GetCurrentProcess(), &target, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
		errno = EOTHER;
		debug("ERROR: Duplicated Handle failed, error:%d", GetLastError());
		return -1;
	}

	pio = (struct w32_io*) malloc(sizeof(struct w32_io));
	if (pio == NULL) {
		CloseHandle(target);
		errno = ENOMEM;
		debug("ERROR: %d", errno);
		return -1;
	}

	memset(pio, 0, sizeof(struct w32_io));
	pio->handle = target;
	pio->type = FILE_FD;
	fd_table_set(pio, min_index);
	return min_index;
}

int
w32_dup2(int oldfd, int newfd) {
	CHECK_FD(oldfd);
	errno = EOPNOTSUPP;
	debug("ERROR: dup2 is not implemented yet");
	return -1;
}

unsigned int 
w32_alarm(unsigned int seconds) {
	/*TODO -  implement alarm */
	return 0;
}

sighandler_t w32_signal(int signum, sighandler_t handler) {
	/*TODO - implement signal()*/
	return 0;
}

int 
w32_temp_DelChildToWatch(HANDLE processtowatch) {
	return 0;
}

int w32_temp_AddChildToWatch(HANDLE processtowatch) {
    return 0;
}

HANDLE 
w32_fd_to_handle(int fd) {
	return fd_table.w32_ios[fd]->handle;
}

int w32_allocate_fd_for_handle(HANDLE h) {
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

	pio->type = FILE_FD;
	pio->handle = h;
	fd_table_set(pio, min_index);
	return min_index;
}
