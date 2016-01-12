#include "w32posix.h"
#include "w32fd.h"
#include <stdarg.h>
#include <errno.h>

struct w32fd_table {
    w32_fd_set occupied;
    struct w32_io* w32_ios[MAX_FDS];
};

struct w32fd_table fd_table;

int fd_table_initialize() {
    memset(&fd_table, 0, sizeof(fd_table));
    //set stdin, stdout and stderr
    return 0;
}

int fd_table_get_min_index() {
    int min_index = 0;
    unsigned char* bitmap = fd_table.occupied.bitmap;
    unsigned char tmp;

    while (*bitmap == 0xff)
    {
        bitmap++;
        min_index += 8;
        if (min_index >= MAX_FDS) {
            errno = ENOMEM;
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

void fd_table_set(struct w32_io* pio, int index) {

    fd_table.w32_ios[index] = pio;
    pio->table_index = index;
    FD_SET(index, &(fd_table.occupied));
}

void fd_table_clear(int index)
{
    fd_table.w32_ios[index]->table_index = -1;
    fd_table.w32_ios[index] = NULL;
    FD_CLR(index, &(fd_table.occupied));
}

void w32posix_initialize() {
    fd_table_initialize();
    socketio_initialize();
}

void w32posix_done() {
    socketio_done();
}

BOOL w32_io_is_blocking(struct w32_io* pio)
{
    return (pio->fd_status_flags & O_NONBLOCK) ? FALSE : TRUE;
}

BOOL w32_io_is_io_available(struct w32_io* pio, BOOL rd) {
    if ((pio->type == LISTEN_FD) || (pio->type == SOCK_FD)) {
        return socketio_is_io_available(pio, rd);
    }
    else {
        //return fileio_is_ready(pio);
        return FALSE;
    }

}

int w32_io_on_select(struct w32_io* pio, BOOL rd)
{
    if ((pio->type == LISTEN_FD) || (pio->type == SOCK_FD)) {
        return socketio_on_select(pio, rd);
    }
    else {
        //return fileio_start_io(pio);
        return -1;
    }

}

int w32_socket(int domain, int type, int protocol) {
    int min_index = fd_table_get_min_index();
    struct w32_io* pio = NULL;

    if (min_index == -1)
        return -1;

    pio = socketio_socket(domain, type, protocol);
    if (!pio) {
        return -1;
    }

    fd_table_set(pio, min_index);
    return min_index;
}

int w32_accept(int fd, struct sockaddr* addr, int* addrlen)
{
    int min_index = fd_table_get_min_index();
    struct w32_io* pio = NULL;

    if (min_index == -1)
        return -1;

    pio = socketio_accept(fd_table.w32_ios[fd], addr, addrlen);
    if (!pio) {
        return -1;
    }

    fd_table_set(pio, min_index);
    return min_index;
}

int w32_setsockopt(int fd, int level, int optname, const char* optval, int optlen) {
    return socketio_setsockopt(fd_table.w32_ios[fd], level, optname, optval, optlen);
}

int w32_getsockopt(int fd, int level, int optname, char* optval, int* optlen) {
    return socketio_getsockopt(fd_table.w32_ios[fd], level, optname, optval, optlen);
}

int w32_getsockname(int fd, struct sockaddr* name, int* namelen) {
    return socketio_getsockname(fd_table.w32_ios[fd], name, namelen);
}

int w32_getpeername(int fd, struct sockaddr* name, int* namelen) {
    return socketio_getpeername(fd_table.w32_ios[fd], name, namelen);
}

int w32_listen(int fd, int backlog) {
    return socketio_listen(fd_table.w32_ios[fd], backlog);
}

int w32_bind(int fd, const struct sockaddr *name, int namelen) {
    return socketio_bind(fd_table.w32_ios[fd], name, namelen);
}

int w32_connect(int fd, const struct sockaddr* name, int namelen) {
    return socketio_connect(fd_table.w32_ios[fd], name, namelen);
}

int w32_recv(int fd, void *buf, size_t len, int flags) {
    return socketio_recv(fd_table.w32_ios[fd], buf, len, flags);
}

int w32_send(int fd, const void *buf, size_t len, int flags) {
    return socketio_send(fd_table.w32_ios[fd], buf, len, flags);
}


int w32_shutdown(int fd, int how) {
    return socketio_shutdown(fd_table.w32_ios[fd], how);
}

int w32_close(int fd) {
    struct w32_io* pio = fd_table.w32_ios[fd];

    fd_table_clear(pio->table_index);
    if ((pio->type == LISTEN_FD) || (pio->type == SOCK_FD)) {
        return socketio_close(pio);
    }
    else
        return -1;
}

int w32_fcntl(int fd, int cmd, ... /* arg */) {
    va_list valist;
    va_start(valist, cmd);

    switch (cmd){
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
        return -1;
    }
}

int w32_select(int fds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval *timeout) {
    int in_ready_fds = 0, out_ready_fds = 0;
    fd_set read_ready_fds, write_ready_fds;
    HANDLE events[10];
    int num_events = 0;

    memset(&read_ready_fds, 0, sizeof(fd_set));
    memset(&write_ready_fds, 0, sizeof(fd_set));

    if (fds > MAX_FDS - 1) {
        errno = EINVAL;
        return -1;
    }

    if (!readfds && !writefds && !exceptfds) {
        errno = EPERM;
        return -1;
    }


    //see if any io is ready
    for (int i = 0; i <= fds; i++) {

        if (readfds && FD_ISSET(i, readfds)) {
            if (fd_table.w32_ios[i] == NULL) {
                errno = EPERM;
                return -1;
            }

            in_ready_fds++;
            if (w32_io_is_io_available(fd_table.w32_ios[i], TRUE)) {
                FD_SET(i, &read_ready_fds);
                out_ready_fds++;
            }
        }

        if (writefds && FD_ISSET(i, writefds)) {
            if (fd_table.w32_ios[i] == NULL) {
                errno = EPERM;
                return -1;
            }

            in_ready_fds++;
            if (w32_io_is_io_available(fd_table.w32_ios[i], FALSE)) {
                FD_SET(i, &write_ready_fds);
                out_ready_fds++;
            }
        }

    }

    //if none of input fds are set return error
    if (in_ready_fds == 0) {
        errno = EINVAL;
        return -1;
    }

    //if some fds are already ready, return
    if (out_ready_fds)
    {
        if (readfds)
            *readfds = read_ready_fds;
        if (writefds)
            *writefds = write_ready_fds;
        return out_ready_fds;
    }

    //start async io on selected fds
    for (int i = 0; i <= fds; i++) {

        if (readfds && FD_ISSET(i, readfds)) {
            if (w32_io_on_select(fd_table.w32_ios[i], TRUE) == -1)
                return -1;
            if (fd_table.w32_ios[i]->type == LISTEN_FD) {
                events[num_events++] = fd_table.w32_ios[i]->read_overlapped.hEvent;
            }
        }

        if (writefds && FD_ISSET(i, writefds)) {
            if (w32_io_on_select(fd_table.w32_ios[i], FALSE) == -1)
                return -1;
        }
    }

    do {
        //to-do cut down wait time on subsequent waits
        if (0 != wait_for_any_event(events, num_events, ((timeout->tv_sec) * 1000) + ((timeout->tv_usec) / 1000))) {
            return -1;
        }

        //check on fd status
        out_ready_fds = 0;
        for (int i = 0; i <= fds; i++) {

            if (readfds && FD_ISSET(i, readfds)) {
                in_ready_fds++;
                if (w32_io_is_io_available(fd_table.w32_ios[i], TRUE)) {
                    FD_SET(i, &read_ready_fds);
                    out_ready_fds++;
                }
            }

            if (writefds && FD_ISSET(i, writefds)) {
                in_ready_fds++;
                if (w32_io_is_io_available(fd_table.w32_ios[i], FALSE)) {
                    FD_SET(i, &write_ready_fds);
                    out_ready_fds++;
                }
            }
        }

        if (out_ready_fds)
            break;

    } while (1);

    if (readfds)
        *readfds = read_ready_fds;
    if (writefds)
        *writefds = write_ready_fds;
    
    return out_ready_fds;
 
}

