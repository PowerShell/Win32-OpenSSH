#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include "test_helper.h"

#define PORT "34912"  
#define BACKLOG 2  
#define SMALL_RECV_BUF_SIZE 128

int listen_fd, accept_fd, connect_fd, ret;
struct addrinfo hints,*servinfo;
fd_set read_set, write_set, except_set;
struct timeval time_val;
struct sockaddr_storage their_addr;
char* send_buf, recv_buf;

int
unset_nonblock(int fd)
{
    int val;

    val = fcntl(fd, F_GETFL, 0);
    if (val < 0) {
        return (-1);
    }
    if (!(val & O_NONBLOCK)) {
        return (0);
    }
    val &= ~O_NONBLOCK;
    if (fcntl(fd, F_SETFL, val) == -1) {
        return (-1);
    }
    return (0);
}

int
set_nonblock(int fd)
{
    int val;

    val = fcntl(fd, F_GETFL, 0);
    if (val < 0) {
        return (-1);
    }
    if (val & O_NONBLOCK) {
        return (0);
    }
    val |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, val) == -1) {
        return (-1);
    }
    return (0);

}

void socket_fd_tests()
{
    fd_set set,*pset;
    pset = &set;
    
    TEST_START("fd_set initial state");
    FD_ZERO(pset);
    ASSERT_CHAR_EQ(0, FD_ISSET(0, pset));
    ASSERT_CHAR_EQ(0, FD_ISSET(1, pset));
    ASSERT_CHAR_EQ(0, FD_ISSET(2, pset));
    TEST_DONE();

    TEST_START("FD_SET");
    FD_SET(0, pset);
    FD_SET(1, pset);
    ASSERT_CHAR_EQ(1, FD_ISSET(0, pset));
    ASSERT_CHAR_EQ(1, FD_ISSET(1, pset));
    ASSERT_CHAR_EQ(0, FD_ISSET(2, pset));
    TEST_DONE();
    
    TEST_START("FD_CLR");
    FD_CLR(0, pset);
    ASSERT_CHAR_EQ(0, FD_ISSET(0, pset));
    ASSERT_CHAR_EQ(1, FD_ISSET(1, pset));
    ASSERT_CHAR_EQ(0, FD_ISSET(2, pset));
    TEST_DONE();

    TEST_START("FD_ZERO");
    FD_ZERO(pset);
    ASSERT_CHAR_EQ(0, FD_ISSET(0, pset));
    ASSERT_CHAR_EQ(0, FD_ISSET(1, pset));
    ASSERT_CHAR_EQ(0, FD_ISSET(2, pset));
    TEST_DONE();


    TEST_START("BAD FDs");
    ASSERT_INT_EQ(accept(-1, NULL, NULL), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(setsockopt(MAX_FDS, 0, 0, NULL, 0), -1);
    ASSERT_INT_EQ(errno, EBADF);
    /*0,1,2 fd's are initialized */
    ASSERT_INT_EQ(getsockopt(3, 0, 0, NULL, NULL), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(getsockname(4, NULL, NULL), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(getpeername(5, NULL, NULL), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(listen(6, 2), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(bind(7, NULL, 0), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(connect(8, NULL, 0), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(recv(9, NULL, 0, 0), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(send(10, NULL, 0,0), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(shutdown(11, 0), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(read(MAX_FDS + 1, NULL, 0), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(write(INFINITE, NULL, 0), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(fstat(11, NULL), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(isatty(12), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(fdopen(13,NULL), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(close(14), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(fcntl(15, 1), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(dup(16), -1);
    ASSERT_INT_EQ(errno, EBADF);
    ASSERT_INT_EQ(dup2(17, 18), -1);
    ASSERT_INT_EQ(errno, EBADF);
    FD_ZERO(&read_set);
    FD_SET(20, &read_set);
    ASSERT_INT_EQ(select(21, &read_set, NULL, NULL, &time_val), -1);
    ASSERT_INT_EQ(errno, EBADF);
    FD_ZERO(&write_set);
    FD_SET(21, &write_set);
    ASSERT_INT_EQ(select(22, NULL, &write_set, NULL, &time_val), -1);
    ASSERT_INT_EQ(errno, EBADF);
    TEST_DONE();

    TEST_START("min fd allocation");
    connect_fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_INT_EQ(connect_fd, 3);
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_INT_EQ(listen_fd, 4);
    close(connect_fd);
    connect_fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_INT_EQ(connect_fd, 3); /*minimum free fd gets allocated*/
    close(connect_fd);
    close(listen_fd);
    TEST_DONE();

}

void socket_blocing_io_tests()
{
    char* small_send_buf = "sample payload";
    char small_recv_buf[SMALL_RECV_BUF_SIZE];

    TEST_START("Basic IPv4 client server connection setup");
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    ret = getaddrinfo("127.0.0.1", PORT, &hints, &servinfo);
    ASSERT_INT_EQ(ret, 0);
    listen_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    ASSERT_INT_NE(listen_fd, -1);
    ret = bind(listen_fd, servinfo->ai_addr, servinfo->ai_addrlen);
    ASSERT_INT_EQ(ret, 0);
    ret = listen(listen_fd, BACKLOG);
    ASSERT_INT_EQ(ret, 0);
    //call listen again??
    connect_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    ASSERT_INT_NE(connect_fd, -1);
    ret = connect(connect_fd, servinfo->ai_addr, servinfo->ai_addrlen);
    ASSERT_INT_EQ(ret, 0);
    //call connect again??
    accept_fd = accept(listen_fd, (struct sockaddr*)&their_addr, sizeof(their_addr));
    ASSERT_INT_NE(accept_fd, -1);
    ret = close(listen_fd);
    ASSERT_INT_EQ(ret, 0);
    //call accept after listen_fd is closed??
    TEST_DONE();

    TEST_START("send failures");
    ret = send(accept_fd, NULL, 4, 0);/*invalid buffer*/
    ASSERT_INT_EQ(ret, -1);
    ASSERT_INT_EQ(errno, EINVAL);
    ret = send(accept_fd, small_send_buf, 0, 0); /*invalid buffer*/
    ASSERT_INT_EQ(ret, -1);
    ASSERT_INT_EQ(errno, EINVAL);
    ret = send(accept_fd, small_send_buf, strlen(small_send_buf), 4); /*flags not supported yet*/
    ASSERT_INT_EQ(ret, -1);
    ASSERT_INT_EQ(errno, ENOTSUP);
    TEST_DONE();

    TEST_START("basic send s->c");
    ret = send(accept_fd, small_send_buf, strlen(small_send_buf), 0);
    ASSERT_INT_EQ(ret, strlen(small_send_buf));
    TEST_DONE();

    TEST_START("recv failures");
    ret = recv(connect_fd, NULL, SMALL_RECV_BUF_SIZE, 0); /* invalid buffer*/
    ASSERT_INT_EQ(ret, -1);
    ASSERT_INT_EQ(errno, EINVAL);
    ret = recv(connect_fd, small_recv_buf, 0, 0); /*invalid buffer*/
    ASSERT_INT_EQ(ret, -1);
    ASSERT_INT_EQ(errno, EINVAL);
    ret = recv(connect_fd, small_recv_buf, SMALL_RECV_BUF_SIZE, 6); /*flags not supported yet*/
    ASSERT_INT_EQ(ret, -1);
    ASSERT_INT_EQ(errno, ENOTSUP);
    TEST_DONE();

    TEST_START("basic recv s->c");
    ret = recv(connect_fd, small_recv_buf, SMALL_RECV_BUF_SIZE, 0);
    ASSERT_INT_EQ(ret, strlen(small_send_buf));
    small_recv_buf[ret] = '\0';
    ASSERT_STRING_EQ(small_send_buf, small_recv_buf);
    memset(small_recv_buf, 0, sizeof(small_recv_buf));
    TEST_DONE();

    TEST_START("basic send recv c->s");
    ret = send(connect_fd, small_send_buf, strlen(small_send_buf), 0);
    ASSERT_INT_EQ(ret, strlen(small_send_buf));
    ret = recv(accept_fd, small_recv_buf, SMALL_RECV_BUF_SIZE, 0);
    ASSERT_INT_EQ(ret, strlen(small_send_buf));
    small_recv_buf[ret] = '\0';
    ASSERT_STRING_EQ(small_send_buf, small_recv_buf);
    memset(small_recv_buf, 0, sizeof(small_recv_buf));
    TEST_DONE();

    TEST_START("shutdown SD_SEND");
    ret = shutdown(connect_fd, SD_SEND);
    ASSERT_INT_EQ(ret, 0);
    ret = recv(accept_fd, small_recv_buf, SMALL_RECV_BUF_SIZE, 0); /* send on other side is shutdown*/
    ASSERT_INT_EQ(ret, 0);
    ret = shutdown(accept_fd, SD_SEND);
    ASSERT_INT_EQ(ret, 0);
    ret = recv(connect_fd, small_recv_buf, SMALL_RECV_BUF_SIZE, 0); /* send on other side is shutdown*/
    ASSERT_INT_EQ(ret, 0);
    TEST_DONE();

    TEST_START("shutdown SD_RECEIVE");
    ret = shutdown(connect_fd, SD_RECEIVE);
    ASSERT_INT_EQ(ret, 0);
    ret = send(accept_fd, small_send_buf, strlen(small_send_buf), 0);
    ASSERT_INT_EQ(ret, -1);
    ASSERT_INT_EQ(errno, ECONNRESET);
    ret = shutdown(accept_fd, SD_RECEIVE);
    ASSERT_INT_EQ(ret, 0);
    ret = send(connect_fd, small_send_buf, strlen(small_send_buf), 0);
    ASSERT_INT_EQ(ret, -1);
    ASSERT_INT_EQ(errno, ECONNRESET);
    TEST_DONE();

    TEST_START("basic close");
    ret = close(connect_fd);
    ASSERT_INT_EQ(ret, 0);
    ret = close(accept_fd);
    ASSERT_INT_EQ(ret, 0);
    TEST_DONE();

    freeaddrinfo(servinfo);
}

void socket_nonblocking_io_tests()
{
    char* small_send_buf = "sample payload";
    char small_recv_buf[SMALL_RECV_BUF_SIZE];

    TEST_START("IPv6 sockets setup");
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    ret = getaddrinfo("::1", PORT, &hints, &servinfo);
    ASSERT_INT_EQ(ret, 0);
    listen_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    ASSERT_INT_NE(listen_fd, -1);
    ret = bind(listen_fd, servinfo->ai_addr, servinfo->ai_addrlen);
    ASSERT_INT_EQ(ret, 0);
    ret = listen(listen_fd, BACKLOG);
    ASSERT_INT_EQ(ret, 0);
    connect_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    ASSERT_INT_NE(connect_fd, -1);
    TEST_DONE();

    TEST_START("non blocking accept and connect");
    ret = set_nonblock(listen_fd);
    ASSERT_INT_EQ(ret, 0);
    accept_fd = accept(listen_fd, (struct sockaddr*)&their_addr, sizeof(their_addr));
    ASSERT_INT_EQ(accept_fd, -1);
    ASSERT_INT_EQ(errno, EAGAIN);
    ret = set_nonblock(connect_fd);
    ASSERT_INT_EQ(ret, 0);
    ret = connect(connect_fd, servinfo->ai_addr, servinfo->ai_addrlen);
    /* connect is too fast to block
    ASSERT_INT_EQ(ret, -1);
    ASSERT_INT_EQ(errno, EINPROGRESS); */
    ASSERT_INT_EQ(ret, 0);
    accept_fd = accept(listen_fd, (struct sockaddr*)&their_addr, sizeof(their_addr));
    ASSERT_INT_NE(accept_fd, -1);
    ret = close(listen_fd);
    ASSERT_INT_EQ(ret, 0);
    TEST_DONE();

    TEST_START("non blocking recv");
    ret = set_nonblock(connect_fd);
    ASSERT_INT_EQ(ret, 0);
    ret = recv(connect_fd, small_recv_buf, SMALL_RECV_BUF_SIZE, 0);
    ASSERT_INT_EQ(ret, -1);
    ASSERT_INT_EQ(errno, EAGAIN);
    ret = unset_nonblock(accept_fd);
    ASSERT_INT_EQ(ret, 0);
    ret = send(accept_fd, small_send_buf, strlen(small_send_buf), 0);
    ASSERT_INT_EQ(ret, strlen(small_send_buf));
    ret = unset_nonblock(connect_fd);
    ASSERT_INT_EQ(ret, 0);
    ret = recv(connect_fd, small_recv_buf, SMALL_RECV_BUF_SIZE, 0);
    ASSERT_INT_EQ(ret, strlen(small_send_buf));
    small_recv_buf[ret] = '\0';
    ASSERT_STRING_EQ(small_send_buf, small_recv_buf);
    memset(small_recv_buf, 0, sizeof(small_recv_buf));
    TEST_DONE();

    TEST_START("non blocking send");
    send_buf = malloc(10 * 1024);
    ASSERT_PTR_NE(send_buf, NULL);
    ret = set_nonblock(connect_fd);
    ASSERT_INT_EQ(ret, 0);
    ret = 1;
    while (ret > 0) {
        ret = send(connect_fd, send_buf, 10 * 1024, 0);
    }
    ASSERT_INT_EQ(ret, -1);
    ASSERT_INT_EQ(errno, EAGAIN);
    ret = close(connect_fd);
    ASSERT_INT_EQ(ret, 0);
    ret = close(accept_fd);
    ASSERT_INT_EQ(ret, 0);
    TEST_DONE();

    free(send_buf);
    freeaddrinfo(servinfo);
}

void socket_select_tests() {
    int s, r, i;
    int num_bytes = 1024 * 1024; //1MB
    int bytes_sent = 0;
    int bytes_received = 0;
    int seed = 326;

    TEST_START("select listen");
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    ret = getaddrinfo("127.0.0.1", PORT, &hints, &servinfo);
    ASSERT_INT_EQ(ret, 0);
    listen_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    ASSERT_INT_NE(listen_fd, -1);
    ret = bind(listen_fd, servinfo->ai_addr, servinfo->ai_addrlen);
    ASSERT_INT_EQ(ret, 0);
    ret = listen(listen_fd, BACKLOG);
    ASSERT_INT_EQ(ret, 0);
    connect_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    ASSERT_INT_NE(connect_fd, -1);
    ret = connect(connect_fd, servinfo->ai_addr, servinfo->ai_addrlen);
    ASSERT_INT_EQ(ret, 0);
    ret = set_nonblock(listen_fd);
    ASSERT_INT_EQ(ret, 0);
    time_val.tv_sec = 60;
    time_val.tv_usec = 0;
    FD_ZERO(&read_set);
    FD_SET(listen_fd, &read_set);
    ret = select(listen_fd + 1, &read_set, NULL, NULL, &time_val);
    ASSERT_INT_EQ(ret, 0);
    ASSERT_INT_EQ(FD_ISSET(listen_fd, &read_set), 1);
    accept_fd = accept(listen_fd, (struct sockaddr*)&their_addr, sizeof(their_addr));
    ASSERT_INT_NE(accept_fd, -1);
    ret = close(listen_fd);
    ASSERT_INT_EQ(ret, 0);
    TEST_DONE();
    
    TEST_START("select send and recv");
    s = accept_fd;
    r = connect_fd;
    ret = set_nonblock(s);
    ASSERT_INT_EQ(ret, 0);
    ret = set_nonblock(r);
    ASSERT_INT_EQ(ret, 0);
    send_buf = malloc(num_bytes);
    recv_buf = malloc(num_bytes);
    ASSERT_PTR_NE(send_buf, NULL);
    ASSERT_PTR_NE(recv_buf, NULL);
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    FD_SET(s, &write_set);
    FD_SET(r, &read_set);
    while (-1 != select(max(r,s)+1, &read_set ,&write_set, NULL, &time_val)) {
        if (FD_ISSET(s, &write_set)) {
            while (((ret = send(s, send_buf + bytes_sent, num_bytes - bytes_sent, 0)) > 0) && (bytes_sent < num_bytes))
                bytes_sent += ret;
            if (bytes_sent < num_bytes) {
                ASSERT_INT_EQ(ret, -1);
                ASSERT_INT_EQ(errno, EAGAIN);
            }
        }

        if (FD_ISSET(r, &read_set)) {
            while ((ret = recv(r, recv_buf + bytes_received, num_bytes - bytes_received, 0)) > 0)
                bytes_received += ret;
            if (ret == 0)
                break;
            ASSERT_INT_EQ(ret, -1);
            ASSERT_INT_EQ(errno, EAGAIN);
        }

        if (bytes_sent < num_bytes)
            FD_SET(s, &write_set);
        else {
            FD_CLR(s, &write_set);
            ret = shutdown(s, SD_SEND);
            ASSERT_INT_EQ(ret, 0);
        }
        FD_SET(r, &read_set);
    }

    ASSERT_INT_EQ(bytes_sent, bytes_received);
    ret = close(connect_fd);
    ASSERT_INT_EQ(ret, 0);
    ret = close(accept_fd);
    ASSERT_INT_EQ(ret, 0);

    freeaddrinfo(servinfo);
}


void socket_tests()
{
    w32posix_initialize();
    socket_fd_tests();
    socket_blocing_io_tests();
    socket_nonblocking_io_tests();
    socket_select_tests();
    w32posix_done();
}

int socket_prepare(char* ip)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(ip, PORT, &hints, &servinfo) == -1)
        return -1;

    listen_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    connect_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if ((listen_fd == -1) || (connect_fd == -1))
        return -1;

    if (-1 == bind(listen_fd, servinfo->ai_addr, servinfo->ai_addrlen))
        return -1;

    if (-1 == listen(listen_fd, BACKLOG))
        return -1;

    return 0;
}
#define READ_BUf_SIZE 1024 * 100 
#define WRITE_BUF_SIZE 1024 * 100
void sample()
{
    w32posix_initialize();
    listen_fd = -1;
    accept_fd = -1;
    connect_fd = -1;
    servinfo = NULL;

    int ret;
    
    ret = socket_prepare("127.0.0.1");
    //Assert::AreEqual(ret, 0);

    ret = connect(connect_fd, servinfo->ai_addr, servinfo->ai_addrlen);
    
    accept_fd = accept(listen_fd, NULL, NULL);
    //Assert::AreNotEqual(accept_fd, -1, L"", LINE_INFO());

    //close(listen_fd);
    //listen_fd = -1;

    int c = connect_fd;
    int s = accept_fd;

    set_nonblock(c);
    set_nonblock(s);

    char *to_write = (char*)malloc(WRITE_BUF_SIZE);

    char *read_to = (char*)malloc(READ_BUf_SIZE);

    //write from c, read from s
    fd_set read_set;
    fd_set write_set;
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    FD_SET(s, &read_set);
    FD_SET(c, &write_set);
    int max_fd = max(c, s) + 1;
    struct timeval time;
    time.tv_sec = 60 * 60;
    time.tv_usec = 0;
    long long bytes_written = 0;
    long long bytes_read = 0;

    while (-1 != select(max_fd, &read_set, &write_set, NULL, &time))
    {
        BOOL read_ready = FD_ISSET(s, &read_set);
        BOOL write_ready = FD_ISSET(c, &write_set);
        FD_ZERO(&read_set);
        FD_ZERO(&write_set);
        FD_SET(s, &read_set);

        if (write_ready)
        {

#define WR_LIMIT  WRITE_BUF_SIZE*5                  

            int bw = 0;// send(c, to_write, WRITE_BUF_SIZE, 0);
            while ((bw != -1) && (bytes_written < WR_LIMIT)) {

                bw = send(c, to_write, WRITE_BUF_SIZE, 0);
                if (bw > 0)
                    bytes_written += bw;
                else {
                    ret = errno;
                    //Assert::AreEqual(errno, EAGAIN, L"", LINE_INFO());
                }

            }

            if (bytes_written >= WR_LIMIT)
            {
                ret = shutdown(c, SD_SEND);
                //Assert::AreEqual(ret, 0, L"", LINE_INFO());
            }
            else
                FD_SET(c, &write_set);
        }



        if (read_ready)
        {
            int br = read(s, read_to, READ_BUf_SIZE);
            while (br > 1) {
                bytes_read += br;
                br = read(s, read_to, READ_BUf_SIZE);
            }

            if (br == 0) //send from other side is done
                break;
            ret = errno;
            //Assert::AreEqual(errno, EAGAIN, L"", LINE_INFO());
        }

    }

    //Assert::AreEqual((bytes_written == bytes_read) ? 1 : 0, TRUE, L"", LINE_INFO());

    if (servinfo) freeaddrinfo(servinfo);
    if (listen_fd != -1)  close(listen_fd);
    if (connect_fd != -1)  close(connect_fd);
    if (accept_fd != -1)  close(accept_fd);
    w32posix_done();
}

