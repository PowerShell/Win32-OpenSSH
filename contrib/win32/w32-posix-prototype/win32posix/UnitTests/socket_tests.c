#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include "test_helper.h"

#define PORT "34912"  
#define BACKLOG 2  

int listen_fd, accept_fd, connect_fd, ret;
struct addrinfo hints,*servinfo;
fd_set read_set, write_set, except_set;
struct timeval time_val;

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

}

socket_syncio_tests()
{
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


}

void socket_tests()
{
    w32posix_initialize();
    socket_fd_tests();
    socket_syncio_tests();
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

