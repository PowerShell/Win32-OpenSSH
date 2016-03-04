/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*/

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include "test_helper.h"

#define SMALL_RECV_BUF_SIZE 128

#pragma warning(disable:4267)

fd_set read_set, write_set, except_set;
struct timeval time_val;
char *send_buf, *recv_buf;
int ret, r, w;

int unset_nonblock(int fd);

int set_nonblock(int fd);

void prep_input_buffer(char* buf, int size, int seed);

void file_blocking_io_tests()
{
    char* small_send_buf = "sample payload";
    char small_recv_buf[SMALL_RECV_BUF_SIZE];

    TEST_START("Basic pipe()");
    int pipeio[2];
    ret = pipe(pipeio);
    ASSERT_INT_EQ(ret, 0);
    TEST_DONE();

    TEST_START("pipe read and write");
    r = pipeio[0];
    w = pipeio[1];
    ret = write(r, small_send_buf, strlen(small_send_buf));
    ASSERT_INT_EQ(ret, -1);
    ASSERT_INT_EQ(errno, EBADF);
    ret = read(w, small_recv_buf, SMALL_RECV_BUF_SIZE);
    ASSERT_INT_EQ(ret, -1);
    ASSERT_INT_EQ(errno, EBADF);
    ret = write(w, small_send_buf, strlen(small_send_buf));
    ASSERT_INT_EQ(ret, strlen(small_send_buf));
    ret = read(r, small_recv_buf, SMALL_RECV_BUF_SIZE);
    ASSERT_INT_EQ(ret, strlen(small_send_buf));
    small_recv_buf[ret] = '\0';
    ASSERT_STRING_EQ(small_send_buf, small_recv_buf);
    memset(small_recv_buf, 0, sizeof(small_recv_buf));
    TEST_DONE();

    TEST_START("close pipe fds");
    ret = close(w);
    ASSERT_INT_EQ(ret, 0);
    ret = read(r, small_recv_buf, SMALL_RECV_BUF_SIZE); /* send on other side is closed*/
    ASSERT_INT_EQ(ret, 0);
    ret = close(r);
    ASSERT_INT_EQ(ret, 0);
    TEST_DONE();
}

void file_nonblocking_io_tests()
{
    char* small_send_buf = "sample payload";
    char small_recv_buf[SMALL_RECV_BUF_SIZE];

    TEST_START("non blocking file io");
    int pipeio[2];
    ret = pipe(pipeio);
    ASSERT_INT_EQ(ret, 0);
    r = pipeio[0];
    w = pipeio[1];
    ret = set_nonblock(r);
    ASSERT_INT_EQ(ret, 0);
    ret = read(r, small_recv_buf, SMALL_RECV_BUF_SIZE);
    ASSERT_INT_EQ(ret, -1);
    ASSERT_INT_EQ(errno, EAGAIN);
    ret = unset_nonblock(w);
    ASSERT_INT_EQ(ret, 0);
    ret = write(w, small_send_buf, strlen(small_send_buf));
    ASSERT_INT_EQ(ret, strlen(small_send_buf));
    ret = unset_nonblock(r);
    ASSERT_INT_EQ(ret, 0);
    ret = read(r, small_recv_buf, SMALL_RECV_BUF_SIZE);
    ASSERT_INT_EQ(ret, strlen(small_send_buf));
    small_recv_buf[ret] = '\0';
    ASSERT_STRING_EQ(small_send_buf, small_recv_buf);
    memset(small_recv_buf, 0, sizeof(small_recv_buf));
    send_buf = malloc(10 * 1024);
    ASSERT_PTR_NE(send_buf, NULL);
    ret = set_nonblock(w);
    ASSERT_INT_EQ(ret, 0);
    ret = 1;
    while (ret > 0) {
        ret = write(w, send_buf, 10 * 1024);
    }
    ASSERT_INT_EQ(ret, -1);
    ASSERT_INT_EQ(errno, EAGAIN);
    ret = close(r);
    ASSERT_INT_EQ(ret, 0);
    ret = close(w);
    ASSERT_INT_EQ(ret, 0);
    TEST_DONE();

    free(send_buf);
}

void file_select_tests() {
    int num_bytes = 1024 * 700; //700KB
    int bytes_sent = 0;
    int bytes_received = 0;
    int seed = 326;
    int eagain_results = 0;

    TEST_START("select on file fds");
    int pipeio[2];
    ret = pipe(pipeio);
    ASSERT_INT_EQ(ret, 0);
    r = pipeio[0];
    w = pipeio[1];
    ret = set_nonblock(w);
    ASSERT_INT_EQ(ret, 0);
    ret = set_nonblock(r);
    ASSERT_INT_EQ(ret, 0);
    send_buf = malloc(num_bytes);
    recv_buf = malloc(num_bytes + 1);
    ASSERT_PTR_NE(send_buf, NULL);
    ASSERT_PTR_NE(recv_buf, NULL);
    prep_input_buffer(send_buf, num_bytes, 17);
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    FD_SET(w, &write_set);
    FD_SET(r, &read_set);
    while (-1 != select(max(r, w) + 1, &read_set, &write_set, NULL, &time_val)) {
        if (FD_ISSET(w, &write_set)) {
            while ((bytes_sent < num_bytes) && ((ret = write(w, send_buf + bytes_sent, num_bytes - bytes_sent)) > 0))
                bytes_sent += ret;
            if (bytes_sent < num_bytes) {
                ASSERT_INT_EQ(ret, -1);
                ASSERT_INT_EQ(errno, EAGAIN);
                eagain_results++;
            }
        }

        if (FD_ISSET(r, &read_set)) {
            while ((ret = read(r, recv_buf + bytes_received, num_bytes - bytes_received + 1)) > 0)
                bytes_received += ret;
            if (ret == 0)
                break;
            ASSERT_INT_EQ(ret, -1);
            ASSERT_INT_EQ(errno, EAGAIN);
            eagain_results++;
        }

        if (bytes_sent < num_bytes)
            FD_SET(w, &write_set);
        else {
            FD_CLR(w, &write_set);
            ret = close(w);
            ASSERT_INT_EQ(ret, 0);
        }
        FD_SET(r, &read_set);
    }

    /*ensure that we hit send and recv paths that returned EAGAIN. Else it would not have touched the async paths*/
    /*if this assert is being hit, then num_bytes is too small. up it*/
    ASSERT_INT_GT(eagain_results, 0);
    ASSERT_INT_EQ(bytes_sent, bytes_received);
    ASSERT_INT_EQ(memcmp(send_buf, recv_buf, num_bytes), 0);
    ret = close(r);
    ASSERT_INT_EQ(ret, 0);

    free(send_buf);
    free(recv_buf);
    TEST_DONE();

}


void file_tests()
{
    w32posix_initialize();
    file_blocking_io_tests();
    file_nonblocking_io_tests();
    file_select_tests();
    w32posix_done();
}

