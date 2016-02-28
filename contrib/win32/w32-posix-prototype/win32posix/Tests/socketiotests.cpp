#include "CppUnitTest.h"
extern "C" {
#include "..\win32posix\w32posix.h"
}

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

#define PORT "34912"  
#define BACKLOG 2  

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

int listen_fd = -1;
int accept_fd = -1;
int connect_fd = -1;
addrinfo *servinfo;

int socket_prepare(char* ip)
{
    addrinfo hints;
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

namespace UnitTests
{
    TEST_CLASS(SocketIOTests)
    {

    public:
        
        TEST_METHOD_INITIALIZE(TestMethodInitialize)
        {
            w32posix_initialize();
            listen_fd = -1;
            accept_fd = -1;
            connect_fd = -1;
            servinfo = NULL;
        }

        TEST_METHOD_CLEANUP(TestMethodCleanup)
        {
            if (servinfo) freeaddrinfo(servinfo);
            if (listen_fd != -1)  close(listen_fd);
            if (connect_fd != -1)  close(connect_fd);
            if (accept_fd != -1)  close(accept_fd);
            w32posix_done();
        }

        TEST_METHOD(TestMethod1)
        {
            int ret;
            ret = socket_prepare("::1");
            Assert::AreEqual(ret, 0, L"failed to prepare sockets", LINE_INFO());
            
            //set_nonblock(listen_fd);
            //set_nonblock(connect_fd);

            //fd_set read_set;
            //fd_set write_set;
            //FD_ZERO(&read_set);
            //FD_ZERO(&write_set);
            //FD_SET(listen_fd, &read_set);
            //FD_SET(connect_fd, &write_set);

             //sin_size = sizeof(their_addr);
            //accept_fd = accept(listen_fd, (struct sockaddr *)&their_addr, &sin_size);
            //Assert::AreEqual(accept_fd, -1, L"", LINE_INFO());
            //Assert::AreEqual(errno, EAGAIN, L"", LINE_INFO());

            ret = connect(connect_fd, servinfo->ai_addr, servinfo->ai_addrlen);
            Assert::AreEqual(ret, 0, L"", LINE_INFO());

            accept_fd = accept(listen_fd, NULL, NULL);
            Assert::AreNotEqual(accept_fd, -1, L"", LINE_INFO());


            
           /* accept_fd = accept(listen_fd, (struct sockaddr *)&their_addr, &sin_size);
            Assert::AreNotEqual(accept_fd, -1, L"", LINE_INFO());
*/
           /* ret = connect(connect_fd, servinfo->ai_addr, servinfo->ai_addrlen);
            Assert::AreEqual(ret, 0, L"", LINE_INFO());*/

        }

        TEST_METHOD(TestMethod)
        {
            fd_set* set = (fd_set*)malloc(sizeof(fd_set));

            FD_ZERO(set);
            FD_SET(0, set);
            FD_SET(1, set);

            Assert::AreEqual(1, FD_ISSET(0, set), L"", LINE_INFO());
            Assert::AreEqual(1, FD_ISSET(1, set), L"", LINE_INFO());
            Assert::AreEqual(0, FD_ISSET(2, set), L"", LINE_INFO());

            FD_CLR(0, set);
            FD_CLR(1, set);

            Assert::AreEqual(0, FD_ISSET(0, set), L"", LINE_INFO());
            Assert::AreEqual(0, FD_ISSET(1, set), L"", LINE_INFO());
            Assert::AreEqual(0, FD_ISSET(2, set), L"", LINE_INFO());
        }
    };
}