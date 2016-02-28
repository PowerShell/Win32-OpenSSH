#include "CppUnitTest.h"
extern "C" {
#include "..\win32posix\w32posix.h"
}

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

#define PORT "34912"  // the port users will be connecting to

#define BACKLOG 10     // how many pending connections queue will hold

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

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

DWORD WINAPI MyThreadFunction(LPVOID lpParam)
{
    accept_fd = accept(listen_fd, NULL, NULL);
    return 0;
}



namespace UnitTests
{
    TEST_CLASS(SocketIOTests)
    {

    public:
        
        struct addrinfo *servinfo = NULL, *p;
        struct addrinfo hints;

        
        TEST_METHOD_INITIALIZE(TestMethodInitialize)
        {
 
            w32posix_initialize();
            listen_fd = -1;
            accept_fd = -1;
            connect_fd = -1;
            struct sockaddr_storage their_addr; // connector's address information
            socklen_t sin_size;
            int yes = 1;
            char s[INET6_ADDRSTRLEN];
            int rv;

            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = AI_PASSIVE; // use my IP

            if ((rv = getaddrinfo("127.0.0.1", PORT, &hints, &servinfo)) != 0) {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
                return;
            }

            // loop through all the results and bind to the first we can
            for (p = servinfo; p != NULL; p = p->ai_next) {
                if ((listen_fd = socket(p->ai_family, p->ai_socktype,
                    p->ai_protocol)) == -1) {
                    perror("server: socket");
                    continue;
                }

                if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&yes,
                    sizeof(int)) == -1) {
                    perror("setsockopt");
                    exit(1);
                }

                if (bind(listen_fd, p->ai_addr, p->ai_addrlen) == -1) {
                    int i = errno;
                    close(listen_fd);
                    perror("server: bind");
                    continue;
                }

                break;
            }

            freeaddrinfo(servinfo); // all done with this structure
            servinfo = NULL;

            if (p == NULL) {
                fprintf(stderr, "server: failed to bind\n");
                exit(1);
            }

            if (listen(listen_fd, BACKLOG) == -1) {
                perror("listen");
                exit(1);
            }        

        }

        TEST_METHOD_CLEANUP(TestMethodCleanup)
        {
            if (servinfo)
                freeaddrinfo(servinfo);
            if (listen_fd != -1)
                close(listen_fd);
            if (connect_fd != -1)
                close(connect_fd);
            if (accept_fd != -1)
                close(accept_fd);
            w32posix_done();

        }

        TEST_METHOD(TestMethod1)
        {
            int rv;
            struct sockaddr_storage their_addr;
            socklen_t sin_size;
            int ret;
            servinfo = NULL;

            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;

            rv = getaddrinfo("::1", PORT, &hints, &servinfo);
            Assert::AreEqual(rv, 0, L"getaddreinfo failed", LINE_INFO());

            p = servinfo;
            connect_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            Assert::AreNotEqual(connect_fd, -1, L"connect_fd", LINE_INFO());
            
            //set_nonblock(listen_fd);
            //set_nonblock(connect_fd);

            //fd_set read_set;
            //fd_set write_set;
            //FD_ZERO(&read_set);
            //FD_ZERO(&write_set);
            //FD_SET(listen_fd, &read_set);
            //FD_SET(connect_fd, &write_set);

            HANDLE thread = CreateThread(NULL, 0, MyThreadFunction, &connect_fd, 0, NULL);

            //sin_size = sizeof(their_addr);
            //accept_fd = accept(listen_fd, (struct sockaddr *)&their_addr, &sin_size);
            //Assert::AreEqual(accept_fd, -1, L"", LINE_INFO());
            //Assert::AreEqual(errno, EAGAIN, L"", LINE_INFO());

            ret = connect(connect_fd, servinfo->ai_addr, servinfo->ai_addrlen);
            Assert::AreEqual(ret, 0, L"", LINE_INFO());

            WaitForSingleObject(thread, INFINITE);
            CloseHandle(thread);
            
            int i = 9;
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