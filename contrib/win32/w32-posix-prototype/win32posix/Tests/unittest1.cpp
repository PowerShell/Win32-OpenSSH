#include "CppUnitTest.h"
extern "C" {
#include "..\win32posix\w32posix.h"
}

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTests
{
    TEST_CLASS(UnitTest1)
    {
    public:

        TEST_METHOD(TestMethod1)
        {
            // TODO: Your test code here
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

            w32posix_initialize();
            int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
            struct addrinfo hints, *servinfo, *p;
            struct sockaddr_storage their_addr; // connector's address information
            socklen_t sin_size;
            int yes = 1;
            char s[INET6_ADDRSTRLEN];
            int rv;
#define PORT "3490"  // the port users will be connecting to

#define BACKLOG 10     // how many pending connections queue will hold

            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = AI_PASSIVE; // use my IP

            if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
            }

            // loop through all the results and bind to the first we can
            for (p = servinfo; p != NULL; p = p->ai_next) {
                if ((sockfd = socket(p->ai_family, p->ai_socktype,
                    p->ai_protocol)) == -1) {
                    perror("server: socket");
                    continue;
                }

                if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&yes,
                    sizeof(int)) == -1) {
                    perror("setsockopt");
                    exit(1);
                }

                if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
                    close(sockfd);
                    perror("server: bind");
                    continue;
                }

                break;
            }

            freeaddrinfo(servinfo); // all done with this structure

            if (p == NULL)  {
                fprintf(stderr, "server: failed to bind\n");
                exit(1);
            }

            if (listen(sockfd, BACKLOG) == -1) {
                perror("listen");
                exit(1);
            }

        }




    };
}