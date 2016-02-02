
#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdlib.h>
extern "C" {
#include "..\win32posix\w32posix.h"
}
// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

int regular()
{
    int iResult;

    int ListenSocket;
    int ClientSocket;

    struct addrinfo *result = NULL;
    struct addrinfo hints;

    int iSendResult;
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

    w32posix_initialize();

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        w32posix_done();
        return 1;
    }

    // Create a SOCKET for connecting to server
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == -1) {
        printf("socket failed with error: %ld\n", errno);
        freeaddrinfo(result);
        w32posix_done();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == -1) {
        printf("bind failed with error: %d\n", errno);
        freeaddrinfo(result);
        close(ListenSocket);
        w32posix_done();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == -1) {
        printf("listen failed with error: %d\n", errno);
        close(ListenSocket);
        w32posix_done();
        return 1;
    }

    // Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == -1) {
        printf("accept failed with error: %d\n", errno);
        close(ListenSocket);
        w32posix_done();
        return 1;
    }

    // No longer need server socket
    close(ListenSocket);

    // Receive until the peer shuts down the connection
    do {

        iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
        if (iResult > 0) {
            printf("Bytes received: %d\n", iResult);
            recvbuf[iResult] = '\0';
            printf("%s\n", recvbuf);

            // Echo the buffer back to the sender
            iSendResult = send(ClientSocket, recvbuf, iResult, 0);
            if (iSendResult == -1) {
                printf("send failed with error: %d\n", errno);
                close(ClientSocket);
                w32posix_done();
                return 1;
            }
            printf("Bytes sent: %d\n", iSendResult);
        }
        else if (iResult == 0)
            printf("Connection closing...\n");
        else  {
            printf("recv failed with error: %d\n", errno);
            close(ClientSocket);
            w32posix_done();
            return 1;
        }

    } while (iResult > 0);

    // shutdown the connection since we're done
    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == -1) {
        printf("shutdown failed with error: %d\n", errno);
        iSendResult = send(ClientSocket, recvbuf, iResult, 0);
        if (iSendResult == -1) 
            printf("send failed with error: %d\n", errno);
        close(ClientSocket);
        w32posix_done();
        return 1;
    }

    // cleanup
    close(ClientSocket);
    w32posix_done();

    return 0;
}

int async()
{
    int iResult;

    int ListenSocket;
    int ClientSocket;

    struct addrinfo *result = NULL;
    struct addrinfo hints;

    int iSendResult;
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

    w32posix_initialize();

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        w32posix_done();
        return 1;
    }

    // Create a SOCKET for connecting to server
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == -1) {
        printf("socket failed with error: %ld\n", errno);
        freeaddrinfo(result);
        w32posix_done();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == -1) {
        printf("bind failed with error: %d\n", errno);
        freeaddrinfo(result);
        close(ListenSocket);
        w32posix_done();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == -1) {
        printf("listen failed with error: %d\n", errno);
        close(ListenSocket);
        w32posix_done();
        return 1;
    }

    fd_set readset;
    memset(&readset, 0, sizeof(fd_set));
    FD_SET(ListenSocket, &readset);

    timeval time;
    time.tv_sec = 60 * 60;
    if (-1 == select(ListenSocket, &readset, NULL, NULL, &time))
    {
        printf("select call failed");
        close(ListenSocket);
        w32posix_done();
        return 1;
    }

    if (!FD_ISSET(ListenSocket, &readset))
        printf("expected that fd is set");

    // Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == -1) {
        printf("accept failed with error: %d\n", errno);
        close(ListenSocket);
        w32posix_done();
        return 1;
    }

    // No longer need server socket
    close(ListenSocket);

    int fd_flags = fcntl(ClientSocket, F_GETFL);
    fcntl(ClientSocket, F_SETFL, fd_flags | O_NONBLOCK);


    // Receive until the peer shuts down the connection
    do {

        memset(&readset, 0, sizeof(fd_set));
        FD_SET(ClientSocket, &readset);
        if (-1 == select(ClientSocket, &readset, NULL, NULL, &time))
        {
            printf("select call failed");
            close(ListenSocket);
            w32posix_done();
            return 1;
        }

        iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
        if (iResult > 0) {
            printf("Bytes received: %d\n", iResult);
            recvbuf[iResult] = '\0';
            printf("%s\n", recvbuf);

            // Echo the buffer back to the sender
            iSendResult = send(ClientSocket, recvbuf, iResult, 0);
            if (iSendResult == -1) {
                printf("send failed with error: %d\n", errno);
                close(ClientSocket);
                w32posix_done();
                return 1;
            }
            printf("Bytes sent: %d\n", iSendResult);
        }
        else if (iResult == 0)
            printf("Connection closing...\n");
        else  {
            printf("recv failed with error: %d\n", errno);
            close(ClientSocket);
            w32posix_done();
            return 1;
        }

    } while (iResult > 0);

    // shutdown the connection since we're done
    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == -1) {
        printf("shutdown failed with error: %d\n", errno);
        close(ClientSocket);
        w32posix_done();
        return 1;
    }

    // cleanup
    close(ClientSocket);
    w32posix_done();

    return 0;
}


#undef DEFAULT_BUFLEN
#define DEFAULT_BUFLEN 1024*1024
BOOL writemode;
int throughput()
{
    int iResult;

    int ListenSocket;
    int ClientSocket;

    struct addrinfo *result = NULL;
    struct addrinfo hints;

    char *recvbuf = (char*)malloc(DEFAULT_BUFLEN);
    int recvbuflen = DEFAULT_BUFLEN;

    w32posix_initialize();

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        w32posix_done();
        return 1;
    }

    // Create a SOCKET for connecting to server
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == -1) {
        printf("socket failed with error: %ld\n", errno);
        freeaddrinfo(result);
        w32posix_done();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == -1) {
        printf("bind failed with error: %d\n", errno);
        freeaddrinfo(result);
        close(ListenSocket);
        w32posix_done();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == -1) {
        printf("listen failed with error: %d\n", errno);
        close(ListenSocket);
        w32posix_done();
        return 1;
    }

    // Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == -1) {
        printf("accept failed with error: %d\n", errno);
        close(ListenSocket);
        w32posix_done();
        return 1;
    }

    // No longer need server socket
    close(ListenSocket);

    double totalbytes = 0;

    // Receive until the peer shuts down the connection
    if (writemode)
    {
        char *sendbuf = (char*)malloc(DEFAULT_BUFLEN);
        int sendbuflen = DEFAULT_BUFLEN;

        while (totalbytes < 50000 * 1024 * 1024)
        {
            iResult = send(ClientSocket, sendbuf, sendbuflen, 0);
            if (iResult == SOCKET_ERROR) {
                printf("send failed with error: %d\n", WSAGetLastError());
                close(ClientSocket);
                w32posix_done();
                return 1;
            }
            totalbytes += iResult;
        }

        printf("send %f bytes\n", totalbytes);
        // shutdown the connection since no more data will be sent
        iResult = shutdown(ClientSocket, SD_SEND);
        if (iResult == SOCKET_ERROR) {
            printf("shutdown failed with error: %d\n", WSAGetLastError());
            close(ClientSocket);
            w32posix_done();
            return 1;
        }
    }
    else
    {
        do {

            iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
            if (iResult > 0) {
                totalbytes += iResult;
            }
            else if (iResult == 0)
                printf("Connection closing...\n");
            else  {
                printf("recv failed with error: %d\n", errno);
                close(ClientSocket);
                w32posix_done();
                return 1;
            }

        } while (iResult > 0);

        printf("Received total bytes %f\n", totalbytes);
    }

    // cleanup
    close(ClientSocket);
    w32posix_done();

    return 0;
}

DWORD WINAPI ThreadProcedure(void* param)
{
    Sleep(20*1000);
    int writefd = *((int*)param);
    close(writefd);
    return 0;
}

int pipetest()
{
    int pipefds[2];

    w32posix_initialize();
    if (-1 == pipe(pipefds))
    {
        printf("creating pipe failed %d\n", errno);
        return -1;
    }

    int readfd = pipefds[0];
    int writefd = pipefds[1];
    char* buf = "test characters to write";
    char readbuf[512];
    
    CreateThread(0, 0, &ThreadProcedure, &readfd, 0, NULL);
    int count = 0;
    while (1) {
        int written = write(writefd, buf, strlen(buf));
        printf("Iteration %d  Written %d\n", count++, written);
        if (written == -1) {
            printf("write to pipe failed %d \n", errno);
            close(readfd);
            close(writefd);
            return -1;
        }
    }

    /*
    int rd = read(readfd, readbuf, 512);
    if (rd == -1) {
        printf("reading from pipe failed %d \n", errno);
        close(readfd);
        close(writefd);
        return -1;
    }
    */

    close(writefd);

    close(readfd);
    return 0;
}

int pipelinetest()
{
    int pipe1[2];
    if (-1 == pipe(pipe1))
    {
        printf("creating pipe failed %d\n", errno);
        return -1;
    }

    int pipe1_out = pipe1[0];
    int pipe1_in = pipe1[1];
    
    int fd_flags = fcntl(pipe1_in, F_GETFL);
    fcntl(pipe1_in, F_SETFL, fd_flags | O_NONBLOCK);

    fd_flags = fcntl(pipe1_out, F_GETFL);
    fcntl(pipe1_out, F_SETFL, fd_flags | O_NONBLOCK);


    int max_fd = max(pipe1_in, pipe1_out) + 1;

    fd_set read_set, write_set;

    FD_ZERO(&read_set);
    FD_ZERO(&write_set);

    FD_SET(pipe1_out, &read_set);
    FD_SET(pipe1_in, &write_set);
    timeval time;
    time.tv_sec = 60000;
    time.tv_usec = 0;
    char* input = "hi how are you?";
    char read_buf[256];

    while (-1 != select(max_fd, &read_set, &write_set, NULL, &time))
    {
        fd_set read_ret_set = read_set;
        fd_set write_ret_set = write_set;

        FD_ZERO(&read_set);
        FD_ZERO(&write_set);

        if (FD_ISSET(pipe1_in, &write_ret_set))
        {
            int to_write = strlen(input);
            int written = write(pipe1_in, input, to_write);
            if (written != to_write)
                FD_SET(pipe1_in, &write_set);
            else
                FD_SET(pipe1_out, &read_set);

        }

        if (FD_ISSET(pipe1_out, &read_ret_set))
        {
            int bytes_read = read(pipe1_out, read_buf, 256);
            if (bytes_read > 0)
            {
                read_buf[bytes_read] = '\0';
                printf("Received %s \n", read_buf);
            }
        }
        
    }
}


int __cdecl main(void)
{
    //return regular();
    //return async();
    writemode = TRUE;
    //return throughput();
    return pipetest();
}
