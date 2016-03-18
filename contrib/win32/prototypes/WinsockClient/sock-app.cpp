

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>


// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


#define DEFAULT_BUFLEN 512*1024 //512 KB
char recvbuf[DEFAULT_BUFLEN];
char sendbuf[DEFAULT_BUFLEN];
bool keep_going = true;
__int64 rec_bytes = 0, sent_bytes = 0;
bool server = true;


void prep_send_buf()
{
	int *buf = (int*)sendbuf;
	for (int i = 0; i < DEFAULT_BUFLEN; i += sizeof(int))
		*buf++ = rand();
}

SOCKET ConnectSocket = INVALID_SOCKET;

DWORD WINAPI RecvThread(
	_In_ LPVOID lpParameter
	) {
	int rec = 1;
	while (keep_going && (rec>0)) {
		rec = recv(ConnectSocket, recvbuf, DEFAULT_BUFLEN, 0);
		rec_bytes += rec;
	}
	return 0;
}

DWORD WINAPI SendThread(
	_In_ LPVOID lpParameter
	) {
	int rec = 1, rnd;
	while (keep_going && (rec>0)) {
		rnd = rand();
		rec = send(ConnectSocket, sendbuf + rnd, DEFAULT_BUFLEN - rnd, 0);
		sent_bytes += rec;
	}
	return 0;
}

int __cdecl main(int argc, char **argv)
{
	WSADATA wsaData;

	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;

	int iResult;
	

	// Validate the parameters
	if ((argc < 2) || (strlen(argv[1]) > 1)) {
		printf("usage: %s [c|s] IP port\n", argv[0]);
		return 1;
	}

	if (argv[1][0] == 'c')
		server = false;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(argv[2], argv[3], &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	if (!server) {
		// Attempt to connect to an address until one succeeds
		for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

			// Create a SOCKET for connecting to server
			ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
				ptr->ai_protocol);
			if (ConnectSocket == INVALID_SOCKET) {
				printf("socket failed with error: %ld\n", WSAGetLastError());
				WSACleanup();
				return 1;
			}

			// Connect to server.
			iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
			if (iResult == SOCKET_ERROR) {
				closesocket(ConnectSocket);
				ConnectSocket = INVALID_SOCKET;
				continue;
			}
			break;
		}

		if (ConnectSocket == INVALID_SOCKET) {
			printf("Unable to connect to server!\n");
			WSACleanup();
			return 1;
		}
	}
	else {
		SOCKET ListenSocket;
		// Create a SOCKET for connecting to server
		ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
		if (ListenSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			freeaddrinfo(result);
			WSACleanup();
			return 1;
		}

		// Setup the TCP listening socket
		iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			printf("bind failed with error: %d\n", WSAGetLastError());
			freeaddrinfo(result);
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		}

		iResult = listen(ListenSocket, SOMAXCONN);
		if (iResult == SOCKET_ERROR) {
			printf("listen failed with error: %d\n", WSAGetLastError());
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		}

		// Accept a client socket
		ConnectSocket = accept(ListenSocket, NULL, NULL);
		if (ConnectSocket == INVALID_SOCKET) {
			printf("accept failed with error: %d\n", WSAGetLastError());
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		}
		// No longer need server socket
		closesocket(ListenSocket);


	}

	freeaddrinfo(result);

	HANDLE rt = CreateThread(NULL, 0, RecvThread, NULL, 0, NULL);
	if (rt == NULL) {
		printf("Unable to create read thread!\n");
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	HANDLE wt = CreateThread(NULL, 0, SendThread, NULL, 0, NULL);
	if (wt == NULL) {
		printf("Unable to create send thread!\n");
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	HANDLE timer = CreateWaitableTimer(NULL, FALSE, NULL);
	if (timer == NULL){
		printf("Unable to create timer!\n");
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}
	LARGE_INTEGER liDueTime;
	liDueTime.QuadPart = 0;
	if(!SetWaitableTimer(timer, &liDueTime, 2000, NULL, NULL, false)) {
		printf("Unable to set timer!\n");
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	printf("\t Recv(Kb/s) \t\t Sent(Kb/s)\n");
	__int64 last_recv = 0;
	__int64 last_send = 0;
	while (1) {
		if (WAIT_OBJECT_0 != WaitForSingleObject(timer, INFINITE)) {
			printf("wait failed %d\n", GetLastError());
			break;
		}
		__int64 now_recv = rec_bytes;
		__int64 now_send = sent_bytes;

		printf("\r\t %lld \t\t %lld", (now_recv - last_recv) / 2048, (now_send - last_send) / 2048);
		last_recv = now_recv;
		last_send = now_send;

	}

	closesocket(ConnectSocket);
	WSACleanup();

	return 0;
}