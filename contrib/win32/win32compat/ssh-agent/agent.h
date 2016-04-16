#include <Windows.h>
#include <stdio.h>
#define MAX_MESSAGE_SIZE 5 * 1024

#define HEADER_SIZE 4
struct agent_connection {
	OVERLAPPED ol;
	HANDLE connection;
	HANDLE client_token;
	struct {
		DWORD num_bytes;
		DWORD transferred;
		char buf[MAX_MESSAGE_SIZE];
		DWORD buf_size;
	} io_buf;
	enum {
		LISTENING = 0,
		READING_HEADER,
		READING,
		WRITING,
		DONE
	} state;
	struct agent_connection* next;
};

void agent_connection_on_io(struct agent_connection*, DWORD, OVERLAPPED*);
void agent_connection_on_error(struct agent_connection* , DWORD );
void agent_connection_disconnect(struct agent_connection*);

int agent_start();
void agent_shutdown();
void agent_listen();
void agent_cleanup_connection(struct agent_connection*);
