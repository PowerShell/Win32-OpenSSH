#include <Windows.h>
#include <stdio.h>


int agent_start();
void agent_shutdown();

struct agent_connection {
	enum {
		LISTENING = 0,
		READING,
		WRITING,
		DONE
	} state;
	HANDLE connection;
	struct agent_con* next;
};

void agent_connection_on_io(struct agent_connection*, DWORD, OVERLAPPED*);
void agent_connection_disconnect(struct agent_connection*);