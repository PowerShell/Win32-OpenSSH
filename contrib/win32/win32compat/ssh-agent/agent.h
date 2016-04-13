#include <Windows.h>
#include <stdio.h>


int agent_start();

void agent_listen();
void agent_shutdown();
void agent_cleanup_connection(struct agent_connection*);

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

void agent_connection_on_io(struct agent_connection*);
void agent_connection_disconnect(struct agent_connection*);