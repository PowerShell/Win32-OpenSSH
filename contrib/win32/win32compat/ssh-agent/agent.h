#include <Windows.h>
#include <stdio.h>
#include "Debug.h"
#include "misc_internal.h"

#define MAX_MESSAGE_SIZE 256 * 1024

#define SSH_AGENT_ROOT SSH_REGISTRY_ROOT L"\\Agent"
#define SSH_KEYS_KEY L"Keys"
#define SSH_KEYS_ROOT SSH_AGENT_ROOT L"\\" SSH_KEYS_KEY

#define HEADER_SIZE 4

struct agent_connection {
	OVERLAPPED ol;
	HANDLE pipe_handle;
	HANDLE client_impersonation_token;
	HANDLE client_process_handle;
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
	enum { /* retain this order */
		UNKNOWN = 0,
		NONADMIN_USER, /* client is running as a nonadmin user */
		ADMIN_USER, /* client is running as admin */
		SSHD_SERVICE, /* client is sshd service */
		SYSTEM, /* client is running as System */
		SERVICE, /* client is running as LS or NS */
	} client_type;
};

void agent_connection_on_io(struct agent_connection*, DWORD, OVERLAPPED*);
void agent_connection_on_error(struct agent_connection* , DWORD);
void agent_connection_disconnect(struct agent_connection*);

void agent_start(BOOL);
void agent_process_connection(HANDLE);
void agent_shutdown();
void agent_cleanup_connection(struct agent_connection*);
