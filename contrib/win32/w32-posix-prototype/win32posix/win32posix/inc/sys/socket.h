/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* POSIX header and needed function definitions
*/

#include "..\w32posix.h"

#define socket w32_socket
#define accept w32_accept
#define setsockopt w32_setsockopt
#define getsockopt w32_getsockopt
#define getsockname w32_getsockname
#define getpeername w32_getpeername
#define listen w32_listen
#define bind w32_bind
#define connect w32_connect
#define recv w32_recv
#define send w32_send
#define shutdown w32_shutdown
