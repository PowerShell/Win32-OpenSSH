/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* POSIX header and needed function definitions
*/
#pragma once

#include "..\w32posix.h"

#define socket(a,b,c)		w32_socket((a), (b), (c))
#define accept(a,b,c)		w32_accept((a), (b), (c))
#define setsockopt(a,b,c,d,e)	w32_setsockopt((a), (b), (c), (d), (e))
#define getsockopt(a,b,c,d,e)	w32_getsockopt((a), (b), (c), (d), (e))
#define getsockname(a,b,c)	w32_getsockname((a), (b), (c))
#define getpeername(a,b,c)	w32_getpeername((a), (b), (c))
#define listen(a,b)		w32_listen((a), (b))
#define bind(a,b,c)		w32_bind((a), (b), (c))
#define connect(a,b,c)		w32_connect((a), (b), (c))
#define recv(a,b,c,d)		w32_recv((a), (b), (c), (d))
#define send(a,b,c,d)		w32_send(((a), (b), (c), (d))
#define shutdown(a,b)		w32_shutdown((a), (b))
#define socketpair(a,b,c)	w32_socketpair((a), (b), (c))
