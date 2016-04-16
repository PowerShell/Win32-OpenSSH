#include <Windows.h>
typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef unsigned __int64 u_int64_t;
#define __attribute__(a)
#include "rsa.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "authfd.h"


int process_add_identity(struct sshbuf*, struct sshbuf*, HANDLE);