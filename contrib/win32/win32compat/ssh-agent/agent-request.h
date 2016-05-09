typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef unsigned __int64 u_int64_t;
#define __attribute__(a)
#include "rsa.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "authfd.h"
#include "digest.h"


int process_keyagent_request(struct sshbuf*, struct sshbuf*, struct agent_connection*);
int process_pubkeyagent_request(struct sshbuf*, struct sshbuf*, struct agent_connection*);
int process_authagent_request(struct sshbuf*, struct sshbuf*, struct agent_connection*);