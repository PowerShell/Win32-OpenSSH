
#ifndef PUBKEYFD_H
#define PUBKEYFD_H

#include "ssh-pubkeydefs.h"

int	ssh_add_pubkey(int sock, struct sshkey *key, const char *comment, const char* password);
int	ssh_list_pubkeys(int sock, struct ssh_identitylist **idlp);
int	ssh_remove_pubkey(int sock, struct sshkey *key);
int	ssh_remove_pubkey_by_fp(int sock, const char *fingerprint);
int	ssh_remove_all_pubkeys(int sock);

#endif
