
#ifndef PUBKEYFD_H
#define PUBKEYFD_H

#define PK_REQUEST_ADD "add"
#define PK_REQUEST_LIST "list"
#define PK_REQUEST_REMOVE "remove"
#define PK_REQUEST_REMOVE_ALL "removeall"
#define PK_REQUEST_REMOVE_BY_FP "removebyfp"

int	ssh_add_pubkey(int sock, struct sshkey *key, const char *comment);
int	ssh_list_pubkeys(int sock, struct ssh_identitylist **idlp);
int	ssh_remove_pubkey(int sock, struct sshkey *key);
int	ssh_remove_pubkey_by_fp(int sock, const char *fingerprint);
int	ssh_remove_all_pubkeys(int sock);

#endif
