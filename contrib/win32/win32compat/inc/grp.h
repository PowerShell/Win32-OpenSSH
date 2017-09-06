#ifndef COMPAT_GRP_H
#define COMPAT_GRP_H 1
#include <Windows.h>
#include "sys/types.h"

typedef enum {
	LOCAL_GROUP = 0,
	DOMAIN_GROUP = 1,
	GLOBAL_UNIVERSAL_GROUP = 2
} group_type;

char ** getusergroups(const char *user, int *numgroups);
void populate_user_groups(char **group_name, int *group_index, DWORD groupsread, DWORD totalgroups, LPBYTE buf, group_type groupType);
void print_user_groups(const char *user, char **user_groups, int num_user_groups);

#endif
