/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Declarations of POSIX spawn family of functions
*/
#pragma once
#include "sys\types.h"

#define POSIX_SPAWN_RESETIDS			0x1
#define POSIX_SPAWN_SETPGROUP			0x2
#define POSIX_SPAWN_SETSIGDEF			0x4
#define POSIX_SPAWN_SETSIGMASK			0x8
#define POSIX_SPAWN_SETSCHEDPARAM		0x10
#define POSIX_SPAWN_SETSCHEDULER		0x20

#define MAX_INHERITED_FDS  10
typedef struct
{	
	/* stdio to be redirected*/
	int stdio_redirect[3];
	/* number of additinal fds to be duplicated/inherited*/
	int num_aux_fds;
	/* additional fds to be duplicated/inherited */
	struct {
		int parent_fd[MAX_INHERITED_FDS];
		int child_fd[MAX_INHERITED_FDS];
	}aux_fds_info;
}posix_spawn_file_actions_t;

typedef struct
{
	int flags;
}posix_spawnattr_t;

int
posix_spawn(pid_t *pidp, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]);

int
__posix_spawn_asuser(pid_t *pidp, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[], char* user);

int
posix_spawnp(pid_t *pidp, const char *file, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]);

int
posix_spawn_file_actions_init(posix_spawn_file_actions_t *file_actions);

int
posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *file_actions);

int
posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *file_actions, int fildes);

int
posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *file_actions, int fildes, int newfildes);

int
posix_spawn_file_actions_addopen(posix_spawn_file_actions_t *file_actions, int fildes, const char *path, int oflag, mode_t mode);

int
posix_spawnattr_init(posix_spawnattr_t *attr);

int
posix_spawnattr_destroy(posix_spawnattr_t *attr); 

int
posix_spawnattr_getflags(const posix_spawnattr_t *attr, short *flags);

int
posix_spawnattr_setflags(posix_spawnattr_t *attr, short flags);

int posix_spawnattr_getpgroup(const posix_spawnattr_t * attr, pid_t * pgroup);

int posix_spawnattr_setpgroup(posix_spawnattr_t *attr, pid_t pgroup);




