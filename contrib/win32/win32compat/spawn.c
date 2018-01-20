/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* Implementation of POSIX spawn family of functions
*/
#include <Windows.h>
#include "inc\spawn.h"
#include "inc\unistd.h"

int
posix_spawnp(pid_t *pidp, const char *file, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[])
{
	errno = ENOTSUP;
	return -1;
}

int
posix_spawn_file_actions_init(posix_spawn_file_actions_t *file_actions)
{
	memset(file_actions, 0, sizeof(posix_spawn_file_actions_t));
	file_actions->stdio_redirect[0] = 0;
	file_actions->stdio_redirect[1] = 1;
	file_actions->stdio_redirect[2] = 2;
	return 0;
}

int
posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *file_actions)
{
	return 0;
}

int
posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *file_actions, int fildes)
{
	errno = ENOTSUP;
	return -1;
}

int
posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *file_actions, int fildes, int newfildes)
{
	if (newfildes <= STDERR_FILENO) {
		file_actions->stdio_redirect[newfildes] = fildes;
		return 0;
	}

	if (file_actions->num_aux_fds == MAX_INHERITED_FDS) {
		errno = ENOMEM;
		return -1;
	}
	
	file_actions->aux_fds_info.parent_fd[file_actions->num_aux_fds] = fildes;
	file_actions->aux_fds_info.child_fd[file_actions->num_aux_fds] = newfildes;
	file_actions->num_aux_fds++;
	return 0;
}

int
posix_spawn_file_actions_addopen(posix_spawn_file_actions_t *file_actions, int fildes, const char *path, int oflag, mode_t mode)
{
	errno = ENOTSUP;
	return -1;
}

int
posix_spawnattr_init(posix_spawnattr_t *attr)
{
	memset(attr, 0, sizeof(posix_spawnattr_t));
	return 0;
}

int
posix_spawnattr_destroy(posix_spawnattr_t *attr)
{
	memset(attr, 0, sizeof(posix_spawnattr_t));
	return 0;
}

int
posix_spawnattr_getflags(const posix_spawnattr_t *attr, short *flags)
{
	errno = ENOTSUP;
	return -1;
}

int
posix_spawnattr_setflags(posix_spawnattr_t *attr, short flags)
{
	if (flags != POSIX_SPAWN_SETPGROUP) {
		errno = ENOTSUP;
		return -1;
	}
	attr->flags = flags;
	return 0;
}

int posix_spawnattr_getpgroup(const posix_spawnattr_t * attr, pid_t * pgroup) {
	return 0;
}

int posix_spawnattr_setpgroup(posix_spawnattr_t *attr, pid_t pgroup) {
	return 0;
}
