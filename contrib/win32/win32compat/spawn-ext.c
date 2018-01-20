#include <Windows.h>
#include "misc_internal.h"
#include "inc\unistd.h"
#include "debug.h"

int posix_spawn_internal(pid_t *pidp, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[], HANDLE user_token);

int
__posix_spawn_asuser(pid_t *pidp, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[], char* user)
{
	extern HANDLE password_auth_token;
	int r = -1;
	/* use token generated from password auth if already present */
	HANDLE user_token = password_auth_token;

	if (!user_token && (user_token = get_user_token(user)) == NULL) {
		error("unable to get security token for user %s", user);
		errno = EOTHER;
		return -1;
	}
	if (strcmp(user, "sshd"))
		load_user_profile(user_token, user);
	
	r = posix_spawn_internal(pidp, path, file_actions, attrp, argv, envp, user_token);
	CloseHandle(user_token);
	return r;
}