#ifndef COMPAT_PWD_H
#define COMPAT_PWD_H 1

/* Compatibility header to give us pwd-like functionality on Win32 */

struct passwd
{
	char	*pw_name;	/* user's login name */
	char	*pw_passwd;	/* password? */
	char	*pw_gecos;	/* ??? */
	uid_t	pw_uid;		/* numerical user ID */
	gid_t	pw_gid;		/* numerical group ID */
	char	*pw_dir;	/* initial working directory */
	char	*pw_shell;	/* path to shell */
};

uid_t getuid(void);
gid_t getgid(void);
uid_t geteuid(void);
gid_t getegid(void);
int setuid(uid_t uid);
int setgid(gid_t gid);
int seteuid(uid_t uid);
int setegid(gid_t gid);
struct passwd *getpwuid(uid_t uid);
struct passwd *getpwnam(const char *username);
void endpwent(void);

typedef int PWD_USER_TOKEN; /* This is really just a HANDLE, but we might not have windows.h included */
PWD_USER_TOKEN PwdCreateUserToken(const char *pUserName, const char *pDomainName, const char *pSourceName);
#endif
