#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include <ctype.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <stdarg.h>
#include <errno.h>
#ifdef HAVE_UTIL_H
#include <util.h>
#endif

#include "openbsd-compat/sys-queue.h"
#include "xmalloc.h"
#include "ssh.h"
#include "log.h"
#include "buffer.h"
#include "misc.h"
#include "servconf.h"
#include "compat.h"
#include "pathnames.h"
#include "cipher.h"
#include "key.h"
#include "kex.h"
#include "mac.h"
#include "match.h"
#include "channels.h"
#include "groupaccess.h"
#include "canohost.h"
#include "packet.h"
#include "hostfile.h"
#include "auth.h"
#include "myproposal.h"
#include "digest.h"
#include "agent.h"

#include <utf.h>

#pragma warning(push, 3)

Buffer cfg;
ServerOptions options;
struct passwd *privsep_pw = NULL;
static char *config_file_name = _PATH_SERVER_CONFIG_FILE;
int auth_sock = -1;

int
auth2_key_already_used(Authctxt *authctxt, const struct sshkey *key)
{
	return 0;
}

void
auth2_record_key(Authctxt *authctxt, int authenticated,
	const struct sshkey *key)
{
	return;
}

int
auth2_methods_valid(const char * c, int i) {
	return 1;
}

int
mm_is_monitor(void) {
	return 0;
}

int
mm_user_key_allowed(struct passwd *pw, Key *k, int i)
{
	return 0;
}

void* mm_auth_pubkey(const char* user_name, const struct sshkey *key,
	const u_char *sig, size_t slen, struct sshbuf* b)
{
	return NULL;
}

int
kexgex_server(struct ssh * sh) {
	return -1;
}

static int
GetCurrentModulePath(wchar_t *path, int pathSize)
{
	if (GetModuleFileNameW(NULL, path, pathSize)) {
		int i;
		int lastSlashPos = 0;

		for (i = 0; path[i]; i++) {
			if (path[i] == L'/' || path[i] == L'\\')
				lastSlashPos = i;
		}

		path[lastSlashPos] = 0;
		return 0;
	}
	return -1;
}

int
load_config() {
	wchar_t basePath[PATH_MAX] = { 0 };
	wchar_t path[PATH_MAX] = { 0 };
	wchar_t* config_file = L"/sshd_config";
	errno_t r = 0;

	if (GetCurrentModulePath(basePath, PATH_MAX) == -1)
		return -1;

	if (wcsnlen_s(basePath, PATH_MAX) + wcslen(config_file) + 1 > PATH_MAX)
		fatal("unexpected config file path length");

	if(( r = wcsncpy_s(path, PATH_MAX, basePath, wcsnlen_s(basePath, PATH_MAX))) != 0) {
		debug3("memcpy_s failed with error: %d.", r);
		return -1;
	}
	if (( r = wcsncat_s(path, PATH_MAX, L"/sshd_config", PATH_MAX - wcsnlen_s(basePath, PATH_MAX))) != 0) {
		debug3("wcscat_s failed with error: %d.", r);
		return -1;
	}
	
	if ((config_file_name = utf16_to_utf8(path)) == NULL)
		return -1;
	
	buffer_init(&cfg);
	initialize_server_options(&options);
	load_server_config(config_file_name, &cfg);
	parse_server_config(&options, config_file_name, &cfg, NULL);
	fill_default_server_options(&options);

	return 0;
}

int 
config_log_level() {
	return options.log_level;
}

int
pubkey_allowed(struct sshkey* pubkey, HANDLE user_token) {
	struct passwd *pw;

	if ((pw = w32_getpwtoken(user_token)) == NULL)
		return 0;

	return user_key_allowed(pw, pubkey, 1);
}

#pragma warning(pop)