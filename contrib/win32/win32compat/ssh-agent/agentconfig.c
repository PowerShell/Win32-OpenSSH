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

Buffer cfg;
ServerOptions options;
struct passwd *privsep_pw = NULL;
static char *config_file_name = _PATH_SERVER_CONFIG_FILE;
int auth_sock = -1;

int	 auth2_methods_valid(const char * c, int i) {
	return 1;
}

int
mm_is_monitor(void) {
	return 0;
}

int	 kexgex_server(struct ssh * sh) {
	return -1;
}

static
int GetCurrentModulePath(wchar_t *path, int pathSize)
{
	if (GetModuleFileNameW(NULL, path, pathSize)) {
		int i;
		int lastSlashPos = 0;

		for (i = 0; path[i]; i++) {
			if (path[i] == L'/' || path[i] == L'\\') {
				lastSlashPos = i;
			}
		}

		path[lastSlashPos] = 0;
		return 0;
	}
	return -1;
}

int load_config() {
	wchar_t basePath[PATH_MAX] = { 0 };
	wchar_t path[PATH_MAX] = { 0 };
        
	/* TODO - account for UNICODE paths*/
        if (GetCurrentModulePath(basePath, PATH_MAX) == -1)
                return -1;

	wcsncpy(path, basePath, PATH_MAX);
        wcsncat(path, L"/sshd_config", PATH_MAX);
	
        if ((config_file_name = utf16_to_utf8(path)) == NULL)
                return -1;
	
        buffer_init(&cfg);
	initialize_server_options(&options);
	load_server_config(config_file_name, &cfg);
	parse_server_config(&options, config_file_name, &cfg, NULL);
	fill_default_server_options(&options);

	return 0;
}

int config_log_level() {
	return options.log_level;
}

int pubkey_allowed(struct sshkey* pubkey, wchar_t* wuser, wchar_t* wuser_home) {
	struct passwd pw;
        int ret;
	char *user = NULL, *user_home = NULL;
	memset(&pw, 0, sizeof(pw));

        if ((user_home = utf16_to_utf8(wuser_home)) == NULL ||
            (user = utf16_to_utf8(wuser)) == NULL)
                return 0;
	
        pw.pw_dir = user_home;
	pw.pw_name = user;
	ret = user_key_allowed(&pw, pubkey, 1);
        free(user);
        free(user_home);
        return ret;
}