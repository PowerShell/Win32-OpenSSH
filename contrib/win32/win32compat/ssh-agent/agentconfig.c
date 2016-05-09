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

static int use_privsep = -1;
Buffer cfg;
ServerOptions options;
struct passwd *privsep_pw = NULL;
char *forced_command = NULL;
static char *config_file_name = _PATH_SERVER_CONFIG_FILE;

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
int GetCurrentModulePath(char *path, int pathSize)
{
	if (GetModuleFileName(NULL, path, pathSize)) {
		int i;
		int lastSlashPos = 0;

		for (i = 0; path[i]; i++) {
			if (path[i] == '/' || path[i] == '\\') {
				lastSlashPos = i;
			}
		}

		path[lastSlashPos] = 0;
		return 0;
	}
	return -1;
}

int load_config() {
	char basePath[MAX_PATH] = { 0 };
	char path[MAX_PATH] = { 0 };

	/* TODO - account for UNICODE paths*/
	if (GetCurrentModulePath(basePath, MAX_PATH) == 0)
	{
		strncpy(path, basePath, MAX_PATH);
		strncat(path, "/sshd_config", MAX_PATH);
		config_file_name = path;
	}
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