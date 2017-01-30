#include "crtheaders.h"
#include STRING_H
#include "utf.h"

/* string.h overrides */
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
char *w32_strerror(int);
#define strerror w32_strerror
#define strdup _strdup