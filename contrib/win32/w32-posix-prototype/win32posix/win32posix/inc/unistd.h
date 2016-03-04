/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* POSIX header and needed function definitions
*/

#include "w32posix.h"

#define pipe w32_pipe
#define open w32_open
#define read w32_read
#define write w32_write
#define isatty w32_isatty
#define close w32_close
#define dup w32_dup
#define dup2 w32_dup2

#define sleep(sec) Sleep(1000 * sec)