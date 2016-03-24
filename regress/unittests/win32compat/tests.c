/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*/

#include <fcntl.h>
#include <sys\types.h>
#include <sys\stat.h>
#include <io.h>
#include "test_helper.h"

extern void log_init(char *av0, int level, int facility, int on_stderr);

void socket_tests();
void file_tests();

void tests(void)
{
    _set_abort_behavior(0, 1);
    log_init(NULL, 7, 2, 0);
    socket_tests();
    file_tests();
    return;
}