/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*/

#include "test_helper.h"

void socket_tests();
void file_tests();

void tests(void)
{
    _set_abort_behavior(0, 1);

    socket_tests();
    file_tests();
    return;
}