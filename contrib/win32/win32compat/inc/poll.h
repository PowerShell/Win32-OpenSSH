#pragma once

#include "w32posix.h"

/* created to #def out decarations in open-bsd.h (that are defined in winsock2.h) */

int   poll(struct pollfd *, nfds_t, int);