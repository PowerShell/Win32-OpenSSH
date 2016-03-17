#include "..\w32posix.h"

#define poll(a,b,c) w32_poll((a), (b), (c))
