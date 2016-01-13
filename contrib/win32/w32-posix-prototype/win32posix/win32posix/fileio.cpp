#include "w32fd.h"
#include "defs.h"

int fileio_pipe(struct w32_io* pio[2]) {
    return -1;
}
struct w32_io* fileio_open(const char *pathname, int flags, int mode) {

    return NULL;
}
int fileio_read(struct w32_io* pio, void *dst, unsigned int max) {
    return -1;
}
int fileio_write(struct w32_io* pio, const void *buf, unsigned int max) {
    return -1;
}

int fileio_fstat(struct w32_io* pio, struct stat *buf) {
    return -1;
}
int fileio_isatty(struct w32_io* pio) {
    return 0;
}
FILE* fileio_fdopen(struct w32_io* pio, const char *mode) {
    return NULL;
}