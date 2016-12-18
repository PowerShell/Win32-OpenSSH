/* 
 * Temporary zlib.h header for Windows 
 * TODO - decide on a compression solution for Windows
 */
#pragma once
#include <Windows.h>

#define Z_OK            0
#define Z_STREAM_END    1
#define Z_NEED_DICT     2
#define Z_ERRNO        (-1)
#define Z_STREAM_ERROR (-2)
#define Z_DATA_ERROR   (-3)
#define Z_MEM_ERROR    (-4)
#define Z_BUF_ERROR    (-5)
#define Z_VERSION_ERROR (-6)

#define Z_PARTIAL_FLUSH 1

#define voidpf void*
typedef voidpf(*alloc_func)(voidpf opaque, unsigned int items, unsigned int size);
typedef void(*free_func)(voidpf opaque, voidpf address);

struct internal_state;

typedef struct z_stream_s {
        char *next_in;     /* next input byte */
        unsigned int     avail_in;  /* number of bytes available at next_in */
        unsigned long    total_in;  /* total number of input bytes read so far */

        char    *next_out; /* next output byte should be put there */
        unsigned int     avail_out; /* remaining free space at next_out */
        unsigned long    total_out; /* total number of bytes output so far */

        char *msg;  /* last error message, NULL if no error */
        struct internal_state FAR *state; /* not visible by applications */

        alloc_func zalloc;  /* used to allocate the internal state */
        free_func  zfree;   /* used to free the internal state */
        voidpf     opaque;  /* private data object passed to zalloc and zfree */

        int     data_type;  /* best guess about the data type: binary or text */
        unsigned long   adler;      /* adler32 value of the uncompressed data */
        unsigned long   reserved;   /* reserved for future use */
} z_stream;

typedef z_stream FAR *z_streamp;

int
deflateEnd(z_streamp strm);

int
inflateEnd(z_streamp strm);

int
deflateInit(z_streamp strm, int level);

int
inflateInit(z_streamp strm);

int
deflate(z_streamp strm, int flush);

int
inflate(z_streamp strm, int flush);











