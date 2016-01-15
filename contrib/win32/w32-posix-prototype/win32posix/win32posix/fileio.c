#define __STDC__ 1
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <io.h>
#include "w32fd.h"
#include "defs.h"
#include <errno.h>
#include <stddef.h>


static int errno_from_Win32Error()
{
    int win32_error = GetLastError();

    switch (win32_error){
    case ERROR_ACCESS_DENIED:
        return EACCES;
    case ERROR_OUTOFMEMORY:
        return ENOMEM;
    default:
        return EOTHER;
    }
}

int pipe_number = 0;

int fileio_pipe(struct w32_io* pio[2]) {
    HANDLE read_handle = INVALID_HANDLE_VALUE, write_handle = INVALID_HANDLE_VALUE;
    struct w32_io *pio_read = NULL, *pio_write = NULL;
    char pipe_name[MAX_PATH];
    SECURITY_ATTRIBUTES sec_attributes;
    
    if (-1 == sprintf_s(pipe_name, MAX_PATH, "\\\\.\\Pipe\\RemoteExeAnon.%08x.%08x", GetCurrentProcessId(), pipe_number++))
        goto error;

    sec_attributes.bInheritHandle = TRUE;
    sec_attributes.lpSecurityDescriptor = NULL;
    sec_attributes.nLength = 0;

    read_handle = CreateNamedPipeA(pipe_name,
        PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_NOWAIT,
        1,
        4096,
        4096,
        0,
        &sec_attributes);
    if (read_handle == INVALID_HANDLE_VALUE) {
        errno = errno_from_Win32Error();
        goto error;
    }

    write_handle = CreateFileA(pipe_name,
        GENERIC_WRITE,
        0,
        &sec_attributes,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (write_handle == INVALID_HANDLE_VALUE) {
        errno = errno_from_Win32Error();
        goto error;
    }

    pio_read = (struct w32_io*)malloc(sizeof(struct w32_io));
    pio_write = (struct w32_io*)malloc(sizeof(struct w32_io));

    if (!pio_read || !pio_write) {
        errno = ENOMEM;
        goto error;
    }

    memset(pio_read, 0, sizeof(struct w32_io));
    memset(pio_write, 0, sizeof(struct w32_io));

    pio_read->handle = read_handle;
    pio_read->type = PIPE_FD;

    pio_write->handle = write_handle;
    pio_write->type = PIPE_FD;

    pio[0] = pio_read;
    pio[1] = pio_write;

error:
    if (read_handle)
        CloseHandle(read_handle);
    if (write_handle)
        CloseHandle(write_handle);
    if (pio_read)
        free(pio_read);
    if (pio_write)
        free(pio_write);
    return -1;
}

struct createFile_flags {
    DWORD dwDesiredAccess;
    DWORD dwShareMode;
    SECURITY_ATTRIBUTES securityAttributes;
    DWORD dwCreationDisposition;
    DWORD dwFlagsAndAttributes;
};

static int createFile_flags_setup(int flags, int mode, struct createFile_flags* cf_flags){

    cf_flags->dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
    cf_flags->dwShareMode = 0;
    cf_flags->securityAttributes.lpSecurityDescriptor = NULL;
    cf_flags->securityAttributes.bInheritHandle = TRUE;
    cf_flags->securityAttributes.nLength = 0;
    cf_flags->dwCreationDisposition = CREATE_NEW;
    cf_flags->dwFlagsAndAttributes = FILE_FLAG_OVERLAPPED | SECURITY_IMPERSONATION;
    return 0;
}

struct w32_io* fileio_open(const char *pathname, int flags, int mode) {
    struct w32_io* pio = NULL;
    struct createFile_flags cf_flags;
    HANDLE handle;

    if (createFile_flags_setup(flags, mode, &cf_flags) == -1)
        return NULL;
    
    handle = CreateFileA(pathname, cf_flags.dwDesiredAccess, cf_flags.dwShareMode, &cf_flags.securityAttributes, cf_flags.dwCreationDisposition, cf_flags.dwFlagsAndAttributes, NULL);

    if (handle == NULL) {
        errno = errno_from_Win32Error();
        return NULL;
    }

    pio = (struct w32_io*)malloc(sizeof(struct w32_io));
    if (pio == NULL) {
        CloseHandle(handle);
        errno = ENOMEM;
        return NULL;
    }
    memset(pio, 0, sizeof(struct w32_io));

    pio->handle = handle;
    pio->type = FILE_FD;

    return pio;
}


VOID CALLBACK ReadCompletionRoutine(
    _In_    DWORD        dwErrorCode,
    _In_    DWORD        dwNumberOfBytesTransfered,
    _Inout_ LPOVERLAPPED lpOverlapped
    ) {
    struct w32_io* pio = (struct w32_io*)((char*)lpOverlapped - offsetof(struct w32_io, read_overlapped));
    pio->read_details.error = dwErrorCode;
    pio->read_details.remaining = dwNumberOfBytesTransfered;
    pio->read_details.completed = 0;
    pio->read_details.pending = FALSE;
}

int fileio_ReadFileEx(struct w32_io* pio, BOOL *completed) {

}

int fileio_read(struct w32_io* pio, void *dst, unsigned int max) {

    BOOL WINAPI ReadFileEx(
        _In_      HANDLE                          hFile,
        _Out_opt_ LPVOID                          lpBuffer,
        _In_      DWORD                           nNumberOfBytesToRead,
        _Inout_   LPOVERLAPPED                    lpOverlapped,
        _In_      LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
        );


    return -1;
}


VOID CALLBACK WriteCompletionRoutine(
    _In_    DWORD        dwErrorCode,
    _In_    DWORD        dwNumberOfBytesTransfered,
    _Inout_ LPOVERLAPPED lpOverlapped
    ) {

}
int fileio_write(struct w32_io* pio, const void *buf, unsigned int max) {
    return -1;
}

int fileio_fstat(struct w32_io* pio, struct stat *buf) {
    int fd = _open_osfhandle((intptr_t)pio->handle, 0);
 
    if (fd == -1) {
        errno = EOTHER;
        return NULL;
    }

    return _fstat(fd, (struct _stat*)&buf);
}


int fileio_isatty(struct w32_io* pio) {
    return 0;
}



FILE* fileio_fdopen(struct w32_io* pio, const char *mode) {

    int fd_flags = 0;

    if (mode[1] == '\0') {
        switch (*mode) {
        case 'r':
            fd_flags = _O_RDONLY;
            break;
        case 'w':
            break;
        case 'a':
            fd_flags = _O_APPEND;
            break;
        default:
            errno = ENOTSUP;
            return NULL;
        }
    }
    else {
        errno = ENOTSUP;
        return NULL;
    }

    int fd = _open_osfhandle((intptr_t)pio->handle, fd_flags);

    if (fd == -1) {
        errno = EOTHER;
        return NULL;
    }

    return _fdopen(fd, mode);
}

int fileio_on_select(struct w32_io* pio, BOOL rd);


int fileio_close(struct w32_io* pio) {
    CancelIo(pio->handle);
    //let queued APCs (if any) drain
    SleepEx(1, TRUE);
    CloseHandle(pio->handle);

    if (pio->read_details.buf)
        free(pio->read_details.buf);

    if (pio->write_details.buf)
        free(pio->write_details.buf);

    free(pio);
    return 0;
}

BOOL fileio_is_io_available(struct w32_io* pio, BOOL rd) {
    if (rd){
        if (pio->read_details.remaining || pio->read_details.error)
            return TRUE;
        else
            return FALSE;
    }
    else { //write
        return (pio->write_details.pending == FALSE) ? TRUE : FALSE;
    }
}