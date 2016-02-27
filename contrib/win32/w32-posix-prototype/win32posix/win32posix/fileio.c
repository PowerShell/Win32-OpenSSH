#define __STDC__ 1
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <io.h>
#include "w32fd.h"
#include "defs.h"
#include <errno.h>
#include <stddef.h>

#define errno_from_Win32LastError() errno_from_Win32Error(GetLastError())

static int errno_from_Win32Error(int win32_error)
{
    switch (win32_error){
    case ERROR_ACCESS_DENIED:
        return EACCES;
    case ERROR_OUTOFMEMORY:
        return ENOMEM;
    case ERROR_FILE_EXISTS:
        return EEXIST;
    case ERROR_FILE_NOT_FOUND:
        return ENOENT;
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
    
    if (pio == NULL) {
        errno = EFAULT;
        debug("ERROR:%d", errno);
        return -1;
    }


    if (-1 == sprintf_s(pipe_name, MAX_PATH, "\\\\.\\Pipe\\W32PosixPipe.%08x.%08x", GetCurrentProcessId(), pipe_number++)) {
        errno = EOTHER;
        debug("ERROR:%d", errno);
        goto error;
    }

    sec_attributes.bInheritHandle = TRUE;
    sec_attributes.lpSecurityDescriptor = NULL;
    sec_attributes.nLength = 0;

    read_handle = CreateNamedPipeA(pipe_name,
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1,
        4096,
        4096,
        0,
        &sec_attributes);
    if (read_handle == INVALID_HANDLE_VALUE) {
        errno = errno_from_Win32LastError();
        debug("ERROR:%d", errno);
        goto error;
    }

    write_handle = CreateFileA(pipe_name,
        GENERIC_WRITE,
        0,
        &sec_attributes,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL);
    if (write_handle == INVALID_HANDLE_VALUE) {
        errno = errno_from_Win32LastError();
        debug("ERROR:%d", errno);
        goto error;
    }

    pio_read = (struct w32_io*)malloc(sizeof(struct w32_io));
    pio_write = (struct w32_io*)malloc(sizeof(struct w32_io));

    if (!pio_read || !pio_write) {
        errno = ENOMEM;
        debug("ERROR:%d", errno);
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
    return 0;

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

    //check flags
    int rwflags = flags & 0xf;
    int c_s_flags = flags & 0xfffffff0; 

    //should be one of one of the following access modes: O_RDONLY, O_WRONLY, or O_RDWR
    if ((rwflags != O_RDONLY) && (rwflags != O_WRONLY) && (rwflags != O_RDWR)) {
        debug("ERROR: wrong rw flags");
        errno = EINVAL;
        return -1;
    }

    //only following create and status flags currently supported
    if (c_s_flags & ~(O_NONBLOCK | O_APPEND | O_CREAT | O_TRUNC | O_EXCL | O_BINARY)) {
        debug("ERROR: Unsupported flags: %d", flags);
        errno = ENOTSUP;
        return -1;
    }

    //validate mode
    if (mode &~(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) {
        debug("ERROR: unsupported mode: %d", mode);
        errno = ENOTSUP;
        return -1;
    }

    switch (rwflags) {
    case O_RDONLY:
        cf_flags->dwDesiredAccess = GENERIC_READ;
        break;
    case O_WRONLY:
        cf_flags->dwDesiredAccess = GENERIC_WRITE;
        break;
    case O_RDWR:
        cf_flags->dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
        break;
    }

    cf_flags->dwShareMode = 0;
    
    cf_flags->securityAttributes.lpSecurityDescriptor = NULL;
    cf_flags->securityAttributes.bInheritHandle = TRUE;
    cf_flags->securityAttributes.nLength = 0;

    cf_flags->dwCreationDisposition = OPEN_EXISTING;
    if (c_s_flags & O_TRUNC)
        cf_flags->dwCreationDisposition = TRUNCATE_EXISTING;
    if (c_s_flags & O_CREAT) {
        if (c_s_flags & O_EXCL)
            cf_flags->dwCreationDisposition = CREATE_NEW;
        else
            cf_flags->dwCreationDisposition = OPEN_ALWAYS;
    }

    if (c_s_flags & O_APPEND)
        cf_flags->dwDesiredAccess = FILE_APPEND_DATA;

    cf_flags->dwFlagsAndAttributes = FILE_FLAG_OVERLAPPED | SECURITY_IMPERSONATION;

    //TODO - map mode

    return 0;
}

struct w32_io* fileio_open(const char *pathname, int flags, int mode) {
    struct w32_io* pio = NULL;
    struct createFile_flags cf_flags;
    HANDLE handle;

    //check input params
    if (pathname == NULL) {
        errno = EINVAL;
        debug("ERROR:%d", errno);
        return NULL;
    }


    if (createFile_flags_setup(flags, mode, &cf_flags) == -1)
        return NULL;
   
    handle = CreateFileA(pathname, cf_flags.dwDesiredAccess, cf_flags.dwShareMode, &cf_flags.securityAttributes, cf_flags.dwCreationDisposition, cf_flags.dwFlagsAndAttributes, NULL);

    if (handle == INVALID_HANDLE_VALUE) {
        errno = errno_from_Win32LastError();
        debug("ERROR:%d", errno);
        return NULL;
    }

    pio = (struct w32_io*)malloc(sizeof(struct w32_io));
    if (pio == NULL) {
        CloseHandle(handle);
        errno = ENOMEM;
        debug("ERROR:%d", errno);
        return NULL;
    }
    memset(pio, 0, sizeof(struct w32_io));

    if (flags & O_NONBLOCK)
        pio->fd_status_flags = O_NONBLOCK;

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
    debug2("pio:%p, pending_state:%d, error:%d, transferred:%d", pio, pio->read_details.pending, dwErrorCode, dwNumberOfBytesTransfered);
    pio->read_details.error = dwErrorCode;
    pio->read_details.remaining = dwNumberOfBytesTransfered;
    pio->read_details.completed = 0;
    pio->read_details.pending = FALSE;
}

#define READ_BUFFER_SIZE 100*1024

int fileio_ReadFileEx(struct w32_io* pio) {
    
    if (pio->read_details.buf == NULL)
    {
        pio->read_details.buf = malloc(READ_BUFFER_SIZE);

        if (!pio->read_details.buf)
        {
            errno = ENOMEM;
            return -1;
        }

        pio->read_details.buf_size = READ_BUFFER_SIZE;
    }
    
    if (ReadFileEx(pio->handle, pio->read_details.buf, pio->read_details.buf_size, &pio->read_overlapped, &ReadCompletionRoutine))
    {
        pio->read_details.pending = TRUE;
    }
    else
    {
        errno = errno_from_Win32LastError();
        return -1;
    }

    return 0;
}

int fileio_read(struct w32_io* pio, void *dst, unsigned int max) {
    int bytes_copied;

    //if read is pending 
    if (pio->read_details.pending) {
        errno = EAGAIN;
        debug2("IO is already pending");
        return -1;
    }

    if (fileio_is_io_available(pio, TRUE) == FALSE)
    {

        if (-1 == fileio_ReadFileEx(pio)) {
            if ((pio->type == PIPE_FD) && (errno == ERROR_NEGATIVE_SEEK))  {//write end of the pipe closed
                debug2("no more data");
                errno = 0;
                return 0;
            }
            return -1;
        }

        //Pick up APC if IO has completed
        SleepEx(0, TRUE);

        if (w32_io_is_blocking(pio))  {
            while (fileio_is_io_available(pio, TRUE) == FALSE) {
                if (-1 == wait_for_any_event(NULL, 0, INFINITE))
                    return -1;
            }
        }
        else if (pio->read_details.pending) {
            errno = EAGAIN;
            debug2("IO is pending");
            return -1;
        }
    }

    if (pio->read_details.error) {
        errno = errno_from_Win32Error(pio->read_details.error);
        if ((errno == ERROR_BROKEN_PIPE) || //write end of the pipe is closed or pipe broken
            (errno == ERROR_HANDLE_EOF)) { //end of file reached
            debug2("no more data");
            errno = 0;
            pio->read_details.error = 0;
            return 0;
        }
        debug("ERROR:%d", errno);
        pio->read_details.error = 0;
        return -1;
    }

    bytes_copied = min(max, pio->read_details.remaining);
    memcpy(dst, pio->read_details.buf + pio->read_details.completed, bytes_copied);
    pio->read_details.remaining -= bytes_copied;
    pio->read_details.completed += bytes_copied;
    debug2("read %d bytes", bytes_copied);
    return bytes_copied;
}

VOID CALLBACK WriteCompletionRoutine(
    _In_    DWORD        dwErrorCode,
    _In_    DWORD        dwNumberOfBytesTransfered,
    _Inout_ LPOVERLAPPED lpOverlapped
    ) {
    struct w32_io* pio = (struct w32_io*)((char*)lpOverlapped - offsetof(struct w32_io, write_overlapped));
    debug2("pio:%p, pending_state:%d, remaining:%d, error:%d, transferred:%d", pio, pio->write_details.pending, pio->write_details.remaining, dwErrorCode, dwNumberOfBytesTransfered);
    pio->write_details.error = dwErrorCode;
    //assert that remaining == dwNumberOfBytesTransfered
    pio->write_details.remaining -= dwNumberOfBytesTransfered;
    pio->write_details.pending = FALSE;
}

#define WRITE_BUFFER_SIZE 100*1024
int fileio_write(struct w32_io* pio, const void *buf, unsigned int max) {
    int bytes_copied;

    if (pio->write_details.pending) {
        if (w32_io_is_blocking(pio))
        {
            //this covers the scenario when the fd was previously non blocking (and hence io is still pending)
            //wait for previous io to complete
            debug2("waiting for prior unblocking write to complete before proceeding with this blocking write");
            while (pio->write_details.pending) {
                if (wait_for_any_event(NULL, 0, INFINITE) == -1)
                    return -1;
            }
        }
        else {
            errno = EAGAIN;
            debug2("IO is already pending");
            return -1;
        }
    }

    if (pio->write_details.error) {
        errno = errno_from_Win32Error(pio->write_details.error);
        debug("ERROR:%d on prior unblocking write", errno);
        pio->write_details.error = 0;
        return -1;
    }

    if (pio->write_details.buf == NULL) {
        pio->write_details.buf = malloc(WRITE_BUFFER_SIZE);
        if (pio->write_details.buf == NULL) {
            errno = ENOMEM;
            debug("ERROR:%d", errno);
            return -1;
        }
        pio->write_details.buf_size = WRITE_BUFFER_SIZE;
    }

    bytes_copied = min(max, pio->write_details.buf_size);
    memcpy(pio->write_details.buf, buf, bytes_copied);

    if (WriteFileEx(pio->handle, pio->write_details.buf, bytes_copied, &pio->write_overlapped, &WriteCompletionRoutine))
    {
        pio->write_details.pending = TRUE;
        //let APC execute if IO was complete
        SleepEx(0, TRUE);

        if (w32_io_is_blocking(pio)) {
            while (pio->write_details.pending) {
                if (wait_for_any_event(NULL, 0, INFINITE) == -1)
                    return -1;
            }
        }
        if (!pio->write_details.pending && pio->write_details.error){
            errno = errno_from_Win32Error(pio->write_details.error);
            pio->write_details.error = 0;
            debug("ERROR:%d", errno);
            return -1;
        }
        return bytes_copied;
    }
    else
    {
        errno = errno_from_Win32LastError();
        if ((pio->type == PIPE_FD) && (errno == ERROR_NEGATIVE_SEEK)) {//read end of the pipe closed   
            debug("ERROR:read end of the pipe closed");
            errno = EPIPE;
        }
        debug("ERROR:%d", errno);
        return -1;
    }

}

int fileio_fstat(struct w32_io* pio, struct stat *buf) {
    int fd = _open_osfhandle((intptr_t)pio->handle, 0);
    debug2("pio:%p", pio);
    if (fd == -1) {
        errno = EOTHER;
        return -1;
    }

    return _fstat(fd, (struct _stat*)&buf);
}


int fileio_isatty(struct w32_io* pio) {
    return (pio->type == CONSOLE_FD) ? TRUE : FALSE;
}


FILE* fileio_fdopen(struct w32_io* pio, const char *mode) {

    int fd_flags = 0;
    debug2("pio:%p", pio);

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
            debug("ERROR:%d", errno);
            return NULL;
        }
    }
    else {
        errno = ENOTSUP;
        debug("ERROR:%d", errno);
        return NULL;
    }

    int fd = _open_osfhandle((intptr_t)pio->handle, fd_flags);

    if (fd == -1) {
        errno = EOTHER;
        debug("ERROR:%d", errno);
        return NULL;
    }

    return _fdopen(fd, mode);
}

int fileio_on_select(struct w32_io* pio, BOOL rd) {
    if (rd && pio->read_details.pending)
        return 0;

    if (!rd && pio->write_details.pending)
        return 0;
    
    if (rd)
        return fileio_ReadFileEx(pio);
    else
        //nothing to do with write
        return 0;
}


int fileio_close(struct w32_io* pio) {
    debug2("pio:%p", pio);
    CancelIo(pio->handle);
    //let queued APCs (if any) drain
    SleepEx(0, TRUE);
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