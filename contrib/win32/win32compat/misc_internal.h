#pragma once
#define PATH_MAX MAX_PATH
#define SSH_ASYNC_STDIN "SSH_ASYNC_STDIN"
#define SSH_ASYNC_STDOUT "SSH_ASYNC_STDOUT"
#define SSH_ASYNC_STDERR "SSH_ASYNC_STDERR"

#define GOTO_CLEANUP_IF(_cond_,_err_) do {  \
    if ((_cond_)) {                         \
        hr = _err_;                         \
        goto cleanup;                       \
    }                                       \
} while(0)
#define NULL_DEVICE "/dev/null"

#define IS_INVALID_HANDLE(h) ( ((NULL == h) || (INVALID_HANDLE_VALUE == h)) ? 1 : 0 )

/* removes first '/' for Windows paths that are unix styled. Ex: /c:/ab.cd */
char * sanitized_path(const char *);

void w32posix_initialize();
void w32posix_done();

char* w32_programdir();

void convertToBackslash(char *str);
void convertToBackslashW(wchar_t *str);
void convertToForwardslash(char *str);

#define errno_from_Win32LastError() errno_from_Win32Error(GetLastError())
int errno_from_Win32Error(int);
void unix_time_to_file_time(ULONG, LPFILETIME);
void file_time_to_unix_time(const LPFILETIME, time_t *);
int file_attr_to_st_mode(wchar_t * path, DWORD attributes);
void invalid_parameter_handler(const wchar_t *, const wchar_t *, const wchar_t *, unsigned int, uintptr_t);
static char *machine_domain_name;
void to_lower_case(char *s);
int get_machine_domain_name(wchar_t *domain, int size);