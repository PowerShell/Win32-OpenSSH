#pragma once
#define PATH_MAX MAX_PATH
#define SSH_ASYNC_STDIN "SSH_ASYNC_STDIN"
#define SSH_ASYNC_STDOUT "SSH_ASYNC_STDOUT"
#define SSH_ASYNC_STDERR "SSH_ASYNC_STDERR"

/* removes first '/' for Windows paths that are unix styled. Ex: /c:/ab.cd */
char * sanitized_path(const char *);

void w32posix_initialize();
void w32posix_done();

char* w32_programdir();

void convertToBackslash(char *str);
void convertToForwardslash(char *str);
