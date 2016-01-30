#include <Windows.h>
#include <stdarg.h>
#include <stdio.h>


FILE* log;

void debug_initialize() {
    char filename[MAX_PATH];
    int len = 0;
    SYSTEMTIME time;

    len = GetModuleFileNameA(NULL, filename, MAX_PATH);
    GetLocalTime(&time);
    
    sprintf(filename + len, "_%d_%d_%d.log", time.wHour, time.wMinute, time.wSecond);

    log = fopen(filename, "w");
}

void debug_done() {
    fclose(log);
}


void write_log(const char *source_name, const char *function_name, int line_num, const char *fmt, ...) {
    va_list args;
    fprintf(log,"\n%s:%s:%d: ", source_name, function_name, line_num);
    va_start(args, fmt);
    fprintf(log,fmt, args);
    va_end(args);
    fflush(log);
}