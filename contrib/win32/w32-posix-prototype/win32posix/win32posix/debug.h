

#define debug(cformat, ...) write_log(__FILE__, __FUNCTION__, __LINE__, cformat, __VA_ARGS__)
#define debug2(cformat, ...) write_log(__FILE__, __FUNCTION__, __LINE__, cformat, __VA_ARGS__)
#define debug3(cformat, ...) write_log(__FILE__, __FUNCTION__, __LINE__, cformat, __VA_ARGS__)

void debug_initialize();
void debug_done();
void write_log(const char *source_name,const char *function_name, int line_num, const char *fmt, ...);
