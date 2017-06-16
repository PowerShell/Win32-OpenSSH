#pragma once

void     fatal(const char *, ...);
void     error(const char *, ...);
void     verbose(const char *, ...);
void     debug(const char *, ...);
void     debug2(const char *, ...);
void     debug3(const char *, ...);

/* Enable the following for verbose logging */
#if (0)
#define debug4 debug2
#define debug5 debug3
#else
#define debug4(a,...)
#define debug5(a,...)
#endif