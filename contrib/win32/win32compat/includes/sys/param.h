#ifndef COMPAT_PARAM_H
#define COMPAT_PARAM_H 1

/* Compatibility header to avoid lots of #ifdef _WIN32's in includes.h */
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef long _off_t;
typedef long off_t;
typedef unsigned int _dev_t;
typedef unsigned int dev_t;


#endif
