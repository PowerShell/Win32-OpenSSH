#ifndef COMPAT_PARAM_H
#define COMPAT_PARAM_H 1

/* Compatibility header to avoid lots of #ifdef _WIN32's in includes.h */
typedef unsigned int uid_t;
typedef unsigned int gid_t;
//typedef size_t _off_t;
typedef size_t off_t;
typedef _dev_t dev_t;


#endif
