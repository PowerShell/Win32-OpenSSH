#ifndef COMPAT_PARAM_H
#define COMPAT_PARAM_H 1

/* Compatibility header to avoid lots of #ifdef _WIN32's in includes.h */
typedef unsigned int uid_t;
typedef unsigned int gid_t;

#ifndef _OFF_T_DEFINED
#define _OFF_T_DEFINED

typedef long _off_t; // file offset value

#if !__STDC__
typedef _off_t off_t;
#endif
#endif

typedef _dev_t dev_t;


#endif
