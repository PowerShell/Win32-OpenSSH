/* tnnet.h
 * Author: Pragma Systems, Inc. <www.pragmasys.com>
 * Contribution by Pragma Systems, Inc. for Microsoft openssh win32 port
 * Copyright (c) 2011, 2015 Pragma Systems, Inc.
 * All rights reserved
 * 
 * Contains terminal emulation related network calls to invoke ANSI parsing engine
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice.
 * 2. Binaries produced provide no direct or implied warranties or any
 *    guarantee of performance or suitability.
 */
 
#ifndef __TNNET_H
#define __TNNET_H

 int NetWriteString( char* pszString, size_t cbString);
 size_t telProcessNetwork ( char *buf, size_t len );
 
#endif
 