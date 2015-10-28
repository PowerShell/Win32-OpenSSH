/* ansiprsr.h
 * Author: Pragma Systems, Inc. <www.pragmasys.com>
 * Contribution by Pragma Systems, Inc. for Microsoft openssh win32 port
 * Copyright (c) 2011, 2015 Pragma Systems, Inc.
 * All rights reserved
 * 
 * ANSI Parser header file to run on Win32 based operating systems.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice.
 * 2. Binaries produced provide no direct or implied warranties or any
 *    guarantee of performance or suitability.
 */

#ifndef __ANSIPRSR_H
#define __ANSIPRSR_H

#define TERM_ANSI 0
#define TERM_VT52 1

unsigned char * ParseBuffer(unsigned char* pszBuffer, unsigned char* pszBufferEnd);
unsigned char * GetNextChar(unsigned char * pszBuffer, unsigned char *pszBufferEnd);
unsigned char * ParseANSI(unsigned char * pszBuffer, unsigned char * pszBufferEnd);
unsigned char * ParseVT52(unsigned char * pszBuffer, unsigned char * pszBufferEnd);

#define true TRUE
#define false FALSE
#define bool BOOL

//typedef enum _crlftype { CRLF = 0, LF, CR } CRLFType;
#define ENUM_CRLF 0
#define ENUM_LF 1
#define ENUM_CR 2

typedef struct _TelParams 
{
	int timeOut;
	int fLocalEcho;
	int fTreatLFasCRLF;
	int	fSendCROnly;
	int nReceiveCRLF;
} TelParams;

#endif