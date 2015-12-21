/*
 * Author: NoMachine <developers@nomachine.com>
 *
 * Copyright (c) 2009, 2013 NoMachine
 * All rights reserved
 *
 * Support functions and system calls' replacements needed to let the
 * software run on Win32 based operating systems.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef Debug_H
#define Debug_H

#undef STRING

#include <winsock2.h>
#include <windows.h>
#include "Types.h"

//
// #define DEBUG flag to enable compilation of debug code.
//

#define DEBUG
  
//
// Macros for errors catching.
//

#define FAIL(CONDITION) if(CONDITION) goto fail

#define FAILEX(X, ...) if(X) {DBG_MSG(__VA_ARGS__); goto fail;}

#define NTFAIL(NTFUNC) if((ntStat = (NTFUNC))) goto fail

//
// Macros and functions for debug messages.
//

#ifdef DEBUG

  #define DBG_INIT(PATH) DbgInit(PATH)
  
  #define DBG_ENTRY(FUNC_NAME) DbgEntry(FUNC_NAME)
  #define DBG_ENTER(FUNC_NAME) DbgEntry(FUNC_NAME)
                          
  #define DBG_LEAVE(FUNC_NAME) DbgLeave(FUNC_NAME)
#ifndef __VS_BUILD__
  #define DBG_MSG(FMT, ARGS...) DbgMsg(FMT, ## ARGS)
  
  #define DBG_MSG_NOLN(FMT, ARGS...) DbgMsgNoLn(FMT, ## ARGS)
#else
#define DBG_MSG(FMT, ...) DbgMsg(FMT, __VA_ARGS__)

#define DBG_MSG_NOLN(FMT, ...) DbgMsgNoLn(FMT, __VA_ARGS__)
#endif

  #define DBG_DUMP_TO_FILE(fname, ptr, size) //DbgDumpToFile(fname, ptr, size)
  
  #define DBG_PRINT_TOKEN(token) DbgPrintToken(token)
  
  #define DBG_SET_TREE_MODE(state) DbgTreeMode = state
  
 
  void DbgInit(Char *unused);

  void DbgEntry(const Char *funcName);

  void DbgLeave(const Char *funcName);

  void DbgMsg(const Char *fmt, ...);

  void DbgMsgNoLn(const Char *fmt, ...);
  
  
  void DbgPrintToken(HANDLE token);
  
  void DbgPrintSid(const Char *pre, PSID pSid, const Char *post);
  
  void DbgPrintLuid(const Char *pre, LUID luid, const Char *post);
                            
  void DbgDumpToFile(const Char *fname, void *ptr, Int size);

#else

  //
  // When no debug, we define only "ghost function" macros.
  //
  
  #define DBG_INIT(PATH) 
  
  #define DBG_ENTRY(FUNC_NAME) 
  #define DBG_ENTER(FUNC_NAME) 

  #define DBG_LEAVE(FUNC_NAME) 
  
  #define DBG_MSG(FMT, ARGS...) 

  #define DBG_MSG_NOLN(FMT, ARGS...)
  

  #define DBG_DUMP_TO_FILE(fname, ptr, size)
  
  #define DBG_PRINT_TOKEN(token)
  
  #define DBG_SET_TREE_MODE(state) 
  

  #define DbgPrintToken(token) 
  
  #define DbgPrintSid(pre, pSid, post) 
  
  #define DbgPrintLuid(pre, luid, post) 
  
  #define DbgDumpToFile(fname, ptr, size) 
  
#endif

#endif
