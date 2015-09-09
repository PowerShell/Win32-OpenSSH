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

#ifndef Utils_H
#define Utils_H

#undef STRING

#undef WINVER
#define WINVER 0x0501

#include "Types.h"
#include "Debug.h"
#include <cstdlib>
#include <sddl.h>
#include <Aclapi.h>
#include <iostream>

void SkipWhite(Char *&p);

void GotoWhite(Char *&p);

Int CreatePipeEx(HANDLE pipe[2], SECURITY_ATTRIBUTES *sa, Int bufSize,
                     DWORD readMode, DWORD writeMode, Int timeout);

Int SetObjectRights(const Char *objName, const Char *rights, Int inherit);

Int SetUpSecurityAttributes(SECURITY_ATTRIBUTES *sa, Char *clientUser);

Int EnvironmentCat(Char *env, Int envSize, 
                       const Char *lvalue, const Char *rvalueCat);

Int EnvironmentSet(Char *env, Int envSize, 
                       const Char *lvalue, const Char *rvalueCat);

void FreeSecurityAttributes(SECURITY_ATTRIBUTES *sa);

Int CheckForAdmin(HANDLE process);

const Char *EnvironmentGet(Char *env, const Char *lvalue);

Int EnvironmentAsciiFromUnicode(Char *ascii, Int asciiSize, wchar_t *unicode);

Int GetVarFromNodeCfg(Char *rvalue, Int rvalueSize, 
                          const Char *lvalue, const Char *user);

#endif
