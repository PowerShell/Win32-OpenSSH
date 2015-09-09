/*
 * Author: NoMachine <developers@nomachine.com>
 *
 * Copyright (c) 2009, 2011 NoMachine
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

#ifndef DeskRight_H
#define DeskRight_H

#include "includes.h"
#include "Debug.h"
#include <winsock2.h>
#include <windows.h>

#define ADD_RIGHT    1
#define REMOVE_RIGHT 0

#define WINSTA_ALL (WINSTA_ACCESSCLIPBOARD  | WINSTA_ACCESSGLOBALATOMS | \ 
                    WINSTA_CREATEDESKTOP    | WINSTA_ENUMDESKTOPS      | \
                    WINSTA_ENUMERATE        | WINSTA_EXITWINDOWS       | \
                    WINSTA_READATTRIBUTES   | WINSTA_READSCREEN        | \
                    WINSTA_WRITEATTRIBUTES  | DELETE                   | \
                    READ_CONTROL            | WRITE_DAC                | \
                    WRITE_OWNER)

#define DESKTOP_ALL (DESKTOP_CREATEMENU      | DESKTOP_CREATEWINDOW  | \
                     DESKTOP_ENUMERATE       | DESKTOP_HOOKCONTROL   | \
                     DESKTOP_JOURNALPLAYBACK | DESKTOP_JOURNALRECORD | \
                     DESKTOP_READOBJECTS     | DESKTOP_SWITCHDESKTOP | \
                     DESKTOP_WRITEOBJECTS    | DELETE                | \
                     READ_CONTROL            | WRITE_DAC             | \
                     WRITE_OWNER)

#define GENERIC_ACCESS (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL)

int ModifyRightsToDesktop(HANDLE hToken, int mode);
int ModifyRightsToDesktopBySid(PSID psid, int mode);

#endif
