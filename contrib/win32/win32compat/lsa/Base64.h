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

#ifndef Base64_H
#define Base64_H

#undef STRING

#include "Win64Fix.h"

#include <cstdio>
#include <ctype.h>
#include <cstring>

#include "Types.h"
#include "Debug.h"

//
// Base64 alphabet.
//

static const Char Base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "abcdefghijklmnopqrstuvwxyz"
                                      "0123456789+/";
#define PAD64 '='
#define WRONG -1

//
// Reverse Base64 alphabet.
//

static const Char RevBase64[] =
{
  //
  // 0     1      2      3      4      5      6      7      8      9
  //
    
    0x0, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 000-009
  WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 010-019
  WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 020-029
  WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 030-039
  WRONG, WRONG, WRONG,  0x3e, WRONG, WRONG, WRONG,  0x3f,  0x34,  0x35, // 040-049
   0x36,  0x37,  0x38,  0x39,  0x3a,  0x3b,  0x3c,  0x3d, WRONG, WRONG, // 050-059
  WRONG, PAD64, WRONG, WRONG, WRONG,  0x00,  0x01,  0x02,  0x03,  0x04, // 060-069
   0x05,  0x06,  0x07,  0x08,  0x09,  0x0a,  0x0b,  0x0c,  0x0d,  0x0e, // 070-079
   0x0f,  0x10,  0x11,  0x12,  0x13,  0x14,  0x15,  0x16,  0x17,  0x18, // 080-089
   0x19, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG,  0x1a,  0x1b,  0x1c, // 090-099
   0x1d,  0x1e,  0x1f,  0x20,  0x21,  0x22,  0x23,  0x24,  0x25,  0x26, // 100-109
   0x27,  0x28,  0x29,  0x2a,  0x2b,  0x2c,  0x2d,  0x2e,  0x2f,  0x30, // 110-119
   0x31,  0x32,  0x33, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 120-129
  WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 130-139
  WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 140-149
  WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 150-159
  WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 160-169
  WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 170-179
  WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 180-189
  WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 190-199
  WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 200-209
  WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 210-219
  WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 220-229
  WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 230-239
  WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, WRONG, // 240-249
  WRONG, WRONG, WRONG, WRONG, WRONG, WRONG                              // 250-255
};

Int DecodeBase64(Char const *src, Char *dest, size_t targsize);

#endif
