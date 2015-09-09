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

#ifndef Key_H
#define Key_H

#undef STRING

#include "Win64Fix.h"

#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>

#include <openssl/sha.h>
#include <openssl/md5.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <cstring>
#include <cstdio>

#include <winsock2.h>
#include <windows.h>

#include <NTSecPkg.h>

#include "Types.h"
#include "String.h"
#include "Base64.h"
#include "Utils.h"
#include "PopBinary.h"
#include "Debug.h"
#include "SSLFix.h"

#define MAX_KEYLINE_SIZE 8192

#define MAX_KEY_BLOB (2 * MAX_KEYLINE_SIZE)

enum types 
{
  KEY_RSA1,
  KEY_RSA,
  KEY_DSA,
  KEY_UNSPEC
};

struct Key 
{
  Int type;
  Int flags;
  RSA *rsa;
  DSA *dsa;
};

Int AllocKey(Key *&key, Int type);

void FreeKey(Key *key);

Int KeyFromBlob(Key *&key, BYTE *blob, Unsigned Int blen);

Int FindKeyInFile(const wchar_t *fname, Key *patternKey);

#endif
