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

#ifndef KeyAuth_H
#define KeyAuth_H

#undef STRING

#include <winsock2.h>

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

#include <windows.h>
#include <NTSecPkg.h>

#include "Types.h"
#include "String.h"
#include "PopBinary.h"
#include "Base64.h"
#include "Utils.h"
#include "Key.h"
#include "Debug.h"
#include "SSLFix.h"


#define SSH_BUG_SIGBLOB   0x00000001
#define SSH_BUG_RSASIGMD5 0x00002000

#define INTBLOB_LEN 20
#define SIGBLOB_LEN (2*INTBLOB_LEN)

//
// Minimum modulus size (n) for RSA keys.
//

#define SSH_RSA_MINIMUM_MODULUS_SIZE 768


static const Unsigned Char id_sha1[] = 
{
  0x30, 0x21,                    // type Sequence, length 0x21 (33) 
  0x30, 0x09,                    // type Sequence, length 0x09
  0x06, 0x05,                    // type OID, length 0x05
  0x2b, 0x0e, 0x03, 0x02, 0x1a,  // id-sha1 OID
  0x05, 0x00,                    // NULL
  0x04, 0x14                     // Octet string, length 0x14 (20), 
                                 // followed by sha1 hash 
};


//
// id-md5 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
// rsadsi(113549) digestAlgorithm(2) 5 }
//

static const Unsigned Char id_md5[] =
{
  0x30, 0x20,                            // type Sequence, length 0x20 (32)
  0x30, 0x0c,                            // type Sequence, length 0x09
  0x06, 0x08,                            // type OID, length 0x05
  
  0x2a, 0x86, 0x48, 0x86,                // id-md5
  0xF7, 0x0D, 0x02, 0x05,                
  
  0x05, 0x00,                            // NULL

  0x04, 0x10                             // Octet string, length 0x10 (16),
                                         // followed by md5 hash
};


Int VerifyKey(const Key *key, BYTE *sign, Int signSize, 
                  BYTE *data, Int dataSize, Int dataFellows);

#endif
