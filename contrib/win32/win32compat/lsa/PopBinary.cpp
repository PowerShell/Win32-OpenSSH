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

#include "PopBinary.h"

extern LSA_SECPKG_FUNCTION_TABLE LsaApi;

#ifdef DYNAMIC_OPENSSL
  extern SSLFuncList DynSSL;
#endif

//
// Pop big endian (!) DWORD value from given buffer. 
// WARNING. Function increses buf pointer if success.
// 
// val        - loaded DWORD value (OUT)
// buf        - pointer to buffer's begin (IN/OUT)
// bytesToEnd - how many bytes remains in buffer (IN/OUT)
//
// RETURNS: 0 if OK.
//

Int PopDword(Unsigned Int &val, BYTE *&buf, Unsigned Int &bytesToEnd)
{
  DBG_MSG("-> PopDword()...");
  
  BYTE *valInBytes = (BYTE *) (&val);
  
  if (bytesToEnd < 4)
  {
    DBG_MSG("ERROR. Cannot load DWORD. Unexpected buffer's end.\n");

    return 1;
  }
  
  valInBytes[0] = buf[3];
  valInBytes[1] = buf[2];
  valInBytes[2] = buf[1];
  valInBytes[3] = buf[0];
  
  buf += 4;

  bytesToEnd -= 4;
  
  return 0;
}

//
// Allocate and pop ASCII string from given buffer. First DWORD in 
// buffer must be a big endian length of string (without length field).
// 
// WARNING. Function increses buf pointer if success.
//
// str        - new allocated and loaded from buffer ASCIIZ string (OUT)
// val        - string length without '0' in bytes (OUT)
// buf        - pointer to buffer's begin (IN/OUT)
// bytesToEnd - how many bytes remains in buffer (IN/OUT)
//
// RETURNS: 0 if OK.
//

Int PopString(Char **str, Unsigned Int &len,
                  BYTE *&buf, Unsigned Int &bytesToEnd)
{
  DBG_MSG("-> PopString()...");
  
  Int exitCode = 1;
  
  FAIL(str == NULL);
  
  //
  // Load string length from buffer.
  //

  FAIL(PopDword(len, buf, bytesToEnd));
  
  //
  // Allocate buffer for new string.
  //
  
  *str = (Char *) LsaApi.AllocateLsaHeap(len + 1);
  
  FAIL(*str == NULL);
  
  //
  // Load 'len' bytes from buffer. It is body of string.
  //
  
  DBG_MSG("LoadString : Checking buffer length"
              " [bytesToEnd = %u, len = %u]...\n", bytesToEnd, len);

  FAIL(bytesToEnd < len);
  
  memcpy(*str, buf, len);
  
  (*str)[len] = 0;
  
  //
  // Increse buffer pointer by len.
  //
  
  buf += len;
  
  bytesToEnd -= len;  
  
  exitCode = 0;
  
fail:

  if (exitCode)
  {
    DBG_MSG("ERROR. Cannot load string from buffer.\n");
    
    LsaApi.FreeLsaHeap(*str);
  }

  return exitCode;
}

//
// Pop raw BIGNUM data from given buffer and initialize given BIGNUM 
// struct with it.
// 
// WARNING. Function increses buf pointer if success.
//
// bigNum     - existing bigNum struct to initialize (OUT)
// buf        - pointer to buffer's begin (IN/OUT)
// bytesToEnd - how many bytes remains in buffer (IN/OUT)
//
// RETURNS: 0 if OK.
//

Int PopBigNum(BIGNUM *bigNum, BYTE *&buf, Unsigned Int &bytesToEnd)
{
  DBG_MSG("-> PopBigNum()...");
  
  Unsigned Int len = 0;
  
  Unsigned Char *rawBigNum = NULL;
  
  Int exitCode = 1;

  FAIL(bigNum == NULL);
  
  //
  // Retrieve raw BIGNUM body from buffer.
  //

  FAIL(PopString((Char **) &rawBigNum, len, buf, bytesToEnd));

  FAIL(len > 8 * 1024);
  
  FAIL((len != 0) && (rawBigNum[0] & 0x80));

  //
  // Convert raw bigNumBlob buffer to BIGNUM struct.
  //
  
  FAIL(OPENSSL(BN_bin2bn(rawBigNum, len, bigNum) == NULL));
  
  exitCode = 0;

fail:

  //
  // Clean up.
  //
  
  if (exitCode)
  {
    DBG_MSG("ERROR. Cannot load BIGNUM from buffer.\n");
  }
  
  LsaApi.FreeLsaHeap(rawBigNum);
  
  return exitCode;
}
