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

#include <winsock2.h>
#include "Base64.h"

//
// Decode base64 string. Input string MUST be '0' byte terminated.
//
// src      - input, zero-terminated string (IN)
// dest     - output, decoded string (OUT)
// destSize - size if dest buffer in bytes (IN)
//
// RETURNS: Number of bytes written to dest or -1 if error.
//

Int DecodeBase64(Char const *src, Char *dest, size_t destSize)
{
  DBG_ENTRY("DecodeBase64");
  
  Int len = 0;
  
  Int exitCode = 1;
  
  Char encoded[4] = {0};
  Char decoded[4] = {0};
  
  Char &encX = encoded[0];
  Char &encY = encoded[1];
  Char &encZ = encoded[2];
  Char &encW = encoded[3];
  
  Char &x = decoded[0];
  Char &y = decoded[1];
  Char &z = decoded[2];
  Char &w = decoded[3];
  
  //
  // i indexes source buffer.
  // j indexes destination buffer.
  //
  
  Unsigned Int i = 0;
  
  Unsigned Int j = 0;
  
  Int goOn = 1;
  
  //
  // Skip white spaces at the buffer's begin.
  //
  
  while (isspace(src[i]))
  {
    i++;
  }
  
  //
  // Decode string by 4 bytes packages {x,y,z,w}
  //
  
  while (goOn && src[i])
  {
    //
    // Read next 4 non white characters from source buffer.
    //

    for (int k = 0; k < 4; k++)
    {
      //
      // Unexepcted end of string?
      //
      
      FAIL(src[i] == 0);
      
      //
      // Find one byte in Base64 alphabet.
      //
      
      encoded[k] = src[i];
      
      decoded[k] = RevBase64[(Int) (src[i])];
      
      FAIL(decoded[k] == WRONG);
      
      //
      // If any character in {x,y,z,w} is PAD64 
      // this is signal to end.
      //

      if (encoded[k] == PAD64)
      {
        goOn = 0;
      }
      
      //
      // Goto next not white character.
      //

      i++;
      
      while (isspace(src[i]))
      {
        i++;
      }
    }
    
    //
    // Translate {x,y,z,w} |-> {x',y',z'}.
    //
    
    FAIL((j + 3) > destSize);
    
    dest[j] = (x << 2) | (y >> 4);
    
    dest[j + 1] = (y << 4) | ((z >> 2) & 0xf);
    
    dest[j + 2] = ((z << 6) & 192) | (w & 63);

    j += 3;
  };

  len = j;
  
  //
  // Do any bytes remain in string? String must be terminated
  // by zero byte.
  
  FAIL(src[i] != 0);
  
  //
  // Fail if last packet is {PAD64, ?, ?, ?} or {?, PAD64, ?, ?}.
  // PAD64 characters can be only at 2 last positions.
  //
  
  FAIL(encX == PAD64);
  FAIL(encY == PAD64);
  
  //
  // Decrese output length if pre-last character is PAD64.
  //
  
  if (encZ == PAD64)
  {
    //
    // {?, ?, PAD64, ?} is incorrect package.
    //
    
    FAIL(encW != PAD64);
    
    len--;
  }
  
  //
  // Decrese once more if last character is PAD64.
  //

  if (encW == PAD64)
  {
    len--;
  }
  
  exitCode = 0;

fail:

  if (exitCode)
  {
    DBG_MSG("ERROR. Cannot decode base64 string.\n");
    
    len = -1;
  }

  DBG_LEAVE("DecodeBase64");
  
  return len;
}
