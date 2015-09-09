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
#include "Key.h"

extern LSA_SECPKG_FUNCTION_TABLE LsaApi;

#ifdef DYNAMIC_OPENSSL
  extern SSLFuncList DynSSL;
#endif

//
// Decode base64 key, readed from 'authorized_keys' file.
//
// key - decoded key (OUT)
// p   - pointer to buffer, where encoded key stored (IN)
//
// RETURNS: 0 if OK.
//

Int DecodeBase64Key(Key *&key, Char *p)
{
  DBG_ENTRY("DecodeBase64Key");

  Int exitCode = 1;
  
  Char encoded[MAX_KEYLINE_SIZE + 1] = {0};
  
  Char pkBlob[MAX_KEY_BLOB] = {0};
  
  Int len = 0;
  
  //
  // Check args.
  //
  
  DBG_MSG("Checking args...\n");
 
  FAIL(p == NULL);
  
  FAIL(p[0] == '\0');
  
  //
  // Skip key type in text form.
  //
  
  DBG_MSG("Skipping plain text key type...\n");
  
  p = strchr(p, ' ');
  
  FAIL(p == NULL);

  p++;
  
  //
  // decode key blob.
  //
  
  len = strlen(p);
  
  strncpy(encoded, p, len);

  encoded[len] = 0;

  //
  // Put zero byte at the first white char after key data started.
  //
  
  p = encoded;
  
  SkipWhite(p);
  
  GotoWhite(p);  

  p[0] = '\0';

  //
  // Decode base64 key blob.
  //
  
  DBG_MSG("Decoding base64 key blob...\n");
  
  len = DecodeBase64(encoded, pkBlob, MAX_KEY_BLOB);
  
  FAIL(len < 0);
  
  //
  // Try to create new key using decoded key blob.
  //
  
  DBG_MSG("Creating key from blob...\n");
  
  FAIL(KeyFromBlob(key, (BYTE *) pkBlob, len));
  
  //DBG_DUMP_TO_FILE("c:/tmp/pkBlob.dat", pkBlob, MAX_KEY_BLOB);
  
  exitCode = 0;
  
fail:

  if (exitCode)
  {
    DBG_MSG("ERROR. Cannot decode auth-key from buffer.\n");
  }

  DBG_LEAVE("DecodeBase64Key");
  
  return exitCode;
}

//
// Compares two key.
//
// key1 - first key to compare (IN)
// key2 - second key to compare (IN)
//
// RETURNS: 0 if keys are equals.
//

Int KeyCompare(const Key *key1, const Key *key2)
{
  DBG_ENTRY("KeyCompare");
  
  Int exitCode = 1;
  
  FAIL(key1 == NULL);
  FAIL(key2 == NULL);
  
  FAIL(key1 -> type != key2 -> type);
  
  switch (key1 -> type)
  {
    case KEY_RSA1:
    case KEY_RSA:
    {
      FAIL(key1 -> rsa == NULL);
      FAIL(key2 -> rsa == NULL);

      FAIL(OPENSSL(BN_cmp(key1 -> rsa -> e, key2 -> rsa -> e)) != 0);
      FAIL(OPENSSL(BN_cmp(key1 -> rsa -> n, key2 -> rsa -> n)) != 0);

      break;
    }  
           
    case KEY_DSA:
    {
      FAIL(key1 -> dsa == NULL);
      FAIL(key2 -> dsa == NULL);
      
      FAIL(OPENSSL(BN_cmp(key1 -> dsa -> p, key2 -> dsa -> p)) != 0);
      FAIL(OPENSSL(BN_cmp(key1 -> dsa -> q, key2 -> dsa -> q)) != 0);
      FAIL(OPENSSL(BN_cmp(key1 -> dsa -> g, key2 -> dsa -> g)) != 0);

      FAIL(OPENSSL(BN_cmp(key1 -> dsa -> pub_key, key2 -> dsa -> pub_key)) != 0);

      break;
    }
    
    default:
    {
      DBG_MSG("KeyCompare : Unknown key type.\n");

      FAIL(1);
    }
  }  

  exitCode = 0;

fail:

  if (exitCode)
  {
    DBG_MSG("KeyCompare : NOT equal.\n");
  }
  else
  {
    DBG_MSG("KeyCompare : OK.\n");
  }
  
  DBG_LEAVE("KeyCompare");
  
  return exitCode;
}

//
// Search for given key in given file.
//
// fname     - file name, where to search (IN)
// patterKey - key pattern, what to search (IN)
//
// RETURNS: 0 if key founded.
//

Int FindKeyInFile(const wchar_t *fname, Key *patternKey)
{
  DBG_ENTRY("FindKeyInFile");
  
  Int exitCode = 1;
  
  Char line[MAX_KEYLINE_SIZE];
  
  Int notFound = 1;
  
  FILE *f = NULL;
  
  //
  // Open file with keys.
  //
  
  DBG_MSG("Opening [%ls] file...\n", fname);
  
  FAIL(fname == NULL);
  
  f = _wfopen(fname, L"rt");
  
  FAIL(f == NULL);
  
  //
  // Search for key in file. Key are stored in lines.
  //
  
  DBG_MSG("Searching for line with given key...\n");
  
  while(notFound && fgets(line, MAX_KEYLINE_SIZE, f))
  {
    Char *p = line;
    
    Key *readedKey = NULL; 
    
    Int decodeError = 1;
    
    SkipWhite(p);

    switch(p[0])
    {
      //
      // # means key is commented.
      // 0 and \n means empty line.
      //
      
      case '\0':
      case '\n':
      case '#':
      {
        DBG_MSG("Skipping empty or commented line...\n");
        
        break;
      }
  
      //
      // Try to decode key from line.
      //
      
      default:
      {
        decodeError = DecodeBase64Key(readedKey, p);

        //
        // If reading key fails, try to skip options before key.
        //
        
        if (decodeError)
        {
          DBG_MSG("Trying to skip options block before key...\n");
          
          Int quoted = 0;
          
          for (; *p && (quoted || (*p != ' ' && *p != '\t')); p++)
          {
            if (*p == '\\' && p[1] == '"')
            {
              p++;
            }  
            else if (*p == '"')
            {
              quoted = !quoted;
            }  
          }

          //
          // Try to read again, after potentially options block skipped.
          //

          SkipWhite(p);
          
          decodeError = DecodeBase64Key(readedKey, p);
        }  

        //
        // If key readed and decoded try to match with pattern key.
        //
        
        if (decodeError == 0)
        {
          notFound = KeyCompare(readedKey, patternKey);
            
          FreeKey(readedKey);
        }
      }
    }
  }
 
  exitCode = notFound;

fail:

  if (exitCode)
  {
    DBG_MSG("ERROR. Pattern key not found.\n");
  }

  if (f)
  {
    fclose(f);
  }  
  
  DBG_LEAVE("FindKeyInFile");
  
  return exitCode;
}


//
// Translate key type name to number.
//
// name - type name (IN)
//
// RETURNS: type number corresponding to given name.
//

Int KeyTypeFromName(const Char *name)
{
  if (StringCompare(name, "rsa1") == 0) 
  {
    return KEY_RSA1;
  } 
  
  if (StringCompare(name, "rsa") == 0) 
  {
    return KEY_RSA;
  } 
  
  if (StringCompare(name, "dsa") == 0) 
  {
    return KEY_DSA;
  } 
  
  if (StringCompare(name, "ssh-rsa") == 0) 
  {
    return KEY_RSA;
  }
  
  if (StringCompare(name, "ssh-dss") == 0) 
  {
    return KEY_DSA;
  }
  
  return KEY_UNSPEC;
}


//
// Allocate new Key struct and BigNum fields for specific Key type.
//
// key  - pointer to new allocated key (OUT)
// type - key type (RSA/DSA) (IN)
//
// RETURNS: 0 if OK.
//

Int AllocKey(Key *&key, Int type)
{
  DBG_ENTRY("AllocKey");
  
  Int exitCode = 1; 
  
  //
  // Allocate new key struct.
  //
  
  DBG_MSG("Allocating Key struct...\n");
  
  key = (Key *) LsaApi.AllocateLsaHeap(sizeof(Key));
  
  FAIL(key == NULL);
  
  ZeroMemory(key, sizeof(Key));
  
  key -> type = type;
  key -> dsa = NULL;
  key -> rsa = NULL;
  
  switch (key -> type)
  {
    //
    // Allocate new RSA key.
    //
    
    case KEY_RSA1:
    case KEY_RSA:
    {
      //
      // Allocate new RSA struct.
      //
      
      DBG_MSG("Allocating new RSA key...\n");
      
      key -> rsa = OPENSSL(RSA_new());
      
      FAIL(key -> rsa == NULL);
      
      //
      // Allcoate new BigNumber fields for RSA key.
      //
      
      DBG_MSG("Allocating BigNum fields in RSA...\n");
      
      key -> rsa -> n = OPENSSL(BN_new());
      key -> rsa -> e = OPENSSL(BN_new());
 
      FAIL(key -> rsa -> e == NULL);
      FAIL(key -> rsa -> n == NULL);
      
      break;
    }  
    
    //
    // Allocate new DSA key.
    //

    case KEY_DSA:
    {
      //
      // Allocate new DSA struct.
      //
      
      DBG_MSG("Allocating new DSA key...\n");
      
      key -> dsa = OPENSSL(DSA_new());
      
      FAIL(key -> dsa == NULL);
      
      //
      // Allcoate new BigNumber fields for DSA key.
      //

      DBG_MSG("Allocating BigNum fields in DSA...\n");

      key -> dsa -> p = OPENSSL(BN_new());
      key -> dsa -> q = OPENSSL(BN_new());
      key -> dsa -> g = OPENSSL(BN_new());
      key -> dsa -> pub_key = OPENSSL(BN_new());
      
      FAIL(key -> dsa -> p == NULL);
      FAIL(key -> dsa -> q == NULL);
      FAIL(key -> dsa -> g == NULL);
      FAIL(key -> dsa -> pub_key == NULL);

      break;
    }  
   
    default:
    {
      DBG_MSG("ERROR. Key type not recognised (%u).\n", type);

      FAIL(1);
    }
  }  

  exitCode = 0;

fail:

  if (exitCode)
  {
    DBG_MSG("ERROR. Cannot create new key.\n");
  }
  
  DBG_LEAVE("AllocKey");
  
  return exitCode;
}

//
// Free Key struct.
//
// key - key to free (IN)
//

void FreeKey(Key *key)
{
  DBG_ENTRY("FreeKey");
  
  if (key)
  {
    switch (key -> type)
    {
      case KEY_RSA1:
      case KEY_RSA:
      {
        if (key -> rsa != NULL)
        {
          OPENSSL(RSA_free(key -> rsa));

          key -> rsa = NULL;
        
          break;
        }  
      }
    
      case KEY_DSA:
      {
        if (key -> dsa != NULL)
        {
          OPENSSL(DSA_free(key -> dsa));
        
          key -> dsa = NULL;
        
          break;
        }  
      }  
    }
  
    LsaApi.FreeLsaHeap(key);
  }  

  DBG_LEAVE("FreeKey");
}

//
// Allocate and initialize new Key from pkBlob buffer.
//
// key  - new, created key (OUT)
// blob - public key blob buffer (IN)
// blen - size of blob buffer in bytes (IN)
//
// RETURNS: 0 if OK.
//

Int KeyFromBlob(Key *&key, Unsigned Char *blob, Unsigned Int blen)
{
  DBG_ENTRY("KeyFromBlob");
  
  //DBG_DUMP_TO_FILE("c:/tmp/pkBlob.dat", blob, blen);
  
  Int exitCode = 1;

  Int type = 0;
  
  Char *ktype = NULL;

  Unsigned Int bytesInBlob = blen;

  Unsigned Int cbSize = 0;
  
  key = NULL;
  
  //
  // Retrieve key type from blob.
  //
  
  DBG_MSG("Retrieving key type from blob...\n");

  FAIL(PopString(&ktype, cbSize, blob, bytesInBlob));
  
  FAIL(ktype == NULL);

  //
  // Convert type name to Int.
  //
  
  type = KeyTypeFromName(ktype);
  
  //
  // Retrieve Key body from blob.
  //

  switch (type) 
  {
    case KEY_RSA:
    { 
      DBG_MSG("Allocating new RSA key...\n");

      FAIL(AllocKey(key, type));
      
      DBG_MSG("Retrieving RSA {e, n} big numbers...\n");

      FAIL(PopBigNum(key -> rsa -> e, blob, bytesInBlob));
      FAIL(PopBigNum(key -> rsa -> n, blob, bytesInBlob));
     
      break;
    }  
    
    case KEY_DSA:
    {
      DBG_MSG("Allocating new DSA key...\n");
      
      FAIL(AllocKey(key, type));
      
      DBG_MSG("Retrieving DSA {p, q, g, pub_key}, big numbers...\n");

      FAIL(PopBigNum(key -> dsa -> p, blob, bytesInBlob));
      FAIL(PopBigNum(key -> dsa -> q, blob, bytesInBlob));
      FAIL(PopBigNum(key -> dsa -> g, blob, bytesInBlob));
      FAIL(PopBigNum(key -> dsa -> pub_key, blob, bytesInBlob));
     
      break;
    }
    
    default:
    {
      FAIL(1);
    }
  }  

  //
  // Does any bytes remain in blob buffer?
  //

  DBG_MSG("%u bytes remaining in key blob.\n", bytesInBlob);

  FAIL(bytesInBlob != 0);
  
  exitCode = 0;

fail:
  
  if (exitCode)
  {
    DBG_MSG("ERROR. Cannot create key from blob.\n");
    
    FreeKey(key);
  }
  
  LsaApi.FreeLsaHeap(ktype);  
  
  DBG_LEAVE("KeyFromBlob");
  
  return exitCode;
}
