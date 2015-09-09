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

#include "KeyAuth.h"

extern LSA_SECPKG_FUNCTION_TABLE LsaApi;

#ifdef DYNAMIC_OPENSSL
  extern SSLFuncList DynSSL;
#endif

//
// Perform DSA Key verification.
//
// key         - DSA key to verification (IN)
// sign        - signature (IN)
// signSize    - size of sign in bytes (IN)
// data        - ??
// dataSize    - size of data int bytes (IN)
// dataFellows - ?? This is copy of global variable from sshd (IN)
//
// RETURNS: 0 if OK.
//

Int VerifyDsaKey(const Key *key, Unsigned Char *sign, 
                   Unsigned Int signSize, const Unsigned Char *data, 
                       Unsigned Int dataSize, Int dataFellows)
{
  DBG_ENTRY("VerifyDsaKey");
  
  Int exitCode = 1;
  
  DSA_SIG *sig = NULL;
  
  const EVP_MD *evp_md = OPENSSL(EVP_sha1());
  
  EVP_MD_CTX md;

  Unsigned Char digest[EVP_MAX_MD_SIZE];

  Unsigned Char *sigblob = NULL;
  
  Char *ktype = NULL;  

  Unsigned Int len    = 0;
  Unsigned Int dlen   = 0;
  Unsigned Int cbSize = 0;
  
  Unsigned Int bytesInSign = signSize;
  
  //
  // Are args correct?
  //
  
  DBG_MSG("Checking args...\n");
  
  FAIL(key == NULL);
  FAIL(key -> type != KEY_DSA);
  FAIL(key -> dsa == NULL);
  
  //
  // fetch signature 
  //
  
  if (dataFellows & SSH_BUG_SIGBLOB) 
  {
    sigblob = (Unsigned Char *) LsaApi.AllocateLsaHeap(signSize);
    
    memcpy(sigblob, sign, signSize);

    len = signSize;
  }
  else 
  {
    //
    // Is signature type 'ssh-dss' ?
    //
    
    DBG_MSG("Checking signature type...\n");
    
    FAIL(PopString(&ktype, cbSize, sign, bytesInSign));
    
    FAIL(ktype == NULL);
    
    FAIL(StringCompare("ssh-dss", ktype) != 0);
    
    //
    // Retrieve signature blob.
    //
    
    DBG_MSG("Retrieving signature blob from buffer...\n");
    
    FAIL(PopString((Char **) &sigblob, len, sign, bytesInSign));
    
    //
    // Does any data still remain in signature bufer?
    //
    
    DBG_MSG("Checking does any data still remain"
                " in signature buffer [%u]...\n", bytesInSign);

    FAIL(bytesInSign != 0);
  }

  //
  // Is signature blob is correct?
  //
  
  DBG_MSG("Checking signature blob size "
              "[len = %u, SIGBLOB_LEN = %u]...\n", len, SIGBLOB_LEN);
  
  FAIL(len != SIGBLOB_LEN);
  
  //
  // parse signature
  //
  
  DBG_MSG("DSA_SIG_new()...\n");
  
  sig = OPENSSL(DSA_SIG_new());
  
  FAIL (sig == NULL);
  
  
  DBG_MSG("BN_new()...\n");  
  
  sig -> r = OPENSSL(BN_new());
  
  FAIL(sig -> r == NULL);
  
  
  DBG_MSG("BN_new()...\n");
  
  sig -> s = OPENSSL(BN_new());
  
  FAIL(sig -> s == NULL);
  
  //
  //
  //
  
  DBG_MSG("BN_bin2bn()...\n");

  FAIL(OPENSSL(BN_bin2bn(sigblob, INTBLOB_LEN, sig -> r) == NULL));

  FAIL(OPENSSL(BN_bin2bn(sigblob + INTBLOB_LEN, INTBLOB_LEN, sig -> s) == NULL));

  //
  // sha1 the data.
  //
  
  OPENSSL(EVP_DigestInit(&md, evp_md));
  
  OPENSSL(EVP_DigestUpdate(&md, data, dataSize));
  
  OPENSSL(EVP_DigestFinal(&md, digest, &dlen));
    
  //
  //
  //
  
  DBG_MSG("DSA_do_verify()...\n");
  
  FAIL(OPENSSL(DSA_do_verify(digest, dlen, sig, key -> dsa) != 1));

  exitCode = 0;

fail:             
             
  if (exitCode)
  {
    DBG_MSG("ERROR. VerifyDsaKey() failed.\n");
  }
  
  //
  // Clean up.
  //  
  
  ZeroMemory(digest, sizeof(digest));

  ZeroMemory(sigblob, len);
  
  if (sig)
  {
    OPENSSL(DSA_SIG_free(sig));
  }  

  LsaApi.FreeLsaHeap(sigblob);

  LsaApi.FreeLsaHeap(ktype);
  
  DBG_LEAVE("VerifyDsaKey");
  
  return exitCode;
}

//
// Decrypt given signature by given RSA key and compare result with given
// hash. It is the last step in Rsa verification. 
//
// type     - NID type for key (sha1/md5) (IN) 
// hash     - hash for comparing (IN)
// hashSize - size of hash buffer in bytes (IN)
// sigBuf   - signature to decrypt (IN)
// sigSize  - size of sigBuf in bytes (IN)
// rsa      - RSA key struct (IN).
//
// RETURNS: 0 if OK.
//

Int DoRsaVerify(Int type, Unsigned Char *hash, Unsigned Int hashSize,
                    Unsigned Char *sigBuf, Unsigned Int sigSize, RSA *rsa)
{
  DBG_ENTRY("DoRsaVerify");
  
  Int exitCode = 1;
  
  Unsigned Int rsaSize = 0;
  Unsigned Int oidlen  = 0;
  Unsigned Int hlen    = 0;

  Int len = 0;
  
  const Unsigned Char *oid = NULL;
  
  Unsigned Char *decrypted = NULL;

  switch (type) 
  {
    //
    // For SHA1 algorithm.
    //
    
    case NID_sha1:
    {
      oid    = id_sha1;
      oidlen = sizeof(id_sha1);
      hlen   = 20;

      break;
    }  

    //
    // For MD5 algorithm.
    //

    case NID_md5:
    {
      oid    = id_md5;
      oidlen = sizeof(id_md5);
      hlen   = 16;
      
      break;
    }  

    default:
    {
      DBG_MSG("ERROR. Unknown NID (%u).\n", type);
      
      FAIL(1);
    }  
  }

  //
  // Does given hash length match to algorithm (sha1/md5) ?
  //
  
  DBG_MSG("Checking hash length...\n");
  
  FAIL(hashSize != hlen);
  
  //
  // Does given signature length match to Key type?
  //
  
  DBG_MSG("Checking signature length...\n");

  rsaSize = OPENSSL(RSA_size(rsa));
  
  FAIL(sigSize == 0);

  FAIL(sigSize > rsaSize);
  
  //
  // Allocate memory for decrypted data.
  //
  
  DBG_MSG("Allocating buffer for decrypted data...\n");
  
  decrypted = (Unsigned Char *) LsaApi.AllocateLsaHeap(rsaSize);

  FAIL(decrypted == NULL);
  
  //
  // Decrypt signature using given RSA key. 
  //
  
  DBG_MSG("RSA_public_decrypt...\n");
  
  len = OPENSSL(RSA_public_decrypt(sigSize, sigBuf, decrypted, rsa, RSA_PKCS1_PADDING));

  FAIL(len < 0);

  FAIL(UnsignedCast(len) != (hlen + oidlen));

  //
  // Compare oids.
  //
  
  DBG_MSG("Comparing oids...\n");
  
  FAIL(memcmp(decrypted, oid, oidlen) != 0);
  
  //
  // Compare hashes.
  //

  DBG_MSG("Comparing hashes...\n");
  
  FAIL(memcmp(decrypted + oidlen, hash, hlen) != 0);
  
  exitCode = 0;

fail:

  LsaApi.FreeLsaHeap(decrypted);
  
  DBG_LEAVE("DoRsaVerify");

  return exitCode;
}

//
// Perform RSA key verification.
//
// key         - RSA key to verification (IN)
// sign        - signature (IN)
// signSize    - size of sign in bytes (IN)
// data        - ??
// dataSize    - size of data int bytes (IN)
// dataFellows - ?? This is copy of global variable from sshd (IN)
//
// RETURNS: 0 if OK.
//

Int VerifyRsaKey(const Key *key, Unsigned Char *sign, Int signSize,
                     Unsigned Char *data, Int dataSize, Int dataFellows)
{
  DBG_ENTRY("VerifyRsaKey");
  
  Int exitCode = 1;

  const EVP_MD *evp_md;
  
  EVP_MD_CTX md;
  
  Char *ktype = NULL;
  
  Unsigned Char digest[EVP_MAX_MD_SIZE];

  Unsigned Char *sigblob    = NULL;
  Unsigned Char *sigblobOld = NULL;
  
  Unsigned Int len    = 0;
  Unsigned Int dlen   = 0;
  Unsigned Int modlen = 0;
  Unsigned Int nid    = 0;
  Unsigned Int cbSize = 0;
  
  Unsigned Int bytesInSign = signSize;

  //
  // Are args correct?
  //
  
  DBG_MSG("Checking args...\n");
  
  FAIL(key == NULL);

  FAIL(key -> type != KEY_RSA);
 
  FAIL(key -> rsa == NULL);  

  //
  // Check is RSA modulus size not too small.
  //
  
  DBG_MSG("Checking RSA.n length...\n");
  
  FAIL(OPENSSL(BN_num_bits(key -> rsa -> n) < SSH_RSA_MINIMUM_MODULUS_SIZE));
  
  //
  // Retrievie and check is signature type correct.
  //

  DBG_MSG("Checking signature type...\n");
  
  //DBG_DUMP_TO_FILE("c:/tmp/sign.dat", sign, bytesInSign);
    
  FAIL(PopString(&ktype, cbSize, sign, bytesInSign));
  
  FAIL(StringCompare("ssh-rsa", ktype) != 0);

  //
  // Check signature size.
  //

  DBG_MSG("Checking signature size...\n");
  
  FAIL(PopString((Char **) &sigblob, len, sign, bytesInSign));
  
  FAIL(bytesInSign != 0);
  
  //
  // RSA_verify expects a signature of RSA_size.
  //
  
  DBG_MSG("Checking signature blob size....\n");
  
  modlen = OPENSSL(RSA_size(key -> rsa));
  
  FAIL(len > modlen);

  //
  // Adds zeros at begin of signature blob
  // to makes RSA_size(key) == Size(SignatureBlob).
  //

  if (len < modlen) 
  {
    Unsigned Int diff = modlen - len;
  
    DBG_MSG("Adding %u zeros to signature (modlen = %u, len = %u)", 
                diff, modlen, len);
                
    //
    // Reallocate sigblob.
    //
    
    DBG_MSG("Reallocating sigblob buffer..."
                "[oldSize = %u, newSize = %u]\n", len, modlen);

    sigblobOld = sigblob;

    sigblob = (Unsigned Char *) LsaApi.AllocateLsaHeap(modlen);
    
    FAIL(sigblob == NULL);
    
    memcpy(sigblob + diff, sigblobOld, len);
    
    memset(sigblob, 0, diff);
    
    len = modlen;
  }

  //
  // ??
  //
  
  nid = (dataFellows & SSH_BUG_RSASIGMD5) ? NID_md5 : NID_sha1;
  
  DBG_MSG("EVP_get_digestbynid(%u)...\n", nid);

  DBG_MSG("OBJ_nid2sn(nid) = %s\n", OPENSSL(OBJ_nid2sn(nid)));
  
  evp_md = OPENSSL(EVP_get_digestbyname(OPENSSL(OBJ_nid2sn(nid))));
  
  DBG_MSG("digest = %p\n", evp_md);
  
  FAIL(evp_md == NULL);
  
  //
  // ??
  //
  
  OPENSSL(EVP_DigestInit(&md, evp_md));

  OPENSSL(EVP_DigestUpdate(&md, data, dataSize));
  
  OPENSSL(EVP_DigestFinal(&md, digest, &dlen));

  FAIL(DoRsaVerify(nid, digest, dlen, sigblob, len, key -> rsa));

  exitCode = 0;
  
fail:

  if (exitCode)
  {
    DBG_MSG("ERROR. VerifyRsaKey() failed.\n");
  }
  
  ZeroMemory(digest, sizeof(digest));
  ZeroMemory(sigblob, len);
  
  LsaApi.FreeLsaHeap(ktype);
  LsaApi.FreeLsaHeap(sigblob);
  LsaApi.FreeLsaHeap(sigblobOld);

  DBG_LEAVE("VerifyRsaKey");
  
  return exitCode;
}


//
// Perform RSA or DSA Key verification.
//
// key         - key to verification (IN)
// sign        - signature (IN)
// signSize    - size of sign in bytes (IN)
// data        - ??
// dataSize    - size of data in bytes (IN)
// dataFellows - ?? This is copy of global variable from sshd (IN)
//
// RETURNS: 0 if OK.
//

Int VerifyKey(const Key *key, Unsigned Char *sign, Int signSize,
                  Unsigned Char *data, Int dataSize, Int dataFellows)
{
  DBG_ENTRY("VerifyKey");
  
  Int exitCode = 1;
  
  //
  // Check args.
  //
  
  DBG_MSG("Checking args...\n");
  
  FAIL(sign == NULL);
  FAIL(data == NULL);
  FAIL(key == NULL);
  
  FAIL(signSize == 0);
  
  //
  // For debug only.
  //
  
  //DBG_DUMP_TO_FILE("c:/tmp/sign.dat", sign, signSize);
  
  //
  // Verify RSA or DSA key.
  //

  switch (key -> type)
  {
    case KEY_DSA:
    {
      DBG_MSG("DSA Key detected...\n");
      
      FAIL(VerifyDsaKey(key, sign, signSize, data, dataSize, dataFellows));
      
      break;
    }
    
    case KEY_RSA:
    {
      DBG_MSG("RSA Key detected...\n");
      
      FAIL(VerifyRsaKey(key, sign, signSize, data, dataSize, dataFellows));
      
      break;
    }

    default:
    {
      DBG_MSG("ERROR. Key type not recognised.\n"); 
      
      FAIL(1);
    }
  }

  exitCode = 0;
  
fail:

  if (exitCode)
  {
    DBG_MSG("ERROR. Key authorization failed.\n");
  }  
  
  DBG_LEAVE("VerifyKey");
  
  return exitCode;
}  
