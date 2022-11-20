/**
  Copyright © 2015 Odzhan. All Rights Reserved.
  
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#ifndef SERPENT_H
#define SERPENT_H

#include "macros.h"

#define GOLDEN_RATIO    0x9e3779b9l

#define SERPENT_ROUNDS  32
#define SERPENT_BLK_LEN 16
#define SERPENT_KEY256  32

#define SERPENT_ENCRYPT  0
#define SERPENT_DECRYPT  1

#define SERPENT_IP       0
#define SERPENT_FP       1

typedef union _serpent_blk_t {
  uint8_t b[SERPENT_BLK_LEN];
  uint32_t w[SERPENT_BLK_LEN/4];
  uint64_t q[SERPENT_BLK_LEN/2];
} serpent_blk;

typedef uint32_t serpent_subkey_t[4];

typedef struct serpent_key_t {
  serpent_subkey_t x[SERPENT_ROUNDS+1];
} serpent_key;

#ifdef __cplusplus
extern "C" {
#endif

  // x86 asm
  void serpent_setkeyx (serpent_key*, void*);  
  void serpent_encryptx (void*, serpent_key*, int);
  
  // C code
  void serpent_setkey (serpent_key*, void*);  
  void serpent_encrypt (void*, serpent_key*, int);

#ifdef __cplusplus
}
#endif

#endif
