// SPDX-License-Identifier: CC0-1.0+ OR 0BSD OR OR MIT-0
// Copyright (c) 2024, Ryan Castellucci, no rights reserved
#pragma once

#ifdef SODIUM_SHA256
typedef struct crypto_hash_sha256_state {
  uint32_t state[8];
  uint64_t count;
  uint8_t  buf[64];
} crypto_hash_sha256_state;

int crypto_hash_sha256_init(crypto_hash_sha256_state *);
int crypto_hash_sha256_update(crypto_hash_sha256_state *, const unsigned char *, unsigned long long);
int crypto_hash_sha256_final(crypto_hash_sha256_state *, unsigned char *);

#define SHA256_CTX crypto_hash_sha256_state
#define SHA256_Init(CTX) crypto_hash_sha256_init(CTX)
#define SHA256_Update(CTX, IN, SZ) crypto_hash_sha256_update(CTX, IN, SZ)
#define SHA256_Final(HASH, CTX) crypto_hash_sha256_final(CTX, HASH)
#endif

#ifdef SODIUM_SHA512
typedef struct crypto_hash_sha512_state {
  uint64_t state[8];
  uint64_t count[2];
  uint8_t  buf[128];
} crypto_hash_sha512_state;

int crypto_hash_sha512_init(crypto_hash_sha512_state *);
int crypto_hash_sha512_update(crypto_hash_sha512_state *, const unsigned char *, unsigned long long);
int crypto_hash_sha512_final(crypto_hash_sha512_state *, unsigned char *);

#define SHA512_CTX crypto_hash_sha512_state
#define SHA512_Init(CTX) crypto_hash_sha512_init(CTX)
#define SHA512_Update(CTX, IN, SZ) crypto_hash_sha512_update(CTX, IN, SZ)
#define SHA512_Final(HASH, CTX) crypto_hash_sha512_final(CTX, HASH)

#include "../gen/sha2_const.h"
static int SHA384_Init(crypto_hash_sha512_state *ctx) {
  static const uint64_t sha384_iv[] = {
    SHA384_IV0, SHA384_IV1, SHA384_IV2, SHA384_IV3,
    SHA384_IV4, SHA384_IV5, SHA384_IV6, SHA384_IV7
  };

  ctx->count[0] = 0;
  ctx->count[1] = 0;
  memcpy(ctx->state, sha384_iv, sizeof(sha384_iv));

  return 0;
}
#endif
