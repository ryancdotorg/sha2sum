// SPDX-License-Identifier: CC0-1.0+ OR 0BSD OR OR MIT-0
// Copyright (c) 2024, Ryan Castellucci, no rights reserved
#pragma once

#include <sodium.h>

#define SHA256_CTX crypto_hash_sha256_state
#define SHA256_Init(CTX) crypto_hash_sha256_init(CTX)
#define SHA256_Update(CTX, IN, SZ) crypto_hash_sha256_update(CTX, IN, SZ)
#define SHA256_Final(HASH, CTX) crypto_hash_sha256_final(CTX, HASH)

#define SHA512_CTX crypto_hash_sha512_state
#define SHA512_Init(CTX) crypto_hash_sha512_init(CTX)
#define SHA512_Update(CTX, IN, SZ) crypto_hash_sha512_update(CTX, IN, SZ)
#define SHA512_Final(HASH, CTX) crypto_hash_sha512_final(CTX, HASH)

#ifdef WITH_SHA512
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
