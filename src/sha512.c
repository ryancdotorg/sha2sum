// SPDX-License-Identifier: CC0-1.0+ OR 0BSD OR OR MIT-0
// Copyright (c) 2024, Ryan Castellucci, no rights reserved

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha2.h"
#include "sha512.h"
#include "../gen/sha2_const.h"

#define s0(x) (ROR64(x,  1) ^ ROR64(x,  8) ^ (x >>   7))   // s0
#define s1(x) (ROR64(x, 19) ^ ROR64(x, 61) ^ (x >>   6))   // s1

#define S0(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39)) // S0
#define S1(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41)) // S1


static const uint64_t IV512[] = {
  SHA512_IV0, SHA512_IV1, SHA512_IV2, SHA512_IV3,
  SHA512_IV4, SHA512_IV5, SHA512_IV6, SHA512_IV7
};

static const uint64_t IV384[] = {
  SHA384_IV0, SHA384_IV1, SHA384_IV2, SHA384_IV3,
  SHA384_IV4, SHA384_IV5, SHA384_IV6, SHA384_IV7
};

#if defined(__OPTIMIZE_SIZE__) || defined(SMALL_SHA512) || defined(SMALL_SHA2)
static const uint64_t K512[] = { SHA512_K00,SHA512_K01,SHA512_K02,SHA512_K03,
SHA512_K04,SHA512_K05,SHA512_K06,SHA512_K07,SHA512_K08,SHA512_K09,SHA512_K10,
SHA512_K11,SHA512_K12,SHA512_K13,SHA512_K14,SHA512_K15,SHA512_K16,SHA512_K17,
SHA512_K18,SHA512_K19,SHA512_K20,SHA512_K21,SHA512_K22,SHA512_K23,SHA512_K24,
SHA512_K25,SHA512_K26,SHA512_K27,SHA512_K28,SHA512_K29,SHA512_K30,SHA512_K31,
SHA512_K32,SHA512_K33,SHA512_K34,SHA512_K35,SHA512_K36,SHA512_K37,SHA512_K38,
SHA512_K39,SHA512_K40,SHA512_K41,SHA512_K42,SHA512_K43,SHA512_K44,SHA512_K45,
SHA512_K46,SHA512_K47,SHA512_K48,SHA512_K49,SHA512_K50,SHA512_K51,SHA512_K52,
SHA512_K53,SHA512_K54,SHA512_K55,SHA512_K56,SHA512_K57,SHA512_K58,SHA512_K59,
SHA512_K60,SHA512_K61,SHA512_K62,SHA512_K63,SHA512_K64,SHA512_K65,SHA512_K66,
SHA512_K67,SHA512_K68,SHA512_K69,SHA512_K70,SHA512_K71,SHA512_K72,SHA512_K73,
SHA512_K74,SHA512_K75,SHA512_K76,SHA512_K77,SHA512_K78,SHA512_K79};

static void NOINLINE sha2_512_round(int r, uint64_t W[16], uint64_t x[8]) {
#define a x[( 8-r)&7]
#define b x[( 9-r)&7]
#define c x[(10-r)&7]
#define d x[(11-r)&7]
#define e x[(12-r)&7]
#define f x[(13-r)&7]
#define g x[(14-r)&7]
#define h x[(15-r)&7]
  uint64_t t = h + S1(e) + maj(e,f,g) + K512[r] + W(r);
  d += t; h = t + S0(a) + ch(a,b,c);
#undef a
#undef b
#undef c
#undef d
#undef e
#undef f
#undef g
#undef h
}

// small implementation
NOINLINE
static void sha2_512_xform(uint64_t *digest, const uint8_t *data, uint32_t nblk) {
  const uint64_t *input=(uint64_t *)data;

  for (const uint64_t *end = input + nblk * 16; input < end; input += 16) {
    uint64_t W[16], x[8];
    // load input
    for (int i = 0; i < 16; ++i) W[i] = U64BE2H(input[i]);
    // load digest state
    for (int i = 0; i <  8; ++i) x[i] = digest[i];
    // run rounds
    for (int i = 0; i < 80; ++i) sha2_512_round(i, W, x);
    // update digest state
    for (int i = 0; i <  8; ++i) digest[i] += x[i];
  }
}
#else

static uint64_t sector_0x00(const uint8_t *data) {
  const uint64_t *block = (uint64_t *)__builtin_assume_aligned(data, 32);
  uint64_t r = 0;
  for (size_t i = 0; i < (SECTOR_SZ/sizeof(*block)); ++i) r |= block[i];
  return r;
}

static uint64_t sector_0xFF(const uint8_t *data) {
  const uint64_t *block = (uint64_t *)__builtin_assume_aligned(data, 32);
  uint64_t r = __UINT64_MAX__;
  for (size_t i = 0; i < (SECTOR_SZ/sizeof(*block)); ++i) r &= block[i];
  return r + 1; // becomes zero if and only if r still had all bits set
}

#define SHA512_ROUNDS(DIGEST) do { \
  uint64_t A, B, C, D, E, F, G, H, temp; \
  /* load digest state */ \
  A = DIGEST[0]; B = DIGEST[1]; C = DIGEST[2]; D = DIGEST[3]; \
  E = DIGEST[4]; F = DIGEST[5]; G = DIGEST[6]; H = DIGEST[7]; \
  /* run rounds */ \
  R( 0,SHA512_K00); R( 1,SHA512_K01); R( 2,SHA512_K02); R( 3,SHA512_K03); \
  R( 4,SHA512_K04); R( 5,SHA512_K05); R( 6,SHA512_K06); R( 7,SHA512_K07); \
  R( 8,SHA512_K08); R( 9,SHA512_K09); R(10,SHA512_K10); R(11,SHA512_K11); \
  R(12,SHA512_K12); R(13,SHA512_K13); R(14,SHA512_K14); R(15,SHA512_K15); \
  R(16,SHA512_K16); R(17,SHA512_K17); R(18,SHA512_K18); R(19,SHA512_K19); \
  R(20,SHA512_K20); R(21,SHA512_K21); R(22,SHA512_K22); R(23,SHA512_K23); \
  R(24,SHA512_K24); R(25,SHA512_K25); R(26,SHA512_K26); R(27,SHA512_K27); \
  R(28,SHA512_K28); R(29,SHA512_K29); R(30,SHA512_K30); R(31,SHA512_K31); \
  R(32,SHA512_K32); R(33,SHA512_K33); R(34,SHA512_K34); R(35,SHA512_K35); \
  R(36,SHA512_K36); R(37,SHA512_K37); R(38,SHA512_K38); R(39,SHA512_K39); \
  R(40,SHA512_K40); R(41,SHA512_K41); R(42,SHA512_K42); R(43,SHA512_K43); \
  R(44,SHA512_K44); R(45,SHA512_K45); R(46,SHA512_K46); R(47,SHA512_K47); \
  R(48,SHA512_K48); R(49,SHA512_K49); R(50,SHA512_K50); R(51,SHA512_K51); \
  R(52,SHA512_K52); R(53,SHA512_K53); R(54,SHA512_K54); R(55,SHA512_K55); \
  R(56,SHA512_K56); R(57,SHA512_K57); R(58,SHA512_K58); R(59,SHA512_K59); \
  R(60,SHA512_K60); R(61,SHA512_K61); R(62,SHA512_K62); R(63,SHA512_K63); \
  R(64,SHA512_K64); R(65,SHA512_K65); R(66,SHA512_K66); R(67,SHA512_K67); \
  R(68,SHA512_K68); R(69,SHA512_K69); R(70,SHA512_K70); R(71,SHA512_K71); \
  R(72,SHA512_K72); R(73,SHA512_K73); R(74,SHA512_K74); R(75,SHA512_K75); \
  R(76,SHA512_K76); R(77,SHA512_K77); R(78,SHA512_K78); R(79,SHA512_K79); \
  /* update digest state */ \
  DIGEST[0] += A; DIGEST[1] += B; DIGEST[2] += C; DIGEST[3] += D; \
  DIGEST[4] += E; DIGEST[5] += F; DIGEST[6] += G; DIGEST[7] += H; \
} while(0);

NOINLINE
static void sha2_512_0x00(uint64_t *digest, size_t nblk) {
  while (nblk--) {
    // entire input block is 0x00
    uint64_t W[16] = {
      0, 0, 0, 0,   0, 0, 0, 0,
      0, 0, 0, 0,   0, 0, 0, 0
    };
    SHA512_ROUNDS(digest);
  }
}

NOINLINE
static void sha2_512_0xFF(uint64_t *digest, size_t nblk) {
  while (nblk--) {
    // entire input block is 0xFF
    uint64_t W[16] = {
      ~0ULL, ~0ULL, ~0ULL, ~0ULL,   ~0ULL, ~0ULL, ~0ULL, ~0ULL,
      ~0ULL, ~0ULL, ~0ULL, ~0ULL,   ~0ULL, ~0ULL, ~0ULL, ~0ULL
    };
    SHA512_ROUNDS(digest);
  }
}

// fast implementation
NOINLINE
static void sha2_512_xform(uint64_t *digest, const uint8_t *data, uint32_t nblk) {
  const uint64_t *input=(uint64_t *)data;

  for (const uint64_t *end = input + nblk * 16; input < end; input += 16) {
    uint64_t W[16];
    // load input
    for (int i = 0; i < 16; ++i) W[i] = U64H2BE(input[i]);
    SHA512_ROUNDS(digest);
  }
}

#endif

int SHA512_Init(SHA512_CTX *ctx) {
  for (int i = 0; i < 8; ++i) ctx->state[i] = IV512[i];

  ctx->bytelen = 0;
  ctx->datalen = 0;
  ctx->openssl = 0;

  return 1;
}

int SHA384_Init(SHA512_CTX *ctx) {
  for (int i = 0; i < 8; ++i) ctx->state[i] = IV384[i];

  ctx->bytelen = 0;
  ctx->datalen = 0;
  ctx->openssl = 0;

  return 1;
}

int SHA512_Update(SHA512_CTX *ctx, const uint8_t data[], size_t len) {
  size_t i = 0;
  const uint8_t *input = data;

  if (ctx->datalen > 0) {
    i = 128 - ctx->datalen;

    if (i > len) {
      memcpy(((unsigned char *)(ctx->data)) + (ctx->datalen), input, len);
      ctx->datalen += len;
      return 1;
    } else {
      memcpy(((unsigned char *)(ctx->data)) + (ctx->datalen), input, i);
      sha2_512_xform(ctx->state, ctx->data, 1);
      ctx->bytelen += 128;
      ctx->datalen = 0;
      input += i;
      len -= i;
    }
  }

#if !(defined(__OPTIMIZE_SIZE__) || defined(SMALL_SHA512) || defined(SMALL_SHA2))
  // for large blocks of data, attempt to detect long runs of zero or one bits
  if (len >= 16384) {
    while (len >= (SECTOR_SZ + 31)) {
      const uint64_t amask = ~31ULL;
      const uint8_t *align = (uint8_t *)((((uintptr_t)input) + 31) & amask);
      const uint8_t *end = (uint8_t *)(((uintptr_t)input) + len);
      const uint8_t *last =  (uint8_t *)(((uintptr_t)end) - (SECTOR_SZ - 1));

      const uint8_t *p = (uint8_t *)input;

      if ((*((uint64_t *)align) + 1) & ~1ULL) {
        /* do nothing */
      } else if (*((uint64_t *)align) == 0) {
        uint8_t x = 0x00;
        while (p < align) x |= *p++;
        if (x == 0x00) {
          while (p < last) {
            if (sector_0x00(p) != 0) break;
            p += SECTOR_SZ;
          }
          size_t skipped = p - align;
          if (skipped > 0) {
            sha2_512_0x00(ctx->state, skipped / 128);
            ctx->bytelen += skipped;
            input += skipped;
            len -= skipped;
            continue;
          }
        }
      } else { /* *((uint64_t *)align) == __UINT64_MAX__ */
        uint8_t x = 0xFF;
        while (p < align) x &= *p++;
        if (x == 0xFF) {
          while (p < last) {
            if (sector_0xFF(p) != 0) break;
            p += SECTOR_SZ;
          }
          size_t skipped = p - align;
          if (skipped > 0) {
            sha2_512_0xFF(ctx->state, skipped / 128);
            ctx->bytelen += skipped;
            input += skipped;
            len -= skipped;
            continue;
          }
        }
      }

      sha2_512_xform(ctx->state, input, SECTOR_SZ / 128);
      ctx->bytelen += SECTOR_SZ;
      input += SECTOR_SZ;
      len -= SECTOR_SZ;
    }
  }
#endif

  if (len >= 128) {
    i = len / 128;
    sha2_512_xform(ctx->state, input, i);
    len -= i * 128;
    input += i * 128;
    ctx->bytelen += i * 128;
  }

  memcpy(ctx->data, input, len);
  ctx->datalen = len;

  return 1;
}

int SHA512_Final(uint8_t hash[], SHA512_CTX *ctx) {
  uint64_t *out = (uint64_t *)hash;
  uint32_t i = ctx->datalen;

  ctx->data[i++] = 0x80;

  if (ctx->datalen < 112) {
    memset(((unsigned char *)(ctx->data)) + i, 0, 120 - i);
  } else {
    memset(((unsigned char *)(ctx->data)) + i, 0, 128 - i);
    sha2_512_xform(ctx->state, ctx->data, 1);
    memset(ctx->data, 0, 120);
  }

  ctx->bytelen += ctx->datalen;
  STOR64BE(ctx->data + 120, ctx->bytelen * 8);
  sha2_512_xform(ctx->state, ctx->data, 1);
  for (int i = 0; i < 8; ++i) out[i] = U64H2BE(ctx->state[i]);

  return 1;
}

#ifdef TEST
static unsigned char sha512_md[64];

unsigned char *SHA512(const uint8_t data[], size_t len, uint8_t hash[]) {
  uint8_t *out = hash != NULL ? hash : sha512_md;
  SHA512_CTX ctx[] = {0};
  SHA512_Init(ctx);
  SHA512_Update(ctx, data, len);
  SHA512_Final(out, ctx);
  return out;
}

unsigned char *SHA384(const uint8_t data[], size_t len, uint8_t hash[]) {
  uint8_t *out = hash != NULL ? hash : sha512_md;
  SHA512_CTX ctx[] = {0};
  SHA384_Init(ctx);
  SHA512_Update(ctx, data, len);
  SHA512_Final(out, ctx);
  return out;
}

int main(int argc, char *argv[]) {
  char buf[129];
  for (int i = 1; i < argc; ++i) {
    char *data = argv[i];
    uint8_t *hash = SHA512((uint8_t*)data, strlen(data), NULL);
    char *p = buf;
    for (int j = 0; j < 64; ++j) {
      sprintf(p, "%02x", hash[j]);
      p += 2;
    }
    printf("%s\n", buf);
  }

  return 0;
}
#endif
