// SPDX-License-Identifier: CC0-1.0+ OR 0BSD OR OR MIT-0
// Copyright (c) 2024, Ryan Castellucci, no rights reserved

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha256.h"
#include "../gen/sha2_const.h"

#define NOINLINE __attribute__ ((noinline))

#define ROR32(x,n) __extension__({ uint32_t _x=(x), _n=(n); (_x >> _n) | (_x << (32-_n)); })
#define ROR64(x,n) __extension__({ uint64_t _x=(x), _n=(n); (_x >> _n) | (_x << (64-_n)); })

#define U32BE2H(V) __extension__({ \
  uint32_t _v = (V); \
  uint8_t *_t = (uint8_t*)&_v; \
  uint32_t _r = 0; \
  _r |= ((uint32_t)_t[0]) << 24; \
  _r |= ((uint32_t)_t[1]) << 16; \
  _r |= ((uint32_t)_t[2]) <<  8; \
  _r |= ((uint32_t)_t[3]) <<  0; \
  _r; \
})

#define U32H2BE(V) __extension__({ \
  uint32_t _v = (V); \
  uint8_t _t[4]; \
  _t[0] = (_v & UINT32_C(0xFF000000)) >> 24; \
  _t[1] = (_v & UINT32_C(0x00FF0000)) >> 16; \
  _t[2] = (_v & UINT32_C(0x0000FF00)) >>  8; \
  _t[3] = (_v & UINT32_C(0x000000FF)) >>  0; \
  *((uint32_t*)_t); \
})

#define U64H2BE(V) __extension__({ \
  uint64_t _v = (V); \
  uint8_t _t[8]; \
  _t[0] = (_v & UINT64_C(0xFF00000000000000)) >> 56; \
  _t[1] = (_v & UINT64_C(0x00FF000000000000)) >> 48; \
  _t[2] = (_v & UINT64_C(0x0000FF0000000000)) >> 40; \
  _t[3] = (_v & UINT64_C(0x000000FF00000000)) >> 32; \
  _t[4] = (_v & UINT64_C(0x00000000FF000000)) >> 24; \
  _t[5] = (_v & UINT64_C(0x0000000000FF0000)) >> 16; \
  _t[6] = (_v & UINT64_C(0x000000000000FF00)) >>  8; \
  _t[7] = (_v & UINT64_C(0x00000000000000FF)) >>  0; \
  *((uint64_t*)_t); \
})

#define STOR32BE(D, V) (*((uint32_t*)(D)) = U32H2BE((V)))
#define STOR64BE(D, V) (*((uint64_t*)(D)) = U64H2BE((V)))

#define s0(x) (ROR32(x,  7) ^ ROR32(x, 18) ^ (x >>  3))
#define s1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ (x >> 10))

#define S0(x) (ROR32(x,  2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define S1(x) (ROR32(x,  6) ^ ROR32(x, 11) ^ ROR32(x, 25))

#define ch(x,y,z) ((x & y) | (z & (x | y)))
#define maj(x,y,z) (z ^ (x & (y ^ z)))

#define W(r) \
(r<16?W[r]:(W[r&15]=s1(W[(r+14)&15])+W[(r+9)&15]+s0(W[(r+1)&15])+W[r&15]))

#define P(r,a,b,c,d,e,f,g,h,K) {            \
  temp = h + S1(e) + maj(e,f,g) + K + W(r); \
  d += temp; h = temp + S0(a) + ch(a,b,c);  \
}

#define R(r,K) do {                                \
  if      ((r%8) == 0) { P(r,A,B,C,D,E,F,G,H,K); } \
  else if ((r%8) == 1) { P(r,H,A,B,C,D,E,F,G,K); } \
  else if ((r%8) == 2) { P(r,G,H,A,B,C,D,E,F,K); } \
  else if ((r%8) == 3) { P(r,F,G,H,A,B,C,D,E,K); } \
  else if ((r%8) == 4) { P(r,E,F,G,H,A,B,C,D,K); } \
  else if ((r%8) == 5) { P(r,D,E,F,G,H,A,B,C,K); } \
  else if ((r%8) == 6) { P(r,C,D,E,F,G,H,A,B,K); } \
  else if ((r%8) == 7) { P(r,B,C,D,E,F,G,H,A,K); } \
} while(0)

static const uint32_t IV[] = {
  SHA256_IV0, SHA256_IV1, SHA256_IV2, SHA256_IV3,
  SHA256_IV4, SHA256_IV5, SHA256_IV6, SHA256_IV7
};

#ifdef __OPTIMIZE_SIZE__
static const uint32_t K[] = {    SHA256_K00,SHA256_K01,SHA256_K02,SHA256_K03,
SHA256_K04,SHA256_K05,SHA256_K06,SHA256_K07,SHA256_K08,SHA256_K09,SHA256_K10,
SHA256_K11,SHA256_K12,SHA256_K13,SHA256_K14,SHA256_K15,SHA256_K16,SHA256_K17,
SHA256_K18,SHA256_K19,SHA256_K20,SHA256_K21,SHA256_K22,SHA256_K23,SHA256_K24,
SHA256_K25,SHA256_K26,SHA256_K27,SHA256_K28,SHA256_K29,SHA256_K30,SHA256_K31,
SHA256_K32,SHA256_K33,SHA256_K34,SHA256_K35,SHA256_K36,SHA256_K37,SHA256_K38,
SHA256_K39,SHA256_K40,SHA256_K41,SHA256_K42,SHA256_K43,SHA256_K44,SHA256_K45,
SHA256_K46,SHA256_K47,SHA256_K48,SHA256_K49,SHA256_K50,SHA256_K51,SHA256_K52,
SHA256_K53,SHA256_K54,SHA256_K55,SHA256_K56,SHA256_K57,SHA256_K58,SHA256_K59,
SHA256_K60,SHA256_K61,SHA256_K62,SHA256_K63};

static void NOINLINE sha2_256_round(int r, uint32_t W[16], uint32_t x[8]) {
#define a x[( 8-r)&7]
#define b x[( 9-r)&7]
#define c x[(10-r)&7]
#define d x[(11-r)&7]
#define e x[(12-r)&7]
#define f x[(13-r)&7]
#define g x[(14-r)&7]
#define h x[(15-r)&7]
  uint32_t t = h + S1(e) + maj(e,f,g) + K[r] + W(r);
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
static void sha2_256_xform(uint32_t *digest, const uint8_t *data, uint32_t nblk) {
  const uint32_t *input=(uint32_t *)data;

  for (const uint32_t *end = input + nblk * 16; input < end; input += 16) {
    uint32_t W[16], x[8];
    // load input
    for (int i = 0; i < 16; ++i) W[i] = U32BE2H(input[i]);
    // load digest state
    for (int i = 0; i <  8; ++i) x[i] = digest[i];
    // run rounds
    for (int i = 0; i < 64; ++i) sha2_256_round(i, W, x);
    // update digest state
    for (int i = 0; i <  8; ++i) digest[i] += x[i];
  }
}
#else

#define SECTOR_SZ 512

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

#define SHA256_ROUNDS(DIGEST) do { \
  uint32_t A, B, C, D, E, F, G, H, temp; \
  /* load digest state */ \
  A = DIGEST[0]; B = DIGEST[1]; C = DIGEST[2]; D = DIGEST[3]; \
  E = DIGEST[4]; F = DIGEST[5]; G = DIGEST[6]; H = DIGEST[7]; \
  /* run rounds */ \
  R( 0,SHA256_K00); R( 1,SHA256_K01); R( 2,SHA256_K02); R( 3,SHA256_K03); \
  R( 4,SHA256_K04); R( 5,SHA256_K05); R( 6,SHA256_K06); R( 7,SHA256_K07); \
  R( 8,SHA256_K08); R( 9,SHA256_K09); R(10,SHA256_K10); R(11,SHA256_K11); \
  R(12,SHA256_K12); R(13,SHA256_K13); R(14,SHA256_K14); R(15,SHA256_K15); \
  R(16,SHA256_K16); R(17,SHA256_K17); R(18,SHA256_K18); R(19,SHA256_K19); \
  R(20,SHA256_K20); R(21,SHA256_K21); R(22,SHA256_K22); R(23,SHA256_K23); \
  R(24,SHA256_K24); R(25,SHA256_K25); R(26,SHA256_K26); R(27,SHA256_K27); \
  R(28,SHA256_K28); R(29,SHA256_K29); R(30,SHA256_K30); R(31,SHA256_K31); \
  R(32,SHA256_K32); R(33,SHA256_K33); R(34,SHA256_K34); R(35,SHA256_K35); \
  R(36,SHA256_K36); R(37,SHA256_K37); R(38,SHA256_K38); R(39,SHA256_K39); \
  R(40,SHA256_K40); R(41,SHA256_K41); R(42,SHA256_K42); R(43,SHA256_K43); \
  R(44,SHA256_K44); R(45,SHA256_K45); R(46,SHA256_K46); R(47,SHA256_K47); \
  R(48,SHA256_K48); R(49,SHA256_K49); R(50,SHA256_K50); R(51,SHA256_K51); \
  R(52,SHA256_K52); R(53,SHA256_K53); R(54,SHA256_K54); R(55,SHA256_K55); \
  R(56,SHA256_K56); R(57,SHA256_K57); R(58,SHA256_K58); R(59,SHA256_K59); \
  R(60,SHA256_K60); R(61,SHA256_K61); R(62,SHA256_K62); R(63,SHA256_K63); \
  /* update digest state */ \
  DIGEST[0] += A; DIGEST[1] += B; DIGEST[2] += C; DIGEST[3] += D; \
  DIGEST[4] += E; DIGEST[5] += F; DIGEST[6] += G; DIGEST[7] += H; \
} while(0);

static void sha2_256_0x00(uint32_t *digest, size_t nblk) {
  while (nblk--) {
    // entire input block is 0x00
    uint32_t W[16] = { 0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0};
    SHA256_ROUNDS(digest);
  }
}

static void sha2_256_0xFF(uint32_t *digest, size_t nblk) {
  while (nblk--) {
    // entire input block is 0xFF
    uint32_t W[16] = {~0,~0,~0,~0, ~0,~0,~0,~0, ~0,~0,~0,~0, ~0,~0,~0,~0};
    SHA256_ROUNDS(digest);
  }
}

// fast implementation
static void sha2_256_xform(uint32_t *digest, const uint8_t *data, uint32_t nblk) {
  const uint32_t *input=(uint32_t *)data;

  for (const uint32_t *end = input + nblk * 16; input < end; input += 16) {
    uint32_t W[16];
    // load input
    for (int i = 0; i < 16; ++i) W[i] = U32H2BE(input[i]);
    SHA256_ROUNDS(digest);
  }
}

#endif

int SHA256_Init(SHA256_CTX *ctx) {
  ctx->bytelen = 0;
  ctx->datalen = 0;
  ctx->openssl = 0;
  for (int i = 0; i < 8; ++i) ctx->state[i] = IV[i];

  return 1;
}

int SHA256_Update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
  size_t i = 0;
  const uint8_t *input = data;

  if (ctx->datalen > 0) {
    i = 64 - ctx->datalen;

    if (i > len) {
      memcpy(((unsigned char *)(ctx->data)) + (ctx->datalen), input, len);
      ctx->datalen += len;
      return 1;
    } else {
      memcpy(((unsigned char *)(ctx->data)) + (ctx->datalen), input, i);
      sha2_256_xform(ctx->state, ctx->data, 1);
      ctx->bytelen += 64;
      ctx->datalen = 0;
      input += i;
      len -= i;
    }
  }

#ifndef __OPTIMIZE_SIZE__
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
            sha2_256_0x00(ctx->state, skipped / 64);
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
            sha2_256_0xFF(ctx->state, skipped / 64);
            ctx->bytelen += skipped;
            input += skipped;
            len -= skipped;
            continue;
          }
        }
      }

      sha2_256_xform(ctx->state, input, SECTOR_SZ / 64);
      ctx->bytelen += SECTOR_SZ;
      input += SECTOR_SZ;
      len -= SECTOR_SZ;
    }
  }
#endif

  if (len >= 64) {
    i = len / 64;
    sha2_256_xform(ctx->state, input, i);
    len -= i * 64;
    input += i * 64;
    ctx->bytelen += i * 64;
  }

  memcpy(ctx->data, input, len);
  ctx->datalen = len;

  return 1;
}

int SHA256_Final(uint8_t hash[], SHA256_CTX *ctx) {
  uint32_t *out = (uint32_t *)hash;
  uint32_t i = ctx->datalen;

  ctx->data[i++] = 0x80;

  if (ctx->datalen < 56) {
    memset(((unsigned char *)(ctx->data)) + i, 0, 56 - i);
  } else {
    memset(((unsigned char *)(ctx->data)) + i, 0, 64 - i);
    sha2_256_xform(ctx->state, ctx->data, 1);
    memset(ctx->data, 0, 56);
  }

  ctx->bytelen += ctx->datalen;
  STOR64BE(ctx->data + 56, ctx->bytelen * 8);
  sha2_256_xform(ctx->state, ctx->data, 1);
  for (int i = 0; i < 8; ++i) out[i] = U32H2BE(ctx->state[i]);

  return 1;
}

static unsigned char md[32];

unsigned char *SHA256(const uint8_t data[], size_t len, uint8_t hash[]) {
  uint8_t *out = hash != NULL ? hash : md;
  SHA256_CTX ctx[] = {0};
  SHA256_Init(ctx);
  SHA256_Update(ctx, data, len);
  SHA256_Final(hash, ctx);
  return out;
}
