// SPDX-License-Identifier: CC0-1.0+ OR 0BSD OR OR MIT-0
// Copyright (c) 2024, Ryan Castellucci, no rights reserved

#define NOINLINE __attribute__ ((noinline))

#define ROR32(x,n) __extension__({ uint32_t _x=(x), _n=(n); (_x >> _n) | (_x << (32-_n)); })

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

#define STOR32BE(D, V) (*((uint32_t*)(D)) = U32H2BE((V)))

#define ROR64(x,n) __extension__({ uint64_t _x=(x), _n=(n); (_x >> _n) | (_x << (64-_n)); })

#define U64BE2H(V) __extension__({ \
  uint64_t _v = (V); \
  uint8_t *_t = (uint8_t*)&_v; \
  uint64_t _r = 0; \
  _r |= ((uint64_t)_t[0]) << 56; \
  _r |= ((uint64_t)_t[1]) << 48; \
  _r |= ((uint64_t)_t[2]) << 40; \
  _r |= ((uint64_t)_t[3]) << 32; \
  _r |= ((uint64_t)_t[4]) << 24; \
  _r |= ((uint64_t)_t[5]) << 16; \
  _r |= ((uint64_t)_t[6]) <<  8; \
  _r |= ((uint64_t)_t[7]) <<  0; \
  _r; \
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

#define STOR64BE(D, V) (*((uint64_t*)(D)) = U64H2BE((V)))

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

#define SECTOR_SZ 512
