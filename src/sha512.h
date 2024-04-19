#pragma once
/* OpenSSL uses:
typedef struct SHA512state_st {
  uint64_t h[8];
  uint64_t Nl, Nh;
  uint64_t data[16];
  unsigned int num, md_len;
} SHA256_CTX;
*/

typedef struct {
    uint64_t state[8];
    uint64_t bytelen;
    uint64_t _pad0;
    uint8_t data[128];
    unsigned int datalen;
    unsigned int openssl;
} SHA512_CTX;

int SHA384_Init(SHA512_CTX *);

int SHA512_Init(SHA512_CTX *);
int SHA512_Update(SHA512_CTX *, const uint8_t[], size_t);
int SHA512_Final(uint8_t[], SHA512_CTX *);
