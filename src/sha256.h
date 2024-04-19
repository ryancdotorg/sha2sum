#pragma once
/* OpenSSL uses:
typedef struct SHA256state_st {
  uint32_t h[8];
  uint32_t Nl, Nh;
  uint32_t data[16];
  unsigned int num, md_len;
} SHA256_CTX;
*/

typedef struct {
    uint32_t state[8];
    uint64_t bytelen;
    uint8_t data[64];
    unsigned int datalen;
    unsigned int openssl;
} SHA256_CTX;

int SHA256_Init(SHA256_CTX *);
int SHA256_Update(SHA256_CTX *, const uint8_t[], size_t);
int SHA256_Final(uint8_t[], SHA256_CTX *);
