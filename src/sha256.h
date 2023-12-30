/* OpenSSL uses:
typedef struct SHA256state_st {
  uint32_t h[8];
  uint32_t Nl, Nh;
  uint32_t data[64];
  unsigned int num, md_len;
} SHA256_CTX;
*/

typedef struct {
    uint8_t data[64];
    uint64_t bytelen;
    uint32_t state[8];
    unsigned int datalen;
    unsigned int openssl;
} SHA256_CTX;

int SHA256_Init(SHA256_CTX *);
int SHA256_Update(SHA256_CTX *, const uint8_t[], size_t);
int SHA256_Final(uint8_t[], SHA256_CTX *);
unsigned char *SHA256(const uint8_t[], size_t, uint8_t[]);
