#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

typedef struct {
  uint8_t S[256];
  uint8_t i;
  uint8_t j;
} rc4_ctx;

static void rc4_init(rc4_ctx *ctx, const char *seed) {
  size_t seedlen = strlen(seed);
  uint8_t i = 0, j = 0, t;

  do { ctx->S[i] = i; } while (++i);

  do {
    j = (j + ctx->S[i] + seed[i % seedlen]) & 0xff;
    t = ctx->S[i];
    ctx->S[i] = ctx->S[j];
    ctx->S[j] = t;
  } while (++i);

  ctx->i = ctx->j = 0;
}

static void rc4_drbg(rc4_ctx *ctx, void *buf, size_t len) {
  uint8_t t;
  uint8_t *out = (uint8_t *)buf;
  uint8_t *end = out + len;

  while (out < end) {
    ctx->j = (ctx->j + ctx->S[++ctx->i]) & 0xff;
    t = ctx->S[ctx->i];
    ctx->S[ctx->i] = ctx->S[ctx->j];
    ctx->S[ctx->j] = t;
    *out++ = ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) & 0xff];
  }
}

#define RC4_T(T) \
static T ## _t rc4_ ## T(rc4_ctx *ctx) { \
  T ## _t r; rc4_drbg(ctx, &r, sizeof(r)); return r; \
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
RC4_T(uint8)
RC4_T(uint16)
RC4_T(uint32)
RC4_T(uint64)
RC4_T(int8)
RC4_T(int16)
RC4_T(int32)
RC4_T(int64)
#pragma GCC diagnostic pop

int main(int argc, char *argv[]) {
  rc4_ctx ctx[] = {0};
  rc4_init(ctx, argc > 1 ? argv[1] : "hunter2");
  uint8_t buf[262144];

  uint16_t n;
  for (int i = 0; i < 8192; ++i) {
    n = rc4_uint16(ctx);
    memset(buf, 0, n);
    fwrite(buf, 1, n, stdout);
    n = rc4_uint8(ctx);
    rc4_drbg(ctx, buf, n);
    fwrite(buf, 1, n, stdout);
  }
  fflush(stdout);

  return 0;
}
