// SPDX-License-Identifier: CC0-1.0+ OR 0BSD OR OR MIT-0
// Copyright (c) 2024, Ryan Castellucci, no rights reserved

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>

#include <linux/limits.h>

#include "sha256.h"
#ifdef WITH_SHA512
#include "sha512.h"
#endif

#define CHECK_EFMT  -1
#define CHECK_OKAY   0
#define CHECK_FAIL   1
#define CHECK_ENOENT 2
#define CHECK_EFILE  3

/* must be a power of 2 */
#define BUF_ALIGN 32
/* must be a multiple of BUF_ALIGN */
#define BUF_SZ 262144

#define ALIGN(X, N) { \
  size_t _n = (N) - 1; \
  (X) = (void *)((((uintptr_t)(X)) + _n) & (~_n)); \
}

typedef struct {
  char *arg0;
  unsigned warn:1;
  unsigned check:1;
  unsigned quiet:1;
  unsigned status:1;
  unsigned strict:1;
  unsigned binary:1;
  unsigned ignore_missing:1;
#ifdef WITH_SHA512
  int hash_sz;
#endif
} sha256sum_opts_t;

static void print_try_help(sha256sum_opts_t *opts) {
  fprintf(stderr, "Try '%s --help' for more information.\n", opts->arg0);
}

static void print_version() {
  printf("sha256sum 0.0.5\n");
}

static void print_help(sha256sum_opts_t *opts) {
  printf(
    "Usage: %s [OPTION]... [FILE]...\n"
    "Print (default) or check SHA256 hashes\n\n"
    "With no FILE, or when FILE is -, read standard input.\n\n"
    "  -b, --binary         read in binary mode\n"
    "  -t, --text           read in text mode (default)\n"
    "  -c, --check          check hashes from FILE(s)\n\n"
    "Options which affect checking:\n"
    "      --ignore-missing don't fail for missing files\n"
    "      --quiet          don't print OK for verified files\n"
    "      --status         silent mode, indicate results only via exit code\n"
    "      --strict         exit non-zero for malformed input lines\n"
    "  -w, --warn           print warning for each malformed input line\n\n"
    "  -h, --help           show help and exit\n"
    "      --version        show version and exit\n"
    , opts->arg0
  );
}

static const char hex_tab[] = {
  '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

#ifdef __OPTIMIZE_SIZE__
#define SENSIBLE_HEX ( \
  '1' == '0' + 1 && '2' == '0' + 2 && '3' == '0' + 3 && '4' == '0' + 4 && \
  '5' == '0' + 5 && '6' == '0' + 6 && '7' == '0' + 7 && '8' == '0' + 8 && \
  '9' == '0' + 9 && 'b' == 'a' + 1 && 'c' == 'a' + 2 && 'd' == 'a' + 3 && \
  'e' == 'a' + 4 && 'f' == 'a' + 5 && 'B' == 'A' + 1 && 'C' == 'A' + 2 && \
  'D' == 'A' + 3 && 'E' == 'A' + 4 && 'F' == 'A' + 5 \
)
#else
static const uint16_t unhex_tab[] = {
  256,256,256,256, 256,256,256,256, 256,256,256,256, 256,256,256,256, // 0x0_
  256,256,256,256, 256,256,256,256, 256,256,256,256, 256,256,256,256, // 0x1_
  256,256,256,256, 256,256,256,256, 256,256,256,256, 256,256,256,256, // 0x2_
    0,  1,  2,  3,   4,  5,  6,  7,   8,  9,256,256, 256,256,256,256, // 0x3_
  256, 10, 11, 12,  13, 14, 15,256, 256,256,256,256, 256,256,256,256, // 0x4_
  256,256,256,256, 256,256,256,256, 256,256,256,256, 256,256,256,256, // 0x5_
  256, 10, 11, 12,  13, 14, 15,256, 256,256,256,256, 256,256,256,256, // 0x6_
  256,256,256,256, 256,256,256,256, 256,256,256,256, 256,256,256,256, // 0x7_
  256,256,256,256, 256,256,256,256, 256,256,256,256, 256,256,256,256, // 0x8_
  256,256,256,256, 256,256,256,256, 256,256,256,256, 256,256,256,256, // 0x9_
  256,256,256,256, 256,256,256,256, 256,256,256,256, 256,256,256,256, // 0xa_
  256,256,256,256, 256,256,256,256, 256,256,256,256, 256,256,256,256, // 0xb_
  256,256,256,256, 256,256,256,256, 256,256,256,256, 256,256,256,256, // 0xc_
  256,256,256,256, 256,256,256,256, 256,256,256,256, 256,256,256,256, // 0xd_
  256,256,256,256, 256,256,256,256, 256,256,256,256, 256,256,256,256, // 0xe_
  256,256,256,256, 256,256,256,256, 256,256,256,256, 256,256,256,256  // 0xf_
};
#endif

static int sha256file(const char *name, unsigned char *buf, sha256sum_opts_t *opts, uint8_t hash[]) {
#ifdef WITH_SHA512
  int sz = opts->hash_sz;
#endif
  int ret = 0;
  errno = 0;
  FILE *f;

  do {
    if (name == NULL) {
      f = stdin;
      name = "-";
    } else {
      if ((f = fopen(name, opts->binary ? "rb" : "r")) == NULL) {
        ret = 1;
        break;
      }
    }

#ifdef WITH_SHA512
    SHA512_CTX ctx[] = {0};
    if (sz == 64) {
      SHA512_Init(ctx);
    } else if (sz == 48) {
      SHA384_Init(ctx);
    } else {
      SHA256_Init((SHA256_CTX*)ctx);
    }
#else
    SHA256_CTX ctx[] = {0};
    SHA256_Init(ctx);
#endif


    size_t n;
    do {
      // fread yields fewer bytes than requested only at eof or on error
      if ((n = fread(buf, 1, BUF_SZ, f)) > 0) {
#ifdef WITH_SHA512
        if (sz == 32) {
          SHA256_Update((SHA256_CTX*)ctx, buf, n);
        } else {
          SHA512_Update(ctx, buf, n);
        }
#else
        SHA256_Update(ctx, buf, n);
#endif
      }
    } while (n == BUF_SZ);

    if (!feof(f)) {
      ret = 1;
      break;
    }

#ifdef WITH_SHA512
    if (sz == 32) {
      SHA256_Final(hash, (SHA256_CTX*)ctx);
    } else {
      SHA512_Final(hash, ctx);
    }
#else
    SHA256_Final(hash, ctx);
#endif
  } while (0);

  if (errno && !(opts->ignore_missing && errno == ENOENT)) {
    fprintf(stderr, "%s: %s: %s\n", opts->arg0, name, strerror(errno));
  }

  if (f != NULL) {
    int saved_errno = errno;
    fclose(f);
    errno = saved_errno;
  }

  return ret;
}

static int load_hash(uint8_t *hash, const char *s, size_t n) {
  const uint8_t *ptr = (uint8_t *)s;

#ifdef __OPTIMIZE_SIZE__
  n <<= 1;
  uint8_t c = 0;
  while (n--) {
    if (SENSIBLE_HEX) {
      char xdigit = *ptr++;
      if (xdigit <= '9' && xdigit >= '0') {
        xdigit = xdigit - '0';
      } else if (xdigit >= 'a' && xdigit <= 'f') {
        xdigit = (xdigit - 'a') + 0xA;
      } else if (xdigit >= 'A' && xdigit <= 'F') {
        xdigit = (xdigit - 'A') + 0xA;
      }

      c |= xdigit;
    } else {
      switch (*ptr++) {
        case '0': c |=  0; break;   case '1': c |=  1; break;
        case '2': c |=  2; break;   case '3': c |=  3; break;
        case '4': c |=  4; break;   case '5': c |=  5; break;
        case '6': c |=  6; break;   case '7': c |=  7; break;
        case '8': c |=  8; break;   case '9': c |=  9; break;
        case 'A': /* fallthrough */ case 'a': c |= 10; break;
        case 'B': /* fallthrough */ case 'b': c |= 11; break;
        case 'C': /* fallthrough */ case 'c': c |= 12; break;
        case 'D': /* fallthrough */ case 'd': c |= 13; break;
        case 'E': /* fallthrough */ case 'e': c |= 14; break;
        case 'F': /* fallthrough */ case 'f': c |= 15; break;
        default: return 1;
      }
    }

    if ((n & 1) == 0) {
      *hash++ = c;
      c = 0;
    } else {
      c <<= 4;
    }
  }

  return 0;
#else
  uint16_t r = 0;
  while (n--) {
    r |= unhex_tab[ptr[0]] << 4;
    r |= unhex_tab[ptr[1]];
    *hash++ = (r & 0xff);
    r &= 0xff00;
    ptr += 2;
  }

  return r;
#endif
}

static int sha256chk(char *line, unsigned char *buf, sha256sum_opts_t *opts) {
#ifdef WITH_SHA512
  int sz = opts->hash_sz;
  uint8_t ref[64], hash[64];
#else
  int sz = 32;
  uint8_t ref[32], hash[32];
#endif
  int escaped = (line[0] == '\\' ? 1 : 0);
  char *hash_start = line + escaped;
  char *name_start = hash_start + sz * 2 + 2;

  if (load_hash(ref, hash_start, sz) != 0) return CHECK_EFMT;

  // make sure there's whitespace where expected
  if (!(hash_start[sz * 2] == ' ' || hash_start[sz * 2] == '\t')) return CHECK_EFMT;

  // check the mode character and adjust the name start if needed
  if (!(hash_start[sz * 2 + 1] == ' ' || hash_start[sz * 2 + 1] == '*')) --name_start;

  char *name_src = name_start;
  char *name_dst = line;
  do {
    switch (*name_src) {
      case '\n':
        *name_dst++ = '\0'; /* terminate */
        break;
      case '\\':
        if (escaped) {
          ++name_src;
          switch (*name_src++) {
            case '\\': *name_dst++ = '\\'; break;
            case 'n':  *name_dst++ = '\n'; break;
            case 'r':  *name_dst++ = '\r'; break;
            default:   return CHECK_EFMT; /* invalid escape sequence */
          }
          break;
        }
        /* fallthrough */
      default:
        *name_dst++ = *name_src++;
        break;
    }
  } while (name_dst[-1] != '\0');

  if (hash_start[sz * 2 + 1] == '*') {
    sha256sum_opts_t optb[] = {0};
    memcpy(optb, opts, sizeof(*optb));
    optb->binary = 1;
    opts = optb;
  }

  if (sha256file(line, buf, opts, hash) != 0) {
    return errno == ENOENT ? CHECK_ENOENT : CHECK_EFILE;
  }

  uint8_t mismatch = 0;
  for (int i = 0; i < sz; ++i) {
    mismatch |= ref[i] ^ hash[i];
  }

  return mismatch ? CHECK_FAIL : CHECK_OKAY;
}

static int escape_filename(char *esc, const char *src, size_t n) {
  int ret = 0;
  char *ptr = esc;

  do {
    if (n <= 0) abort();
    if (*src == '\n' || *src == '\r' || *src == '\\') {
      // character needs to be escaped
      ret |= 1; *ptr++ = '\\'; --n;
      if (n <= 0) abort();
      switch (*src++) {
        case '\n': *ptr++ = 'n';  --n; break;
        case '\r': *ptr++ = 'r';  --n; break;
        case '\\': *ptr++ = '\\'; --n; break;
      }
    } else {
      *ptr++ = *src++;
      --n;
    }
    //debugp("]]%d|%02x|%02x[[", (ptr - esc) - 1, ptr[-1], src[-1]);
  } while (src[-1] != '\0');

  return ret;
}

static int sha256sum(const char *name, unsigned char *buf, sha256sum_opts_t *opts) {
#ifdef WITH_SHA512
  int sz = opts->hash_sz;
  uint8_t hash[64];
#else
  int sz = 32;
  uint8_t hash[32];
#endif
  // escape flag, sha256 hash in hex, two spaces,
  // escaped filename, newline, null terminator
  char line[1 + sz * 2 + 2 + PATH_MAX * 2 + 2];
  char *line_start = line + 1;
  char *hash_ptr = line_start;
  char *name_ptr = hash_ptr + sz * 2 + 2;
  size_t name_free = PATH_MAX * 2 + 2;

  if (sha256file(name, buf, opts, hash) != 0) return 1;

  for (int i = 0; i < sz; ++i) {
    *hash_ptr++ = hex_tab[hash[i] >> 4];
    *hash_ptr++ = hex_tab[hash[i] & 15];
  }
  *hash_ptr++ = ' ';
  *hash_ptr++ = ' ';

  if (name == NULL) {
    *name_ptr++ = '-';
    *name_ptr++ = '\0';
  } else {
    if (escape_filename(name_ptr, name, name_free) == 1) {
      *(--line_start) = '\\';
    }
  }

  printf("%s\n", line_start);

  return 0;
}

static int handler(const char *name, unsigned char *buf, sha256sum_opts_t *opts) {
  int ret = 0;
  if (opts->check) {
    FILE *f;
    size_t failed_fmt = 0, failed_read = 0, failed_csum = 0;

    if (name == NULL) {
      f = stdin;
      name = "'standard input'";
    } else {
      if ((f = fopen(name, "r")) == NULL) {
        fprintf(stderr, "%s: %s: %s\n", opts->arg0, name, strerror(errno));
        return 1;
      }
    }

    char *lineptr = NULL;
    size_t lineno = 0, n = 0;
    ssize_t r;
    while ((r = getline(&lineptr, &n, f)) >= 0) {
      ++lineno;

      int res = sha256chk(lineptr, buf, opts);
      char _vname[PATH_MAX * 2 + 3];
      char *vname = _vname + 1;
      if (escape_filename(vname, lineptr, sizeof(_vname)-1) == 1) {
        *(--vname) = '\\';
      }
      switch (res) {
        case CHECK_OKAY:
          if (!(opts->quiet || opts->status)) {
            printf("%s: OK\n", vname);
          }
          break;
        case CHECK_FAIL:
          if (!opts->status) {
            printf("%s: FAILED\n", vname);
          }
          ++failed_csum;
          break;
        case CHECK_EFMT:
          if (opts->warn) {
            fprintf(
              stderr, "%s: %s: %zu: improperly formatted SHA256"
              " checksum line\n", opts->arg0, name, lineno
            );
          }
          ++failed_fmt;
          break;
        case CHECK_ENOENT:
          if (opts->ignore_missing) break;
          /* fallthrough */
        case CHECK_EFILE:
          if (!opts->status) {
            printf("%s: FAILED open or read\n", vname);
          }
          ++failed_read;
          break;
      }
    }

    if (!feof(f)) {
      fprintf(stderr, "%s: %s: %s\n", opts->arg0, name, strerror(errno));
      ret = 1;
    }

    fclose(f);
    errno = 0;

    if (!opts->status) {
      if (failed_fmt) {
        fprintf(
          stderr, "%s: WARNING: %zu line%s improperly formatted\n",
          opts->arg0, failed_fmt, failed_fmt == 1 ? " is" : "s are"
        );
      }

      if (failed_read) {
        fprintf(
          stderr, "%s: WARNING: %zu listed file%s could not be read\n",
          opts->arg0, failed_read, failed_read == 1 ? "" : "s"
        );
      }

      if (failed_csum) {
        fprintf(
          stderr, "%s: WARNING: %zu computed checksum%s did NOT match\n",
          opts->arg0, failed_csum, failed_csum == 1 ? "" : "s"
        );
      }
    }

    if (failed_read || failed_csum || (failed_fmt && opts->strict)) ret |= 1;
  } else {
    ret = sha256sum(name, buf, opts);
  }

  return ret;
}

#ifndef SHA256SUM_MAIN
#define SHA256SUM_MAIN main
#endif

int SHA256SUM_MAIN(int argc, char *argv[]) {
  int ret = 0;

#if BUF_SZ <= (1 << 18)
  // we can just use the stack since the buffer is smallish
  unsigned char _buf[BUF_SZ + BUF_ALIGN - 1];
  unsigned char *buf = _buf;
#else
  unsigned char *buf;
  // initialize things...
  if ((buf = malloc(BUF_SZ + BUF_ALIGN - 1)) == NULL) {
    fprintf(stderr, "Could not allocate buffer: %s\n", strerror(errno));
    return 1;
  }
#endif

  ALIGN(buf, BUF_ALIGN);

  sha256sum_opts_t opts[] = {0};
  memset(opts, 0, sizeof(sha256sum_opts_t));
  opts->arg0 = argv[0];

#ifdef WITH_SHA512
  char *prog = basename(opts->arg0);

  if (strcmp(prog, "sha512sum") == 0) {
    opts->hash_sz = 64;
  } else if (strcmp(prog, "sha384sum") == 0) {
    opts->hash_sz = 48;
  } else {
    opts->hash_sz = 32;
  }
#endif


  // pass over the argument list twice to avoid allocating memory
  // assumes the arguments don't change between passes
  for (int pass = 1; pass <= 2; ++pass) {
    int optend = 0, nfiles = 0;
    for (int n = 1; n < argc; ++n) {
      int optchk = 0, optgen = 0;
      char *arg = argv[n];
      if (optend) {
        ++nfiles;
      } else if (arg[0] == '-' && arg[1] == '\0') {
        arg = NULL;
        ++nfiles;
      } else if (arg[0] == '-') {
        if (arg[1] == '-') {
          if (arg[2] == '\0') {
            optend = 1;
            break;
          } else if (strcmp("check", arg + 2) == 0) {
            opts->check = 1;
          } else if (strcmp("warn", arg + 2) == 0) {
            opts->warn = 1;
            optchk = 1;
          } else if (strcmp("status", arg + 2) == 0) {
            opts->status = 1;
            optchk = 1;
          } else if (strcmp("strict", arg + 2) == 0) {
            opts->strict = 1;
            optchk = 1;
          } else if (strcmp("text", arg + 2) == 0) {
            opts->binary = 0;
            optgen = 1;
          } else if (strcmp("binary", arg + 2) == 0) {
            opts->binary = 1;
            optgen = 1;
          } else if (strcmp("quiet", arg + 2) == 0) {
            opts->quiet = 1;
            optchk = 1;
          } else if (strcmp("ignore-missing", arg + 2) == 0) {
            opts->ignore_missing = 1;
            optchk = 1;
          } else if (strcmp("version", arg + 2) == 0) {
            print_version();
            return 0;
          } else if (strcmp("help", arg + 2) == 0) {
            print_help(opts);
            return 0;
          } else {
            fprintf(stderr, "%s: unrecognized option '%s'\n", argv[0], arg);
            print_try_help(opts);
            return 1;
          }
        } else {
          char flag; size_t i = 1;
          while ((flag = arg[i++]) != '\0') {
            if        (flag == 'c') {
              opts->check = 1;
            } else if (flag == 'w') {
              opts->warn = 1;
              optchk = 1;
            } else if (flag == 's') {
              opts->status = 1;
              optchk = 1;
            } else if (flag == 't') {
              opts->binary = 0;
              optgen = 1;
            } else if (flag == 'b') {
              opts->binary = 1;
              optgen = 1;
            } else if (flag == 'h') {
              print_help(opts);
              return 0;
            } else {
              fprintf(stderr, "%s: invalid option '%c'\n", argv[0], flag);
              print_try_help(opts);
              return 1;
            }
          }
        }

        if (pass == 2 && (opts->check ? optgen : optchk)) {
          fprintf(
            stderr, "%s: %s %s with -c/--check\n", opts->arg0, arg,
            opts->check ? "doesn't work" : "only works"
          );
          return 1;
        }

        continue;
      }

      if (pass == 1) continue;

      /* argument must be a filename */
      ++nfiles;

      ret |= handler(arg, buf, opts);
    }

    if (pass == 1) continue;

    if (nfiles == 0) {
      ret |= handler(NULL, buf, opts);
    }
  }

  return ret;
}
