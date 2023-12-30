#define _GNU_SOURCE
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

/* must be a power of 2 */
#define BUF_ALIGN 32
/* must be a multiple of BUF_ALIGN */
#define BUF_SZ 65536

#define ALIGN(X, N) { \
  size_t _n = (N) - 1; \
  (X) = (void *)((((uintptr_t)(X)) + _n) & (~_n)); \
}

typedef struct {
  unsigned warn:1;
  unsigned check:1;
  unsigned quiet:1;
  unsigned status:1;
  unsigned ignore_missing:1;
} sha256sum_opts_t;

static void print_try_help(char *arg0) {
  fprintf(stderr, "Try '%s --help' for more information.\n", arg0);
}

static void print_not_verify(char *arg0, char *opt) {
  fprintf(stderr, "%s: %s is meaningful only with -c/--check\n", arg0, opt);
}

static void print_version() {
  printf("sha256sum (...) 0.0.1\n");
}

static void print_help(char *arg0) {
  printf("TODO %s\n", arg0);
}

const char hex_char[] = "0123456789abcdef";

static int sha256sum(FILE *f, const char *name, unsigned char *buf, char *arg0) {
  //printf("sha256sum(%p, \"%s\", %p)\n", (void *)f, name, buf);
  uint8_t hash[32];
  // escape flag, sha256 hash in hex, two spaces,
  // escaped filename, newline, null terminator
  char line[1 + 64 + 2 + PATH_MAX * 2 + 1];
  char *hash_start = line + 1;
  char *line_ptr = hash_start;
  char *name_ptr = line + 1 + 64 + 2;
  size_t n, name_free = PATH_MAX * 2 + 1;
  SHA256_CTX ctx[] = {0};

  SHA256_Init(ctx);

  do {
    // fread yields fewer bytes than requested only at end-of-file or on error
    if ((n = fread(buf, 1, BUF_SZ, f)) > 0) {
      SHA256_Update(ctx, buf, n);
    }
  } while (n == BUF_SZ);

  if (!feof(f)) {
    fprintf(stderr, "%s: %s: %s\n", arg0, name, strerror(errno));
    return 1;
  }

  SHA256_Final(hash, ctx);
  for (size_t i = 0; i < sizeof(hash); ++i) {
    *line_ptr++ = hex_char[hash[i] >> 4];
    *line_ptr++ = hex_char[hash[i] & 15];
  }
  *line_ptr++ = ' ';
  *line_ptr++ = ' ';

  for (size_t i = 0; name[i] != '\0'; ++i) {
    if (name_free <= 0) abort();
    if (name[i] == '\n' || name[i] == '\r' || name[i] == '\\') {
      // character needs to be escaped
      line[0] = '\\';
      hash_start = line;
      *name_ptr++ = '\\'; --name_free;
      if (name_free <= 0) abort();
      switch (name[i]) {
        case '\n': *name_ptr++ = 'n';  --name_free; break;
        case '\r': *name_ptr++ = 'r';  --name_free; break;
        case '\\': *name_ptr++ = '\\'; --name_free; break;
      }
    } else {
      *name_ptr++ = name[i];
      --name_free;
    }
  }
  *name_ptr = '\0';

  printf("%s\n", hash_start);

  return 0;
}

int main(int argc, char *argv[]) {
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

  // pass over the argument list twice to avoid allocating memory
  // assumes the arguments don't change between passes
  for (int pass = 1; pass <= 2; ++pass) {
    int optend = 0, nfiles = 0;
    for (int n = 1; n < argc; ++n) {
      int optchk = 0;
      char *arg = argv[n];
      if (optend || (arg[0] == '-' && arg[1] == '\0')) {
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
            print_help(argv[0]);
            return 0;
          } else {
            fprintf(stderr, "%s: unrecognized option '%s'\n", argv[0], arg);
            print_try_help(argv[0]);
            return 1;
          }
        } else {
          char flag; size_t i = 1;
          while ((flag = arg[i++]) != '\0') {
            if (flag == 'c') {
              opts->check = 1;
            } else if (flag == 'w') {
              opts->warn = 1;
              optchk = 1;
            } else if (flag == 's') {
              opts->status = 1;
              optchk = 1;
            } else {
              fprintf(stderr, "%s: invalid option '%c'\n", argv[0], flag);
              print_try_help(argv[0]);
              return 1;
            }
          }
        }

        if (pass == 2 && optchk && !opts->check) {
          print_not_verify(argv[0], arg);
          return 1;
        }

        continue;
      }

      if (pass == 1) continue;

      /* argument must be a filename */
      ++nfiles;

      FILE *f;
      if (arg[0] == '-' && arg[1] == 0) {
        f = stdin;
      } else {
        if ((f = fopen(arg, "r")) == NULL) {
          fprintf(stderr, "%s: %s: %s\n", argv[0], arg, strerror(errno));
          ret |= 1;
        }
      }

      ret |= sha256sum(f, arg, buf, argv[0]);
      if (f != stdin) fclose(f);
    }

    if (pass == 1) continue;

    if (nfiles == 0) {
      ret |= sha256sum(stdin, "-", buf, argv[0]);
    }
  }

  return ret;
}
