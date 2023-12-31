// SPDX-License-Identifier: CC0-1.0+ 0BSD OR OR MIT-0
// Copyright (c) 2024, Ryan Castellucci, no rights reserved
// https://rya.nc/
// https://github.com/ryancdotorg

#pragma once

#ifndef NDEBUG
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
// void debugp(const char *format, ...);
#define debugp(...) _debugp(__FILE__, __func__, __LINE__, __VA_ARGS__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
static void _debugp(const char *file, const char *func, unsigned int line, const char *fmt, ...) {
  // ANSI SGR escape code parameters, e.g. `31` for red
  // https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_.28Select_Graphic_Rendition.29_parameters
  char *color = getenv("DEBUGP_COLOR");
  int fd = STDERR_FILENO;

#if __STDC_VERSION__ >= 199900L
  size_t n = strlen(fmt);
  char modified_fmt[n + 1];
#else
  char modified_fmt[65536];
  size_t n = strnlen(fmt, sizeof(modified_fmt) - 1);
#endif
  // copy format *without* null terminator
  memcpy(modified_fmt, fmt, n);

  va_list args;
  va_start(args, fmt);
  // add null terminator, stripping newline if present
  modified_fmt[n-(modified_fmt[n-1] == '\n' ? 1 : 0)] = '\0';
  // set color if supplied via environment
  if (color != NULL) dprintf(fd, "\033[%sm", color);
  // line header
  dprintf(fd, "%s(%s:%u,%d): ", file, func, line, errno);
  // actual content
  vdprintf(fd, modified_fmt, args);
  // reset color if required, and print and ending newline
  dprintf(fd, color != NULL ? "\033[0m\n" : "\n");
  fdatasync(fd);
}
#pragma GCC diagnostic pop
#else
// no-op
#define debugp(...) do {} while (0)
#endif
