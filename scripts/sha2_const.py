#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0+ OR 0BSD OR OR MIT-0
# Copyright (c) 2024, Ryan Castellucci, no rights reserved

from sys import argv, exit, stdin, stdout, stderr, version_info
from functools import partial
eprint = partial(print, file=stderr)

# Python standard library imports
import re
import lzma

from pathlib import Path
from hashlib import sha256
# End imports

SCRIPT_DIR = Path(__file__).parent.resolve()

ror32 = lambda x, n: ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
ror64 = lambda x, n: ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF
ch    = lambda x, y, z: ((x & y) | (z & (x | y)))
maj   = lambda x, y, z: (z ^ (x & (y ^ z)))

sig0_32  = lambda x: (ror32(x,  7) ^ ror32(x, 18) ^ (x >>  3))
sig1_32  = lambda x: (ror32(x, 17) ^ ror32(x, 19) ^ (x >> 10))
Sig0_32  = lambda x: (ror32(x,  2) ^ ror32(x, 13) ^ ror32(x, 22))
Sig1_32  = lambda x: (ror32(x,  6) ^ ror32(x, 11) ^ ror32(x, 25))

sig0_64  = lambda x: (ror64(x,  1) ^ ror64(x,  8) ^ (x >>  7))
sig1_64  = lambda x: (ror64(x, 19) ^ ror64(x, 61) ^ (x >>  6))
Sig0_64  = lambda x: (ror64(x, 28) ^ ror64(x, 34) ^ ror64(x, 39))
Sig1_64  = lambda x: (ror64(x, 14) ^ ror64(x, 18) ^ ror64(x, 41))

def islast(iterable):
    tup = lambda flag, val: (flag,) + val if isinstance(val, tuple) else (flag, val)

    iterator = iter(iterable)
    curr = Unset = object()
    try:
        curr = next(iterator)
        while True:
            ahead = next(iterator)
            yield tup(False, curr)
            curr = ahead
    except StopIteration:
        if curr is not Unset:
            yield tup(True, curr)

# find integer nth root of non-negative integer x using a binary search
def inthrt(x, n):
    if not isinstance(x, int) or x < 0:
        raise ValueError('x must be a non-negative integer')

    lo, hi = 0, int(x)
    while True:
        md = int((hi + lo) // 2)
        if lo == md: return md
        v = md ** n
        #print(i, n, hex(lo), hex(md), hex(hi), hex(v), hex(x))
        if   v > x: hi = md
        elif v < x: lo = md

# first b bits of fractional portion of nth root of x
def frnthrt(x, n, b):
    return inthrt(x << (n * b), n) & ((1 << b) - 1)

def w32(r, W):
    if r < 16:
        return W[r]
    else:
        W[r & 15] = (W[r & 15] + Sig1_32(W[(r + 14) & 15])) & 0xFFFFFFFF
        W[r & 15] = (W[r & 15] + W[(r + 9) & 15]) & 0xFFFFFFFF
        W[r & 15] = (W[r & 15] + Sig0_32(W[(r +  1) & 15])) & 0xFFFFFFFF
        return W[r & 15]

def expand32(W):
    if isinstance(W, int): W = [W]
    n, W, W_ = len(W), W[:], []
    for i in range(n, 16): W.append(W[i%n])
    for r in range(64): W_.append(w32(r, W))
    return W_

def w64(r, W):
    if r < 16:
        return W[r]
    else:
        W[r & 15] = (W[r & 15] + Sig1_64(W[(r + 14) & 15])) & 0xFFFFFFFFFFFFFFFF
        W[r & 15] = (W[r & 15] + W[(r + 9) & 15]) & 0xFFFFFFFFFFFFFFFF
        W[r & 15] = (W[r & 15] + Sig0_64(W[(r +  1) & 15])) & 0xFFFFFFFFFFFFFFFF
        return W[r & 15]

def expand64(W):
    if isinstance(W, int): W = [W]
    n, W, W_ = len(W), W[:], []
    for i in range(n, 16): W.append(W[i%n])
    for r in range(80): W_.append(w64(r, W))
    return W_

W32_F = [0xFFFFFFFF] * 16
W64_F = [0xFFFFFFFFFFFFFFFF] * 16

P = [2, 3]
IV, K = [], []

# find primes by unoptimized trial division
for i in range(2, 80):
    p = P[i - 1]
    while True:
        okay, p = True, p + 2
        for j in range(0, i):
            if p % P[j] == 0:
                okay = False
                break

        if okay:
            P.append(p)
            break

for i in range(16):
    # first 64 bits of the fractional part of the square root
    IV.append(frnthrt(P[i], 2, 64))

for i in range(80):
    # first 64 bits of the fractional part of the cube root
    K.append(frnthrt(P[i], 3, 64))

good = 'fe3bcb2caed620064a42c74072e154b26d8591e5b98e916bb5b7a971559a2a8d'
check = sha256()
check.update(b''.join(map(lambda x: x.to_bytes(8, byteorder='big'), IV)))
check.update(b''.join(map(lambda x: x.to_bytes(8, byteorder='big'), K)))
dgst = check.hexdigest()
if good is not None and dgst != good:
    raise ValueError('Incorrect constants generated!')

Path(SCRIPT_DIR.parent, 'data').mkdir(exist_ok=True)
rfc_file = Path(SCRIPT_DIR.parent, 'data', 'rfc6234.txt.xz')
rfc_hash = '8f39f02a57bfd1da15634706724a585766e6223f77ecdaf243cad16cd3a1aa1b'
if not rfc_file.exists():
    from urllib.request import urlopen, Request
    try:
        rfc = urlopen(Request(
            'https://www.rfc-editor.org/rfc/rfc6234.txt',
            headers={'User-Agent':'Mozilla/5.0'}
        )).read()
        chk = sha256(rfc).hexdigest()
        if chk != rfc_hash:
            raise ValueError(f'RFC6234 data invalid: SHA256:{chk}')

        with lzma.open(rfc_file, 'wb') as f:
            f.write(rfc)
    except Exception as e:
        eprint(e)

rfc_values = {}
try:
    with lzma.open(rfc_file, 'rt') as f:
        rfc_section, rfc_key = None, None
        hex2int = lambda x: int(x, 16)
        # extract constant values from rfc
        for line in map(str.strip, f):
            if m := re.match(r'((?:\d+[.])+)\s{2,99}([A-Z].*)', line):
                rfc_section = m.group(1)
            elif rfc_section == '5.1.':
                if m := re.match((r'([0-9a-f]{8})\s+' * 4)[:-3], line):
                    data = rfc_values.setdefault('K32', [])
                    for v in map(hex2int, m.groups()): data.append(v)
            elif rfc_section == '5.2.':
                if m := re.match((r'([0-9a-f]{16})\s+' * 4)[:-3], line):
                    data = rfc_values.setdefault('K64', [])
                    for v in map(hex2int, m.groups()): data.append(v)
            elif rfc_section == '6.1.':
                if rfc_key is None: rfc_key = 'IV224'
                if m := re.match(r'H\(0\)\d\s+=\s+([0-9a-f]{8})', line):
                    data = rfc_values.setdefault(rfc_key, [])
                    data.append(hex2int(m.group(1)))
                    if len(data) == 8: rfc_key = 'IV256'
            elif rfc_section == '6.3.':
                if rfc_key == 'IV256': rfc_key = 'IV384'
                if m := re.match(r'H\(0\)\d\s+=\s+([0-9a-f]{16})', line):
                    data = rfc_values.setdefault(rfc_key, [])
                    data.append(hex2int(m.group(1)))
                    if len(data) == 8: rfc_key = 'IV512'

except Exception as e:
    eprint(e)
    rfc_values = None

class IncorrectConstant(ValueError):
    def __init__(self, name, index, actual, expected):
        fmt = '08X' if expected < (1 << 32) else '016X'
        message = f'{name}[{index}] is {{0:{fmt}}}, should be {{1:{fmt}}}'
        super().__init__(message.format(actual, expected))

if rfc_values is not None:
    def verify(name, key, i, x):
        if x != rfc_values[key][i]:
            raise IncorrectConstant(name, i, x, rfc_values[key][i])

    for i, x in map(lambda i: (i, IV[i+8] & ((1 << 32) - 1)), range(8)):
        verify('SHA224_IV', 'IV224', i, x)

    for i, x in map(lambda i: (i, IV[i] >> 32), range(8)):
        verify('SHA256_IV', 'IV256', i, x)

    for i, x in map(lambda i: (i, IV[i+8]), range(8)):
        verify('SHA384_IV', 'IV384', i, x)

    for i, x in map(lambda i: (i, IV[i]), range(8)):
        verify('SHA512_IV', 'IV512', i, x)

    for i, x in map(lambda i: (i, K[i] >> 32), range(64)):
        verify('SHA256_K', 'K32', i, x)

    for i, x in map(lambda i: (i, K[i]), range(80)):
        verify('SHA512_K', 'K64', i, x)

print('#pragma once\n')
print('/*', dgst, '*/\n')

for i, x in map(lambda i: (i, IV[i+8] & ((1 << 32) - 1)), range(8)):
    print(f'#define SHA224_IV{i} 0x{x:08X}UL')

for i, x in map(lambda i: (i, IV[i] >> 32), range(8)):
    print(f'#define SHA256_IV{i} 0x{x:08X}UL')

for i, x in map(lambda i: (i, IV[i+8]), range(8)):
    print(f'#define SHA384_IV{i} 0x{x:016X}ULL')

for i, x in map(lambda i: (i, IV[i]), range(8)):
    print(f'#define SHA512_IV{i} 0x{x:016X}ULL')

for i, x in map(lambda i: (i, K[i] >> 32), range(64)):
    print(f'#define SHA256_K{i:02} 0x{x:08X}UL')

for i, x in map(lambda i: (i, K[i]), range(80)):
    print(f'#define SHA512_K{i:02} 0x{x:016X}ULL')

for i in range(64):
    print(f'#define SHA224_K{i:02} SHA256_K{i:02}')

for i in range(80):
    print(f'#define SHA384_K{i:02} SHA512_K{i:02}')

w32_0 = expand32(0x00000000)
w32_f = expand32(0xFFFFFFFF)

line = '\nstatic const uint32_t SHA256_WxF[] = { '
for last, i in islast(range(64)):
    k = K[i] >> 32
    x = (k + w32_f[i]) & 0xFFFFFFFF
    end = '};' if last else ','
    line += f'0x{x:08X}UL{end}'
    if last or len(line) > 60:
        print(line)
        line = ''

w64_0 = expand64(0x0000000000000000)
w64_f = expand64(0xFFFFFFFFFFFFFFFF)
line = '\nstatic const uint64_t SHA512_WxF[] = {      '
for last, i in islast(range(80)):
    k = K[i]
    x = (k + w64_f[i]) & 0xFFFFFFFFFFFFFFFF
    end = '};' if last else ','
    line += f'0x{x:016X}ULL{end}'
    if last or len(line) > 60:
        print(line)
        line = ''

