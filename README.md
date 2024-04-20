# sha2sum

## Description

`sha2sum` is a re-implementation of `sha256sum`, `sha384sum`, and `sha512sum`
with public domain equivalent licensing. With the exception of not supporting
the `-z`, `--zero`, and `--tag` command line options, `sha2sum` can act as
a drop-in replacement for the GNU core utilities programs of the same names.

Special optimizations are included for faster processing of large blocks of
`0x00` or `0xff` bytes. This can be useful for computing hashes of storage
media.

Size-optimized (but slower) hash implementations are also included, and will
be used if `sha2sum` is built with the `-Os` compiler flag.

Alternatively, `sha2sum` can be linked against `libcrypto` (OpenSSL) which has
significantly faster assembly implementations for many platforms.

## Getting Started

### Dependencies

None.

### Building

Pretty simple.

```
git clone https://github.com/ryancdotorg/sha2sum.git
cd sha2sum
make
```

If you want the small implementations:

```
make clean all CFLAGS=-Os
```

If you want to link OpenSSL (`bin/sha256sum_ossl` and `bin/sha2sum_ossl`):

```
make ossl
```

If you want to link libsodium (`bin/sha256sum_nacl` and `bin/sha2sum_nacl`):

```
make nacl
```

By default, you get `bin/sha256sum` and `bin/sha2sum`.

`sha256sum` is exactly what you’d expect.

`sha2sum` can automatically detect between sha256, sha384, and sha512 when
checking hashes, but needs to have one specified via `-a` or `--algorithm` to
generate hashes. It is a [multi-call binary](https://www.redbooks.ibm.com/abstracts/tips0092.html)
and will act as `sha256sum`, `sha384sum`, or `sha512sum` if called by an
appropriate symlink.

There are also make targets for

* `obj/sha2sum_multicall.o` (provides `sha2sum_main`)
* `obj/sha256sum_multicall.o` (provides `sha256sum_main`)
* `obj/sha2sum_ossl_multicall.o` (provides `sha2sum_main`)
* `obj/sha256sum_ossl_multicall.o` (provides `sha256sum_main`)
* `obj/sha2sum_nacl_multicall.o` (provides `sha2sum_main`)
* `obj/sha256sum_nacl_multicall.o` (provides `sha256sum_main`)

These can be used to link their functionality into other multi-call binaries.

### Usage

```
Usage: sha2sum [OPTION]... [FILE]...
Print (default) or check SHA2 hashes

With no FILE, or when FILE is -, read standard input.
  -a, --algorithm=TYPE SHA2 variant to use (sha256, sha384, or sha512)
  -b, --binary         read in binary mode
  -t, --text           read in text mode (default)
  -c, --check          check hashes from FILE(s)

Options which affect checking:
      --ignore-missing don't fail for missing files
      --quiet          don't print OK for verified files
      --status         silent mode, indicate results only via exit code
      --strict         exit non-zero for malformed input lines
  -w, --warn           print warning for each malformed input line

  -h, --help           show help and exit
      --version        show version and exit
```

## Help

You can file an issue on GitHub, however I may not respond. This software is
being provided without warranty in the hopes that it may be useful.

## Authors

[Ryan Castellucci](https://rya.nc/about.html)
([@ryancdotorg](https://github.com/ryancdotorg))

## License

Your choice of CC0-1.0, 0BSD, or MIT-0. Do what you want.
