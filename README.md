# sha2sum

## Description

sha2sum is a re-implementation of the GNU core utilities sha256sum, sha384sum,
and sha512sum with public domain equivalent licensing. Most of the same
functionality is supported with identical command line options.

## Getting Started

### Dependencies

None.

### Installation

```
git clone https://github.com/ryancdotorg/sha2sum.git
cd sha2sum
make
```

You can then copy `bin/sha2sum` where you want it.

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
