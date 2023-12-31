# sha256sum

## Description

An implementation of the sha256sum command line utility, supporting most of
the functionality of the GNU core utilities version.

## Getting Started

### Dependencies

None.

### Installation

```
git clone https://github.com/ryancdotorg/sha256sum.git
cd sha256sum
make
```

You can then copy `bin/sha256sum` where you want it.

### Usage

```
Usage: sha256sum [OPTION]... [FILE]...
Print (default) or check SHA256 hashes

With no FILE, or when FILE is -, read standard input.

  -b, --binary         read in binary mode
  -t, --text           read in text mode (default)
  -c, --check          check hashes from FILE(s)

Options which affect checking:
      --ignore-missing don't fail for missing files
      --quiet          don't print OK for verified files
      --status         silent mode, indicate results only via exit code
      --strict         exit non-zero for malformed input lines
  -w, --warn           print warning for each malformed input line

      --help           show help and exit
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
