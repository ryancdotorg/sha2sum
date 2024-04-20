MAKEFLAGS += --no-builtin-rules
export LANG=C LC_ALL=C

.PHONY: all clean _clean _nop

C ?= gcc
AS ?= gcc
PP ?= cpp
LD ?= ld

VERSION ?= $(shell git describe --abbrev=0 --tags 2> /dev/null || printf '')
VERSION_EXTRA ?=

GIT_TAGGED := $(shell git tag --points-at HEAD 2> /dev/null | grep . || printf '')
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2> /dev/null | tr -c '\n0-9A-Za-z' - || printf '')
GIT_COMMIT := $(shell git log -1 --format=.%h 2> /dev/null || printf '')
GIT_STATUS := $(shell git status --porcelain -uno 2> /dev/null | grep -q . && printf '%s' '-dirty' || printf '')

ifeq ($(VERSION_EXTRA),)
	ifneq ($(GIT_BRANCH),)
		GIT_INFO := $(GIT_BRANCH)$(GIT_COMMIT)$(GIT_STATUS)
		ifeq ($(GIT_TAGGED),)
			VERSION_EXTRA := +$(GIT_INFO)
		else
			ifneq ($(GIT_STATUS),)
				VERSION_EXTRA := +$(GIT_INFO)
			endif
		endif
	endif
endif

CPPFLAGS ?=
override CPPFLAGS += -D_ALL_SOURCE -D_GNU_SOURCE \
	-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

ifneq ($(VERSION),)
	override CPPFLAGS += -DVERSION=$(VERSION)
endif

ifneq ($(VERSION_EXTRA),)
	override CPPFLAGS += -DVERSION_EXTRA=$(VERSION_EXTRA)
endif

CFLAGS ?= -O2
override CFLAGS += -std=gnu17 -Wall -Wextra -pedantic

COMPILE = $(CC) $(CPPFLAGS) $(CFLAGS)



all: bin/sha2sum bin/sha256sum

links: bin/sha384sum bin/sha512sum

bin/test: obj/test.o
	@mkdir -p $(@D)
	$(COMPILE) $^ $(LDFLAGS) -o $@

bin/test_%: src/%.c gen/sha2_const.h
	@mkdir -p $(@D)
	$(COMPILE) -DTEST $< $(LDFLAGS) -o $@



bin/sha256sum: obj/sha256.o obj/sha256sum.o
	@mkdir -p $(@D)
	$(COMPILE) $^ $(LDFLAGS) -o $@

bin/sha256sum_ossl: obj/sha256sum.o
	@mkdir -p $(@D)
	$(COMPILE) $^ -lcrypto $(LDFLAGS) -o $@

obj/sha256sum.o: src/sha2sum.c src/sha256.h
	@mkdir -p $(@D)
	$(COMPILE) -c $< $(LDFLAGS) -o $@

obj/sha256sum_main.o: src/sha2sum.c
	@mkdir -p $(@D)
	$(COMPILE) -DSHA256SUM_MAIN=sha256sum_main -c $< -o $@

obj/sha256sum_multicall.o: obj/sha256sum_main.o obj/sha256.o
	@mkdir -p $(@D)
	$(COMPILE) --entry sha256sum_main -r $^ -o $@



bin/sha2sum: obj/sha256.o obj/sha512.o obj/sha2sum.o
	@mkdir -p $(@D)
	$(COMPILE) $^ $(LDFLAGS) -o $@

bin/sha2sum_ossl: obj/sha2sum.o
	@mkdir -p $(@D)
	$(COMPILE) $^ -lcrypto $(LDFLAGS) -o $@

obj/sha2sum.o: src/sha2sum.c src/sha256.h src/sha512.h
	@mkdir -p $(@D)
	$(COMPILE) -DWITH_SHA512 -c $< $(LDFLAGS) -o $@

obj/sha2sum_main.o: src/sha2sum.c
	@mkdir -p $(@D)
	$(COMPILE) -DWITH_SHA512 -DSHA256SUM_MAIN=sha2sum_main -c $< -o $@

obj/sha2sum_multicall.o: obj/sha2sum_main.o obj/sha256.o obj/sha512.o
	@mkdir -p $(@D)
	$(COMPILE) --entry sha2sum_main -r $^ -o $@



bin/sha%sum: bin/sha2sum
	@mkdir -p $(@D)
	ln -s sha2sum $@

bin/sha%sum_ossl: bin/sha2sum_ossl
	@mkdir -p $(@D)
	ln -s sha2sum_ossl $@



gen/sha2_const.h: scripts/sha2_const.py
	@mkdir -p $(@D)
	python3 $< > $@

obj/sha%.o: src/sha%.c src/sha%.h src/sha2.h gen/sha2_const.h
	@mkdir -p $(@D)
	$(COMPILE) -c $< -o $@



# generic build rules
obj/%.o: src/%.c src/%.h
	@mkdir -p $(@D)
	$(COMPILE) -c $< -o $@

obj/%.o: src/%.c
	@mkdir -p $(@D)
	$(COMPILE) -c $< -o $@



# hack to force clean to run first *to completion* even for parallel builds
# note that $(info ...) prints everything on one line
clean: _nop $(foreach _,$(filter clean,$(MAKECMDGOALS)),$(info $(shell $(MAKE) _clean)))
_clean:
	rm -rf obj bin gen || /bin/true
_nop:
	@true
