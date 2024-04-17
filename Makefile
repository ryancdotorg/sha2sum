MAKEFLAGS += --no-builtin-rules
export LANG=C LC_ALL=C

.PHONY: all clean _clean _nop

C ?= gcc
AS ?= gcc
PP ?= cpp
LD ?= ld

#override CPPFLAGS += ...
CFLAGS ?= -O2
override CFLAGS += -std=gnu17 -Wall -Wextra -pedantic \
	-D_ALL_SOURCE -D_GNU_SOURCE \
	-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

COMPILE = $(CC) $(CPPFLAGS) $(CFLAGS)

all: bin/sha256sum

bin/test: obj/test.o
	@mkdir -p $(@D)
	$(COMPILE) $^ $(LDFLAGS) -o $@

bin/test_%: src/%.c gen/sha2_const.h
	@mkdir -p $(@D)
	$(COMPILE) -DTEST $< $(LDFLAGS) -o $@

bin/sha256sum: obj/sha256.o obj/sha256sum.o
	@mkdir -p $(@D)
	$(COMPILE) $^ $(LDFLAGS) -o $@

bin/sha512sum: obj/sha256.o obj/sha512.o obj/sha512sum.o
	@mkdir -p $(@D)
	$(COMPILE) $^ $(LDFLAGS) -o $@

bin/sha384sum: bin/sha512sum
	@mkdir -p $(@D)
	ln -s sha512sum $@

bin/sha256sum_ossl: obj/sha256sum.o
	@mkdir -p $(@D)
	$(COMPILE) $^ -lcrypto $(LDFLAGS) -o $@

obj/sha256sum_main.o: src/sha256sum.c
	@mkdir -p $(@D)
	$(COMPILE) -DSHA256SUM_MAIN=sha256sum_main -c $< -o $@

obj/sha256sum_multicall.o: obj/sha256sum_main.o obj/sha256.o
	@mkdir -p $(@D)
	$(COMPILE) --entry sha256sum_main -r $^ -o $@

obj/sha512sum_main.o: src/sha256sum.c
	@mkdir -p $(@D)
	$(COMPILE) -DWITH_SHA512 -DSHA256SUM_MAIN=sha512sum_main -c $< -o $@

obj/sha512sum_multicall.o: obj/sha512sum_main.o obj/sha256.o obj/sha512.o
	@mkdir -p $(@D)
	$(COMPILE) --entry sha512sum_main -r $^ -o $@

obj/sha512sum.o: src/sha256sum.c
	@mkdir -p $(@D)
	$(COMPILE) -DWITH_SHA512 -c $^ $(LDFLAGS) -o $@

gen/sha2_const.h: scripts/sha2_const.py
	@mkdir -p $(@D)
	python3 $< > $@

obj/sha%.o: src/sha%.c src/sha%.h gen/sha2_const.h
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
