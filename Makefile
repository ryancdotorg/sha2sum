MAKEFLAGS += --no-builtin-rules
export LANG=C LC_ALL=C

.PHONY: all clean _clean _nop

C ?= gcc
AS ?= gcc
PP ?= cpp
LD ?= ld

#override CPPFLAGS += ...
CFLAGS ?= -O2
override CFLAGS += -std=gnu17 -Wall -Wextra -pedantic

COMPILE = $(CC) $(CPPFLAGS) $(CFLAGS)

all: bin/sha256sum

bin/test: obj/test.o
	@mkdir -p $(@D)
	$(COMPILE) $^ $(LDFLAGS) -o $@

bin/sha256sum: obj/sha256.o obj/sha256sum.o
	@mkdir -p $(@D)
	$(COMPILE) $^ $(LDFLAGS) -o $@

bin/sha256sum_ossl: obj/sha256sum.o
	@mkdir -p $(@D)
	$(COMPILE) $^ -lcrypto $(LDFLAGS) -o $@

obj/sha256.o: src/sha256.c src/sha256.h gen/sha2_const.h
	@mkdir -p $(@D)
	$(COMPILE) -c $< -o $@

gen/sha2_const.h: scripts/sha2_const.py
	@mkdir -p $(@D)
	python3 $< > $@

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
