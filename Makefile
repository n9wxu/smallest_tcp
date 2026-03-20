# Portable Minimal TCP/IP Stack — Makefile
#
# C99, -Wall -Werror. Builds library, unit tests, and demo.
# Auto-detects Linux (TAP) or macOS (BPF) for the driver.

CC       ?= cc
CFLAGS   := -std=c99 -Wall -Wextra -Werror -pedantic
CFLAGS   += -Iinclude
LDFLAGS  :=

# Build directory
BUILD    := build

# ── Source files ──────────────────────────────────────────────────────

LIB_SRCS := src/net.c src/net_cksum.c src/eth.c

# Platform-specific driver
UNAME_S  := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  LIB_SRCS += src/driver/tap.c
  DRIVER_DEMO := tap
else ifeq ($(UNAME_S),Darwin)
  LIB_SRCS += src/driver/bpf.c
  DRIVER_DEMO := bpf
endif

LIB_OBJS := $(patsubst src/%.c,$(BUILD)/%.o,$(LIB_SRCS))

# ── Unit test executables ─────────────────────────────────────────────

TEST_SRCS := tests/unit/test_endian.c \
             tests/unit/test_checksum.c \
             tests/unit/test_eth.c \
             tests/unit/test_net.c

TEST_BINS := $(patsubst tests/unit/%.c,$(BUILD)/tests/%,$(TEST_SRCS))

# ── Targets ───────────────────────────────────────────────────────────

.PHONY: all lib test clean

all: lib test

# Static library
lib: $(BUILD)/libnet.a

$(BUILD)/libnet.a: $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

# Compile library sources
$(BUILD)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# ── Unit tests ────────────────────────────────────────────────────────

test: $(TEST_BINS)
	@echo "=== Running unit tests ==="
	@fail=0; \
	for t in $(TEST_BINS); do \
		echo "--- $$t ---"; \
		$$t || fail=1; \
	done; \
	if [ $$fail -eq 0 ]; then \
		echo ""; \
		echo "=== ALL TESTS PASSED ==="; \
	else \
		echo ""; \
		echo "=== SOME TESTS FAILED ==="; \
		exit 1; \
	fi

# Test for endian (header-only, no lib needed)
$(BUILD)/tests/test_endian: tests/unit/test_endian.c include/net_endian.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ $<

# Test for checksum
$(BUILD)/tests/test_checksum: tests/unit/test_checksum.c src/net_cksum.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ tests/unit/test_checksum.c src/net_cksum.c

# Test for eth (needs net.c + eth.c + net_cksum.c for linking)
$(BUILD)/tests/test_eth: tests/unit/test_eth.c src/eth.c src/net.c src/net_cksum.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ tests/unit/test_eth.c src/eth.c src/net.c src/net_cksum.c

# Test for net (needs net.c)
$(BUILD)/tests/test_net: tests/unit/test_net.c src/net.c src/net_cksum.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ tests/unit/test_net.c src/net.c src/net_cksum.c

# ── Clean ─────────────────────────────────────────────────────────────

clean:
	rm -rf $(BUILD)
