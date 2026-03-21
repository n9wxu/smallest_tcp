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

LIB_SRCS := src/net.c src/net_cksum.c src/eth.c src/arp.c src/ipv4.c src/icmp.c src/udp.c \
            src/tcp.c src/tcp_buf_saw.c

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

# Core stack sources needed by most tests
STACK_SRCS := src/net.c src/net_cksum.c src/eth.c src/arp.c src/ipv4.c src/icmp.c src/udp.c \
              src/tcp.c src/tcp_buf_saw.c

TEST_SRCS := tests/unit/test_endian.c \
             tests/unit/test_checksum.c \
             tests/unit/test_eth.c \
             tests/unit/test_net.c \
             tests/unit/test_arp.c \
             tests/unit/test_ipv4.c \
             tests/unit/test_icmp.c \
             tests/unit/test_udp.c \
             tests/unit/test_tcp_buf.c \
             tests/unit/test_tcp.c

TEST_BINS := $(patsubst tests/unit/%.c,$(BUILD)/tests/%,$(TEST_SRCS))

# ── Demo executables ──────────────────────────────────────────────────

DEMO_SRCS := demo/echo_server/main.c

# ── Targets ───────────────────────────────────────────────────────────

.PHONY: all lib test demo clean

all: lib test demo

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

# Test for eth (needs full stack since eth.c dispatches to arp/ipv4)
$(BUILD)/tests/test_eth: tests/unit/test_eth.c $(STACK_SRCS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ tests/unit/test_eth.c $(STACK_SRCS)

# Test for net
$(BUILD)/tests/test_net: tests/unit/test_net.c src/net.c src/net_cksum.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ tests/unit/test_net.c src/net.c src/net_cksum.c

# Test for ARP
$(BUILD)/tests/test_arp: tests/unit/test_arp.c $(STACK_SRCS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ tests/unit/test_arp.c $(STACK_SRCS)

# Test for IPv4
$(BUILD)/tests/test_ipv4: tests/unit/test_ipv4.c $(STACK_SRCS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ tests/unit/test_ipv4.c $(STACK_SRCS)

# Test for ICMP
$(BUILD)/tests/test_icmp: tests/unit/test_icmp.c $(STACK_SRCS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ tests/unit/test_icmp.c $(STACK_SRCS)

# Test for UDP
$(BUILD)/tests/test_udp: tests/unit/test_udp.c $(STACK_SRCS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ tests/unit/test_udp.c $(STACK_SRCS)

# Test for TCP buffer (stop-and-wait)
$(BUILD)/tests/test_tcp_buf: tests/unit/test_tcp_buf.c $(STACK_SRCS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ tests/unit/test_tcp_buf.c $(STACK_SRCS)

# Test for TCP state machine
$(BUILD)/tests/test_tcp: tests/unit/test_tcp.c $(STACK_SRCS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ tests/unit/test_tcp.c $(STACK_SRCS)

# ── Demo ──────────────────────────────────────────────────────────────

demo: $(BUILD)/demo/echo_server

$(BUILD)/demo/echo_server: demo/echo_server/main.c $(STACK_SRCS) $(LIB_SRCS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ demo/echo_server/main.c $(LIB_SRCS)

# ── ARM size measurement ──────────────────────────────────────────────

ARM_CC     := arm-none-eabi-gcc
ARM_SIZE   := arm-none-eabi-size
ARM_OBJDUMP:= arm-none-eabi-objdump
ARM_CFLAGS := -std=c99 -Wall -Wextra -Werror -pedantic \
              -Os -mthumb -mcpu=cortex-m0 -ffreestanding -ffunction-sections -fdata-sections \
              -DNET_DEBUG=0 -DNET_ASSERT_ENABLED=0 \
              -Iinclude
ARM_LDFLAGS:= -Wl,--gc-sections -Tbench/cortex-m0.ld --specs=nano.specs --specs=nosys.specs -nostartfiles

ARM_SRCS   := src/net.c src/net_cksum.c src/eth.c src/arp.c src/ipv4.c src/icmp.c src/udp.c \
              src/driver/stub.c bench/size_measure.c

.PHONY: arm-size arm-size-detail

arm-size: $(BUILD)/arm/size_measure.elf
	@echo ""
	@echo "=== smallest_tcp ARM Cortex-M0 Size (UDP echo, -Os -mthumb) ==="
	@$(ARM_SIZE) $<
	@echo ""
	@echo "=== Per-module .text sizes ==="
	@$(ARM_SIZE) $(patsubst %.c,$(BUILD)/arm/%.o,$(ARM_SRCS))
	@echo ""
	@echo "Flash = .text + .data, RAM = .data + .bss"

$(BUILD)/arm/size_measure.elf: $(patsubst %.c,$(BUILD)/arm/%.o,$(ARM_SRCS))
	@mkdir -p $(dir $@)
	$(ARM_CC) $(ARM_CFLAGS) $(ARM_LDFLAGS) -o $@ $^

$(BUILD)/arm/%.o: %.c
	@mkdir -p $(dir $@)
	$(ARM_CC) $(ARM_CFLAGS) -c -o $@ $<

# ── Clean ─────────────────────────────────────────────────────────────

clean:
	rm -rf $(BUILD)
