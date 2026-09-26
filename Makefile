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
             tests/unit/test_tcp.c \
             tests/unit/test_tftp.c \
             tests/unit/test_dhcpv4.c \
             tests/unit/test_dns_wire.c \
             tests/unit/test_mcast.c \
             tests/unit/test_mdns.c

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

# Test for TFTP client
$(BUILD)/tests/test_tftp: tests/unit/test_tftp.c src/tftp.c $(STACK_SRCS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ tests/unit/test_tftp.c src/tftp.c $(STACK_SRCS)

# Test for DHCPv4 client + server
$(BUILD)/tests/test_dhcpv4: tests/unit/test_dhcpv4.c src/dhcpv4_client.c src/dhcpv4_server.c $(STACK_SRCS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ tests/unit/test_dhcpv4.c \
		src/dhcpv4_client.c src/dhcpv4_server.c $(STACK_SRCS)

# Test for DNS wire format helpers
$(BUILD)/tests/test_dns_wire: tests/unit/test_dns_wire.c src/dns_wire.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ tests/unit/test_dns_wire.c src/dns_wire.c

# Test for IPv4 multicast + IGMP
$(BUILD)/tests/test_mcast: tests/unit/test_mcast.c src/igmp.c $(STACK_SRCS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ tests/unit/test_mcast.c src/igmp.c $(STACK_SRCS)

# Test for the mDNS responder
MDNS_SRCS := src/mdns.c src/dns_wire.c src/igmp.c
$(BUILD)/tests/test_mdns: tests/unit/test_mdns.c $(MDNS_SRCS) $(STACK_SRCS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Itests/unit -o $@ tests/unit/test_mdns.c $(MDNS_SRCS) $(STACK_SRCS)

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
              -DNET_DEBUG=0 -DNET_ASSERT_ENABLED=0 -DNET_MAX_MCAST_GROUPS=0 \
              -Iinclude
ARM_LDFLAGS:= -Wl,--gc-sections -Tbench/cortex-m0.ld --specs=nano.specs --specs=nosys.specs -nostartfiles

# Two configurations, built into separate object dirs (multicast RX compiled
# out — neither app joins a group, and the lwIP build has IGMP off):
#   arm-size      UDP echo, -DNET_USE_TCP=0 (the lwIP UDP-only comparison)
#   arm-size-tcp  UDP echo + TCP echo server (adds tcp.c + tcp_buf_saw.c)

ARM_UDP_SRCS := src/net.c src/net_cksum.c src/eth.c src/arp.c src/ipv4.c src/icmp.c src/udp.c \
                src/driver/stub.c bench/size_measure.c
ARM_TCP_SRCS := $(ARM_UDP_SRCS) src/tcp.c src/tcp_buf_saw.c

ARM_UDP_OBJS := $(patsubst %.c,$(BUILD)/arm/udp/%.o,$(ARM_UDP_SRCS))
ARM_TCP_OBJS := $(patsubst %.c,$(BUILD)/arm/tcp/%.o,$(ARM_TCP_SRCS))

.PHONY: arm-size arm-size-tcp

arm-size: $(BUILD)/arm/udp/size_measure.elf
	@echo ""
	@echo "=== smallest_tcp ARM Cortex-M0 Size (UDP echo, -Os -mthumb) ==="
	@$(ARM_SIZE) $<
	@echo ""
	@echo "=== Per-module sizes ==="
	@$(ARM_SIZE) $(ARM_UDP_OBJS)
	@echo ""
	@echo "Flash = .text + .data, RAM = .data + .bss"

arm-size-tcp: $(BUILD)/arm/tcp/size_measure.elf
	@echo ""
	@echo "=== smallest_tcp ARM Cortex-M0 Size (UDP + TCP echo, -Os -mthumb) ==="
	@$(ARM_SIZE) $<
	@echo ""
	@echo "=== Per-module sizes ==="
	@$(ARM_SIZE) $(ARM_TCP_OBJS)
	@echo ""
	@echo "Flash = .text + .data, RAM = .data + .bss"

$(BUILD)/arm/udp/size_measure.elf: $(ARM_UDP_OBJS)
	@mkdir -p $(dir $@)
	$(ARM_CC) $(ARM_CFLAGS) -DNET_USE_TCP=0 $(ARM_LDFLAGS) -o $@ $^

$(BUILD)/arm/udp/%.o: %.c
	@mkdir -p $(dir $@)
	$(ARM_CC) $(ARM_CFLAGS) -DNET_USE_TCP=0 -c -o $@ $<

$(BUILD)/arm/tcp/size_measure.elf: $(ARM_TCP_OBJS)
	@mkdir -p $(dir $@)
	$(ARM_CC) $(ARM_CFLAGS) $(ARM_LDFLAGS) -o $@ $^

$(BUILD)/arm/tcp/%.o: %.c
	@mkdir -p $(dir $@)
	$(ARM_CC) $(ARM_CFLAGS) -c -o $@ $<

# ── Clean ─────────────────────────────────────────────────────────────

clean:
	rm -rf $(BUILD)
