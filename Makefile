# smallest_tcp — ARM Cortex-M0 code size measurement.
#
# The library, tests and demos build with CMake (see the README):
#   cmake -S . -B build && cmake --build build && ctest --test-dir build
#
# This Makefile builds the size benchmark (bench/size_measure.c) with
# arm-none-eabi-gcc, -Os -mthumb, and checks that no configuration needs a
# library divide (Cortex-M0 has no divide instruction; docs/design/
# coding-rules.md).  CI runs `make arm-size-all`.
#
#   arm-size        UDP echo (ETH + ARP + IPv4 + ICMP + UDP), -DNET_USE_TCP=0:
#                   the lwIP UDP-only comparison
#   arm-size-tcp    UDP echo + TCP echo server
#   arm-size-mdns   UDP echo + mDNS/DNS-SD responder
#   arm-size-http   UDP echo + HTTP server (one connection slot)
#   arm-size-ipv6   UDP echo, dual stack (IPv6, ICMPv6, ND, SLAAC, MLD)
#   arm-size-ipv6-only  UDP echo over IPv6 alone: no ARP, IPv4 or ICMP
#   arm-size-tls    the TLS 1.3 protocol code: server only, then client and
#                   server (the crypto backend is extra and not measured)
#   arm-size-dtls   the DTLS 1.3 protocol code, the same two ways
#   arm-check-division  fail if any ARM object calls a library divide
#   arm-check-links     fail if the TLS objects need the DTLS record layer,
#                       or the DTLS objects TLS's

BUILD      := build
ARM_CC     := arm-none-eabi-gcc
ARM_SIZE   := arm-none-eabi-size
ARM_NM     := arm-none-eabi-nm
ARM_CFLAGS := -std=c99 -Wall -Wextra -Werror -pedantic \
              -Os -mthumb -mcpu=cortex-m0 -ffreestanding -ffunction-sections \
              -fdata-sections -DNET_DEBUG=0 -Iinclude
ARM_LDFLAGS:= -Wl,--gc-sections -Tbench/cortex-m0.ld --specs=nano.specs \
              --specs=nosys.specs -nostartfiles

# The UDP-only and TCP builds compile multicast reception out: neither
# joins a group, and the lwIP build has IGMP off.
ARM_NOMCAST := -DNET_MAX_MCAST_GROUPS=0

ARM_UDP_SRCS  := src/net.c src/net_cksum.c src/eth.c src/arp.c src/ipv4.c \
                 src/icmp.c src/udp.c src/driver/stub.c bench/size_measure.c
ARM_TCP_SRCS  := $(ARM_UDP_SRCS) src/tcp.c src/tcp_buf_saw.c
ARM_MDNS_SRCS := $(ARM_UDP_SRCS) src/mdns.c src/dns_wire.c src/igmp.c
ARM_HTTP_SRCS := $(ARM_TCP_SRCS) src/http.c src/net_text.c
ARM_IPV6_SRCS := $(ARM_UDP_SRCS) src/ipv6.c src/icmpv6.c src/ndp.c src/mld.c
ARM_IPV6ONLY_SRCS := src/net.c src/net_cksum.c src/eth.c src/udp.c \
                     src/driver/stub.c bench/size_measure.c src/ipv6.c \
                     src/icmpv6.c src/ndp.c src/mld.c
ARM_TLS_SERVER_SRCS := src/tls_common.c src/tls.c src/tls_keys.c src/tls_server.c
ARM_TLS_SRCS  := $(ARM_TLS_SERVER_SRCS) src/tls_client.c
ARM_DTLS_SERVER_SRCS := src/tls_common.c src/dtls.c src/tls_keys.c \
                        src/tls_server.c
ARM_DTLS_SRCS := $(ARM_DTLS_SERVER_SRCS) src/tls_client.c

ARM_UDP_FLAGS  := $(ARM_NOMCAST) -DNET_USE_TCP=0
ARM_TCP_FLAGS  := $(ARM_NOMCAST)
ARM_MDNS_FLAGS := -DNET_USE_TCP=0 -DBENCH_MDNS
ARM_HTTP_FLAGS := $(ARM_NOMCAST) -DBENCH_HTTP
ARM_IPV6_FLAGS := $(ARM_NOMCAST) -DNET_USE_TCP=0 -DNET_USE_IPV6=1 \
                  -DNET_MAX_MCAST6_GROUPS=0 -DBENCH_IPV6
ARM_IPV6ONLY_FLAGS := $(ARM_IPV6_FLAGS) -DNET_USE_IPV4=0
ARM_TLS_FLAGS  := -DTLS_USE_DTLS=0
ARM_DTLS_FLAGS := -DTLS_USE_DTLS=1

ARM_CONFIGS := udp tcp mdns http ipv6 ipv6only

.PHONY: help arm-size arm-size-tcp arm-size-mdns arm-size-http arm-size-ipv6 \
        arm-size-ipv6-only arm-size-tls arm-size-dtls arm-size-all \
        arm-check-division arm-check-links clean

help:
	@sed -n '1,/^$$/p' Makefile | sed 's/^# \{0,1\}//'

# One benchmark configuration: $(1) name, $(2) sources, $(3) flags
define arm_config
ARM_$(1)_OBJS := $$(patsubst %.c,$$(BUILD)/arm/$(1)/%.o,$(2))

$$(BUILD)/arm/$(1)/%.o: %.c
	@mkdir -p $$(dir $$@)
	$$(ARM_CC) $$(ARM_CFLAGS) $(3) -c -o $$@ $$<

$$(BUILD)/arm/$(1)/size_measure.elf: $$(ARM_$(1)_OBJS)
	$$(ARM_CC) $$(ARM_CFLAGS) $(3) $$(ARM_LDFLAGS) -o $$@ $$^
endef

$(eval $(call arm_config,udp,$(ARM_UDP_SRCS),$(ARM_UDP_FLAGS)))
$(eval $(call arm_config,tcp,$(ARM_TCP_SRCS),$(ARM_TCP_FLAGS)))
$(eval $(call arm_config,mdns,$(ARM_MDNS_SRCS),$(ARM_MDNS_FLAGS)))
$(eval $(call arm_config,http,$(ARM_HTTP_SRCS),$(ARM_HTTP_FLAGS)))
$(eval $(call arm_config,ipv6,$(ARM_IPV6_SRCS),$(ARM_IPV6_FLAGS)))
$(eval $(call arm_config,ipv6only,$(ARM_IPV6ONLY_SRCS),$(ARM_IPV6ONLY_FLAGS)))

ARM_TLS_OBJS := $(patsubst %.c,$(BUILD)/arm/tls/%.o,$(ARM_TLS_SRCS))
ARM_TLS_SERVER_OBJS := $(patsubst %.c,$(BUILD)/arm/tls/%.o,$(ARM_TLS_SERVER_SRCS))

$(BUILD)/arm/tls/%.o: %.c
	@mkdir -p $(dir $@)
	$(ARM_CC) $(ARM_CFLAGS) $(ARM_TLS_FLAGS) -c -o $@ $<

ARM_DTLS_OBJS := $(patsubst %.c,$(BUILD)/arm/dtls/%.o,$(ARM_DTLS_SRCS))
ARM_DTLS_SERVER_OBJS := $(patsubst %.c,$(BUILD)/arm/dtls/%.o,$(ARM_DTLS_SERVER_SRCS))

$(BUILD)/arm/dtls/%.o: %.c
	@mkdir -p $(dir $@)
	$(ARM_CC) $(ARM_CFLAGS) $(ARM_DTLS_FLAGS) -c -o $@ $<

# $(1) title, $(2) ELF, $(3) objects
define report
	@echo ""
	@echo "=== smallest_tcp ARM Cortex-M0 size: $(1) ==="
	@$(ARM_SIZE) $(2)
	@echo ""
	@echo "=== Per-module sizes ==="
	@$(ARM_SIZE) $(3)
	@echo ""
	@echo "Flash = .text + .data, RAM = .data + .bss"
endef

arm-size: $(BUILD)/arm/udp/size_measure.elf
	$(call report,UDP echo,$<,$(ARM_udp_OBJS))

arm-size-tcp: $(BUILD)/arm/tcp/size_measure.elf
	$(call report,UDP + TCP echo,$<,$(ARM_tcp_OBJS))

arm-size-mdns: $(BUILD)/arm/mdns/size_measure.elf
	$(call report,UDP echo + mDNS/DNS-SD,$<,$(ARM_mdns_OBJS))

arm-size-http: $(BUILD)/arm/http/size_measure.elf
	$(call report,UDP echo + HTTP server,$<,$(ARM_http_OBJS))

arm-size-ipv6: $(BUILD)/arm/ipv6/size_measure.elf
	$(call report,UDP echo dual stack IPv4 + IPv6,$<,$(ARM_ipv6_OBJS))

arm-size-ipv6-only: $(BUILD)/arm/ipv6only/size_measure.elf
	$(call report,UDP echo IPv6 only,$<,$(ARM_ipv6only_OBJS))

arm-size-tls: $(ARM_TLS_OBJS)
	@echo ""
	@echo "=== smallest_tcp ARM Cortex-M0 size: TLS 1.3 protocol (crypto backend extra) ==="
	@$(ARM_SIZE) $(ARM_TLS_OBJS)
	@echo ""
	@$(ARM_SIZE) -t $(ARM_TLS_SERVER_OBJS) | tail -1 | \
	  awk '{print "server only (tls_common.c, tls.c, tls_keys.c, tls_server.c): " $$1 " bytes .text"}'
	@$(ARM_SIZE) -t $(ARM_TLS_OBJS) | tail -1 | \
	  awk '{print "client and server:                                           " $$1 " bytes .text"}'

arm-size-dtls: $(ARM_DTLS_OBJS)
	@echo ""
	@echo "=== smallest_tcp ARM Cortex-M0 size: DTLS 1.3 protocol (crypto backend extra) ==="
	@$(ARM_SIZE) $(ARM_DTLS_OBJS)
	@echo ""
	@$(ARM_SIZE) -t $(ARM_DTLS_SERVER_OBJS) | tail -1 | \
	  awk '{print "server only (tls_common.c, dtls.c, tls_keys.c, tls_server.c): " $$1 " bytes .text"}'
	@$(ARM_SIZE) -t $(ARM_DTLS_OBJS) | tail -1 | \
	  awk '{print "client and server:                                            " $$1 " bytes .text"}'

# Neither record layer may be linked by the other's objects: the shared
# code reaches them only through tls_conn_t.rl
arm-check-links: $(ARM_TLS_OBJS) $(ARM_DTLS_OBJS) $(BUILD)/arm/dtls/src/tls.o
	@tls_only=$$($(ARM_NM) -g --defined-only $(BUILD)/arm/dtls/src/tls.o | awk '{print $$3}'); \
	dtls_only=$$($(ARM_NM) -g --defined-only $(BUILD)/arm/dtls/src/dtls.o | awk '{print $$3}'); \
	bad=0; \
	for s in $$($(ARM_NM) -u $(ARM_DTLS_OBJS) | awk '{print $$2}'); do \
	  if echo "$$tls_only" | grep -qx "$$s"; then echo "DTLS needs tls.c: $$s"; bad=1; fi; done; \
	for s in $$($(ARM_NM) -u $(ARM_TLS_OBJS) | awk '{print $$2}'); do \
	  if echo "$$dtls_only" | grep -qx "$$s"; then echo "TLS needs dtls.c: $$s"; bad=1; fi; done; \
	if [ $$bad -eq 0 ]; then \
	  echo "TLS links no DTLS record layer, and DTLS no TLS one."; \
	else exit 1; fi

arm-size-all: arm-size arm-size-tcp arm-size-mdns arm-size-http arm-size-ipv6 \
              arm-size-ipv6-only arm-size-tls arm-size-dtls arm-check-division \
              arm-check-links

# Every stack source (dual stack), compiled only for the division check
ARM_EVERY_SRCS := $(filter-out src/tls_crypto_mbedtls.c,$(wildcard src/*.c))
ARM_EVERY_OBJS := $(patsubst %.c,$(BUILD)/arm/every/%.o,$(ARM_EVERY_SRCS))

$(BUILD)/arm/every/%.o: %.c
	@mkdir -p $(dir $@)
	$(ARM_CC) $(ARM_CFLAGS) -DNET_USE_IPV6=1 -c -o $@ $<

ARM_ALL_OBJS := $(foreach c,$(ARM_CONFIGS),$(ARM_$(c)_OBJS)) $(ARM_TLS_OBJS) \
                $(ARM_DTLS_OBJS) $(ARM_EVERY_OBJS)
ARM_DIVIDES  := __aeabi_uidiv|__aeabi_idiv|__aeabi_uidivmod|__aeabi_idivmod|__aeabi_uldivmod|__aeabi_ldivmod|__udivsi3|__divsi3|__umodsi3|__modsi3

arm-check-division: $(ARM_ALL_OBJS)
	@found=$$(for o in $(ARM_ALL_OBJS); do \
	    $(ARM_NM) -u $$o | grep -Eq '$(ARM_DIVIDES)' && echo "  $$o"; done); \
	if [ -n "$$found" ]; then \
	  echo "These objects call a library divide (no division on Cortex-M0):"; \
	  echo "$$found"; exit 1; \
	else \
	  echo "No ARM object calls a library divide."; \
	fi

clean:
	rm -rf $(BUILD)/arm
