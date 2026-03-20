# Configuration Model — Design

**Last updated:** 2026-03-19

## Overview

Stack configuration falls into three categories based on **when the value is known** and **whether it can change**:

| Category | When Known | Can Change? | Mechanism | Example |
|---|---|---|---|---|
| **Compile-time fixed** | Build time | Never | `#define` in `net_config.h` | Checksum offload, byte order |
| **Compile-time default, runtime tunable** | Build time (default), runtime (override) | At init or via protocol | Struct field + `#define` default | IP address, gateway, MAC |
| **Runtime only** | Runtime | Yes, continuously | Struct field, no default | TCP sequence numbers, DHCP lease |

The design tenet **"prefer compile-time → link-time → run-time"** applies to **error detection**, not to all configuration. Many protocol parameters are inherently runtime values — the tenet means we validate *what we can* at compile time, not that everything must be compiled in.

## Category 1: Compile-Time Fixed

These describe **hardware facts** or **build-time decisions** that never change at runtime. Defined as `#define` macros in `net_config.h`. The compiler eliminates dead code paths.

```c
// net_config.h — one per target/application
// ──────────────────────────────────────────

// Hardware capabilities (determined by MAC chip, never changes)
#define NET_MAC_CAP_TX_CKSUM_IPV4   0
#define NET_MAC_CAP_TX_CKSUM_TCP    0
#define NET_MAC_CAP_TX_CKSUM_UDP    0
#define NET_MAC_CAP_RX_CKSUM_OK     0

// Protocol inclusion (link-time composability, but guards headers too)
#define NET_USE_IPV4                1
#define NET_USE_IPV6                0
#define NET_USE_TCP                 1
#define NET_USE_UDP                 1
#define NET_USE_DHCPV4              1
#define NET_USE_DHCPV6              0
#define NET_USE_DNS                 1
#define NET_USE_TFTP                0
#define NET_USE_HTTP                1

// Architecture
#define NET_8BIT_TARGET             0   // 1 = PIC16/AVR: big-endian native, no byte swap

// Debug
#define NET_DEBUG                   0   // 1 = enable trace output
#define NET_ASSERT_ENABLED          0   // 1 = enable runtime assertions
```

**Why compile-time?** These describe the hardware or build variant. An ENC28J60 doesn't gain checksum offload at runtime. An application that doesn't link TFTP shouldn't pay for TFTP headers being parsed.

## Category 2: Compile-Time Default, Runtime Tunable

These have **sensible defaults** at compile time but **can be overridden** at runtime (at initialization, by user input, or by a protocol like DHCP). The pattern:

1. `#define NET_DEFAULT_*` provides the compile-time default in `net_config.h`.
2. The factory method (`net_init()`) sets the struct field to the default.
3. Runtime code (DHCP, user configuration, etc.) overwrites the struct field.

```c
// net_config.h
// ──────────────────────────────────────────

// Network identity — defaults for simple demo; DHCP/user overrides at runtime
#define NET_DEFAULT_IPV4_ADDR       NET_IPV4(10, 0, 0, 2)  // 0 = unconfigured (wait for DHCP)
#define NET_DEFAULT_SUBNET_MASK     NET_IPV4(255, 255, 255, 0)
#define NET_DEFAULT_GATEWAY         NET_IPV4(10, 0, 0, 1)  // 0 = none / wait for DHCP
#define NET_DEFAULT_DNS_SERVER      NET_IPV4(0, 0, 0, 0)   // 0 = wait for DHCP

// MAC address — default for dev/test; production reads from OTP/EEPROM at runtime
#define NET_DEFAULT_MAC             { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 }

// TCP tuning — defaults work for most cases; app can adjust per-connection
#define NET_DEFAULT_TCP_RTO_INIT_MS     1000    // Initial retransmission timeout
#define NET_DEFAULT_TCP_RTO_MIN_MS      200     // Minimum RTO
#define NET_DEFAULT_TCP_RTO_MAX_MS      60000   // Maximum RTO
#define NET_DEFAULT_TCP_MSL_MS          120000  // Maximum segment lifetime (2 min)
#define NET_DEFAULT_TCP_DELAYED_ACK_MS  200     // Delayed ACK timer (≤ 500ms per RFC)

// ARP tuning
#define NET_DEFAULT_ARP_RETRY_MS        1000    // ARP request retry interval
#define NET_DEFAULT_ARP_MAX_RETRIES     3       // Give up after N retries

// DHCP tuning
#define NET_DEFAULT_DHCP_HOSTNAME       "smallest"  // or NULL for no hostname
```

### Usage Pattern

```c
// ── Simple demo: compiled-in IP, no DHCP ──
// net_config.h:
#define NET_DEFAULT_IPV4_ADDR   NET_IPV4(10, 0, 0, 2)
#define NET_USE_DHCPV4          0

// app.c:
net_init(&net, ...);
// net.ipv4_addr is already 10.0.0.2 from default — done.


// ── Production: DHCP discovery ──
// net_config.h:
#define NET_DEFAULT_IPV4_ADDR   0  // unconfigured
#define NET_USE_DHCPV4          1

// app.c:
net_init(&net, ...);
// net.ipv4_addr is 0 (unconfigured)
dhcpv4_start(&dhcp, &net);
// ... later, DHCP sets net.ipv4_addr = assigned address


// ── Production: static IP entered by user ──
// net_config.h:
#define NET_DEFAULT_IPV4_ADDR   0  // no default
#define NET_USE_DHCPV4          0

// app.c:
net_init(&net, ...);
net.ipv4_addr = user_configured_ip;  // set at runtime from EEPROM/CLI/etc.
net.subnet_mask = user_configured_mask;
net.gateway_ipv4 = user_configured_gw;
```

### All Runtime-Tunable Fields

These live in `net_t` and connection structs. The factory method initializes them from `NET_DEFAULT_*` values. Any of them can be overwritten before or during operation.

| Field | Struct | Default Source | Runtime Override Source |
|---|---|---|---|
| `ipv4_addr` | `net_t` | `NET_DEFAULT_IPV4_ADDR` | DHCP, user config, EEPROM |
| `subnet_mask` | `net_t` | `NET_DEFAULT_SUBNET_MASK` | DHCP, user config |
| `gateway_ipv4` | `net_t` | `NET_DEFAULT_GATEWAY` | DHCP, user config |
| `dns_server` | `net_t` | `NET_DEFAULT_DNS_SERVER` | DHCP, DHCPv6, user config |
| `mac` | `net_t` | `NET_DEFAULT_MAC` | OTP/EEPROM read at init |
| `ipv6_addr` | `net_t` | — (always runtime) | SLAAC, DHCPv6 |
| `rto_init_ms` | `tcp_conn_t` | `NET_DEFAULT_TCP_RTO_INIT_MS` | Adapted by RTT measurement |
| `delayed_ack_ms` | `tcp_conn_t` | `NET_DEFAULT_TCP_DELAYED_ACK_MS` | App tuning per connection |
| `arp_retry_ms` | `net_t` | `NET_DEFAULT_ARP_RETRY_MS` | App tuning |
| `hostname` | `dhcp_state_t` | `NET_DEFAULT_DHCP_HOSTNAME` | App sets before DHCP start |

## Category 3: Runtime Only

These are inherently dynamic — they have no meaningful compile-time value.

| Value | Source | Notes |
|---|---|---|
| TCP sequence numbers | Random or counter at connection start | Must not be predictable |
| TCP peer's window size | SYN/ACK from remote | Changes per ACK |
| TCP RTT estimate | Measured per segment | Feeds RTO calculation |
| ARP-resolved MAC addresses | ARP/NDP replies | Cached in connection structs |
| DHCP lease time, T1, T2 | DHCP server | Drives renewal timers |
| DHCP transaction ID | Random per exchange | |
| DNS transaction ID | Random per query | |
| IPv6 link-local address | Derived from MAC at init | Computed, not configured |
| SLAAC prefix | Router Advertisement | |
| DAD state | NDP process | |

## Factory Method: Default Application

```c
// In net_init():
net_err_t net_init(net_t *net, ...) {
    memset(net, 0, sizeof(*net));
    
    // Apply compile-time defaults to runtime-tunable fields
    #ifdef NET_DEFAULT_IPV4_ADDR
    net->ipv4_addr = NET_DEFAULT_IPV4_ADDR;
    #endif
    #ifdef NET_DEFAULT_SUBNET_MASK
    net->subnet_mask = NET_DEFAULT_SUBNET_MASK;
    #endif
    #ifdef NET_DEFAULT_GATEWAY
    net->gateway_ipv4 = NET_DEFAULT_GATEWAY;
    #endif
    
    static const uint8_t default_mac[] = NET_DEFAULT_MAC;
    memcpy(net->mac, default_mac, 6);
    
    net->arp_retry_ms = NET_DEFAULT_ARP_RETRY_MS;
    net->arp_max_retries = NET_DEFAULT_ARP_MAX_RETRIES;
    
    // ... validate buffers, set up MAC driver ...
    return NET_OK;
}
```

## net_config.h Delivery

The application provides `net_config.h`. The stack headers include it:

```c
// net.h
#include "net_config.h"  // application-provided, must be on include path
```

For the demo applications, a default `net_config.h` is provided:
```
demo/
├── echo_server/
│   ├── net_config.h    ← static IP, no DHCP, no IPv6
│   └── main.c
├── dhcp_demo/
│   ├── net_config.h    ← DHCP enabled, no static IP
│   └── main.c
└── http_server/
    ├── net_config.h    ← static IP, TCP + HTTP enabled
    └── main.c
```

## Summary: Where Each Decision Is Made

| Decision | Where | Why |
|---|---|---|
| Does the MAC offload checksums? | `#define` (compile-time) | Hardware fact, never changes |
| Is IPv6 included? | `#define` + linker (compile/link-time) | Build variant, dead code elimination |
| What is the IP address? | Struct field (runtime, with optional default) | May come from DHCP, EEPROM, or user |
| What is the TCP RTO? | Struct field (runtime, with default) | Starts from default, adapted by measurement |
| What are the buffer sizes? | Array declaration (compile-time) | Application declares static arrays |
| What MSS do we advertise? | Derived from buffer size (compile-time) | `NET_TCP_MSS_IPV4(sizeof(tx_buf))` |
| What MSS does peer use? | TCP SYN option (runtime) | Peer tells us in handshake |
| What is the DHCP lease time? | DHCP server response (runtime) | Only known after DHCP completes |
