# Code Size Comparison — smallest_tcp vs lwIP

## Methodology

Both stacks compiled for **ARM Cortex-M0** (representative of STM32F042, CH32X033) with identical optimization flags:

```
arm-none-eabi-gcc -std=c99 -Os -mthumb -mcpu=cortex-m0
                  -ffreestanding -ffunction-sections -fdata-sections
```

- **smallest_tcp:** Linked ELF with `-Wl,--gc-sections`, debug logging disabled (`-DNET_DEBUG=0`), built by the `Makefile`'s `arm-size*` targets from `bench/size_measure.c`
- **lwIP:** 2.2.1 (`STABLE-2_2_1_RELEASE`), object files compiled with matching flags by `bench/build_lwip.sh`, minimal `lwipopts.h` (see below)
- **Feature set:** ETH + ARP + IPv4 + ICMP + UDP (no TCP, no DHCP, no DNS, no IGMP); smallest_tcp built with `-DNET_USE_TCP=0 -DNET_MAX_MCAST_GROUPS=0`
- **Toolchain:** arm-none-eabi-gcc 13.2.1 (Arm GNU Toolchain 13.2.Rel1)

Two kinds of figure appear below.  **Flash** and **RAM** are the linked
ELF's (`.text`, and `.data` + `.bss`): what a device carries.  **Per-module
`.text`** is the object file's, before `--gc-sections`, so it includes
functions a given program never calls and the linker drops.  The largest
of these is IPv4 reassembly: `ipv4.o` carries it (792 B: `reassemble()`,
`reassembly_tick()`, `ipv4_set_reassembly()` and its operations table), and
`icmp.o` the Time Exceeded it sends (16 B), but only a program that calls
`ipv4_set_reassembly()` links them
([architecture.md §6](../architecture.md#6-transmit-path)).  None of the
benchmarks does.

### lwIP Configuration

lwIP configured for the smallest possible UDP-only build (`bench/lwip/lwipopts.h`):
- `NO_SYS=1` (bare-metal, no OS)
- `LWIP_TCP=0`, `LWIP_DHCP=0`, `LWIP_DNS=0`, `LWIP_IPV6=0`
- `LWIP_SOCKET=0`, `LWIP_NETCONN=0`
- `IP_REASSEMBLY=0`, `IP_FRAG=0`
- `MEM_SIZE=1024`, `PBUF_POOL_SIZE=4`, `ARP_TABLE_SIZE=4`
- `LWIP_STATS=0`, `LWIP_DEBUG=0`, `LWIP_NOASSERT=1`

## Summary

| Metric | smallest_tcp | lwIP | Ratio |
|--------|-------------|------|-------|
| **Flash (code + rodata)** | **4,098 B** | 10,089 B | **2.5× smaller** |
| **RAM (static state)** | **720 B** | 2,619 B | **3.6× smaller** |
| Stack-only code (objects) | **4,870 B** | 10,087 B | **2.1× smaller** |
| Stack-only code, without reassembly | **4,062 B** | 10,087 B (none) | **2.5× smaller** |
| Stack-internal RAM | **0 B** | ~2,619 B | — |
| Source modules | 7 | 16 | — |

> **Note:** smallest_tcp's 720 B of RAM is all declared by the application: the 600 bytes of
> rx/tx frame buffers, the 116-byte `net_t`, and a 4-byte benchmark variable.  The stack's own
> objects have no `.data` or `.bss` at all: the port table pointer lives in `net_t`, and IPv4
> datagrams are sent with DF set and identification 0 (RFC 6864), so there is no ID counter.
> lwIP's 2,619 B of BSS is internal memory pools (mem, memp, pbuf_pool, ARP table, etc.).

## Per-Module Breakdown

### smallest_tcp — 7 modules, 4,870 bytes code

| Module | .text | .data | .bss | Function |
|--------|------:|------:|-----:|----------|
| `net.c` | 672 | 0 | 0 | `net_init()`, `net_poll()`, `net_tick()`, `net_transmit()`, random numbers (HalfSipHash-2-4) |
| `net_cksum.c` | 194 | 0 | 0 | Internet checksum (RFC 1071), pieces of any length |
| `eth.c` | 242 | 0 | 0 | Ethernet II parse/build/dispatch |
| `arp.c` | 620 | 0 | 0 | ARP request/reply, the gateway's MAC and its expiry, request rate limit, address probe |
| `ipv4.c` | 1,760 | 0 | 0 | IPv4 parse/build (TTL and TOS per packet), options, source and destination checks, protocol dispatch, Protocol Unreachable, MMS_R/MMS_S; reassembly (792 B, not linked here) |
| `icmp.c` | 564 | 0 | 0 | ICMP echo reply, Destination Unreachable, Time Exceeded, errors received passed to UDP |
| `udp.c` | 818 | 0 | 0 | UDP parse/send (copying + in-place, TTL and TOS per datagram), port dispatch, destination address and ICMP errors to the application |
| **Total** | **4,870** | **0** | **0** | |

The benchmark's own `size_measure.c` (216 B) and the stub MAC driver (44 B) make up the rest
of the 5,130 B of objects; the linked ELF is 4,098 B, since `--gc-sections` drops what the
benchmark never calls — reassembly above all.

### lwIP 2.2.1 — 16 modules, 10,087 bytes code

| Module | .text | .data | .bss | Function |
|--------|------:|------:|-----:|----------|
| `pbuf.c` | 1,706 | 0 | 0 | Packet buffer management |
| `etharp.c` | 1,644 | 0 | 97 | ARP + Ethernet address resolution |
| `udp.c` | 1,280 | 2 | 4 | UDP protocol |
| `ip4.c` | 922 | 0 | 2 | IPv4 processing |
| `netif.c` | 862 | 0 | 9 | Network interface abstraction |
| `mem.c` | 686 | 0 | 1,055 | Heap memory allocator |
| `ip4_addr.c` | 588 | 0 | 16 | IPv4 address utilities |
| `inet_chksum.c` | 532 | 0 | 0 | Internet checksum |
| `icmp.c` | 504 | 0 | 0 | ICMP protocol |
| `def.c` | 390 | 0 | 0 | Byte-order, string utilities |
| `timeouts.c` | 384 | 0 | 8 | Timer management |
| `memp.c` | 301 | 0 | 1,404 | Fixed-size memory pools |
| `ethernet.c` | 264 | 0 | 0 | Ethernet frame parsing |
| `init.c` | 24 | 0 | 0 | Stack initialization |
| `ip.c` | 0 | 0 | 24 | IP globals |
| `ip4_frag.c` | 0 | 0 | 0 | (disabled via config) |
| **Total** | **10,087** | **2** | **2,619** | |

## Where the Difference Comes From

### Memory Management: +3,555 bytes in lwIP

lwIP's internal memory management adds significant overhead:

| lwIP Module | .text | .bss | Purpose | smallest_tcp equivalent |
|-------------|------:|-----:|---------|------------------------|
| `mem.c` | 686 | 1,055 | Heap allocator | None — zero allocation |
| `memp.c` | 301 | 1,404 | Fixed pools | None — zero allocation |
| `pbuf.c` | 1,706 | 0 | Packet buffers | None — app-owned buffers |
| `netif.c` | 862 | 9 | Interface abstraction | MAC vtable (in net.h) |
| **Subtotal** | **3,555** | **2,468** | | **0** |

smallest_tcp eliminates all of this by having the application own all memory. The stack operates on caller-provided buffers with no internal allocation, pools, or buffer management.

### Protocol Code Comparison

Comparing just the protocol-equivalent modules:

| Function | smallest_tcp | lwIP | Ratio |
|----------|-------------|------|-------|
| ARP | 620 B | 1,644 B | 2.7× |
| IPv4 | 1,760 B (968 B without reassembly) | 922 B | 0.5× (1.0×) |
| ICMP | 564 B (548 B without reassembly) | 504 B | 0.9× |
| UDP | 818 B | 1,280 B | 1.6× |
| Checksum | 194 B | 532 B | 2.7× |
| Ethernet | 242 B | 264 B | 1.1× |
| **Subtotal** | **4,198 B (3,390 B without reassembly)** | **5,146 B** | **1.2× (1.5×)** |

Protocol for protocol, the difference is smaller than for the whole stack.
smallest_tcp's ARP, UDP and checksum are well under lwIP's, because of:
- No pbuf chain traversal (operates on flat buffers)
- No ARP cache table (the gateway's MAC in `net_t`, peers' MACs in their connections — [arp-resolution.md](arp-resolution.md))
- No general-purpose netif callbacks
- Simpler API (direct function calls vs. callback chains)

Its IPv4 and ICMP are about the size of lwIP's minimal ones and do more:
received IP options, every broadcast form of the network and the source
checks of RFC 1122, the MTU and the MMS_R/MMS_S limits, TOS per datagram,
and ICMP errors passed up to the transports.  The rest of the difference is
lwIP's memory management, above.

## Adding TCP

`make arm-size-tcp` builds the same benchmark with TCP enabled: a single-connection
TCP echo server on port 7 using the stop-and-wait buffers (128 B TX + 128 B RX),
alongside the UDP echo server.

| Metric | UDP only | UDP + TCP | Delta |
|--------|---------:|----------:|------:|
| **Flash (code + rodata)** | 4,098 B | **8,546 B** | +4,448 B |
| **RAM (static state)** | 720 B | **1,116 B** | +396 B |
| Stack-only code (objects) | 4,870 B | 9,664 B | +4,794 B |
| Stack-internal RAM | 0 B | 0 B | 0 |

| Module | .text | .data | .bss | Function |
|--------|------:|------:|-----:|----------|
| `tcp.c` | 4,340 | 0 | 0 | Full state machine, in-order delivery, retransmit (data + FIN; R1 and R2), persist timer, MSS/window and the Path MTU from ICMP, window updates, FIN queued behind unsent data, RFC 6528 initial sequence numbers, CLOSE and ABORT in every state, a passive open listening again, ICMP errors, TOS |
| `tcp_buf_saw.c` | 416 | 0 | 0 | Stop-and-wait TX/RX buffers |
| `ipv4.c` | 1,770 | 0 | 0 | (+10 B for TCP dispatch) |
| `icmp.c` | 584 | 0 | 0 | (+20 B: ICMP errors to TCP) |
| `net.c` | 680 | 0 | 0 | (+8 B: `net_tick()` runs `tcp_tick()`) |

TCP has no static state.  The application owns the connection table and binds
it with `tcp_set_connections(net, table, n)` — its pointer and count live in
`net_t` — and initial sequence numbers are `net_t`'s TCP clock plus a hash
under `net_t`'s secret key ([tcp.md §4.6](tcp.md#46-initial-sequence-numbers)).  The extra RAM is therefore all application-owned: the
256 B of TCP buffers, the 104-byte `tcp_conn_t`, the two 12-byte buffer
contexts, and 12 more bytes of `net_t` (the table pointer and count, and the
TCP clock).  The table itself is `const` and sits in flash.  The object
totals include functions this benchmark never calls (`tcp_connect()`,
`tcp_window_update()`, reassembly, …), which link-time gc removes — hence
stack-only code above the ELF's flash total.

## Adding mDNS + DNS-SD

`make arm-size-mdns` builds the UDP benchmark plus the mDNS responder advertising
a host name and one DNS-SD service (A, PTR, SRV, TXT), with one multicast group
(`NET_MAX_MCAST_GROUPS=1`).

| Metric | UDP only | UDP + mDNS | Delta |
|--------|---------:|-----------:|------:|
| **Flash (code + rodata)** | 4,098 B | **14,424 B** | +10,326 B |
| **RAM (static state)** | 720 B | **832 B** | +112 B |
| Stack-only code (objects) | 4,870 B | 15,105 B | +10,235 B |
| Stack-internal RAM | 0 B | 0 B | 0 |

| Module | .text | .data | .bss | Function |
|--------|------:|------:|-----:|----------|
| `mdns.c` | 7,837 | 0 | 0 | Probe/announce/answer state machine, DNS-SD additionals, NSEC negative answers, known-answer suppression (truncated queries too), conflicts and tiebreaking, rate limiting, legacy unicast, goodbye, withdrawing records, the size check of the table |
| `dns_wire.c` | 1,616 | 0 | 0 | RFC 1035 names with compression, bounds-checked readers |
| `igmp.c` | 536 | 0 | 0 | IGMPv2 host: reports, leaves and query answers with Router Alert, IGMPv1 routers |
| `ipv4.c` | 1,974 | 0 | 0 | (+214 B: multicast group table and acceptance, IGMP dispatch and timer) |
| `eth.c`, `icmp.c`, `udp.c` | 1,656 | 0 | 0 | (+32 B: joined-group MAC filter, no ICMP errors for multicast) |

The 112 B of extra RAM is the application-owned `mdns_t` (96 B) and `net_t`'s
multicast part (16 B: the one group slot, IGMP's operations, its report
delay and the IGMPv1-router timer); the responder keeps no static state.
Responses are built directly in the TX buffer, so no second message buffer is
needed.  The random probe/response delays use `net_random_below()`, which
scales a random number instead of dividing — on Cortex-M0 (no divide
instruction) `%` would link libgcc's `__udivsi3`.

## Adding an HTTP server

`make arm-size-http` builds the UDP benchmark plus the HTTP server (and TCP) with
one connection slot — 256 B TCP TX, 256 B TCP RX and a 256 B request buffer —
serving a static page.

| Metric | UDP only | UDP + HTTP | Delta |
|--------|---------:|-----------:|------:|
| **Flash (code + rodata)** | 4,098 B | **14,974 B** | +10,876 B |
| **RAM (static state)** | 720 B | **1,760 B** | +1,040 B |
| Stack-only code (objects) | 4,870 B | 15,694 B | +10,824 B |
| Stack-internal RAM | 0 B | 0 B | 0 |

| Module | .text | .data | .bss | Function |
|--------|------:|------:|-----:|----------|
| `http.c` | 5,922 | 0 | 0 | Request parser, header formatter, routes, streaming, conditional requests, `Expect`, Date, slot recycling, timeouts, the TCP transport |
| `net_text.c` | 108 | 0 | 0 | Case-insensitive compare, decimal formatting (no division) |
| `tcp.c` + `tcp_buf_saw.c` | 4,756 | 0 | 0 | As in "Adding TCP" |

HTTP costs about 6.4 KB of flash on top of TCP (14,974 B against the TCP
echo's 8,546 B).  The extra RAM is all application owned: the three 256 B
buffers, the 220-byte `http_conn_t` (which embeds the `tcp_conn_t`), the
36-byte `http_server_t`, the one-entry connection table and the larger
`net_t`.  The response header is formatted on the stack (`HTTP_HDR_MAX`,
224 B, while sending), without `printf` and without division.

## Adding IPv6 (dual stack)

`make arm-size-ipv6` builds the UDP benchmark dual stack (`-DNET_USE_IPV6=1`)
with a UDP echo over IPv6 as well: IPv6 input/output with the extension-header
walk, ICMPv6 (echo, errors), Neighbor Discovery (NS/NA responder, DAD, router
discovery, SLAAC with lifetimes) and MLDv2/v1.  No multicast groups to join
(`NET_MAX_MCAST_GROUPS=0`, `NET_MAX_MCAST6_GROUPS=0`).

| Metric | UDP (IPv4) | UDP, dual stack | Delta |
|--------|-----------:|----------------:|------:|
| **Flash (code + rodata)** | 4,098 B | **9,113 B** | +5,015 B |
| **RAM (static state)** | 720 B | **824 B** | +104 B |
| Stack-only code (objects) | 4,870 B | 9,887 B | +5,017 B |

| Module | .text | Function |
|--------|------:|----------|
| `ipv6.c` | 1,439 | Header parse/build, extension headers, addresses and lifetimes, source selection, dispatch |
| `ndp.c` | 1,459 | NS/NA, DAD, Router Solicitation/Advertisement, SLAAC |
| `mld.c` | 985 | MLDv2 reports and query answers, MLDv1 fallback |
| `icmpv6.c` | 592 | Checksum, echo, error messages |
| `udp.c` (IPv6 part) | +498 | `udp6_input`, `udp6_send[_inplace]` |
| `eth.c`, `net.c` | +44 | IPv6 dispatch, `ipv6_tick()` from `net_tick()` |

The RAM is `net_t`'s IPv6 part: two address slots with their lifetimes,
the default router, the MLD and router-solicitation timers, and the IPv6 port
table pointer.  No divide routine is linked (lifetimes count seconds by
subtraction).

## IPv6 only

`make arm-size-ipv6-only` builds the same UDP echo over IPv6 alone
(`-DNET_USE_IPV4=0`): no ARP, IPv4, ICMPv4, no IPv4 half of UDP, and none of
`net_t`'s IPv4 fields ([configuration.md §5](configuration.md#5-compile-time-protocol-selection)).

| Metric | UDP, dual stack | UDP, IPv6 only | Delta |
|--------|----------------:|---------------:|------:|
| **Flash (code + rodata)** | 9,113 B | **6,105 B** | −3,008 B |
| **RAM (static state)** | 824 B | **752 B** | −72 B |
| Stack-only code (objects) | 9,887 B | 6,011 B | −3,876 B |

The IPv6 modules are nearly the same objects as in the dual stack (`ipv6.c`
and `ndp.c` are 16 B smaller); what goes is `arp.c` (620 B),
`ipv4.c` (1,760 B, reassembly included), `icmp.c` (564 B), UDP over IPv4
(832 B) and the IPv4 branches of `eth.c` and `net.c` (84 B).  The RAM saved
is `net_t`'s IPv4 part: 148 bytes instead of 220.

## Adding TLS 1.3

`make arm-size-tls` compiles the TLS 1.3 protocol — records, key schedule,
handshake with certificates and pre-shared keys, HelloRetryRequest,
max_fragment_length, KeyUpdate — with the benchmark flags, DTLS left out of
the handshake (`TLS_USE_DTLS` 0), and reports it per object and for the two
ways a device links it.  It is not linked into a
benchmark: every cryptographic primitive comes from a `tls_crypto_t` backend
(Mbed TLS in this project), whose size depends entirely on its configuration
and is not measured here.

| | .text | RAM |
|---|---:|---:|
| `tls_common.c` (handshake framing, keys, alerts; shared with DTLS) | 766 B | — |
| `tls.c` (stream records, KeyUpdate, API) | 2,490 B | — |
| `tls_keys.c` (key schedule, record protection) | 1,086 B | — |
| `tls_server.c` (`tls_accept()`, server handshake) | 3,118 B | — |
| `tls_client.c` (`tls_connect()`, client handshake) | 3,490 B | — |
| **Server only** | **7,460 B** | — |
| **Client and server** | **10,950 B** | — |
| `tls_conn_t` (per connection) | — | 448 B (128 of them the backend's SHA-256 state) |
| `tls_config_t` (shared) | — | 44 B |

A server-only device links 7.5 KB: `tls.c` reaches the handshake only through
the role pointer that `tls_accept()` or `tls_connect()` sets, so the role an
application never starts is never referenced and never linked
([tls.md §2.1](tls.md#21-the-role-interface)).  Plus the application's record
buffers ([tls.md §5](tls.md#5-buffers)).  The TLS objects have no `.data` or
`.bss`, and no divide routine is linked.

## Adding DTLS 1.3

`make arm-size-dtls` compiles DTLS 1.3 the same way: the shared handshake
built with DTLS (`TLS_USE_DTLS` 1) and the datagram record layer, `dtls.c`,
in place of TLS's `tls.c`.

| | .text | RAM |
|---|---:|---:|
| `tls_common.c` | 770 B | — |
| `dtls.c` (records, epochs, flights, timer, ACKs, API) | 5,861 B | — |
| `tls_keys.c` | 1,086 B | — |
| `tls_server.c`, with DTLS's hello formats and cookie | 3,546 B | — |
| `tls_client.c`, with DTLS's hello formats | 3,658 B | — |
| **Server only** | **11,263 B** | — |
| **Client and server** | **14,921 B** | — |
| `dtls_conn_t` (per connection) | — | 904 B (its `tls_conn_t` is 448 B) |

The datagram record layer costs more than the stream one — reliability,
fragmentation and reassembly, epochs and ACKs are DTLS's to do, where TCP
does them for TLS — but the handshake is shared: a device with both
protocols links 17.4 KB (the DTLS build of the handshake, `tls.c` and
`dtls.c`), not two handshakes.  `make arm-check-links` checks
that neither protocol's build references the other's record layer
([dtls.md §12](dtls.md#12-size-and-memory)).

## Target Fit Analysis

| Target | Flash | RAM | smallest_tcp UDP | lwIP UDP |
|--------|-------|-----|-----------------|----------|
| **PIC16F1454** | 14 KB | 1 KB | ✅ 4.1 KB + buffers | ❌ 10 KB code alone |
| **CH32X033** | 62 KB | 20 KB | ✅ Plenty of room | ✅ Fits |
| **STM32F042** | 32 KB | 6 KB | ✅ 4.1 KB; 8.5 KB with TCP; 14.4 KB with mDNS; 15.0 KB with HTTP; 9.1 KB dual stack; 6.1 KB IPv6 only | ⚠️ Tight with app |
| **CH32V203** | 256 KB | 10 KB | ✅ Plenty of room | ✅ Fits |

## How to Reproduce

```bash
# Build smallest_tcp for ARM and show sizes (needs arm-none-eabi-gcc)
make arm-size        # UDP only (lwIP comparison)
make arm-size-tcp    # UDP + TCP
make arm-size-mdns   # UDP + mDNS/DNS-SD responder
make arm-size-http   # UDP + HTTP server (with TCP)
make arm-size-ipv6   # UDP, dual stack IPv4 + IPv6 (ICMPv6, ND, SLAAC, MLD)
make arm-size-ipv6-only  # UDP over IPv6 alone (no ARP, IPv4, ICMPv4)
make arm-size-tls    # TLS 1.3 protocol: server only, client and server
make arm-size-dtls   # DTLS 1.3 protocol: the same
make arm-size-all    # all of the above, then arm-check-division and
                     # arm-check-links
make arm-check-division  # fail if any ARM object calls a library divide
make arm-check-links     # fail if TLS needs dtls.c, or DTLS tls.c

# The functions of one object, by size (reassembly in ipv4.o, say)
arm-none-eabi-nm --size-sort -S -t d build/arm/udp/src/ipv4.o

# Build lwIP for comparison (clones lwIP 2.2.1 into build/lwip if missing)
bash bench/build_lwip.sh
```

The objects and ELFs go to `build/arm/` (`make BUILD=<dir>` puts them
elsewhere); `make clean` removes them.  Remeasure from scratch
(`rm -rf build/arm`) after changing a source: make compares file times, and
misses a change made in the same second as the last build.
`arm-check-division` compiles every
source in `src/` (dual stack, the Mbed TLS backend excepted) as well as the
benchmark configurations, and fails if any object refers to `__aeabi_uidiv`,
`__aeabi_idiv`, their `divmod` forms or the other libgcc divide helpers —
Cortex-M0 has no divide instruction ([coding-rules.md](coding-rules.md)).

### Files

| File | Purpose |
|------|---------|
| `Makefile` | The `arm-size*`, `arm-check-division` and `arm-check-links` targets (the Makefile builds nothing for the host) |
| `bench/size_measure.c` | Bare-metal app exercising all stack layers; `BENCH_MDNS`, `BENCH_HTTP`, `BENCH_IPV6` select the extra configurations, and `NET_USE_IPV4=0` with `BENCH_IPV6` the IPv6-only one |
| `bench/cortex-m0.ld` | Minimal linker script (32KB flash, 6KB RAM) |
| `src/driver/stub.c` | No-op MAC driver for cross-compilation |
| `bench/lwip/lwipopts.h` | Minimal lwIP UDP-only config |
| `bench/lwip/arch/cc.h` | lwIP architecture port for bare-metal ARM |
| `bench/build_lwip.sh` | Script to compile lwIP modules |

## Notes

- lwIP sizes are .o file totals (before link-time gc-sections). Actual linked lwIP would be somewhat smaller depending on which functions the application calls.  They come from `bench/build_lwip.sh` against lwIP 2.2.1 with the toolchain above.
- smallest_tcp's Flash and RAM are from a linked ELF with `--gc-sections`, representing real deployed size; its per-module and stack-only figures are object totals, like lwIP's.
- Both use nano newlib for memcpy/memset (not counted — same for both).
- Flash totals depend on the toolchain's newlib. The figures here use the Arm GNU Toolchain
  13.2.Rel1, whose `memcpy`/`memset`/`memcmp` total 62 B. Ubuntu's `libnewlib-arm-none-eabi`
  (used by the `arm-size` CI job) ships larger, speed-optimized versions, so the ELF totals CI
  reports are a few hundred bytes higher.  Stack-only code is identical on both toolchains.
- lwIP has more features even in minimal config (e.g., ARP queueing infrastructure, pbuf chaining, multi-netif support). smallest_tcp intentionally omits these for size.
