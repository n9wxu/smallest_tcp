# Code Size Comparison — smallest_tcp vs lwIP

**Last updated:** 2026-09-27 (every smallest_tcp configuration re-measured after the refactoring: no static state left in the stack, TLS split by role)

## Methodology

Both stacks compiled for **ARM Cortex-M0** (representative of STM32F042, CH32X033) with identical optimization flags:

```
arm-none-eabi-gcc -std=c99 -Os -mthumb -mcpu=cortex-m0
                  -ffreestanding -ffunction-sections -fdata-sections
```

- **smallest_tcp:** Linked ELF with `-Wl,--gc-sections`, debug logging disabled (`-DNET_DEBUG=0`), built by the `Makefile`'s `arm-size*` targets from `bench/size_measure.c`
- **lwIP:** 2.2.1 (`STABLE-2_2_1_RELEASE`), object files compiled with matching flags, minimal `lwipopts.h` (see below)
- **Feature set:** ETH + ARP + IPv4 + ICMP + UDP (no TCP, no DHCP, no DNS, no IGMP); smallest_tcp built with `-DNET_USE_TCP=0 -DNET_MAX_MCAST_GROUPS=0`
- **Toolchain:** arm-none-eabi-gcc 13.2.1 (Arm GNU Toolchain 13.2.Rel1)

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
| **Flash (code + rodata)** | **2,574 B** | 10,089 B | **3.9× smaller** |
| **RAM (static state)** | **668 B** | 2,619 B | **3.9× smaller** |
| Stack-only code | **2,476 B** | 10,087 B | **4.1× smaller** |
| Stack-internal RAM | **0 B** | ~2,619 B | — |
| Source modules | 7 | 16 | — |

> **Note:** smallest_tcp's 668 B of RAM is all declared by the application: the 600 bytes of
> rx/tx frame buffers, the 64-byte `net_t`, and a 4-byte benchmark variable.  The stack's own
> objects have no `.data` or `.bss` at all: the port table pointer lives in `net_t`, and IPv4
> datagrams are sent with DF set and identification 0 (RFC 6864), so there is no ID counter.
> lwIP's 2,619 B of BSS is internal memory pools (mem, memp, pbuf_pool, ARP table, etc.).

## Per-Module Breakdown

### smallest_tcp — 7 modules, 2,476 bytes code

| Module | .text | .data | .bss | Function |
|--------|------:|------:|-----:|----------|
| `net.c` | 340 | 0 | 0 | `net_init()`, `net_poll()`, `net_tick()`, `net_transmit()`, random numbers |
| `net_cksum.c` | 158 | 0 | 0 | Internet checksum (RFC 1071) |
| `eth.c` | 226 | 0 | 0 | Ethernet II parse/build/dispatch |
| `arp.c` | 362 | 0 | 0 | ARP request/reply, gateway MAC |
| `ipv4.c` | 598 | 0 | 0 | IPv4 parse/build (per-packet TTL), protocol dispatch, Protocol Unreachable |
| `icmp.c` | 320 | 0 | 0 | ICMP echo reply, dest unreachable |
| `udp.c` | 472 | 0 | 0 | UDP parse/send (copying + in-place), port dispatch |
| **Total** | **2,476** | **0** | **0** | |

The benchmark's own `size_measure.c` (216 B) and the stub MAC driver (44 B) make up the rest
of the 2,736 B of objects; the linked ELF is 2,574 B, since `--gc-sections` drops what the
benchmark never calls.

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
| ARP | 362 B | 1,644 B | 4.5× |
| IPv4 | 598 B | 922 B | 1.5× |
| ICMP | 320 B | 504 B | 1.6× |
| UDP | 472 B | 1,280 B | 2.7× |
| Checksum | 158 B | 532 B | 3.4× |
| Ethernet | 226 B | 264 B | 1.2× |
| **Subtotal** | **2,136 B** | **5,146 B** | **2.4×** |

Even protocol-for-protocol, smallest_tcp is 2.4× smaller due to:
- No pbuf chain traversal (operates on flat buffers)
- No ARP cache table (the gateway's MAC in `net_t`, peers' MACs in their connections — [arp-resolution.md](arp-resolution.md))
- No general-purpose netif callbacks
- Simpler API (direct function calls vs. callback chains)

## Adding TCP

`make arm-size-tcp` builds the same benchmark with TCP enabled: a single-connection
TCP echo server on port 7 using the stop-and-wait buffers (128 B TX + 128 B RX),
alongside the UDP echo server.

| Metric | UDP only | UDP + TCP | Delta |
|--------|---------:|----------:|------:|
| **Flash (code + rodata)** | 2,574 B | **6,130 B** | +3,556 B |
| **RAM (static state)** | 668 B | **1,052 B** | +384 B |
| Stack-only code (.o, before gc) | 2,476 B | 6,288 B | +3,812 B |
| Stack-internal RAM | 0 B | 0 B | 0 |

| Module | .text | .data | .bss | Function |
|--------|------:|------:|-----:|----------|
| `tcp.c` | 3,362 | 0 | 0 | Full state machine, in-order delivery, retransmit (data + FIN), persist timer, MSS/window, window updates |
| `tcp_buf_saw.c` | 428 | 0 | 0 | Stop-and-wait TX/RX buffers |
| `ipv4.c` | 614 | 0 | 0 | (+16 B for TCP dispatch) |
| `net.c` | 346 | 0 | 0 | (+6 B: `net_tick()` runs `tcp_tick()`) |

TCP has no static state.  The application owns the connection table and binds
it with `tcp_set_connections(net, table, n)` — its pointer and count live in
`net_t` — and initial sequence numbers come from `net_t`'s random generator
([tcp.md](tcp.md)).  The extra RAM is therefore all application-owned: the
256 B of TCP buffers, the 96-byte `tcp_conn_t`, the two 12-byte buffer
contexts, and 8 more bytes of `net_t` (the table pointer and count).  The
table itself is `const` and sits in flash.  The `.o` totals include functions
this benchmark never calls (`tcp_connect()`, `tcp_window_update()`, …), which
link-time gc removes — hence stack-only code above the ELF's flash total.

## Adding mDNS + DNS-SD

`make arm-size-mdns` builds the UDP benchmark plus the mDNS responder advertising
a host name and one DNS-SD service (A, PTR, SRV, TXT), with one multicast group
(`NET_MAX_MCAST_GROUPS=1`).

| Metric | UDP only | UDP + mDNS | Delta |
|--------|---------:|-----------:|------:|
| **Flash (code + rodata)** | 2,574 B | **8,956 B** | +6,382 B |
| **RAM (static state)** | 668 B | **716 B** | +48 B |
| Stack-only code (.o, before gc) | 2,476 B | 8,555 B | +6,079 B |
| Stack-internal RAM | 0 B | 0 B | 0 |

| Module | .text | .data | .bss | Function |
|--------|------:|------:|-----:|----------|
| `mdns.c` | 4,445 | 0 | 0 | Probe/announce/answer state machine, DNS-SD additionals, NSEC negative answers, known-answer suppression, conflicts, goodbye |
| `dns_wire.c` | 1,238 | 0 | 0 | RFC 1035 names with compression, bounds-checked readers |
| `igmp.c` | 250 | 0 | 0 | IGMPv2 report / leave with Router Alert |
| `ipv4.c` | 712 | 0 | 0 | (+114 B: multicast group table and acceptance) |
| `eth.c`, `icmp.c`, `udp.c` | 1,050 | 0 | 0 | (+32 B: joined-group MAC filter, no ICMP errors for multicast) |

The 48 B of extra RAM is the application-owned `mdns_t` (44 B) and the one-entry
multicast table in `net_t` (4 B); the responder keeps no static state.
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
| **Flash (code + rodata)** | 2,574 B | **10,510 B** | +7,936 B |
| **RAM (static state)** | 668 B | **1,672 B** | +1,004 B |
| Stack-only code (.o, before gc) | 2,476 B | 10,302 B | +7,826 B |
| Stack-internal RAM | 0 B | 0 B | 0 |

| Module | .text | .data | .bss | Function |
|--------|------:|------:|-----:|----------|
| `http.c` | 3,906 | 0 | 0 | Request parser, header formatter, routes, streaming, slot recycling, timeouts, the TCP transport |
| `net_text.c` | 108 | 0 | 0 | Case-insensitive compare, decimal formatting (no division) |
| `tcp.c` + `tcp_buf_saw.c` | 3,790 | 0 | 0 | As in "Adding TCP" |

HTTP itself costs about 4 KB on top of TCP.  The extra RAM is all application
owned: the three 256 B buffers, the 200-byte `http_conn_t` (which embeds the
`tcp_conn_t`), the `http_server_t`, the one-entry connection table and the
larger `net_t`.  The response header is formatted on the stack (192 B while
sending), without `printf` and without division.

## Adding IPv6 (dual stack)

`make arm-size-ipv6` builds the UDP benchmark dual stack (`-DNET_USE_IPV6=1`)
with a UDP echo over IPv6 as well: IPv6 input/output with the extension-header
walk, ICMPv6 (echo, errors), Neighbor Discovery (NS/NA responder, DAD, router
discovery, SLAAC with lifetimes) and MLDv2/v1.  No multicast groups to join
(`NET_MAX_MCAST_GROUPS=0`, `NET_MAX_MCAST6_GROUPS=0`).

| Metric | UDP (IPv4) | UDP, dual stack | Delta |
|--------|-----------:|----------------:|------:|
| **Flash (code + rodata)** | 2,574 B | **7,549 B** | +4,975 B |
| **RAM (static state)** | 668 B | **772 B** | +104 B |
| Stack-only code (.o, before gc) | 2,476 B | 7,441 B | +4,965 B |

| Module | .text | Function |
|--------|------:|----------|
| `ipv6.c` | 1,429 | Header parse/build, extension headers, addresses and lifetimes, source selection, dispatch |
| `ndp.c` | 1,459 | NS/NA, DAD, Router Solicitation/Advertisement, SLAAC |
| `mld.c` | 985 | MLDv2 reports and query answers, MLDv1 fallback |
| `icmpv6.c` | 592 | Checksum, echo, error messages |
| `udp.c` (IPv6 part) | +462 | `udp6_input`, `udp6_send[_inplace]` |
| `eth.c`, `net.c` | +38 | IPv6 dispatch, `ipv6_tick()` from `net_tick()` |

The RAM is `net_t`'s IPv6 part: two address slots with their lifetimes,
the default router, the MLD and router-solicitation timers, and the IPv6 port
table pointer.  No divide routine is linked (lifetimes count seconds by
subtraction).  An IPv6-only build (no ARP, IPv4, ICMPv4) is not offered yet.

## Adding TLS 1.3

`make arm-size-tls` compiles the TLS 1.3 protocol — records, key schedule,
handshake with certificates and pre-shared keys, HelloRetryRequest,
max_fragment_length, KeyUpdate — with the benchmark flags and reports it per
object and for the two ways a device links it.  It is not linked into a
benchmark: every cryptographic primitive comes from a `tls_crypto_t` backend
(Mbed TLS in this project), whose size depends entirely on its configuration
and is not measured here.

| | .text | RAM |
|---|---:|---:|
| `tls.c` (records, alerts, KeyUpdate, API) | 2,910 B | — |
| `tls_keys.c` (key schedule, record protection) | 1,043 B | — |
| `tls_server.c` (`tls_accept()`, server handshake) | 3,070 B | — |
| `tls_client.c` (`tls_connect()`, client handshake) | 3,480 B | — |
| **Server only** | **7,023 B** | — |
| **Client and server** | **10,503 B** | — |
| `tls_conn_t` (per connection) | — | 440 B (128 of them the backend's SHA-256 state) |
| `tls_config_t` (shared) | — | 40 B |

A server-only device links 7.0 KB: `tls.c` reaches the handshake only through
the role pointer that `tls_accept()` or `tls_connect()` sets, so the role an
application never starts is never referenced and never linked
([tls.md §2.1](tls.md#21-the-role-interface)).  Plus the application's record
buffers ([tls.md §5](tls.md#5-buffers)).  The TLS objects have no `.data` or
`.bss`, and no divide routine is linked.

## Target Fit Analysis

| Target | Flash | RAM | smallest_tcp UDP | lwIP UDP |
|--------|-------|-----|-----------------|----------|
| **PIC16F1454** | 14 KB | 1 KB | ✅ 2.6 KB + buffers | ❌ 10 KB code alone |
| **CH32X033** | 62 KB | 20 KB | ✅ Plenty of room | ✅ Fits |
| **STM32F042** | 32 KB | 6 KB | ✅ 2.6 KB; 6.1 KB with TCP; 9.0 KB with mDNS; 10.5 KB with HTTP; 7.5 KB dual stack | ⚠️ Tight with app |
| **CH32V203** | 256 KB | 10 KB | ✅ Plenty of room | ✅ Fits |

## How to Reproduce

```bash
# Build smallest_tcp for ARM and show sizes (needs arm-none-eabi-gcc)
make arm-size        # UDP only (lwIP comparison)
make arm-size-tcp    # UDP + TCP
make arm-size-mdns   # UDP + mDNS/DNS-SD responder
make arm-size-http   # UDP + HTTP server (with TCP)
make arm-size-ipv6   # UDP, dual stack IPv4 + IPv6 (ICMPv6, ND, SLAAC, MLD)
make arm-size-tls    # TLS 1.3 protocol: server only, client and server
make arm-size-all    # all of the above, then arm-check-division
make arm-check-division  # fail if any ARM object calls a library divide

# Build lwIP for comparison (clones lwIP 2.2.1 into build/lwip if missing)
bash bench/build_lwip.sh
```

The objects and ELFs go to `build/arm/` (`make BUILD=<dir>` puts them
elsewhere); `make clean` removes them.  `arm-check-division` compiles every
source in `src/` (dual stack, the Mbed TLS backend excepted) as well as the
benchmark configurations, and fails if any object refers to `__aeabi_uidiv`,
`__aeabi_idiv`, their `divmod` forms or the other libgcc divide helpers —
Cortex-M0 has no divide instruction ([coding-rules.md](coding-rules.md)).

### Files

| File | Purpose |
|------|---------|
| `Makefile` | The `arm-size*` and `arm-check-division` targets (the Makefile builds nothing for the host) |
| `bench/size_measure.c` | Bare-metal app exercising all stack layers; `BENCH_MDNS`, `BENCH_HTTP`, `BENCH_IPV6` select the extra configurations |
| `bench/cortex-m0.ld` | Minimal linker script (32KB flash, 6KB RAM) |
| `src/driver/stub.c` | No-op MAC driver for cross-compilation |
| `bench/lwip/lwipopts.h` | Minimal lwIP UDP-only config |
| `bench/lwip/arch/cc.h` | lwIP architecture port for bare-metal ARM |
| `bench/build_lwip.sh` | Script to compile lwIP modules |

## Historical Data

| Date | Config | smallest_tcp Flash | lwIP Flash | Ratio |
|------|--------|-------------------|------------|-------|
| 2026-03-19 | ETH+ARP+IPv4+ICMP+UDP | 2,650 B (2,460 stack) | 10,103 B | 4.1× |
| 2026-09-25 | ETH+ARP+IPv4+ICMP+UDP | 2,822 B (2,604 stack) | 10,087 B (2.2.1) | 3.9× |
| 2026-09-25 | ETH+ARP+IPv4+ICMP+UDP+TCP | 7,114 B (6,600 stack) | — | — |
| 2026-09-26 | ETH+ARP+IPv4+ICMP+UDP | 2,902 B (2,708 stack) | 10,087 B (2.2.1) | 3.7× |
| 2026-09-26 | ETH+ARP+IPv4+ICMP+UDP+TCP | 7,202 B (6,712 stack) | — | — |
| 2026-09-26 | ETH+ARP+IPv4+ICMP+UDP+mDNS/DNS-SD | 8,712 B (8,319 stack) | — | — |
| 2026-09-26 | …+TCP (retransmit fixes, no RX-ring `%`) | 6,798 B (6,886 stack) | — | — |
| 2026-09-26 | …+mDNS/DNS-SD (+NSEC) | 9,272 B (8,879 stack) | — | — |
| 2026-09-26 | …+TCP+HTTP | 11,010 B (10,738 stack) | — | — |
| 2026-09-26 | …+TCP+HTTP (TCP refactored for IPv6; IPv4-only build) | 11,014 B (10,738 stack) | — | — |
| 2026-09-26 | …+mDNS/DNS-SD (family-aware writer for IPv6; IPv4-only build) | 9,292 B | — | — |
| 2026-09-26 | ETH+ARP+IPv4+ICMP+UDP, dual stack (+IPv6, ICMPv6, ND, SLAAC, MLD) | 8,021 B | — | — |
| 2026-09-26 | …+TCP (in-order delivery: overlaps trimmed, segments after a gap dropped) | 6,814 B (6,902 stack) | — | — |
| 2026-09-26 | …+TCP+HTTP (same) | 11,030 B (10,754 stack) | — | — |
| 2026-09-26 | TLS 1.3 protocol, `tls.c` alone (client + server) | 10,323 B | — | — |
| 2026-09-27 | ETH+ARP+IPv4+ICMP+UDP (no static state, IPv4 ID 0) | 2,574 B (2,476 stack) | 10,087 B (2.2.1) | 4.1× |
| 2026-09-27 | …+TCP (application-owned connection table) | 6,130 B (6,288 stack) | — | — |
| 2026-09-27 | …+mDNS/DNS-SD | 8,956 B (8,555 stack) | — | — |
| 2026-09-27 | …+TCP+HTTP (transport interface) | 10,510 B (10,302 stack) | — | — |
| 2026-09-27 | ETH+ARP+IPv4+ICMP+UDP, dual stack | 7,549 B (7,441 stack) | — | — |
| 2026-09-27 | TLS 1.3 protocol, split by role: server only / client and server | 7,023 B / 10,503 B | — | — |

> The UDP-only growth from 2026-03-19 to 2026-09-26 came from `net_poll()`
> (Milestone 7), the peek-based UDP dispatch, IPv4 Protocol Unreachable, and
> (Milestone 10, +80 B) splitting `udp_send()` into a copy plus
> `udp_send_inplace()` with a per-packet TTL, which lets mDNS build responses in
> the TX buffer without a second buffer.  The 2026-09-27 refactoring removed the
> stack's last static variables and reduced every configuration.  Multicast
> receive compiles away when `NET_MAX_MCAST_GROUPS` is 0.  The ratio column
> compares stack-only code.

## Notes

- lwIP sizes are .o file totals (before link-time gc-sections). Actual linked lwIP would be somewhat smaller depending on which functions the application calls.  They were measured with lwIP 2.2.1 and the toolchain below, and were not re-measured on 2026-09-27.
- smallest_tcp sizes are from a linked ELF with `--gc-sections`, representing real deployed size.
- Both use nano newlib for memcpy/memset (not counted — same for both).
- Flash totals depend on the toolchain's newlib. The figures here use the Arm GNU Toolchain
  13.2.Rel1, whose `memcpy`/`memset`/`memcmp` total 62 B. Ubuntu's `libnewlib-arm-none-eabi`
  (used by the `arm-size` CI job) ships larger, speed-optimized versions, so the ELF totals CI
  reports are a few hundred bytes higher.  Stack-only code is identical on both toolchains.
- lwIP has more features even in minimal config (e.g., ARP queueing infrastructure, pbuf chaining, multi-netif support). smallest_tcp intentionally omits these for size.
