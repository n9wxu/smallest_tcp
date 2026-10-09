# 🚀 smallest_tcp

**A portable, zero-allocation TCP/IP stack that runs everywhere — from $0.20 microcontrollers to Linux and macOS.**

[![CI — Build & Unit Tests](https://github.com/n9wxu/smallest_tcp/actions/workflows/ci.yml/badge.svg)](https://github.com/n9wxu/smallest_tcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/n9wxu/smallest_tcp)](https://github.com/n9wxu/smallest_tcp/releases/latest)

---

## ✨ What Is This?

**smallest_tcp** is a ground-up TCP/IP network stack written in portable C99.  It's designed for one audacious goal: give *any* device with a MAC interface a full networking capability — IPv4 and IPv6, TCP, UDP, DHCP, TFTP, mDNS + DNS-SD, HTTP, TLS 1.3 — using **zero dynamic memory allocation** and fitting in as little as **4.1 KB of flash**.

Whether you're building a TCP/IP bootloader on a chip with 1 KB of RAM, adding network connectivity to a $0.20 RISC-V MCU, or prototyping protocol logic on your laptop — this stack has you covered.

### 🎯 Design Principles

| Principle | How We Do It |
|---|---|
| **Zero `malloc()`** | Your application owns all memory — frame buffers, `net_t`, connections, module state. The stack never allocates and has no static variables of its own. |
| **Parse and build in place** | A received frame is copied once, from the MAC driver into your receive buffer, and parsed where it lies; replies are built in place in your transmit buffer. |
| **Link what you need** | The transport layer (UDP, TCP, IPv6) is selected at compile time with CMake options or `NET_USE_*`; the application protocols (DHCP, TFTP, mDNS, HTTP, TLS) are separate libraries composed at link time.  See [configuration.md §5](docs/design/configuration.md#5-compile-time-protocol-selection). |
| **Portable C99** | No compiler extensions, no `__attribute__((packed))`, no run-time division. Built in CI with GCC (Linux), Clang (macOS) and `arm-none-eabi-gcc` (Cortex-M0), and written to stay portable to 8-bit targets ([coding-rules.md](docs/design/coding-rules.md)). |
| **Abstract MAC interface** | Plug in any hardware through a six-function vtable — TAP and raw sockets (Linux), BPF (macOS), or your own driver for an ENC28J60, a CDC-ECM USB device, anything. |
| **Compile-time configuration** | Protocols and table sizes are `#define`s in `net_config.h` (or your own configuration header); buffer sizes come from the buffers you pass in. |

---

## 📊 How Small Is It?

Measured on ARM Cortex-M0 (`-Os -mthumb`, `arm-none-eabi-gcc` 13.2), UDP echo server (ETH + ARP + IPv4 + ICMP + UDP), vs lwIP 2.2.1:

| Metric | smallest_tcp | lwIP (same features) | Ratio |
|---|---|---|---|
| **Flash** | **4,110 B** | 10,089 B | **2.5× smaller** |
| **RAM** | **720 B** (600 = app buffers) | 2,619 B | **3.6× smaller** |
| Stack-only code (objects) | **4,882 B** | 10,087 B | **2.1× smaller** |
| Stack-internal state | **0 B** | ~2,619 B | — |

The stack itself has **no static state**: everything it keeps lives in `net_t` and in structures your application declares and sizes.  The object total includes IPv4 reassembly (about 800 B), which lwIP's build has switched off and which is linked only when the application gives it a buffer.

| Configuration (`make` target) | Flash (.text) | RAM |
|---|---:|---:|
| UDP echo (`arm-size`) | 4,110 B | 720 B |
| UDP + TCP echo (`arm-size-tcp`) | 8,932 B | 1,116 B |
| UDP + mDNS/DNS-SD responder (`arm-size-mdns`) | 14,156 B | 832 B |
| UDP + HTTP server, with TCP (`arm-size-http`) | 15,310 B | 1,760 B |
| UDP echo, dual stack IPv4 + IPv6 with ICMPv6, ND, SLAAC, MLD (`arm-size-ipv6`) | 9,497 B | 832 B |
| UDP echo, IPv6 only: no ARP, IPv4 or ICMP (`arm-size-ipv6-only`) | 6,465 B | 760 B |
| TLS 1.3 protocol, server only (`arm-size-tls`) | 7,476 B | 448 B per connection + record buffers |
| TLS 1.3 protocol, client and server (`arm-size-tls`) | 11,088 B | 448 B per connection + record buffers |
| DTLS 1.3 protocol, server only (`arm-size-dtls`) | 11,271 B | 904 B per connection + buffers |
| DTLS 1.3 protocol, client and server (`arm-size-dtls`) | 15,071 B | 904 B per connection + buffers |

RAM is `.data` + `.bss` of the whole benchmark, all of it application-owned.  TLS and DTLS take their cryptography from a backend you choose (Mbed TLS is bundled), which is not included in these figures; they share the handshake, so a device with both links 17.6 KB, not two handshakes.

> 📐 See [docs/design/size-comparison.md](docs/design/size-comparison.md) for the full comparison methodology, per-module breakdowns, and analysis.

---

## 📊 What's Implemented

### ✅ Verification

Every requirement is a numbered row traced to its RFC section
([docs/requirements/](docs/requirements/)), and the tests name the rows
they verify.  Two measures, produced by CI on every push, say how far the
tests reach ([test-plan.md §0](docs/test-plan.md#0-policy-and-the-integration-tests)):

| Measure | Snapshot | Produced by |
|---|---|---|
| **Requirements coverage** — MUST rows verified by a test | 967 of 1008 by a test, 966 of them by a black-box test (through the API or on the wire); of the other 41, 11 state what no test can observe and 30 belong to what is not implemented (28 of them the DNS resolver's); none is left without a test or the reason there is none | `python3 scripts/trace.py` (CI job `traceability`, which fails if one is) |
| **Code coverage** — `src/` reached by the black-box integration tests alone | 97.0 % of lines, 87.9 % of branches | gcovr on a `-DSMALLEST_TCP_COVERAGE=ON` build after `ctest -L integration` (CI job `coverage`) |

The figures are a snapshot; the test plan has the tables per requirement
document and per source file, and the commands that regenerate them.

Everything compiles with `-Wall -Wextra -Werror -pedantic`.  CI runs the unit and integration tests on Linux and macOS, in dual-stack, IPv4-only and IPv6-only builds, and checks that a configuration which cannot work refuses to build.  The blackbox conformance suites (ARP, IPv4, ICMPv4, UDP, TCP, DHCPv4, mDNS/DNS-SD, HTTP, IPv6, TLS server and client, HTTPS, DTLS server and client) run the demos on a live link — on every push on Linux, over both the TAP and the raw-socket driver, and by hand on macOS (feth) — with interop checks against Avahi (over IPv4 and IPv6), macOS (discover the device, browse to `http://pyro-dead01.local/`), dnsmasq (DHCPv6), OpenSSL, Python ssl and curl (TLS 1.3), and wolfSSL (DTLS 1.3).  A TCP fuzz suite runs nightly.

### 🧩 Components

| Component | File(s) | Requirements | Description |
|---|---|---|---|
| Core context | `net.h` / `net.c` / `net_version.h` | — | `net_init()`, `net_poll()`, `net_tick()`, `net_transmit()`, random numbers (HalfSipHash-2-4 under a secret key, seeded with any number of bytes), defaults from `net_config.h`, the version |
| Byte order | `net_endian.h` | — | Portable wire read/write + host/network conversion |
| Checksum | `net_cksum.h` / `net_cksum.c` | [checksum](docs/requirements/checksum.md) | RFC 1071 Internet checksum — incremental (pieces of any length), one-shot, verify |
| Ethernet | `eth.h` / `eth.c` | [ethernet](docs/requirements/ethernet.md) | Ethernet II parse/build, protocol dispatch; our own frames looped back dropped |
| ARP | `arp.h` / `arp.c` | [arp](docs/requirements/arp.md) | Requests for our address answered, gateway MAC learning (expiring after 5 minutes), next-hop choice, requests rate-limited; no cache |
| IPv4 | `ipv4.h` / `ipv4.c` | [ipv4](docs/requirements/ipv4.md) | Parse/build/send, protocol dispatch, every broadcast form of our network, sources that name no host refused, source routes dropped, reassembly in an application buffer, the MTU (`net_t.mtu`, MMS_S/MMS_R), ICMP Protocol Unreachable |
| ICMPv4 | `icmp.h` / `icmp.c` | [icmpv4](docs/requirements/icmpv4.md) | Echo reply (ping, truncated to fit), destination unreachable, Time Exceeded on reassembly timeout, errors received passed to UDP and TCP, checksum validation |
| UDP | `udp.h` / `udp.c` | [udp](docs/requirements/udp.md) | Parse/send (the MTU at most), port table dispatch, pseudo-header checksum, ICMP Port Unreachable; the destination address and ICMP and ICMPv6 errors to the application, TTL and TOS per datagram |
| **TCP** | **`tcp.h` / `tcp.c`** | [tcp](docs/requirements/tcp.md) | **Full state machine, retransmit (data + FIN; R1 reported, R2 per connection), MSS (and Path MTU from ICMP), window updates, persist timer, in-order delivery, close with the FIN queued behind unsent data — and in every state, a listener that outlives a failed handshake, RFC 6528 initial sequence numbers, ICMP soft and hard errors, TOS; application-owned connection table** |
| TCP buffer | `tcp_buf.h` / `tcp_buf_saw.c` | [tcp](docs/requirements/tcp.md) | Stop-and-wait TX + RX buffers |
| **DHCPv4** | **`dhcpv4_client.h/.c`** `dhcpv4_server.h/.c` | [dhcpv4](docs/requirements/dhcpv4.md) | **RFC 2131 client state machine (DISCOVER→OFFER→REQUEST→ACK/NAK), the offered address probed with ARP and declined if in use, options in `file`/`sname` and split options joined; minimal server for one client; option callback API** |
| TFTP | `tftp.h` / `tftp.c` | [tftp](docs/requirements/tftp.md) | RFC 1350 TFTP client — block-read, octet and netascii, blksize option, adaptive retransmission timeout, error handling |
| Multicast + IGMP | `ipv4.c` / `igmp.h` / `igmp.c` | [igmp](docs/requirements/igmp.md) | Fixed-size group table (224.0.0.1 always joined), multicast RX, per-packet TTL, IGMPv2 host: join/leave, queries answered, IGMPv1 routers (RFC 1112, 2236) |
| DNS wire format | `dns_wire.h` / `dns_wire.c` | [mdns](docs/requirements/mdns.md) | RFC 1035 names with compression, bounds-checked readers |
| **mDNS + DNS-SD** | **`mdns.h` / `mdns.c`** | [mdns](docs/requirements/mdns.md), [dns-sd](docs/requirements/dns-sd.md) | **RFC 6762 responder: probe, announce, answer (A/AAAA/PTR/SRV/TXT + DNS-SD additionals), NSEC negative answers, known-answer suppression (truncated queries too), conflict rename, goodbye, withdrawing a service while the rest stay; RFC 6763 service advertising; dual stack: ff02::fb, AAAA for every usable IPv6 address, answers on the query's family** |
| **HTTP server** | **`http.h` / `http.c`** `http_tls.h/.c` | [http](docs/requirements/http.md) | **HTTP/1.0: GET/HEAD/POST route table, streamed responses of any length, 400/404/405/412/413/414/417/421/431/501/505, Date, conditional requests, `Expect: 100-continue`, connection slots recycled at once, timeouts; over IPv4 and IPv6; plain TCP or TLS 1.3 through a transport interface** |
| **IPv6** | **`ipv6.h/.c`** `icmpv6.h/.c` `ndp.h/.c` `mld.h/.c` `udp.c` `tcp.c` | [ipv6](docs/requirements/ipv6.md), [icmpv6](docs/requirements/icmpv6.md), [ndp](docs/requirements/ndp.md), [slaac](docs/requirements/slaac.md) | **RFC 8200 header + extension-header walk, EUI-64 link-local, ICMPv6 echo, errors sent under a rate limit and errors received passed to UDP and TCP, Neighbor Solicitation/Advertisement responder, Duplicate Address Detection, UDP and TCP over IPv6 (dual-stack listeners), router discovery + SLAAC (global address, default router, lifetimes), MLDv2 with MLDv1 fallback + `ipv6_mcast_join()`; dual stack via `NET_USE_IPV6`, or IPv6 alone with `NET_USE_IPV4` 0** |
| **DHCPv6** | **`dhcpv6_client.h/.c`** | [dhcpv6](docs/requirements/dhcpv6.md) | **RFC 8415 client: stateless (Information-Request → DNS) and stateful (Solicit/Advertise/Request/Reply, Renew at T1, Rebind at T2, expiry, Release), DUID-LL, §15 retransmission with jitter, option handler table; started by the RA's M / O flags** |
| **TLS 1.3** | **`tls.h`** `tls_common.c` `tls.c` `tls_keys.h/.c` `tls_server.c` `tls_client.c` `tls_tcp.h/.c` `tls_crypto.h` `tls_crypto_mbedtls.h/.c` | [tls](docs/requirements/tls.md) | **RFC 8446 client and server over the stack's TCP: `TLS_AES_128_GCM_SHA256`, x25519 / secp256r1 (HelloRetryRequest both ways), ECDSA P-256 and RSA-PSS certificates (chain + name + CertificateVerify checks), pre-shared keys (psk_dhe_ke, psk_ke) with binders, max_fragment_length for small buffers, KeyUpdate, close_notify; key schedule and records verified against RFC 8448; each role in its own file, so a server-only build does not link the client; all cryptography through a `tls_crypto_t` vtable (Mbed TLS 3.6 backend bundled); HTTPS demo** |
| **DTLS 1.3** | **`dtls.h`** `dtls.c`, with TLS's `tls_common.c` `tls_keys.c` `tls_server.c` `tls_client.c` | [dtls](docs/requirements/dtls.md) | **RFC 9147 client and server on TLS 1.3's handshake, key schedule and crypto backend: DTLSPlaintext and the unified header, record number encryption, a replay window per epoch, flights with fragmentation to the MTU and reassembly of overlapping fragments, a retransmission timer (1 s doubling to 60 s), ACKs, KeyUpdate taking effect once acknowledged, the server's cookie exchange; invalid records dropped silently; the application moves datagrams (`dtls_input()` / `dtls_pending()`); `TLS_USE_DTLS` 0 compiles it out of the handshake** |
| MAC: TAP | `driver/tap.c` | — | Linux TAP driver |
| MAC: raw socket | `driver/rawsock.c` | — | Linux `AF_PACKET` driver on an existing interface — a real NIC or a veth end, no `/dev/net/tun`; finishes offloaded checksums |
| MAC: BPF | `driver/bpf.c` | — | macOS BPF driver (feth pair) |
| MAC: STM32F4 Ethernet | `driver/stm32f4_eth.c` | — | The STM32F4's ETH MAC and DMA over RMII; with the NUCLEO-F429ZI board port (`boards/nucleo-f429zi`), the firmware of the hardware fuzz job.  Built in CI; not run on hardware |
| MAC: Stub | `driver/stub.c` | — | No-op driver for cross-compilation / size measurement |
| Build | `CMakeLists.txt`, `Makefile` | — | CMake: libraries, tests, demos, FetchContent integration.  Makefile: Cortex-M0 size benchmarks and the no-division check |
| CI | `.github/workflows/ci.yml` | — | Linux + macOS CMake builds with the unit and integration tests, IPv4-only and IPv6-only builds, requirements traceability and code coverage, the blackbox suites over TAP and raw socket (DTLS against a pinned wolfSSL), the ARM size benchmark, the board firmware and the release check on every push |
| Releases | `.github/workflows/release.yml`, `scripts/release.py`, `CHANGELOG.md` | — | Every push to `main` that passes CI is released as the next version: CI commits it, tags it and publishes it ([release-process.md](docs/release-process.md)) |
| Fuzz (nightly) | `.github/workflows/fuzz.yml` | — | TCP adversarial fuzz + full conformance regression nightly |

### 🔜 Roadmap

What is not implemented.  The design documents say what the stack does
instead, and [tcpip-stack-plan.md](tcpip-stack-plan.md) has the whole list.

| Area | Not implemented |
|---|---|
| **DNS** | The stub resolver ([requirements](docs/requirements/dns.md) written; `dns_wire.c` is the wire format it will share with mDNS); an mDNS querier / DNS-SD browser |
| **TCP** | Congestion control (RFC 5681), delayed ACK and Nagle, window scale / timestamps / SACK (RFC 7323), keep-alive; buffer implementations beyond stop-and-wait (a ring and a packet list are designed in [tcp-buffer.md](docs/design/tcp-buffer.md)) |
| **Hardware** | The STM32F4 port run on a board, and the hardware fuzz job with it; drivers for an ENC28J60 (SPI) or a USB CDC-ECM link; checksum offload |
| **Timers** | Tickless operation (`net_next_event_ms()`): the device wakes at its tick period ([timer-model.md](docs/design/timer-model.md)) |
| **IPv6** | Fragment reassembly, a neighbour cache with unreachability detection, Redirects ([ipv6.md §13](docs/design/ipv6.md#13-deviations-and-limitations)) |
| **HTTP** | Persistent connections, chunked transfer coding |
| **TLS / DTLS** | ChaCha20-Poly1305, client certificates, session tickets and 0-RTT, DTLS connection IDs |
| **TFTP** | Write requests; the tsize, timeout and windowsize options; TFTP over IPv6 |
| **Tests** | Fuzz suites beyond TCP ([test-plan.md §5](docs/test-plan.md#5-open-items--known-gaps)) |

### 📐 Target Platforms

| Chip | Flash | RAM | Cost | smallest_tcp | lwIP UDP |
|---|---|---|---|---|---|
| PIC16F1454 | 14 KB | 1 KB | ~$1.20 | ✅ UDP: 4.1 KB + buffers | ❌ 10 KB code alone |
| CH32X033 | 62 KB | 20 KB | ~$0.20 | ✅ Plenty of room | ✅ Fits |
| STM32F042 | 32 KB | 6 KB | ~$1.00 | ✅ Room for TCP (8.9 KB), mDNS (14.2 KB), HTTP (15.3 KB), dual-stack UDP (9.5 KB) or IPv6-only UDP (6.5 KB) | ⚠️ Tight with app |
| CH32V203 | 256 KB | 10 KB | ~$0.50 | ✅ Plenty of room | ✅ Fits |
| Linux / macOS | ∞ | ∞ | — | ✅ Dev & testing | ✅ Dev & testing |

---

## 🔧 Building

### CMake (the host build)

CMake builds the libraries, the unit and integration tests and the demos:

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

| Option | Default | Effect |
|---|---|---|
| `SMALLEST_TCP_BUILD_TESTS` | ON at top level, OFF when cross-compiling | Unit and integration tests (`ctest`) |
| `SMALLEST_TCP_BUILD_DEMO` | ON at top level, OFF when cross-compiling | Demo applications |
| `SMALLEST_TCP_BUILD_DRIVERS` | ON at top level | Platform MAC drivers (TAP and raw socket on Linux, BPF on macOS) |
| `SMALLEST_TCP_IPV4` | ON | IPv4, ARP, ICMP in the core (`NET_USE_IPV4`), and the libraries that run only over IPv4 (DHCPv4, TFTP); OFF for IPv6 only |
| `SMALLEST_TCP_IPV6` | ON | Dual stack: IPv6, ICMPv6, NDP, MLD in the core (`NET_USE_IPV6`); OFF for IPv4 only |
| `SMALLEST_TCP_UDP` | ON | UDP in the core (`NET_USE_UDP`) and the libraries over it |
| `SMALLEST_TCP_TCP` | ON | TCP in the core (`NET_USE_TCP`) and the libraries over it |
| `SMALLEST_TCP_TLS` | ON at top level, OFF when cross-compiling | The Mbed TLS crypto backend, the TLS and DTLS demos and tests; CMake downloads Mbed TLS 3.6.7 (pinned by SHA-256) |
| `SMALLEST_TCP_DTLS` | ON | DTLS 1.3 (`dtls.c`) as well as TLS, sharing the handshake (`TLS_USE_DTLS`); OFF builds the handshake for TLS alone |
| `SMALLEST_TCP_DEBUG` | OFF | `NET_LOG()` output to `stderr` (`NET_DEBUG=1`) |
| `SMALLEST_TCP_COVERAGE` | OFF | Instruments the stack and the tests for gcov line and branch coverage ([test-plan.md §0](docs/test-plan.md#code-coverage)) |
| `SMALLEST_TCP_BOARD` | empty | With a cross toolchain, a board port's firmware: `nucleo-f429zi` builds `tcp_echo_demo.elf` ([test-plan.md §4](docs/test-plan.md#4-hardware-test-fixture-recommended)) |
| `SMALLEST_TCP_CONFIG_FILE` | empty | Your configuration header, included first by `net_config.h` (`NET_CONFIG_FILE`) |

"At top level" means ON when smallest_tcp is the top-level project and OFF when it is pulled in with FetchContent.  With UDP or TCP off, the tests and demos (which use the whole stack) are not built; with IPv4 off, only the suites and demos that need no IPv4 are (`tcp_echo_demo`, `tls_echo_demo`, `frame_dump`).  The protocol options are `PUBLIC` compile definitions of the core, so everything linked against it is compiled with the same `net_t` layout ([configuration.md §3](docs/design/configuration.md#3-library-and-application-must-agree)).

**Cross-compiling the libraries** for a Cortex-M: `cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=cmake/arm-none-eabi.cmake` (GNU Arm toolchain; Cortex-M4 unless `-DSMALLEST_TCP_ARM_CPU=` names another core).  The tests and demos are hosted programs and stay off, and so does the bundled Mbed TLS backend (`SMALLEST_TCP_TLS`), whose configuration needs a platform entropy source a bare-metal target does not have; the TLS protocol library itself is built.

**CMake output directory layout** — binaries mirror the source tree:

| What | Path after `cmake --build build` |
|---|---|
| Unit and integration tests | `build/tests/test_tcp`, `build/tests/itest_tcp`, … |
| Demo binaries | `build/demo/tcp_echo_demo`, `build/demo/frame_dump`, `build/demo/https_demo`, … |

> ⚠️ **Do not** use `build/tcp_echo_demo` — that path does not exist.
> Always use `build/demo/tcp_echo_demo`.  Getting this wrong is the most
> common cause of blackbox test failures (all tests ERROR with
> `ARP timeout: no reply from 10.0.0.2`).

### Demos

| Demo | What it does |
|---|---|
| `frame_dump` | Hex dump of every frame received (and the stack's answers to ARP and ping) |
| `echo_server` | The smallest demo: UDP echo on port 7, and ping |
| `tcp_echo_demo` | TCP and UDP echo on port 7, over IPv6 too (DHCPv6 when a Router Advertisement asks for it); the SUT of most blackbox suites |
| `tftp_client_demo` | Fetch one file from a TFTP server |
| `dhcp_echo_demo` | `tcp_echo_demo` with its IPv4 address from DHCP |
| `mdns_demo` | Advertises `pyro-dead01.local` and a DNS-SD service over mDNS |
| `http_demo` | HTTP server with a status page, JSON API and POST echo, advertised over mDNS as `http://pyro-dead01.local/` |
| `tls_echo_demo` | TLS 1.3 echo server on port 4433 (with `SMALLEST_TCP_TLS`) |
| `https_demo` | The HTTP server over TLS 1.3 on port 443 (with `SMALLEST_TCP_TLS`) |
| `tls_client_demo` | TLS 1.3 client: connects, sends a message, prints the reply (with `SMALLEST_TCP_TLS`) |
| `dtls_echo_demo` | DTLS 1.3 echo server on UDP port 4433, a connection per peer (with `SMALLEST_TCP_TLS` and `SMALLEST_TCP_DTLS`) |
| `dtls_client_demo` | DTLS 1.3 client: connects, sends a message in datagrams, checks the echo (the same) |

Each takes its interface as the first argument: on Linux a TAP device (default `tap0`) or `raw:<ifname>` for the raw-socket driver; on macOS a BPF-attached interface (default `feth1`).

### ARM Size Measurement (Makefile)

The `Makefile` builds no host code; it cross-compiles the size benchmark (`bench/size_measure.c`) with `arm-none-eabi-gcc -Os -mthumb -mcpu=cortex-m0` into `build/arm/`:

```bash
make arm-size             # UDP echo (ETH + ARP + IPv4 + ICMP + UDP) — the lwIP comparison
make arm-size-tcp         # UDP + TCP echo
make arm-size-mdns        # UDP + mDNS/DNS-SD responder
make arm-size-http        # UDP + HTTP server (with TCP)
make arm-size-ipv6        # UDP echo, dual stack
make arm-size-ipv6-only   # UDP echo, IPv6 alone (NET_USE_IPV4=0)
make arm-size-tls         # TLS 1.3 protocol: server only, then client and server
make arm-size-dtls        # DTLS 1.3 protocol: the same
make arm-size-all         # all of the above, then arm-check-division and arm-check-links
make arm-check-division   # fail if any ARM object calls __aeabi_uidiv or another library divide
make arm-check-links      # fail if TLS's objects need dtls.c, or DTLS's tls.c
bash bench/build_lwip.sh  # Build lwIP 2.2.1 for comparison (fetched on first run)
```

Requires `arm-none-eabi-gcc` (install via Arm GNU Toolchain or `brew install --cask gcc-arm-embedded`).  CI runs `make arm-size-all`.

### Running Blackbox Conformance Tests (Linux)

The conformance suites run against the live demos over a Linux
TAP interface, or over a veth pair with the raw-socket driver
([Option E](#option-e--any-suite-over-the-raw-socket-driver-no-tun)).  The
core suites (ARP, IPv4, ICMPv4, UDP, TCP) run against `tcp_echo_demo`; the
DHCPv4, mDNS, HTTP, IPv6, TLS, HTTPS and DTLS suites start their own SUTs.
Requires `sudo` / `CAP_NET_RAW`.

#### Option A — `run_blackbox.sh` (the core suites)

```bash
# 1. Build
cmake -S . -B build && cmake --build build --target tcp_echo_demo

# 2. Install Python deps once
pip install -r tests/blackbox/requirements.txt

# 3. Run ARP, IPv4, ICMP, UDP and TCP — sets up TAP, starts SUT, runs the suites, tears down
sudo tests/blackbox/run_blackbox.sh \
    --sut-bin ./build/demo/tcp_echo_demo \
    --setup-tap --teardown-tap -v
```

`run_blackbox.sh` creates `tap0`, starts the SUT, runs each suite in order,
prints a `✓ / ✗` summary, and cleans up — even if a suite fails.  `--dhcp`
adds the DHCPv4 suite, `--fuzz` the fuzz tests.

#### Option B — Run a single suite manually

```bash
# 1. Build
cmake -S . -B build && cmake --build build --target tcp_echo_demo

# 2. Set up TAP and iptables
sudo ip tuntap add dev tap0 mode tap user $(whoami)
sudo ip link set tap0 up
sudo ip addr add 10.0.0.100/24 dev tap0
# Scope the iptables rule to tap0 only.
# The kernel sees the SUT's SYN-ACKs (10.0.0.100 is assigned to tap0)
# and auto-RSTs them. Scoped drop prevents this while leaving other
# interfaces unaffected.
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -o tap0 -j DROP

# 3. Start the SUT
sudo ./build/demo/tcp_echo_demo &

# 4. Run one suite (replace test_tcp_conform.py with any suite name)
pip install -r tests/blackbox/requirements.txt
sudo python3 -m pytest tests/blackbox/test_tcp_conform.py \
    --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 --sut-port 7 -v

# 5. Cleanup when done
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -o tap0 -j DROP
sudo ip tuntap del dev tap0 mode tap
```

#### Option C — mDNS + DNS-SD suite

The mDNS tests start a fresh `mdns_demo` for every test (probing, announcing and
goodbye happen at start-up and shutdown), so do not start a SUT yourself:

```bash
cmake --build build --target mdns_demo
sudo python3 -m pytest tests/blackbox/test_mdns_conform.py \
    --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 \
    --mdns-sut-bin ./build/demo/mdns_demo -v

# Interop with Avahi (needs avahi-daemon on tap0: allow-interfaces=tap0)
sudo tests/blackbox/mdns_interop.sh ./build/demo/mdns_demo
```

#### Option D — HTTP server suite

The HTTP tests start `http_demo` themselves; the client is the host's own TCP
stack, so do **not** add the RST-drop iptables rule from Option B:

```bash
cmake --build build --target http_demo
sudo python3 -m pytest tests/blackbox/test_http_conform.py \
    --iface tap0 --sut-ip 10.0.0.2 --http-sut-bin ./build/demo/http_demo -v

# Browse by name (Avahi on tap0 + libnss-mdns): curl http://pyro-dead01.local/
sudo tests/blackbox/http_interop.sh ./build/demo/http_demo
```

#### Option D2 — TLS 1.3 and HTTPS suites

The TLS tests start their SUTs themselves (`tls_echo_demo` on port 4433,
`https_demo` on 443, `tls_client_demo` per test, which connects to servers the
tests run on `--our-ip`); the peers are Python ssl, openssl and curl.  No
RST-drop rule:

```bash
cmake --build build --target tls_echo_demo tls_client_demo https_demo
sudo python3 -m pytest tests/blackbox/test_tls_conform.py \
    tests/blackbox/test_tls_client_conform.py tests/blackbox/test_https_conform.py \
    --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 \
    --tls-sut-bin ./build/demo/tls_echo_demo \
    --tls-client-bin ./build/demo/tls_client_demo \
    --https-sut-bin ./build/demo/https_demo -v

# By hand:
sudo ./build/demo/https_demo &
curl --cacert tests/tls/ca.pem https://10.0.0.2/
```

The certificates and keys in `tests/tls` are for testing only.

#### Option D3 — DTLS 1.3 suites

The peer is wolfSSL — OpenSSL and Mbed TLS have no DTLS 1.3 —
built from its pinned release by `tests/blackbox/build_wolfssl.sh`, which
prints the paths of its example client and server.  The server suite starts
`dtls_echo_demo` (UDP port 4433) itself; the client suite runs
`dtls_client_demo` per test against wolfSSL's server on `--our-ip`:

```bash
eval "$(tests/blackbox/build_wolfssl.sh build/wolfssl)"  # WOLFSSL_CLIENT, WOLFSSL_SERVER
cmake --build build --target dtls_echo_demo dtls_client_demo
sudo python3 -m pytest tests/blackbox/test_dtls_conform.py \
    tests/blackbox/test_dtls_client_conform.py \
    --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 \
    --dtls-sut-bin ./build/demo/dtls_echo_demo \
    --dtls-client-bin ./build/demo/dtls_client_demo \
    --wolfssl-client "$WOLFSSL_CLIENT" --wolfssl-server "$WOLFSSL_SERVER" -v

# By hand (in wolfSSL's source tree, which its examples insist on):
sudo ./build/demo/dtls_echo_demo &
./examples/client/client -u -v 4 -h 10.0.0.2 -p 4433 -A <repo>/tests/tls/ca.pem -x
```

#### Option E — any suite over the raw-socket driver (no TUN)

Every demo takes its interface as the first argument: `tap0` (the default) or
`raw:<ifname>` for the raw-socket (`AF_PACKET`) driver, which needs no
`/dev/net/tun`.  For the tests a veth pair stands in for the wire;
`tests/blackbox/sut_net.sh` builds it (or the TAP link) and prints the names
to use — the harness end and the demo's argument:

```bash
eval "$(sudo tests/blackbox/sut_net.sh up raw --rst-drop)"  # TEST_IF=veth-test SUT_IF=raw:veth-sut
sudo tests/blackbox/run_blackbox.sh --sut-bin ./build/demo/tcp_echo_demo \
    --iface "$TEST_IF" --sut-iface "$SUT_IF"
sudo tests/blackbox/sut_net.sh down raw
```

The suites that launch their own SUT (DHCPv4, mDNS, HTTP, TLS, DTLS) take
`--sut-iface "$SUT_IF"`; the interop scripts take it as a second argument.  Leave
out `--rst-drop` for the HTTP suite, as in Option D.  On a real network:
`sudo ./build/demo/http_demo raw:eth0` — the driver keeps the interface in
promiscuous mode while it runs, since the stack uses its own MAC address.

#### Option F — IPv6 suite

The CMake build is dual stack (`-DSMALLEST_TCP_IPV6=OFF` for IPv4 only,
`-DSMALLEST_TCP_IPV4=OFF` for IPv6 only; the suite runs against either).  The
IPv6 tests launch a fresh `tcp_echo_demo` per test — Duplicate Address
Detection at start-up is under test — so do not start a SUT yourself:

```bash
sudo python3 -m pytest tests/blackbox/test_ipv6_conform.py \
    --iface tap0 --ipv6-sut-bin ./build/demo/tcp_echo_demo -v
# The demo's link-local address is fe80::ff:fede:ad01 (EUI-64 of its MAC):
ping -6 fe80::ff:fede:ad01%tap0
```

> ⚠️ If every test reports `ERROR: ARP timeout: no reply from 10.0.0.2`,
> the SUT is not running.  The most common cause is a wrong binary path —
> see [Test Plan §6 Troubleshooting](docs/test-plan.md#6-troubleshooting--known-pitfalls).

### Running Blackbox Conformance Tests (macOS)

The same suites run on macOS over a `feth` pair: the tests use `feth0`, the demos
open `feth1` through BPF.  Every suite runs, with the `dns-sd` and browse-by-name interop checks; the tests that need Linux or host IPv6 set-up skip.  The DTLS suites need wolfSSL built by `tests/blackbox/build_wolfssl.sh` (found in `build/wolfssl`, else skipped); the TLS suites need Homebrew's `openssl` first in `PATH` (not the system LibreSSL) and Python ≥ 3.13 for the PSK tests, and their IPv6 test is Linux-only; the IPv6 suite's host ping, UDP and TCP checks need `sudo ifconfig feth0 inet6 -ifdisabled`, and reaching the SLAAC address from the host is Linux-only.

```bash
# Once per boot (root): create the pair.  10.0.0.100, the tests' source
# address, stays off the Mac, so no firewall rule is needed.
sudo ifconfig feth0 create && sudo ifconfig feth1 create
sudo ifconfig feth0 peer feth1
sudo ifconfig feth0 inet 10.0.0.1/24 up && sudo ifconfig feth1 up

# Once: Python deps in a venv (Homebrew Python refuses global pip installs)
python3 -m venv .venv && .venv/bin/pip install -r tests/blackbox/requirements.txt

# Build and run everything (ARP … TCP, DHCPv4, mDNS, HTTP, TLS, interop checks)
cmake -S . -B build && cmake --build build
tests/blackbox/run_blackbox_macos.sh build
```

Without `sudo`, the demos and Scapy need BPF access — Wireshark's ChmodBPF
provides it via the `access_bpf` group; otherwise run the script with `sudo`.
Remove the pair with `sudo ifconfig feth0 destroy; sudo ifconfig feth1 destroy`.

---

## 📦 Using In Your Project

### A first program

A UDP echo server and one TCP connection on a bare-metal board.  The `board_*` symbols stand for your platform: a MAC driver implementing `net_mac_t`, a millisecond counter and an entropy source.

```c
#include "net.h"
#include "tcp.h"
#include "tcp_buf.h"
#include "udp.h"

/* Supplied by your board support package */
extern const net_mac_t board_mac_ops; /* your MAC driver (net_mac.h) */
extern void *board_mac_ctx;
extern uint32_t board_millis(void);
extern void board_entropy(uint8_t *buf, uint16_t len); /* a hardware RNG */

static uint8_t rx_buf[1514], tx_buf[1514]; /* one frame each way */
static net_t net;

/* UDP echo on port 7.  payload points into rx_buf: valid during the call. */
static void echo(net_t *n, uint32_t src_ip, uint16_t src_port,
                 const uint8_t *src_mac, const uint8_t *payload,
                 uint16_t payload_len) {
  udp_send(n, src_ip, src_mac, 7, src_port, payload, payload_len);
}
static const udp_port_entry_t udp_ports[] = {{7, echo}};

/* One TCP connection, listening on port 80, with stop-and-wait buffers */
static uint8_t tcp_tx[536], tcp_rx[536];
static tcp_saw_tx_ctx_t tx_ctx;
static tcp_saw_rx_ctx_t rx_ctx;
static tcp_conn_t conn;
static tcp_conn_t *const tcp_table[] = {&conn};

int main(void) {
  uint8_t entropy[16];
  uint32_t last;

  if (net_init(&net, rx_buf, sizeof rx_buf, tx_buf, sizeof tx_buf, NULL,
               &board_mac_ops, board_mac_ctx) != NET_OK ||
      board_mac_ops.init(board_mac_ctx) != 0)
    return 1;
  board_entropy(entropy, sizeof entropy);
  net_random_seed(&net, entropy, sizeof entropy); /* TCP ISNs, DHCP xids */
  udp_set_ports(&net, udp_ports, 1);

  tcp_saw_tx_init(&tx_ctx, tcp_tx, sizeof tcp_tx);
  tcp_saw_rx_init(&rx_ctx, tcp_rx, sizeof tcp_rx);
  tcp_conn_init(&conn, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops, &rx_ctx,
                NULL);
  tcp_set_connections(&net, tcp_table, 1);
  tcp_listen(&conn, 80);

  last = board_millis();
  for (;;) {
    uint32_t now = board_millis();
    while (net_poll(&net) > 0) { /* receive and dispatch every frame */
    }
    if (now - last >= 10) {
      net_tick(&net, now - last); /* the stack's timers */
      last = now;
    }
    /* the application: tcp_recv(&conn, ...), tcp_send(&net, &conn, ...) */
  }
}
```

`net_init()` does not open the driver — call its `init()` yourself.  `net_poll()` reads one frame into `rx_buf`, dispatches it through the layers (ARP, ICMP and the UDP handler answer from inside the call) and releases it; `net_tick()` runs the stack's own timers.  The stack keeps no connection table of its own: `tcp_set_connections()` binds yours.  A complete TCP echo is in [tcp.md §2.3](docs/design/tcp.md#23-quick-start); adding DHCP, mDNS, TFTP, HTTP or TLS follows one recipe, in [integrating-modules.md](docs/integrating-modules.md).

### CMake FetchContent (recommended)

The easiest way to use **smallest_tcp** in your project — just three lines in your `CMakeLists.txt`:

```cmake
include(FetchContent)

FetchContent_Declare(
    smallest_tcp
    GIT_REPOSITORY https://github.com/n9wxu/smallest_tcp.git
    GIT_TAG        vX.Y.Z   # the release you choose: see CHANGELOG.md
)
FetchContent_MakeAvailable(smallest_tcp)

# Link it to your target
target_link_libraries(my_app PRIVATE smallest_tcp::smallest_tcp)
```

When included via FetchContent, smallest_tcp builds its libraries only — no tests, no demos, no drivers, no Mbed TLS (the `SMALLEST_TCP_*` options above turn any of them on).  Choose the transports before `FetchContent_MakeAvailable()`, e.g. `set(SMALLEST_TCP_IPV6 OFF)`.

> 💡 See [`examples/fetchcontent/`](examples/fetchcontent/) for a complete working example.

### Versions

Every push to `main` that passes CI is released, as the next patch version, with what changed listed in [CHANGELOG.md](CHANGELOG.md).  Versions follow [Semantic Versioning](https://semver.org/); while the version is 0.x, a minor release may change the API.  Pin a release tag (`vX.Y.Z`) rather than `main`.  The version is in `net_version.h` — `NET_VERSION_STRING`, and `NET_VERSION` (`0x00MMmmpp`) for `#if`.  How releases are made: [release-process.md](docs/release-process.md).

### Available CMake Targets

Each library is `smallest_tcp_<name>`, also available as `smallest_tcp::<name>`.

| Target | Description |
|---|---|
| `smallest_tcp::core` (alias `smallest_tcp::smallest_tcp`) | The core: net, checksum, text helpers, Ethernet; ARP, IPv4, ICMP with `SMALLEST_TCP_IPV4`; UDP with `SMALLEST_TCP_UDP`, TCP and its buffers with `SMALLEST_TCP_TCP`, IPv6/ICMPv6/NDP/MLD with `SMALLEST_TCP_IPV6` |
| `smallest_tcp::dhcpv4_client` | DHCPv4 client (with UDP) |
| `smallest_tcp::dhcpv4_server` | Minimal stateless DHCPv4 server (with UDP) |
| `smallest_tcp::tftp` | TFTP client (with UDP) |
| `smallest_tcp::mdns` | mDNS + DNS-SD responder, DNS wire helpers, IGMPv2 (with UDP) |
| `smallest_tcp::dhcpv6_client` | DHCPv6 client (with UDP and IPv6) |
| `smallest_tcp::tls` | TLS 1.3 protocol, both roles, and DTLS 1.3 with `SMALLEST_TCP_DTLS` (no dependencies — bring a `tls_crypto_t` backend) |
| `smallest_tcp::http` | HTTP/1.0 server (with TCP) |
| `smallest_tcp::tls_tcp` | A TLS connection carried over a TCP connection (with TCP) |
| `smallest_tcp::https` | The HTTP server over TLS (`http_tls.c`; with TCP) |
| `smallest_tcp::tls_mbedtls` | The `tls_crypto_t` backend on Mbed TLS 3.6 (with `SMALLEST_TCP_TLS`) |
| `smallest_tcp::driver_tap`, `::driver_rawsock` | Linux TAP and raw-socket (`AF_PACKET`) MAC drivers (with `SMALLEST_TCP_BUILD_DRIVERS`) |
| `smallest_tcp::driver_bpf` | macOS BPF MAC driver (with `SMALLEST_TCP_BUILD_DRIVERS`) |
| `smallest_tcp::driver_stm32f4_eth` | STM32F4 Ethernet MAC driver (with `SMALLEST_TCP_BUILD_DRIVERS`, cross-compiling for ARM) |

### Manual Integration

If you're not using CMake (e.g., bare-metal Makefile or IDE project):

1. Copy `src/` and `include/` into your project
2. Add `include/` to your compiler's include path
3. Choose the transports: the core (`net.c`, `net_cksum.c`, `eth.c`, `arp.c`, `ipv4.c`, `icmp.c`) dispatches to UDP and TCP unless you compile everything with `-DNET_USE_UDP=0` / `-DNET_USE_TCP=0` and leave out `udp.c` / `tcp.c` + `tcp_buf_saw.c`; `-DNET_USE_IPV6=1` adds `ipv6.c`, `icmpv6.c`, `ndp.c`, `mld.c`, and `-DNET_USE_IPV4=0` with it leaves out `arp.c`, `ipv4.c`, `icmp.c`.  Compile the library and the application with the same settings — they change `net_t` ([configuration.md](docs/design/configuration.md))
4. Add the application protocols you use (`dhcpv4_client.c`, `mdns.c` + `dns_wire.c` + `igmp.c`, `tftp.c` or `http.c` with `net_text.c`, the `tls*.c` files, …)
5. Provide your own MAC driver implementing the `net_mac_t` interface ([mac-hal.md](docs/design/mac-hal.md))

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────┐
│ Application — owns net_t, buffers, connections,      │
│ module state; drives net_poll() and net_tick()       │
├──────────────────────────────────────────────────────┤
│ Application protocols (link time):                   │
│   dhcpv4_client  dhcpv4_server  dhcpv6_client  tftp  │
│   mdns  http (+ http_tls)                            │
├──────────────────────────────────────────────────────┤
│ TLS 1.3 and DTLS 1.3 (link time): the handshake in   │
│   tls_common.c + tls_server.c / tls_client.c; TLS's  │
│   records (tls.c) over a tcp_conn_t via tls_tcp.c,   │
│   DTLS's (dtls.c) over UDP datagrams;                │
│   crypto through tls_crypto_t (Mbed TLS backend)     │
├───────────────────────────┬──────────────────────────┤
│ udp.c                     │ tcp.c + tcp_buf_saw.c    │  ← compile time
├───────────────────────────┴──────────────────────────┤
│ ipv4.c icmp.c arp.c │ ipv6.c icmpv6.c ndp.c mld.c    │  ← IPv6: compile time
├──────────────────────────────────────────────────────┤
│ eth.c                                                │
├──────────────────────────────────────────────────────┤
│ MAC driver interface (net_mac.h) — abstract vtable   │
├──────────────┬─────────────┬─────────────────────────┤
│ tap.c        │ bpf.c       │ your driver.c           │
│ rawsock.c    │ (macOS)     │ (your HW)               │
│ (Linux)      │             │                         │
└──────────────┴─────────────┴─────────────────────────┘
```

**Your application owns everything:** buffers, connection state, configuration. The stack provides the protocol logic and operates on your memory.  See [docs/architecture.md](docs/architecture.md).

---

## 📖 Documentation

Detailed design docs and RFC-traced requirements live in [`docs/`](docs/):

- **[Architecture](docs/architecture.md)** — How the stack is composed, layers, receive and transmit paths, `net_t`
- **[Integrating Protocol Modules](docs/integrating-modules.md)** — The one recipe for DHCP, TFTP, mDNS, HTTP and TLS, with a complete main loop
- **[Size Comparison](docs/design/size-comparison.md)** — ARM Cortex-M0 code size: smallest_tcp vs lwIP (2.5× less flash, 3.6× less RAM for a UDP echo)
- **Design Documents:**
  - [Coding Rules](docs/design/coding-rules.md) — C99, memory, parsing received data, no run-time division, comments
  - [MAC HAL](docs/design/mac-hal.md) — The driver interface: poll/peek/discard/send; `net_poll()` copies each frame once into the receive buffer
  - [Memory Model](docs/design/memory-model.md) — Application-owned memory, `net_t`, frame buffers, init functions
  - [Configuration](docs/design/configuration.md) — Settings, compile-time protocol selection, link-time composition
  - [Timer Model](docs/design/timer-model.md) — `net_poll()`, `net_tick()` and the module ticks; countdown timers
  - [Checksum](docs/design/checksum.md) — Incremental Internet checksum design
  - [Byte Order](docs/design/byte-order.md) — Portable endian handling, 8-bit target strategy
  - [ARP Resolution](docs/design/arp-resolution.md) — No cache: gateway MAC, reply-to-sender, application-driven resolution
  - [UDP](docs/design/udp.md) — Port tables; handlers get a pointer into the receive buffer `net_poll()` filled; checksum, ICMP port unreachable
  - [TCP](docs/design/tcp.md) — Stop-and-wait TCP: connections bound by the application, receive path, timers, events
  - [TCP Buffer](docs/design/tcp-buffer.md) — The buffer interface and the stop-and-wait implementation
  - [IPv6](docs/design/ipv6.md) — Dual stack: ICMPv6, neighbor discovery, SLAAC, MLD, DHCPv6
  - [DHCPv4](docs/design/dhcpv4.md) — Client + server design, option handler callback API
  - [TFTP](docs/design/tftp.md) — TFTP client: block size from the receive buffer, transfer IDs, retransmission
  - [mDNS + DNS-SD](docs/design/mdns.md) — Zero-config hostname + service discovery, probing/announcing state machine, DNS-SD PTR/SRV/TXT composition
  - [HTTP](docs/design/http.md) — HTTP/1.0 server: connection slots, transports (TCP, TLS), streaming, TIME-WAIT recycling, lingering close
  - [TLS 1.3](docs/design/tls.md) — Client and server over the stack's TCP, role files linked separately, pluggable crypto backend (Mbed TLS bundled), certificates + PSK, HelloRetryRequest, max_fragment_length, RFC 8448-verified key schedule
  - [DTLS 1.3](docs/design/dtls.md) — TLS 1.3's handshake over datagrams: the record layer shared through an interface, epochs and record number encryption, replay window, flights with fragmentation and a retransmission timer, ACKs, the cookie; interoperates with wolfSSL
- **[RFC Requirements](docs/requirements/)** — Numbered requirements per protocol, each traced to its RFC section and cited by the tests that verify it (the components table links each one's)
- **[Test Plan](docs/test-plan.md)** — The testing rules, requirements coverage and code coverage, the integration, unit and blackbox suites, CI jobs
- **[CI Debugging](docs/ci-debugging.md)** — The CI jobs, known failures and how to diagnose them
- **[Plan](tcpip-stack-plan.md)** — Objective, design decisions, what is implemented and what is not
- **[Release Process](docs/release-process.md)** — Versions, the changelog, and the release CI makes of every green push
- **[Changelog](CHANGELOG.md)** — What each release changed

---

## 🤝 Contributing

We'd love your help making **smallest_tcp** even better! Whether it's a bug fix, a new protocol layer, a driver for your favorite hardware, or better docs — all contributions are welcome.

### How to Contribute

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone git@github.com:YOUR_USERNAME/smallest_tcp.git
   cd smallest_tcp
   ```
3. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/my-awesome-change
   ```
4. **Make your changes** — write code, add tests, update docs
5. **Run the tests** to make sure everything passes:
   ```bash
   cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure
   make arm-size-all   # if you have arm-none-eabi-gcc: sizes and the no-division check
   ```
6. **Commit** with a clear, descriptive message:
   ```bash
   git commit -m "Add support for frobnicating the widget"
   ```
7. **Push** to your fork:
   ```bash
   git push origin feature/my-awesome-change
   ```
8. **Open a Pull Request** against `main` on the upstream repo

If your change is one a user of the library would notice, add a line for it under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md).  Every push to `main` that passes CI is released: CI commits the new version, tags and publishes it, so pull before your next push ([release-process.md](docs/release-process.md)).

### Guidelines

- **C99, `-Wall -Wextra -Werror -pedantic`** — all code must compile cleanly
- **Zero dynamic allocation** — `malloc`/`calloc`/`realloc` are not allowed in the stack
- **No run-time division** — Cortex-M0 has no divide instruction; `make arm-check-division` enforces it
- **Add tests** for new functionality — black-box, through the API or the wire, each citing the requirement IDs it verifies ([test-plan.md §0](docs/test-plan.md#0-policy-and-the-integration-tests)); a bug gets a failing test before its fix
- **Keep it small** — every byte of flash matters on our target platforms
- **Document as you go** — see [coding-rules.md](docs/design/coding-rules.md); update requirements docs if implementing RFC behavior

### Reporting Issues

Found a bug? Have a feature idea? [Open an issue](https://github.com/n9wxu/smallest_tcp/issues) — we're happy to discuss!

---

## 📄 License

See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Built with 🔥 for the tiniest devices and the biggest ambitions.</strong>
</p>
