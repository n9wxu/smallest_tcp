# 🚀 smallest_tcp

**A portable, zero-allocation TCP/IP stack that runs everywhere — from $0.20 microcontrollers to Linux and macOS.**

[![CI — Build & Unit Tests](https://github.com/n9wxu/smallest_tcp/actions/workflows/ci.yml/badge.svg)](https://github.com/n9wxu/smallest_tcp/actions/workflows/ci.yml)

---

## ✨ What Is This?

**smallest_tcp** is a ground-up TCP/IP network stack written in portable C99.  It's designed for one audacious goal: give *any* device with a MAC interface a full networking capability — IPv4 and IPv6, TCP, UDP, DHCP, TFTP, mDNS + DNS-SD, HTTP, TLS 1.3 — using **zero dynamic memory allocation** and fitting in as little as **2.8 KB of flash**.

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
| **Flash** | **2,802 B** | 10,089 B | **3.6× smaller** |
| **RAM** | **676 B** (600 = app buffers) | 2,619 B | **3.9× smaller** |
| Stack-only code | **2,726 B** | 10,087 B | **3.7× smaller** |
| Stack-internal state | **0 B** | ~2,619 B | — |

The stack itself has **no static state**: everything it keeps lives in `net_t` and in structures your application declares and sizes.

| Configuration (`make` target) | Flash (.text) | RAM |
|---|---:|---:|
| UDP echo (`arm-size`) | 2,802 B | 676 B |
| UDP + TCP echo (`arm-size-tcp`) | 6,626 B | 1,064 B |
| UDP + mDNS/DNS-SD responder (`arm-size-mdns`) | 9,244 B | 724 B |
| UDP + HTTP server, with TCP (`arm-size-http`) | 10,990 B | 1,684 B |
| UDP echo, dual stack IPv4 + IPv6 with ICMPv6, ND, SLAAC, MLD (`arm-size-ipv6`) | 7,805 B | 780 B |
| UDP echo, IPv6 only: no ARP, IPv4 or ICMP (`arm-size-ipv6-only`) | 5,977 B | 752 B |
| TLS 1.3 protocol, server only (`arm-size-tls`) | 7,460 B | 448 B per connection + record buffers |
| TLS 1.3 protocol, client and server (`arm-size-tls`) | 10,950 B | 448 B per connection + record buffers |
| DTLS 1.3 protocol, server only (`arm-size-dtls`) | 11,263 B | 904 B per connection + buffers |
| DTLS 1.3 protocol, client and server (`arm-size-dtls`) | 14,921 B | 904 B per connection + buffers |

RAM is `.data` + `.bss` of the whole benchmark, all of it application-owned.  TLS and DTLS take their cryptography from a backend you choose (Mbed TLS is bundled), which is not included in these figures; they share the handshake, so a device with both links 17.4 KB, not two handshakes.

> 📐 See [docs/design/size-comparison.md](docs/design/size-comparison.md) for the full comparison methodology, per-module breakdowns, and analysis.

---

## 📊 Current Status

**809 unit tests passing** across 29 test suites on macOS — 820 on Linux, where the raw-socket driver's suite adds 3 socket tests and, as root, 8 live tests — compiled with `-Wall -Wextra -Werror -pedantic`; CTest adds five checks that a configuration which cannot work refuses to build (`mdns.c` without a multicast group slot, TFTP and the DHCPv4 client without IPv4, a build with neither IPv4 nor IPv6).  
**209 blackbox conformance tests** across 14 suites (ARP ×5, IPv4 ×8, ICMPv4 ×7, UDP ×7, TCP ×20, DHCPv4 ×8, mDNS/DNS-SD ×21, HTTP ×22, IPv6 ×29, TLS server ×29, TLS client ×17, HTTPS ×9, DTLS server ×19, DTLS client ×8), plus 5 fuzz tests and interop checks with Avahi (over IPv4 and IPv6), macOS (discover the device, browse to `http://pyro-dead01.local/`), dnsmasq (DHCPv6), OpenSSL, Python ssl and curl (TLS 1.3), and wolfSSL (DTLS 1.3) — run on every push/PR on Linux over both the TAP and the raw-socket driver, and locally on macOS (feth).

### ✅ Implemented (Milestones 1–14)

| Component | File(s) | Tests | Description |
|---|---|---|---|
| Core context | `net.h` / `net.c` | 13 | `net_init()`, `net_poll()`, `net_tick()`, `net_transmit()`, random numbers (HalfSipHash-2-4 under a secret key), defaults from `net_config.h` |
| Byte order | `net_endian.h` | 10 | Portable wire read/write + host/network conversion |
| Checksum | `net_cksum.h` / `net_cksum.c` | 12 | RFC 1071 Internet checksum — incremental, one-shot, verify |
| Ethernet | `eth.h` / `eth.c` | 11 | Ethernet II parse/build, protocol dispatch |
| ARP | `arp.h` / `arp.c` | 8 unit + **5 blackbox** | Fast-path reply, gateway MAC learning, next-hop routing |
| IPv4 | `ipv4.h` / `ipv4.c` | 10 unit + **8 blackbox** | Parse/build/send, protocol dispatch, broadcast detection, ICMP Protocol Unreachable |
| ICMPv4 | `icmp.h` / `icmp.c` | 4 unit + **7 blackbox** | Echo reply (ping), destination unreachable, checksum validation |
| UDP | `udp.h` / `udp.c` | 7 unit + **7 blackbox** | Parse/send, port table dispatch, pseudo-header checksum, ICMP Port Unreachable |
| **TCP** | **`tcp.h` / `tcp.c`** | **63 unit + 20 blackbox + 5 fuzz** | **Full state machine, retransmit (data + FIN), MSS, window updates, persist timer, in-order delivery, close with the FIN queued behind unsent data, RFC 6528 initial sequence numbers; application-owned connection table** |
| TCP buffer | `tcp_buf.h` / `tcp_buf_saw.c` | 22 | Stop-and-wait TX + RX buffers |
| **DHCPv4** | **`dhcpv4_client.h/.c`** `dhcpv4_server.h/.c` | **38 unit + 8 blackbox** | **RFC 2131 client state machine (DISCOVER→OFFER→REQUEST→ACK/NAK), minimal stateless server, option callback API** |
| TFTP | `tftp.h` / `tftp.c` | 28 unit | RFC 1350 TFTP client — block-read, blksize option, retransmit, error handling |
| Multicast + IGMP | `ipv4.c` / `igmp.h` / `igmp.c` | 19 unit | Fixed-size group table, multicast RX, per-packet TTL, IGMPv2 join/leave (RFC 1112, 2236) |
| DNS wire format | `dns_wire.h` / `dns_wire.c` | 23 unit | RFC 1035 names with compression, bounds-checked readers |
| **mDNS + DNS-SD** | **`mdns.h` / `mdns.c`** | **68 unit + 21 blackbox + interop** | **RFC 6762 responder: probe, announce, answer (A/AAAA/PTR/SRV/TXT + DNS-SD additionals), NSEC negative answers, known-answer suppression, conflict rename, goodbye; RFC 6763 service advertising; dual stack: ff02::fb, AAAA for every usable IPv6 address, answers on the query's family** |
| **HTTP server** | **`http.h` / `http.c`** `http_tls.h/.c` | **46 unit + 22 blackbox + 9 HTTPS + interop** | **HTTP/1.0: GET/HEAD/POST route table, streamed responses of any length, 400/404/405/413/414/431/501/505, connection slots recycled at once, timeouts; over IPv4 and IPv6; plain TCP or TLS 1.3 through a transport interface** |
| **IPv6** (Milestone 12) | **`ipv6.h/.c`** `icmpv6.h/.c` `ndp.h/.c` `mld.h/.c` `udp.c` `tcp.c` | **127 unit + 27 blackbox** | **RFC 8200 header + extension-header walk, EUI-64 link-local, ICMPv6 echo + errors, Neighbor Solicitation/Advertisement responder, Duplicate Address Detection, UDP and TCP over IPv6 (dual-stack listeners), router discovery + SLAAC (global address, default router, lifetimes), MLDv2 with MLDv1 fallback + `ipv6_mcast_join()`; dual stack via `NET_USE_IPV6` (IPv4-only builds unchanged), or IPv6 alone with `NET_USE_IPV4` 0** |
| **DHCPv6** (Milestone 12) | **`dhcpv6_client.h/.c`** | **20 unit + 2 blackbox + dnsmasq interop** | **RFC 8415 client: stateless (Information-Request → DNS) and stateful (Solicit/Advertise/Request/Reply, Renew at T1, Rebind at T2, expiry, Release), DUID-LL, §15 retransmission with jitter, option handler table; started by the RA's M / O flags** |
| **TLS 1.3** (Milestone 13) | **`tls.h`** `tls_common.c` `tls.c` `tls_keys.h/.c` `tls_server.c` `tls_client.c` `tls_tcp.h/.c` `tls_crypto.h` `tls_crypto_mbedtls.h/.c` | **219 unit + 55 blackbox + OpenSSL/Python/curl interop** | **RFC 8446 client and server over the stack's TCP: `TLS_AES_128_GCM_SHA256`, x25519 / secp256r1 (HelloRetryRequest both ways), ECDSA P-256 and RSA-PSS certificates (chain + name + CertificateVerify checks), pre-shared keys (psk_dhe_ke, psk_ke) with binders, max_fragment_length for small buffers, KeyUpdate, close_notify; key schedule and records verified against RFC 8448; each role in its own file, so a server-only build does not link the client; all cryptography through a `tls_crypto_t` vtable (Mbed TLS 3.6 backend bundled); HTTPS demo** |
| **DTLS 1.3** (Milestone 14) | **`dtls.h`** `dtls.c`, with TLS's `tls_common.c` `tls_keys.c` `tls_server.c` `tls_client.c` | **57 unit + 27 blackbox + wolfSSL interop** | **RFC 9147 client and server on TLS 1.3's handshake, key schedule and crypto backend: DTLSPlaintext and the unified header, record number encryption, a replay window per epoch, flights with fragmentation to the MTU and reassembly of overlapping fragments, a retransmission timer (1 s doubling to 60 s), ACKs, KeyUpdate taking effect once acknowledged, the server's cookie exchange; invalid records dropped silently; the application moves datagrams (`dtls_input()` / `dtls_pending()`); `TLS_USE_DTLS` 0 compiles it out of the handshake** |
| MAC: TAP | `driver/tap.c` | — | Linux TAP driver |
| MAC: raw socket | `driver/rawsock.c` | 15 unit (8 live, as root) | Linux `AF_PACKET` driver on an existing interface — a real NIC or a veth end, no `/dev/net/tun`; finishes offloaded checksums |
| MAC: BPF | `driver/bpf.c` | — | macOS BPF driver (feth pair) |
| MAC: STM32F4 Ethernet | `driver/stm32f4_eth.c` | — (built in CI; not yet run on hardware) | The STM32F4's ETH MAC and DMA over RMII; with the NUCLEO-F429ZI board port (`boards/nucleo-f429zi`), the firmware of the hardware fuzz job |
| MAC: Stub | `driver/stub.c` | — | No-op driver for cross-compilation / size measurement |
| Build | `CMakeLists.txt`, `Makefile` | — | CMake: libraries, tests, demos, FetchContent integration.  Makefile: Cortex-M0 size benchmarks and the no-division check |
| CI | `.github/workflows/ci.yml` | — | Linux + macOS CMake builds and unit tests, IPv4-only and IPv6-only builds, full blackbox suites over TAP and raw socket (DTLS against a pinned wolfSSL), and the ARM size benchmark on every push |
| Fuzz (nightly) | `.github/workflows/fuzz.yml` | 5 fuzz | TCP adversarial fuzz + full conformance regression nightly |
| **Total** | **31 source + 5 drivers** | **820 unit + 209 blackbox + 5 fuzz** | |

### 🔜 Roadmap

| Milestone | Status | What's Included |
|---|---|---|
| **1 — Project skeleton** | ✅ Done | MAC abstraction, Linux TAP driver, frame hex-dump demo |
| **2 — Ethernet** | ✅ Done | Ethernet II parse/build, protocol dispatch |
| **3 — ARP** | ✅ Done | Fast-path filter, ARP reply, gateway MAC learning |
| **4 — IPv4 + ICMPv4** | ✅ Done | IPv4 parse/build/send, ICMP echo reply (`ping` works) |
| **5 — UDP** | ✅ Done | UDP parse/send, port dispatch, pseudo-header checksum |
| **6 — TCP core** | ✅ Done | Full state machine, retransmit, MSS, echo demo |
| **7 — TCP persist + integration** | ✅ Done | Zero-window persist timer, `net_poll()` API, ARP+TCP integration |
| **8 — DHCP** | ✅ Done | DHCPv4 client (auto-configure IP) + minimal stateless server (USB peer assignment) + option handler callback API (TFTP, NTP, DNS, …) |
| **9 — TFTP** | ✅ Done | Fetch files over the network — bootloader data path |
| **10 — mDNS + DNS-SD** | ✅ Done | Multicast DNS (RFC 6762) + DNS-Based Service Discovery (RFC 6763) — zero-config hostname resolution (`<name>.local`) + service announcement (`_service._tcp.local.`) with PTR/SRV/TXT records; required for pyro_fw device discovery |
| **11 — HTTP** | ✅ Done | HTTP/1.0 server — browse to your microcontroller at `http://pyro-dead01.local/` |
| **12 — IPv6** | ✅ Done | Dual stack: IPv6 + ICMPv6, neighbor discovery + DAD, UDP and TCP over IPv6, router discovery + SLAAC, DHCPv6 (stateless + stateful), MLD, mDNS (AAAA, ff02::fb) and HTTP over IPv6 — 7.8 KB flash for a dual-stack UDP echo on Cortex-M0 |
| **13 — TLS 1.3** | ✅ Done | Encrypted TCP, client and server: certificates (ECDSA, RSA-PSS) and pre-shared keys, x25519 / P-256 with HelloRetryRequest, `max_fragment_length` for small buffers, KeyUpdate — pluggable crypto backend (Mbed TLS bundled); `https://10.0.0.2/` from the HTTPS demo — 7.5 KB of protocol code on Cortex-M0 for a server, 11.0 KB for both roles |
| **14 — DTLS 1.3** | ✅ Done | Encrypted UDP on TLS 1.3's handshake and crypto backend: epochs, record number encryption, anti-replay window, flights with fragmentation and a retransmission timer, ACKs, the cookie exchange — interoperates with wolfSSL; 11.3 KB of protocol code on Cortex-M0 for a server, 14.9 KB for both roles |

### 📐 Target Platforms

| Chip | Flash | RAM | Cost | smallest_tcp | lwIP UDP |
|---|---|---|---|---|---|
| PIC16F1454 | 14 KB | 1 KB | ~$1.20 | ✅ UDP: 2.8 KB + buffers | ❌ 10 KB code alone |
| CH32X033 | 62 KB | 20 KB | ~$0.20 | ✅ Plenty of room | ✅ Fits |
| STM32F042 | 32 KB | 6 KB | ~$1.00 | ✅ Room for TCP (6.6 KB), mDNS (9.2 KB), HTTP (11.0 KB), dual-stack UDP (7.8 KB) or IPv6-only UDP (6.0 KB) | ⚠️ Tight with app |
| CH32V203 | 256 KB | 10 KB | ~$0.50 | ✅ Plenty of room | ✅ Fits |
| Linux / macOS | ∞ | ∞ | — | ✅ Dev & testing | ✅ Dev & testing |

---

## 🔧 Building

### CMake (the host build)

CMake builds the libraries, the unit tests and the demos:

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

| Option | Default | Effect |
|---|---|---|
| `SMALLEST_TCP_BUILD_TESTS` | ON at top level, OFF when cross-compiling | Unit tests (`ctest`) |
| `SMALLEST_TCP_BUILD_DEMO` | ON at top level, OFF when cross-compiling | Demo applications |
| `SMALLEST_TCP_BUILD_DRIVERS` | ON at top level | Platform MAC drivers (TAP and raw socket on Linux, BPF on macOS) |
| `SMALLEST_TCP_IPV4` | ON | IPv4, ARP, ICMP in the core (`NET_USE_IPV4`), and the libraries that run only over IPv4 (DHCPv4, TFTP); OFF for IPv6 only |
| `SMALLEST_TCP_IPV6` | ON | Dual stack: IPv6, ICMPv6, NDP, MLD in the core (`NET_USE_IPV6`); OFF for IPv4 only |
| `SMALLEST_TCP_UDP` | ON | UDP in the core (`NET_USE_UDP`) and the libraries over it |
| `SMALLEST_TCP_TCP` | ON | TCP in the core (`NET_USE_TCP`) and the libraries over it |
| `SMALLEST_TCP_TLS` | ON at top level | The Mbed TLS crypto backend, the TLS and DTLS demos and tests; CMake downloads Mbed TLS 3.6.7 (pinned by SHA-256) |
| `SMALLEST_TCP_DTLS` | ON | DTLS 1.3 (`dtls.c`) as well as TLS, sharing the handshake (`TLS_USE_DTLS`); OFF builds the handshake for TLS alone |
| `SMALLEST_TCP_DEBUG` | OFF | `NET_LOG()` output to `stderr` (`NET_DEBUG=1`) |
| `SMALLEST_TCP_BOARD` | empty | With a cross toolchain, a board port's firmware: `nucleo-f429zi` builds `tcp_echo_demo.elf` ([test-plan.md §4](docs/test-plan.md#4-hardware-test-fixture-recommended)) |
| `SMALLEST_TCP_CONFIG_FILE` | empty | Your configuration header, included first by `net_config.h` (`NET_CONFIG_FILE`) |

"At top level" means ON when smallest_tcp is the top-level project and OFF when it is pulled in with FetchContent.  With UDP or TCP off, the tests and demos (which use the whole stack) are not built; with IPv4 off, only the suites and demos that need no IPv4 are (`tcp_echo_demo`, `tls_echo_demo`, `frame_dump`).  The protocol options are `PUBLIC` compile definitions of the core, so everything linked against it is compiled with the same `net_t` layout ([configuration.md §3](docs/design/configuration.md#3-library-and-application-must-agree)).

**Cross-compiling the libraries** for a Cortex-M: `cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=cmake/arm-none-eabi.cmake` (GNU Arm toolchain; Cortex-M4 unless `-DSMALLEST_TCP_ARM_CPU=` names another core).  The tests and demos are hosted programs and stay off, and so does the bundled Mbed TLS backend (`SMALLEST_TCP_TLS`), whose configuration needs a platform entropy source a bare-metal target does not have; the TLS protocol library itself is built.

**CMake output directory layout** — binaries mirror the source tree:

| What | Path after `cmake --build build` |
|---|---|
| Unit tests | `build/tests/test_tcp`, `build/tests/test_arp`, … |
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

Fourteen conformance suites (209 tests) run against the live demos over a Linux
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
open `feth1` through BPF.  203 tests pass and 6 skip (the checks that need Linux or host IPv6 set-up), plus the `dns-sd` and browse-by-name interop checks pass — the DTLS suites against wolfSSL built by `tests/blackbox/build_wolfssl.sh` (found in `build/wolfssl`, else skipped), the TLS suites with Homebrew's `openssl` first in `PATH` (not the system LibreSSL), Python ≥ 3.13 for the PSK tests, and their IPv6 test Linux-only (the IPv6 suite's host ping, UDP and TCP checks need `sudo ifconfig feth0 inet6 -ifdisabled`; reaching the SLAAC address from the host is Linux-only).

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
extern uint32_t board_entropy(void);

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
  uint32_t last;

  if (net_init(&net, rx_buf, sizeof rx_buf, tx_buf, sizeof tx_buf, NULL,
               &board_mac_ops, board_mac_ctx) != NET_OK ||
      board_mac_ops.init(board_mac_ctx) != 0)
    return 1;
  net_random_seed(&net, board_entropy()); /* TCP ISNs, DHCP xids, ... */
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
      net_tick(&net, now - last); /* TCP (and IPv6) timers */
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
    GIT_TAG        main   # or pin to a specific commit/tag
)
FetchContent_MakeAvailable(smallest_tcp)

# Link it to your target
target_link_libraries(my_app PRIVATE smallest_tcp::smallest_tcp)
```

When included via FetchContent, smallest_tcp builds its libraries only — no tests, no demos, no drivers, no Mbed TLS (the `SMALLEST_TCP_*` options above turn any of them on).  Choose the transports before `FetchContent_MakeAvailable()`, e.g. `set(SMALLEST_TCP_IPV6 OFF)`.

> 💡 See [`examples/fetchcontent/`](examples/fetchcontent/) for a complete working example.

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
3. Choose the transports: the core (`net.c`, `net_cksum.c`, `eth.c`, `arp.c`, `ipv4.c`, `icmp.c`) dispatches to UDP and TCP unless you compile everything with `-DNET_USE_UDP=0` / `-DNET_USE_TCP=0` and leave out `udp.c` / `tcp.c` + `tcp_buf_saw.c`; `-DNET_USE_IPV6=1` adds `ipv6.c`, `icmpv6.c`, `ndp.c`, `mld.c`.  Compile the library and the application with the same settings — they change `net_t` ([configuration.md](docs/design/configuration.md))
4. Add the application protocols you use (`dhcpv4_client.c`, `mdns.c` + `dns_wire.c` + `igmp.c`, `http.c` + `net_text.c`, the `tls*.c` files, …)
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
- **[Size Comparison](docs/design/size-comparison.md)** — ARM Cortex-M0 code size: smallest_tcp vs lwIP (3.7× smaller stack code)
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
- **[RFC Requirements](docs/requirements/)** — RFC-traced requirements across 20 protocol specifications:
  - [mDNS](docs/requirements/mdns.md) — RFC 6762: probing, announcing, responding, goodbye, known-answer suppression
  - [DNS-SD](docs/requirements/dns-sd.md) — RFC 6763: PTR/SRV/TXT advertisement, service-type enumeration, conflict detection
- **[Test Plan](docs/test-plan.md)** — Unit and black-box conformance testing with Python/Scapy/pytest, CI jobs
- **[CI Debugging](docs/ci-debugging.md)** — Known CI failures and how to diagnose them

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

### Guidelines

- **C99, `-Wall -Wextra -Werror -pedantic`** — all code must compile cleanly
- **Zero dynamic allocation** — `malloc`/`calloc`/`realloc` are not allowed in the stack
- **No run-time division** — Cortex-M0 has no divide instruction; `make arm-check-division` enforces it
- **Add tests** for new functionality — we target 100% passing in CI
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
