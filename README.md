# 🚀 smallest_tcp

**A portable, zero-allocation TCP/IP stack that runs everywhere — from $0.20 microcontrollers to Linux and macOS.**

[![CI — Build & Unit Tests](https://github.com/n9wxu/smallest_tcp/actions/workflows/ci.yml/badge.svg)](https://github.com/n9wxu/smallest_tcp/actions/workflows/ci.yml)

---

## ✨ What Is This?

**smallest_tcp** is a ground-up TCP/IP network stack written in portable C99.  It's designed for one audacious goal: give *any* device with a MAC interface a full networking capability — TCP, UDP, DHCP, TFTP, mDNS + DNS-SD, HTTP — using **zero dynamic memory allocation** and fitting in as little as **2.9 KB of flash**.

Whether you're building a TCP/IP bootloader on a chip with 1 KB of RAM, adding network connectivity to a $0.20 RISC-V MCU, or prototyping protocol logic on your laptop — this stack has you covered.

### 🎯 Design Principles

| Principle | How We Do It |
|---|---|
| **Zero `malloc()`** | Your application owns all memory. The stack never allocates — you provide buffers and it adapts. |
| **Zero-copy** | Headers are parsed and built in-place. No copying frames around. |
| **Link what you need** | Each protocol is a separate `.c` file. Don't use TCP? It doesn't get linked. |
| **Portable C99** | No compiler extensions, no `__attribute__((packed))`. Runs on XC8, GCC, Clang, MSVC. |
| **Abstract MAC interface** | Plug in any hardware — TAP (Linux), BPF (macOS), ENC28J60, CDC-ECM USB, anything. |
| **Compile-time safety** | Catch errors at compile time, not runtime. Buffer sizes, feature flags, and capabilities are `#define`s. |

---

## 📊 How Small Is It?

Measured on ARM Cortex-M0 (`-Os -mthumb`), UDP echo server (ETH + ARP + IPv4 + ICMP + UDP), vs lwIP 2.2.1:

| Metric | smallest_tcp | lwIP (same features) | Ratio |
|---|---|---|---|
| **Flash** | **2,902 B** | 10,089 B | **3.5× smaller** |
| **RAM** | **672 B** (600 = app buffers) | 2,619 B | **3.9× smaller** |
| Stack-only code | **2,708 B** | 10,087 B | **3.7× smaller** |
| Stack-internal state | **10 B** | ~2,619 B | **262× smaller** |

The stack itself uses only **10 bytes** of static state. All other memory is application-owned buffers that you size to your needs.
Adding a TCP echo server brings the total to **6.8 KB flash / 1.1 KB RAM**; the mDNS + DNS-SD responder instead gives **9.3 KB flash / 0.7 KB RAM**; an HTTP server (with TCP) **11.0 KB flash / 1.7 KB RAM**.

> 📐 See [docs/design/size-comparison.md](docs/design/size-comparison.md) for the full comparison methodology, per-module breakdowns, and analysis.

---

## 📊 Current Status

**380 unit tests passing** across 19 test suites, compiled with `-Wall -Wextra -Werror -pedantic`.  
**112 blackbox conformance tests passing** across 9 suites (ARP ×5, IPv4 ×8, ICMPv4 ×7, UDP ×7, TCP ×20, DHCPv4 ×8, mDNS/DNS-SD ×19, HTTP ×21, IPv6 ×17), plus 5 fuzz tests and interop checks with Avahi and macOS (discover the device, browse to `http://pyro-dead01.local/`) — all run on every push/PR on Linux over both the TAP and the raw-socket driver, and locally on macOS (feth).

### ✅ Implemented (Milestones 1–11)

| Component | File(s) | Tests | Description |
|---|---|---|---|
| Core context | `net.h` / `net.c` | 8 | Factory method, defaults from `net_config.h`, MAC helpers |
| Byte order | `net_endian.h` | 10 | Portable wire read/write + host/network conversion |
| Checksum | `net_cksum.h` / `net_cksum.c` | 12 | RFC 1071 Internet checksum — incremental, one-shot, verify |
| Ethernet | `eth.h` / `eth.c` | 11 | Ethernet II parse/build, zero-copy, protocol dispatch |
| ARP | `arp.h` / `arp.c` | 8 unit + **5 blackbox** | Fast-path reply, gateway MAC learning, next-hop routing |
| IPv4 | `ipv4.h` / `ipv4.c` | 10 unit + **8 blackbox** | Parse/build/send, protocol dispatch, broadcast detection, ICMP Protocol Unreachable |
| ICMPv4 | `icmp.h` / `icmp.c` | 4 unit + **7 blackbox** | Echo reply (ping), destination unreachable, checksum validation |
| UDP | `udp.h` / `udp.c` | 7 unit + **7 blackbox** | Parse/send, port dispatch, pseudo-header checksum, ICMP Port Unreachable |
| **TCP** | **`tcp.h` / `tcp.c`** | **39 unit + 20 blackbox + 5 fuzz** | **Full state machine, retransmit (data + FIN), MSS, window updates, persist timer, close** |
| TCP buffer | `tcp_buf.h` / `tcp_buf_saw.c` | 20 | Stop-and-wait TX + RX buffers |
| **DHCPv4** | **`dhcpv4_client.h/.c`** `dhcpv4_server.h/.c` | **16 unit + 8 blackbox** | **RFC 2131 client state machine (DISCOVER→OFFER→REQUEST→ACK/NAK), minimal stateless server, option callback API** |
| TFTP | `tftp.h` / `tftp.c` | 15 unit | RFC 1350 TFTP client — block-read, retransmit, error handling |
| Multicast + IGMP | `ipv4.c` / `igmp.h` / `igmp.c` | 19 unit | Fixed-size group table, multicast RX, per-packet TTL, IGMPv2 join/leave (RFC 1112, 2236) |
| DNS wire format | `dns_wire.h` / `dns_wire.c` | 23 unit | RFC 1035 names with compression, bounds-checked readers (shared with the future DNS resolver) |
| **mDNS + DNS-SD** | **`mdns.h` / `mdns.c`** | **49 unit + 19 blackbox + interop** | **RFC 6762 responder: probe, announce, answer (A/PTR/SRV/TXT + DNS-SD additionals), NSEC negative answers, known-answer suppression, conflict rename, goodbye; RFC 6763 service advertising** |
| **HTTP server** | **`http.h` / `http.c`** | **45 unit + 21 blackbox + interop** | **HTTP/1.0: GET/HEAD/POST route table, streamed responses of any length, 400/404/405/413/414/431/501/505, connection slots recycled at once, timeouts** |
| **IPv6** (Milestone 12, stages 1–2) | **`ipv6.h/.c`** `icmpv6.h/.c` `ndp.h/.c` `udp.c` | **69 unit + 17 blackbox** | **RFC 8200 header + extension-header walk, EUI-64 link-local, ICMPv6 echo + errors, Neighbor Solicitation/Advertisement responder, Duplicate Address Detection, UDP over IPv6 (`udp6_ports`, mandatory checksum, Port Unreachable); dual stack via `NET_USE_IPV6` (IPv4-only builds unchanged)** |
| MAC: TAP | `driver/tap.c` | — | Linux TAP driver |
| MAC: raw socket | `driver/rawsock.c` | 15 unit (8 live, as root) | Linux `AF_PACKET` driver on an existing interface — a real NIC or a veth end, no `/dev/net/tun`; finishes offloaded checksums |
| MAC: BPF | `driver/bpf.c` | — | macOS BPF driver (feth pair) |
| MAC: Stub | `driver/stub.c` | — | No-op driver for cross-compilation / size measurement |
| CMake | `CMakeLists.txt` | — | Library + tests + FetchContent integration |
| CI | `.github/workflows/ci.yml` | — | Linux + macOS build; unit tests, full blackbox suite over TAP and raw socket, and ARM size benchmark on every push |
| Fuzz (nightly) | `.github/workflows/fuzz.yml` | 5 fuzz | TCP adversarial fuzz + full conformance regression nightly |
| **Total** | **19 source + 4 drivers** | **380 unit + 112 blackbox + 5 fuzz** | |

> ✅ **TCP persist timer implemented:** REQ-TCP-085/086/087 (zero-window persist timer)
> are fully implemented and covered by 3 unit tests and 1 blackbox conformance test.

### 🔜 Roadmap

| Milestone | Status | What's Included |
|---|---|---|
| **1 — Project skeleton** | ✅ Done | MAC abstraction, Linux TAP driver, frame hex-dump demo |
| **2 — Ethernet** | ✅ Done | Ethernet II parse/build, zero-copy, protocol dispatch |
| **3 — ARP** | ✅ Done | Fast-path filter, ARP reply, gateway MAC learning |
| **4 — IPv4 + ICMPv4** | ✅ Done | IPv4 parse/build/send, ICMP echo reply (`ping` works) |
| **5 — UDP** | ✅ Done | UDP parse/send, port dispatch, pseudo-header checksum |
| **6 — TCP core** | ✅ Done | Full state machine, retransmit, MSS, echo demo |
| **7 — TCP persist + integration** | ✅ Done | Zero-window persist timer, `net_poll()` API, ARP+TCP integration |
| **8 — DHCP** | ✅ Done | DHCPv4 client (auto-configure IP) + minimal stateless server (USB peer assignment) + option handler callback API (TFTP, NTP, DNS, …) |
| **9 — TFTP** | ✅ Done | Fetch files over the network — bootloader data path |
| **10 — mDNS + DNS-SD** | ✅ Done | Multicast DNS (RFC 6762) + DNS-Based Service Discovery (RFC 6763) — zero-config hostname resolution (`<name>.local`) + service announcement (`_service._tcp.local.`) with PTR/SRV/TXT records; required for pyro_fw device discovery |
| **11 — HTTP** | ✅ Done | HTTP/1.0 server — browse to your microcontroller at `http://pyro-dead01.local/` |
| **12 — IPv6** | In progress | ✅ stage 1: IPv6 + ICMPv6 + NDP responder + DAD (ping6 by link-local); ✅ stage 2: UDP; next: TCP, SLAAC, DHCPv6, mDNS/HTTP over IPv6 |
| **13 — TLS 1.3** | Planned | Encrypted TCP — pluggable crypto backend (mbedTLS/wolfSSL/BearSSL), PSK + cert modes, `max_fragment_length` for small buffers |
| **14 — DTLS 1.3** | Planned | Encrypted UDP — shares TLS crypto backend; adds anti-replay window, flight retransmit, handshake fragmentation (CoAP/RADIUS/SIP) |

### 📐 Target Platforms

| Chip | Flash | RAM | Cost | smallest_tcp UDP | lwIP UDP |
|---|---|---|---|---|---|
| PIC16F1454 | 14 KB | 1 KB | ~$1.20 | ✅ 2.9 KB + buffers | ❌ 10 KB code alone |
| CH32X033 | 62 KB | 20 KB | ~$0.20 | ✅ Plenty of room | ✅ Fits |
| STM32F042 | 32 KB | 6 KB | ~$1.00 | ✅ Room for TCP (6.8 KB), mDNS (9.3 KB) or HTTP (11.0 KB) | ⚠️ Tight |
| CH32V203 | 256 KB | 10 KB | ~$0.50 | ✅ Plenty of room | ✅ Fits |
| Linux / macOS | ∞ | ∞ | — | ✅ Dev & testing | ✅ Dev & testing |

---

## 🔧 Building

### Make (quick & simple)

```bash
make          # Build library + run tests + demo
make lib      # Build static library only
make test     # Build and run all 380 unit tests (19 suites; the raw-socket driver's live tests need root)
make demo     # Build the UDP echo server demo
make clean    # Clean all build artifacts
```

### ARM Size Measurement

```bash
make arm-size             # Cortex-M0 sizes, UDP only (the lwIP comparison)
make arm-size-tcp         # Cortex-M0 sizes, UDP + TCP
make arm-size-mdns        # Cortex-M0 sizes, UDP + mDNS/DNS-SD responder
make arm-size-http        # Cortex-M0 sizes, UDP + HTTP server (with TCP)
bash bench/build_lwip.sh  # Build lwIP 2.2.1 for comparison (fetched on first run)
```

Requires `arm-none-eabi-gcc` (install via Arm GNU Toolchain or `brew install --cask gcc-arm-embedded`).

### CMake (recommended for integration)

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

**CMake output directory layout** — binaries mirror the source tree:

| What | Path after `cmake --build build` |
|---|---|
| Unit tests | `build/tests/test_tcp`, `build/tests/test_arp`, … |
| Demo binaries | `build/demo/tcp_echo_demo`, `build/demo/frame_dump` |

> ⚠️ **Do not** use `build/tcp_echo_demo` — that path does not exist.
> Always use `build/demo/tcp_echo_demo`.  Getting this wrong is the most
> common cause of blackbox test failures (all tests ERROR with
> `ARP timeout: no reply from 10.0.0.2`).

### Running Blackbox Conformance Tests (Linux)

Nine conformance suites (ARP, IPv4, ICMPv4, UDP, TCP, DHCPv4, mDNS, HTTP, IPv6 —
112 tests total) run against the live `tcp_echo_demo`, `dhcp_echo_demo`, `mdns_demo` or
`http_demo` over a Linux TAP interface, or over a veth pair with the raw-socket
driver ([Option E](#option-e--any-suite-over-the-raw-socket-driver-no-tun)).
Requires `sudo` / `CAP_NET_RAW`.

#### Option A — `run_blackbox.sh` (recommended, all suites)

```bash
# 1. Build
cmake -S . -B build && cmake --build build --target tcp_echo_demo

# 2. Install Python deps once
pip install -r tests/blackbox/requirements.txt

# 3. Run everything — sets up TAP, starts SUT, runs all suites, tears down
sudo tests/blackbox/run_blackbox.sh \
    --sut-bin ./build/demo/tcp_echo_demo \
    --setup-tap --teardown-tap -v
```

`run_blackbox.sh` creates `tap0`, starts the SUT, runs each suite in order,
prints a `✓ / ✗` summary, and cleans up — even if a suite fails.

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

The suites that launch their own SUT (DHCPv4, mDNS, HTTP) take
`--sut-iface "$SUT_IF"`; the interop scripts take it as a second argument.  Leave
out `--rst-drop` for the HTTP suite, as in Option D.  On a real network:
`sudo ./build/demo/http_demo raw:eth0` — the driver keeps the interface in
promiscuous mode while it runs, since the stack uses its own MAC address.

#### Option F — IPv6 suite

The CMake build is dual stack (`-DSMALLEST_TCP_IPV6=OFF` for IPv4 only).  The
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
open `feth1` through BPF.  All 112 tests plus the `dns-sd` and browse-by-name interop checks pass (the IPv6 suite's host ping and UDP checks need `sudo ifconfig feth0 inet6 -ifdisabled`).

```bash
# Once per boot (root): create the pair.  10.0.0.100, the tests' source
# address, stays off the Mac, so no firewall rule is needed.
sudo ifconfig feth0 create && sudo ifconfig feth1 create
sudo ifconfig feth0 peer feth1
sudo ifconfig feth0 inet 10.0.0.1/24 up && sudo ifconfig feth1 up

# Once: Python deps in a venv (Homebrew Python refuses global pip installs)
python3 -m venv .venv && .venv/bin/pip install -r tests/blackbox/requirements.txt

# Build and run everything (ARP … TCP, DHCPv4, mDNS, HTTP, interop checks)
cmake -S . -B build && cmake --build build
tests/blackbox/run_blackbox_macos.sh build
```

Without `sudo`, the demos and Scapy need BPF access — Wireshark's ChmodBPF
provides it via the `access_bpf` group; otherwise run the script with `sudo`.
Remove the pair with `sudo ifconfig feth0 destroy; sudo ifconfig feth1 destroy`.

---

## 📦 Using In Your Project

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

That's it! Your app gets the headers and library automatically. When included via FetchContent, **only the core library is built** — no tests, no demos, no drivers. Clean and minimal.

> 💡 See [`examples/fetchcontent/`](examples/fetchcontent/) for a complete working example.

### Available CMake Targets

| Target | Description |
|---|---|
| `smallest_tcp::smallest_tcp` | Core stack library (net, checksum, ethernet, ARP, IPv4, ICMP, UDP, TCP) |
| `smallest_tcp::dhcpv4_client` | DHCPv4 client (optional) |
| `smallest_tcp::dhcpv4_server` | Minimal stateless DHCPv4 server (optional) |
| `smallest_tcp::tftp` | TFTP client (optional) |
| `smallest_tcp::mdns` | mDNS + DNS-SD responder, DNS wire helpers, IGMPv2 (optional) |
| `smallest_tcp::http` | HTTP/1.0 server (optional) |
| `smallest_tcp::driver_tap` | Linux TAP MAC driver (optional, top-level only) |
| `smallest_tcp::driver_rawsock` | Linux raw-socket (`AF_PACKET`) MAC driver (optional, top-level only) |
| `smallest_tcp::driver_bpf` | macOS BPF MAC driver (optional, top-level only) |

### Manual Integration

If you're not using CMake (e.g., bare-metal Makefile or IDE project):

1. Copy `src/` and `include/` into your project
2. Add `include/` to your compiler's include path
3. Compile the `.c` files you need — link only what you use
4. Provide your own MAC driver implementing the `net_mac_t` interface

---

## 🏗️ Architecture

```
┌─────────────────────────────────────┐
│           Application               │
│  (bootloader, web server, etc.)     │
│  Owns all buffers and conn state    │
├─────────────────────────────────────┤
│  L7: dhcp ✅ tftp ✅ mdns ✅ http ✅│  ← optional, link what you need
├─────────────────────────────────────┤
│  L4: udp.c ✅       tcp.c ✅       │  ← optional independently
├─────────────────────────────────────┤
│  L3: ipv4.c ✅  icmp.c ✅          │
├─────────────────────────────────────┤
│  L2: arp.c ✅                       │
├─────────────────────────────────────┤
│  L2: eth.c ✅                       │
├─────────────────────────────────────┤
│  MAC driver interface (net_mac.h)   │  ← abstract vtable
├──────────────┬──────────┬───────────┤
│ tap.c ✅     │ bpf.c ✅ │ your      │
│ rawsock.c ✅ │ (macOS)  │ driver.c  │
│ (Linux)      │          │ (your HW) │
└──────────────┴──────────┴───────────┘
```

**Your application owns everything:** buffers, connection state, configuration. The stack provides the protocol logic and operates on your memory.

---

## 📖 Documentation

Detailed design docs and RFC-traced requirements live in [`docs/`](docs/):

- **[Architecture](docs/architecture.md)** — System architecture, layer interaction, data flow
- **[Size Comparison](docs/design/size-comparison.md)** — ARM Cortex-M0 code size: smallest_tcp vs lwIP (3.7× smaller)
- **Design Documents:**
  - [MAC HAL](docs/design/mac-hal.md) — Abstract hardware interface (vtable, peek+discard)
  - [Checksum](docs/design/checksum.md) — Incremental Internet checksum design
  - [Byte Order](docs/design/byte-order.md) — Portable endian handling, 8-bit target strategy
  - [Timer Model](docs/design/timer-model.md) — net_poll, net_tick, tickless support
  - [TCP Buffer](docs/design/tcp-buffer.md) — Stop-and-wait, circular, packet-list strategies
  - [ARP Resolution](docs/design/arp-resolution.md) — Distributed cache, gateway-only mode
  - [Memory Model](docs/design/memory-model.md) — Zero-allocation factory methods
  - [Configuration](docs/design/configuration.md) — Compile-time vs. runtime taxonomy
  - [UDP](docs/design/udp.md) — Port dispatch table, zero-copy RX, checksum, ICMP port unreachable
  - [DHCPv4](docs/design/dhcpv4.md) — Client + server design, option handler callback API
  - [mDNS + DNS-SD](docs/design/mdns.md) — Zero-config hostname + service discovery design, probing/announcing state machine, DNS-SD PTR/SRV/TXT composition *(Milestone 10 — implemented)*
  - [HTTP](docs/design/http.md) — HTTP/1.0 server on the stop-and-wait TCP: connection slots, streaming, TIME_WAIT recycling, lingering close *(Milestone 11 — implemented)*
  - [TLS 1.3](docs/design/tls.md) — Pluggable crypto backend, PSK + cert modes, record + handshake SM *(Milestone 13)*
  - [DTLS 1.3](docs/design/dtls.md) — Anti-replay window, flight retransmit, handshake fragmentation *(Milestone 14)*
- **[RFC Requirements](docs/requirements/)** — RFC-traced requirements across 20 protocol specifications:
  - [mDNS](docs/requirements/mdns.md) — RFC 6762: probing, announcing, responding, goodbye, known-answer suppression
  - [DNS-SD](docs/requirements/dns-sd.md) — RFC 6763: PTR/SRV/TXT advertisement, service-type enumeration, conflict detection
- **[Test Plan](docs/test-plan.md)** — Black-box conformance testing strategy with Python/Scapy/pytest

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
   make clean && make test
   # or
   cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure
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
- **Add tests** for new functionality — we target 100% passing in CI
- **Keep it small** — every byte of flash matters on our target platforms
- **Document as you go** — update requirements docs if implementing RFC behavior

### Reporting Issues

Found a bug? Have a feature idea? [Open an issue](https://github.com/n9wxu/smallest_tcp/issues) — we're happy to discuss!

---

## 📄 License

See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Built with 🔥 for the tiniest devices and the biggest ambitions.</strong>
</p>
