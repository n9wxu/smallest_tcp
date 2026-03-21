# 🚀 smallest_tcp

**A portable, zero-allocation TCP/IP stack that runs everywhere — from $0.20 microcontrollers to Linux and macOS.**

[![CI — Build & Unit Tests](https://github.com/n9wxu/smallest_tcp/actions/workflows/ci.yml/badge.svg)](https://github.com/n9wxu/smallest_tcp/actions/workflows/ci.yml)

---

## ✨ What Is This?

**smallest_tcp** is a ground-up TCP/IP network stack written in portable C99.  It's designed for one audacious goal: give *any* device with a MAC interface a full networking capability — TCP, UDP, DHCP, HTTP, TFTP — using **zero dynamic memory allocation** and fitting in as little as **2.6 KB of flash**.

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

Measured on ARM Cortex-M0 (`-Os -mthumb`), UDP echo server (ETH + ARP + IPv4 + ICMP + UDP):

| Metric | smallest_tcp | lwIP (same features) | Ratio |
|---|---|---|---|
| **Flash** | **2,650 B** | 10,103 B | **3.8× smaller** |
| **RAM** | **672 B** (600 = app buffers) | 2,619 B | **3.9× smaller** |
| Stack-only code | **2,460 B** | 10,103 B | **4.1× smaller** |
| Stack-internal state | **10 B** | ~2,619 B | **262× smaller** |

The stack itself uses only **10 bytes** of static state. All other memory is application-owned buffers that you size to your needs.

> 📐 See [docs/design/size-comparison.md](docs/design/size-comparison.md) for the full comparison methodology, per-module breakdowns, and analysis.

---

## 📊 Current Status

**70 unit tests passing** across 8 test suites, compiled with `-Wall -Wextra -Werror -pedantic`.

### ✅ Implemented (Milestones 1–5)

| Component | File(s) | Tests | Description |
|---|---|---|---|
| Core context | `net.h` / `net.c` | 8 | Factory method, defaults from `net_config.h`, MAC helpers |
| Byte order | `net_endian.h` | 10 | Portable wire read/write + host/network conversion |
| Checksum | `net_cksum.h` / `net_cksum.c` | 12 | RFC 1071 Internet checksum — incremental, one-shot, verify |
| Ethernet | `eth.h` / `eth.c` | 11 | Ethernet II parse/build, zero-copy, protocol dispatch |
| ARP | `arp.h` / `arp.c` | 8 | Fast-path reply, gateway MAC learning, next-hop routing |
| IPv4 | `ipv4.h` / `ipv4.c` | 10 | Parse/build/send, protocol dispatch, broadcast detection |
| ICMPv4 | `icmp.h` / `icmp.c` | 4 | Echo reply (ping), destination unreachable |
| UDP | `udp.h` / `udp.c` | 7 | Parse/send, port dispatch, pseudo-header checksum |
| MAC: TAP | `driver/tap.c` | — | Linux TAP driver |
| MAC: BPF | `driver/bpf.c` | — | macOS BPF driver (feth pair) |
| MAC: Stub | `driver/stub.c` | — | No-op driver for cross-compilation / size measurement |
| CMake | `CMakeLists.txt` | — | Library + tests + FetchContent integration |
| CI | `.github/workflows/ci.yml` | — | Linux + macOS build & test on every push |
| **Total** | **8 source + 3 drivers** | **70** | |

### 🔜 Roadmap

| Milestone | Status | What's Coming |
|---|---|---|
| **6 — TCP** | 🔜 Next | Full state machine, app-managed connections, retransmit |
| **7 — Integration** | Planned | Event loop, timer tick, ARP+ping+UDP+TCP simultaneously |
| **8 — DHCP** | Planned | Auto-configure IP from any DHCP server |
| **9 — TFTP** | Planned | Fetch files over the network — bootloader data path |
| **10 — HTTP** | Planned | HTTP/1.0 server — browse to your microcontroller! |
| **11 — IPv6** | Planned | IPv6 + ICMPv6 + NDP + SLAAC + DHCPv6 |

### 📐 Target Platforms

| Chip | Flash | RAM | Cost | smallest_tcp UDP | lwIP UDP |
|---|---|---|---|---|---|
| PIC16F1454 | 14 KB | 1 KB | ~$1.20 | ✅ 2.6 KB + buffers | ❌ 10 KB code alone |
| CH32X033 | 62 KB | 20 KB | ~$0.20 | ✅ Plenty of room | ✅ Fits |
| STM32F042 | 32 KB | 6 KB | ~$1.00 | ✅ Room for TCP too | ⚠️ Tight |
| CH32V203 | 256 KB | 10 KB | ~$0.50 | ✅ Plenty of room | ✅ Fits |
| Linux / macOS | ∞ | ∞ | — | ✅ Dev & testing | ✅ Dev & testing |

---

## 🔧 Building

### Make (quick & simple)

```bash
make          # Build library + run tests + demo
make lib      # Build static library only
make test     # Build and run all 70 unit tests
make demo     # Build the UDP echo server demo
make clean    # Clean all build artifacts
```

### ARM Size Measurement

```bash
make arm-size           # Build for Cortex-M0 and show sizes
bash bench/build_lwip.sh  # Build lwIP for comparison
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

The full TCP conformance suite runs against the live `tcp_echo_demo` over
a Linux TAP interface.  Requires `sudo` / `CAP_NET_RAW`.

```bash
# 1. Build
cmake -S . -B build && cmake --build build --target tcp_echo_demo
# Binary lives at build/demo/tcp_echo_demo  ← NOT build/tcp_echo_demo

# 2. Set up the TAP interface
sudo ip tuntap add dev tap0 mode tap user $(whoami)
sudo ip link set tap0 up
sudo ip addr add 10.0.0.100/24 dev tap0
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

# 3. Start the SUT
sudo ./build/demo/tcp_echo_demo &

# 4. Run the suite
pip install -r tests/blackbox/requirements.txt
sudo python3 -m pytest tests/blackbox/test_tcp_conform.py \
    --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 -v
```

> ⚠️ If every test reports `ERROR: ARP timeout: no reply from 10.0.0.2`,
> the SUT is not running.  The most common cause is a wrong binary path —
> see [Test Plan §6 Troubleshooting](docs/test-plan.md#6-troubleshooting--known-pitfalls).

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
| `smallest_tcp::smallest_tcp` | Core stack library (net, checksum, ethernet, ARP, IPv4, ICMP, UDP) |
| `smallest_tcp::driver_tap` | Linux TAP MAC driver (optional, top-level only) |
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
│  L7: dhcp.c  tftp.c  http.c        │  ← optional, link what you need
├─────────────────────────────────────┤
│  L4: udp.c ✅       tcp.c          │  ← optional independently
├─────────────────────────────────────┤
│  L3: ipv4.c ✅  icmp.c ✅          │
├─────────────────────────────────────┤
│  L2: arp.c ✅                       │
├─────────────────────────────────────┤
│  L2: eth.c ✅                       │
├─────────────────────────────────────┤
│  MAC driver interface (net_mac.h)   │  ← abstract vtable
├──────────┬──────────┬───────────────┤
│ tap.c ✅ │ bpf.c ✅ │ your_driver.c │
│ (Linux)  │ (macOS)  │ (your HW)     │
└──────────┴──────────┴───────────────┘
```

**Your application owns everything:** buffers, connection state, configuration. The stack provides the protocol logic and operates on your memory.

---

## 📖 Documentation

Detailed design docs and RFC-traced requirements live in [`docs/`](docs/):

- **[Architecture](docs/architecture.md)** — System architecture, layer interaction, data flow
- **[Size Comparison](docs/design/size-comparison.md)** — ARM Cortex-M0 code size: smallest_tcp vs lwIP (4.1× smaller)
- **Design Documents:**
  - [MAC HAL](docs/design/mac-hal.md) — Abstract hardware interface (vtable, peek+discard)
  - [Checksum](docs/design/checksum.md) — Incremental Internet checksum design
  - [Byte Order](docs/design/byte-order.md) — Portable endian handling, 8-bit target strategy
  - [Timer Model](docs/design/timer-model.md) — net_poll, net_tick, tickless support
  - [TCP Buffer](docs/design/tcp-buffer.md) — Stop-and-wait, circular, packet-list strategies
  - [ARP Resolution](docs/design/arp-resolution.md) — Distributed cache, gateway-only mode
  - [Memory Model](docs/design/memory-model.md) — Zero-allocation factory methods
  - [Configuration](docs/design/configuration.md) — Compile-time vs. runtime taxonomy
- **[RFC Requirements](docs/requirements/)** — 785 requirements traced to RFC sections across 16 protocol specifications
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
