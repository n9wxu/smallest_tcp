# 🚀 smallest_tcp

**A portable, zero-allocation TCP/IP stack that runs everywhere — from $0.20 microcontrollers to Linux and macOS.**

[![CI — Build & Unit Tests](https://github.com/n9wxu/smallest_tcp/actions/workflows/ci.yml/badge.svg)](https://github.com/n9wxu/smallest_tcp/actions/workflows/ci.yml)

---

## ✨ What Is This?

**smallest_tcp** is a ground-up TCP/IP network stack written in portable C99.  It's designed for one audacious goal: give *any* device with a MAC interface a full networking capability — TCP, UDP, DHCP, HTTP, TFTP — using **zero dynamic memory allocation** and fitting in as little as **3–14 KB of flash**.

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

## 📊 Current Status

### ✅ Milestone 1 — Foundation (Complete!)

The core infrastructure is built, tested, and ready:

| Component | Status | Description |
|---|---|---|
| `net.h` / `net.c` | ✅ Done | Core types, error codes, factory method, defaults from `net_config.h` |
| `net_endian.h` | ✅ Done | Portable byte-order helpers (wire read/write + host/network conversion) |
| `net_cksum.h` / `net_cksum.c` | ✅ Done | RFC 1071 Internet checksum — one-shot, incremental, verify, RFC 1624 update |
| `eth.h` / `eth.c` | ✅ Done | Ethernet II frame parsing + building, zero-copy, 802.3 rejection |
| `net_mac.h` | ✅ Done | Abstract MAC driver interface (init, send, recv, peek, discard, close) |
| `driver/tap.c` | ✅ Done | Linux TAP driver |
| `driver/bpf.c` | ✅ Done | macOS BPF driver (feth pair) |
| Unit tests | ✅ 41 pass | Endian, checksum, Ethernet, net init — all green |
| CMake + FetchContent | ✅ Done | Drop into any CMake project with 3 lines |

### 🔜 Roadmap

| Milestone | What's Coming |
|---|---|
| **2 — ARP** | Fast-path ARP filter, reply, resolve. No bloated cache — MACs live in your connection structs. |
| **3 — IPv4 + ICMP** | `ping` works! IPv4 header parse/build, ICMP echo reply. |
| **4 — UDP** | Datagram send/receive, port dispatch, pseudo-header checksum. |
| **5 — TCP** | Full state machine, app-managed connections, stop-and-wait retransmit. |
| **6 — DHCP** | Auto-configure IP from any DHCP server. |
| **7 — TFTP** | Fetch files over the network — the bootloader data path. |
| **8 — HTTP** | HTTP/1.0 server — browse to your microcontroller! |
| **9 — IPv6** | IPv6 + ICMPv6 + NDP + SLAAC + DHCPv6. |

### 📐 Target Platforms

| Chip | Flash | RAM | Cost | Notes |
|---|---|---|---|---|
| PIC16F1454 | 14 KB | 1 KB | ~$1.20 | Smallest viable target |
| CH32X033 | 62 KB | 20 KB | ~$0.20 | Best bang for the buck, RISC-V |
| CH32V203 | 256 KB | 10 KB | ~$0.50 | Better TinyUSB support |
| STM32F042 | 32 KB | 6 KB | ~$1.00 | Mature ARM ecosystem |
| Linux / macOS | ∞ | ∞ | — | Development & testing via TAP or BPF |

---

## 🔧 Building

### Make (quick & simple)

```bash
make          # Build library + run tests
make lib      # Build static library only
make test     # Build and run unit tests
make clean    # Clean all build artifacts
```

### CMake (recommended for integration)

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

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
| `smallest_tcp::smallest_tcp` | Core stack library (net, checksum, ethernet) |
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
│  L4: udp.c          tcp.c          │  ← optional independently
├─────────────────────────────────────┤
│  L3: ipv4.c   icmp.c               │
├─────────────────────────────────────┤
│  L2: arp.c                          │
├─────────────────────────────────────┤
│  L2: eth.c                          │
├─────────────────────────────────────┤
│  MAC driver interface (net_mac.h)   │  ← abstract vtable
├──────────┬──────────┬───────────────┤
│ tap.c    │ bpf.c    │ your_driver.c │
│ (Linux)  │ (macOS)  │ (your HW)     │
└──────────┴──────────┴───────────────┘
```

**Your application owns everything:** buffers, connection state, configuration. The stack provides the protocol logic and operates on your memory.

---

## 📖 Documentation

Detailed design docs and RFC-traced requirements live in [`docs/`](docs/):

- **[Architecture](docs/architecture.md)** — System architecture, layer interaction, data flow
- **[Design Documents](docs/design/)** — MAC HAL, checksum, byte order, timers, TCP buffers, ARP, memory model, configuration
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
