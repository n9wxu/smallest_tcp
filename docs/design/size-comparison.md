# Code Size Comparison — smallest_tcp vs lwIP

**Last updated:** 2026-09-25 (Milestones 1–9; UDP comparison re-measured, TCP configuration added)

## Methodology

Both stacks compiled for **ARM Cortex-M0** (representative of STM32F042, CH32X033) with identical optimization flags:

```
arm-none-eabi-gcc -std=c99 -Os -mthumb -mcpu=cortex-m0
                  -ffreestanding -ffunction-sections -fdata-sections
```

- **smallest_tcp:** Linked ELF with `-Wl,--gc-sections`, debug logging disabled (`-DNET_DEBUG=0`)
- **lwIP:** 2.2.1 (`STABLE-2_2_1_RELEASE`), object files compiled with matching flags, minimal `lwipopts.h` (see below)
- **Feature set:** ETH + ARP + IPv4 + ICMP + UDP (no TCP, no DHCP, no DNS); smallest_tcp built with `-DNET_USE_TCP=0`
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
| **Flash (code + rodata)** | **2,822 B** | 10,089 B | **3.6× smaller** |
| **RAM (static state)** | **672 B** | 2,619 B | **3.9× smaller** |
| Stack-only code | **2,604 B** | 10,087 B | **3.9× smaller** |
| Stack-internal RAM | **10 B** | ~2,619 B | **262× smaller** |
| Source modules | 7 | 16 | — |

> **Note:** smallest_tcp's 672 B of RAM includes 600 bytes of application-owned rx/tx buffers.
> The stack itself uses only 10 bytes of static state (IP ID counter + UDP port table pointer).
> lwIP's 2,619 B of BSS is internal memory pools (mem, memp, pbuf_pool, ARP table, etc.).

## Per-Module Breakdown

### smallest_tcp — 7 modules, 2,604 bytes code

| Module | .text | .data | .bss | Function |
|--------|------:|------:|-----:|----------|
| `net.c` | 234 | 0 | 0 | Core context init, `net_poll()`, MAC helpers |
| `net_cksum.c` | 158 | 0 | 0 | Internet checksum (RFC 1071) |
| `eth.c` | 234 | 0 | 0 | Ethernet II parse/build/dispatch |
| `arp.c` | 480 | 0 | 0 | ARP request/reply, gateway MAC |
| `ipv4.c` | 564 | 0 | 2 | IPv4 parse/build, protocol dispatch, Protocol Unreachable |
| `icmp.c` | 382 | 0 | 0 | ICMP echo reply, dest unreachable |
| `udp.c` | 552 | 0 | 8 | UDP parse/send, port dispatch |
| **Total** | **2,604** | **0** | **10** | |

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
| ARP | 480 B | 1,644 B | 3.4× |
| IPv4 | 564 B | 922 B | 1.6× |
| ICMP | 382 B | 504 B | 1.3× |
| UDP | 552 B | 1,280 B | 2.3× |
| Checksum | 158 B | 532 B | 3.4× |
| Ethernet | 234 B | 264 B | 1.1× |
| **Subtotal** | **2,370 B** | **5,146 B** | **2.2×** |

Even protocol-for-protocol, smallest_tcp is 2.2× smaller due to:
- No pbuf chain traversal (operates on flat buffers)
- No ARP cache table (distributed to connection structs)
- No general-purpose netif callbacks
- Simpler API (direct function calls vs. callback chains)

## Adding TCP

`make arm-size-tcp` builds the same benchmark with TCP enabled: a single-connection
TCP echo server on port 7 using the stop-and-wait buffers (128 B TX + 128 B RX),
alongside the UDP echo server.

| Metric | UDP only | UDP + TCP | Delta |
|--------|---------:|----------:|------:|
| **Flash (code + rodata)** | 2,822 B | **7,114 B** | +4,292 B |
| **RAM (static state)** | 672 B | **1,080 B** | +408 B |
| Stack-only code | 2,604 B | 6,600 B | +3,996 B |
| Stack-internal RAM | 10 B | 22 B | +12 B |

| Module | .text | .data | .bss | Function |
|--------|------:|------:|-----:|----------|
| `tcp.c` | 3,530 | 4 | 8 | Full state machine, retransmit, persist timer, MSS/window |
| `tcp_buf_saw.c` | 450 | 0 | 0 | Stop-and-wait TX/RX buffers |
| `ipv4.c` | 580 | 0 | 2 | (+16 B for TCP dispatch) |

The extra RAM is application-owned: the 256 B of TCP buffers, the `tcp_conn_t`,
and the buffer contexts. TCP itself adds 12 bytes of static state (connection
table pointer + ISN counter).

## Target Fit Analysis

| Target | Flash | RAM | smallest_tcp UDP | lwIP UDP |
|--------|-------|-----|-----------------|----------|
| **PIC16F1454** | 14 KB | 1 KB | ✅ 2.8 KB + buffers | ❌ 10 KB code alone |
| **CH32X033** | 62 KB | 20 KB | ✅ Plenty of room | ✅ Fits |
| **STM32F042** | 32 KB | 6 KB | ✅ 2.8 KB; 7.1 KB with TCP | ⚠️ Tight with app |
| **CH32V203** | 256 KB | 10 KB | ✅ Plenty of room | ✅ Fits |

## How to Reproduce

```bash
# Build smallest_tcp for ARM and show sizes
make arm-size        # UDP only (lwIP comparison)
make arm-size-tcp    # UDP + TCP

# Build lwIP for comparison (clones lwIP 2.2.1 into build/lwip if missing)
bash bench/build_lwip.sh
```

### Files

| File | Purpose |
|------|---------|
| `bench/size_measure.c` | Bare-metal app exercising all stack layers |
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

> The UDP-only growth since 2026-03-19 comes from `net_poll()` (Milestone 7), the
> peek-based UDP dispatch, and IPv4 Protocol Unreachable. The ratio column compares
> stack-only code.

## Notes

- lwIP sizes are .o file totals (before link-time gc-sections). Actual linked lwIP would be somewhat smaller depending on which functions the application calls.
- smallest_tcp sizes are from a linked ELF with `--gc-sections`, representing real deployed size.
- Both use nano newlib for memcpy/memset (not counted — same for both).
- Flash totals depend on the toolchain's newlib. The figures here use the Arm GNU Toolchain
  13.2.Rel1, whose `memcpy`/`memset`/`memcmp` total 62 B. Ubuntu's `libnewlib-arm-none-eabi`
  (used by the `arm-size` CI job) ships speed-optimized versions totalling 376 B, so CI reports
  3,140 B (UDP) and 7,572 B (UDP + TCP). Stack-only code is identical on both toolchains.
- lwIP has more features even in minimal config (e.g., ARP queueing infrastructure, pbuf chaining, multi-netif support). smallest_tcp intentionally omits these for size.
