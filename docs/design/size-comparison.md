# Code Size Comparison — smallest_tcp vs lwIP

**Last updated:** 2026-03-19 (Tasks 1–5: ETH + ARP + IPv4 + ICMP + UDP)

## Methodology

Both stacks compiled for **ARM Cortex-M0** (representative of STM32F042, CH32X033) with identical optimization flags:

```
arm-none-eabi-gcc -std=c99 -Os -mthumb -mcpu=cortex-m0
                  -ffreestanding -ffunction-sections -fdata-sections
```

- **smallest_tcp:** Linked ELF with `-Wl,--gc-sections`, debug logging disabled (`-DNET_DEBUG=0`)
- **lwIP:** Object files compiled with matching flags, minimal `lwipopts.h` (see below)
- **Feature set:** ETH + ARP + IPv4 + ICMP + UDP (no TCP, no DHCP, no DNS)
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
| **Flash (code + rodata)** | **2,650 B** | 10,105 B | **3.8× smaller** |
| **RAM (static state)** | **672 B** | 2,619 B | **3.9× smaller** |
| Stack-only code | **2,460 B** | 10,103 B | **4.1× smaller** |
| Stack-internal RAM | **10 B** | ~2,619 B | **262× smaller** |
| Source modules | 7 | 16 | — |

> **Note:** smallest_tcp's 672 B of RAM includes 600 bytes of application-owned rx/tx buffers.
> The stack itself uses only 10 bytes of static state (IP ID counter + UDP port table pointer).
> lwIP's 2,619 B of BSS is internal memory pools (mem, memp, pbuf_pool, ARP table, etc.).

## Per-Module Breakdown

### smallest_tcp — 7 modules, 2,460 bytes code

| Module | .text | .data | .bss | Function |
|--------|------:|------:|-----:|----------|
| `net.c` | 166 | 0 | 0 | Core context init, MAC helpers |
| `net_cksum.c` | 158 | 0 | 0 | Internet checksum (RFC 1071) |
| `eth.c` | 226 | 0 | 0 | Ethernet II parse/build/dispatch |
| `arp.c` | 480 | 0 | 0 | ARP request/reply, gateway MAC |
| `ipv4.c` | 496 | 0 | 2 | IPv4 parse/build, protocol dispatch |
| `icmp.c` | 382 | 0 | 0 | ICMP echo reply, dest unreachable |
| `udp.c` | 552 | 0 | 8 | UDP parse/send, port dispatch |
| **Total** | **2,460** | **0** | **10** | |

### lwIP — 16 modules, 10,103 bytes code

| Module | .text | .data | .bss | Function |
|--------|------:|------:|-----:|----------|
| `pbuf.c` | 1,706 | 0 | 0 | Packet buffer management |
| `etharp.c` | 1,660 | 0 | 97 | ARP + Ethernet address resolution |
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
| **Total** | **10,103** | **2** | **2,619** | |

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
| ARP | 480 B | 1,660 B | 3.5× |
| IPv4 | 496 B | 922 B | 1.9× |
| ICMP | 382 B | 504 B | 1.3× |
| UDP | 552 B | 1,280 B | 2.3× |
| Checksum | 158 B | 532 B | 3.4× |
| Ethernet | 226 B | 264 B | 1.2× |
| **Subtotal** | **2,294 B** | **5,162 B** | **2.2×** |

Even protocol-for-protocol, smallest_tcp is 2.2× smaller due to:
- No pbuf chain traversal (operates on flat buffers)
- No ARP cache table (distributed to connection structs)
- No general-purpose netif callbacks
- Simpler API (direct function calls vs. callback chains)

## Target Fit Analysis

| Target | Flash | RAM | smallest_tcp UDP | lwIP UDP |
|--------|-------|-----|-----------------|----------|
| **PIC16F1454** | 14 KB | 1 KB | ✅ 2.6 KB + buffers | ❌ 10 KB code alone |
| **CH32X033** | 62 KB | 20 KB | ✅ Plenty of room | ✅ Fits |
| **STM32F042** | 32 KB | 6 KB | ✅ 2.6 KB + room for TCP | ⚠️ Tight with app |
| **CH32V203** | 256 KB | 10 KB | ✅ Plenty of room | ✅ Fits |

## How to Reproduce

```bash
# Build smallest_tcp for ARM and show sizes
make arm-size

# Build lwIP for comparison
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

> This table will be updated as more protocol layers (TCP, DHCP, HTTP) are implemented.

## Notes

- lwIP sizes are .o file totals (before link-time gc-sections). Actual linked lwIP would be somewhat smaller depending on which functions the application calls.
- smallest_tcp sizes are from a linked ELF with `--gc-sections`, representing real deployed size.
- Both use nano newlib for memcpy/memset (not counted — same for both).
- lwIP has more features even in minimal config (e.g., ARP queueing infrastructure, pbuf chaining, multi-netif support). smallest_tcp intentionally omits these for size.
