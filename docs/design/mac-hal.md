# MAC Hardware Abstraction Layer — Design

**Last updated:** 2026-03-19

## Overview

The MAC HAL abstracts the physical network interface, allowing the stack to operate on TAP (Linux), feth+BPF (macOS), ENC28J60 (SPI), CDC-ECM (USB), or any other Ethernet-capable device. The interface uses a vtable (function pointer struct) pattern for C99 compatibility.

## Interface

```c
typedef struct {
    int      (*init)(void *ctx);
    int      (*send)(void *ctx, const uint8_t *frame, uint16_t len);
    int      (*recv)(void *ctx, uint8_t *frame, uint16_t maxlen);
    int      (*peek)(void *ctx, uint16_t offset, uint8_t *buf, uint16_t len);
    void     (*discard)(void *ctx);
    void     (*close)(void *ctx);
} net_mac_t;
```

### Function Semantics

| Function | Returns | Semantics |
|---|---|---|
| `init` | 0 on success, <0 on error | Initialize hardware, bring link up |
| `send` | bytes sent, or <0 on error | Transmit a complete Ethernet frame |
| `recv` | bytes received, or 0 if no frame, <0 on error | Non-blocking receive into caller's buffer |
| `peek` | bytes copied, or <0 on error | Read bytes from current RX frame at offset without consuming |
| `discard` | void | Skip/drop current RX frame without full read |
| `close` | void | Shutdown interface, release resources |

### Hardware Capabilities — Compile-Time, Not Runtime

An embedded system does not dynamically reconfigure its MAC hardware. Therefore hardware capabilities are **compile-time `#define`s** in a per-target configuration header (`net_config.h`), not a runtime function call. This follows the design tenet: **prefer compile-time → link-time → run-time error detection.**

```c
// net_config.h — application provides this, one per target
#define NET_MAC_CAP_TX_CKSUM_IPV4  0  // 1 = HW computes IPv4 header checksum on TX
#define NET_MAC_CAP_TX_CKSUM_TCP   0  // 1 = HW computes TCP checksum on TX
#define NET_MAC_CAP_TX_CKSUM_UDP   0  // 1 = HW computes UDP checksum on TX
#define NET_MAC_CAP_RX_CKSUM_OK    0  // 1 = HW verified RX checksums are correct
```

Protocol layers use `#if` to select the code path at compile time. The compiler eliminates the unused branch entirely — zero runtime overhead:

```c
// In ipv4.c
#if NET_MAC_CAP_TX_CKSUM_IPV4
    net_write16be(hdr + 10, 0x0000);  // MAC fills in checksum
#else
    net_write16be(hdr + 10, net_cksum(hdr, 20));  // Software checksum
#endif
```

**Why not a runtime function?** A runtime `capabilities()` call would:
1. Prevent the compiler from eliminating dead code (both branches compiled).
2. Add a function pointer call on every packet TX/RX.
3. Waste flash on code paths that can never execute on a given target.
4. Be meaningless — the hardware doesn't change at runtime.

## peek + discard Pattern

### Basic fast-path filtering

On hardware MACs (e.g., ENC28J60 via SPI), reading a full frame is expensive.
For ARP/NDP fast-path filtering, we only need a few bytes (e.g., the ARP target
IP at offset 38).  `peek()` reads those bytes via SPI without consuming the
frame.  If the frame isn't for us, `discard()` drops it without the full read.

For software MACs (TAP, feth+BPF), `recv()` has already read the full frame
into the driver's internal buffer.  `peek()` is a `memcpy` from that buffer,
and `discard()` is a no-op (frame already consumed by `recv`).

### Full receive path — peek-based header parsing

The `peek` / `discard` idiom extends beyond ARP filtering to the **entire
receive path**.  Rather than staging the whole frame in `net->rx.buf` before
dispatch, each protocol layer `peek()`s only its own header:

| Layer | peek offset | bytes | Purpose |
|---|---|---|---|
| Ethernet | 0 | 14 | dst_mac, src_mac, EtherType |
| IPv4 | 14 | 20 | src_ip, dst_ip, protocol, length |
| UDP | 14 + ip_hlen | 8 | src_port, dst_port, udp_len, cksum |
| UDP payload | 14 + ip_hlen + 8 | `payload_len` | passed to port handler as offset |
| ARP | 14 | 28 | operation, sender/target IP+MAC |
| ICMP | 14 + 20 | 4 | type, code |

The MAC frame is never staged into a large `net->rx.buf`.  `net->rx.buf` can
therefore shrink from the traditional 1514 bytes down to just enough for the
largest single header region (typically 20 bytes for the IPv4 header).

**UDP port handler contract:** The UDP dispatch layer calls the port handler
with `(src_ip, src_port, src_mac, payload_offset, payload_len)`.  The handler
calls `mac_driver->peek(ctx, payload_offset, buf, n)` for only the bytes it
needs, then returns.  After the handler returns, `udp_input()` calls
`mac_driver->discard()` to release the frame.  See
[docs/design/udp.md §4](udp.md#4-receive-path) for the full receive path
diagram.

### RAM comparison — full-frame staging vs. peek-based dispatch

| Approach | `net->rx.buf` size |
|---|---|
| Current (full-frame staging) | 1514 bytes (max Ethernet frame) |
| Peek-based header parsing | ≤ 20 bytes (largest header region) |
| Handler's receive buffer | allocated on handler's stack, sized to protocol need |

## Driver Implementations

| Driver | Platform | peek behavior | discard behavior |
|---|---|---|---|
| `tap.c` | Linux | memcpy from rx buffer | no-op |
| `bpf.c` | macOS | memcpy from rx buffer | advance BPF read pointer |
| `enc28j60.c` | SPI MCU | SPI read at offset | SPI advance RX pointer |
| `cdc_ecm.c` | USB | memcpy from USB buffer | discard USB buffer |

## Scatter-Gather TX Extension (Future Enhancement)

The current `send(ctx, frame, len)` signature requires the caller to assemble a
complete, contiguous Ethernet frame before transmitting.  This forces the stack
to `memcpy` every payload into `net->tx.buf`, meaning the tx buffer must be
large enough for the full frame including payload (e.g., 618 bytes for DHCP).

For the TFTP bootloader use case — sending 512-byte data blocks that live in
flash — this represents a significant RAM waste on targets with 1 KB total RAM.

The solution is to add an optional scatter-gather entry to the vtable:

```c
/* Iovec descriptor — one memory region */
typedef struct {
    const uint8_t *base;
    uint16_t       len;
} net_iov_t;

/* Optional: send from multiple non-contiguous regions (header + payload) */
int (*send_iov)(void *ctx, const net_iov_t *iov, uint8_t iovcnt);
```

With `send_iov`, the stack builds only the 42-byte ETH+IP+UDP header into
`net->tx.buf` and passes the application's payload pointer directly to the
MAC — no copy.  `net->tx.buf` shrinks from `42 + payload_len` to just 42 bytes.

**Driver implementations:**
- `tap.c`: use `writev(fd, ...)` — Linux supports scatter-gather on TAP file descriptors
- `bpf.c`: BPF `write()` is single-buffer; driver falls back to a small internal combine buffer
- ENC28J60 (SPI): write header bytes via SPI, then payload bytes via SPI — naturally sequential, no staging buffer needed
- DMA MACs (STM32 EMAC, etc.): scatter-gather DMA descriptors natively support multi-region sends

**Backward compatibility:** `send_iov` is an optional vtable field.  When NULL,
the stack falls back to the current `send()` path with memcpy.  Existing drivers
continue to work unchanged.

See [docs/design/udp.md §8](udp.md#8-transmit-buffer--current-limitation-and-the-scatter-gather-path) for the full analysis and RAM savings table.

## Context

Each driver defines its own context struct (e.g., `tap_ctx_t`, `bpf_ctx_t`). The application allocates this and passes `void *ctx` to all MAC functions. The stack never knows the concrete type.

```c
// Example: TAP driver context
typedef struct {
    int fd;              // TAP file descriptor
    uint8_t rx_buf[1514]; // internal read buffer (for peek after recv)
    uint16_t rx_len;     // bytes in rx_buf
} tap_ctx_t;
```
