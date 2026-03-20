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

The key design insight: on hardware MACs (e.g., ENC28J60 via SPI), reading a full frame is expensive. For ARP/NDP fast-path filtering, we only need to check a few bytes (e.g., the ARP target IP at offset 38). `peek()` reads those bytes via SPI without consuming the frame. If the frame isn't for us, `discard()` drops it without the full read.

For software MACs (TAP, feth+BPF), `recv()` has already read the full frame into the buffer. `peek()` is a `memcpy` from the buffer, and `discard()` is a no-op (the frame is already consumed by `recv`).

## Driver Implementations

| Driver | Platform | peek behavior | discard behavior |
|---|---|---|---|
| `tap.c` | Linux | memcpy from rx buffer | no-op |
| `bpf.c` | macOS | memcpy from rx buffer | advance BPF read pointer |
| `enc28j60.c` | SPI MCU | SPI read at offset | SPI advance RX pointer |
| `cdc_ecm.c` | USB | memcpy from USB buffer | discard USB buffer |

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
