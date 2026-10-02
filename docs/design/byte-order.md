# Byte Order Design

**Files:** `include/net_endian.h`

## API

```c
// net_endian.h

// Wire read/write helpers (always big-endian, unaligned-safe)
static inline uint16_t net_read16be(const uint8_t *p);
static inline void     net_write16be(uint8_t *p, uint16_t v);
static inline uint32_t net_read24be(const uint8_t *p);
static inline void     net_write24be(uint8_t *p, uint32_t v);
static inline uint32_t net_read32be(const uint8_t *p);
static inline void     net_write32be(uint8_t *p, uint32_t v);

// Host/network conversions, for applications
static inline uint16_t net_htons(uint16_t h);  // host → network (16-bit)
static inline uint16_t net_ntohs(uint16_t n);  // network → host (16-bit)
static inline uint32_t net_htonl(uint32_t h);  // host → network (32-bit)
static inline uint32_t net_ntohl(uint32_t n);  // network → host (32-bit)
```

## Implementation

### Wire Helpers

Every protocol field the stack reads or writes goes through these.  They
operate on byte pointers, so they are unaligned-safe and independent of the
host's byte order on all architectures:

```c
static inline uint16_t net_read16be(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}
static inline void net_write16be(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v);
}
```

The 24-bit pair serves the TLS and DTLS handshake lengths.  Values the API
takes and returns — IPv4 addresses (`uint32_t`), ports (`uint16_t`) — are
ordinary host-order integers: `NET_IPV4(10, 0, 0, 2)` is `0x0A000002` on
every target.

### Host/Network Order Helpers

The stack itself does not call `net_htons()` and friends; they are there for
applications that hold a field in network order.

For **little-endian** targets (ARM, RISC-V, x86): byte-swap.
For **big-endian** targets: identity (no-op).

### 8-Bit Targets

A compiler for an 8-bit MCU (PIC16, PIC18, AVR) may not predefine
`__BYTE_ORDER__`.  The application then defines `NET_LITTLE_ENDIAN` or
`NET_BIG_ENDIAN` to match how the compiler lays out a `uint16_t`.  Setting
`NET_8BIT_TARGET` to 1 instead selects `NET_BIG_ENDIAN`, which makes
`net_htons()` / `net_htonl()` no-ops: an application on such a target that
uses them keeps its multi-byte fields in network byte order in memory.  The
wire helpers, and so the stack, do not depend on any of this.

## Detection

```c
#if defined(NET_BIG_ENDIAN) && defined(NET_LITTLE_ENDIAN)
#error "NET_BIG_ENDIAN and NET_LITTLE_ENDIAN are both defined."
#elif defined(NET_BIG_ENDIAN) || defined(NET_LITTLE_ENDIAN)
/* the application says */
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define NET_BIG_ENDIAN 1
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define NET_LITTLE_ENDIAN 1
#elif defined(NET_8BIT_TARGET) && NET_8BIT_TARGET
#define NET_BIG_ENDIAN 1
#else
#error "Cannot determine byte order. Define NET_BIG_ENDIAN or NET_LITTLE_ENDIAN."
#endif
```

The application's own definition comes first, so it also overrides a
compiler's; `NET_8BIT_TARGET` is 0 by default (`net_config.h`).  Two CTest
cases compile these configurations (`byte_order_set_by_hand`,
`byte_order_set_twice`).
