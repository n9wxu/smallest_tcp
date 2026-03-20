# Byte Order Design

**Last updated:** 2026-03-19

## API

```c
// net_endian.h
static inline uint16_t net_htons(uint16_t h);  // host → network (16-bit)
static inline uint16_t net_ntohs(uint16_t n);  // network → host (16-bit)
static inline uint32_t net_htonl(uint32_t h);  // host → network (32-bit)
static inline uint32_t net_ntohl(uint32_t n);  // network → host (32-bit)

// Wire read/write helpers (always big-endian, unaligned-safe)
static inline uint16_t net_read16be(const uint8_t *p);
static inline void     net_write16be(uint8_t *p, uint16_t v);
static inline uint32_t net_read32be(const uint8_t *p);
static inline void     net_write32be(uint8_t *p, uint32_t v);
```

## Implementation

### Wire Helpers (Always Needed)

These operate on byte pointers and are unaligned-safe on all architectures:

```c
static inline uint16_t net_read16be(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | p[1];
}
static inline void net_write16be(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}
```

### Host/Network Order Helpers

For **little-endian** targets (ARM, RISC-V, x86): byte-swap.
For **big-endian** targets: identity (no-op).

### 8-Bit Target Strategy

On 8-bit MCUs (PIC16, PIC18, AVR), there is no native multi-byte register order. We store all multi-byte protocol fields in **network byte order (big-endian)** natively in memory. This means:
- `net_htons()` / `net_htonl()` are **no-ops**
- `net_read16be()` / `net_write16be()` still work correctly
- Saves code and cycles — no byte swapping needed anywhere

This is a documented design choice. Application code on 8-bit targets should be aware that IP addresses and port numbers are stored big-endian.

## Detection

```c
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  #define NET_BIG_ENDIAN 1
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  #define NET_LITTLE_ENDIAN 1
#elif defined(NET_8BIT_TARGET)
  // 8-bit: use big-endian (network order) natively
  #define NET_BIG_ENDIAN 1
#else
  #error "Cannot determine byte order. Define NET_BIG_ENDIAN or NET_LITTLE_ENDIAN."
#endif
```
