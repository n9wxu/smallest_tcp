# Checksum Design

**Last updated:** 2026-03-19

## API

```c
typedef struct { uint32_t sum; } net_cksum_t;

void     net_cksum_init(net_cksum_t *c);
void     net_cksum_add(net_cksum_t *c, const uint8_t *data, uint16_t len);
void     net_cksum_add_u16(net_cksum_t *c, uint16_t val);
void     net_cksum_add_u32(net_cksum_t *c, uint32_t val);
uint16_t net_cksum_finalize(net_cksum_t *c);

// Convenience
uint16_t net_cksum(const uint8_t *data, uint16_t len);
int      net_cksum_verify(const uint8_t *data, uint16_t len);

// Incremental update (RFC 1624)
uint16_t net_cksum_update(uint16_t old_cksum, uint16_t old_val, uint16_t new_val);
```

## Implementation Strategy

- **uint32 accumulator** defers carry folding until `finalize()`. This avoids per-word fold overhead.
- **16-bit word processing** in the inner loop for speed. Handle odd trailing byte specially.
- **Unaligned access safe**: read bytes individually and compose 16-bit words, avoiding alignment faults on ARM/RISC-V.
- **Pseudo-header**: Use `add_u16`/`add_u32` to feed IP addresses and protocol/length without constructing a temporary buffer.

## Hardware Offload Integration

Hardware capabilities are **compile-time `#define`s** (not runtime queries) per the design tenet: prefer compile-time → link-time → run-time. The application's `net_config.h` declares what the MAC hardware supports. Protocol layers use `#if` to select the code path — the compiler eliminates the unused branch entirely:

```c
// TX: IPv4 header checksum
#if NET_MAC_CAP_TX_CKSUM_IPV4
    net_write16be(hdr + 10, 0x0000);  // MAC fills in
#else
    net_write16be(hdr + 10, net_cksum(hdr, 20));  // Software
#endif

// TX: TCP checksum
#if NET_MAC_CAP_TX_CKSUM_TCP
    net_write16be(tcp_hdr + 16, 0x0000);  // MAC fills in
#else
    // Compute over pseudo-header + TCP header + payload
    net_cksum_t c;
    net_cksum_init(&c);
    net_cksum_add_u32(&c, src_ip);
    net_cksum_add_u32(&c, dst_ip);
    net_cksum_add_u16(&c, htons(6));      // protocol
    net_cksum_add_u16(&c, htons(tcp_len));
    net_cksum_add(&c, tcp_hdr, tcp_len);
    net_write16be(tcp_hdr + 16, net_cksum_finalize(&c));
#endif
```

On RX, if `NET_MAC_CAP_RX_CKSUM_OK` is defined as 1, the protocol layer skips verification:

```c
#if !NET_MAC_CAP_RX_CKSUM_OK
    if (!net_cksum_verify(ip_hdr, ip_hdr_len)) {
        return;  // bad checksum, discard
    }
#endif
```

This ensures zero runtime overhead for checksum decisions — the hardware configuration is known at compile time and never changes.
