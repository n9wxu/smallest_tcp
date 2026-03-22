# UDP Design

**Protocol:** User Datagram Protocol  
**Files:** `include/udp.h`, `src/udp.c`  
**Primary RFC:** RFC 768  
**Last updated:** 2026-03-22

---

## 1. Overview

UDP provides a connectionless, unreliable datagram service over IPv4.  It is the
foundation for DHCP, DNS, TFTP, NTP, CoAP, and many other protocols used in
embedded network applications.

The implementation follows the same principles as the rest of the stack:

- **Zero `malloc()`** — no dynamic allocation anywhere in the UDP layer
- **Zero-copy RX** — the port handler receives a MAC frame offset and calls
  `peek()` for only the bytes it needs; no full-frame staging buffer required
- **Static port table** — the application provides a compile-time or
  init-time array of `{port, callback}` entries; no dynamic registration
- **Link only what you need** — `udp.c` is a separate compilation unit;
  a build that omits UDP (e.g., TCP-only) does not link it

---

## 2. UDP Header Format

```
Offset  Size  Field
  0      2    Source Port      (big-endian)
  2      2    Destination Port (big-endian)
  4      2    Length           (header + data, big-endian, minimum 8)
  6      2    Checksum         (pseudo-header + UDP, 0 = not computed)
  8      …    Payload data
```

Header constants in `udp.h`:

```c
#define UDP_OFF_SPORT  0
#define UDP_OFF_DPORT  2
#define UDP_OFF_LEN    4
#define UDP_OFF_CKSUM  6
#define UDP_HDR_SIZE   8
```

All header fields are read and written with `net_read16be()` / `net_write16be()`
from `net_endian.h`, maintaining strict portability to 8-bit MCUs.

---

## 3. Port Dispatch Table

Port handlers are registered via a flat array owned by the application.

### Proposed interface — peek-based dispatch

The handler receives **source information and a MAC frame offset**, not a data
pointer.  To read payload bytes, the handler calls
`net->mac_driver->peek(net->mac_ctx, offset, buf, len)` for only the bytes it
actually needs:

```c
/**
 * Called when a UDP datagram arrives for a registered port.
 *
 * The handler receives where the datagram came from and WHERE the payload
 * begins within the current MAC frame (payload_offset), plus how long it is.
 * To read bytes, call net->mac_driver->peek(net->mac_ctx, payload_offset, buf, n).
 *
 * The handler MUST NOT call discard() — udp_input() does that after returning.
 * The handler MUST NOT retain the payload_offset past its return; the MAC frame
 * is consumed (discard()'d) immediately after the handler returns.
 */
typedef void (*udp_handler_t)(net_t    *net,
                              uint32_t  src_ip,
                              uint16_t  src_port,
                              const uint8_t *src_mac,     /* 6 bytes */
                              uint16_t  payload_offset,   /* byte offset in MAC frame */
                              uint16_t  payload_len);

typedef struct {
    uint16_t       port;     /* local port (host byte order) */
    udp_handler_t  handler;  /* called on matching inbound datagram */
} udp_port_entry_t;

typedef struct {
    const udp_port_entry_t *entries;
    uint8_t                 count;
} udp_port_table_t;

extern udp_port_table_t udp_ports;   /* application sets this */
```

### Handler example — selective peek

The handler reads only what it needs into its own application-provided buffer:

```c
static void echo_handler(net_t *net, uint32_t src_ip, uint16_t src_port,
                          const uint8_t *src_mac,
                          uint16_t offset, uint16_t len) {
    uint8_t buf[64];
    uint16_t n = (len < sizeof(buf)) ? len : sizeof(buf);
    net->mac_driver->peek(net->mac_ctx, offset, buf, n);   /* only n bytes */
    udp_send(net, src_ip, src_mac, 7 /* echo */, src_port, buf, n);
}

static void dhcp_client_handler(net_t *net, uint32_t src_ip, uint16_t src_port,
                                 const uint8_t *src_mac,
                                 uint16_t offset, uint16_t len) {
    uint8_t scratch[576];
    uint16_t n = (len < sizeof(scratch)) ? len : sizeof(scratch);
    net->mac_driver->peek(net->mac_ctx, offset, scratch, n);
    dhcpv4_client_input(&dhcp_cli, src_ip, scratch, n);
}
```

Each handler allocates only as much buffer as it needs.  A handler that only
needs the first 4 bytes of a TFTP header to dispatch on opcode reads 4 bytes,
not 512.  On ENC28J60 over SPI, only those bytes are transferred over the bus.

### Dispatch rules

- `udp_input()` performs a linear scan over `udp_ports.entries` matching
  `entry.port == dst_port`
- First matching entry wins; only one handler is called per datagram
- After the handler returns, `udp_input()` calls `mac_driver->discard()`

### Why not pass a data pointer?

The current implementation passes `const uint8_t *data` pointing into
`net->rx.buf`.  This requires:

1. The entire Ethernet frame to be read into `net->rx.buf` before any dispatch
2. `net->rx.buf` to be large enough for a full frame (1514 bytes typically)
3. On ENC28J60: all 1514 bytes transferred over SPI even if the handler only
   needs 8 bytes

The peek-based interface eliminates the full-frame staging requirement.
`net->rx.buf` shrinks from ≥ 1514 bytes to just enough for header parsing
(54 bytes for ETH+IP+UDP headers), or goes away entirely when all parsing is
done directly via `peek()`.

See §9 for the complete RX path redesign that accompanies this interface change.

---

## 4. Receive Path

The revised receive path parses headers by `peek()`-ing small fixed-size
regions at known offsets.  The MAC frame is **never fully staged in RAM** —
each protocol layer reads only the bytes it needs.

```
net_poll()
  └── mac_driver->poll()               frame available?
  │
  └── eth_input()
        └── peek(0, hdr, 14)            read ETH header
        └── EtherType dispatch
              │
              └── IPv4 → ipv4_input()
                    └── peek(14, hdr, 20)   read IP header
                    └── src_ip, dst_ip, proto, payload_len, ip_hdr_len
                    └── protocol dispatch
                          │
                          └── UDP (proto=17) → udp_input()
                                └── peek(14+ip_hlen, udp_hdr, 8)  read UDP header
                                │
                                ├── length sanity checks
                                │   • udp_len < 8              → discard, drop
                                │   • udp_len > ip payload_len → discard, drop
                                │
                                ├── checksum verify (if cksum field ≠ 0)
                                │   • stream UDP header+payload through
                                │     cksum accumulator via chunked peek()
                                │   • bad checksum              → discard, drop
                                │
                                ├── port table scan (linear, O(n))
                                │   • match found
                                │   │   → handler(net, src_ip, src_port, src_mac,
                                │   │             payload_offset, payload_len)
                                │   │     (handler calls peek() for what it needs)
                                │   │
                                │   • no match, unicast
                                │   │   → peek(14, hdr, ip_hlen+8) for ICMP quote
                                │   │   → icmp_send_dest_unreach()
                                │   │
                                │   • no match, broadcast/multicast
                                │       → silently drop
                                │
                                └── mac_driver->discard()   ← always last
```

`payload_offset` passed to the handler is `14 + ip_hlen + 8` — the byte
offset in the raw MAC frame where the UDP payload begins.

### Checksum verification

If the checksum field is **non-zero**, `udp_input()` streams the UDP header +
payload through the `net_cksum_t` accumulator using chunked `peek()` calls:

```
Pseudo-header included first:
  uint32  src_ip
  uint32  dst_ip
  uint16  0x0011       (zero + protocol = 17)
  uint16  udp_length
Then: peek(udp_offset, chunk, MIN(remaining, CHUNK_SIZE)) in a loop
```

The result must equal `0x0000` or `0xFFFF`.  If not, the frame is discarded.
If the checksum field is `0x0000`, verification is skipped.

**Trade-off:** When checksum verification is followed by the handler also
`peek()`-ing the payload, the payload bytes are read twice from the MAC
(once for checksum, once for the handler).  On SPI MACs this means two
sequential SPI read operations over the same region.  This is the cost of
eliminating the full-frame staging buffer.  For most embedded protocols
(DHCP, CoAP, TFTP) the payload is small enough that this is acceptable.
Handlers that are extremely latency-sensitive may disable RX UDP checksum
verification via `NET_UDP_RX_CKSUM` (compile-time option in `net_config.h`).

### ICMP Port Unreachable

When a unicast datagram arrives for an unregistered port, `udp_input()`
peeks the IP header + 8 bytes of UDP header to construct the ICMP
destination-unreachable quote and calls `icmp_send_dest_unreach()`.

Broadcast and multicast datagrams with no matching handler are silently dropped
— sending ICMP Port Unreachable to a broadcast address is incorrect per
RFC 1122 §3.2.2.

---

## 5. Transmit Path

```c
net_err_t udp_send(net_t *net,
                   uint32_t dst_ip, const uint8_t *dst_mac,
                   uint16_t src_port, uint16_t dst_port,
                   const uint8_t *data, uint16_t data_len);
```

The transmit path builds the complete frame in `net->tx.buf` (the application's
transmit buffer) from inside out:

```
net->tx.buf:
┌─────────────┬──────────────┬────────────┬──────────┐
│  ETH header │  IP header   │ UDP header │ payload  │
│  14 bytes   │  20 bytes    │  8 bytes   │ data_len │
└─────────────┴──────────────┴────────────┴──────────┘
```

Steps:
1. **Size check** — total = 14 + 20 + 8 + `data_len`; if > `net->tx.capacity`
   return `NET_ERR_BUF_TOO_SMALL`
2. **Ethernet header** — `eth_build()` writes dst/src MAC + EtherType 0x0800
3. **UDP header** — source port, destination port, length, checksum = 0
4. **Payload copy** — `memcpy` payload into position (only copy in the entire path)
5. **Checksum** — compute over pseudo-header + full UDP segment; store result;
   if result would be 0x0000, store 0xFFFF (RFC 768)
6. **IPv4 header** — `ipv4_build()` fills in length, protocol=17, src/dst IP,
   and computes the IP header checksum in-place
7. **Send** — `net->mac_driver->send(net->mac_ctx, buf, total)`

The payload `data` pointer may point anywhere (including the RX buffer for
loopback scenarios); the `memcpy` at step 4 is the only allocation-free copy
in the path.

### Buffer constraint

The application must size its `net_t` transmit buffer to hold the largest UDP
datagram it intends to send:

```
tx buffer min size = 14 (ETH) + 20 (IP) + 8 (UDP) + max_payload
                   = 42 + max_payload
```

For DHCP (max payload 576 bytes): 42 + 576 = **618 bytes minimum**.

---

## 6. Checksum Detail

UDP checksum uses the IPv4 pseudo-header (RFC 768):

```
+--------+--------+--------+--------+
|          source address           |  4 bytes
+--------+--------+--------+--------+
|        destination address        |  4 bytes
+--------+--------+--------+--------+
|  zero  |  proto |   UDP length    |  4 bytes (proto = 17 = 0x11)
+--------+--------+--------+--------+
|           UDP header              |  8 bytes
+--------+--------+--------+--------+
|           payload data            |  N bytes
+--------+--------+--------+--------+
```

Computed using the incremental `net_cksum_t` accumulator from `net_cksum.h`:

```c
net_cksum_t c;
net_cksum_init(&c);
net_cksum_add_u32(&c, src_ip);
net_cksum_add_u32(&c, dst_ip);
net_cksum_add_u16(&c, 0x0011);        /* zero + proto 17 */
net_cksum_add_u16(&c, udp_len);
net_cksum_add(&c, udp_hdr, udp_len);  /* header + data */
uint16_t cksum = net_cksum_finalize(&c);
if (cksum == 0x0000) cksum = 0xFFFF;  /* RFC 768: 0 means "not computed" */
```

The same logic is used in both `udp_send()` and for RX verification in
`udp_input()`.  The helper `udp_checksum()` is exposed in `udp.h` for use by
higher-layer protocols (e.g., DHCP) that need to pre-compute a checksum over
their own payload.

---

## 7. Integration with IPv4 and ICMP

```
udp_input()  ←── called by ipv4_input() when protocol == 17
udp_send()   ───► calls ipv4_build() + mac_driver->send()
                  calls icmp_send_dest_unreach() on port miss (unicast only)
```

`udp.c` depends on:
- `ipv4.h` — `ipv4_is_broadcast()`, `ipv4_build()`, `ipv4_hdr_t`
- `eth.h` — `eth_build()`, `eth_frame_t`, `net_mac_is_broadcast()`
- `icmp.h` — `icmp_send_dest_unreach()`
- `net_cksum.h` — `net_cksum_t` and accumulator API
- `net_endian.h` — `net_read16be()` / `net_write16be()`

Nothing in `udp.c` depends on TCP or any L7 protocol.

---

## 8. Transmit Buffer — Current Limitation and the Scatter-Gather Path

### Why the current design needs a full-frame staging buffer

`udp_send()` currently calls:

```c
mac_driver->send(ctx, net->tx.buf, total_len)
```

The MAC `send()` interface takes **one contiguous buffer** containing the complete
Ethernet frame.  Before that call can be made, the stack must assemble the frame
somewhere, which is `net->tx.buf`.  The payload is `memcpy`'d into that buffer
after the 42-byte header region:

```
net->tx.buf (must be ≥ 42 + payload_len):
┌──────────────────────────┬───────────────────┐
│  ETH + IP + UDP headers  │  payload (copy)   │
│       42 bytes           │  data_len bytes   │
└──────────────────────────┴───────────────────┘
```

The staging buffer is an **application memory requirement** — on a PIC16 with
1 KB of total RAM, allocating 618 bytes for a DHCP tx buffer consumes 60% of
the entire RAM budget.

### What the user can't do today

The application cannot currently say "here is my payload in flash; send it
without copying it through RAM."  If the application holds a TFTP data block as
a `const` array in program memory (flash), today it still has to copy it through
a RAM staging buffer.  For a 512-byte TFTP block: 42 + 512 = 554 bytes of RAM
required, even though the payload data never changes.

### The scatter-gather fix

The root cause is the MAC `send(ctx, frame, len)` signature accepting a single
contiguous buffer.  The correct fix is to add **scatter-gather** to the MAC
send interface:

```c
/* Two-region iovec — enough for header + payload (most cases have only 2) */
typedef struct {
    const uint8_t *base;
    uint16_t       len;
} net_iov_t;

/* New MAC vtable entry — replaces or supplements send() */
int (*send_iov)(void *ctx, const net_iov_t *iov, uint8_t iovcnt);
```

With scatter-gather, `udp_send()` would:

1. Build ETH + IP + UDP headers (42 bytes) into a **small header-only area** of
   `net->tx.buf` — just 42 bytes, not 42 + payload_len
2. Call `mac_driver->send_iov(ctx, [{hdr, 42}, {payload, data_len}], 2)` with
   the application's payload pointer **as-is, without copying**

```
net->tx.buf (only 42 bytes needed):
┌──────────────────────────┐
│  ETH + IP + UDP headers  │  ← built here
│       42 bytes           │
└──────────────────────────┘

Application payload (anywhere — RAM or flash):
┌───────────────────┐
│  payload data     │  ← pointer passed directly to MAC, no copy
│  data_len bytes   │
└───────────────────┘
```

### MAC driver scatter-gather implementations

| Driver | send_iov implementation |
|---|---|
| `tap.c` (Linux TAP) | `writev(fd, iov, iovcnt)` — Linux `writev` on a TAP fd works natively |
| `bpf.c` (macOS BPF) | BPF `write()` is single-buffer only; driver allocates a small internal combine buffer or uses `write` twice (BPF BIOCSBLEN can be set small) |
| ENC28J60 (SPI) | Write header bytes to SPI SRAM, then write payload bytes to SPI SRAM sequentially — natively supports two-phase write |
| DMA MAC (STM32 EMAC) | Scatter-gather DMA descriptors point to header + payload regions separately — native hardware support |

### RAM savings at each layer

| Protocol | Current tx_buf needed | With scatter-gather |
|---|---|---|
| ARP reply | 42 bytes | 42 bytes (no payload) |
| ICMP echo | 42 + payload | 42 bytes |
| UDP echo | 42 + payload | 42 bytes |
| DHCP (max 576 B payload) | **618 bytes** | **42 bytes** |
| TFTP (512 B data block from flash) | **554 bytes RAM** | **42 bytes RAM** |

### Implementation plan

The MAC interface change is backward-compatible: keep `send()` for drivers that
cannot support scatter-gather; add `send_iov()` as an optional entry (NULL means
"fall back to combining into tx_buf and calling send").  The stack checks at
init time:

```c
if (net->mac_driver->send_iov)
    mac_driver->send_iov(ctx, iov, 2);   /* zero-copy */
else {
    memcpy(net->tx.buf + hdr_len, payload, payload_len);
    mac_driver->send(ctx, net->tx.buf, total);   /* copy fallback */
}
```

This is tracked as a future enhancement; the current implementation uses the
single-buffer `send()` path.

---

## 9. Design Decisions and Trade-offs

### Linear port scan vs. hash table
A hash table or sorted binary search would be faster for large port tables, but
embedded applications typically register 2–6 ports at most.  A linear scan over
`uint8_t count` entries adds negligible overhead and zero code/data overhead
(no hash state, no sorted array maintenance).

### Global `udp_ports` vs. passed-in table
`udp_ports` is a single global rather than a pointer in `net_t`, because:
- UDP port assignments are process-global (there is one UDP layer per stack)
- It matches the pattern used in existing upper-layer protocols (DHCP, echo, etc.)
- On MCUs, the table lives in flash (read-only) and uses no RAM beyond the pointer

If a future multi-stack configuration is needed, `udp_ports` can be moved into
`net_t` with a one-line change.

### No port binding / port allocation
The stack has no concept of "binding" a port or allocating an ephemeral source
port number.  The application chooses source and destination ports explicitly in
every `udp_send()` call.  For request-response protocols (DHCP, TFTP), the
source port is fixed per RFC (e.g., 68 for DHCP client); for ad-hoc sends, the
application picks a suitable value.

### Zero-copy RX and the peek-based handler interface
Rather than staging the full frame in `net->rx.buf` and handing a pointer to
the handler, the stack passes the handler a `payload_offset` (frame offset)
and `payload_len`.  The handler calls `mac_driver->peek(ctx, offset, buf, n)`
for exactly the bytes it needs.  This eliminates the large RX staging buffer
(`net->rx.buf` can shrink from 1514 bytes to ≤ 54 bytes for ETH+IP+UDP header
parsing).  The handler's receive buffer is stack-allocated inside the handler
and is exactly as large as the handler requires — not sized to the worst-case
frame.

**Symmetric with TX scatter-gather:** Together, peek-based RX dispatch (§4)
and scatter-gather TX (§8) eliminate both the large `net->rx.buf` and the
large `net->tx.buf` staging buffers.  The remaining memory requirement on the
application is:
- **RX:** 54 bytes for header parsing + handler's own application buffer
- **TX:** 42 bytes for header construction + application payload (in place)
