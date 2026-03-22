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
- **Zero-copy RX** — the payload pointer passed to the port handler points
  directly into the MAC receive buffer; no copying is performed
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

Port handlers are registered via a flat array owned by the application:

```c
typedef void (*udp_handler_t)(net_t *net,
                              uint32_t src_ip,  uint16_t src_port,
                              const uint8_t *src_mac,
                              const uint8_t *data, uint16_t data_len);

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

The global `udp_ports` is zero-initialised by default (no handlers).  The
application sets it before entering the main loop:

```c
static const udp_port_entry_t my_ports[] = {
    {  7, udp_echo_handler   },   /* RFC 863 echo   */
    { 68, dhcp_client_handler},   /* DHCP client    */
    {  0, NULL               },   /* sentinel (optional) */
};
udp_ports.entries = my_ports;
udp_ports.count   = 2;
```

### Dispatch rules

- `udp_input()` performs a linear scan over `udp_ports.entries` matching
  `entry.port == dst_port`
- First matching entry wins; only one handler is called per datagram
- For applications with a small number of ports (typical for embedded) linear
  scan is fast and has no overhead beyond a short loop

### Handler contract

The handler is called **synchronously** from within `udp_input()`, which is
itself called from `net_poll()` inside the application's main loop.  The handler
receives:

| Parameter | Description |
|---|---|
| `net` | The network context (same pointer passed everywhere) |
| `src_ip` | Sender's IPv4 address (host byte order) |
| `src_port` | Sender's UDP source port (host byte order) |
| `src_mac` | Sender's Ethernet MAC address (6 bytes) |
| `data` | Pointer to payload bytes in the MAC RX buffer (zero-copy) |
| `data_len` | Payload length in bytes |

**Important:** `data` points into the MAC receive buffer.  The handler MUST NOT
retain this pointer past its return; copy any bytes that need to outlive the
handler call.

---

## 4. Receive Path

```
net_poll()
  └── mac_driver->poll()          frame arrives
  └── mac_driver->peek()          copy frame into net->rx.buf
  └── net_dispatch()
        └── eth_parse()           EtherType dispatch
              └── ipv4_input()    protocol dispatch
                    └── udp_input()
                          │
                          ├── length sanity checks
                          │   • avail < 8         → drop
                          │   • udp_len < 8        → drop
                          │   • udp_len > avail    → drop
                          │
                          ├── checksum verify (if non-zero)
                          │   • compute over pseudo-header + UDP
                          │   • bad checksum       → drop, log
                          │
                          ├── port table scan
                          │   • match found        → call handler (zero-copy)
                          │   • no match, unicast  → ICMP Port Unreachable
                          │   • no match, bcast    → silently drop
                          │
                          └── return
```

### Checksum verification

If the received checksum field is **non-zero**, `udp_input()` verifies it by
recomputing over the IPv4 pseudo-header + full UDP segment:

```
Pseudo-header:
  uint32  src_ip
  uint32  dst_ip
  uint16  0x0011       (zero + protocol = 17)
  uint16  udp_length
UDP header + data (as received)
```

The result must equal `0x0000` or `0xFFFF` (the one's complement of zero).
Any other value causes the datagram to be silently dropped with a log message.

If the checksum field is `0x0000` (checksum disabled), verification is skipped.

### ICMP Port Unreachable

When a unicast datagram arrives for an unregistered port, `udp_input()` calls
`icmp_send_dest_unreach()` with code 3 (Port Unreachable), providing:
- The original IP header (for the ICMP quote-back)
- The first 8 bytes of the original UDP header (RFC 792 requirement)
- The sender's address + MAC (for the ICMP reply destination)

Broadcast and multicast datagrams with no matching handler are silently dropped
— sending ICMP Port Unreachable to a broadcast address would be incorrect per
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

## 8. Design Decisions and Trade-offs

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

### Zero-copy receive
The handler receives a `const uint8_t *data` pointer into the MAC RX buffer.
This avoids a second copy on the hot path but requires handlers to copy any data
they need to retain.  This is an explicit design choice consistent with the
overall zero-copy architecture.
