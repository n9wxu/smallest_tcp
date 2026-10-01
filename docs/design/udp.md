# UDP Design

**Protocol:** User Datagram Protocol, over IPv4 and IPv6
**Files:** `include/udp.h`, `src/udp.c`
**Primary RFC:** RFC 768; RFC 8200 §8.1 (over IPv6); RFC 1122 §4.1
**Last updated:** 2026-09-27

---

## 1. Overview

UDP carries DHCP, TFTP, mDNS and most application protocols on small
devices.  The implementation:

- **allocates nothing** — datagrams are parsed in `net->rx.buf` and built in
  `net->tx.buf`;
- **dispatches by a port table** the application owns (usually `const`, in
  flash) and binds to the interface with `udp_set_ports()`;
- **hands each handler a pointer** to the payload inside the received frame;
- **sends from the transmit buffer**, either copying the payload in
  (`udp_send()`) or sending one the caller wrote in place
  (`udp_send_inplace*()`).

UDP over IPv4 and over IPv6 share the length checks, the header writer and
the checksum rule, and have separate port tables and entry points.

---

## 2. Header

```
Offset  Size  Field
  0      2    Source port
  2      2    Destination port
  4      2    Length (header + data, ≥ 8)
  6      2    Checksum (0 = none, IPv4 only)
  8      …    Data
```

`udp.h` defines `UDP_OFF_SPORT`, `UDP_OFF_DPORT`, `UDP_OFF_LEN`,
`UDP_OFF_CKSUM` and `UDP_HDR_SIZE`.  Fields are read and written with
`net_read16be()` / `net_write16be()`.

---

## 3. Port tables

```c
typedef void (*udp_handler_t)(net_t *net, uint32_t src_ip, uint16_t src_port,
                              const uint8_t *src_mac, const uint8_t *payload,
                              uint16_t payload_len);

typedef struct udp_port_entry_s {
  uint16_t port;          /* local port, host byte order */
  udp_handler_t handler;
} udp_port_entry_t;

static inline void udp_set_ports(net_t *net, const udp_port_entry_t *ports,
                                 uint8_t count);
```

The table pointer and count live in `net_t` (`udp_ports`, `udp_port_count`).
A port absent from the table is closed.  The table must outlive its binding;
it can be replaced at any time between `net_poll()` calls.

```c
static void echo(net_t *net, uint32_t src_ip, uint16_t src_port,
                 const uint8_t *src_mac, const uint8_t *payload,
                 uint16_t len) {
  udp_send(net, src_ip, src_mac, 7, src_port, payload, len);
}

static const udp_port_entry_t ports[] = {{7, echo}};

udp_set_ports(&net, ports, 1);
```

### Handler contract

- `payload` and `src_mac` point into `net->rx.buf` and are valid **only until
  the handler returns**.  Copy anything needed later.
- Addresses and ports are host byte order; `payload_len` comes from the UDP
  Length field, not the IP length (link padding and trailing bytes are not
  part of the datagram).
- The handler runs inside `net_poll()`, before the driver's frame is
  released (see [mac-hal.md §3](mac-hal.md#3-the-receive-lifecycle-net_poll)):
  keep it short.
- `udp_rx_dst_ip(net)`, called in the handler, gives the datagram's
  destination address: ours, a broadcast or a group (RFC 1122 §4.1.3.5).
- The handler **may send**.  `net->tx.buf` is separate from `net->rx.buf`, so
  `udp_send()` with `payload` as its data (the echo above) is safe, as is
  building a reply in place.  The application protocol modules answer from
  inside their handlers this way (mDNS defers some answers to its tick).

### Dispatch

`udp_input()` scans the table linearly and calls the first entry whose `port`
matches the destination port; one handler per datagram.  Ports are not bound
to addresses: a handler receives the port's datagrams sent to our unicast
address, to broadcast, and to any joined multicast group.  It tells these
apart with `udp_rx_dst_ip()`.

---

## 4. Receive path

```
net_poll()
 └─ eth_input()                          MAC filter, EtherType
     └─ ipv4_input()                     ipv4_parse(): version, lengths, header
         │                               checksum, no fragments; source and
         │                               destination checks
         └─ udp_input()                  protocol 17 (only if NET_USE_UDP)
             ├─ udp_length()             IP payload ≥ 8, 8 ≤ Length ≤ IP payload
             │                           → else drop
             ├─ checksum field ≠ 0 ?     ipv4_cksum() over the datagram must be 0
             │                           → else drop; a zero field is not checked
             ├─ port table scan          match → handler(net, src_ip, src_port,
             │                                    src_mac, payload, len)
             └─ no match                 icmp_send_dest_unreach(PORT_UNREACH)
```

### ICMP Port Unreachable

On a port miss `udp_input()` calls
`icmp_send_dest_unreach(net, ICMP_CODE_PORT_UNREACH, ip, eth)` unconditionally;
the ICMP layer decides.  It quotes the invoking IP header plus up to 8 bytes
of its payload (the UDP header), and it **sends nothing** about a datagram
sent to a broadcast or multicast IP address or received in a
broadcast/multicast frame (RFC 1122 §3.2.2).  So a broadcast to a closed port
is dropped silently, and every caller gets the rule for free.

### ICMP errors to the application

`icmp_input()` takes Destination Unreachable, Time Exceeded and Parameter
Problem (Source Quench is discarded, RFC 6633) and, if the quoted IPv4
header is whole and its source is our address, hands the error to the
transport the quoted header names (RFC 1122 §3.2.2).  For UDP,
`udp_icmp_error()` reads the quoted ports and calls the handler set with
`udp_set_error_handler()`:

```c
typedef struct {
  uint16_t local_port, dst_port; /* from the quoted UDP header */
  uint32_t dst_ip;
  uint8_t type, code;            /* ICMP */
  uint16_t mtu;                  /* Fragmentation Needed: next-hop MTU */
  const uint8_t *quote;          /* the quoted IP header and data */
  uint16_t quote_len;
} udp_icmp_error_t;
```

One handler per interface, not one per port: a port table entry with a
second function would make every application initializer name it.  The
handler is stored in `net_t` as `void (*)(void)` (net.h cannot see
`udp.h`'s types) and converted back to be called.  Without a handler the
error is dropped.  The quote, like a payload, is valid only until the
handler returns.

---

## 5. Transmit path

```c
/* Copy data_len bytes from data; send from net->ipv4_addr, NET_DEFAULT_TTL */
net_err_t udp_send(net_t *net, uint32_t dst_ip, const uint8_t *dst_mac,
                   uint16_t src_port, uint16_t dst_port,
                   const uint8_t *data, uint16_t data_len);

/* The payload is already at net->tx.buf + UDP_PAYLOAD_OFFSET */
net_err_t udp_send_inplace(net_t *net, uint32_t dst_ip, const uint8_t *dst_mac,
                           uint16_t src_port, uint16_t dst_port,
                           uint16_t data_len, uint8_t ttl);

/* The same, from an explicit IPv4 source address: ours or 0.0.0.0 */
net_err_t udp_send_inplace_from(net_t *net, uint32_t src_ip, uint32_t dst_ip,
                                const uint8_t *dst_mac, uint16_t src_port,
                                uint16_t dst_port, uint16_t data_len,
                                uint8_t ttl);

/* The same, with the source, TTL and TOS in udp_tx_opts_t */
net_err_t udp_send_inplace_opts(net_t *net, uint32_t dst_ip,
                                const uint8_t *dst_mac, uint16_t src_port,
                                uint16_t dst_port, uint16_t data_len,
                                const udp_tx_opts_t *opts);
```

All four end in `udp_send_inplace_opts()`, which builds the frame around the
payload:

```
net->tx.buf
┌────────────┬─────────────┬────────────┬──────────────────────┐
│ Ethernet   │ IPv4        │ UDP        │ payload              │
│ 14         │ 20          │ 8          │ data_len             │
└────────────┴─────────────┴────────────┴──────────────────────┘
                                         ↑ UDP_PAYLOAD_OFFSET = 42
```

1. Size check: `42 + data_len` within `tx.capacity` and within one Ethernet
   frame (1514 bytes: 1472 bytes of payload, 1452 over IPv6), else
   `NET_ERR_BUF_TOO_SMALL` — every datagram goes with DF set and is never
   fragmented, however large the frame buffer.  `NET_ERR_INVALID_PARAM`
   refuses a TTL of 0 (RFC 1122 §3.2.1.7), a source other than
   `net->ipv4_addr` or 0.0.0.0 (§4.1.3.6), a destination of 0.0.0.0, an
   address in 127/8 at either end (§3.2.1.3), and the broadcast MAC with a
   destination that is no IP broadcast or multicast (§3.3.6).
2. UDP header, checksum field 0; then the checksum over the pseudo-header,
   header and payload (`ipv4_cksum()`), a computed 0 written as `0xFFFF`.
3. Ethernet header to `dst_mac`.
4. IPv4 header (`ipv4_build_tos()`: DF set, ID 0, the TTL and TOS,
   header checksum).
5. `net_transmit()`.

Notes:

- **The caller supplies `dst_mac`.**  UDP does no address resolution; see
  [arp-resolution.md](arp-resolution.md).  A reply normally uses the
  `src_mac` its handler was given.
- **Protocols with larger messages build in place.**  DHCP, TFTP and mDNS
  write their message at `net->tx.buf + UDP_PAYLOAD_OFFSET` and call
  `udp_send_inplace*()`, so the payload is never copied.  `udp_send()`'s
  `data` must not point into `net->tx.buf` itself.
- **Why `udp_send_inplace_from()`.**  A DHCP client must send from 0.0.0.0
  until its lease is bound (and from its leased address when renewing), and
  the DHCP server sends from its configured address — which must be the
  host's (`dhcpv4_server_init()` checks).  They pass that address
  explicitly; previously the modules overwrote `net->ipv4_addr` around each
  send, which briefly changed the interface's address for everything else.
- **TTL.**  `udp_send()` uses `NET_DEFAULT_TTL`; mDNS passes 255
  (RFC 6762 §11).

Buffer sizing: the TX buffer must hold `42 + largest payload` (342 bytes for
DHCP, whose messages are padded to 300 bytes).  The RX buffer must hold
`42 + largest datagram` accepted; larger frames are truncated by `net_poll()`
and then rejected by IPv4.

---

## 6. Checksum rules

| | IPv4 | IPv6 |
|---|---|---|
| Pseudo-header | `ipv4_cksum()`: source, destination, protocol 17, UDP length | `ipv6_cksum()`: source, destination, UDP length, next header 17 |
| Sending | Always computed; a computed 0 is sent as `0xFFFF` (RFC 768) | Same |
| Receiving, field = 0 | "No checksum": accepted without verification | Invalid: dropped (RFC 8200 §8.1) |
| Receiving, field ≠ 0 | The checksum over the datagram as received must be 0 | Same |

Why "must be 0" and why `0xFFFF` also verifies: see
[checksum.md §3](checksum.md#3-verifying-why-a-valid-packet-sums-to-0).

---

## 7. UDP over IPv6

Enabled by `NET_USE_IPV6` (with `NET_USE_UDP`).  In an IPv6-only build
(`NET_USE_IPV4` 0) it is all there is: `udp_set_ports()`, `udp_send()` and
the other IPv4 functions, `UDP_PAYLOAD_OFFSET` and the IPv4 port table are
not declared.

```c
typedef void (*udp6_handler_t)(net_t *net, const uint8_t *src_ip,
                               uint16_t src_port, const uint8_t *src_mac,
                               const uint8_t *payload, uint16_t payload_len);
typedef struct udp6_port_entry_s { uint16_t port; udp6_handler_t handler; }
    udp6_port_entry_t;

void udp6_set_ports(net_t *net, const udp6_port_entry_t *ports, uint8_t count);
net_err_t udp6_send(net_t *net, const uint8_t *dst_ip, const uint8_t *dst_mac,
                    uint16_t src_port, uint16_t dst_port,
                    const uint8_t *data, uint16_t data_len);
net_err_t udp6_send_inplace(net_t *net, const uint8_t *dst_ip,
                            const uint8_t *dst_mac, uint16_t src_port,
                            uint16_t dst_port, uint16_t data_len,
                            uint8_t hop_limit);
```

- **A separate table.**  The IPv6 handler gets the 16-byte source address
  (valid, like the payload, during the call).  A port missing from the IPv6
  table is closed over IPv6 even if it is open over IPv4; register a handler
  in both tables to serve both (mDNS does).  Keeping `udp_port_entry_t` at
  two fields means existing positional `{port, handler}` initializers stay
  warning-free under `-Wextra`.
- **Receive.**  `udp6_input()` applies the same length checks, drops a zero
  checksum, and verifies with `ipv6_cksum()`.  A port miss calls
  `icmpv6_send_error(ICMPV6_DEST_UNREACH, ICMPV6_CODE_PORT_UNREACH, …)`, which
  enforces RFC 4443 §2.4(e) itself (nothing about a packet sent to a group, to
  a link-layer multicast/broadcast address, or from a multicast or unspecified
  source).
- **Send.**  The source address is always chosen by `ipv6_src_for()`
  (RFC 6724, one interface); if no usable address can reach `dst_ip` the send
  fails with `NET_ERR_INVALID_PARAM`.  There is no `_from` variant: DHCPv6
  sends from the link-local address, which source selection already picks
  for its link-scope destination.  `udp6_send()` uses `net->ip6.hop_limit`
  (from Router Advertisements); `UDP6_PAYLOAD_OFFSET` is 62.

---

## 8. Dependencies and composition

`udp.c` uses `ipv4.h` (`ipv4_cksum()`, `ipv4_build_ttl()`), `eth.h`,
`icmp.h`, `net_cksum.h`, `net_endian.h`, and with IPv6 `ipv6.h` and
`icmpv6.h`.  Nothing in it depends on TCP or on application protocols.

Whether UDP is in the build is decided at compile time: `ipv4_input()` and
`ipv6_input()` call `udp_input()` / `udp6_input()` only under
`NET_USE_UDP`, and `net_t` has its port-table fields only then (`udp.h` does
not compile without them).  With `NET_USE_UDP=0`, a UDP datagram is answered
like any unsupported protocol (ICMP Protocol Unreachable; ICMPv6 Parameter
Problem).  See [configuration.md §5](configuration.md#5-compile-time-protocol-selection).

---

## 9. Not implemented

| Item | Consequence |
|---|---|
| Ephemeral port allocation, port binding, connected sockets | The application picks source and destination ports on every send and filters sources in its handler. |
| Per-address dispatch | One table for every address; the handler reads `udp_rx_dst_ip()`. |
| IP fragmentation | Datagrams are limited by the buffers and the MTU; received fragments are dropped. |
| Receive queues | A datagram is delivered during `net_poll()` or not at all. |
| UDP-Lite, zero-checksum IPv6 tunnels (RFC 6935) | — |

---

## 10. Design decisions

### 10.1 Decision record: payload pointers, not frame offsets

**Decision.**  Handlers receive `const uint8_t *payload`, a pointer into
`net->rx.buf`, valid for the duration of the call.

**Previous design.**  Handlers received a *frame offset* and length and were
expected to call `net->mac_driver->peek(net->mac_ctx, offset, buf, n)` for the
bytes they needed, so that `net->rx.buf` could shrink to a few header bytes
and an SPI MAC would transfer only what the handler read.

**Why it changed.**  That design was only half implemented.  The whole frame
was staged in `net->rx.buf` anyway, because the IP header checksum and the
UDP/TCP checksums are computed over the bytes in memory; nothing ever streamed
a checksum through `peek()`.  So every handler made a *second* copy of a
payload that was already in RAM, into a stack buffer it had to size itself,
and applications had to call into the MAC driver — an interface that should be
private to the stack.  TCP already received a pointer.  Passing the pointer is
the simpler system: one copy per frame, no driver calls in application code,
and the handler sees the whole datagram.

**Cost.**  `net->rx.buf` must hold the largest datagram the device accepts.

**Possible future.**  A true peek-based receive path — each layer peeking its
own header, checksums accumulated over chunked `peek()` reads, a small
`rx.buf` — would suit an ENC28J60-class MAC with frames in its own SRAM.  It
would read payload bytes twice (once for the checksum, once for the handler)
and would need the handler interface revisited, since a pointer into a small
buffer cannot describe a whole datagram.  Nothing in the current code depends
on the old offset interface.

### 10.2 Port tables in `net_t`

The tables were once globals (`udp_ports`, `udp6_ports`).  They are now
fields of `net_t`, bound with `udp_set_ports()` / `udp6_set_ports()`, so the
stack has no global mutable state: two interfaces can have different
services, and tests can set up independent contexts.

### 10.3 Linear scan

Devices open two to six ports.  A linear scan of an `uint8_t`-counted array
costs a few comparisons and no RAM; a hash or a sorted table would cost code
and a rule for keeping it sorted.

### 10.4 Full frame in the transmit buffer

The MAC `send()` takes one contiguous frame, so the payload sits behind the
headers in `net->tx.buf`.  Building in place avoids a copy for the modules
that can; removing the TX buffer's payload area would need scatter-gather
transmit ([mac-hal.md §8](mac-hal.md#8-future-work)).
