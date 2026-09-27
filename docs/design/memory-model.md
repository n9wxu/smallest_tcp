# Memory Model — Design

**Last updated:** 2026-09-27

## 1. Principles

- **Zero allocation.**  The stack never calls `malloc()`.  Every object —
  the interface context, frame buffers, connections, module state — is
  declared by the application, usually as a `static`.
- **The application owns everything; the stack owns nothing.**  There is no
  global mutable state in the stack: all of it lives in `net_t` or in a
  module structure the application passed in.  What the stack does keep at
  file scope is `const` (driver tables, well-known addresses such as
  `ipv6_all_nodes`), which on a microcontroller stays in flash.
- **Tables are borrowed, not copied.**  The UDP port tables and the TCP
  connection table are pointers into application memory
  (`udp_set_ports()`, `udp6_set_ports()`, `tcp_set_connections()`); so are
  mDNS record tables, HTTP route tables and DHCP option-handler tables.  They
  must outlive their use and may be `const`.
- **Sizes come from the buffers.**  Protocol limits are derived from the
  buffers the application provides rather than configured separately (§3).
- **Init functions validate and set defaults.**  Each structure has an init
  function that zeroes it, sets its defaults and checks what it can
  (§5).

## 2. The interface context, `net_t`

One `net_t` per network interface (`include/net.h`):

| Field(s) | Purpose | Present when |
|---|---|---|
| `rx`, `tx` | The frame buffers: `{uint8_t *buf; uint16_t capacity;}` each | always |
| `mac`, `mac_driver`, `mac_ctx` | Our MAC address; the driver's table and context | always |
| `rng` | `net_random()` state (xorshift32) | always |
| `ipv4_addr`, `subnet_mask`, `gateway_ipv4` | IPv4 configuration, host byte order; 0 = unconfigured | always |
| `gateway_mac`, `gateway_mac_valid` | The gateway's MAC, learned from ARP replies | always |
| `mcast_groups[]` | Joined IPv4 groups (0 = free slot) | `NET_MAX_MCAST_GROUPS > 0` |
| `ip6` | Address slots with DAD state and lifetimes, hop limit, RA flags, default router, router-solicitation and lifetime timers, MLD timers | `NET_USE_IPV6` |
| `mcast6_groups[][16]` | Joined IPv6 groups (`::` = free slot) | `NET_USE_IPV6` and `NET_MAX_MCAST6_GROUPS > 0` |
| `udp_ports`, `udp_port_count` | The UDP port table | `NET_USE_UDP` |
| `udp6_ports`, `udp6_port_count` | The UDP-over-IPv6 port table | `NET_USE_UDP` and `NET_USE_IPV6` |
| `tcp_conns`, `tcp_conn_count` | The TCP connection table (pointers) | `NET_USE_TCP` |

Size on Cortex-M0 (`arm-none-eabi-gcc -mcpu=cortex-m0`):

| Configuration | `sizeof(net_t)` |
|---|---|
| IPv4, UDP only, no multicast (the `make arm-size` build) | 64 bytes |
| IPv4, UDP + TCP, one multicast group (defaults) | 76 bytes |
| Dual stack, defaults (`NET_USE_IPV6=1`) | 196 bytes |

Because the configuration changes this layout, the library and the
application must be built with the same settings
([configuration.md §3](configuration.md#3-library-and-application-must-agree)).

## 3. Frame buffers

`net_init(net, rx_buf, rx_size, tx_buf, tx_size, mac, driver, ctx)` takes
two application buffers.  Every received frame is copied into `rx.buf`
([mac-hal.md §3](mac-hal.md#3-the-receive-lifecycle-net_poll)); every frame
sent is built in `tx.buf`.  The two must not overlap: replies are built in
`tx.buf` while the request is still being read from `rx.buf`.

**Receive buffer.**  Must hold the largest frame the device should accept.
A longer frame is truncated and then rejected by IPv4/IPv6, so the buffer
size is the largest datagram the device can receive; 1514 bytes accepts
everything Ethernet carries.  The TFTP client sizes its requested block to
it (`largest_blksize()` in `tftp.c`).

**Transmit buffer.**  Must hold the largest frame the device builds.  A
message that does not fit is not sent (`NET_ERR_BUF_TOO_SMALL`, or silently
for automatic replies).

| Frame | TX bytes needed |
|---|---|
| ARP reply or request | 42 |
| IGMP report / leave | 46 |
| ICMPv4 echo reply | 34 + the request's ICMP message (else no reply) |
| ICMPv4 Destination Unreachable | 42 + the invoking IP header + up to 8 bytes (70 for an option-less header) |
| UDP over IPv4 / IPv6 | 42 / 62 + payload |
| DHCPv4 (client and server) | 342 (messages are padded to 300 bytes) |
| TCP segment over IPv4 / IPv6 | 54 / 74 + payload (+ 4 on a SYN) |
| ICMPv6 error | Quotes as much of the invoking packet as fits, up to the 1280-byte minimum MTU |

**TCP MSS.**  The MSS we advertise and the largest segment we send are
both derived from the TX buffer: `tx.capacity − 14 − IP header − 20`, capped
at 1460 (`our_mss()` in `tcp.c`); a peer's larger MSS is clamped to it.  The
advertised MSS invites the peer to send segments that size, so **keep
`rx.capacity ≥ tx.capacity`**, or a full-size segment from the peer will be
truncated and dropped.  The usual choice is two equal buffers.

## 4. Per-module memory

Each connection or module instance is an application structure plus any
buffers it is given.  Sizes on Cortex-M0, default configuration (dual stack
in parentheses where it differs):

| Structure | Size | Plus |
|---|---|---|
| `tcp_conn_t` | 100 B (120 B) | A TX and an RX buffer through the buffer operation tables; the bundled stop-and-wait contexts (`tcp_saw_tx_ctx_t`, `tcp_saw_rx_ctx_t`) are 12 B each ([tcp-buffer.md](tcp-buffer.md)) |
| `http_conn_t` (one slot) | about 200 B (230 B) | Embeds its `tcp_conn_t` and buffer contexts; needs TCP TX/RX buffers and a request buffer (and a `tls_conn_t` for HTTPS) |
| `http_server_t` | 24 B | The slot array and a `const` route table |
| `mdns_t` | 44 B | A `const` record table |
| `dhcpv4_client_t` | 48 B | An optional option-handler table |
| `dhcpv4_server_t` | 12 B | A `const dhcpv4_server_cfg_t` |
| `dhcpv6_client_t` | 100 B | An optional option-handler table |
| `tftp_client_t` | 172 B | — (128 B of it is the filename) |

The TCP receive window is the free space in the connection's own RX buffer,
not in `net->rx.buf`: TCP copies arriving data out of the frame during
`net_poll()`.

Stack (automatic) memory is modest; the largest locals are HTTP's response
header (`HTTP_HDR_MAX`, 192 bytes), mDNS's DNS writer (about 44 bytes with
`DNS_COMPRESS_MAX` 16) and MLD's list of reported groups
(16 × (`NET_IPV6_ADDRS` + `NET_MAX_MCAST6_GROUPS`) bytes).

For whole-build flash and RAM figures, see
[size-comparison.md](size-comparison.md).

## 5. Init functions

| Function | Validates | Sets |
|---|---|---|
| `net_init()` | Non-NULL `net`, buffers and driver; each buffer ≥ 14 bytes (`NET_ERR_INVALID_PARAM`, `NET_ERR_BUF_TOO_SMALL`) | Zeroes `net_t`; buffers, MAC (argument or `NET_DEFAULT_MAC`), driver; `NET_DEFAULT_IPV4_ADDR`/`_SUBNET_MASK`/`_GATEWAY`; seeds `rng` from the MAC.  Does **not** call `driver->init()`. |
| `tcp_conn_init()` | Non-NULL connection and buffer tables/contexts | CLOSED, initial RTO, default MSS |
| `tcp_saw_tx_init()`, `tcp_saw_rx_init()` | — | Buffer and capacity |
| `http_conn_init()` | Buffers present; request buffer ≥ 32 bytes | Slot buffers and its TCP connection |
| `http_server_init()` | At least one slot, a port, routes if `n_routes` | Every slot LISTENing on the port |
| `mdns_init()` | Record count 1..`MDNS_MAX_RECORDS`; each record's type and names | STOPPED |
| `dhcpv4_client_init()`, `dhcpv6_client_init()`, `tftp_client_init()` | — | Zeroed state, callbacks, tables |
| `dhcpv4_server_init()` | — | Configuration and callback |

Protocol layers that have no state of their own (Ethernet, ARP, IPv4, ICMP,
UDP) have no init function; their state is in `net_t`.

## 6. Errors

- API calls return `net_err_t`: `NET_OK`, `NET_ERR_BUF_TOO_SMALL`,
  `NET_ERR_INVALID_PARAM`, `NET_ERR_NO_FRAME` (the driver failed to send).
  Check them — especially from `net_init()`.
- Invalid or unwanted received packets are dropped silently, as the RFCs
  require.  With `NET_DEBUG=1`, `NET_LOG()` traces some of the reasons to
  `stderr` on hosted builds.
- There are no run-time assertions (`NET_ASSERT` was removed).
