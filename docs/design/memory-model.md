# Memory Model — Design

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
| `mtu` | The link MTU (`NET_DEFAULT_MTU`): no datagram sent is longer | always |
| `secret`, `random_count` | The 64-bit key of `net_hash()` and the count of `net_random()` outputs ([architecture.md §9](../architecture.md#9-randomness)) | always |
| `ipv4_addr`, `subnet_mask`, `gateway_ipv4` | IPv4 configuration, host byte order; 0 = unconfigured | `NET_USE_IPV4` |
| `gateway_mac`, `gateway_mac_valid`, `gateway_mac_s` | The gateway's MAC, learned from ARP replies, and the seconds until it is out of date (`NET_ARP_GATEWAY_TIMEOUT_MS`) | `NET_USE_IPV4` |
| `arp_recent[]`, `arp_carry_ms` | The targets of recent ARP requests, none requested again within a second (`NET_ARP_RATE_SLOTS`), and ARP's millisecond carry | `NET_USE_IPV4` |
| `mcast_groups[]` | Joined IPv4 groups (0 = free slot; 224.0.0.1, always joined, takes none) | `NET_USE_IPV4` and `NET_MAX_MCAST_GROUPS > 0` |
| `igmp_ops`, `igmp_delay_ms[]`, `igmp_v1_ms` | IGMP, once `igmp_join()` installs it: its input and timer, each group's report delay after a query, and the IGMPv1-querier state (RFC 2236; [mdns.md §10](mdns.md#10-multicast-igmp-and-mld)) | `NET_USE_IPV4` and `NET_MAX_MCAST_GROUPS > 0` |
| `reasm`, `reasm_cap`, `reasm_ops` | The application's reassembly buffer, the data it holds, and reassembly's input and timer — all set by `ipv4_set_reassembly()` | `NET_USE_IPV4` |
| `arp_probe_ip`, `arp_probe_conflict` | An address being checked before use, and whether `arp_input()` saw it in use (RFC 5227; the DHCPv4 client's, [dhcpv4.md §3.1](dhcpv4.md#31-state-machine)) | `NET_USE_IPV4` |
| `ip6` | Address slots with DAD state and lifetimes, hop limit, RA flags, default router, router-solicitation and lifetime timers, MLD timers | `NET_USE_IPV6` |
| `mcast6_groups[][16]` | Joined IPv6 groups (`::` = free slot) | `NET_USE_IPV6` and `NET_MAX_MCAST6_GROUPS > 0` |
| `udp_ports`, `udp_port_count` | The UDP port table | `NET_USE_UDP` and `NET_USE_IPV4` |
| `udp_rx_dst`, `udp_error_handler` | The destination address of the datagram being handled (`udp_rx_dst_ip()`), and where ICMP errors about UDP go (`udp_set_error_handler()`) | `NET_USE_UDP` and `NET_USE_IPV4` |
| `udp6_ports`, `udp6_port_count` | The UDP-over-IPv6 port table | `NET_USE_UDP` and `NET_USE_IPV6` |
| `tcp_conns`, `tcp_conn_count` | The TCP connection table (pointers) | `NET_USE_TCP` |
| `tcp_clock` | 4 µs ticks, advanced by `tcp_tick()`, for initial sequence numbers ([tcp.md §4.6](tcp.md#46-initial-sequence-numbers)) | `NET_USE_TCP` |

Size on Cortex-M0 (`arm-none-eabi-gcc -mcpu=cortex-m0`):

| Configuration | `sizeof(net_t)` |
|---|---|
| IPv4, UDP only, no multicast (the `make arm-size` build) | 116 bytes |
| IPv4, UDP + TCP, one multicast group (the defaults of `net_config.h`) | 144 bytes |
| Dual stack, the other settings default (`NET_USE_IPV6=1`; the CMake default) | 264 bytes |
| IPv6 only (`NET_USE_IPV4=0`, `NET_USE_IPV6=1`) | 176 bytes |

Because the configuration changes this layout, the library and the
application must be built with the same settings
([configuration.md §3](configuration.md#3-library-and-application-must-agree)).

## 3. Frame buffers

`net_init(net, rx_buf, rx_size, tx_buf, tx_size, mac, driver, ctx)` takes
two application buffers.  Every received frame is copied into `rx.buf`
([mac-hal.md §3](mac-hal.md#3-the-receive-lifecycle-net_poll)); every frame
sent is built in `tx.buf`.  The two must not overlap: replies are built in
`tx.buf` while the request is still being read from `rx.buf`.  `net_init()`
refuses buffers that share a byte (`NET_ERR_INVALID_PARAM`); it compares
their addresses as `uintptr_t`, since `<` between pointers into different
objects is undefined in C.

**Receive buffer.**  Must hold the largest frame the device should accept.
A longer frame is truncated and then rejected by IPv4/IPv6, so the buffer
size is the largest datagram the device can receive; 1514 bytes accepts
everything Ethernet carries.  `ipv4_mms_r()` and `ipv4_mms_s()` tell the
transports the largest message each buffer, and the MTU (`net->mtu`,
default `NET_DEFAULT_MTU` 1500), allow (RFC 1122 §3.4).  The TFTP client sizes its requested block to
it (`largest_blksize()` in `tftp.c`).

**Transmit buffer.**  Must hold the largest frame the device builds.  A
message that does not fit is not sent (`NET_ERR_BUF_TOO_SMALL`, or silently
for automatic replies).

| Frame | TX bytes needed |
|---|---|
| ARP reply or request | 42 |
| IGMP report / leave | 46 |
| ICMPv4 echo reply | 34 + the request's ICMP message; a longer reply is truncated to what the buffer and the MTU hold (`ipv4_mms_s()`), and none is sent if not even its 8-byte header fits |
| ICMPv4 Destination Unreachable | 42 + the invoking IP header + up to 8 bytes (70 for an option-less header) |
| UDP over IPv4 / IPv6 | 42 / 62 + payload |
| DHCPv4 (client and server) | 342 (messages are padded to 300 bytes) |
| TCP segment over IPv4 / IPv6 | 54 / 74 + payload (+ 4 on a SYN) |
| ICMPv6 error | Quotes as much of the invoking packet as fits, up to the 1280-byte minimum MTU |

**TCP MSS.**  Each buffer limits TCP in its own direction
(`segment_room()` in `tcp.c`: capacity − 14 − IP header − 20, at most what
the MTU carries, so 1460 over IPv4 and 1440 over IPv6 with the default MTU of
1500).
The MSS we advertise comes from `rx.capacity`, so a peer that honours it never
sends a segment `net_poll()` would truncate; the largest segment we send comes from
`tx.capacity`, and a peer's larger MSS is clamped to it.  The two buffers
need not be equal: either can be the smaller
([tcp.md §4.4](tcp.md#44-segment-size)).

**The smallest buffers.**  With TCP compiled in, `net_init()` refuses a
buffer smaller than `TCP_MIN_FRAME` (`tcp.h`): 94 bytes, or 114 with IPv6 —
an Ethernet and IP header and the longest TCP header, 60 bytes.  The RX
buffer must take any peer's SYN, and a peer may fill its header with 40
bytes of options (Linux's SYN carries 20); a TX buffer of that size carries
40 bytes a segment.  Without TCP, the minimum is an Ethernet header, 14
bytes.

## 4. Per-module memory

Each connection or module instance is an application structure plus any
buffers it is given.  Sizes on Cortex-M0, default configuration (dual stack
in parentheses where it differs):

| Structure | Size | Plus |
|---|---|---|
| `tcp_conn_t` | 104 B (120 B) | A TX and an RX buffer through the buffer operation tables; the bundled stop-and-wait contexts (`tcp_saw_tx_ctx_t`, `tcp_saw_rx_ctx_t`) are 12 B each ([tcp-buffer.md](tcp-buffer.md)) |
| `http_conn_t` (one slot) | 220 B (240 B) | Embeds its `tcp_conn_t` and buffer contexts; needs TCP TX/RX buffers and a request buffer (and a `tls_conn_t` for HTTPS) |
| `http_server_t` | 36 B | The slot array and a `const` route table (and, optional, a clock and the HTTPS host names) |
| `mdns_t` | 96 B | A `const` record table |
| `dhcpv4_client_t` | 64 B | An optional option-handler table |
| `dhcpv4_server_t` | 20 B | A `const dhcpv4_server_cfg_t` |
| `dhcpv6_client_t` | 100 B | An optional option-handler table |
| `tftp_client_t` | 188 B | — (128 B of it is the filename, `TFTP_MAX_FILENAME`) |
| `tls_conn_t` | 448 B | A receive and a transmit buffer ([tls.md §5](tls.md#5-buffers)); a shared `tls_config_t` (44 B) |
| `dtls_conn_t` | 904 B | Its `tls_conn_t` included; a receive and a transmit buffer ([dtls.md §11](dtls.md#11-sizing)) |
| IPv4 reassembly buffer | `IPV4_REASSEMBLY_BUFFER(emtu_r)`: 96 B + `emtu_r` − 20 + a bit per 8 bytes (1600 B for 1500, 661 B for 576) | Optional (`ipv4_set_reassembly()`); 576 complies with RFC 1122 §3.3.2 ([architecture.md §6](../architecture.md)) |

The TCP receive window is the free space in the connection's own RX buffer,
not in `net->rx.buf`: TCP copies arriving data out of the frame during
`net_poll()`.

Stack (automatic) memory is modest; the largest locals are the DHCPv4
client's buffer for joining a split option for its handler
(`DHCPV4_SPLIT_OPTION_MAX`, 255 bytes, which an application may lower —
[dhcpv4.md §3.6](dhcpv4.md#36-option-handlers-and-the-parameter-request-list)),
HTTP's response header (`HTTP_HDR_MAX`, 224 bytes), mDNS's DNS writer
(about 44 bytes with `DNS_COMPRESS_MAX` 16) and MLD's list of reported
groups (16 × (`NET_IPV6_ADDRS` + `NET_MAX_MCAST6_GROUPS`) bytes).

For whole-build flash and RAM figures, see
[size-comparison.md](size-comparison.md).

## 5. Init functions

| Function | Validates | Sets |
|---|---|---|
| `net_init()` | Non-NULL `net`, buffers and driver; buffers that do not overlap; each buffer ≥ `TCP_MIN_FRAME` with TCP compiled in (94 bytes, 114 with IPv6), else ≥ 14 (`NET_ERR_INVALID_PARAM`, `NET_ERR_BUF_TOO_SMALL`) | Zeroes `net_t`; buffers, MAC (argument or `NET_DEFAULT_MAC`), driver, `mtu` (`NET_DEFAULT_MTU`); `NET_DEFAULT_IPV4_ADDR`/`_SUBNET_MASK`/`_GATEWAY` with IPv4; seeds the zeroed `secret` with the MAC address (`net_random_seed()`).  Does **not** call `driver->init()`. |
| `tcp_conn_init()` | Non-NULL connection and buffer tables/contexts | CLOSED, initial RTO, default MSS |
| `tcp_saw_tx_init()`, `tcp_saw_rx_init()` | — | Buffer and capacity |
| `http_conn_init()` | Buffers present and not empty; request buffer ≥ 32 bytes | Slot buffers and its TCP connection |
| `http_server_init()` | At least one slot, a port, routes if `n_routes` | Every slot LISTENing on the port |
| `mdns_init()` | Record count 1..`MDNS_MAX_RECORDS`; each record's type and names; each record fits a packet in the TX buffer on its own (`NET_ERR_BUF_TOO_SMALL`) | STOPPED |
| `dhcpv4_client_init()` | Non-NULL state and `net`; TX ≥ 342 and RX ≥ 590 bytes (`NET_ERR_BUF_TOO_SMALL`) | Zeroed state, callbacks, tables |
| `dhcpv6_client_init()`, `tftp_client_init()` | — | Zeroed state, callbacks, tables |
| `dhcpv4_server_init()` | Non-NULL state, `net` and configuration; the configured `server_ip` is `net->ipv4_addr`; TX and RX ≥ 342 bytes (`NET_ERR_BUF_TOO_SMALL`) | Configuration and callback |

Protocol layers that have no state of their own (Ethernet, ARP, IPv4, ICMP,
UDP) have no init function; their state is in `net_t`.

## 6. Errors

- API calls return `net_err_t`: `NET_OK`, `NET_ERR_BUF_TOO_SMALL`,
  `NET_ERR_INVALID_PARAM`, `NET_ERR_NO_FRAME` (the driver failed to send),
  `NET_ERR_BUSY` (the driver had no room for the frame; try again).
  Check them — especially from `net_init()`.
- Invalid or unwanted received packets are dropped silently, as the RFCs
  require.  With `NET_DEBUG=1`, `NET_LOG()` traces some of the reasons to
  `stderr` on hosted builds.
- There are no run-time assertions.
