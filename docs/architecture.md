# Architecture — smallest_tcp

smallest_tcp is a TCP/IP stack in portable C99 for devices from small
microcontrollers up to Linux and macOS hosts.  This document describes how
it is put together and why; the design documents under
[`design/`](design/) go deeper into each part, and the RFC-traced
requirements are under [`requirements/`](requirements/).

## 1. Principles

| Principle | What it means in the code |
|---|---|
| **Zero allocation** | The stack never calls `malloc()`.  The application declares every buffer and structure; init functions validate and prepare them ([memory-model.md](design/memory-model.md)). |
| **No global mutable state** | All state lives in `net_t` or in structures the application passes in.  File-scope data is `const`. |
| **Application-sized buffers** | Limits follow from the buffers the application provides: the TCP MSS we advertise from the RX buffer and the segments we send from the TX buffer, TFTP block size from the RX buffer, the largest datagram from both. |
| **Parse and build in place** | A received frame is copied once, from the MAC driver into `net->rx.buf`, and parsed where it lies.  Outgoing frames are built in place in `net->tx.buf`; application data is copied into the frame once (by `udp_send()`, or from a TCP connection's buffer), and modules write their messages there directly. |
| **Compile-time composition of the core, link-time for the rest** | IPv6 and the two transports are compiled in or out; the application protocols are separate libraries that are linked or not (§2). |
| **Abstract MAC** | The hardware is reached through one six-function interface, `net_mac_t` ([mac-hal.md](design/mac-hal.md)). |
| **RFC-driven** | Behaviour is traced to numbered requirements (`REQ-UDP-009`), and those to tests. |
| **Portable C99** | No compiler extensions, no packed structs, no run-time division ([coding-rules.md](design/coding-rules.md)). |
| **Single-threaded** | The stack is not reentrant; the application serializes every call (§13). |

## 2. Composition

The core — Ethernet, ARP, IPv4, ICMP, UDP, TCP, and optionally IPv6 with
ICMPv6, NDP and MLD — is composed **at compile time**:

- `eth.c` dispatches to ARP/IPv4 under `NET_USE_IPV4` and to IPv6 under
  `NET_USE_IPV6` — either may be 0, for an IPv4-only or an IPv6-only stack
  ([configuration.md §5](design/configuration.md#5-compile-time-protocol-selection));
- `ipv4.c` and `ipv6.c` dispatch to UDP under `NET_USE_UDP` and to TCP under
  `NET_USE_TCP`.

Those dispatches are references — and so are the calls with which
`icmp.c` and `icmpv6.c` hand a received error to the transport it is
about — so linking IPv4 or IPv6 pulls in `udp.o` and `tcp.o` unless the
build switches the transport off with `-DNET_USE_UDP=0` or
`-DNET_USE_TCP=0` and leaves its source out (CMake: the options
`SMALLEST_TCP_UDP` and `SMALLEST_TCP_TCP`).  For the transport layer,
"link only what you need" is really "configure what you need".  The same
switches change `net_t`, so the library and the application must be built
with the same settings ([configuration.md](design/configuration.md)).

The application protocols — DHCPv4 client and server, DHCPv6 client, TFTP
client, mDNS/DNS-SD, HTTP, TLS, DTLS — are composed **at link time**.  The core
never refers to them; the application calls them and routes their traffic to
them, and an unused one is simply not linked.  Each is its own CMake library
(`smallest_tcp::dhcpv4_client`, `::mdns`, `::http`, `::tls`, …).

## 3. Layers

```
┌──────────────────────────────────────────────────────────────────────┐
│ Application — owns net_t, frame buffers, connections, module state   │
├──────────────────────────────────────────────────────────────────────┤
│ Application protocols (link-time)                                    │
│   dhcpv4_client  dhcpv4_server  dhcpv6_client  tftp                  │
│   mdns (+ dns_wire, igmp)  http (+ http_tls)                         │
├──────────────────────────────────────────────────────────────────────┤
│ TLS 1.3 over a tcp_conn_t, DTLS 1.3 over datagrams (link-time):      │
│   one handshake, two record layers; crypto via tls_crypto_t          │
├────────────────────────────────┬─────────────────────────────────────┤
│ udp.c          [NET_USE_UDP]   │ tcp.c, tcp_buf_saw.c  [NET_USE_TCP] │
├────────────────────────────────┼─────────────────────────────────────┤
│ IPv4: ipv4.c  icmp.c  arp.c    │ IPv6: ipv6.c icmpv6.c ndp.c mld.c   │
│       (igmp.c)                 │                     [NET_USE_IPV6]  │
├────────────────────────────────┴─────────────────────────────────────┤
│ eth.c — Ethernet II: MAC filter, EtherType dispatch                  │
├──────────────────────────────────────────────────────────────────────┤
│ net.c — net_init, net_poll, net_tick, net_transmit, net_random       │
│ support: net_cksum.c  net_text.c  net_endian.h                       │
├──────────────────────────────────────────────────────────────────────┤
│ MAC driver interface — net_mac_t (net_mac.h)                         │
├────────────┬──────────────┬────────────┬───────────────┬─────────────┤
│ tap.c      │ rawsock.c    │ bpf.c      │ stm32f4_eth.c │ stub.c      │
│ Linux TAP  │ Linux raw    │ macOS BPF  │ STM32F4 MAC   │ size builds │
└────────────┴──────────────┴────────────┴───────────────┴─────────────┘
```

`igmp.c` sends IGMP joins and leaves for IPv4 multicast; it is only needed by
mDNS and ships in the `mdns` library.  `stm32f4_eth.c` drives the STM32F4's
Ethernet MAC for the NUCLEO-F429ZI board port (`boards/`; built in CI, not
yet run on hardware).  An ENC28J60 (SPI) or USB CDC-ECM driver would sit
beside the bundled ones; none is in the tree yet — the stack has run over
USB CDC-ECM on an RP2040 with a driver kept in that project
([mac-hal.md §7](design/mac-hal.md)).

## 4. The network context: `net_t`

One `net_t` per interface holds everything the core knows:

| Part | Fields |
|---|---|
| Buffers | `rx`, `tx` — `{buf, capacity}`, supplied to `net_init()` |
| Link | `mac`, `mtu`, `mac_driver`, `mac_ctx` |
| Randomness | `secret`, `random_count` (§9) |
| IPv4 | `ipv4_addr`, `subnet_mask`, `gateway_ipv4` (host byte order), `gateway_mac`, `gateway_mac_valid` and its expiry, the ARP request rate limit, `mcast_groups[]` and IGMP's state, the reassembly buffer and operations, the DHCP client's address probe |
| IPv6 | `ip6` — address slots with DAD state and lifetimes, hop limit, RA flags, default router, solicitation, lifetime and MLD timers, the token bucket of the ICMPv6 errors sent; `mcast6_groups[][16]` |
| Dispatch | `udp_ports` / `udp_port_count`, `udp6_ports` / `udp6_port_count`, `tcp_conns` / `tcp_conn_count` — tables the application binds with `udp_set_ports()`, `udp6_set_ports()`, `tcp_set_connections()`; UDP's error handlers (`udp_set_error_handler()`, `udp6_set_error_handler()`) |
| TCP | `tcp_clock` — 4 µs ticks, advanced by `tcp_tick()`, for initial sequence numbers ([tcp.md §4.6](design/tcp.md#46-initial-sequence-numbers)) |

The dispatch tables are the application's, bound into `net_t`, so the stack
has no global mutable state.  On Cortex-M0, `net_t` is 116 bytes for a
UDP-only IPv4 build, 144 with the defaults of `net_config.h` and 268 dual
stack ([memory-model.md](design/memory-model.md)).

## 5. Receive path

`net_poll(net)` owns a received frame from start to finish:

```
net_poll(net)
 ├─ driver->poll()                      a frame waiting? (non-blocking)
 ├─ driver->peek(0, net->rx.buf, len)   the one copy (len clamped to rx.capacity)
 ├─ eth_input()                         our MAC, broadcast or a joined group, not sent by us; EtherType
 │   ├─ arp_input()                     answer requests; learn the gateway's MAC
 │   ├─ ipv4_input()                    header and options; source and destination checks;
 │   │   │                                fragments to reassembly, if installed
 │   │   ├─ icmp_input()                echo replies; errors received → udp_icmp_error(),
 │   │   │                                tcp_icmp_error()
 │   │   ├─ udp_input()                 → port handler (payload pointer)
 │   │   ├─ tcp_input()                 → state machine; data into the connection's
 │   │   │                                RX buffer; on_event
 │   │   ├─ IGMP                        → igmp.c, once a group is joined
 │   │   └─ other protocols             ICMP Protocol Unreachable
 │   └─ ipv6_input()                    ipv6_parse(), extension headers, address checks
 │       ├─ icmpv6_input()              echo; ndp_input(); mld_input(); errors received →
 │       │                                udp6_icmp_error(), tcp6_icmp_error()
 │       ├─ udp6_input(), tcp6_input()
 │       ├─ Routing header, segments left   ICMPv6 Parameter Problem (code 0)
 │       └─ other next headers          ICMPv6 Parameter Problem (code 1)
 └─ driver->discard()                   release the frame
```

Every layer parses in place and passes pointers into `net->rx.buf` upward
(`eth_frame_t`, `ipv4_hdr_t`, `ipv6_hdr_t`).  UDP handlers receive
`const uint8_t *payload`; TCP copies in-order data into the connection's
receive buffer.  Everything a handler is given is valid only until it
returns, and handlers run before `discard()`, so they should be short.

UDP handlers get a pointer, not a frame offset from which to `peek()` the
payload out of the MAC driver themselves: the frame is in `rx.buf` anyway,
since checksums are computed over it, so an offset would cost a second copy
in every handler and expose the driver to applications.  The reasoning
is in [udp.md §10.1](design/udp.md#101-payload-pointers-not-frame-offsets);
the driver side is in [mac-hal.md §3](design/mac-hal.md#3-the-receive-lifecycle-net_poll).

## 6. Transmit path

Every frame is built in place in `net->tx.buf`, from the payload outwards,
and sent with `net_transmit(net, len)`:

1. The payload is written at its final offset (`UDP_PAYLOAD_OFFSET`,
   `UDP6_PAYLOAD_OFFSET`, `ICMPV6_OFFSET`, after the TCP header), either
   directly by the module or copied by `udp_send()` / `tcp_send()`.
2. The transport header, with its checksum over the pseudo-header:
   `ipv4_cksum()` or `ipv6_cksum()` (UDP sends a computed 0 as `0xFFFF`).
3. `eth_build()`, then `ipv4_build()` / `ipv4_build_ttl()` /
   `ipv4_build_tos()` (20 bytes, DF set, ID 0 — every datagram is atomic,
   RFC 6864 §4.1 — header checksum),
   `ipv4_build_router_alert()` (24 bytes with the Router Alert option and
   TTL 1, for IGMP) or `ipv6_build()`.
4. `net_transmit()` hands the frame to `driver->send()`.

Source addresses: IPv4 sends from `net->ipv4_addr`, except
`udp_send_inplace_from()`, which takes the source explicitly (the DHCP client
sends from 0.0.0.0 before it has a lease; the DHCP server from its configured
address).  IPv6 picks the source with `ipv6_src_for()` (RFC 6724), which
has none for the unspecified address: nothing is sent to `::`.

Error reports check their own rules: `icmp_send_dest_unreach()` and
`icmp_send_time_exceeded()` quote the invoking header and up to 8 bytes of
its payload and send nothing about a broadcast or multicast datagram, an
ICMP error, or a source that is no single host (RFC 1122 §3.2.2);
`icmpv6_send_error()` applies RFC 4443 §2.4(e), and §2.4(f): a token
bucket limits the rate of the errors sent — `ICMPV6_ERROR_BURST` at once,
one more every `ICMPV6_ERROR_INTERVAL_MS`, refilled by `icmpv6_tick()` —
and an error held back returns `NET_ERR_BUSY`.  Callers just report.

Received ICMP and ICMPv6 errors about a packet we sent go to the transport
the quoted header names (`udp_icmp_error()`, `tcp_icmp_error()`;
`udp6_icmp_error()`, `tcp6_icmp_error()`).  UDP passes them to the
application's error handler (`udp_set_error_handler()`,
`udp6_set_error_handler()`); the TCP connection treats them as soft or hard
errors and lowers its segment size on Fragmentation Needed or Packet Too
Big.  An ICMPv6 error of a type the stack does not know goes up as well
(RFC 4443 §2.4(a)); a Packet Too Big that reports an MTU below 1280 is
discarded.

`net->tx.buf` holds one frame at a time and is reused by the next send, so
nothing keeps a built frame: TCP retransmits from the connection's TX buffer,
and the DHCP, TFTP and mDNS modules rebuild a message to resend it.  Because
`tx.buf` is separate from `rx.buf`, a handler may send while it still reads
the request.  Nothing is fragmented on the way out: every datagram fits
the MTU (`net->mtu`, `ipv4_mms_s()`) and goes with DF set.

Fragments received are reassembled in a buffer the application gives
(`ipv4_set_reassembly(net, buf, size)`, sized with
`IPV4_REASSEMBLY_BUFFER(emtu_r)`), one datagram at a time; without one
they are dropped.  `ipv4_set_reassembly()` also installs reassembly's code
(`net->reasm_ops`), so a program that never calls it links none of it —
about 800 bytes on Cortex-M0.  The buffer starts with 96 bytes of bookkeeping — the
datagram's key, a 60 s timer (`ipv4_tick()`), the sender's MAC and a copy
of fragment zero's header with 8 bytes of data, which is what Time
Exceeded (code 1) quotes when the timer runs out — then a bitmap of the
8-byte blocks received and the data.  Fragments may come in any order and
overlap; the whole datagram goes up through the same switch as an
unfragmented one, its payload in the reassembly buffer.  `ipv4_mms_r()` is
the larger of what an RX frame and the reassembly buffer hold
(RFC 1122 §3.3.2).

## 7. Address resolution

There is no ARP cache and no IPv6 neighbour cache.  Replies go to the source
MAC of the frame they answer; broadcast and multicast MACs are computed; the
gateway's MAC is learned from its ARP replies and the IPv6 router's from its
Router Advertisements; everything else is supplied by the application when it
opens a conversation (`udp_send()`, `tcp_connect()`, `tftp_client_get()`),
using `arp_next_hop()` and `arp_request()`.  The stack does not retry ARP.
See [arp-resolution.md](design/arp-resolution.md).

## 8. TCP

The application owns each `tcp_conn_t`, binds the set with
`tcp_set_connections()`, and chooses each connection's buffers through two
operation tables (`tcp_txbuf_ops_t`, `tcp_rxbuf_ops_t`); `tcp.c` never touches
buffer memory itself.  The bundled implementation, `tcp_buf_saw.c`, is
stop-and-wait: one segment in flight, a ring buffer for received data.
Received data is accepted in order only (no reassembly queue), every data
segment is acknowledged at once, the retransmission timeout backs off without
RTT measurement, and the only option is MSS.  Events reach the application
through `on_event`, which must not send or close.  See
[tcp.md](design/tcp.md) and [tcp-buffer.md](design/tcp-buffer.md).

## 9. Randomness

The stack has one generator: a keyed pseudo-random function,
HalfSipHash-2-4 with a 32-bit output (the 32-bit-word variant of Aumasson and
Bernstein's SipHash), under a 64-bit secret key in `net->secret`.

```c
void     net_random_seed(net_t *net, const uint8_t *entropy, uint16_t len); /* into the key */
uint32_t net_hash(const net_t *net, const uint8_t *data, uint16_t len);
uint32_t net_random(net_t *net);
uint32_t net_random_below(net_t *net, uint32_t n);     /* [0, n), n ≤ 65536 */
```

- `net_hash()` is HalfSipHash-2-4 of `data` under the key.  `test_net` checks
  it against the algorithm's reference vectors.
- `net_random()` is `net_hash()` of how many outputs came before it
  (`net->random_count`, big-endian), so no two calls hash the same input
  until the 32-bit count wraps.
- `net_random_seed()` replaces the key with two hashes under the old key of
  16 bytes of the entropy, zero-padded, followed by a byte of how many were
  entropy and which word; longer entropy goes in 16 bytes at a time.  Every
  byte counts, and each seed adds to what the key already holds.
- `net_init()` zeroes the key and seeds it with the MAC address.
- `net_random_below()` scales rather than takes a remainder (no division on
  Cortex-M0).

The three kinds of input have different lengths — a 4-byte count, a 17-byte
seed, a 12- or 36-byte TCP connection id — and HalfSipHash puts the length
into its last block, so zero padding cannot make one kind of input the same
message as another.

**Why a keyed hash.**  A small generator such as xorshift32 returns its
whole 32-bit state as every output: anyone who saw one value — a DHCPv4
transaction ID on the wire, the initial sequence number of a SYN,ACK — could
compute every value after it.  An output of a pseudo-random function reveals
nothing of the key or of any other output.  It also serves as the keyed hash
RFC 6528 asks for, so TCP's initial sequence numbers need no second
primitive.  On Cortex-M0 the generator is about 350 bytes of `net.c`
(HalfSipHash, the seed, `net_random()`, `net_random_below()`) and 12 bytes
of `net_t` (the key and the count).

Users: TCP initial sequence numbers, which hash the connection's addresses
and ports with `net_hash()` directly ([tcp.md §4.6](design/tcp.md#46-initial-sequence-numbers));
and through `net_random()`, DHCPv4 and DHCPv6 transaction IDs and the
randomized delays of mDNS (probing, shared-record answers), NDP (DAD, Router
Solicitations), MLD (query responses) and DHCPv6 (start delay, retransmission
jitter).  It is the only generator in the stack.  TLS does not use it; its
randomness comes from the crypto backend.

**Seed it.**  The MAC address differs per device but is public, so an
unseeded device's key — and with it its sequence numbers and transaction IDs
— can be computed by anyone who knows the MAC.  Call `net_random_seed()`
after `net_init()` with real entropy — a hardware RNG, ADC noise, timing
jitter — and again whenever more is available, preferably before TCP
connections are opened (a new key moves every initial sequence number).

**Know its limits.**  The key is 64 bits, which 8 random bytes of seed fill
(RFC 6528 recommends 128, more than HalfSipHash's key holds); the outputs
are 32 bits.  That suits sequence numbers, transaction IDs and delays; it is
not a source for cryptographic keys or nonces.

## 10. Timers

`net_tick(net, elapsed_ms)` runs the stack's own timers, in this order:

- with IPv4 compiled in, `arp_tick()` (the gateway MAC's expiry, the ARP
  request rate limit) and `ipv4_tick()`, which runs two hooks if they are
  installed: reassembly's timeout, installed by `ipv4_set_reassembly()`,
  and IGMP's report delays, installed by `igmp_join()` — a program that
  calls neither links neither;
- with TCP, `tcp_tick()` (retransmission, zero-window probes, TIME-WAIT,
  and the clock of initial sequence numbers);
- with IPv6, `ipv6_tick()`: address and router lifetimes, then
  `icmpv6_tick()` (the bucket of the error rate limit), `mld_tick()`
  (reports and query answers) and `ndp_tick()` (DAD, router solicitation).

Application-owned modules — the DHCP clients, TFTP, mDNS, HTTP, DTLS —
keep their own `*_tick()` functions, because the stack cannot reach their
state; the application calls them with the same elapsed time.  Timers are countdown fields with `net_countdown()`,
`net_countdown16()` and `net_whole_seconds()` as helpers.

There is no `net_next_event_ms()`: tickless operation is not implemented, and
the device must wake at its tick period.  What adding it would take, and the
full timer inventory, are in [timer-model.md](design/timer-model.md).

## 11. Configuration

Every setting is an `#ifndef` default in `net_config.h` (or in a module
header); an application overrides them with `-D` or in a header named by
`NET_CONFIG_FILE`, included first (CMake: `SMALLEST_TCP_CONFIG_FILE`).
Several settings change `net_t`'s layout (`NET_USE_IPV4`, `NET_USE_IPV6`,
`NET_USE_UDP`, `NET_USE_TCP`, `NET_MAX_MCAST_GROUPS`,
`NET_MAX_MCAST6_GROUPS`, `NET_ARP_RATE_SLOTS`, `NET_IPV6_ADDRS`), which is
why library and application must agree.  Identity
defaults (`NET_DEFAULT_IPV4_ADDR`, `_SUBNET_MASK`, `_GATEWAY`, `_MAC`) are
copied into `net_t` by `net_init()` and are ordinary run-time fields after
that.  There are no hardware-capability switches: checksum offload is not
implemented.  See [configuration.md](design/configuration.md).

## 12. Checksums and byte order

All checksums are computed in software with an incremental one's complement
accumulator (`net_cksum.h`); pseudo-headers go through `ipv4_cksum()` and
`ipv6_cksum()`, and a received segment verifies when its checksum finalizes to
0 ([checksum.md](design/checksum.md)).  Wire fields are read and written byte
by byte in network order at any alignment (`net_read16be()` …); addresses are
held in host order for IPv4 and as 16-byte network-order arrays for IPv6
([byte-order.md](design/byte-order.md)).

## 13. Errors, debugging, concurrency

- API calls return `net_err_t` (`NET_OK`, `NET_ERR_BUF_TOO_SMALL`,
  `NET_ERR_INVALID_PARAM`, `NET_ERR_NO_FRAME`, `NET_ERR_BUSY`).
- Malformed, unwanted or unsupported packets are dropped silently, as the
  RFCs require, or answered with the ICMP error the RFCs call for.
- `NET_DEBUG=1` makes `NET_LOG()` trace to `stderr` on hosted builds; it is
  off by default.  There are no run-time assertions.
- The stack is **not reentrant**.  `net_poll()`, `net_tick()`, the module
  ticks and every sending API call must run in one thread or be serialized
  by the application, and none may be called from an interrupt handler.
  Callbacks run inside those calls; TCP's `on_event` must not re-enter the
  stack to send or close.

## 14. Application protocols

| Module | Files | Design |
|---|---|---|
| DHCPv4 client and single-client server | `dhcpv4_client.c`, `dhcpv4_server.c`, `dhcpv4_wire.h` | [dhcpv4.md](design/dhcpv4.md) |
| DHCPv6 client (stateless and stateful) | `dhcpv6_client.c` | [ipv6.md](design/ipv6.md), [requirements/dhcpv6.md](requirements/dhcpv6.md) |
| TFTP client (RFC 1350, blksize) | `tftp.c` | [tftp.md](design/tftp.md) |
| mDNS responder with DNS-SD | `mdns.c`, `dns_wire.c`, `igmp.c` | [mdns.md](design/mdns.md) |
| HTTP/1.0 server, also over TLS | `http.c`, `http_tls.c` | [http.md](design/http.md) |
| TLS 1.3 client and server | `tls*.c`, crypto through `tls_crypto_t` (Mbed TLS backend bundled) | [tls.md](design/tls.md) |
| DTLS 1.3 client and server | `dtls.c` on TLS's handshake and backend | [dtls.md](design/dtls.md) |

All of them follow one integration recipe — init, route traffic to the
module's input function, start, tick — described with a working example in
[integrating-modules.md](integrating-modules.md).  TLS is the exception to
the UDP pattern: a TLS connection rides on a TCP connection, and the
application moves ciphertext between the two.  DTLS follows it: the UDP
handler feeds a peer's datagrams to its connection and sends what the
connection has pending.

## 15. Project structure

```
smallest_tcp/
├── CMakeLists.txt          CMake: core + optional libraries, tests, demos
├── Makefile                Cortex-M0 size builds and the no-division check
├── README.md
├── CHANGELOG.md            what each release changed
├── include/
│   ├── net.h               net_t, net_init/poll/tick/transmit, random, timer helpers
│   ├── net_config.h        compile-time settings
│   ├── net_version.h       the release: NET_VERSION_STRING, NET_VERSION
│   ├── net_mac.h           MAC driver interface
│   ├── net_endian.h        wire field access, byte order
│   ├── net_cksum.h         Internet checksum
│   ├── net_text.h          ASCII helpers: case-insensitive compare, decimal
│   ├── eth.h  arp.h  ipv4.h  icmp.h  igmp.h  udp.h  tcp.h  tcp_buf.h
│   ├── ipv6.h  icmpv6.h  ndp.h  mld.h
│   ├── dhcpv4_client.h  dhcpv4_server.h  dhcpv6_client.h  tftp.h
│   ├── dns_wire.h  mdns.h  http.h  http_tls.h
│   ├── tls*.h  dtls.h      TLS 1.3 and DTLS 1.3, the crypto interface and Mbed TLS backend
│   └── driver/             tap.h  rawsock.h  bpf.h  stm32f4_eth.h  stub.h
├── src/
│   ├── net.c  net_cksum.c  net_text.c
│   ├── eth.c  arp.c  ipv4.c  icmp.c  igmp.c  udp.c  tcp.c  tcp_buf_saw.c
│   ├── ipv6.c  icmpv6.c  ndp.c  mld.c
│   ├── dhcpv4_client.c  dhcpv4_server.c  dhcpv4_wire.h (private)  dhcpv6_client.c
│   ├── tftp.c  dns_wire.c  mdns.c  http.c  http_tls.c
│   ├── tls*.c  dtls.c      TLS 1.3 and DTLS 1.3 (see design/tls.md, dtls.md)
│   └── driver/             tap.c  rawsock.c  bpf.c  stm32f4_eth.c  stub.c
├── demo/                   hosted demos; common/ has the shared main loop
│   ├── common/             demo_loop.h  demo_mac.h  demo_echo.h  demo_ipv6.h  demo_tls.h
│   └── dhcp_echo/  dtls_client/  dtls_echo/  echo_server/  frame_dump/
│       http_demo/  https_demo/  mdns_demo/  tcp_echo/  tftp_client/
│       tls_client/  tls_echo/
├── tests/
│   ├── integration/        the stack through its API on a scripted link (wire.h),
│   │                       traced to the requirements
│   ├── unit/               C unit tests (test_main.h framework), per module or feature
│   ├── blackbox/           pytest + Scapy conformance suites and interop scripts
│   └── tls/                test certificates; RFC 8448 and DTLS label vector generators
├── boards/nucleo-f429zi/   bare-metal port: start-up, clocks, linker script, the
│                           tcp_echo_demo firmware of the hardware fuzz job
├── cmake/                  arm-none-eabi.cmake: cross-compiling the libraries
├── bench/                  Cortex-M0 size measurement (and the lwIP comparison)
├── examples/fetchcontent/  consuming the library with CMake FetchContent
├── scripts/                release.py: the next version, stamping it, its release notes;
│                           trace.py: which tests verify which requirements
└── docs/
    ├── architecture.md     this document
    ├── integrating-modules.md
    ├── test-plan.md  ci-debugging.md  release-process.md
    ├── design/             one document per subsystem
    └── requirements/       RFC-traced requirements per protocol
```

## 16. Design documents

| Topic | Document |
|---|---|
| MAC driver interface, receive lifecycle, drivers | [mac-hal.md](design/mac-hal.md) |
| Memory ownership, `net_t`, buffer sizing | [memory-model.md](design/memory-model.md) |
| Settings and composition | [configuration.md](design/configuration.md) |
| Timers and the main loop | [timer-model.md](design/timer-model.md) |
| Checksums | [checksum.md](design/checksum.md) |
| Byte order | [byte-order.md](design/byte-order.md) |
| Address resolution | [arp-resolution.md](design/arp-resolution.md) |
| UDP | [udp.md](design/udp.md) |
| TCP; its buffers | [tcp.md](design/tcp.md); [tcp-buffer.md](design/tcp-buffer.md) |
| IPv6, NDP, SLAAC, MLD, DHCPv6 | [ipv6.md](design/ipv6.md) |
| Application protocols | [dhcpv4.md](design/dhcpv4.md), [tftp.md](design/tftp.md), [mdns.md](design/mdns.md), [http.md](design/http.md), [tls.md](design/tls.md), [dtls.md](design/dtls.md) |
| Coding rules | [coding-rules.md](design/coding-rules.md) |
| Code size against lwIP | [size-comparison.md](design/size-comparison.md) |

## 17. References

| RFC | Title | Used by |
|---|---|---|
| RFC 768 | UDP | `udp.c` |
| RFC 791 | IPv4 | `ipv4.c` |
| RFC 792 | ICMP | `icmp.c` |
| RFC 826 | ARP | `arp.c` |
| RFC 894 | IP over Ethernet | `eth.c` |
| RFC 1035 | DNS message format | `dns_wire.c` |
| RFC 1071 | Computing the Internet checksum | `net_cksum.c` |
| RFC 1112 | IP multicast | `ipv4.c` |
| RFC 1122 | Host requirements | all layers |
| RFC 1350, RFC 2348 | TFTP, blksize option | `tftp.c` |
| RFC 1624 | Incremental checksum update | `net_cksum.c` |
| RFC 2113 | IP Router Alert | `ipv4.c` |
| RFC 2131, RFC 2132 | DHCPv4 | `dhcpv4_client.c`, `dhcpv4_server.c` |
| RFC 2236 | IGMPv2 (joins and leaves) | `igmp.c` |
| RFC 2464 | IPv6 over Ethernet | `ipv6.h` |
| RFC 2710, RFC 3810 | MLDv1, MLDv2 | `mld.c` |
| RFC 4291 | IPv6 addressing | `ipv6.c` |
| RFC 4443 | ICMPv6 | `icmpv6.c` |
| RFC 4861 | Neighbor Discovery | `ndp.c` |
| RFC 4862 | SLAAC, DAD | `ndp.c`, `ipv6.c` |
| RFC 6528 | TCP initial sequence numbers | `tcp.c` (clock), `net.c` (keyed hash) |
| RFC 6724 | IPv6 source address selection | `ipv6.c` |
| RFC 6762, RFC 6763 | mDNS, DNS-SD | `mdns.c` |
| RFC 6864 | IPv4 ID field | `ipv4.c` |
| RFC 8200 | IPv6 | `ipv6.c` |
| RFC 8415 | DHCPv6 | `dhcpv6_client.c` |
| RFC 8446 | TLS 1.3 | `tls*.c` |
| RFC 9110, RFC 9112 | HTTP semantics, HTTP/1.1 syntax | `http.c` |
| RFC 9147 | DTLS 1.3 | `dtls.c`, the roles in `tls_server.c`, `tls_client.c` |
| RFC 9293 | TCP | `tcp.c` |

Partly implemented: RFC 6298 (initial RTO and back-off, no RTT
estimation), RFC 5227 (the DHCPv4 client's probe of an offered address; no
conflict detection after that).  Not implemented: TCP congestion control
(RFC 5681), TCP extensions (RFC 7323), the DNS stub resolver.
