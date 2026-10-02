# Portable Minimal TCP/IP Stack — Plan

This is the project's plan: what the stack is for, the decisions its design
rests on, what is implemented, and what is not.  The design documents under
[`docs/`](docs/) describe each part in detail; [CHANGELOG.md](CHANGELOG.md)
and the git history record how it got here.

## Objective

A general-purpose, portable TCP/IP stack in C99 with:
- Zero dynamic allocation — the application provides all memory
- Application-sized buffers — the stack adapts (MSS, TCP window, TFTP block size)
- Parse and build in place — a received frame is copied once, into the application's receive buffer, and parsed there; replies are built in the transmit buffer
- Strict layering — each protocol is a separate compilation unit.  The network layers (IPv4, IPv6) and the transports (UDP, TCP) are chosen at compile time (`NET_USE_*`, because the layer below dispatches to them), the application protocols at link time ([configuration.md §5](docs/design/configuration.md#5-compile-time-protocol-selection))
- Abstract MAC interface — the stack is transport-agnostic (TAP, raw socket, feth+BPF, an MCU's Ethernet MAC, ENC28J60, CDC-ECM, …)
- Errors caught early — at compile time where possible, then at link time, then at run time (configuration is `#define`s; buffer sizes come from the buffers the application passes in, and the init functions check them)

The use case it is validated against is a TCP/IP bootloader on a small
MCU, but the stack is general-purpose: DHCP, TFTP, mDNS, HTTP, TLS.

## Target Platforms

The stack scales from tiny MCUs to hosted environments:

| Chip | Flash | RAM | Cost | Notes |
|---|---|---|---|---|
| PIC16F1454 | 14 KB | 1 KB | ~$1.20 | Smallest viable target |
| CH32X033 | 62 KB | 20 KB | ~$0.20 | Best cost/capability ratio, RISC-V, QFN20/TSSOP20 |
| CH32V203 | 32+224 KB | 10 KB | ~$0.50 | Better TinyUSB support, RISC-V |
| STM32F042 | 32 KB | 6 KB | ~$1.00 | Mature ecosystem, QFN20 |
| STM32F429 (NUCLEO-F429ZI) | 2 MB | 256 KB | ~$30 (board) | The board port, with the on-chip Ethernet MAC |
| Linux/macOS | unlimited | unlimited | — | Development and test via TAP, raw socket or feth+BPF |

## Architecture

```
┌──────────────────────────────────────────────┐
│           Application                        │
│  (bootloader, web server, etc.)              │
│  Owns all buffers and conn state             │
├──────────────────────────────────────────────┤
│  L7: dhcpv4_client/server  dhcpv6_client     │  ← optional, link what you need
│      tftp  mdns  http (+ http_tls)           │
├──────────────────────────────────────────────┤
│  TLS 1.3 over a tcp_conn_t, DTLS 1.3 over    │  ← optional, link time
│  datagrams: one handshake, two record layers │
├──────────────────────────────────────────────┤
│  L4: udp.c          tcp.c                    │  ← optional, compile time
├──────────────────────────────────────────────┤
│  L3: ipv4.c icmp.c │ ipv6.c icmpv6.c ndp.c   │  ← either or both, compile time
│      arp.c         │ mld.c                   │
├──────────────────────────────────────────────┤
│  L2: eth.c                                   │
├──────────────────────────────────────────────┤
│  MAC driver interface (net_mac.h)            │  ← abstract: function pointers
├──────────────┬─────────────┬─────────────────┤
│ tap.c        │ bpf.c       │ stm32f4_eth.c,  │  ← one per platform
│ rawsock.c    │ (macOS,     │ or yours (e.g.  │
│ (Linux)      │  feth pair) │ ENC28J60, SPI)  │
└──────────────┴─────────────┴─────────────────┘
```

See [docs/architecture.md](docs/architecture.md).

## Key Design Decisions

### Memory Model

All memory is owned and provided by the application (`include/net.h`,
abbreviated):

```c
typedef struct {
    uint8_t *buf;       // frame buffer (rx or tx)
    uint16_t capacity;  // its size
} net_buf_t;

typedef struct {
    net_buf_t rx, tx;               // one frame each way
    uint8_t mac[6];
    uint16_t mtu;
    const net_mac_t *mac_driver;
    void *mac_ctx;
    uint32_t secret[2];             // key of net_hash() / net_random()
    uint32_t random_count;
    uint32_t ipv4_addr, subnet_mask, gateway_ipv4;
    uint8_t gateway_mac[6], gateway_mac_valid;
    // + multicast groups, the reassembly buffer, the IPv6 state
    //   (NET_USE_IPV6), and the application's UDP port tables and TCP
    //   connection table
} net_t;
```

The stack never calls malloc and has no static variables. Buffer sizes
determine protocol parameters:
- TCP MSS = frame buffer − Ethernet header − IP header − 20, at most what
  the MTU carries (1460 over IPv4): the RX buffer for the MSS advertised,
  the TX buffer for the segments sent
- TCP window = the free space in the connection's own receive buffer

See [docs/design/memory-model.md](docs/design/memory-model.md).

### TCP Connection Model

Application-managed: the app declares a `tcp_conn_t` per connection, with
its own TX and RX buffers, and binds an array of pointers to them with
`tcp_set_connections(net, table, count)`.  The stack has no internal
connection pool or table of its own.  The connection carries its peer's
address and MAC (`remote_ip`, `remote_mac`, `mac_valid`), the RFC 9293
send and receive sequence variables, the MSS, its timers, its buffer
operations and an event callback — the full list is in
[docs/design/tcp.md §2.1](docs/design/tcp.md#21-the-connection).

Buffers are reached through two operation tables, so the buffer strategy
is the application's choice; the one implementation is stop-and-wait (one
segment in flight) — [docs/design/tcp-buffer.md](docs/design/tcp-buffer.md).

### ARP Design — Fast Path + No General Cache

**Problem:** On a live Ethernet network, ARP storms from other devices can overflow small MAC RX buffers (e.g., ENC28J60's 8 KB). The device must drain ARP frames as fast as possible.

**Solution ([docs/design/arp-resolution.md](docs/design/arp-resolution.md)):**
- No ARP cache table.  The one MAC the stack learns from ARP is the gateway's (`net_t.gateway_mac`, valid for five minutes after a reply); a TCP connection keeps its peer's MAC for its life (from the peer's SYN, or given to `tcp_connect()`); replies go to the source MAC of the frame they answer.
- Inbound ARP requests: check the target IP; not for us → ignore. For us → reply immediately. Don't store anything from the requester.
- Inbound ARP replies: only one from the gateway's IP is used, to fill in the gateway MAC.
- Outbound ARP: the stack does not resolve on its own.  The application calls `arp_next_hop()` and `arp_request()` and waits for the MAC before an active open (`tcp_connect()`, `tftp_client_get()`, `udp_send()` to a new peer).  No target is requested more than once a second.

**Fast-path RX drain:** The main loop prioritizes emptying the MAC RX buffer over processing: `while (net_poll(&net) > 0) {}` first, then application processing.

### MAC Driver Interface

```c
typedef struct {
    int  (*init)(void *ctx);
    int  (*send)(void *ctx, const uint8_t *frame, uint16_t len);
    int  (*poll)(void *ctx);  // non-blocking, returns frame length or 0 if no frame available
    int  (*peek)(void *ctx, uint16_t offset, uint8_t *buf, uint16_t len);  // read bytes without consuming
    void (*discard)(void *ctx);  // release the current RX frame
    void (*close)(void *ctx);
} net_mac_t;
```

- `net_poll()` in `net.c` calls `poll()` for the frame's length, one `peek()` of the whole frame into `net->rx.buf`, dispatches it, then `discard()`.  The frame is copied once and every layer parses it in place.
- `peek` + `discard` also allow a driver for a hardware MAC with its own buffer (ENC28J60 over SPI) to read only the bytes needed — the ARP target address, say — and discard the rest unread; `net_poll()` does not do that ([docs/design/mac-hal.md](docs/design/mac-hal.md)).
- For TAP, raw sockets and BPF the driver caches the frame: `poll()` reads it and returns its length, `peek` copies from the driver's buffer, `discard` releases it.

### Timers and randomness

Every timer is a countdown field advanced by `net_tick(net, elapsed_ms)`
and the modules' own `*_tick()` functions; there is no timer queue and no
clock source in the stack ([docs/design/timer-model.md](docs/design/timer-model.md)).
Random numbers — TCP initial sequence numbers, transaction IDs, protocol
delays — come from one keyed hash (HalfSipHash-2-4) whose key the
application seeds ([docs/architecture.md §9](docs/architecture.md#9-randomness)).

## Development Platforms

**Linux TAP** (also in a container or VM on macOS):
- `open("/dev/net/tun")`, `ioctl(TUNSETIFF, IFF_TAP | IFF_NO_PI)`
- `read()`/`write()` raw Ethernet frames
- Host assigns IP to `tap0`, stack uses a different IP on the same subnet

**Linux raw socket** (`rawsock.c`, `AF_PACKET`) — no `/dev/net/tun` needed:
- Bind to an existing interface — a real NIC, or one end of a veth pair whose other end the host uses
- Promiscuous while open (the stack has its own MAC); frames the host sends out are ignored
- Finishes checksums the local kernel left to offload (`PACKET_VNET_HDR`)
- Demos pick it with `raw:<ifname>`; CI runs every Linux blackbox suite over both TAP and the raw socket

**macOS** (feth + BPF):
- `ifconfig feth0 create; ifconfig feth1 create; ifconfig feth0 peer feth1; ifconfig feth0 up; ifconfig feth1 up`
- Open `/dev/bpfN`, bind to `feth1` with `BIOCSETIF`, enable `BIOCIMMEDIATE`
- `read()`/`write()` raw Ethernet frames (reads prefixed with `bpf_hdr`)
- Host assigns IP to `feth0`

**STM32F4** (`stm32f4_eth.c`, `boards/nucleo-f429zi`): the on-chip Ethernet
MAC and DMA over RMII, with start-up code, clocks and a `tcp_echo_demo`
firmware.  Built in CI; not run on hardware.

## Scope: Implemented

| Layer | What | Files | Design |
|---|---|---|---|
| Core | `net_t`; `net_init()`, `net_poll()`, `net_tick()`, `net_transmit()`; the keyed-hash random generator; the Internet checksum; byte-order access | `net.c`, `net_cksum.c`, `net_endian.h`, `net_config.h` | [architecture](docs/architecture.md), [memory-model](docs/design/memory-model.md), [configuration](docs/design/configuration.md), [checksum](docs/design/checksum.md), [byte-order](docs/design/byte-order.md), [timer-model](docs/design/timer-model.md) |
| MAC drivers | The six-function interface; TAP and raw socket (Linux), BPF (macOS), STM32F4 Ethernet, a stub | `net_mac.h`, `src/driver/` | [mac-hal](docs/design/mac-hal.md) |
| Link | Ethernet II; ARP without a cache | `eth.c`, `arp.c` | [arp-resolution](docs/design/arp-resolution.md) |
| IPv4 | Host IPv4 with options skipped, every broadcast form, the MTU and MMS_R/MMS_S, reassembly in an application buffer; ICMP echo and errors, received errors passed to the transports; multicast reception and IGMPv2 | `ipv4.c`, `icmp.c`, `igmp.c` | [architecture §5–§6](docs/architecture.md#5-receive-path) |
| IPv6 | Header and extension headers, ICMPv6, Neighbor Discovery with Duplicate Address Detection, router discovery and SLAAC, MLDv2/v1; dual stack or IPv6 alone | `ipv6.c`, `icmpv6.c`, `ndp.c`, `mld.c` | [ipv6](docs/design/ipv6.md) |
| Transport | UDP with port tables; TCP with the full state machine, stop-and-wait buffers, retransmission and persist timers, RFC 6528 initial sequence numbers — both over IPv4 and IPv6 | `udp.c`, `tcp.c`, `tcp_buf_saw.c` | [udp](docs/design/udp.md), [tcp](docs/design/tcp.md), [tcp-buffer](docs/design/tcp-buffer.md) |
| Configuration | DHCPv4 client and a one-client server; DHCPv6 client, stateless and stateful | `dhcpv4_client.c`, `dhcpv4_server.c`, `dhcpv6_client.c` | [dhcpv4](docs/design/dhcpv4.md), [ipv6](docs/design/ipv6.md) |
| File transfer | TFTP client (read requests, blksize, netascii) | `tftp.c` | [tftp](docs/design/tftp.md) |
| Discovery | mDNS responder with DNS-SD, over IPv4 and IPv6 | `mdns.c`, `dns_wire.c` | [mdns](docs/design/mdns.md) |
| Web | HTTP/1.0 server, over TCP or TLS | `http.c`, `http_tls.c` | [http](docs/design/http.md) |
| Security | TLS 1.3 client and server; DTLS 1.3 on the same handshake; cryptography through a backend interface (Mbed TLS bundled) | `tls*.c`, `dtls.c` | [tls](docs/design/tls.md), [dtls](docs/design/dtls.md) |
| Project | CMake build with FetchContent; Cortex-M0 size benchmarks and the no-division check; CI, with a release of every green push | `CMakeLists.txt`, `Makefile`, `.github/workflows/` | [test-plan](docs/test-plan.md), [release-process](docs/release-process.md) |

### Measured size

On Cortex-M0 ([size-comparison.md](docs/design/size-comparison.md)): a UDP
echo is 4,102 B of flash, UDP + TCP 8,622 B, UDP + HTTP (with TCP)
14,998 B, UDP + mDNS 14,444 B, dual-stack UDP 9,465 B, IPv6-only UDP
6,453 B; the TLS 1.3 protocol is 7,476 B for a server, DTLS 1.3 11,271 B —
with **no** stack-internal static state at all: every byte of RAM is
application-owned.

### Verification

Requirements are numbered rows traced to their RFCs
([docs/requirements/](docs/requirements/)); tests drive the stack only
through its API and the wire and cite the rows they verify; a bug becomes
a failing test before its fix.  Quality is measured by requirements
coverage and by the code coverage of the black-box integration tests, both
reported by CI ([test-plan.md §0](docs/test-plan.md#0-policy-and-the-integration-tests)).

## Scope: Left Out by Design

What an RFC asks of a host, or a stack commonly has, and this design
leaves out on purpose.  Where that is an RFC MUST, its requirement row
says **deviation** and what the stack does instead:

- **One default gateway, no route cache, Redirects ignored** — the
  application chooses next hops (`arp_next_hop()` gives the subnet rule);
  a route table would be state the stack does not keep.
- **Source-routed datagrams dropped; IP options neither passed up to nor
  settable by the transports.**
- **No TCP urgent data** — the URG flag and pointer are ignored and the
  data delivered in line.
- **Frame buffers smaller than a 576-byte datagram are allowed**, for the
  smallest targets; a build meets RFC 1122's EMTU_R only with an RX frame
  buffer of at least 590 bytes and a reassembly buffer of at least 576.
- **No neighbour caches** — neither ARP's nor IPv6's; peers' MACs live in
  the conversations that use them.
- **Nothing is fragmented on the way out** — datagrams fit the MTU and go
  with DF set.

## Roadmap: Not Implemented

| Area | Not implemented | Where it stands |
|---|---|---|
| DNS | The stub resolver (A and AAAA lookups through a recursive server) | Requirements written ([dns.md](docs/requirements/dns.md)); `dns_wire.c` is the wire format it shares with mDNS |
| mDNS | A querier (resolving `.local` names) and DNS-SD browsing | [mdns.md §2](docs/design/mdns.md) |
| TCP | RTT measurement and a computed RTO (RFC 6298); congestion control (RFC 5681); delayed ACK and Nagle; window scale, timestamps and SACK (RFC 7323); keep-alive; RFC 5961 challenge ACKs | [tcp.md §8](docs/design/tcp.md#8-not-implemented-and-known-gaps): one segment in flight and a fixed initial RTO with backoff stand in for them |
| TCP buffers | A ring buffer and a packet list, for more than one segment in flight | Designed in [tcp-buffer.md §5](docs/design/tcp-buffer.md) |
| Hardware | The STM32F4 port run on a board, and the nightly hardware fuzz job with it | Firmware built in CI; fixture described in [test-plan.md §4](docs/test-plan.md#4-hardware-test-fixture-recommended) |
| MAC drivers | ENC28J60 (SPI), USB CDC-ECM; checksum offload; scatter-gather transmit | [mac-hal.md §8](docs/design/mac-hal.md) |
| Timers | Tickless operation (`net_next_event_ms()`) | What it takes is in [timer-model.md §7](docs/design/timer-model.md) |
| IPv6 | Fragment reassembly; a neighbour cache with unreachability detection; Redirects; the RA's MTU option; ICMPv6 error rate limiting; DHCPv6 Confirm, Decline, Reconfigure, Rapid Commit | [ipv6.md §13](docs/design/ipv6.md) |
| IPv4 | Address conflict detection after an address is in use (RFC 5227); the DHCPv4 client probes an offered address once | [dhcpv4.md §7](docs/design/dhcpv4.md) |
| HTTP | Persistent connections and pipelining; chunked transfer coding; percent-decoding | [http.md §2](docs/design/http.md) |
| TLS | ChaCha20-Poly1305; client certificates; session tickets and 0-RTT; record_size_limit | [tls.md §1](docs/design/tls.md) |
| DTLS | Connection IDs; resending only the unacknowledged part of a flight | [dtls.md §1](docs/design/dtls.md) |
| TFTP | Write requests; the tsize, timeout and windowsize options; IPv6 | [tftp.md §9](docs/design/tftp.md) |
| Tests | Integration tests for IPv6, NDP, MLD, DHCPv6, TLS and DTLS; a test for every MUST row; fuzzing beyond TCP | [test-plan.md §5](docs/test-plan.md#5-open-items--known-gaps) |

## Language & Build

- C99 for maximum portability (XC8, GCC, Clang)
- No compiler extensions required (no `__attribute__((packed))` — wire formats are read and written byte by byte, for portability across PIC16/ARM/RISC-V), and no run-time division ([coding-rules.md](docs/design/coding-rules.md))
- CMake for the host build (libraries, tests, demos, FetchContent); the Makefile builds the Cortex-M0 size benchmarks and checks that no object calls a library divide

## Prior Art / References

- **Microchip TCP/IP Lite stack**: Validates this architecture. Streaming `ETH_*` interface, ~8 KB for UDP-only, runs on PIC16 with 1 KB RAM. Licensed Microchip-only.
- **level-ip (saminiir)**: Educational Linux TAP-based userspace TCP/IP stack. Good reference for TAP setup and protocol parsing.
- **tapip (chobits)**: Another educational userspace TCP/IP stack.
- **lwIP**: Full-featured; its smallest UDP-only build is about 10 KB of code and 2.6 KB of RAM on Cortex-M0 ([size-comparison.md](docs/design/size-comparison.md)). Too large for PIC16-class targets.

## Documentation

Detailed documentation is maintained in `docs/`:

### Architecture & Design
- **[docs/architecture.md](docs/architecture.md)** — System architecture, layer interaction, data flow, compilation model
- **[docs/integrating-modules.md](docs/integrating-modules.md)** — Wiring the application protocols into a program
- **[docs/design/coding-rules.md](docs/design/coding-rules.md)** — C99, memory, parsing, no run-time division, comments
- **[docs/design/mac-hal.md](docs/design/mac-hal.md)** — MAC Hardware Abstraction Layer (vtable; `net_poll()` copies each frame once)
- **[docs/design/checksum.md](docs/design/checksum.md)** — Internet checksum API and implementation
- **[docs/design/byte-order.md](docs/design/byte-order.md)** — Byte order handling and 8-bit target strategy
- **[docs/design/timer-model.md](docs/design/timer-model.md)** — Timer/event model (net_poll, net_tick, module ticks)
- **[docs/design/tcp.md](docs/design/tcp.md)** — TCP
- **[docs/design/tcp-buffer.md](docs/design/tcp-buffer.md)** — TCP buffer interface; stop-and-wait implemented, ring and packet list designed only
- **[docs/design/arp-resolution.md](docs/design/arp-resolution.md)** — Address resolution (no cache; gateway MAC; application-driven resolution)
- **[docs/design/memory-model.md](docs/design/memory-model.md)** — Zero-allocation memory model and init functions
- **[docs/design/configuration.md](docs/design/configuration.md)** — Configuration taxonomy, compile-time and link-time composition
- **[docs/design/udp.md](docs/design/udp.md)** — UDP port tables, payload pointers into the receive buffer, checksum, ICMP port unreachable
- **[docs/design/dhcpv4.md](docs/design/dhcpv4.md)** — DHCPv4 client + server, option handler callback API
- **[docs/design/tftp.md](docs/design/tftp.md)** — TFTP client
- **[docs/design/mdns.md](docs/design/mdns.md)** — mDNS + DNS-SD
- **[docs/design/http.md](docs/design/http.md)** — HTTP/1.0 server, also over TLS
- **[docs/design/ipv6.md](docs/design/ipv6.md)** — IPv6, ICMPv6, NDP, SLAAC, DHCPv6, MLD, mDNS/HTTP over IPv6
- **[docs/design/tls.md](docs/design/tls.md)** — TLS 1.3
- **[docs/design/dtls.md](docs/design/dtls.md)** — DTLS 1.3: the datagram record layer on the TLS handshake

### RFC Requirements (traced to RFC sections and to tests)

**IPv4 and the protocols over it:**
- **[docs/requirements/ethernet.md](docs/requirements/ethernet.md)** — Ethernet II framing (RFC 894)
- **[docs/requirements/arp.md](docs/requirements/arp.md)** — ARP address resolution (RFC 826)
- **[docs/requirements/checksum.md](docs/requirements/checksum.md)** — Internet checksum (RFC 1071)
- **[docs/requirements/ipv4.md](docs/requirements/ipv4.md)** — IPv4 host behavior (RFC 791/1122)
- **[docs/requirements/icmpv4.md](docs/requirements/icmpv4.md)** — ICMPv4 echo + errors (RFC 792)
- **[docs/requirements/igmp.md](docs/requirements/igmp.md)** — IGMPv2 host (RFC 2236)
- **[docs/requirements/udp.md](docs/requirements/udp.md)** — UDP datagrams (RFC 768)
- **[docs/requirements/tcp.md](docs/requirements/tcp.md)** — TCP (RFC 9293/5681/6298)
- **[docs/requirements/dhcpv4.md](docs/requirements/dhcpv4.md)** — DHCPv4 client and server (RFC 2131)
- **[docs/requirements/dns.md](docs/requirements/dns.md)** — DNS stub resolver (RFC 1035) — not implemented
- **[docs/requirements/tftp.md](docs/requirements/tftp.md)** — TFTP client (RFC 1350)
- **[docs/requirements/http.md](docs/requirements/http.md)** — HTTP/1.0 server (RFC 9110/9112)

**Service discovery:**
- **[docs/requirements/mdns.md](docs/requirements/mdns.md)** — Multicast DNS (RFC 6762)
- **[docs/requirements/dns-sd.md](docs/requirements/dns-sd.md)** — DNS-Based Service Discovery (RFC 6763)

**Security:**
- **[docs/requirements/tls.md](docs/requirements/tls.md)** — TLS 1.3 (RFC 8446)
- **[docs/requirements/dtls.md](docs/requirements/dtls.md)** — DTLS 1.3 (RFC 9147)

**IPv6:**
- **[docs/requirements/ipv6.md](docs/requirements/ipv6.md)** — IPv6 host behavior (RFC 8200)
- **[docs/requirements/icmpv6.md](docs/requirements/icmpv6.md)** — ICMPv6 (RFC 4443)
- **[docs/requirements/ndp.md](docs/requirements/ndp.md)** — Neighbor Discovery Protocol (RFC 4861)
- **[docs/requirements/slaac.md](docs/requirements/slaac.md)** — Stateless Address Autoconfiguration (RFC 4862)
- **[docs/requirements/dhcpv6.md](docs/requirements/dhcpv6.md)** — DHCPv6 client (RFC 8415)

### Size Benchmarks
- **[docs/design/size-comparison.md](docs/design/size-comparison.md)** — ARM Cortex-M0 code size per configuration, and against lwIP (a UDP echo in 2.5× less flash and 3.6× less RAM)

### Tests, CI and Releases
- **[docs/test-plan.md](docs/test-plan.md)** — The testing rules, requirements coverage and code coverage, the integration, unit and blackbox suites, the CI jobs
- **[docs/ci-debugging.md](docs/ci-debugging.md)** — Diagnosing CI failures
- **[docs/release-process.md](docs/release-process.md)** — Versions, the changelog, the release of every green push
- **[CHANGELOG.md](CHANGELOG.md)** — What each release changed
