# Portable Minimal TCP/IP Stack — Design & Implementation Plan

**Last updated:** 2026-09-27 (Tasks 1–13 complete: through Milestone 13, TLS 1.3, and the Linux raw-socket driver.  718 unit tests on macOS (729 on Linux as root) + 182 blackbox + 5 fuzz + interop checks passing, blackbox over both Linux drivers.  Cortex-M0: 2.8 KB for a UDP echo, 7.8 KB dual stack, 7.1 KB of TLS protocol code for a server.  Open issues from the review: Task 15.  Next: Milestone 14, DTLS 1.3.)

This is the original plan, kept as the record of the design decisions and the
order of work.  Where the implementation departed from it, the text below says
so; the design documents under [`docs/`](docs/) describe the code as it is.

## Objective

Build a general-purpose, portable TCP/IP stack in C99 with:
- Zero dynamic allocation — application provides all memory
- Application-sized buffers — stack adapts (MSS, TCP window, etc.)
- Parse and build in place — a received frame is copied once, into the application's receive buffer, and parsed there; replies are built in the transmit buffer
- Strict OSI layering — each protocol is a separate compilation unit.  As built: the transports (UDP, TCP) and IPv6 are chosen at compile time (`NET_USE_*`, because IP dispatches to them), the application protocols at link time ([configuration.md §5](docs/design/configuration.md#5-compile-time-protocol-selection))
- Abstract MAC interface — stack is transport-agnostic (TAP, feth+BPF, ENC28J60, CDC-ECM, etc.)
- Catch errors early — prefer compile-time checks, then link-time, then run-time (configuration is `#define`s; buffer sizes come from the buffers the application passes in)

Primary validation use case: TCP/IP bootloader on small MCUs. But the stack is general-purpose — supports TFTP, HTTP, UDP, DHCP, etc.

## Target Platforms

The stack must scale from tiny MCUs to hosted environments:

| Chip | Flash | RAM | Cost | Notes |
|---|---|---|---|---|
| PIC16F1454 | 14 KB | 1 KB | ~$1.20 | Smallest viable target |
| CH32X033 | 62 KB | 20 KB | ~$0.20 | Best cost/capability ratio, RISC-V, QFN20/TSSOP20 |
| CH32V203 | 32+224 KB | 10 KB | ~$0.50 | Better TinyUSB support, RISC-V |
| STM32F042 | 32 KB | 6 KB | ~$1.00 | Mature ecosystem, QFN20 |
| Linux/macOS | unlimited | unlimited | — | Development/test via TAP or feth+BPF |

## Architecture

As built (the original sketch had only IPv4 and planned `feth.c` and
`enc28j60.c` drivers; macOS uses `bpf.c` on an feth pair, and no ENC28J60
driver exists yet):

```
┌──────────────────────────────────────────────┐
│           Application                        │
│  (bootloader, web server, etc.)              │
│  Owns all buffers and conn state             │
├──────────────────────────────────────────────┤
│  L7: dhcpv4_client/server  dhcpv6_client     │  ← optional, link what you need
│      tftp  mdns  http (+ http_tls)           │
├──────────────────────────────────────────────┤
│  TLS 1.3: tls*.c over a tcp_conn_t           │  ← optional, link time
├──────────────────────────────────────────────┤
│  L4: udp.c          tcp.c                    │  ← optional, compile time
├──────────────────────────────────────────────┤
│  L3: ipv4.c icmp.c │ ipv6.c icmpv6.c ndp.c   │  ← IPv6 optional, compile time
│      arp.c         │ mld.c                   │
├──────────────────────────────────────────────┤
│  L2: eth.c                                   │
├──────────────────────────────────────────────┤
│  MAC driver interface (net_mac.h)            │  ← abstract: function pointers
├──────────────┬─────────────┬─────────────────┤
│ tap.c        │ bpf.c       │ your driver     │  ← one per platform
│ rawsock.c    │ (macOS,     │ (e.g. ENC28J60  │
│ (Linux)      │  feth pair) │  over SPI)      │
└──────────────┴─────────────┴─────────────────┘
```

## Key Design Decisions

### Memory Model

All memory is owned and provided by the application.  As built
(`include/net.h`, abbreviated):

```c
typedef struct {
    uint8_t *buf;       // frame buffer (rx or tx)
    uint16_t capacity;  // its size
} net_buf_t;

typedef struct {
    net_buf_t rx, tx;               // one frame each way
    uint8_t mac[6];
    const net_mac_t *mac_driver;
    void *mac_ctx;
    uint32_t rng;                   // net_random() state
    uint32_t ipv4_addr, subnet_mask, gateway_ipv4;
    uint8_t gateway_mac[6], gateway_mac_valid;
    // + multicast groups, the IPv6 state (NET_USE_IPV6), and the
    //   application's UDP port tables and TCP connection table
} net_t;
```

The stack never calls malloc and has no static variables. Buffer sizes
determine protocol parameters:
- TCP MSS = TX frame buffer − Ethernet header − IP header − 20, at most 1460
  (54 bytes of headers over IPv4)
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

### ARP Design — Fast Path + No General Cache

**Problem:** On a live Ethernet network, ARP storms from other devices can overflow small MAC RX buffers (e.g., ENC28J60's 8 KB). The device must drain ARP frames as fast as possible.

**Solution (as built — [docs/design/arp-resolution.md](docs/design/arp-resolution.md)):**
- No ARP cache table.  The one MAC the stack learns from ARP is the gateway's (`net_t.gateway_mac`); a TCP connection keeps its peer's MAC for its life (from the peer's SYN, or given to `tcp_connect()`); replies go to the source MAC of the frame they answer.
- Inbound ARP requests: check the target IP; not for us → ignore. For us → reply immediately. Don't store anything from the requester.
- Inbound ARP replies: only one from the gateway's IP is used, to fill in the gateway MAC.
- Outbound ARP: the stack does not resolve on its own.  The application calls `arp_next_hop()` and `arp_request()` and waits for the MAC before an active open (`tcp_connect()`, `tftp_client_get()`, `udp_send()` to a new peer).

**Fast-path RX drain:** The main loop must prioritize emptying the MAC RX buffer over processing: `while (net_poll(&net) > 0) {}` first, then application processing.

### MAC Driver Interface

```c
typedef struct {
    int  (*init)(void *ctx);
    int  (*send)(void *ctx, const uint8_t *frame, uint16_t len);
    int  (*poll)(void *ctx);  // non-blocking, returns frame length or 0 if no frame available
    int  (*peek)(void *ctx, uint16_t offset, uint8_t *buf, uint16_t len);  // read bytes without consuming
    void (*discard)(void *ctx);  // skip current RX frame without full read
    void (*close)(void *ctx);
} net_mac_t;
```

- `peek` + `discard` were meant to allow fast ARP filtering on hardware MACs (ENC28J60) — read just the target IP via SPI, discard if not ours, without reading the full frame.  As built, `net_poll()` in `net.c` uses them more simply: `poll()` for the frame's length, one `peek()` of the whole frame into `net->rx.buf`, dispatch, then `discard()`.  The frame is copied once and every layer parses it in place.  Reading only the needed bytes remains possible future work ([docs/design/mac-hal.md](docs/design/mac-hal.md)).
- For TAP, raw sockets and BPF the driver caches the frame: `poll()` reads it and returns its length, `peek` copies from the driver's buffer, `discard` releases it.

### Flash Size Estimates (custom stack on RISC-V/ARM)

| Config | Layers | Est. Flash | Est. RAM (stack-internal) |
|---|---|---|---|
| UDP only | eth + arp + ipv4 + udp | ~3-4 KB | ~20 bytes state |
| UDP + CoAP | above + coap | ~5-6 KB | ~20 bytes state |
| TCP minimal | eth + arp + ipv4 + tcp (1 conn) | ~5-7 KB | ~30 bytes state |
| TCP + HTTP | above + http | ~7-9 KB | ~30 bytes state |
| Full (UDP+TCP+DHCP+HTTP) | everything | ~10-14 KB | ~50 bytes state |

Measured on Cortex-M0 (2026-09-27, [size-comparison.md](docs/design/size-comparison.md)):
UDP echo 2,574 B, UDP + TCP 6,130 B, UDP + HTTP (with TCP) 10,510 B, UDP +
mDNS 8,956 B, dual-stack UDP 7,549 B — with **no** stack-internal static
state at all: every byte of RAM is application-owned.

## First Demo Platform

**Linux TAP** (can run in Docker/VM on macOS):
- `open("/dev/net/tun")`, `ioctl(TUNSETIFF, IFF_TAP | IFF_NO_PI)`
- `read()`/`write()` raw Ethernet frames
- Host assigns IP to `tap0`, stack uses a different IP on the same subnet

**macOS alternative** (feth + BPF):
- `ifconfig feth0 create; ifconfig feth1 create; ifconfig feth0 peer feth1; ifconfig feth0 up; ifconfig feth1 up`
- Open `/dev/bpfN`, bind to `feth1` with `BIOCSETIF`, enable `BIOCIMMEDIATE`
- `read()`/`write()` raw Ethernet frames (reads prefixed with `bpf_hdr`)
- Host assigns IP to `feth0`

**Linux raw socket** (`rawsock.c`, `AF_PACKET`) — no `/dev/net/tun` needed:
- Bind to an existing interface — a real NIC, or one end of a veth pair whose other end the host uses
- Promiscuous while open (the stack has its own MAC); frames the host sends out are ignored
- Finishes checksums the local kernel left to offload (`PACKET_VNET_HDR`)
- Demos pick it with `raw:<ifname>`; CI runs every Linux blackbox suite over both TAP and the raw socket

## Implementation Tasks

### ✅ Task 1: Project skeleton + MAC abstraction + Linux TAP driver *(DONE)*
- Directory structure: `src/`, `src/driver/`, `include/`, `demo/`
- Define `net_mac.h` (init, send, poll, peek, discard, close)
- Implement `tap.c` for Linux
- Makefile (C99, `-Wall -Werror`) — since replaced by CMake for the host build; the Makefile now holds only the Cortex-M0 size targets
- Demo: open TAP, send hardcoded frame, hex-dump received frames
- Verify with `tcpdump -i tap0`

### ✅ Task 2: Ethernet frame parsing/building (eth.c) *(DONE)*
- `eth_parse()` — validate, return ethertype + payload offset, in-place
- `eth_build()` — write 14-byte header, return payload pointer
- In place: operates on the application's frame buffers (`net_buf_t`)
- Test: build frame → parse frame → verify roundtrip

### ✅ Task 3: ARP (arp.c) — fast-path filter + reply *(DONE)*
- Fast path: check the target IP, ignore if not ours
- `arp_input()` — reply to requests for our IP; learn the gateway's MAC from its replies
- `arp_request()` — send an ARP request; `arp_next_hop()` — the peer or the gateway
- No ARP cache table — the gateway MAC lives in `net_t`, peers' MACs in the app's connection structs
- Test: `arping -I tap0 10.0.0.2` → get reply
- Demo: host learns our MAC via ARP

### ✅ Task 4: IPv4 + ICMP echo reply (ipv4.c, icmp.c) *(DONE)*
- `ipv4_input()` — validate, check dst IP, dispatch by protocol
- `ipv4_build()` — write IP header at offset 14, compute checksum
- `icmp_input()` — echo request → echo reply (swap src/dst in-place, fix checksum)
- **Milestone demo: `ping 10.0.0.2` works**

### ✅ Task 5: UDP (udp.c) *(DONE)*
- `udp_input()` — parse 8-byte header, dispatch by port
- `udp_send()` — build UDP+IPv4+ETH headers, send
- Port handlers: app provides static array of `{port, callback}`
- UDP checksum over pseudo-header
- Demo: UDP echo server, `nc -u 10.0.0.2 7`

### Task 6: TCP (tcp.c) — minimal state machine  ✅ COMPLETE
- Application-managed `tcp_conn_t`
- States: LISTEN → SYN_RCVD → ESTABLISHED → FIN_WAIT/CLOSE_WAIT → CLOSED
- `tcp_listen()`, `tcp_input()`, `tcp_send()`
- Window = free space in the connection's RX buffer. MSS from the TX frame buffer.
- Retransmit: single unacked segment; the timeout starts at `NET_DEFAULT_TCP_RTO_INIT_MS` and doubles per expiry (no RTT estimation)
- No Nagle, no slow-start
- Demo: TCP echo server, `nc 10.0.0.2 7`
- Design: [docs/design/tcp.md](docs/design/tcp.md), [docs/design/tcp-buffer.md](docs/design/tcp-buffer.md)

### Task 7: Main event loop + integration demo  ✅ COMPLETE
- RX drain loop: prioritize emptying MAC over processing
- Timer tick: `net_tick(net, ms)` for the TCP timers (and, later, IPv6); ARP needs no timer, and application modules have their own `*_tick()`
- Demo: static IP, ARP + ping + UDP echo + TCP echo all working simultaneously

### ✅ Task 8: DHCPv4 client + server (dhcpv4_client.c, dhcpv4_server.c) *(DONE)*
- DISCOVER → OFFER → REQUEST → ACK over UDP port 67/68
- Sets `net->ipv4_addr`, `subnet_mask` and `gateway_ipv4` from the lease (the gateway's MAC is learned by ARP when the application asks)
- Demo: device gets IP from dnsmasq, then ping works

### ✅ Task 9: TFTP client (tftp.c) *(DONE)*
- RFC 1350: RRQ → DATA/ACK loop
- Block size adapts to app buffer
- Demo: fetch file from TFTP server — proves bootloader data path
- Design: [docs/design/tftp.md](docs/design/tftp.md)

### ✅ Task 10: mDNS + DNS-SD (mdns.c, dns_wire.c, igmp.c) *(DONE)*
- RFC 6762 responder: probe → announce → respond, goodbye packets, conflict handling
- RFC 6763 service advertisement: PTR/SRV/TXT (+A) from an application-provided record table
- Minimal IGMPv2 join for 224.0.0.251
- Required for pyro_fw device discovery
- Design: [docs/design/mdns.md](docs/design/mdns.md)

### ✅ Task 11: HTTP server (http.c) *(DONE)*
- HTTP/1.0 semantics, `Connection: close`; GET, HEAD, POST
- Route table → app handler; handler returns status, content type and a body pointer (streamed, any length)
- Poll-driven connection slots, recycled out of TIME_WAIT; request/response timeouts
- TCP gains `tcp_write()` + `tcp_output()` so header + body share a segment
- Demo: browse to `http://pyro-dead01.local/` (advertised over mDNS)
- Design: [docs/design/http.md](docs/design/http.md)

### ✅ Task 12: IPv6 (ipv6.c, icmpv6.c, ndp.c, mld.c, dhcpv6_client.c) *(DONE)*
- ✅ Stage 1: IPv6 header in/out + extension-header walk, EUI-64 link-local, ICMPv6 echo + Parameter Problem, NS/NA responder, DAD — `ping -6` by link-local
- ✅ Stage 2: UDP over IPv6 (`udp6_ports`, `udp6_send`)
- ✅ Stage 3: TCP over IPv6 (dual-stack listeners, `tcp6_connect`)
- ✅ Stage 4: router discovery + SLAAC (default router, global address, lifetimes, `ipv6_addr_add`)
- ✅ Stage 5: DHCPv6 client, stateless and stateful (`dhcpv6_client.c`), interop with dnsmasq
- ✅ Stage 6a: MLDv2 (+ MLDv1 fallback), `ipv6_mcast_join/leave`
- ✅ Stage 6b/6c: mDNS over IPv6 (ff02::fb, AAAA, both families) and HTTP over IPv6 — `curl -6` to the demo's link-local address, Avahi resolves it over IPv6
- Dual stack is a compile-time choice (`NET_USE_IPV6`, CMake `SMALLEST_TCP_IPV6`); IPv4-only builds are unchanged
- Design: [docs/design/ipv6.md](docs/design/ipv6.md)

### ✅ Task 13: TLS 1.3 (tls.c, tls_keys.c, tls_server.c, tls_client.c, tls_tcp.c, http_tls.c) *(DONE)*
- RFC 8446 client and server, `TLS_AES_128_GCM_SHA256`, x25519 and secp256r1 with HelloRetryRequest
- Certificates (ECDSA P-256, RSA-PSS) and pre-shared keys (psk_dhe_ke, psk_ke)
- max_fragment_length for small buffers, KeyUpdate, close_notify
- Every cryptographic primitive through the `tls_crypto_t` vtable; an Mbed TLS 3.6 backend
- Each role in its own file, reached through a role pointer, so a server-only build does not link the client
- `tls_tcp_carry()` moves records between a TLS and a TCP connection; HTTPS is the HTTP server with `http_conn_use_tls()`
- Design: [docs/design/tls.md](docs/design/tls.md)

### Task 14: DTLS 1.3 — planned
- Design: [docs/design/dtls.md](docs/design/dtls.md); tracked in the README roadmap

### Task 15: Open issues found in the 2026-09-27 review — open
Found while fixing the design review's bugs; none is fixed yet.  Each fix
starts with a unit test that fails on the current code.

**TCP** ([docs/design/tcp.md](docs/design/tcp.md) §8.3)
- [x] The FIN is sent whatever the peer's window and counts toward
      `TCP_MAX_RETRANSMITS`: a peer holding its window at zero resets the
      connection after about 4 minutes, where unsent data would be probed
      indefinitely — resends into a zero window are probes now, as in Linux
- [x] A busy driver fails `tcp_connect()` / `tcp6_connect()` with
      `NET_ERR_BUSY`, while every later segment treats it as a loss and
      retransmits — the SYN is resent by its timer too
- [x] A frame buffer too small for a TCP header (< 54 B IPv4, < 74 B IPv6)
      gives an MSS of 0 rather than refusing TCP at `net_init()`, which
      accepts buffers of 14 B — `net_init()` requires `TCP_MIN_FRAME`

**Core** ([docs/design/mac-hal.md](docs/design/mac-hal.md),
[docs/design/configuration.md](docs/design/configuration.md))
- [x] `net_init()` does not check that `rx.buf` and `tx.buf` do not overlap
      (replies are built in tx while rx is still read)
- [x] `NET_USE_IPV4=0` only gates the Ethernet dispatch and is untested —
      IPv6-only builds work: CMake `SMALLEST_TCP_IPV4`, CI job
      `cmake-ipv6-only`, the IPv6 blackbox suite against an IPv6-only
      `tcp_echo_demo`, `make arm-size-ipv6-only` (5,977 B)

**TLS 1.3** ([docs/design/tls.md](docs/design/tls.md))
- [ ] No API wipes a connection's secrets: one abandoned without an error,
      or closed cleanly with close_notify, keeps its keys and `kx_priv`
      until the next `tls_init()`
- [ ] The `shared` secret on the stack is not wiped when `kx_shared()` fails
      (client `on_server_hello()`, server `on_client_hello()`), nor the
      server's `priv` when `kx_keygen()` fails — matters if a backend writes
      partial output on failure
- [ ] A crossed KeyUpdate: if the peer's says update_not_requested while our
      `tls_key_update(t, 1)` is pending, ours still asks — allowed by RFC 8446
      §4.6.3, but costs the peer an extra KeyUpdate

**DHCPv4** ([docs/design/dhcpv4.md](docs/design/dhcpv4.md) §7)
- [ ] No random 1–10 s delay before the first DISCOVER (RFC 2131 §4.4.1 SHOULD)
- [ ] T1 and T2 are not randomized ("fuzzed", RFC 2131 §4.4.5)
- [ ] The lease is timed from the ACK, not from the REQUEST it answers
      (§4.4.5), so it ends later by a round-trip time
- [ ] Renewing REQUESTs carry the Server Identifier (RFC 2131 §4.3.2: MUST NOT)
- [ ] Unicast renewals are sent to the broadcast MAC
- [ ] Any NAK with our xid drops the lease; its source is not checked
- [ ] No event when REQUESTING gives up and discovery restarts (§3.1 SHOULD
      notify the user); adding one changes the API
- [ ] An ACK without a lease time leaves the client bound for good, like an
      infinite lease
- [ ] Server: always sets the broadcast flag and leaves `giaddr` 0, where
      RFC 2131 Table 3 copies the client's values
- [ ] REQ-DHCPv4-050, 051 and 078 require the init functions to check for a
      576-byte buffer and return an error; they return `void` and check
      nothing — fix the code or the requirements
- [ ] REQ-DHCPv4-048/049 (ARP for the gateway's MAC) are unverified

**TFTP** ([docs/design/tftp.md](docs/design/tftp.md) §9)
- [ ] `parse_decimal()` accepts trailing junk: "512abc" reads as 512
- [ ] A truncated ERROR (2–3 bytes) still ends the transfer, with code 0;
      the coding rules' "reject, don't repair" says drop it
- [ ] Options in an OACK we never requested, other than blksize, are ignored
      rather than refused (RFC 2347)
- [ ] The retransmission timer restarts on any datagram from the server's
      TID, including ones that are ignored
- [ ] The server TID uses 0 for "unknown", so a server answering from port 0
      is mishandled
- [ ] The 119-character cap on ERROR text in `put_error()` never applies —
      every text is a short constant — and can go

**CI** (`.github/workflows/fuzz.yml`)
- [ ] The hardware fuzz job needs a board port — start-up code, linker
      script, MAC driver and a `tcp_echo_demo` firmware target;
      `cmake/arm-none-eabi.cmake` builds the libraries for it

## Language & Build

- C99 for maximum portability (XC8, GCC, Clang)
- No compiler extensions required (avoid `__attribute__((packed))` — use manual serialization for portability across PIC16/ARM/RISC-V)
- CMake for the host build (libraries, unit tests, demos, FetchContent); the Makefile builds the Cortex-M0 size benchmarks and checks that no object calls a library divide

## Prior Art / References

- **Microchip TCP/IP Lite stack**: Validates this architecture. Streaming `ETH_*` interface, ~8 KB for UDP-only, runs on PIC16 with 1 KB RAM. Licensed Microchip-only.
- **level-ip (saminiir)**: Educational Linux TAP-based userspace TCP/IP stack. Good reference for TAP setup and protocol parsing.
- **tapip (chobits)**: Another educational userspace TCP/IP stack.
- **lwIP**: Full-featured but ~30-40 KB flash minimum. Too large for PIC16-class targets.

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
- **[docs/design/tcp.md](docs/design/tcp.md)** — TCP (Tasks 6–7)
- **[docs/design/tcp-buffer.md](docs/design/tcp-buffer.md)** — TCP buffer interface; stop-and-wait implemented, ring and packet list designed only
- **[docs/design/arp-resolution.md](docs/design/arp-resolution.md)** — Address resolution (no cache; gateway MAC; application-driven resolution)
- **[docs/design/memory-model.md](docs/design/memory-model.md)** — Zero-allocation memory model and init functions
- **[docs/design/configuration.md](docs/design/configuration.md)** — Configuration taxonomy, compile-time and link-time composition
- **[docs/design/udp.md](docs/design/udp.md)** — UDP port tables, payload pointers into the receive buffer, checksum, ICMP port unreachable
- **[docs/design/dhcpv4.md](docs/design/dhcpv4.md)** — DHCPv4 client + server, option handler callback API
- **[docs/design/tftp.md](docs/design/tftp.md)** — TFTP client (Task 9)
- **[docs/design/mdns.md](docs/design/mdns.md)** — mDNS + DNS-SD (Task 10, implemented)
- **[docs/design/http.md](docs/design/http.md)** — HTTP/1.0 server, also over TLS (Task 11, implemented)
- **[docs/design/ipv6.md](docs/design/ipv6.md)** — IPv6, ICMPv6, NDP, SLAAC, DHCPv6, MLD, mDNS/HTTP over IPv6 (Task 12, implemented)
- **[docs/design/tls.md](docs/design/tls.md)** — TLS 1.3 (Task 13, implemented)
- **[docs/design/dtls.md](docs/design/dtls.md)** — DTLS 1.3 (Task 14, planned)

### RFC Requirements (~950 total, traced to RFC sections)

**V1 — IPv4 Core (~546 requirements):**
- **[docs/requirements/ethernet.md](docs/requirements/ethernet.md)** — Ethernet II framing (20 reqs, RFC 894)
- **[docs/requirements/arp.md](docs/requirements/arp.md)** — ARP address resolution (37 reqs, RFC 826)
- **[docs/requirements/checksum.md](docs/requirements/checksum.md)** — Internet checksum (29 reqs, RFC 1071)
- **[docs/requirements/ipv4.md](docs/requirements/ipv4.md)** — IPv4 host behavior (57 reqs, RFC 791/1122)
- **[docs/requirements/icmpv4.md](docs/requirements/icmpv4.md)** — ICMPv4 echo + errors (41 reqs, RFC 792)
- **[docs/requirements/udp.md](docs/requirements/udp.md)** — UDP datagrams (39 reqs, RFC 768)
- **[docs/requirements/tcp.md](docs/requirements/tcp.md)** — TCP full state machine (155 reqs, RFC 9293/5681/6298)
- **[docs/requirements/dhcpv4.md](docs/requirements/dhcpv4.md)** — DHCPv4 client (51 reqs, RFC 2131)
- **[docs/requirements/dns.md](docs/requirements/dns.md)** — DNS stub resolver (36 reqs, RFC 1035)
- **[docs/requirements/tftp.md](docs/requirements/tftp.md)** — TFTP client (38 reqs, RFC 1350)
- **[docs/requirements/http.md](docs/requirements/http.md)** — HTTP/1.0 server (43 reqs, RFC 9110/9112)

**Service discovery (75 requirements):**
- **[docs/requirements/mdns.md](docs/requirements/mdns.md)** — Multicast DNS (43 reqs, RFC 6762)
- **[docs/requirements/dns-sd.md](docs/requirements/dns-sd.md)** — DNS-Based Service Discovery (32 reqs, RFC 6763)

**Security (88 requirements):**
- **[docs/requirements/tls.md](docs/requirements/tls.md)** — TLS 1.3 (43 reqs, RFC 8446)
- **[docs/requirements/dtls.md](docs/requirements/dtls.md)** — DTLS 1.3 (45 reqs, RFC 9147)

**V2 — IPv6 Fast-Follow (~239 requirements):**
- **[docs/requirements/ipv6.md](docs/requirements/ipv6.md)** — IPv6 host behavior (47 reqs, RFC 8200)
- **[docs/requirements/icmpv6.md](docs/requirements/icmpv6.md)** — ICMPv6 (41 reqs, RFC 4443)
- **[docs/requirements/ndp.md](docs/requirements/ndp.md)** — Neighbor Discovery Protocol (70 reqs, RFC 4861)
- **[docs/requirements/slaac.md](docs/requirements/slaac.md)** — Stateless Address Autoconfiguration (37 reqs, RFC 4862)
- **[docs/requirements/dhcpv6.md](docs/requirements/dhcpv6.md)** — DHCPv6 client (44 reqs, RFC 8415)

### Size Benchmarks
- **[docs/design/size-comparison.md](docs/design/size-comparison.md)** — ARM Cortex-M0 code size comparison vs lwIP (4.1× smaller stack code; UDP + TCP = 6.1 KB)

### Test Plan
- **[docs/test-plan.md](docs/test-plan.md)** — Unit and black-box conformance testing with Python/Scapy/pytest, CI strategy, traceability matrix
- **[docs/ci-debugging.md](docs/ci-debugging.md)** — Diagnosing CI failures

## Historical Context

This project evolved from evaluating USB network devices:
- Started with PIC16F145x + CDC-ECM + Microchip TCP/IP Lite stack
- CDC-ECM chosen over RNDIS (simpler, zero per-frame overhead, Linux/macOS native)
- Microchip Lite stack licensing (Microchip-only) prompted evaluation of alternatives
- RP2040 rejected due to external flash requirement (adds BOM cost and board area)
- CH32X033 identified as best single-chip candidate ($0.20, 62 KB flash, 20 KB RAM, USB Full-Speed)
- Scope shifted from "USB network device" to "portable TCP/IP stack" — the stack is the product
