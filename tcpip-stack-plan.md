# Portable Minimal TCP/IP Stack — Design & Implementation Plan

**Last updated:** 2026-03-19 (Tasks 1–5 implemented, 70 unit tests passing)

## Objective

Build a general-purpose, portable TCP/IP stack in C99 with:
- Zero dynamic allocation — application provides all memory
- Application-sized buffers — stack adapts (MSS, TCP window, etc.)
- Zero-copy where possible — parse/build headers in-place
- Strict OSI layering — each protocol is a separate compilation unit; unused protocols are not linked
- Abstract MAC interface — stack is transport-agnostic (TAP, feth+BPF, ENC28J60, CDC-ECM, etc.)
- Catch errors early — prefer compile-time checks, then link-time, then run-time (hardware capabilities are `#define`s, not runtime queries)

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

```
┌─────────────────────────────────────┐
│           Application               │
│  (bootloader, web server, etc.)     │
│  Owns all buffers and conn state    │
├─────────────────────────────────────┤
│  L7: dhcp.c  tftp.c  http.c         │  ← optional, link what you need
├─────────────────────────────────────┤
│  L4: udp.c          tcp.c           │  ← optional independently
├─────────────────────────────────────┤
│  L3: ipv4.c   icmp.c                │
├─────────────────────────────────────┤
│  L2: arp.c                          │
├─────────────────────────────────────┤
│  L2: eth.c                          │
├─────────────────────────────────────┤
│  MAC driver interface (net_mac.h)   │  ← abstract: function pointers
├──────────┬──────────┬───────────────┤
│ tap.c    │ feth.c   │ enc28j60.c    │  ← one per platform
│ (Linux)  │ (macOS)  │ (PIC/SPI)     │
└──────────┴──────────┴───────────────┘
```

## Key Design Decisions

### Memory Model

All memory is owned and provided by the application:

```c
typedef struct {
    uint8_t *buf;       // frame buffer (rx or tx)
    uint16_t len;       // buffer capacity
    uint16_t frame_len; // actual frame length
} net_buf_t;

typedef struct {
    net_buf_t rx;
    net_buf_t tx;
    uint32_t ip;
    uint8_t mac[6];
    const net_mac_t *mac_driver;
    void *mac_ctx;
} net_t;
```

The stack never calls malloc. Buffer sizes determine protocol parameters:
- TCP MSS = tx_buf.len - 54 (ETH+IP+TCP headers)
- TCP window = rx_buf.len - 40 (IP+TCP headers)

### TCP Connection Model

Application-managed: the app passes in a `tcp_conn_t` per connection. The stack has no internal connection pool or table.

```c
typedef struct {
    uint8_t state;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t remote_ip;
    uint8_t remote_mac[6];
    uint8_t mac_valid;      // 0 = needs ARP resolution
    uint32_t seq;
    uint32_t ack;
    uint16_t window;
    // retransmit timer state
} tcp_conn_t;
```

### ARP Design — Fast Path + No General Cache

**Problem:** On a live Ethernet network, ARP storms from other devices can overflow small MAC RX buffers (e.g., ENC28J60's 8 KB). The device must drain ARP frames as fast as possible.

**Solution:**
- No general ARP cache table. ARP entries live in the application's connection structs (each has `{ip, mac, mac_valid}`).
- Inbound ARP requests: fast-path filter — check target IP (4-byte compare at fixed frame offset 38). Not for us → discard immediately. For us → reply immediately. Don't store anything from the requester.
- Inbound ARP replies: scan the app's active connections for a matching IP, fill in the MAC.
- Outbound ARP: only when sending to a connection with `mac_valid == 0`. Send ARP request, defer the data send until reply arrives.

**Fast-path RX drain:** The main loop must prioritize emptying the MAC RX buffer over processing. Drain all pending frames first (filter/discard ARP not for us, dispatch non-ARP), then do application processing.

### MAC Driver Interface

```c
typedef struct {
    int  (*init)(void *ctx);
    int  (*send)(void *ctx, const uint8_t *frame, uint16_t len);
    int  (*recv)(void *ctx, uint8_t *frame, uint16_t maxlen);  // non-blocking, returns 0 if no frame
    int  (*peek)(void *ctx, uint16_t offset, uint8_t *buf, uint16_t len);  // read bytes without consuming
    void (*discard)(void *ctx);  // skip current RX frame without full read
    void (*close)(void *ctx);
} net_mac_t;
```

- `peek` + `discard`: enables fast ARP filtering on hardware MACs (ENC28J60) — read just the target IP via SPI, discard if not ours, without reading the full frame.
- For TAP/feth: `recv()` reads the whole frame into the buffer; `peek` is a memcpy from the buffer; `discard` is a no-op.

### Flash Size Estimates (custom stack on RISC-V/ARM)

| Config | Layers | Est. Flash | Est. RAM (stack-internal) |
|---|---|---|---|
| UDP only | eth + arp + ipv4 + udp | ~3-4 KB | ~20 bytes state |
| UDP + CoAP | above + coap | ~5-6 KB | ~20 bytes state |
| TCP minimal | eth + arp + ipv4 + tcp (1 conn) | ~5-7 KB | ~30 bytes state |
| TCP + HTTP | above + http | ~7-9 KB | ~30 bytes state |
| Full (UDP+TCP+DHCP+HTTP) | everything | ~10-14 KB | ~50 bytes state |

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

## Implementation Tasks

### ✅ Task 1: Project skeleton + MAC abstraction + Linux TAP driver *(DONE)*
- Directory structure: `src/`, `src/driver/`, `include/`, `demo/`
- Define `net_mac.h` (init, send, recv, peek, discard, close)
- Implement `tap.c` for Linux
- Makefile (C99, `-Wall -Werror`)
- Demo: open TAP, send hardcoded frame, hex-dump received frames
- Verify with `tcpdump -i tap0`

### ✅ Task 2: Ethernet frame parsing/building (eth.c) *(DONE)*
- `eth_parse()` — validate, return ethertype + payload offset, in-place
- `eth_build()` — write 14-byte header, return payload pointer
- Zero-copy: operates on app's `net_buf_t`
- Test: build frame → parse frame → verify roundtrip

### ✅ Task 3: ARP (arp.c) — fast-path filter + reply *(DONE)*
- Fast path: check target IP at offset 38, discard if not ours
- `arp_input()` — reply to requests for our IP; fill connection MACs from replies
- `arp_resolve()` — send ARP request for a connection's IP
- No ARP cache table — MACs live in app's connection structs
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

### Task 6: TCP (tcp.c) — minimal state machine
- Application-managed `tcp_conn_t`
- States: LISTEN → SYN_RCVD → ESTABLISHED → FIN_WAIT/CLOSE_WAIT → CLOSED
- `tcp_listen()`, `tcp_input()`, `tcp_send()`
- Window = app buffer size. MSS from tx buffer size.
- Retransmit: simple fixed timeout, single unacked segment
- No Nagle, no slow-start
- Demo: TCP echo server, `nc 10.0.0.2 7`

### Task 7: Main event loop + integration demo
- RX drain loop: prioritize emptying MAC over processing
- Timer tick: `net_tick(net, ms)` for ARP timeout, TCP retransmit
- Demo: static IP, ARP + ping + UDP echo + TCP echo all working simultaneously

### Task 8: DHCP client (dhcp.c)
- DISCOVER → OFFER → REQUEST → ACK over UDP port 67/68
- Sets `net->ip`, populates gateway MAC via ARP
- Demo: device gets IP from dnsmasq, then ping works

### Task 9: TFTP client (tftp.c)
- RFC 1350: RRQ → DATA/ACK loop
- Block size adapts to app buffer
- Demo: fetch file from TFTP server — proves bootloader data path

### Task 10: HTTP server (http.c)
- HTTP/1.0 only, `Connection: close`
- Parse request line (method + path), call app handler
- App handler returns body + content-type
- Demo: browse to `http://10.0.0.2/` from host

## Language & Build

- C99 for maximum portability (XC8, GCC, Clang)
- No compiler extensions required (avoid `__attribute__((packed))` — use manual serialization for portability across PIC16/ARM/RISC-V)
- Makefile-based build

## Prior Art / References

- **Microchip TCP/IP Lite stack**: Validates this architecture. Streaming `ETH_*` interface, ~8 KB for UDP-only, runs on PIC16 with 1 KB RAM. Licensed Microchip-only.
- **level-ip (saminiir)**: Educational Linux TAP-based userspace TCP/IP stack. Good reference for TAP setup and protocol parsing.
- **tapip (chobits)**: Another educational userspace TCP/IP stack.
- **lwIP**: Full-featured but ~30-40 KB flash minimum. Too large for PIC16-class targets.

## Documentation

Detailed documentation is maintained in `docs/`:

### Architecture & Design
- **[docs/architecture.md](docs/architecture.md)** — System architecture, layer interaction, data flow, compilation model
- **[docs/design/mac-hal.md](docs/design/mac-hal.md)** — MAC Hardware Abstraction Layer (vtable interface, peek+discard)
- **[docs/design/checksum.md](docs/design/checksum.md)** — Internet checksum API and implementation
- **[docs/design/byte-order.md](docs/design/byte-order.md)** — Byte order handling and 8-bit target strategy
- **[docs/design/timer-model.md](docs/design/timer-model.md)** — Timer/event model (net_poll, net_tick, tickless)
- **[docs/design/tcp-buffer.md](docs/design/tcp-buffer.md)** — TCP buffer abstraction (stop-and-wait, circular, packet-list)
- **[docs/design/arp-resolution.md](docs/design/arp-resolution.md)** — Address resolution (distributed cache, gateway-only mode)
- **[docs/design/memory-model.md](docs/design/memory-model.md)** — Zero-allocation memory model and factory methods
- **[docs/design/configuration.md](docs/design/configuration.md)** — Configuration taxonomy (compile-time fixed vs. runtime tunable vs. runtime only)

### RFC Requirements (~785 total, traced to RFC sections)

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

**V2 — IPv6 Fast-Follow (~239 requirements):**
- **[docs/requirements/ipv6.md](docs/requirements/ipv6.md)** — IPv6 host behavior (47 reqs, RFC 8200)
- **[docs/requirements/icmpv6.md](docs/requirements/icmpv6.md)** — ICMPv6 (41 reqs, RFC 4443)
- **[docs/requirements/ndp.md](docs/requirements/ndp.md)** — Neighbor Discovery Protocol (70 reqs, RFC 4861)
- **[docs/requirements/slaac.md](docs/requirements/slaac.md)** — Stateless Address Autoconfiguration (37 reqs, RFC 4862)
- **[docs/requirements/dhcpv6.md](docs/requirements/dhcpv6.md)** — DHCPv6 client (44 reqs, RFC 8415)

### Test Plan
- **[docs/test-plan.md](docs/test-plan.md)** — Black-box conformance testing with Python/Scapy/pytest, CI strategy, traceability matrix

## Historical Context

This project evolved from evaluating USB network devices:
- Started with PIC16F145x + CDC-ECM + Microchip TCP/IP Lite stack
- CDC-ECM chosen over RNDIS (simpler, zero per-frame overhead, Linux/macOS native)
- Microchip Lite stack licensing (Microchip-only) prompted evaluation of alternatives
- RP2040 rejected due to external flash requirement (adds BOM cost and board area)
- CH32X033 identified as best single-chip candidate ($0.20, 62 KB flash, 20 KB RAM, USB Full-Speed)
- Scope shifted from "USB network device" to "portable TCP/IP stack" — the stack is the product
