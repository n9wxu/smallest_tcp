# Architecture Overview — Portable Minimal TCP/IP Stack

**Last updated:** 2026-03-19 (Milestones 1–5 implemented: Eth, ARP, IPv4, ICMP, UDP)

## 1. Design Principles

| Principle | Description |
|---|---|
| **Zero dynamic allocation** | The stack never calls `malloc`. All memory is owned and provided by the application via factory methods. |
| **Application-sized buffers** | Protocol parameters (MSS, TCP window, etc.) adapt to the buffers the application provides. |
| **Zero-copy where possible** | Headers are parsed and built in-place in application buffers. |
| **Strict composability** | Each protocol is a separate compilation unit. Unused protocols are not linked. IPv4 and IPv6 are independently selectable. |
| **Abstract MAC interface** | The stack is transport-agnostic. A vtable-style HAL adapts to TAP, feth+BPF, ENC28J60, CDC-ECM, etc. |
| **RFC-driven** | Every protocol behavior is traced to an RFC requirement. All requirements are tested. |
| **Catch errors early** | Prefer compile-time checks (`#define`, `_Static_assert`), then link-time (unused protocols not linked), then run-time (factory method validation). Hardware capabilities are compile-time `#define`s, not runtime queries. |
| **Portable C99** | No compiler extensions. Manual serialization (no packed structs). Builds with XC8, GCC, Clang. |

## 2. Protocol Composability

The stack is a set of independent libraries that compose at link time:

```
App links: eth.o + arp.o + ipv4.o + icmpv4.o + udp.o        → IPv4 UDP-only
App links: eth.o + arp.o + ipv4.o + icmpv4.o + tcp.o        → IPv4 TCP-only
App links: eth.o + ipv6.o + icmpv6.o + ndp.o + udp.o        → IPv6 UDP-only
App links: eth.o + arp.o + ipv4.o + ipv6.o + icmpv4.o +     → Dual-stack full
           icmpv6.o + ndp.o + udp.o + tcp.o
```

**Rules:**
- `eth.c` is always required (Ethernet framing).
- IPv4 requires `arp.c` for address resolution.
- IPv6 requires `ndp.c` + `icmpv6.c` for address resolution (NDP runs over ICMPv6).
- `udp.c` and `tcp.c` work with either or both IP versions.
- L7 protocols (`dhcpv4.c`, `dhcpv6.c`, `dns.c`, `tftp.c`, `http.c`) are independently optional.

## 3. Layer Architecture

```
┌──────────────────────────────────────────────┐
│              Application                      │
│  Owns all buffers, connection state, config   │
│  Uses factory methods to create structures    │
├──────────────────────────────────────────────┤
│  L7: dhcpv4  dhcpv6  dns  tftp  http         │  ← optional, link what you need
├──────────────────────────────────────────────┤
│  L4: udp               tcp                    │  ← optional independently
├──────────┬───────────────────────┬───────────┤
│  L3 v4:  │                       │  L3 v6:   │
│  ipv4    │                       │  ipv6     │  ← one or both
│  icmpv4  │                       │  icmpv6   │
│          │                       │  ndp      │
│          │                       │  slaac    │
├──────────┴───────────────────────┴───────────┤
│  L2: arp (IPv4)                               │
├──────────────────────────────────────────────┤
│  L2: eth                                      │
├──────────────────────────────────────────────┤
│  MAC driver interface (net_mac.h)             │
├────────┬────────┬────────┬───────────────────┤
│ tap.c  │ bpf.c  │enc28j60│ cdc_ecm.c        │
│(Linux) │(macOS) │ (SPI)  │ (USB)            │
└────────┴────────┴────────┴───────────────────┘
```

## 4. Memory Model

### 4.1 Application Owns All Memory

The application declares all buffers and state structures. The stack provides **factory methods** to initialize them correctly:

```c
// Application code
static uint8_t rx_buf[600];
static uint8_t tx_buf[600];
static net_t net;
static tcp_conn_t conn;

// Factory methods ensure correct initialization
net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf));
tcp_conn_init(&conn, 80);  // listen port 80
```

### 4.2 Factory Methods and Data Types

Every structure the stack uses has:
1. **A typedef** with all fields documented.
2. **A factory/init function** that:
   - Validates minimum size requirements (e.g., buffer must hold at least ETH+IP+TCP headers).
   - Zeroes the structure.
   - Sets default values.
   - Returns an error code if constraints are violated.
3. **Compile-time size macros** where applicable:
   ```c
   #define NET_MIN_BUF_SIZE  (14 + 20 + 20)  // ETH + IPv4 + TCP minimum
   #define NET_TCP_MSS(buf_size)  ((buf_size) - 14 - 20 - 20)
   ```

### 4.3 Core Data Types

```c
// Network buffer — wraps an application-provided byte array
typedef struct {
    uint8_t  *buf;        // pointer to application's buffer
    uint16_t  capacity;   // buffer size (set at init, never changes)
    uint16_t  frame_len;  // current frame length (0 = empty)
} net_buf_t;

// Network context — one per network interface
typedef struct {
    net_buf_t           rx;
    net_buf_t           tx;
    uint32_t            ipv4_addr;      // 0 = unconfigured
    uint8_t             ipv6_addr[16];  // all-zero = unconfigured
    uint8_t             mac[6];
    const net_mac_t    *mac_driver;
    void               *mac_ctx;
    uint32_t            gateway_ipv4;
    uint8_t             gateway_mac[6];
    uint8_t             gateway_mac_valid;
    uint32_t            subnet_mask;
} net_t;

// IP address — version-tagged union for dual-stack support
typedef struct {
    uint8_t version;  // 4 or 6
    union {
        uint32_t v4;
        uint8_t  v6[16];
    } addr;
} net_ip_addr_t;
```

### 4.4 Buffer Sizing Determines Protocol Parameters

The stack adapts to whatever buffer sizes the application provides:

| Parameter | Derived From |
|---|---|
| TCP MSS (outbound) | `tx.capacity - ETH_HDR - IP_HDR - TCP_HDR` |
| TCP receive window | `rx.capacity - IP_HDR - TCP_HDR` (or TX buffer abstraction) |
| Max UDP payload | `tx.capacity - ETH_HDR - IP_HDR - UDP_HDR` |
| DHCP viability | Buffer ≥ 342 bytes (minimum DHCP message) |

## 5. MAC Hardware Abstraction Layer (HAL)

See [docs/design/mac-hal.md](design/mac-hal.md) for detailed design.

```c
typedef struct {
    int      (*init)(void *ctx);
    int      (*send)(void *ctx, const uint8_t *frame, uint16_t len);
    int      (*recv)(void *ctx, uint8_t *frame, uint16_t maxlen);
    int      (*peek)(void *ctx, uint16_t offset, uint8_t *buf, uint16_t len);
    void     (*discard)(void *ctx);
    void     (*close)(void *ctx);
} net_mac_t;
```

**Key design:** `peek` + `discard` enables fast ARP/NDP filtering on hardware MACs without reading full frames.

**Hardware capabilities are compile-time, not runtime.** An embedded system does not change its MAC hardware at runtime. Capabilities like checksum offload are `#define`s in `net_config.h`, allowing the compiler to eliminate dead code paths entirely:

```c
// net_config.h — application provides this per target
#define NET_MAC_CAP_TX_CKSUM_IPV4  0  // 0 = software checksum, 1 = hardware offload
#define NET_MAC_CAP_TX_CKSUM_TCP   0
#define NET_MAC_CAP_TX_CKSUM_UDP   0
#define NET_MAC_CAP_RX_CKSUM_OK    0
```

## 6. Address Resolution Strategy

See [docs/design/arp-resolution.md](design/arp-resolution.md) for detailed design.

**No global ARP/NDP cache table.** Address resolution state is distributed:

| Owner | Stores | Used For |
|---|---|---|
| `net_t` | Gateway MAC | Off-subnet routing |
| `tcp_conn_t` | Remote MAC | Per-TCP-connection |
| `udp_peer_t` (optional) | Remote MAC | Persistent UDP peers |
| Protocol layers (DNS, DHCP) | Server MAC | Protocol-specific caching |

**Minimal mode:** Send all packets to gateway. Legal per RFC (gateway forwards + may send ICMP Redirect). Eliminates per-destination ARP entirely.

## 7. TCP Buffer Abstraction

See [docs/design/tcp-buffer.md](design/tcp-buffer.md) for detailed design.

TCP does not manage buffers directly. It calls a **buffer operations vtable** provided by the application:

```c
typedef struct {
    uint16_t (*write)(void *ctx, const uint8_t *data, uint16_t len);
    uint16_t (*next_segment)(void *ctx, const uint8_t **data, uint16_t mss);
    void     (*ack)(void *ctx, uint32_t bytes_acked);
    uint16_t (*in_flight)(void *ctx);
    uint16_t (*window)(void *ctx);
} tcp_txbuf_ops_t;
```

**Three reference implementations provided:**

| Strategy | Memory Cost | Throughput | Best For |
|---|---|---|---|
| Stop-and-wait | 1 × MSS | 1 segment/RTT | PIC16 (1 KB RAM) |
| Circular buffer | N bytes | Window-sized | CH32X033 (20 KB RAM) |
| Packet list | N × MSS chunks | Window-sized | Linux/macOS testing |

## 8. Checksum Architecture

See [docs/design/checksum.md](design/checksum.md) for detailed design.

**Incremental API** (RFC 1071, RFC 1624):

```c
typedef struct { uint32_t sum; } net_cksum_t;

void     net_cksum_init(net_cksum_t *c);
void     net_cksum_add(net_cksum_t *c, const uint8_t *data, uint16_t len);
uint16_t net_cksum_finalize(net_cksum_t *c);
```

Protocol layers compute checksums in software by default. When a MAC hardware offloads checksums, the corresponding `NET_MAC_CAP_*` compile-time flag is set to 1 in `net_config.h`. The protocol layer uses `#if` to either compute the checksum in software or write 0x0000 for the MAC to fill in. The compiler eliminates the unused code path entirely — no runtime branching.

## 9. Byte Order

See [docs/design/byte-order.md](design/byte-order.md) for detailed design.

```c
// net_endian.h
static inline uint16_t net_htons(uint16_t h);
static inline uint16_t net_ntohs(uint16_t n);
static inline uint32_t net_htonl(uint32_t h);
static inline uint32_t net_ntohl(uint32_t n);
```

**8-bit target strategy:** Store multi-byte fields in network (big-endian) order natively. Helpers become no-ops. This saves code and cycles on architectures with no native 16/32-bit register order.

## 10. Timer and Event Model

See [docs/design/timer-model.md](design/timer-model.md) for detailed design.

**Two entry points into the stack (besides application API):**

1. **`net_poll(net)`** — Process pending MAC frames. Called when MAC signals data ready (interrupt or poll).
2. **`net_tick(net, elapsed_ms)`** — Advance internal timers (ARP timeout, TCP retransmit, etc.).

**Tickless support:**

```c
uint32_t net_next_event_ms(net_t *net);
```

Returns milliseconds until the next scheduled event. The application can sleep this long between ticks. Returns `UINT32_MAX` if nothing is scheduled.

**Supported execution models:**

| Model | How It Works |
|---|---|
| Bare-metal tight loop | `while(1) { net_poll(); net_tick(0); app_work(); }` |
| Bare-metal timer | Sleep until `min(net_next_event_ms(), mac_irq)` |
| RTOS | Block on MAC semaphore with timeout = `net_next_event_ms()` |
| Linux/macOS | `select(mac_fd, timeout=net_next_event_ms())` |

## 11. Configuration Model

See [docs/design/configuration.md](design/configuration.md) for detailed design.

Stack configuration falls into three categories:

| Category | Mechanism | Examples |
|---|---|---|
| **Compile-time fixed** | `#define` in `net_config.h` | HW checksum offload, protocol inclusion, byte order |
| **Compile-time default, runtime tunable** | `#define NET_DEFAULT_*` + struct field | IP address, gateway, MAC, TCP timers |
| **Runtime only** | Struct field, no default | TCP sequence numbers, DHCP lease, ARP-resolved MACs |

The application provides `net_config.h` (one per target/application). Factory methods apply compile-time defaults to struct fields; runtime sources (DHCP, user input, EEPROM) override them.

## 12. Error Handling

- **Invalid inbound packets:** Silently discarded per RFC requirements.
- **Optional debug tracing:** Compile-time `NET_DEBUG` macro enables printf-style trace output.
- **Factory method errors:** Return error codes (e.g., `NET_ERR_BUF_TOO_SMALL`).
- **No assertions in production:** `NET_ASSERT()` macro compiles to nothing in release builds.

## 13. Target Platforms

| Chip | Flash | RAM | Cost | V1 (IPv4) | V2 (+IPv6) |
|---|---|---|---|---|---|
| PIC16F1454 | 14 KB | 1 KB | ~$1.20 | UDP only | Too small |
| CH32X033 | 62 KB | 20 KB | ~$0.20 | Full stack | Likely fits |
| CH32V203 | 256 KB | 10 KB | ~$0.50 | Full stack | Yes |
| STM32F042 | 32 KB | 6 KB | ~$1.00 | TCP+UDP | Tight |
| Linux/macOS | unlimited | unlimited | — | Full + tests | Full + tests |

## 14. Project Structure

```
smallest_tcp/
├── CMakeLists.txt                   ← CMake build (library + tests + demo)
├── Makefile                         ← GNU Make build (library + tests)
├── README.md
├── tcpip-stack-plan.md              ← high-level overview & task status
├── docs/
│   ├── architecture.md              ← this file
│   ├── test-plan.md
│   ├── requirements/                ← RFC-traced requirements (~785)
│   │   ├── ethernet.md  arp.md  checksum.md
│   │   ├── ipv4.md  icmpv4.md  udp.md  tcp.md
│   │   ├── dhcpv4.md  dns.md  tftp.md  http.md
│   │   └── ipv6.md  icmpv6.md  ndp.md  slaac.md  dhcpv6.md
│   └── design/
│       ├── mac-hal.md  checksum.md  byte-order.md
│       ├── timer-model.md  tcp-buffer.md
│       ├── arp-resolution.md  memory-model.md
│       ├── configuration.md
│       └── size-comparison.md       ← ARM size comparison vs lwIP
├── include/
│   ├── net.h                        ← core net_t context, factory, errors
│   ├── net_config.h                 ← compile-time configuration
│   ├── net_mac.h                    ← MAC HAL vtable
│   ├── net_endian.h                 ← byte-order helpers
│   ├── net_cksum.h                  ← Internet checksum API
│   ├── eth.h                        ← ✅ Ethernet II parse/build/dispatch
│   ├── arp.h                        ← ✅ ARP request/reply/next-hop
│   ├── ipv4.h                       ← ✅ IPv4 parse/build/send/input
│   ├── icmp.h                       ← ✅ ICMPv4 echo reply, dest unreach
│   ├── udp.h                        ← ✅ UDP parse/send, port dispatch
│   └── driver/
│       ├── tap.h                    ← Linux TAP driver
│       └── bpf.h                    ← macOS BPF driver
├── src/
│   ├── net.c                        ← ✅ net_init, MAC helpers
│   ├── net_cksum.c                  ← ✅ checksum (incremental + oneshot)
│   ├── eth.c                        ← ✅ Ethernet + ARP/IPv4 dispatch
│   ├── arp.c                        ← ✅ ARP reply, gateway MAC learning
│   ├── ipv4.c                       ← ✅ IPv4 parse/build, protocol dispatch
│   ├── icmp.c                       ← ✅ ICMP echo reply, port unreach
│   ├── udp.c                        ← ✅ UDP input/send, pseudo-header cksum
│   └── driver/
│       ├── tap.c                    ← Linux TAP
│       └── bpf.c                    ← macOS BPF
├── tests/
│   ├── CMakeLists.txt               ← CTest definitions
│   └── unit/
│       ├── test_main.h              ← minimal C unit test framework
│       ├── test_endian.c            ← ✅ 10 tests
│       ├── test_checksum.c          ← ✅ 12 tests
│       ├── test_eth.c               ← ✅ 11 tests
│       ├── test_net.c               ← ✅  8 tests
│       ├── test_arp.c               ← ✅  8 tests
│       ├── test_ipv4.c              ← ✅ 10 tests
│       ├── test_icmp.c              ← ✅  4 tests
│       └── test_udp.c               ← ✅  7 tests
├── demo/
│   ├── CMakeLists.txt
│   └── frame_dump/main.c           ← raw frame hex-dump demo
├── examples/
│   └── fetchcontent/                ← CMake FetchContent integration example
└── .github/
    └── workflows/ci.yml            ← CI: build + test (Linux + macOS)
```

**Implementation status (as of 2026-03-19):** 8 source files, 8 test files, **70 unit tests all passing** with `-Wall -Wextra -Werror -pedantic`. Layers through UDP (Tasks 1–5) are complete. TCP (Task 6) is next.

## References

See individual requirements documents for complete RFC citations.

| RFC | Title | Used By |
|---|---|---|
| RFC 768 | UDP | udp.c |
| RFC 791 | IPv4 | ipv4.c |
| RFC 792 | ICMPv4 | icmpv4.c |
| RFC 826 | ARP | arp.c |
| RFC 894 | IP over Ethernet | eth.c |
| RFC 1035 | DNS | dns.c |
| RFC 1071 | Checksum | net_cksum.c |
| RFC 1122 | Host Requirements | all layers |
| RFC 1350 | TFTP | tftp.c |
| RFC 1624 | Incremental Checksum | net_cksum.c |
| RFC 2131/2132 | DHCPv4 | dhcpv4.c |
| RFC 2348 | TFTP Blocksize | tftp.c |
| RFC 4291 | IPv6 Addressing | ipv6.c |
| RFC 4443 | ICMPv6 | icmpv6.c |
| RFC 4861 | NDP | ndp.c |
| RFC 4862 | SLAAC | slaac.c |
| RFC 5227 | ARP Conflict Detection | arp.c |
| RFC 5681 | TCP Congestion Control | tcp.c |
| RFC 6298 | TCP Retransmit Timer | tcp.c |
| RFC 6724 | IPv6 Address Selection | ipv6.c |
| RFC 6864 | IPv4 ID Field | ipv4.c |
| RFC 7323 | TCP Extensions | tcp.c |
| RFC 8200 | IPv6 | ipv6.c |
| RFC 8415 | DHCPv6 | dhcpv6.c |
| RFC 9110 | HTTP Semantics | http.c |
| RFC 9293 | TCP | tcp.c |
