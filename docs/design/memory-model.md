# Memory Model — Design

**Last updated:** 2026-03-19

## Principles

### Zero Allocation
The stack NEVER allocates memory. All memory is declared and owned by the application. The stack provides:
1. **Type definitions** (structs) for all state.
2. **Factory methods** (init functions) to validate and initialize state.
3. **Compile-time macros** for sizing.

### Error Detection Hierarchy

**Prefer compile-time → link-time → run-time error detection.**

| Level | Mechanism | Example |
|---|---|---|
| **Compile-time** | `#define` flags, `_Static_assert`, `#if` guards | `NET_MAC_CAP_TX_CKSUM_IPV4` enables/disables checksum code at compile time |
| **Link-time** | Separate compilation units, unused protocols not linked | Missing `arp.o` → linker error if IPv4 calls `arp_resolve()` |
| **Run-time** | Factory method validation, error return codes | `net_init()` returns `NET_ERR_BUF_TOO_SMALL` if buffer < minimum |

An embedded system does not dynamically reconfigure its hardware. Therefore hardware capabilities (checksum offload, etc.) are compile-time `#define`s in the driver's configuration header — not runtime function calls. This allows the compiler to eliminate dead code paths entirely.

```c
// net_config.h (application provides this)
#define NET_MAC_CAP_TX_CKSUM_IPV4  0  // Our MAC does not offload IPv4 checksum
#define NET_MAC_CAP_TX_CKSUM_TCP   0
#define NET_MAC_CAP_TX_CKSUM_UDP   0
#define NET_MAC_CAP_RX_CKSUM_OK    0

// In ipv4.c — compiler eliminates the #else branch entirely
#if NET_MAC_CAP_TX_CKSUM_IPV4
    net_write16be(hdr + 10, 0x0000);  // MAC fills in
#else
    net_write16be(hdr + 10, net_cksum(hdr, 20));
#endif
```

Similarly, use `_Static_assert` for compile-time buffer size validation where possible:
```c
_Static_assert(sizeof(rx_buf) >= NET_MIN_BUF_TCP,
               "RX buffer too small for TCP");
```

## Factory Method Pattern

Every structure has an init function that:
- Validates all constraints (e.g., minimum buffer size).
- Zeros the structure.
- Sets default values.
- Returns `NET_OK` or an error code.

```c
typedef enum {
    NET_OK = 0,
    NET_ERR_BUF_TOO_SMALL = -1,
    NET_ERR_INVALID_PARAM = -2,
} net_err_t;

// Factory: initializes net context
net_err_t net_init(net_t *net,
                   uint8_t *rx_buf, uint16_t rx_size,
                   uint8_t *tx_buf, uint16_t tx_size,
                   const uint8_t mac[6],
                   const net_mac_t *driver, void *driver_ctx);

// Factory: initializes TCP connection
net_err_t tcp_conn_init(tcp_conn_t *conn,
                        const tcp_txbuf_ops_t *tx_ops, void *tx_ctx,
                        const tcp_rxbuf_ops_t *rx_ops, void *rx_ctx);
```

## Compile-Time Size Macros

```c
// Minimum buffer sizes
#define NET_MIN_BUF_ETH         14
#define NET_MIN_BUF_IPV4        (14 + 20)          // ETH + IPv4
#define NET_MIN_BUF_IPV6        (14 + 40)          // ETH + IPv6
#define NET_MIN_BUF_UDP         (14 + 20 + 8)      // ETH + IPv4 + UDP = 42
#define NET_MIN_BUF_TCP         (14 + 20 + 20)     // ETH + IPv4 + TCP = 54
#define NET_MIN_BUF_DHCP        576                 // RFC 2131 minimum

// Protocol parameter derivation
#define NET_TCP_MSS_IPV4(buf)   ((buf) - 14 - 20 - 20)  // ETH + IP + TCP
#define NET_TCP_MSS_IPV6(buf)   ((buf) - 14 - 40 - 20)  // ETH + IPv6 + TCP
#define NET_UDP_MAX_IPV4(buf)   ((buf) - 14 - 20 - 8)   // ETH + IP + UDP
```

## Application Usage Example

```c
// Minimal TCP echo server — all memory declared by application
static uint8_t rx_buf[300];
static uint8_t tx_buf[300];
static net_t net;

static uint8_t conn_txbuf[256];
static uint8_t conn_rxbuf[256];
static tcp_saw_ctx_t conn_tx_ctx, conn_rx_ctx;
static tcp_conn_t conn;

// Platform-specific driver context
static tap_ctx_t tap;

void app_init(void) {
    static const uint8_t mac[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    
    // Init network context
    net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf),
             mac, &tap_mac_ops, &tap);
    net.ipv4_addr = NET_IPv4(10, 0, 0, 2);
    net.subnet_mask = NET_IPv4(255, 255, 255, 0);
    
    // Init TCP buffers
    tcp_saw_init(&conn_tx_ctx, conn_txbuf, sizeof(conn_txbuf));
    tcp_saw_init(&conn_rx_ctx, conn_rxbuf, sizeof(conn_rxbuf));
    
    // Init TCP connection
    tcp_conn_init(&conn, &tcp_saw_tx_ops, &conn_tx_ctx,
                  &tcp_saw_rx_ops, &conn_rx_ctx);
    tcp_listen(&conn, 7);  // Echo port
}
```

## Memory Budget Examples

| Configuration | RX buf | TX buf | TCP state | TCP buffers | Total |
|---|---|---|---|---|---|
| UDP only (PIC16) | 300 | 300 | — | — | ~600 bytes |
| TCP stop-wait (PIC16) | 300 | 300 | ~60 | 2 × 256 | ~1172 bytes |
| TCP circular (CH32X) | 1500 | 1500 | ~60 | 2 × 4096 | ~11.3 KB |
| TCP + HTTP (STM32) | 1500 | 1500 | ~60 | 2 × 2048 | ~7.2 KB |

## Error Handling

Factory methods validate all parameters:
- Buffer too small → `NET_ERR_BUF_TOO_SMALL`
- NULL pointer → `NET_ERR_INVALID_PARAM`
- Application MUST check return values

Runtime errors (bad packets, etc.) are silently discarded per RFC requirements. Optional `NET_DEBUG` tracing available at compile time.
