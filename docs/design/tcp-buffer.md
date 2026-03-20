# TCP Buffer Abstraction — Design

**Last updated:** 2026-03-19

## Motivation

TCP needs to buffer data for retransmission (TX) and for ordered delivery to the application (RX). Different environments have vastly different memory budgets:

| Target | RAM | Best buffer strategy |
|---|---|---|
| PIC16F1454 | 1 KB | Stop-and-wait (1 segment) |
| CH32X033 | 20 KB | Circular buffer |
| Linux/macOS | unlimited | Packet list or circular |

The TCP state machine MUST NOT know which strategy is in use.

## TX Buffer Operations

```c
typedef struct {
    // Write data into buffer. Returns bytes accepted (may be less than len if full).
    uint16_t (*write)(void *ctx, const uint8_t *data, uint16_t len);
    
    // Get pointer to next segment to send. Returns segment length (0 = nothing to send).
    // *data points into the buffer (zero-copy). Segment size ≤ mss.
    uint16_t (*next_segment)(void *ctx, const uint8_t **data, uint16_t mss);
    
    // Mark bytes as acknowledged (advance buffer past ACKed data).
    void (*ack)(void *ctx, uint32_t bytes_acked);
    
    // How many bytes are in-flight (sent but not yet ACKed)?
    uint16_t (*in_flight)(void *ctx);
    
    // How many bytes can the application write (free space)?
    uint16_t (*writable)(void *ctx);
} tcp_txbuf_ops_t;
```

## RX Buffer Operations

```c
typedef struct {
    // Deliver received data into buffer. Returns bytes accepted.
    uint16_t (*deliver)(void *ctx, const uint8_t *data, uint16_t len);
    
    // Application reads data from buffer. Returns bytes copied.
    uint16_t (*read)(void *ctx, uint8_t *dst, uint16_t maxlen);
    
    // How many bytes available for reading?
    uint16_t (*readable)(void *ctx);
    
    // How many bytes of free space (for window advertisement)?
    uint16_t (*available)(void *ctx);
} tcp_rxbuf_ops_t;
```

## Reference Implementations

### 1. Stop-and-Wait (Smallest)

- TX: One MSS-sized buffer. `write()` fills it. `next_segment()` returns the whole buffer. `ack()` clears it. Only 1 segment in flight.
- RX: One MSS-sized buffer. `deliver()` copies in. `read()` copies out. Window = buffer size when empty, 0 when full.
- **Memory:** 2 × MSS (one TX, one RX). For 536-byte MSS: ~1 KB total.
- **Throughput:** 1 segment per RTT.

### 2. Circular Buffer (Best Balance)

- TX: Ring buffer of N bytes. `write()` appends. `next_segment()` returns up to MSS from unset data. `ack()` advances tail. Multiple segments can be in flight.
- RX: Ring buffer of N bytes. Window = free space.
- **Memory:** 2 × N bytes. For 4 KB TX + 4 KB RX: 8 KB total.
- **Throughput:** Window-sized (limited by buffer and cwnd).

### 3. Packet List (Most Flexible)

- TX: Linked list of MSS-sized buffers. Each node is one segment. `ack()` frees nodes.
- RX: Same structure.
- **Memory:** N × (MSS + overhead). Application provides the node pool.
- **Throughput:** Window-sized.
- **Note:** Requires list management. Best for hosted environments.

## Application Provides Everything

```c
// Application code for stop-and-wait:
static uint8_t tx_seg[600];
static uint8_t rx_seg[600];
static tcp_saw_ctx_t saw_tx, saw_rx;
static const tcp_txbuf_ops_t saw_tx_ops = { saw_write, saw_next, saw_ack, saw_inflight, saw_writable };
static const tcp_rxbuf_ops_t saw_rx_ops = { saw_deliver, saw_read, saw_readable, saw_available };

tcp_conn_init(&conn, &saw_tx_ops, &saw_tx, &saw_rx_ops, &saw_rx);
```

The stack provides factory functions for each strategy:
```c
void tcp_saw_init(tcp_saw_ctx_t *ctx, uint8_t *buf, uint16_t size);
void tcp_ring_init(tcp_ring_ctx_t *ctx, uint8_t *buf, uint16_t size);
```
