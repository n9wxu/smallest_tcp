/**
 * @file tcp_buf.h
 * @brief TCP buffer abstraction — compile-time dependency injection.
 *
 * The TCP state machine (tcp.c) never directly touches buffer memory.
 * Instead, it calls exclusively through the two ops vtables defined here.
 * The application "injects" a concrete buffer implementation at
 * tcp_conn_init() time by passing a pointer to a const ops object.
 *
 * Implements REQ-TCP-142, REQ-TCP-143, REQ-TCP-144, REQ-TCP-145,
 * REQ-TCP-146, REQ-TCP-147.
 *
 * ── Provided implementations ────────────────────────────────────────
 *
 *  tcp_buf_saw.c   — Stop-and-wait (1 segment in flight, ~2×MSS RAM)
 *                    Smallest footprint. Best for PIC16/CH32X033.
 *
 *  tcp_buf_ring.c  — Circular/ring buffer (multiple segments in flight)
 *                    Best balance. For CH32V203/STM32F042 class devices.
 *                    (Future — V2)
 *
 *  tcp_buf_pkt.c   — Packet-list / scatter-gather (zero-copy TX paths)
 *                    For hosted environments with plenty of RAM.
 *                    (Future — V3)
 *
 * ── Usage ────────────────────────────────────────────────────────────
 *
 *  // Application code — stop-and-wait, compile-time wiring:
 *  static uint8_t tx_mem[600], rx_mem[600];
 *  static tcp_saw_tx_ctx_t tx_ctx;
 *  static tcp_saw_rx_ctx_t rx_ctx;
 *
 *  tcp_saw_tx_init(&tx_ctx, tx_mem, sizeof(tx_mem));
 *  tcp_saw_rx_init(&rx_ctx, rx_mem, sizeof(rx_mem));
 *
 *  tcp_conn_init(&conn, port,
 *                &tcp_saw_tx_ops, &tx_ctx,
 *                &tcp_saw_rx_ops, &rx_ctx,
 *                my_event_cb);
 */

#ifndef TCP_BUF_H
#define TCP_BUF_H

#include <stdint.h>

/* ── TX buffer operations vtable ────────────────────────────────────
 *
 * The TCP state machine uses this to write outgoing data, obtain
 * segments to transmit, and acknowledge sent data.
 */
typedef struct {
  /**
   * Write data into the TX buffer.
   * Called by the application to queue data for transmission.
   * @param ctx   Buffer context.
   * @param data  Data to enqueue.
   * @param len   Number of bytes to enqueue.
   * @return Bytes accepted (may be < len if buffer is full or in-flight).
   */
  uint16_t (*write)(void *ctx, const uint8_t *data, uint16_t len);

  /**
   * Get pointer to the next segment to send (zero-copy).
   * @param ctx   Buffer context.
   * @param data  Output: pointer into buffer memory (zero-copy).
   * @param mss   Maximum segment size (caller's constraint).
   * @return Segment length in bytes (0 = nothing ready to send).
   */
  uint16_t (*next_segment)(void *ctx, const uint8_t **data, uint16_t mss);

  /**
   * Acknowledge bytes (advance past ACKed data).
   * Called when a received ACK advances SND.UNA.
   * @param ctx          Buffer context.
   * @param bytes_acked  Number of newly ACKed bytes.
   */
  void (*ack)(void *ctx, uint32_t bytes_acked);

  /**
   * How many bytes are currently in-flight (sent but not yet ACKed)?
   * Used by the retransmit timer to determine if there is anything to
   * retransmit on timeout.
   * @return In-flight byte count.
   */
  uint16_t (*in_flight)(const void *ctx);

  /**
   * How many bytes of free space remain for the application to write?
   * @return Available write space in bytes.
   */
  uint16_t (*writable)(const void *ctx);

  /**
   * Mark all in-flight data as needing retransmission.
   * Called by tcp_tick() on retransmit timeout (REQ-TCP-095).
   *
   * For stop-and-wait: clears in_flight flag so next_segment() returns
   *   the buffered data again.
   * For ring buffer: resets send_head back to ack_head (SND.UNA position).
   * For packet-list: marks head node as unsent.
   *
   * After this call, next_segment() MUST return the same data that was
   * previously in-flight, so the TCP layer can retransmit it.
   */
  void (*mark_retransmit)(void *ctx);
} tcp_txbuf_ops_t;

/* ── RX buffer operations vtable ────────────────────────────────────
 *
 * The TCP state machine uses this to deliver received data to the
 * application and to compute the advertised receive window (RCV.WND).
 */
typedef struct {
  /**
   * Deliver received bytes from the network into the RX buffer.
   * Called by tcp_input() when valid in-order data arrives.
   * @param ctx   Buffer context.
   * @param data  Received payload (points into the net RX buffer).
   * @param len   Number of bytes to deliver.
   * @return Bytes accepted (may be < len if buffer is full; rest trimmed).
   */
  uint16_t (*deliver)(void *ctx, const uint8_t *data, uint16_t len);

  /**
   * Application reads data out of the RX buffer.
   * @param ctx     Buffer context.
   * @param dst     Destination buffer.
   * @param maxlen  Maximum bytes to read.
   * @return Bytes actually copied.
   */
  uint16_t (*read)(void *ctx, uint8_t *dst, uint16_t maxlen);

  /**
   * How many bytes are available for the application to read?
   * @return Readable byte count.
   */
  uint16_t (*readable)(const void *ctx);

  /**
   * How many bytes of free space remain in the RX buffer?
   * This value is used to compute and advertise RCV.WND.
   * When zero, TCP sends a zero-window (peer must stop sending).
   * @return Free space in bytes.
   */
  uint16_t (*available)(const void *ctx);
} tcp_rxbuf_ops_t;

/* ══════════════════════════════════════════════════════════════════
 * Stop-and-Wait Buffer (tcp_buf_saw.c) — REQ-TCP-145
 *
 * One MSS-sized buffer each for TX and RX. Only 1 segment in flight
 * at a time. Throughput = 1 segment / RTT.
 * Flash: ~200 bytes. RAM: 2 × buffer_size (provided by application).
 * ══════════════════════════════════════════════════════════════════ */

/**
 * @brief Stop-and-wait TX buffer context.
 * Application allocates this (stack or static) and provides the backing store.
 */
typedef struct {
  uint8_t *buf;      /**< Application-provided backing store */
  uint16_t capacity; /**< Capacity of buf in bytes */
  uint16_t data_len; /**< Bytes written by application (not yet ACKed) */
  uint8_t in_flight; /**< 1 after next_segment() until ack() clears it */
} tcp_saw_tx_ctx_t;

/**
 * @brief Stop-and-wait RX buffer context.
 * Application allocates this (stack or static) and provides the backing store.
 */
typedef struct {
  uint8_t *buf;       /**< Application-provided backing store */
  uint16_t capacity;  /**< Capacity of buf in bytes */
  uint16_t write_pos; /**< Next write position */
  uint16_t read_pos;  /**< Next read position */
  uint16_t data_len;  /**< Bytes delivered but not yet read */
} tcp_saw_rx_ctx_t;

/** Singleton ops object for stop-and-wait TX (link tcp_buf_saw.c to use). */
extern const tcp_txbuf_ops_t tcp_saw_tx_ops;

/** Singleton ops object for stop-and-wait RX (link tcp_buf_saw.c to use). */
extern const tcp_rxbuf_ops_t tcp_saw_rx_ops;

/**
 * Initialize a stop-and-wait TX context.
 * @param ctx   Context to initialize.
 * @param buf   Application-provided backing buffer.
 * @param size  Size of buf in bytes (determines max data before send).
 */
void tcp_saw_tx_init(tcp_saw_tx_ctx_t *ctx, uint8_t *buf, uint16_t size);

/**
 * Initialize a stop-and-wait RX context.
 * @param ctx   Context to initialize.
 * @param buf   Application-provided backing buffer.
 * @param size  Size of buf in bytes (determines advertised window size).
 */
void tcp_saw_rx_init(tcp_saw_rx_ctx_t *ctx, uint8_t *buf, uint16_t size);

/* ══════════════════════════════════════════════════════════════════
 * Circular (Ring) Buffer (tcp_buf_ring.c) — REQ-TCP-146
 *
 * Future V2 implementation. Multiple segments may be in flight.
 * Throughput = window-limited (up to buffer_size / RTT).
 * Flash: ~400 bytes. RAM: 2 × N bytes.
 * ══════════════════════════════════════════════════════════════════ */

/**
 * @brief Circular TX buffer context.
 */
typedef struct {
  uint8_t *buf;
  uint16_t capacity;
  uint16_t app_head;  /**< Next byte application will write */
  uint16_t send_head; /**< Next byte to send (SND.NXT) */
  uint16_t ack_head;  /**< Next byte to be ACKed (SND.UNA tail) */
} tcp_ring_tx_ctx_t;

/**
 * @brief Circular RX buffer context.
 */
typedef struct {
  uint8_t *buf;
  uint16_t capacity;
  uint16_t write_pos;
  uint16_t read_pos;
  uint16_t data_len;
} tcp_ring_rx_ctx_t;

/** Singleton ops objects for ring buffer (link tcp_buf_ring.c to use). */
extern const tcp_txbuf_ops_t tcp_ring_tx_ops;
extern const tcp_rxbuf_ops_t tcp_ring_rx_ops;

void tcp_ring_tx_init(tcp_ring_tx_ctx_t *ctx, uint8_t *buf, uint16_t size);
void tcp_ring_rx_init(tcp_ring_rx_ctx_t *ctx, uint8_t *buf, uint16_t size);

/* ══════════════════════════════════════════════════════════════════
 * Packet-List / Scatter-Gather Buffer (tcp_buf_pkt.c) — REQ-TCP-147
 *
 * Future V3 implementation. Application provides a pool of packet
 * nodes. Best for hosted environments or when zero-copy TX matters.
 * ══════════════════════════════════════════════════════════════════ */

/** Single node in a packet-list TX buffer. */
typedef struct tcp_pkt_node_s {
  const uint8_t *data; /**< Payload pointer (may point anywhere) */
  uint16_t len;        /**< Payload length */
  struct tcp_pkt_node_s *next;
} tcp_pkt_node_t;

/**
 * @brief Packet-list TX buffer context.
 */
typedef struct {
  tcp_pkt_node_t *head;      /**< Oldest unACKed node */
  tcp_pkt_node_t *free_list; /**< Available node pool */
  uint16_t total_queued;     /**< Total unACKed bytes */
} tcp_pktlist_tx_ctx_t;

/** Singleton ops for packet-list TX (link tcp_buf_pkt.c to use). */
extern const tcp_txbuf_ops_t tcp_pktlist_tx_ops;

#endif /* TCP_BUF_H */
