/**
 * @file tcp_buf.h
 * @brief The buffers behind a TCP connection, as two operation tables the
 *        application passes to tcp_conn_init(), and the stop-and-wait
 *        implementation (tcp_buf_saw.c).
 *
 * tcp.c never touches buffer memory itself.  See docs/design/tcp-buffer.md.
 */

#ifndef TCP_BUF_H
#define TCP_BUF_H

#include "net_config.h"
#include <stdint.h>

/** Outgoing data: what the application wrote, until the peer ACKs it. */
typedef struct {
  /** Queue data from the application; returns the bytes accepted. */
  uint16_t (*write)(void *ctx, const uint8_t *data, uint16_t len);

  /** The next segment to send, at most @p mss bytes, in place; 0 if
   *  nothing is ready.  The bytes are then in flight.  Not called if
   *  copy_segment() is given. */
  uint16_t (*next_segment)(void *ctx, const uint8_t **data, uint16_t mss);

  /** The peer acknowledged @p bytes_acked bytes: release them.  The count
   *  may include our FIN, so it is capped at the bytes sent. */
  void (*ack)(void *ctx, uint32_t bytes_acked);

  /** Bytes sent and not yet acknowledged: TCP resends them, from the
   *  start, only after mark_retransmit(). */
  uint16_t (*in_flight)(const void *ctx);

  /** Bytes written and not yet acknowledged, sent or not. */
  uint16_t (*queued)(const void *ctx);

  /** Room for the application to write. */
  uint16_t (*writable)(const void *ctx);

  /** A retransmission timeout: next_segment() must return the in-flight
   *  data again. */
  void (*mark_retransmit)(void *ctx);

  /** Optional, in place of next_segment() (which may then be NULL): copy
   *  the next segment, at most @p mss bytes, to @p dst — for a buffer
   *  whose data is not always one contiguous run, such as a ring, which
   *  would otherwise send a short segment at every wrap.  @return the
   *  bytes copied, which are then in flight; 0 if nothing is ready. */
  uint16_t (*copy_segment)(void *ctx, uint8_t *dst, uint16_t mss);
} tcp_txbuf_ops_t;

/** Incoming data: in-order bytes from the peer, until the application
 *  reads them.  Free space is the advertised window. */
typedef struct {
  /** Store received bytes; returns the bytes taken. */
  uint16_t (*deliver)(void *ctx, const uint8_t *data, uint16_t len);

  /** Copy bytes out for the application; returns the byte count. */
  uint16_t (*read)(void *ctx, uint8_t *dst, uint16_t maxlen);

  /** Bytes waiting to be read. */
  uint16_t (*readable)(const void *ctx);

  /** Free space: the receive window. */
  uint16_t (*available)(const void *ctx);
} tcp_rxbuf_ops_t;

/* ── Stop-and-wait (tcp_buf_saw.c) ──────────────────────────────────
 * One segment in flight: nothing more is accepted from the application
 * until it is acknowledged.  The receive side is a ring buffer.        */

typedef struct {
  uint8_t *buf;
  uint16_t capacity;
  uint16_t data_len; /**< Written, not yet acknowledged */
  uint16_t sent_len; /**< Of those, sent: in flight */
} tcp_saw_tx_ctx_t;

typedef struct {
  uint8_t *buf;
  uint16_t capacity;
  uint16_t write_pos;
  uint16_t read_pos;
  uint16_t data_len; /**< Received, not yet read */
} tcp_saw_rx_ctx_t;

extern const tcp_txbuf_ops_t tcp_saw_tx_ops;
extern const tcp_rxbuf_ops_t tcp_saw_rx_ops;

void tcp_saw_tx_init(tcp_saw_tx_ctx_t *ctx, uint8_t *buf, uint16_t size);

/** @p size is also the largest window advertised. */
void tcp_saw_rx_init(tcp_saw_rx_ctx_t *ctx, uint8_t *buf, uint16_t size);

#endif /* TCP_BUF_H */
