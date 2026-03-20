/**
 * @file tcp_buf_saw.c
 * @brief TCP stop-and-wait buffer implementation — REQ-TCP-145.
 *
 * Smallest possible TCP buffer strategy:
 *   - TX: one application-provided buffer, at most 1 segment in flight.
 *   - RX: one application-provided buffer, at most 1 segment worth of data.
 *
 * Throughput: 1 segment per RTT (adequate for TFTP, bootloader, etc.).
 * RAM overhead: 2 × buffer_size (both provided by the application).
 * Flash: ~200 bytes.
 *
 * This file is separate so that an application linking only this file
 * pays only this code's flash cost. Applications that need streaming
 * throughput can link tcp_buf_ring.c instead without changing tcp.c.
 *
 * Implements the compile-time dependency injection contract defined in
 * tcp_buf.h (REQ-TCP-142, REQ-TCP-143, REQ-TCP-144, REQ-TCP-145).
 */

#include "tcp_buf.h"
#include <string.h>

/* ── TX Implementation ───────────────────────────────────────────── */

/**
 * Write data into the TX buffer.
 *
 * If a segment is currently in-flight (sent but not yet ACKed), no new
 * data can be accepted — the application must wait for the ACK.
 * Otherwise, data is appended up to available capacity.
 */
static uint16_t saw_tx_write(void *ctx, const uint8_t *data, uint16_t len) {
  tcp_saw_tx_ctx_t *c = (tcp_saw_tx_ctx_t *)ctx;

  /* Stop-and-wait: cannot accept new data while a segment is in flight */
  if (c->in_flight)
    return 0;

  /* Clamp to available space */
  uint16_t space = c->capacity - c->data_len;
  if (len > space)
    len = space;
  if (len == 0)
    return 0;

  memcpy(c->buf + c->data_len, data, len);
  c->data_len += len;
  return len;
}

/**
 * Get pointer to the next segment to send (zero-copy).
 *
 * Returns the buffered data (up to mss bytes) as a pointer directly into
 * the buffer, avoiding any copy. Sets in_flight = 1 to prevent overwriting
 * before the ACK arrives.
 *
 * Returns 0 if:
 *   - There is no data to send (data_len == 0)
 *   - A segment is already in-flight (stop-and-wait constraint)
 */
static uint16_t saw_tx_next_segment(void *ctx, const uint8_t **data,
                                    uint16_t mss) {
  tcp_saw_tx_ctx_t *c = (tcp_saw_tx_ctx_t *)ctx;

  /* Already in-flight or nothing to send */
  if (c->in_flight || c->data_len == 0)
    return 0;

  uint16_t seg_len = c->data_len;
  if (seg_len > mss)
    seg_len = mss;

  *data = c->buf;
  c->in_flight = 1;
  return seg_len;
}

/**
 * Acknowledge bytes (advance past ACKed data).
 *
 * For stop-and-wait, the entire in-flight segment is either ACKed or not.
 * On partial ACK (shouldn't happen with 1 segment, but handle defensively),
 * shift remaining data to the front of the buffer.
 */
static void saw_tx_ack(void *ctx, uint32_t bytes_acked) {
  tcp_saw_tx_ctx_t *c = (tcp_saw_tx_ctx_t *)ctx;

  if (bytes_acked == 0)
    return;

  /* Clamp to data_len (defensive) */
  if ((uint16_t)bytes_acked > c->data_len)
    bytes_acked = c->data_len;

  if ((uint16_t)bytes_acked == c->data_len) {
    /* All data acknowledged — clear buffer */
    c->data_len = 0;
    c->in_flight = 0;
  } else {
    /* Partial ACK — shift unACKed data to front */
    uint16_t remaining = c->data_len - (uint16_t)bytes_acked;
    memmove(c->buf, c->buf + bytes_acked, remaining);
    c->data_len = remaining;
    c->in_flight = 0; /* allow resend of remainder */
  }
}

/**
 * How many bytes are currently in-flight?
 *
 * In stop-and-wait mode this is either data_len (if in_flight) or 0.
 */
static uint16_t saw_tx_in_flight(const void *ctx) {
  const tcp_saw_tx_ctx_t *c = (const tcp_saw_tx_ctx_t *)ctx;
  return c->in_flight ? c->data_len : 0;
}

/**
 * How many bytes can the application still write?
 *
 * Zero if a segment is in-flight (must wait for ACK).
 */
static uint16_t saw_tx_writable(const void *ctx) {
  const tcp_saw_tx_ctx_t *c = (const tcp_saw_tx_ctx_t *)ctx;
  if (c->in_flight)
    return 0;
  return c->capacity - c->data_len;
}

/* ── RX Implementation ───────────────────────────────────────────── */

/**
 * Deliver received bytes from the network into the RX buffer.
 *
 * Accepts as many bytes as fit in the remaining capacity.
 * The TCP layer will advertise window = available(), so in normal
 * operation the peer will not send more than fits.
 */
static uint16_t saw_rx_deliver(void *ctx, const uint8_t *data, uint16_t len) {
  tcp_saw_rx_ctx_t *c = (tcp_saw_rx_ctx_t *)ctx;

  uint16_t space = c->capacity - c->data_len;
  if (len > space)
    len = space;
  if (len == 0)
    return 0;

  /* Simple linear delivery — write at write_pos */
  uint16_t end = c->write_pos + len;
  if (end <= c->capacity) {
    memcpy(c->buf + c->write_pos, data, len);
  } else {
    /* Wrap around (for future ring-compatible layout) */
    uint16_t first = c->capacity - c->write_pos;
    memcpy(c->buf + c->write_pos, data, first);
    memcpy(c->buf, data + first, len - first);
  }
  c->write_pos = (uint16_t)((c->write_pos + len) % c->capacity);
  c->data_len += len;
  return len;
}

/**
 * Application reads data out of the RX buffer.
 *
 * Copies up to maxlen bytes into dst, advances read_pos.
 */
static uint16_t saw_rx_read(void *ctx, uint8_t *dst, uint16_t maxlen) {
  tcp_saw_rx_ctx_t *c = (tcp_saw_rx_ctx_t *)ctx;

  if (c->data_len == 0 || maxlen == 0)
    return 0;

  uint16_t n = c->data_len;
  if (n > maxlen)
    n = maxlen;

  uint16_t end = c->read_pos + n;
  if (end <= c->capacity) {
    memcpy(dst, c->buf + c->read_pos, n);
  } else {
    uint16_t first = c->capacity - c->read_pos;
    memcpy(dst, c->buf + c->read_pos, first);
    memcpy(dst + first, c->buf, n - first);
  }
  c->read_pos = (uint16_t)((c->read_pos + n) % c->capacity);
  c->data_len -= n;
  return n;
}

/**
 * How many bytes are available for the application to read?
 */
static uint16_t saw_rx_readable(const void *ctx) {
  const tcp_saw_rx_ctx_t *c = (const tcp_saw_rx_ctx_t *)ctx;
  return c->data_len;
}

/**
 * How many bytes of free space remain in the RX buffer?
 *
 * This value is advertised as RCV.WND in outgoing TCP segments.
 * When it reaches zero the peer must stop sending.
 */
static uint16_t saw_rx_available(const void *ctx) {
  const tcp_saw_rx_ctx_t *c = (const tcp_saw_rx_ctx_t *)ctx;
  return c->capacity - c->data_len;
}

/* ── Ops Singletons ──────────────────────────────────────────────── */

/**
 * Mark in-flight data as needing retransmission.
 *
 * For stop-and-wait: clear in_flight so next_segment() returns the
 * buffered data again on the next call. The data bytes remain intact.
 */
static void saw_tx_mark_retransmit(void *ctx) {
  tcp_saw_tx_ctx_t *c = (tcp_saw_tx_ctx_t *)ctx;
  c->in_flight = 0;
}

/* ── Ops Singletons ──────────────────────────────────────────────── */

/**
 * Compile-time-constant ops table for stop-and-wait TX.
 * Link tcp_buf_saw.c to get this symbol.
 */
const tcp_txbuf_ops_t tcp_saw_tx_ops = {
    saw_tx_write,     saw_tx_next_segment, saw_tx_ack,
    saw_tx_in_flight, saw_tx_writable,     saw_tx_mark_retransmit,
};

/**
 * Compile-time-constant ops table for stop-and-wait RX.
 * Link tcp_buf_saw.c to get this symbol.
 */
const tcp_rxbuf_ops_t tcp_saw_rx_ops = {
    saw_rx_deliver,
    saw_rx_read,
    saw_rx_readable,
    saw_rx_available,
};

/* ── Factory Functions ───────────────────────────────────────────── */

void tcp_saw_tx_init(tcp_saw_tx_ctx_t *ctx, uint8_t *buf, uint16_t size) {
  ctx->buf = buf;
  ctx->capacity = size;
  ctx->data_len = 0;
  ctx->in_flight = 0;
}

void tcp_saw_rx_init(tcp_saw_rx_ctx_t *ctx, uint8_t *buf, uint16_t size) {
  ctx->buf = buf;
  ctx->capacity = size;
  ctx->write_pos = 0;
  ctx->read_pos = 0;
  ctx->data_len = 0;
}
