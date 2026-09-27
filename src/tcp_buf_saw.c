/**
 * @file tcp_buf_saw.c
 * @brief Stop-and-wait TCP buffers (REQ-TCP-145): one segment in flight;
 *        a ring buffer for received data.
 */

#include "tcp_buf.h"
#include <string.h>

static uint16_t saw_tx_write(void *ctx, const uint8_t *data, uint16_t len) {
  tcp_saw_tx_ctx_t *c = (tcp_saw_tx_ctx_t *)ctx;
  uint16_t space = (uint16_t)(c->capacity - c->data_len);
  if (c->sent_len)
    return 0;
  if (len > space)
    len = space;
  memcpy(c->buf + c->data_len, data, len);
  c->data_len = (uint16_t)(c->data_len + len);
  return len;
}

static uint16_t saw_tx_next_segment(void *ctx, const uint8_t **data,
                                    uint16_t mss) {
  tcp_saw_tx_ctx_t *c = (tcp_saw_tx_ctx_t *)ctx;
  if (c->sent_len || c->data_len == 0)
    return 0;
  *data = c->buf;
  c->sent_len = c->data_len < mss ? c->data_len : mss;
  return c->sent_len;
}

static void saw_tx_ack(void *ctx, uint32_t bytes_acked) {
  tcp_saw_tx_ctx_t *c = (tcp_saw_tx_ctx_t *)ctx;
  uint16_t acked =
      bytes_acked < c->sent_len ? (uint16_t)bytes_acked : c->sent_len;
  if (acked == 0)
    return;
  c->data_len = (uint16_t)(c->data_len - acked);
  c->sent_len = (uint16_t)(c->sent_len - acked);
  memmove(c->buf, c->buf + acked, c->data_len);
}

static uint16_t saw_tx_in_flight(const void *ctx) {
  return ((const tcp_saw_tx_ctx_t *)ctx)->sent_len;
}

static uint16_t saw_tx_queued(const void *ctx) {
  return ((const tcp_saw_tx_ctx_t *)ctx)->data_len;
}

static uint16_t saw_tx_writable(const void *ctx) {
  const tcp_saw_tx_ctx_t *c = (const tcp_saw_tx_ctx_t *)ctx;
  return c->sent_len ? 0 : (uint16_t)(c->capacity - c->data_len);
}

static void saw_tx_mark_retransmit(void *ctx) {
  ((tcp_saw_tx_ctx_t *)ctx)->sent_len = 0;
}

const tcp_txbuf_ops_t tcp_saw_tx_ops = {
    saw_tx_write,           saw_tx_next_segment, saw_tx_ack,
    saw_tx_in_flight,       saw_tx_queued,       saw_tx_writable,
    saw_tx_mark_retransmit,
};

void tcp_saw_tx_init(tcp_saw_tx_ctx_t *ctx, uint8_t *buf, uint16_t size) {
  ctx->buf = buf;
  ctx->capacity = size;
  ctx->data_len = 0;
  ctx->sent_len = 0;
}

/* pos + n with pos < capacity and n <= capacity: one subtraction wraps
 * it (no '%', which Cortex-M0 would have to call a library divide for) */
static uint16_t ring_advance(const tcp_saw_rx_ctx_t *c, uint16_t pos,
                             uint16_t n) {
  uint16_t next = (uint16_t)(pos + n);
  return next >= c->capacity ? (uint16_t)(next - c->capacity) : next;
}

static uint16_t saw_rx_deliver(void *ctx, const uint8_t *data, uint16_t len) {
  tcp_saw_rx_ctx_t *c = (tcp_saw_rx_ctx_t *)ctx;
  uint16_t space = (uint16_t)(c->capacity - c->data_len);
  uint16_t first;
  if (len > space)
    len = space;
  first = (uint16_t)(c->capacity - c->write_pos);
  if (first > len)
    first = len;
  memcpy(c->buf + c->write_pos, data, first);
  memcpy(c->buf, data + first, (size_t)(len - first));
  c->write_pos = ring_advance(c, c->write_pos, len);
  c->data_len = (uint16_t)(c->data_len + len);
  return len;
}

static uint16_t saw_rx_read(void *ctx, uint8_t *dst, uint16_t maxlen) {
  tcp_saw_rx_ctx_t *c = (tcp_saw_rx_ctx_t *)ctx;
  uint16_t n = c->data_len < maxlen ? c->data_len : maxlen;
  uint16_t first = (uint16_t)(c->capacity - c->read_pos);
  if (first > n)
    first = n;
  memcpy(dst, c->buf + c->read_pos, first);
  memcpy(dst + first, c->buf, (size_t)(n - first));
  c->read_pos = ring_advance(c, c->read_pos, n);
  c->data_len = (uint16_t)(c->data_len - n);
  return n;
}

static uint16_t saw_rx_readable(const void *ctx) {
  return ((const tcp_saw_rx_ctx_t *)ctx)->data_len;
}

static uint16_t saw_rx_available(const void *ctx) {
  const tcp_saw_rx_ctx_t *c = (const tcp_saw_rx_ctx_t *)ctx;
  return (uint16_t)(c->capacity - c->data_len);
}

const tcp_rxbuf_ops_t tcp_saw_rx_ops = {
    saw_rx_deliver,
    saw_rx_read,
    saw_rx_readable,
    saw_rx_available,
};

void tcp_saw_rx_init(tcp_saw_rx_ctx_t *ctx, uint8_t *buf, uint16_t size) {
  ctx->buf = buf;
  ctx->capacity = size;
  ctx->write_pos = 0;
  ctx->read_pos = 0;
  ctx->data_len = 0;
}
