/**
 * @file http_tls.c
 * @brief The HTTP server's TLS transport: TLS 1.3 over the slot's TCP
 *        connection.
 */

#include "http_tls.h"
#include "tls_tcp.h"

static tls_conn_t *slot_tls(const http_conn_t *c) {
  return (tls_conn_t *)c->transport_ctx;
}

static void tls_accepted(net_t *net, http_conn_t *c) {
  tls_conn_t *t = slot_tls(c);
  (void)net;
  tls_init(t, t->cfg, t->rx, t->rx_cap, t->tx, t->tx_cap);
  tls_accept(t);
}

static uint16_t tls_read_some(net_t *net, http_conn_t *c, uint8_t *buf,
                              uint16_t len) {
  tls_tcp_carry(net, &c->tcp, slot_tls(c));
  return (uint16_t)tls_read(slot_tls(c), buf, len);
}

static uint16_t tls_write_some(http_conn_t *c, const uint8_t *data,
                               uint16_t len) {
  int n = tls_write(slot_tls(c), data, len);
  return n > 0 ? (uint16_t)n : 0;
}

static void tls_flush(net_t *net, http_conn_t *c) {
  tls_tcp_carry(net, &c->tcp, slot_tls(c));
}

static void tls_finish(net_t *net, http_conn_t *c) {
  tls_close(slot_tls(c));
  tls_tcp_carry(net, &c->tcp, slot_tls(c));
}

static int tls_client_done(const http_conn_t *c) {
  tls_state_t st = tls_state(slot_tls(c));
  return c->tcp.state == TCP_CLOSE_WAIT || st == TLS_STATE_CLOSED ||
         st == TLS_STATE_ERROR;
}

static int tls_delivered(http_conn_t *c) {
  return tls_tcp_idle(&c->tcp, slot_tls(c));
}

static void tls_released(http_conn_t *c) { tls_release(slot_tls(c)); }

static const http_transport_t tls_transport = {
    tls_accepted, tls_read_some,   tls_write_some, tls_flush,
    tls_finish,   tls_client_done, tls_delivered,  tls_released,
};

void http_conn_use_tls(http_conn_t *c, tls_conn_t *tls) {
  c->transport = &tls_transport;
  c->transport_ctx = tls;
}
