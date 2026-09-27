/**
 * @file tls_tcp.c
 * @brief A TLS connection carried over a TCP connection.
 */

#include "tls_tcp.h"

static uint16_t at_most_u16(size_t n) {
  return (uint16_t)(n > 0xFFFFu ? 0xFFFFu : n);
}

static void carry_in(net_t *net, tcp_conn_t *tcp, tls_conn_t *tls) {
  uint8_t *space;
  uint16_t got;
  size_t room;
  while ((room = tls_rx_space(tls, &space)) > 0 &&
         (got = tcp_recv(tcp, space, at_most_u16(room))) > 0) {
    tls_rx_commit(tls, got);
    tcp_window_update(net, tcp);
  }
}

static void carry_out(tcp_conn_t *tcp, tls_conn_t *tls) {
  const uint8_t *pending;
  size_t n;
  int taken;
  while ((n = tls_tx_pending(tls, &pending)) > 0 &&
         (taken = tcp_write(tcp, pending, at_most_u16(n))) > 0)
    tls_tx_done(tls, (size_t)taken);
}

void tls_tcp_carry(net_t *net, tcp_conn_t *tcp, tls_conn_t *tls) {
  carry_in(net, tcp, tls);
  carry_out(tcp, tls);
  tcp_output(net, tcp);
}

int tls_tcp_idle(const tcp_conn_t *tcp, tls_conn_t *tls) {
  const uint8_t *pending;
  return tls_tx_pending(tls, &pending) == 0 && tcp_tx_idle(tcp);
}
