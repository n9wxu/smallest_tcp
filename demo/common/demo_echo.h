/**
 * @file demo/common/demo_echo.h
 * @brief A TCP echo service on one connection: every byte received is sent
 *        back; when the client closes we close, then listen again.
 */

#ifndef DEMO_ECHO_H
#define DEMO_ECHO_H

#include "net.h"
#include "tcp.h"
#include "tcp_buf.h"
#include <stdio.h>
#include <unistd.h>

#define DEMO_ECHO_BUF 1024u

typedef struct {
  tcp_conn_t conn; /* first: the event callback gets a pointer to it */
  tcp_saw_tx_ctx_t tx_ctx;
  tcp_saw_rx_ctx_t rx_ctx;
  uint8_t tx_mem[DEMO_ECHO_BUF];
  uint8_t rx_mem[DEMO_ECHO_BUF];
  uint16_t port;
  const char *tag;
  volatile int data, peer_closed, gone; /* set by the event callback */
} demo_echo_t;

static void demo_echo_on_event(tcp_conn_t *conn, uint8_t events) {
  demo_echo_t *e = (demo_echo_t *)conn;
  if (events & TCP_EVT_CONNECTED)
    printf("[%s] connection established\n", e->tag);
  if (events & TCP_EVT_DATA)
    e->data = 1;
  if (events & TCP_EVT_CLOSED)
    e->peer_closed = 1;
  if (events & (TCP_EVT_RESET | TCP_EVT_ERROR)) {
    printf("[%s] connection reset\n", e->tag);
    e->gone = 1;
  }
  fflush(stdout);
}

static inline void demo_echo_listen(demo_echo_t *e) {
  tcp_saw_tx_init(&e->tx_ctx, e->tx_mem, sizeof(e->tx_mem));
  tcp_saw_rx_init(&e->rx_ctx, e->rx_mem, sizeof(e->rx_mem));
  tcp_conn_init(&e->conn, &tcp_saw_tx_ops, &e->tx_ctx, &tcp_saw_rx_ops,
                &e->rx_ctx, demo_echo_on_event);
  tcp_listen(&e->conn, e->port);
  e->data = e->peer_closed = e->gone = 0;
  printf("[%s] listening on port %u\n", e->tag, (unsigned)e->port);
  fflush(stdout);
}

/** Bind the connection to @p net and listen on @p port. */
static inline void demo_echo_start(net_t *net, demo_echo_t *e, uint16_t port,
                                   const char *tag) {
  static tcp_conn_t *table[1];
  e->port = port;
  e->tag = tag;
  table[0] = &e->conn;
  tcp_set_connections(net, table, 1);
  demo_echo_listen(e);
}

/* The stop-and-wait buffer takes one segment at a time: what does not fit
 * is dropped (and reported) */
static inline void demo_echo_data(net_t *net, demo_echo_t *e) {
  uint8_t buf[256];
  uint16_t n;
  while ((n = tcp_recv(&e->conn, buf, sizeof(buf))) > 0) {
    int sent = tcp_send(net, &e->conn, buf, n);
    if (sent < (int)n)
      fprintf(stderr, "[%s] TX buffer full, %d bytes dropped\n", e->tag,
              (int)n - (sent > 0 ? sent : 0));
  }
}

/** From the main loop: act on what the event callback recorded. */
static inline void demo_echo_service(net_t *net, demo_echo_t *e) {
  if (e->data) {
    e->data = 0;
    demo_echo_data(net, e);
  }
  if (e->peer_closed) {
    e->peer_closed = 0;
    if (e->conn.state == TCP_CLOSE_WAIT)
      tcp_close(net, &e->conn); /* our FIN answers theirs */
    else if (e->conn.state == TCP_CLOSED)
      e->gone = 1;
  }
  if (e->gone) {
    usleep(50000); /* the pacing the blackbox TCP suite is tuned to */
    demo_echo_listen(e);
  }
}

static inline void demo_echo_stop(net_t *net, demo_echo_t *e) {
  if (e->conn.state == TCP_ESTABLISHED || e->conn.state == TCP_CLOSE_WAIT)
    tcp_abort(net, &e->conn);
}

#endif /* DEMO_ECHO_H */
