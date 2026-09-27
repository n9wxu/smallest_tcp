/**
 * @file demo_tls.h
 * @brief Shared by the TLS demos: moving bytes between TCP and TLS, and a
 *        pre-shared key from the environment.
 *
 *   TLS_PSK        the key, hex (e.g. 32 bytes = 64 hex digits)
 *   TLS_PSK_ID     its identity                     (default "device-1")
 *   TLS_PSK_MODES  "dhe" (psk_dhe_ke, the default), "ke" (psk_ke) or
 *                  "both"
 */

#ifndef DEMO_TLS_H
#define DEMO_TLS_H

#include "net.h"
#include "tcp.h"
#include "tls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Move ciphertext between a TCP connection and its TLS connection: what
 * arrived straight into the TLS receive buffer, what TLS has to send into
 * the TCP transmit buffer, then transmit. */
static inline void demo_tls_carry(net_t *net, tcp_conn_t *conn,
                                  tls_conn_t *tls) {
  const uint8_t *q;
  uint8_t *p;
  size_t n;
  uint16_t got;
  int w;
  for (;;) {
    n = tls_rx_space(tls, &p);
    if (n > 0xFFFFu)
      n = 0xFFFFu;
    if (!n || !(got = tcp_recv(conn, p, (uint16_t)n)))
      break;
    tls_rx_commit(tls, got);
    tcp_window_update(net, conn);
  }
  while ((n = tls_tx_pending(tls, &q)) > 0) {
    w = tcp_write(conn, q, (uint16_t)(n > 0xFFFFu ? 0xFFFFu : n));
    if (w <= 0)
      break;
    tls_tx_done(tls, (size_t)w);
  }
  tcp_output(net, conn);
}

/* Fill @p cfg's PSK fields from the environment; 0 if none is set, 1 if
 * one is, -1 if TLS_PSK is not valid hex. */
static inline int demo_tls_psk(tls_config_t *cfg, uint8_t *buf, size_t cap) {
  const char *hex = getenv("TLS_PSK"), *id = getenv("TLS_PSK_ID");
  const char *modes = getenv("TLS_PSK_MODES");
  size_t n = 0;
  if (!hex || !*hex)
    return 0;
  while (hex[0] && hex[1] && n < cap) {
    unsigned v;
    if (sscanf(hex, "%2x", &v) != 1)
      return -1;
    buf[n++] = (uint8_t)v;
    hex += 2;
  }
  if (*hex || n == 0)
    return -1;
  if (!id || !*id)
    id = "device-1";
  cfg->psk = buf;
  cfg->psk_len = (uint16_t)n;
  cfg->psk_id = (const uint8_t *)id;
  cfg->psk_id_len = (uint16_t)strlen(id);
  cfg->psk_modes = TLS_PSK_DHE_KE;
  if (modes && strcmp(modes, "ke") == 0)
    cfg->psk_modes = TLS_PSK_KE;
  else if (modes && strcmp(modes, "both") == 0)
    cfg->psk_modes = TLS_PSK_KE | TLS_PSK_DHE_KE;
  return 1;
}

#endif /* DEMO_TLS_H */
