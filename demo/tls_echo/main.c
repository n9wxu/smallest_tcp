/**
 * @file demo/tls_echo/main.c
 * @brief TLS 1.3 echo server on port 4433: smallest_tcp's TLS over its own
 *        TCP, with Mbed TLS for the cryptography.
 *
 * One connection at a time.  Each byte a client sends comes back; a
 * close_notify is answered with one, then the TCP connection closes.
 *
 *   sudo ./build/demo/tls_echo_demo [tap0 | raw:<ifname> | feth1]
 *   openssl s_client -connect 10.0.0.2:4433 -CAfile tests/tls/ca.pem
 *
 * Credentials and a pre-shared key as demo_tls.h; with TLS_PSK set, a
 * client offering the key needs no certificate:
 *   openssl s_client -connect 10.0.0.2:4433 -psk <hex> -psk_identity <id>
 *
 * The SUT of tests/blackbox/test_tls_conform.py.
 */

#include "net.h"
#include "tcp.h"
#include "tcp_buf.h"
#include "tls.h"
#include "tls_tcp.h"
#include <stdio.h>
#include <string.h>

#include "demo_loop.h"
#include "demo_tls.h"

#define TLS_PORT 4433u
#define TCP_TX_SIZE 1460u
#define TCP_RX_SIZE 4096u

#ifndef TLS_ECHO_DEFAULT_CERT
#define TLS_ECHO_DEFAULT_CERT "tests/tls/server.pem"
#define TLS_ECHO_DEFAULT_KEY "tests/tls/server.key"
#endif

static net_t net;
static demo_mac_t nic;

static uint8_t tcp_tx_mem[TCP_TX_SIZE];
static uint8_t tcp_rx_mem[TCP_RX_SIZE];
static tcp_saw_tx_ctx_t tx_ctx;
static tcp_saw_rx_ctx_t rx_ctx;
static tcp_conn_t conn;
static tcp_conn_t *conn_table[1];

static demo_tls_t credentials;
static tls_config_t cfg;
static uint8_t tls_rx[DEMO_TLS_RX_SIZE];
static uint8_t tls_tx[DEMO_TLS_TX_SIZE];
static tls_conn_t tls;

/* The session on the current TCP connection */
static int active, announced, closing, fin_sent;
static uint8_t echo_buf[1024];
static size_t echo_off, echo_len;
static volatile int want_listen;

static void on_tcp_event(tcp_conn_t *c, uint8_t events) {
  (void)c;
  if (events & TCP_EVT_CONNECTED)
    printf("[tls_echo] TCP connection established\n");
  if (events & (TCP_EVT_RESET | TCP_EVT_ERROR))
    printf("[tls_echo] TCP connection reset\n");
  if (events & (TCP_EVT_CLOSED | TCP_EVT_RESET | TCP_EVT_ERROR))
    want_listen = 1;
  fflush(stdout);
}

static void listen_again(void) {
  tcp_saw_tx_init(&tx_ctx, tcp_tx_mem, TCP_TX_SIZE);
  tcp_saw_rx_init(&rx_ctx, tcp_rx_mem, TCP_RX_SIZE);
  tcp_conn_init(&conn, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops, &rx_ctx,
                on_tcp_event);
  tcp_listen(&conn, TLS_PORT);
  active = announced = closing = fin_sent = 0;
  echo_len = 0;
  want_listen = 0;
  printf("[tls_echo] listening on port %u\n", TLS_PORT);
  fflush(stdout);
}

static void echo(void) {
  for (;;) {
    int w;
    if (!echo_len) {
      echo_off = 0;
      if (!(echo_len = tls_read(&tls, echo_buf, sizeof(echo_buf))))
        return;
    }
    if ((w = tls_write(&tls, echo_buf + echo_off, echo_len)) <= 0)
      return;
    echo_off += (size_t)w;
    echo_len -= (size_t)w;
  }
}

/* Once: the handshake's outcome, and the start of the close */
static void report_tls_state(void) {
  switch (tls_state(&tls)) {
  case TLS_STATE_CONNECTED:
    if (!announced) {
      announced = 1;
      printf("[tls_echo] TLS 1.3 established (TLS_AES_128_GCM_SHA256, "
             "%s, %s)\n",
             demo_tls_group_name(&tls),
             tls_psk_used(&tls) ? "PSK" : "certificate");
    }
    break;
  case TLS_STATE_CLOSED: /* close_notify: answer it */
    if (!closing) {
      printf("[tls_echo] close_notify received\n");
      tls_close(&tls);
      closing = 1;
    }
    break;
  case TLS_STATE_ERROR:
    if (!closing) {
      printf("[tls_echo] TLS alert %u\n", (unsigned)tls.alert);
      closing = 1;
    }
    break;
  default:
    break;
  }
  fflush(stdout);
}

static void service(void) {
  tcp_state_t st = conn.state;

  if (want_listen) {
    usleep(50000);
    listen_again();
    return;
  }
  /* Both sides closed and everything was acknowledged: recycle the
   * connection now instead of after 2×MSL in TIME-WAIT */
  if (fin_sent &&
      (st == TCP_TIME_WAIT || st == TCP_CLOSING || st == TCP_CLOSED)) {
    want_listen = 1;
    return;
  }
  if (st != TCP_ESTABLISHED && st != TCP_CLOSE_WAIT)
    return;
  if (!active) {
    tls_init(&tls, &cfg, tls_rx, sizeof(tls_rx), tls_tx, sizeof(tls_tx));
    tls_accept(&tls);
    active = 1;
  }
  tls_tcp_carry(&net, &conn, &tls);
  echo();
  tls_tcp_carry(&net, &conn, &tls);
  report_tls_state();
  if (st == TCP_CLOSE_WAIT) /* the peer is gone, notify or not */
    closing = 1;
  if (closing && !fin_sent && tls_tcp_idle(&conn, &tls)) {
    tcp_close(&net, &conn);
    fin_sent = 1;
  }
}

int main(int argc, char *argv[]) {
  const demo_hooks_t hooks = {NULL, service, NULL};

  if (demo_tls_server(&credentials, &cfg, TLS_ECHO_DEFAULT_CERT,
                      TLS_ECHO_DEFAULT_KEY, "tls_echo") != 0)
    return 1;
  if (demo_net_open(&net, &nic, argc > 1 ? argv[1] : NULL, "tls_echo") != 0)
    return 1;
  conn_table[0] = &conn;
  tcp_set_connections(&net, conn_table, 1);

  printf("[tls_echo] IP: ");
  demo_print_ipv4(net.ipv4_addr);
  printf(", %u certificate(s), %s key%s%s\n", (unsigned)cfg.cert_count,
         cfg.sig_scheme == TLS_SIG_ECDSA_SECP256R1_SHA256 ? "ECDSA P-256"
                                                          : "RSA",
         cfg.psk ? ", PSK " : "", cfg.psk ? (const char *)cfg.psk_id : "");
  listen_again();

  demo_run(&net, "tls_echo", &hooks);

  printf("[tls_echo] shutting down\n");
  if (conn.state == TCP_ESTABLISHED || conn.state == TCP_CLOSE_WAIT)
    tcp_abort(&net, &conn);
  demo_net_close(&nic);
  demo_tls_free(&credentials);
  return 0;
}
