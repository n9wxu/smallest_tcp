/**
 * @file demo/tls_echo/main.c
 * @brief TLS 1.3 echo server on port 4433: smallest_tcp's TLS over its own
 *        TCP, with Mbed TLS for the cryptography.
 *
 * One connection at a time.  Each byte a client sends comes back; a
 * close_notify is answered with one, then the TCP connection closes.
 *
 * Linux:  sudo ./build/demo/tls_echo_demo [tap0 | raw:veth-sut]
 * macOS:  sudo ./build/demo/tls_echo_demo [feth1]
 * Client: openssl s_client -connect 10.0.0.2:4433 -CAfile tests/tls/ca.pem
 *
 * The certificate chain (PEM, leaf first) and key default to the test
 * credentials in tests/tls — TEST ONLY; set TLS_CERT and TLS_KEY to use
 * others.  An ECDSA P-256 key signs with ecdsa_secp256r1_sha256, an RSA
 * key with rsa_pss_rsae_sha256.  TLS_PSK (hex), TLS_PSK_ID and
 * TLS_PSK_MODES add a pre-shared key (demo_tls.h); clients that offer it
 * need no certificate:
 *   openssl s_client -connect 10.0.0.2:4433 -psk <hex> -psk_identity <id>
 *
 * Also the SUT for tests/blackbox/test_tls_conform.py.
 */

#include "eth.h"
#include "net.h"
#include "tcp.h"
#include "tcp_buf.h"
#include "tls.h"
#include "tls_crypto_mbedtls.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "demo_ipv6.h"
#include "demo_mac.h"
#include "demo_tls.h"

#define TLS_PORT 4433u
#define NET_BUF_SIZE 1514u
#define TCP_TX_SIZE 1460u
#define TCP_RX_SIZE 4096u
#define TLS_RX_SIZE (TLS_RECORD_HDR + TLS_MAX_CIPHERTEXT + 512u)
#define TLS_TX_SIZE 4096u
#define MAX_CHAIN 4

#ifndef TLS_ECHO_DEFAULT_CERT
#define TLS_ECHO_DEFAULT_CERT "tests/tls/server.pem"
#define TLS_ECHO_DEFAULT_KEY "tests/tls/server.key"
#endif

/* ── Memory (application-owned) ───────────────────────────────────── */

static uint8_t net_rx_mem[NET_BUF_SIZE];
static uint8_t net_tx_mem[NET_BUF_SIZE];
static net_t net;

static uint8_t tcp_tx_mem[TCP_TX_SIZE];
static uint8_t tcp_rx_mem[TCP_RX_SIZE];
static tcp_saw_tx_ctx_t tx_ctx;
static tcp_saw_rx_ctx_t rx_ctx;
static tcp_conn_t conn;
static tcp_conn_t *conn_table[1];

static tls_mbedtls_t backend;
static tls_crypto_t crypto;
static mbedtls_x509_crt chain;
static mbedtls_pk_context key;
static const uint8_t *chain_der[MAX_CHAIN];
static uint16_t chain_len[MAX_CHAIN];
static tls_config_t cfg;
static uint8_t psk[64];

static uint8_t tls_rx[TLS_RX_SIZE];
static uint8_t tls_tx[TLS_TX_SIZE];
static tls_conn_t tls;

/* The session on the current TCP connection */
static int active, announced, closing, fin_sent;
static uint8_t echo_buf[1024];
static size_t echo_off, echo_len;

static volatile int running = 1;
static volatile int want_listen;

static void sig_handler(int s) {
  (void)s;
  running = 0;
}

static uint32_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}

/* ── Credentials ─────────────────────────────────────────────────── */

static int load_credentials(void) {
  const char *cert_path = getenv("TLS_CERT"), *key_path = getenv("TLS_KEY");
  mbedtls_x509_crt *crt;
  static uint8_t pem[16384];
  FILE *f;
  size_t n;

  if (!cert_path)
    cert_path = TLS_ECHO_DEFAULT_CERT;
  if (!key_path)
    key_path = TLS_ECHO_DEFAULT_KEY;

  mbedtls_x509_crt_init(&chain);
  if (mbedtls_x509_crt_parse_file(&chain, cert_path) != 0) {
    fprintf(stderr, "[tls_echo] cannot read certificate %s\n", cert_path);
    return -1;
  }
  for (crt = &chain; crt && crt->raw.len && cfg.cert_count < MAX_CHAIN;
       crt = crt->next) {
    chain_der[cfg.cert_count] = crt->raw.p;
    chain_len[cfg.cert_count] = (uint16_t)crt->raw.len;
    cfg.cert_count++;
  }

  f = fopen(key_path, "rb");
  if (!f) {
    fprintf(stderr, "[tls_echo] cannot open key %s\n", key_path);
    return -1;
  }
  n = fread(pem, 1, sizeof(pem) - 1, f);
  fclose(f);
  pem[n++] = 0; /* PEM wants its terminating NUL counted */
  if (tls_mbedtls_parse_key(&backend, &key, pem, n) != 0) {
    fprintf(stderr, "[tls_echo] cannot parse key %s\n", key_path);
    return -1;
  }

  cfg.crypto = &crypto;
  cfg.cert = chain_der;
  cfg.cert_len = chain_len;
  cfg.key = &key;
  cfg.sig_scheme = mbedtls_pk_get_type(&key) == MBEDTLS_PK_ECKEY
                       ? TLS_SIG_ECDSA_SECP256R1_SHA256
                       : TLS_SIG_RSA_PSS_RSAE_SHA256;
  return 0;
}

/* ── TCP ─────────────────────────────────────────────────────────── */

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

static void do_listen(void) {
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

/* ── TLS over the connection ─────────────────────────────────────── */

static void tls_service(void) {
  const uint8_t *q;
  int w;
  tcp_state_t st = conn.state;

  /* Both sides have closed and everything was ACKed: recycle the slot now
   * instead of after 2xMSL in TIME_WAIT (as http.c does) */
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

  demo_tls_carry(&net, &conn, &tls);

  /* Echo */
  for (;;) {
    if (!echo_len) {
      echo_off = 0;
      echo_len = tls_read(&tls, echo_buf, sizeof(echo_buf));
      if (!echo_len)
        break;
    }
    w = tls_write(&tls, echo_buf + echo_off, echo_len);
    if (w <= 0)
      break;
    echo_off += (size_t)w;
    echo_len -= (size_t)w;
  }

  demo_tls_carry(&net, &conn, &tls);

  switch (tls_state(&tls)) {
  case TLS_STATE_CONNECTED:
    if (!announced) {
      announced = 1;
      printf("[tls_echo] TLS 1.3 established (TLS_AES_128_GCM_SHA256, "
             "%s, %s)\n",
             tls.group == TLS_GROUP_X25519    ? "x25519"
             : tls.group == TLS_GROUP_SECP256R1 ? "secp256r1"
                                                : "no (EC)DHE",
             tls_psk_used(&tls) ? "PSK" : "certificate");
      fflush(stdout);
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
  if (st == TCP_CLOSE_WAIT) /* the peer is gone, notify or not */
    closing = 1;

  /* Close TCP once everything, alert included, is acknowledged */
  if (closing && !fin_sent && !tls_tx_pending(&tls, &q) &&
      tx_ctx.data_len == 0 && conn.snd_una == conn.snd_nxt) {
    tcp_close(&net, &conn);
    fin_sent = 1;
  }
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
  demo_mac_t nic;
  const net_mac_t *drv;
  uint32_t last_tick;

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  if (tls_mbedtls_init(&backend, &crypto) != 0) {
    fprintf(stderr, "[tls_echo] Mbed TLS initialisation failed\n");
    return 1;
  }
  if (load_credentials() != 0)
    return 1;
  if (demo_tls_psk(&cfg, psk, sizeof(psk)) < 0) {
    fprintf(stderr, "[tls_echo] TLS_PSK is not hex\n");
    return 1;
  }

  if (demo_mac_select(&nic, (argc > 1) ? argv[1] : NULL) != 0)
    return 1;
  drv = nic.ops;
  net_init(&net, net_rx_mem, sizeof(net_rx_mem), net_tx_mem,
           sizeof(net_tx_mem), NULL, drv, &nic.ctx);
  if (drv->init(&nic.ctx) != 0) {
    fprintf(stderr, "[tls_echo] Failed to open MAC driver\n");
    return 1;
  }
#if NET_USE_IPV6
  ipv6_start(&net);
#endif

  conn_table[0] = &conn;
  tcp_connections.conns = conn_table;
  tcp_connections.count = 1;

  printf("[tls_echo] IP: %u.%u.%u.%u, %u certificate(s), %s key%s%s\n",
         (unsigned)((net.ipv4_addr >> 24) & 0xFF),
         (unsigned)((net.ipv4_addr >> 16) & 0xFF),
         (unsigned)((net.ipv4_addr >> 8) & 0xFF),
         (unsigned)(net.ipv4_addr & 0xFF), (unsigned)cfg.cert_count,
         cfg.sig_scheme == TLS_SIG_ECDSA_SECP256R1_SHA256 ? "ECDSA P-256"
                                                          : "RSA",
         cfg.psk ? ", PSK " : "", cfg.psk ? (const char *)cfg.psk_id : "");
  do_listen();

  last_tick = now_ms();
  while (running) {
    uint32_t now, elapsed;
    if (net_poll(&net) > 0)
      eth_input(&net, net.rx.buf, net.rx.frame_len);

    now = now_ms();
    elapsed = now - last_tick;
    if (elapsed >= 10u) {
      tcp_tick(&net, elapsed);
#if NET_USE_IPV6
      ipv6_tick(&net, elapsed);
      demo_ipv6_report(&net, "tls_echo");
#endif
      last_tick = now;
    }

    tls_service();
    if (want_listen) {
      usleep(50000);
      do_listen();
    }
  }

  printf("[tls_echo] shutting down\n");
  if (conn.state == TCP_ESTABLISHED || conn.state == TCP_CLOSE_WAIT)
    tcp_abort(&net, &conn);
  drv->close(&nic.ctx);
  mbedtls_pk_free(&key);
  mbedtls_x509_crt_free(&chain);
  tls_mbedtls_free(&backend);
  return 0;
}
