/**
 * @file demo/https_demo/main.c
 * @brief HTTPS server demo: HTTP/1.0 over smallest_tcp's TLS 1.3 over its
 *        TCP, with Mbed TLS for the cryptography — https://10.0.0.2/.
 *
 * One connection at a time on port 443.  The request is parsed and the
 * response header formatted by http.c's parser and formatter; every
 * response ends the connection (close_notify, then FIN).
 *
 *   GET  /            HTML status page
 *   GET  /api/status  JSON: uptime, requests, the connection's TLS
 *                     parameters
 *   GET  /big         20000 bytes (many records, many TCP segments)
 *   HEAD on any of them; anything else 404 / 405
 *
 * Linux:  sudo ./build/demo/https_demo [tap0 | raw:veth-sut]
 * macOS:  sudo ./build/demo/https_demo [feth1]
 * Client: curl --cacert tests/tls/ca.pem https://10.0.0.2/
 *         curl --cacert tests/tls/ca.pem \
 *              --resolve pyro-dead01.local:443:10.0.0.2 \
 *              https://pyro-dead01.local/
 *
 * Credentials as tls_echo: tests/tls (TEST ONLY) unless TLS_CERT and
 * TLS_KEY name others.  Also the SUT for
 * tests/blackbox/test_https_conform.py.
 */

#define _POSIX_C_SOURCE 200809L

#include "eth.h"
#include "http.h"
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

#include "demo_ipv6.h"
#include "demo_mac.h"
#include "demo_tls.h"

#define HTTPS_PORT 443u
#define NET_BUF_SIZE 1514u
#define TCP_TX_SIZE 1460u
#define TCP_RX_SIZE 4096u
#define TLS_RX_SIZE (TLS_RECORD_HDR + TLS_MAX_CIPHERTEXT + 512u)
#define TLS_TX_SIZE 4096u
#define REQ_SIZE 2048u
#define TIMEOUT_MS 10000u

#ifndef HTTPS_DEFAULT_CERT
#define HTTPS_DEFAULT_CERT "tests/tls/server.pem"
#define HTTPS_DEFAULT_KEY "tests/tls/server.key"
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
static const uint8_t *chain_der[4];
static uint16_t chain_len[4];
static tls_config_t cfg;
static uint8_t tls_rx[TLS_RX_SIZE];
static uint8_t tls_tx[TLS_TX_SIZE];
static tls_conn_t tls;

/* The exchange on the current connection */
enum { S_IDLE, S_READ, S_WRITE, S_CLOSING };
static int phase, fin_sent;
static char req[REQ_SIZE];
static size_t req_len;
static char hdr[HTTP_HDR_MAX];
static size_t hdr_len, sent;
static const uint8_t *body;
static size_t body_len;
static uint32_t started_ms;

static uint32_t start_ms, requests;
static uint8_t big[20000];
static char scratch[512];

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

/* ── Pages ────────────────────────────────────────────────────────── */

static const char index_html[] =
    "<!DOCTYPE html>\n"
    "<html><head><title>Pyro Unit 1 (HTTPS)</title></head>\n"
    "<body><h1>Pyro Unit 1</h1>\n"
    "<p>Served over TLS 1.3 by smallest_tcp.</p>\n"
    "<ul><li><a href=\"/api/status\">/api/status</a> (JSON)</li>\n"
    "<li><a href=\"/big\">/big</a> (20000 bytes)</li></ul>\n"
    "</body></html>\n";

/* The response to a parsed request: status, type, body */
static uint16_t route(const http_request_t *rq, const char **type) {
  int n;
  *type = "text/html";
  if (strcmp(rq->path, "/") == 0) {
    body = (const uint8_t *)index_html;
    body_len = sizeof(index_html) - 1;
  } else if (strcmp(rq->path, "/api/status") == 0) {
    n = snprintf(scratch, sizeof(scratch),
                 "{\"uptime_ms\":%lu,\"requests\":%lu,"
                 "\"tls\":\"TLSv1.3\",\"cipher\":\"TLS_AES_128_GCM_SHA256\","
                 "\"group\":\"%s\",\"auth\":\"%s\"}\n",
                 (unsigned long)(now_ms() - start_ms),
                 (unsigned long)requests,
                 tls.group == TLS_GROUP_X25519      ? "x25519"
                 : tls.group == TLS_GROUP_SECP256R1 ? "secp256r1"
                                                    : "none",
                 tls_psk_used(&tls) ? "psk" : "certificate");
    body = (const uint8_t *)scratch;
    body_len = (size_t)n;
    *type = "application/json";
  } else if (strcmp(rq->path, "/big") == 0) {
    body = big;
    body_len = sizeof(big);
    *type = "text/plain";
  } else {
    body = (const uint8_t *)http_reason(404);
    body_len = strlen(http_reason(404));
    *type = "text/plain";
    return 404;
  }
  if (rq->method == HTTP_POST) {
    body = (const uint8_t *)http_reason(405);
    body_len = strlen(http_reason(405));
    *type = "text/plain";
    return 405;
  }
  return 200;
}

/* A whole request header block is in req[]: prepare the response */
static void respond(size_t end) {
  http_request_t rq;
  uint32_t content_length = 0;
  const char *type = "text/plain";
  uint16_t status;

  memset(&rq, 0, sizeof(rq));
  status = http_parse_request(req, (uint16_t)end, &rq, &content_length);
  if (status == HTTP_PARSE_OK)
    status = route(&rq, &type);
  else {
    body = (const uint8_t *)http_reason(status);
    body_len = strlen(http_reason(status));
  }
  requests++;
  hdr_len = http_format_header(hdr, sizeof(hdr), status, type,
                               (uint32_t)body_len,
                               status == 405 ? HTTP_GET | HTTP_HEAD : 0);
  if (rq.method == HTTP_HEAD)
    body_len = 0;
  printf("[https] %s %s -> %u\n",
         rq.method == HTTP_HEAD ? "HEAD" : rq.method == HTTP_POST ? "POST"
                                                                  : "GET",
         rq.path ? rq.path : "?", (unsigned)status);
  fflush(stdout);
  sent = 0;
  phase = S_WRITE;
}

/* ── Credentials (as demo/tls_echo) ──────────────────────────────── */

static int load_credentials(void) {
  const char *cert_path = getenv("TLS_CERT"), *key_path = getenv("TLS_KEY");
  static uint8_t pem[16384];
  mbedtls_x509_crt *crt;
  FILE *f;
  size_t n;

  if (!cert_path)
    cert_path = HTTPS_DEFAULT_CERT;
  if (!key_path)
    key_path = HTTPS_DEFAULT_KEY;
  mbedtls_x509_crt_init(&chain);
  if (mbedtls_x509_crt_parse_file(&chain, cert_path) != 0) {
    fprintf(stderr, "[https] cannot read certificate %s\n", cert_path);
    return -1;
  }
  for (crt = &chain; crt && crt->raw.len && cfg.cert_count < 4;
       crt = crt->next) {
    chain_der[cfg.cert_count] = crt->raw.p;
    chain_len[cfg.cert_count] = (uint16_t)crt->raw.len;
    cfg.cert_count++;
  }
  if (!(f = fopen(key_path, "rb"))) {
    fprintf(stderr, "[https] cannot open key %s\n", key_path);
    return -1;
  }
  n = fread(pem, 1, sizeof(pem) - 1, f);
  fclose(f);
  pem[n++] = 0;
  if (tls_mbedtls_parse_key(&backend, &key, pem, n) != 0) {
    fprintf(stderr, "[https] cannot parse key %s\n", key_path);
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
  if (events & (TCP_EVT_CLOSED | TCP_EVT_RESET | TCP_EVT_ERROR))
    want_listen = 1;
}

static void do_listen(void) {
  tcp_saw_tx_init(&tx_ctx, tcp_tx_mem, TCP_TX_SIZE);
  tcp_saw_rx_init(&rx_ctx, tcp_rx_mem, TCP_RX_SIZE);
  tcp_conn_init(&conn, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops, &rx_ctx,
                on_tcp_event);
  tcp_listen(&conn, HTTPS_PORT);
  phase = S_IDLE;
  fin_sent = 0;
  want_listen = 0;
}

/* ── HTTPS on the connection ─────────────────────────────────────── */

static void https_service(void) {
  const uint8_t *q;
  tcp_state_t st = conn.state;

  if (fin_sent &&
      (st == TCP_TIME_WAIT || st == TCP_CLOSING || st == TCP_CLOSED)) {
    want_listen = 1;
    return;
  }
  if (st != TCP_ESTABLISHED && st != TCP_CLOSE_WAIT)
    return;
  if (phase == S_IDLE) {
    tls_init(&tls, &cfg, tls_rx, sizeof(tls_rx), tls_tx, sizeof(tls_tx));
    tls_accept(&tls);
    req_len = 0;
    phase = S_READ;
    started_ms = now_ms();
  }

  demo_tls_carry(&net, &conn, &tls);

  if (phase == S_READ && tls_state(&tls) == TLS_STATE_CONNECTED) {
    size_t end;
    req_len += tls_read(&tls, (uint8_t *)req + req_len,
                        sizeof(req) - 1 - req_len);
    end = http_header_end(req, (uint16_t)req_len);
    if (end)
      respond(end);
    else if (req_len == sizeof(req) - 1) { /* no end in sight */
      body = (const uint8_t *)http_reason(431);
      body_len = strlen(http_reason(431));
      hdr_len = http_format_header(hdr, sizeof(hdr), 431, "text/plain",
                                   (uint32_t)body_len, 0);
      sent = 0;
      phase = S_WRITE;
    }
  }
  if (phase == S_WRITE) {
    int w;
    while (sent < hdr_len + body_len) {
      if (sent < hdr_len)
        w = tls_write(&tls, (const uint8_t *)hdr + sent, hdr_len - sent);
      else
        w = tls_write(&tls, body + (sent - hdr_len),
                      hdr_len + body_len - sent);
      if (w <= 0)
        break;
      sent += (size_t)w;
    }
    if (sent == hdr_len + body_len) {
      tls_close(&tls);
      phase = S_CLOSING;
    }
  }
  if (tls_state(&tls) == TLS_STATE_ERROR || tls_state(&tls) == TLS_STATE_CLOSED ||
      st == TCP_CLOSE_WAIT || now_ms() - started_ms > TIMEOUT_MS)
    phase = S_CLOSING;

  demo_tls_carry(&net, &conn, &tls);

  if (phase == S_CLOSING && !fin_sent && !tls_tx_pending(&tls, &q) &&
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
  size_t i;

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);
  for (i = 0; i < sizeof(big); i++) /* 'a'..'z', a newline every 64th */
    big[i] = (uint8_t)((i & 63u) == 63u ? '\n' : 'a' + (i % 26u));

  if (tls_mbedtls_init(&backend, &crypto) != 0 || load_credentials() != 0)
    return 1;
  if (demo_mac_select(&nic, (argc > 1) ? argv[1] : NULL) != 0)
    return 1;
  drv = nic.ops;
  net_init(&net, net_rx_mem, sizeof(net_rx_mem), net_tx_mem,
           sizeof(net_tx_mem), NULL, drv, &nic.ctx);
  if (drv->init(&nic.ctx) != 0) {
    fprintf(stderr, "[https] Failed to open MAC driver\n");
    return 1;
  }
#if NET_USE_IPV6
  ipv6_start(&net);
#endif
  conn_table[0] = &conn;
  tcp_connections.conns = conn_table;
  tcp_connections.count = 1;
  start_ms = now_ms();
  printf("[https] https://%u.%u.%u.%u/ (port %u)\n",
         (unsigned)((net.ipv4_addr >> 24) & 0xFF),
         (unsigned)((net.ipv4_addr >> 16) & 0xFF),
         (unsigned)((net.ipv4_addr >> 8) & 0xFF),
         (unsigned)(net.ipv4_addr & 0xFF), HTTPS_PORT);
  fflush(stdout);
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
      demo_ipv6_report(&net, "https");
#endif
      last_tick = now;
    }
    https_service();
    if (want_listen)
      do_listen();
  }

  printf("[https] shutting down\n");
  if (conn.state == TCP_ESTABLISHED || conn.state == TCP_CLOSE_WAIT)
    tcp_abort(&net, &conn);
  drv->close(&nic.ctx);
  mbedtls_pk_free(&key);
  mbedtls_x509_crt_free(&chain);
  tls_mbedtls_free(&backend);
  return 0;
}
