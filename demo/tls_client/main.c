/**
 * @file demo/tls_client/main.c
 * @brief TLS 1.3 client: connects to a TLS server, sends a message, prints
 *        the reply, closes with close_notify.  smallest_tcp's TLS over its
 *        own TCP, with Mbed TLS for the cryptography.
 *
 * Linux:  sudo ./build/demo/tls_client_demo [tap0 | raw:veth-sut]
 * macOS:  sudo ./build/demo/tls_client_demo [feth1]
 * Server: openssl s_server -accept 4433 -cert tests/tls/server.pem
 *           -key tests/tls/server.key -rev        (on 10.0.0.100)
 *
 * Settings (environment):
 *   TLS_SERVER   server IPv4 address            (10.0.0.100)
 *   TLS_PORT     server port                    (4433)
 *   TLS_NAME     name the certificate must carry, sent as server_name
 *                (pyro-dead01.local; "-" skips the name check)
 *   TLS_CA       trust anchors, PEM             (tests/tls/ca.pem)
 *   TLS_MESSAGE  what to send                   ("hello from smallest_tcp\n")
 *   TLS_BYTES    send this many pattern bytes instead, and require them
 *                back unchanged (an echo server)
 *   TLS_PSK, TLS_PSK_ID, TLS_PSK_MODES   offer a pre-shared key
 *                (demo_tls.h)
 *   TLS_MFL      ask for records of at most 512/1024/2048/4096 bytes
 *   TLS_KEY_UPDATE  1: new keys (both ways) before sending
 *
 * Exit status: 0 done, 2 TLS alert, 3 timeout or TCP failure, 1 setup.
 * Also the SUT for tests/blackbox/test_tls_client_conform.py.
 */

#include "arp.h"
#include "eth.h"
#include "net.h"
#include "tcp.h"
#include "tcp_buf.h"
#include "tls.h"
#include "tls_crypto_mbedtls.h"
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "demo_mac.h"
#include "demo_tls.h"

#define NET_BUF_SIZE 1514u
#define TCP_TX_SIZE 1460u
#define TCP_RX_SIZE 4096u
#define TLS_RX_SIZE (TLS_RECORD_HDR + TLS_MAX_CIPHERTEXT + 512u)
#define TLS_TX_SIZE 4096u
#define TIMEOUT_MS 15000u

#ifndef TLS_CLIENT_DEFAULT_CA
#define TLS_CLIENT_DEFAULT_CA "tests/tls/ca.pem"
#endif

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
static tls_config_t cfg;
static uint8_t tls_rx[TLS_RX_SIZE];
static uint8_t tls_tx[TLS_TX_SIZE];
static tls_conn_t tls;

static volatile int running = 1;
static void sig_handler(int s) {
  (void)s;
  running = 0;
}

static uint32_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}

static const char *env(const char *name, const char *dflt) {
  const char *v = getenv(name);
  return v && *v ? v : dflt;
}

/* Poll the network and run timers */
static void service(uint32_t *last) {
  uint32_t now = now_ms();
  if (net_poll(&net) > 0)
    eth_input(&net, net.rx.buf, net.rx.frame_len);
  if (now - *last >= 10u) {
    tcp_tick(&net, now - *last);
    *last = now;
  }
}

/* Move ciphertext between TCP and TLS */
static void carry(void) {
  const uint8_t *q;
  uint8_t *p;
  size_t n;
  uint16_t got;
  int w;
  for (;;) {
    n = tls_rx_space(&tls, &p);
    if (n > 0xFFFFu)
      n = 0xFFFFu;
    if (!n || !(got = tcp_recv(&conn, p, (uint16_t)n)))
      break;
    tls_rx_commit(&tls, got);
    tcp_window_update(&net, &conn);
  }
  while ((n = tls_tx_pending(&tls, &q)) > 0) {
    w = tcp_write(&conn, q, (uint16_t)(n > 0xFFFFu ? 0xFFFFu : n));
    if (w <= 0)
      break;
    tls_tx_done(&tls, (size_t)w);
  }
  tcp_output(&net, &conn);
}

int main(int argc, char *argv[]) {
  static uint8_t out[65536], in[65536];
  const char *name = env("TLS_NAME", "pyro-dead01.local");
  const char *ca = env("TLS_CA", TLS_CLIENT_DEFAULT_CA);
  const char *msg = env("TLS_MESSAGE", "hello from smallest_tcp\n");
  long bytes = atol(env("TLS_BYTES", "0"));
  unsigned port = (unsigned)atoi(env("TLS_PORT", "4433"));
  struct in_addr a;
  uint32_t server, hop, start, last, arp_at = 0;
  size_t out_len, sent = 0, got = 0;
  int started = 0, announced = 0, closing = 0, rc = 3;
  demo_mac_t nic;
  const net_mac_t *drv;
  size_t i;

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);
  if (strcmp(name, "-") == 0)
    name = NULL;
  if (inet_pton(AF_INET, env("TLS_SERVER", "10.0.0.100"), &a) != 1) {
    fprintf(stderr, "[tls_client] bad TLS_SERVER\n");
    return 1;
  }
  server = ntohl(a.s_addr);

  /* What to send */
  if (bytes > 0) {
    if (bytes > (long)sizeof(out))
      bytes = (long)sizeof(out);
    out_len = (size_t)bytes;
    for (i = 0; i < out_len; i++)
      out[i] = (uint8_t)('a' + (i % 26u));
  } else {
    out_len = strlen(msg);
    memcpy(out, msg, out_len);
  }

  /* Crypto and trust anchors */
  {
    static uint8_t pem[65536];
    FILE *f = fopen(ca, "rb");
    size_t n;
    if (tls_mbedtls_init(&backend, &crypto) != 0 || !f) {
      fprintf(stderr, "[tls_client] cannot set up (CA %s)\n", ca);
      return 1;
    }
    n = fread(pem, 1, sizeof(pem) - 1, f);
    fclose(f);
    pem[n++] = 0;
    if (tls_mbedtls_set_ca(&backend, pem, n) != 0) {
      fprintf(stderr, "[tls_client] cannot parse %s\n", ca);
      return 1;
    }
  }
  cfg.crypto = &crypto;
  {
    unsigned mfl = (unsigned)atoi(env("TLS_MFL", "0")), code;
    for (code = 1; code <= 4; code++)
      if (mfl == 256u << code)
        cfg.max_fragment = (uint8_t)code;
  }
  {
    static uint8_t psk[64];
    if (demo_tls_psk(&cfg, psk, sizeof(psk)) < 0) {
      fprintf(stderr, "[tls_client] TLS_PSK is not hex\n");
      return 1;
    }
  }

  if (demo_mac_select(&nic, (argc > 1) ? argv[1] : NULL) != 0)
    return 1;
  drv = nic.ops;
  net_init(&net, net_rx_mem, sizeof(net_rx_mem), net_tx_mem,
           sizeof(net_tx_mem), NULL, drv, &nic.ctx);
  if (drv->init(&nic.ctx) != 0) {
    fprintf(stderr, "[tls_client] Failed to open MAC driver\n");
    return 1;
  }
  conn_table[0] = &conn;
  tcp_connections.conns = conn_table;
  tcp_connections.count = 1;
  tcp_saw_tx_init(&tx_ctx, tcp_tx_mem, TCP_TX_SIZE);
  tcp_saw_rx_init(&rx_ctx, tcp_rx_mem, TCP_RX_SIZE);
  tcp_conn_init(&conn, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops, &rx_ctx,
                NULL);

  /* The next hop's MAC: the stack learns one MAC by ARP, the gateway's,
   * so the gateway is pointed at the next hop to the server */
  hop = arp_next_hop(&net, server);
  net.gateway_ipv4 = hop;
  net.gateway_mac_valid = 0;
  start = last = now_ms();
  while (running && !net.gateway_mac_valid &&
         now_ms() - start < TIMEOUT_MS) {
    if (now_ms() - arp_at >= 500u) {
      arp_request(&net, hop);
      arp_at = now_ms();
    }
    service(&last);
  }
  if (!net.gateway_mac_valid) {
    fprintf(stderr, "[tls_client] no ARP reply from the next hop\n");
    goto done;
  }
  tcp_connect(&net, &conn, server, net.gateway_mac, (uint16_t)port,
              (uint16_t)(49152u + (now_ms() & 0x3FFFu)));
  printf("[tls_client] connecting to %s:%u as %s\n",
         env("TLS_SERVER", "10.0.0.100"), port, name ? name : "(any name)");
  fflush(stdout);

  while (running && now_ms() - start < TIMEOUT_MS) {
    service(&last);
    if (conn.state == TCP_CLOSED) { /* done, refused or reset */
      if (!closing)
        fprintf(stderr, "[tls_client] TCP connection %s\n",
                started ? "closed" : "refused");
      break;
    }
    if (conn.state != TCP_ESTABLISHED && conn.state != TCP_CLOSE_WAIT &&
        !(closing && started))
      continue;
    if (!started) {
      tls_init(&tls, &cfg, tls_rx, sizeof(tls_rx), tls_tx, sizeof(tls_tx));
      tls_connect(&tls, name);
      started = 1;
    }
    if (conn.state == TCP_ESTABLISHED || conn.state == TCP_CLOSE_WAIT)
      carry();

    switch (tls_state(&tls)) {
    case TLS_STATE_CONNECTED:
      if (!announced) {
        announced = 1;
        printf("[tls_client] TLS 1.3 established (TLS_AES_128_GCM_SHA256, "
               "%s, %s)\n",
               tls.group == TLS_GROUP_X25519      ? "x25519"
               : tls.group == TLS_GROUP_SECP256R1 ? "secp256r1"
                                                  : "no (EC)DHE",
               tls_psk_used(&tls) ? "PSK" : "certificate");
        if (tls.max_frag)
          printf("[tls_client] max_fragment_length %u\n",
                 (unsigned)tls.max_frag);
        if (atoi(env("TLS_KEY_UPDATE", "0")) && tls_key_update(&tls, 1) == 0)
          printf("[tls_client] KeyUpdate sent\n");
        fflush(stdout);
      }
      if (sent < out_len) {
        int w = tls_write(&tls, out + sent, out_len - sent);
        if (w > 0)
          sent += (size_t)w;
      }
      got += tls_read(&tls, in + got, sizeof(in) - got);
      if (got >= out_len && !closing) {
        if (bytes > 0)
          printf("[tls_client] echo %s (%lu bytes)\n",
                 memcmp(in, out, out_len) == 0 ? "ok" : "MISMATCH",
                 (unsigned long)got);
        else
          printf("[tls_client] received: %.*s\n", (int)got, (char *)in);
        fflush(stdout);
        tls_close(&tls);
        closing = 1;
        rc = (bytes > 0 && memcmp(in, out, out_len) != 0) ? 2 : 0;
      }
      break;
    case TLS_STATE_CLOSED:
      if (!closing) {
        printf("[tls_client] server closed after %lu bytes\n",
               (unsigned long)got);
        tls_close(&tls);
        closing = 1;
        rc = got >= out_len ? 0 : 2;
      }
      break;
    case TLS_STATE_ERROR:
      printf("[tls_client] TLS alert %u\n", (unsigned)tls.alert);
      fflush(stdout);
      carry(); /* our alert, if it was ours */
      rc = 2;
      goto done;
    default:
      break;
    }
    if (closing && conn.state == TCP_ESTABLISHED) {
      const uint8_t *q;
      if (!tls_tx_pending(&tls, &q) && tx_ctx.data_len == 0 &&
          conn.snd_una == conn.snd_nxt)
        tcp_close(&net, &conn);
    }
    if (closing && (conn.state == TCP_TIME_WAIT ||
                    conn.state == TCP_CLOSE_WAIT)) {
      if (conn.state == TCP_CLOSE_WAIT)
        tcp_close(&net, &conn);
      break;
    }
  }
  if (rc == 3 && running)
    fprintf(stderr, "[tls_client] timed out\n");

done:
  if (conn.state == TCP_ESTABLISHED || conn.state == TCP_CLOSE_WAIT) {
    uint32_t t0 = now_ms();
    while (now_ms() - t0 < 200u) /* let the last segments go */
      service(&last);
    tcp_abort(&net, &conn);
  }
  drv->close(&nic.ctx);
  tls_mbedtls_free(&backend);
  printf("[tls_client] exit %d\n", rc);
  return rc;
}
