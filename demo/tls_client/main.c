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
#include "net.h"
#include "tcp.h"
#include "tcp_buf.h"
#include "tls.h"
#include "tls_tcp.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "demo_loop.h"
#include "demo_tls.h"

#define TCP_TX_SIZE 1460u
#define TCP_RX_SIZE 4096u
#define TIMEOUT_MS 15000u
#define ARP_RETRY_MS 500u

#ifndef TLS_CLIENT_DEFAULT_CA
#define TLS_CLIENT_DEFAULT_CA "tests/tls/ca.pem"
#endif

/* Exit status */
#define EXIT_DONE 0
#define EXIT_SETUP 1
#define EXIT_TLS 2
#define EXIT_TIMEOUT 3

static net_t net;
static demo_mac_t nic;
static uint32_t last_tick;

static uint8_t tcp_tx_mem[TCP_TX_SIZE];
static uint8_t tcp_rx_mem[TCP_RX_SIZE];
static tcp_saw_tx_ctx_t tx_ctx;
static tcp_saw_rx_ctx_t rx_ctx;
static tcp_conn_t conn;
static tcp_conn_t *conn_table[1];

static demo_tls_t backend;
static tls_config_t cfg;
static uint8_t tls_rx[DEMO_TLS_RX_SIZE];
static uint8_t tls_tx[DEMO_TLS_TX_SIZE];
static tls_conn_t tls;

/* What to send, what came back */
static uint8_t out[65536], in[65536];
static size_t out_len, sent, got;
static long pattern_bytes; /* TLS_BYTES: an echo is expected */

static void step(void) { demo_step(&net, &last_tick, "tls_client", NULL); }

static int setup_tls(void) {
  static uint8_t pem[65536];
  const char *ca = demo_env("TLS_CA", TLS_CLIENT_DEFAULT_CA);
  unsigned mfl = (unsigned)atoi(demo_env("TLS_MFL", "0")), code;
  size_t n;

  if (demo_tls_backend(&backend, &cfg, "tls_client") != 0)
    return -1;
  if (!(n = demo_read_pem(ca, pem, sizeof(pem))) ||
      tls_mbedtls_set_ca(&backend.backend, pem, n) != 0) {
    fprintf(stderr, "[tls_client] cannot read CA %s\n", ca);
    return -1;
  }
  for (code = TLS_MFL_512; code <= TLS_MFL_4096; code++)
    if (mfl == 256u << code)
      cfg.max_fragment = (uint8_t)code;
  return 0;
}

static void choose_message(void) {
  size_t i;
  pattern_bytes = atol(demo_env("TLS_BYTES", "0"));
  if (pattern_bytes > 0) {
    if (pattern_bytes > (long)sizeof(out))
      pattern_bytes = (long)sizeof(out);
    out_len = (size_t)pattern_bytes;
    for (i = 0; i < out_len; i++)
      out[i] = (uint8_t)('a' + (i % 26u));
  } else {
    const char *msg = demo_env("TLS_MESSAGE", "hello from smallest_tcp\n");
    out_len = strlen(msg);
    memcpy(out, msg, out_len);
  }
}

/* The stack resolves one MAC by ARP, the gateway's: the gateway is pointed
 * at the next hop to the server.  0, or -1 on timeout. */
static int resolve_next_hop(uint32_t server, uint32_t start) {
  uint32_t hop = arp_next_hop(&net, server), asked = 0;
  net.gateway_ipv4 = hop;
  net.gateway_mac_valid = 0;
  while (demo_running && !net.gateway_mac_valid &&
         demo_now_ms() - start < TIMEOUT_MS) {
    if (!asked || demo_now_ms() - asked >= ARP_RETRY_MS) {
      arp_request(&net, hop);
      asked = demo_now_ms();
    }
    step();
  }
  return net.gateway_mac_valid ? 0 : -1;
}

static void announce_connected(void) {
  printf("[tls_client] TLS 1.3 established (TLS_AES_128_GCM_SHA256, %s, "
         "%s)\n",
         demo_tls_group_name(&tls), tls_psk_used(&tls) ? "PSK" : "certificate");
  if (tls.max_frag)
    printf("[tls_client] max_fragment_length %u\n", (unsigned)tls.max_frag);
  if (atoi(demo_env("TLS_KEY_UPDATE", "0")) && tls_key_update(&tls, 1) == 0)
    printf("[tls_client] KeyUpdate sent\n");
  fflush(stdout);
}

/* Send the message, collect the reply; once it is all back, close.
 * Returns the exit status once decided, else -1. */
static int exchange(int *closing) {
  if (sent < out_len) {
    int w = tls_write(&tls, out + sent, out_len - sent);
    if (w > 0)
      sent += (size_t)w;
  }
  got += tls_read(&tls, in + got, sizeof(in) - got);
  if (got < out_len || *closing)
    return -1;
  if (pattern_bytes > 0)
    printf("[tls_client] echo %s (%lu bytes)\n",
           memcmp(in, out, out_len) == 0 ? "ok" : "MISMATCH",
           (unsigned long)got);
  else
    printf("[tls_client] received: %.*s\n", (int)got, (char *)in);
  fflush(stdout);
  tls_close(&tls);
  *closing = 1;
  return (pattern_bytes > 0 && memcmp(in, out, out_len) != 0) ? EXIT_TLS
                                                              : EXIT_DONE;
}

static int tcp_open(void) {
  return conn.state == TCP_ESTABLISHED || conn.state == TCP_CLOSE_WAIT;
}

/* The TLS session over the TCP connection, until it ends or times out */
static int run_session(const char *name, uint32_t start) {
  int started = 0, announced = 0, closing = 0, rc = EXIT_TIMEOUT, r;

  while (demo_running && demo_now_ms() - start < TIMEOUT_MS) {
    step();
    if (conn.state == TCP_CLOSED) { /* done, refused or reset */
      if (!closing)
        fprintf(stderr, "[tls_client] TCP connection %s\n",
                started ? "closed" : "refused");
      return rc;
    }
    if (!tcp_open() && !(closing && started))
      continue;
    if (!started) {
      tls_init(&tls, &cfg, tls_rx, sizeof(tls_rx), tls_tx, sizeof(tls_tx));
      tls_connect(&tls, name);
      started = 1;
    }
    if (tcp_open())
      tls_tcp_carry(&net, &conn, &tls);

    switch (tls_state(&tls)) {
    case TLS_STATE_CONNECTED:
      if (!announced) {
        announced = 1;
        announce_connected();
      }
      if ((r = exchange(&closing)) >= 0)
        rc = r;
      break;
    case TLS_STATE_CLOSED:
      if (!closing) {
        printf("[tls_client] server closed after %lu bytes\n",
               (unsigned long)got);
        tls_close(&tls);
        closing = 1;
        rc = got >= out_len ? EXIT_DONE : EXIT_TLS;
      }
      break;
    case TLS_STATE_ERROR:
      printf("[tls_client] TLS alert %u\n", (unsigned)tls.alert);
      fflush(stdout);
      tls_tcp_carry(&net, &conn, &tls); /* our alert, if it was ours */
      return EXIT_TLS;
    default:
      break;
    }
    if (closing && conn.state == TCP_ESTABLISHED && tls_tcp_idle(&conn, &tls))
      tcp_close(&net, &conn);
    if (closing &&
        (conn.state == TCP_TIME_WAIT || conn.state == TCP_CLOSE_WAIT)) {
      if (conn.state == TCP_CLOSE_WAIT)
        tcp_close(&net, &conn);
      return rc;
    }
  }
  if (demo_running && rc == EXIT_TIMEOUT)
    fprintf(stderr, "[tls_client] timed out\n");
  return rc;
}

int main(int argc, char *argv[]) {
  const char *name = demo_env("TLS_NAME", "pyro-dead01.local");
  const char *server_s = demo_env("TLS_SERVER", "10.0.0.100");
  unsigned port = (unsigned)atoi(demo_env("TLS_PORT", "4433"));
  uint32_t server, start;
  struct in_addr a;
  int rc = EXIT_TIMEOUT;

  if (strcmp(name, "-") == 0)
    name = NULL;
  if (inet_pton(AF_INET, server_s, &a) != 1) {
    fprintf(stderr, "[tls_client] bad TLS_SERVER\n");
    return EXIT_SETUP;
  }
  server = ntohl(a.s_addr);
  choose_message();
  if (setup_tls() != 0)
    return EXIT_SETUP;
  if (demo_net_open(&net, &nic, argc > 1 ? argv[1] : NULL, "tls_client") != 0)
    return EXIT_SETUP;
  conn_table[0] = &conn;
  tcp_set_connections(&net, conn_table, 1);
  tcp_saw_tx_init(&tx_ctx, tcp_tx_mem, TCP_TX_SIZE);
  tcp_saw_rx_init(&rx_ctx, tcp_rx_mem, TCP_RX_SIZE);
  tcp_conn_init(&conn, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops, &rx_ctx,
                NULL);

  start = last_tick = demo_now_ms();
  if (resolve_next_hop(server, start) != 0) {
    fprintf(stderr, "[tls_client] no ARP reply from the next hop\n");
  } else {
    tcp_connect(&net, &conn, server, net.gateway_mac, (uint16_t)port,
                (uint16_t)(49152u + (net_random(&net) & 0x3FFFu)));
    printf("[tls_client] connecting to %s:%u as %s\n", server_s, port,
           name ? name : "(any name)");
    fflush(stdout);
    rc = run_session(name, start);
  }

  if (tcp_open()) {
    uint32_t t0 = demo_now_ms();
    while (demo_now_ms() - t0 < 200u) /* let the last segments go */
      step();
    tcp_abort(&net, &conn);
  }
  tls_release(&tls);
  demo_net_close(&nic);
  tls_mbedtls_free(&backend.backend);
  printf("[tls_client] exit %d\n", rc);
  return rc;
}
