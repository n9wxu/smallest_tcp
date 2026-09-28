/**
 * @file demo/dtls_client/main.c
 * @brief DTLS 1.3 client: connects to a DTLS server, sends a message in
 *        datagrams, prints the replies, closes with close_notify.
 *        smallest_tcp's DTLS over its own UDP, with Mbed TLS for the
 *        cryptography.
 *
 * Linux:  sudo ./build/demo/dtls_client_demo [tap0 | raw:veth-sut]
 * macOS:  sudo ./build/demo/dtls_client_demo [feth1]
 * Server: ./examples/server/server -u -v 4 -p 4433 -c tests/tls/server.pem
 *           -k tests/tls/server.key -e              (wolfSSL, on 10.0.0.100)
 *
 * Settings (environment):
 *   DTLS_SERVER  server IPv4 address            (10.0.0.100)
 *   DTLS_PORT    server port                    (4433)
 *   DTLS_MTU     largest datagram to send       (1400)
 *   TLS_NAME     name the certificate must carry, sent as server_name
 *                (pyro-dead01.local; "-" skips the name check)
 *   TLS_CA       trust anchors, PEM             (tests/tls/ca.pem)
 *   TLS_MESSAGE  what to send                   ("hello from smallest_tcp\n")
 *   TLS_BYTES    send this many pattern bytes instead, in datagrams as
 *                large as the MTU allows, and require them back unchanged
 *                (an echo server)
 *   TLS_PSK, TLS_PSK_ID, TLS_PSK_MODES   offer a pre-shared key
 *                (demo_tls.h)
 *   TLS_MFL      ask for records of at most 512/1024/2048/4096 bytes
 *   TLS_KEY_UPDATE  1: new keys (both ways) before sending
 *
 * Exit status: 0 done, 2 DTLS alert, 3 timeout, 1 setup.
 * Also the SUT for tests/blackbox/test_dtls_client_conform.py.
 */

#include "arp.h"
#include "dtls.h"
#include "net.h"
#include "udp.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "demo_loop.h"
#include "demo_tls.h"

#define TIMEOUT_MS 30000u /* the retransmission timer's own limit is 2 min */
#define ARP_RETRY_MS 500u
#define DTLS_RX_SIZE 8192u
#define DTLS_TX_SIZE 4096u

#ifndef DTLS_CLIENT_DEFAULT_CA
#define DTLS_CLIENT_DEFAULT_CA "tests/tls/ca.pem"
#endif

/* Exit status */
#define EXIT_DONE 0
#define EXIT_SETUP 1
#define EXIT_DTLS 2
#define EXIT_TIMEOUT 3

static net_t net;
static demo_mac_t nic;
static uint32_t last_tick;

static demo_tls_t backend;
static tls_config_t cfg;
static uint8_t dtls_rx[DTLS_RX_SIZE];
static uint8_t dtls_tx[DTLS_TX_SIZE];
static dtls_conn_t dtls;

static uint32_t server;
static uint16_t server_port, local_port;

/* What to send, what came back */
static uint8_t out[65536], in[65536];
static size_t out_len, sent, got;
static long pattern_bytes; /* TLS_BYTES: an echo is expected */

/* Everything the connection has to send, to the server */
static void flush(void) {
  const uint8_t *dg;
  size_t n;
  while ((n = dtls_pending(&dtls, &dg)) > 0) {
    udp_send(&net, server, net.gateway_mac, local_port, server_port, dg,
             (uint16_t)n);
    dtls_sent(&dtls);
  }
}

static void on_udp(net_t *n, uint32_t src_ip, uint16_t src_port,
                   const uint8_t *src_mac, const uint8_t *dg, uint16_t len) {
  (void)n;
  (void)src_mac;
  if (src_ip != server || src_port != server_port)
    return; /* not our association */
  (void)dtls_input(&dtls, dg, len);
  flush();
}

static udp_port_entry_t udp_ports[1];

static void tick(uint32_t elapsed_ms) {
  dtls_tick(&dtls, elapsed_ms);
  flush();
}

static const demo_hooks_t hooks = {tick, NULL, NULL};

static void step(void) { demo_step(&net, &last_tick, "dtls_client", &hooks); }

static int setup_tls(void) {
  static uint8_t pem[65536];
  const char *ca = demo_env("TLS_CA", DTLS_CLIENT_DEFAULT_CA);
  unsigned mfl = (unsigned)atoi(demo_env("TLS_MFL", "0")), code;
  size_t n;

  if (demo_tls_backend(&backend, &cfg, "dtls_client") != 0)
    return -1;
  if (!(n = demo_read_pem(ca, pem, sizeof(pem))) ||
      tls_mbedtls_set_ca(&backend.backend, pem, n) != 0) {
    fprintf(stderr, "[dtls_client] cannot read CA %s\n", ca);
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
static int resolve_next_hop(uint32_t start) {
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
  tls_conn_t *t = &dtls.tls;
  printf("[dtls_client] DTLS 1.3 established (TLS_AES_128_GCM_SHA256, %s, "
         "%s)\n",
         demo_tls_group_name(t), tls_psk_used(t) ? "PSK" : "certificate");
  if (t->max_frag)
    printf("[dtls_client] max_fragment_length %u\n", (unsigned)t->max_frag);
  if (atoi(demo_env("TLS_KEY_UPDATE", "0")) && dtls_key_update(&dtls, 1) == 0)
    printf("[dtls_client] KeyUpdate sent\n");
  fflush(stdout);
  flush();
}

/* Send the message a datagram at a time, collect the replies; once it is
 * all back, close.  Returns the exit status once decided, else -1. */
static int exchange(int *closing) {
  size_t n;
  if (sent < out_len) {
    size_t k = out_len - sent, max = dtls_max_data(&dtls);
    int w;
    if (k > max)
      k = max;
    if ((w = dtls_write(&dtls, out + sent, k)) > 0)
      sent += (size_t)w;
    flush();
  }
  while ((n = dtls_read(&dtls, in + got, sizeof(in) - got)) > 0)
    got += n;
  if (got < out_len || *closing)
    return -1;
  if (pattern_bytes > 0)
    printf("[dtls_client] echo %s (%lu bytes)\n",
           memcmp(in, out, out_len) == 0 ? "ok" : "MISMATCH",
           (unsigned long)got);
  else
    printf("[dtls_client] received: %.*s\n", (int)got, (char *)in);
  fflush(stdout);
  (void)dtls_close(&dtls);
  flush();
  *closing = 1;
  return (pattern_bytes > 0 && memcmp(in, out, out_len) != 0) ? EXIT_DTLS
                                                              : EXIT_DONE;
}

/* The session, until it ends or times out */
static int run_session(const char *name, uint32_t start) {
  int announced = 0, closing = 0, rc = EXIT_TIMEOUT, r;
  uint32_t closed_at = 0;

  if (dtls_connect(&dtls, name) != 0) {
    fprintf(stderr, "[dtls_client] cannot start the handshake\n");
    return EXIT_SETUP;
  }
  flush();
  while (demo_running && demo_now_ms() - start < TIMEOUT_MS) {
    step();
    switch (dtls_state(&dtls)) {
    case TLS_STATE_CONNECTED:
      if (!announced) {
        announced = 1;
        announce_connected();
      }
      if ((r = exchange(&closing)) >= 0) {
        rc = r;
        closed_at = demo_now_ms();
      }
      break;
    case TLS_STATE_CLOSED:
      if (!closing) {
        printf("[dtls_client] server closed after %lu bytes\n",
               (unsigned long)got);
        (void)dtls_close(&dtls);
        flush();
        closing = 1;
        rc = got >= out_len ? EXIT_DONE : EXIT_DTLS;
        closed_at = demo_now_ms();
      }
      break;
    case TLS_STATE_ERROR:
      if (dtls.tls.alert == DTLS_TIMEOUT)
        printf("[dtls_client] the server stopped answering\n");
      else
        printf("[dtls_client] DTLS alert %u\n", (unsigned)dtls.tls.alert);
      fflush(stdout);
      flush(); /* our alert, if it was ours */
      return dtls.tls.alert == DTLS_TIMEOUT ? EXIT_TIMEOUT : EXIT_DTLS;
    default:
      break;
    }
    /* after our close_notify, a moment for the server's */
    if (closing && (dtls_state(&dtls) == TLS_STATE_CLOSED ||
                    demo_now_ms() - closed_at > 500u))
      return rc;
  }
  if (demo_running && rc == EXIT_TIMEOUT)
    fprintf(stderr, "[dtls_client] timed out\n");
  return rc;
}

int main(int argc, char *argv[]) {
  const char *name = demo_env("TLS_NAME", "pyro-dead01.local");
  const char *server_s = demo_env("DTLS_SERVER", "10.0.0.100");
  unsigned mtu = (unsigned)atoi(demo_env("DTLS_MTU", "1400"));
  uint32_t start;
  struct in_addr a;
  int rc = EXIT_TIMEOUT;

  server_port = (uint16_t)atoi(demo_env("DTLS_PORT", "4433"));
  if (strcmp(name, "-") == 0)
    name = NULL;
  if (inet_pton(AF_INET, server_s, &a) != 1) {
    fprintf(stderr, "[dtls_client] bad DTLS_SERVER\n");
    return EXIT_SETUP;
  }
  server = ntohl(a.s_addr);
  choose_message();
  if (setup_tls() != 0)
    return EXIT_SETUP;
  if (dtls_init(&dtls, &cfg, dtls_rx, sizeof(dtls_rx), dtls_tx, sizeof(dtls_tx),
                mtu) != 0) {
    fprintf(stderr, "[dtls_client] bad DTLS_MTU\n");
    return EXIT_SETUP;
  }
  if (demo_net_open(&net, &nic, argc > 1 ? argv[1] : NULL, "dtls_client") != 0)
    return EXIT_SETUP;
  local_port = (uint16_t)(49152u + (net_random(&net) & 0x3FFFu));
  udp_ports[0].port = local_port;
  udp_ports[0].handler = on_udp;
  udp_set_ports(&net, udp_ports, 1);

  start = last_tick = demo_now_ms();
  if (resolve_next_hop(start) != 0) {
    fprintf(stderr, "[dtls_client] no ARP reply from the next hop\n");
  } else {
    printf("[dtls_client] connecting to %s:%u as %s (MTU %u)\n", server_s,
           (unsigned)server_port, name ? name : "(any name)", mtu);
    fflush(stdout);
    rc = run_session(name, start);
  }

  dtls_release(&dtls);
  demo_net_close(&nic);
  tls_mbedtls_free(&backend.backend);
  printf("[dtls_client] exit %d\n", rc);
  return rc;
}
