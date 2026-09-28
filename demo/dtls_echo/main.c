/**
 * @file demo/dtls_echo/main.c
 * @brief DTLS 1.3 echo server on UDP port 4433: smallest_tcp's DTLS over
 *        its own UDP, with Mbed TLS for the cryptography.
 *
 * Each datagram a client sends comes back; a close_notify is answered with
 * one.  A few clients at a time, each with its own connection: a
 * ClientHello from a new address and port takes a free one, or one still
 * waiting for its cookie to come back — forged ClientHellos cannot fill
 * the table — and a connection is let go when it closes, fails or has been
 * idle for IDLE_MS.
 *
 *   sudo ./build/demo/dtls_echo_demo [tap0 | raw:<ifname> | feth1]
 *   ./examples/client/client -u -v 4 -h 10.0.0.2 -p 4433 -A tests/tls/ca.pem
 *                                                         (wolfSSL)
 *
 * Credentials and a pre-shared key as demo_tls.h.  DTLS_NO_COOKIE=1 skips
 * the cookie exchange; DTLS_MTU sets the largest datagram sent (1400).  The
 * SUT of tests/blackbox/test_dtls_conform.py.
 */

#include "dtls.h"
#include "net.h"
#include "udp.h"
#include <stdio.h>
#include <string.h>

#include "demo_loop.h"
#include "demo_tls.h"

#define DTLS_PORT 4433u
#define PEERS 3
#define MTU_MAX 1400u /* within an Ethernet frame over IPv4 or IPv6 */
#define IDLE_MS 60000u
#define DTLS_RX_SIZE 4096u
#define DTLS_TX_SIZE 4096u

#ifndef DTLS_ECHO_DEFAULT_CERT
#define DTLS_ECHO_DEFAULT_CERT "tests/tls/server.pem"
#define DTLS_ECHO_DEFAULT_KEY "tests/tls/server.key"
#endif

typedef struct {
  dtls_conn_t d;
  uint8_t rx[DTLS_RX_SIZE], tx[DTLS_TX_SIZE];
  int used, announced, closing;
  uint32_t idle_ms;
  /* the peer: where its datagrams come from, where ours go */
  int v6;
  uint32_t ip;
#if NET_USE_IPV6
  uint8_t ip6[16];
#endif
  uint16_t port;
  uint8_t mac[6];
} peer_t;

static net_t net;
static demo_mac_t nic;
static demo_tls_t credentials;
static tls_config_t cfg;
static peer_t peers[PEERS];
static unsigned mtu = MTU_MAX;

static void print_peer(const peer_t *p) {
#if NET_USE_IPV6
  if (p->v6) {
    char s[48];
    size_t i, n = 0;
    for (i = 0; i < 16; i += 2)
      n += (size_t)snprintf(s + n, sizeof(s) - n, "%s%x", i ? ":" : "",
                            (unsigned)((p->ip6[i] << 8) | p->ip6[i + 1]));
    printf("[%s]:%u", s, (unsigned)p->port);
    return;
  }
#endif
  demo_print_ipv4(p->ip);
  printf(":%u", (unsigned)p->port);
}

/* Everything the connection has to send, to its peer */
static void flush(peer_t *p) {
  const uint8_t *dg;
  size_t n;
  while ((n = dtls_pending(&p->d, &dg)) > 0) {
#if NET_USE_IPV6
    if (p->v6)
      udp6_send(&net, p->ip6, p->mac, DTLS_PORT, p->port, dg, (uint16_t)n);
    else
#endif
      udp_send(&net, p->ip, p->mac, DTLS_PORT, p->port, dg, (uint16_t)n);
    dtls_sent(&p->d);
  }
}

static void drop(peer_t *p, const char *why) {
  printf("[dtls_echo] ");
  print_peer(p);
  printf(" %s\n", why);
  fflush(stdout);
  dtls_release(&p->d);
  p->used = 0;
}

/* A DTLSPlaintext ClientHello (RFC 9147 §4, §5.2) starts an association */
static int is_client_hello(const uint8_t *dg, uint16_t len) {
  return len > 13 + 12 && dg[0] == TLS_CT_HANDSHAKE &&
         dg[13] == TLS_HS_CLIENT_HELLO;
}

/* A connection for a new peer: a free one, else one whose client never
 * returned its cookie (a forged address, or a client gone) */
static peer_t *new_peer(void) {
  int i;
  for (i = 0; i < PEERS; i++)
    if (!peers[i].used)
      break;
  if (i == PEERS)
    for (i = 0; i < PEERS; i++)
      if (!dtls_peer_verified(&peers[i].d)) {
        drop(&peers[i], "never returned its cookie: connection reused");
        break;
      }
  if (i == PEERS)
    return NULL;
  memset(&peers[i], 0, sizeof(peers[i]));
  if (dtls_init(&peers[i].d, &cfg, peers[i].rx, DTLS_RX_SIZE, peers[i].tx,
                DTLS_TX_SIZE, mtu) != 0 ||
      dtls_accept(&peers[i].d) != 0)
    return NULL;
  peers[i].used = 1;
  return &peers[i];
}

static void datagram(peer_t *p, const uint8_t *dg, uint16_t len) {
  p->idle_ms = 0;
  (void)dtls_input(&p->d, dg, len);
  flush(p);
}

static peer_t *find4(uint32_t ip, uint16_t port) {
  int i;
  for (i = 0; i < PEERS; i++)
    if (peers[i].used && !peers[i].v6 && peers[i].ip == ip &&
        peers[i].port == port)
      return &peers[i];
  return NULL;
}

static void on_udp(net_t *n, uint32_t src_ip, uint16_t src_port,
                   const uint8_t *src_mac, const uint8_t *dg, uint16_t len) {
  peer_t *p = find4(src_ip, src_port);
  (void)n;
  if (!p) {
    if (!is_client_hello(dg, len) || !(p = new_peer()))
      return;
    p->ip = src_ip;
    p->port = src_port;
    memcpy(p->mac, src_mac, 6);
  }
  datagram(p, dg, len);
}

static const udp_port_entry_t udp_ports[] = {{DTLS_PORT, on_udp}};

#if NET_USE_IPV6
static peer_t *find6(const uint8_t *ip, uint16_t port) {
  int i;
  for (i = 0; i < PEERS; i++)
    if (peers[i].used && peers[i].v6 && peers[i].port == port &&
        memcmp(peers[i].ip6, ip, 16) == 0)
      return &peers[i];
  return NULL;
}

static void on_udp6(net_t *n, const uint8_t *src_ip, uint16_t src_port,
                    const uint8_t *src_mac, const uint8_t *dg, uint16_t len) {
  peer_t *p = find6(src_ip, src_port);
  (void)n;
  if (!p) {
    if (!is_client_hello(dg, len) || !(p = new_peer()))
      return;
    p->v6 = 1;
    memcpy(p->ip6, src_ip, 16);
    p->port = src_port;
    memcpy(p->mac, src_mac, 6);
  }
  datagram(p, dg, len);
}

static const udp6_port_entry_t udp6_ports[] = {{DTLS_PORT, on_udp6}};
#endif

/* Each datagram back as it came: a record read is a datagram written */
static void echo(peer_t *p) {
  uint8_t buf[MTU_MAX];
  size_t n;
  while (dtls_max_data(&p->d) > 0 &&
         (n = dtls_read(&p->d, buf, sizeof(buf))) > 0) {
    flush(p);
    if (dtls_write(&p->d, buf, n) <= 0)
      break;
    flush(p);
  }
}

static void service_peer(peer_t *p) {
  tls_conn_t *t = &p->d.tls;
  switch (dtls_state(&p->d)) {
  case TLS_STATE_CONNECTED:
    if (!p->announced) {
      p->announced = 1;
      printf("[dtls_echo] DTLS 1.3 established with ");
      print_peer(p);
      printf(" (TLS_AES_128_GCM_SHA256, %s, %s)\n", demo_tls_group_name(t),
             tls_psk_used(t) ? "PSK" : "certificate");
      fflush(stdout);
    }
    echo(p);
    break;
  case TLS_STATE_CLOSED: /* close_notify: answered, and done */
    echo(p);
    if (!p->closing) {
      p->closing = 1;
      (void)dtls_close(&p->d);
      flush(p);
      drop(p, "sent close_notify: connection closed");
    }
    break;
  case TLS_STATE_ERROR: {
    char why[64];
    if (t->alert == DTLS_TIMEOUT)
      snprintf(why, sizeof(why), "stopped answering");
    else
      snprintf(why, sizeof(why), "DTLS alert %u", (unsigned)t->alert);
    flush(p); /* our alert, if it was ours */
    drop(p, why);
    break;
  }
  default:
    break;
  }
}

static void tick(uint32_t elapsed_ms) {
  int i;
  for (i = 0; i < PEERS; i++) {
    if (!peers[i].used)
      continue;
    dtls_tick(&peers[i].d, elapsed_ms);
    flush(&peers[i]);
    if ((peers[i].idle_ms += elapsed_ms) >= IDLE_MS)
      drop(&peers[i], "idle: connection let go");
  }
}

static void service(void) {
  int i;
  for (i = 0; i < PEERS; i++)
    if (peers[i].used)
      service_peer(&peers[i]);
}

int main(int argc, char *argv[]) {
  const demo_hooks_t hooks = {tick, service, NULL};

  if (demo_tls_server(&credentials, &cfg, DTLS_ECHO_DEFAULT_CERT,
                      DTLS_ECHO_DEFAULT_KEY, "dtls_echo") != 0)
    return 1;
  cfg.dtls_no_cookie = (uint8_t)(atoi(demo_env("DTLS_NO_COOKIE", "0")) != 0);
  mtu = (unsigned)atoi(demo_env("DTLS_MTU", "1400"));
  if (mtu < DTLS_MTU_MIN || mtu > MTU_MAX) {
    fprintf(stderr, "[dtls_echo] DTLS_MTU: %u to %u\n", DTLS_MTU_MIN, MTU_MAX);
    return 1;
  }
  if (demo_net_open(&net, &nic, argc > 1 ? argv[1] : NULL, "dtls_echo") != 0)
    return 1;
  udp_set_ports(&net, udp_ports, 1);
#if NET_USE_IPV6
  udp6_set_ports(&net, udp6_ports, 1);
#endif

  printf("[dtls_echo] IP: ");
  demo_print_ip(&net);
  printf(", UDP port %u, MTU %u, %u certificate(s)%s%s%s\n", DTLS_PORT, mtu,
         (unsigned)cfg.cert_count, cfg.psk ? ", PSK " : "",
         cfg.psk ? (const char *)cfg.psk_id : "",
         cfg.dtls_no_cookie ? ", no cookie exchange" : "");
  fflush(stdout);

  demo_run(&net, "dtls_echo", &hooks);

  printf("[dtls_echo] shutting down\n");
  demo_net_close(&nic);
  demo_tls_free(&credentials);
  return 0;
}
