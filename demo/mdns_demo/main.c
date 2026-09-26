/**
 * @file demo/mdns_demo/main.c
 * @brief mDNS + DNS-SD demo — advertises a host name and a service.
 *
 * Announces "pyro-dead01.local" (A record for the stack's IP) and the DNS-SD
 * service "Pyro Unit 1._pyro._tcp.local" on port 80, where it runs a TCP
 * echo server so the advertised service is real.  On a name conflict the
 * demo renames itself ("pyro-dead01-2.local", "Pyro Unit 1 (2)") and probes
 * again.  SIGINT / SIGTERM sends goodbye packets before exiting.
 *
 * Also the SUT for tests/blackbox/test_mdns_conform.py.
 *
 * Linux:  sudo ip tuntap add dev tap0 mode tap
 *         sudo ip addr add 10.0.0.100/24 dev tap0 && sudo ip link set tap0 up
 *         sudo ./build/demo/mdns_demo
 *         avahi-resolve -n pyro-dead01.local ; avahi-browse -rt _pyro._tcp
 * macOS:  (feth pair as in demo/echo_server) sudo ./build/demo/mdns_demo feth1
 *         dns-sd -B _pyro._tcp local
 */

#define _POSIX_C_SOURCE 200809L

#include "eth.h"
#include "mdns.h"
#include "net.h"
#include "tcp.h"
#include "tcp_buf.h"
#include "udp.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(__linux__)
#include "driver/tap.h"
#elif defined(__APPLE__)
#include "driver/bpf.h"
#endif

#define SERVICE_PORT 80u
#define TCP_BUF_SIZE 512u
#define NET_BUF_SIZE 1514u

/* ── Network + TCP echo state ────────────────────────────────────── */

static uint8_t net_rx_mem[NET_BUF_SIZE];
static uint8_t net_tx_mem[NET_BUF_SIZE];
static net_t net;

static uint8_t tcp_tx_mem[TCP_BUF_SIZE];
static uint8_t tcp_rx_mem[TCP_BUF_SIZE];
static tcp_saw_tx_ctx_t tx_ctx;
static tcp_saw_rx_ctx_t rx_ctx;
static tcp_conn_t echo_conn;
static tcp_conn_t *conn_table[1];

static volatile int running = 1;
static volatile int want_echo, want_close, want_listen;

static void sig_handler(int s) {
  (void)s;
  running = 0;
}

/* ── mDNS records (names are buffers so a conflict can rename them) ─ */

static char host[64] = "pyro-dead01.local";
static char inst[96] = "Pyro Unit 1._pyro._tcp.local";
static int host_n = 1, inst_n = 1;

static const char *const txt[] = {"txtvers=1", "fw=1.2.3", "serial=DEAD01",
                                  NULL};

static const mdns_record_t records[] = {
    {.type = DNS_TYPE_A, .ttl = MDNS_TTL_HOST, .name = host, .rdata.a = 0},
    {.type = DNS_TYPE_PTR,
     .ttl = MDNS_TTL_OTHER,
     .name = "_pyro._tcp.local",
     .rdata.ptr = inst},
    {.type = DNS_TYPE_SRV,
     .ttl = MDNS_TTL_HOST,
     .name = inst,
     .rdata.srv = {0, 0, SERVICE_PORT, host}},
    {.type = DNS_TYPE_TXT, .ttl = MDNS_TTL_HOST, .name = inst, .rdata.txt = txt},
};

static mdns_t mdns;
static volatile int want_restart;

/* RFC 6762 §9 / RFC 6763 §8: pick a new name and probe again */
static void on_conflict(mdns_t *m, uint8_t index, void *ctx) {
  (void)m;
  (void)ctx;
  if (records[index].name == host) {
    snprintf(host, sizeof(host), "pyro-dead01-%d.local", ++host_n);
    printf("[mdns] conflict on host name, renamed to %s\n", host);
  } else {
    snprintf(inst, sizeof(inst), "Pyro Unit 1 (%d)._pyro._tcp.local",
             ++inst_n);
    printf("[mdns] conflict on service name, renamed to %s\n", inst);
  }
  fflush(stdout);
  want_restart = 1;
}

/* UDP 5353: copy the message out of the MAC and hand it to the responder */
static void mdns_udp_handler(net_t *n, uint32_t src_ip, uint16_t src_port,
                             const uint8_t *src_mac, uint16_t payload_offset,
                             uint16_t payload_len) {
  static uint8_t buf[NET_BUF_SIZE];
  uint16_t copy = (payload_len < sizeof(buf)) ? payload_len
                                              : (uint16_t)sizeof(buf);
  int got = n->mac_driver->peek(n->mac_ctx, payload_offset, buf, copy);
  if (got > 0)
    mdns_input(&mdns, src_ip, src_mac, src_port, buf, (uint16_t)got);
}

static const udp_port_entry_t udp_handlers[] = {
    {MDNS_PORT, mdns_udp_handler},
};

/* ── TCP echo on the advertised port ─────────────────────────────── */

static void on_tcp_event(tcp_conn_t *conn, uint8_t events) {
  (void)conn;
  if (events & TCP_EVT_DATA)
    want_echo = 1;
  if (events & TCP_EVT_CLOSED)
    want_close = 1;
  if (events & (TCP_EVT_RESET | TCP_EVT_ERROR))
    want_listen = 1;
}

static void do_listen(void) {
  tcp_saw_tx_init(&tx_ctx, tcp_tx_mem, TCP_BUF_SIZE);
  tcp_saw_rx_init(&rx_ctx, tcp_rx_mem, TCP_BUF_SIZE);
  tcp_conn_init(&echo_conn, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops, &rx_ctx,
                on_tcp_event);
  tcp_listen(&echo_conn, SERVICE_PORT);
  want_echo = want_close = want_listen = 0;
}

static void do_echo(void) {
  uint8_t buf[256];
  uint16_t n;
  while ((n = tcp_recv(&echo_conn, buf, sizeof(buf))) > 0)
    tcp_send(&net, &echo_conn, buf, n);
}

/* ── Main ─────────────────────────────────────────────────────────── */

static uint32_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}

static const char *state_name(uint8_t s) {
  switch (s) {
  case MDNS_STATE_PROBING:
    return "probing";
  case MDNS_STATE_ANNOUNCING:
    return "announcing";
  case MDNS_STATE_RUNNING:
    return "running";
  case MDNS_STATE_CONFLICT:
    return "conflict";
  default:
    return "stopped";
  }
}

int main(int argc, char *argv[]) {
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

#if defined(__linux__)
  tap_ctx_t mac_ctx;
  const net_mac_t *drv = &tap_mac_ops;
  (void)argc;
  (void)argv;
  tap_ctx_init(&mac_ctx, "tap0");
#elif defined(__APPLE__)
  bpf_ctx_t mac_ctx;
  const net_mac_t *drv = &bpf_mac_ops;
  bpf_ctx_init(&mac_ctx, (argc > 1) ? argv[1] : "feth1");
#else
#error "Unsupported platform"
#endif

  net_init(&net, net_rx_mem, sizeof(net_rx_mem), net_tx_mem, sizeof(net_tx_mem),
           NULL, drv, &mac_ctx);
  if (drv->init(&mac_ctx) != 0) {
    fprintf(stderr, "[mdns] failed to open MAC driver\n");
    return 1;
  }

  udp_ports.entries = udp_handlers;
  udp_ports.count = 1;
  conn_table[0] = &echo_conn;
  tcp_connections.conns = conn_table;
  tcp_connections.count = 1;
  do_listen();

  if (mdns_init(&mdns, &net, records, sizeof(records) / sizeof(records[0]),
                on_conflict, NULL) != NET_OK) {
    fprintf(stderr, "[mdns] invalid record table\n");
    return 1;
  }
  printf("[mdns] %s -> %u.%u.%u.%u, service \"%s\" port %u\n", host,
         (unsigned)((net.ipv4_addr >> 24) & 0xFF),
         (unsigned)((net.ipv4_addr >> 16) & 0xFF),
         (unsigned)((net.ipv4_addr >> 8) & 0xFF),
         (unsigned)(net.ipv4_addr & 0xFF), inst, SERVICE_PORT);
  fflush(stdout);
  mdns_start(&mdns);

  uint32_t last_tick = now_ms();
  uint8_t last_state = MDNS_STATE_STOPPED;

  while (running) {
    int got = net_poll(&net);
    if (got > 0)
      eth_input(&net, net.rx.buf, net.rx.frame_len);

    uint32_t now = now_ms();
    uint32_t elapsed = now - last_tick;
    if (elapsed >= 5u) {
      tcp_tick(&net, elapsed);
      mdns_tick(&mdns, elapsed);
      last_tick = now;
    }

    if (want_restart) {
      want_restart = 0;
      mdns_start(&mdns);
    }
    if (mdns_state(&mdns) != last_state) {
      last_state = mdns_state(&mdns);
      printf("[mdns] %s (%s)\n", state_name(last_state), host);
      fflush(stdout);
    }

    if (want_echo) {
      want_echo = 0;
      do_echo();
    }
    if (want_close) {
      want_close = 0;
      if (echo_conn.state == TCP_CLOSE_WAIT)
        tcp_close(&net, &echo_conn);
      else if (echo_conn.state == TCP_CLOSED)
        want_listen = 1;
    }
    if (want_listen)
      do_listen();

    if (got <= 0) {
      struct timespec idle = {0, 1000000}; /* 1 ms */
      nanosleep(&idle, NULL);
    }
  }

  printf("[mdns] shutting down: sending goodbye\n");
  fflush(stdout);
  mdns_stop(&mdns);
  if (echo_conn.state == TCP_ESTABLISHED || echo_conn.state == TCP_CLOSE_WAIT)
    tcp_abort(&net, &echo_conn);
  drv->close(&mac_ctx);
  return 0;
}
