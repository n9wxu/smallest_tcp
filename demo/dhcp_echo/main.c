/**
 * @file demo/dhcp_echo/main.c
 * @brief DHCP client + TCP/UDP echo — SUT for DHCP blackbox tests.
 *
 * Starts a DHCP client on tap0.  Once BOUND, echoes on TCP port 7 and
 * UDP port 7 — same services as tcp_echo_demo but with a
 * dynamically-acquired IP address.
 *
 * Usage (Linux, requires root):
 *   sudo ip tuntap add dev tap0 mode tap user $(whoami)
 *   sudo ip link set tap0 up
 *   sudo ./build/demo/dhcp_echo_demo
 */

#include "dhcpv4_client.h"
#include "eth.h"
#include "net.h"
#include "tcp.h"
#include "tcp_buf.h"
#include "udp.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include "driver/tap.h"
#elif defined(__APPLE__)
#include "driver/bpf.h"
#else
#error "This demo requires Linux (TAP) or macOS (BPF)"
#endif

/* ── Configuration ───────────────────────────────────────────────── */
#define ECHO_PORT 7u
#define TX_BUF_SIZE 1024u
#define RX_BUF_SIZE 1024u
#define NET_BUF_SIZE 1514u

/* ── Global state ────────────────────────────────────────────────── */

static uint8_t net_rx_mem[NET_BUF_SIZE];
static uint8_t net_tx_mem[NET_BUF_SIZE];
static net_t net;

static uint8_t tcp_tx_mem[TX_BUF_SIZE];
static uint8_t tcp_rx_mem[RX_BUF_SIZE];
static tcp_saw_tx_ctx_t tx_ctx;
static tcp_saw_rx_ctx_t rx_ctx;
static tcp_conn_t echo_conn;
static tcp_conn_t *conn_table[1];

static volatile int want_echo = 0;
static volatile int want_close = 0;
static volatile int want_listen = 0;
static volatile int g_bound = 0;
static volatile int running = 1;

static dhcpv4_client_t dhcp;

static void sig_handler(int s) {
  (void)s;
  running = 0;
}

/* ── DHCP event callback ─────────────────────────────────────────── */

static void on_dhcp_event(uint8_t event, void *ctx) {
  (void)ctx;
  switch (event) {
  case DHCPV4_EVT_BOUND:
    g_bound = 1;
    printf("[DHCP] BOUND: %u.%u.%u.%u\n",
           (unsigned)((net.ipv4_addr >> 24) & 0xFF),
           (unsigned)((net.ipv4_addr >> 16) & 0xFF),
           (unsigned)((net.ipv4_addr >> 8) & 0xFF),
           (unsigned)(net.ipv4_addr & 0xFF));
    fflush(stdout);
    break;
  case DHCPV4_EVT_RENEWED:
    printf("[DHCP] RENEWED\n");
    fflush(stdout);
    break;
  case DHCPV4_EVT_EXPIRED:
    g_bound = 0;
    printf("[DHCP] EXPIRED — restarting\n");
    fflush(stdout);
    break;
  case DHCPV4_EVT_NAK:
    printf("[DHCP] NAK — restarting\n");
    fflush(stdout);
    break;
  default:
    break;
  }
}

/* ── DHCP port-68 UDP handler ────────────────────────────────────── */

static void dhcp_udp_handler(net_t *n, uint32_t src_ip, uint16_t src_port,
                             const uint8_t *src_mac, uint16_t payload_offset,
                             uint16_t payload_len) {
  (void)src_port;
  (void)src_mac;
  uint8_t buf[576];
  uint16_t copy = (payload_len < (uint16_t)sizeof(buf)) ? payload_len
                                                        : (uint16_t)sizeof(buf);
  n->mac_driver->peek(n->mac_ctx, payload_offset, buf, copy);
  dhcpv4_client_input(n, &dhcp, src_ip, buf, copy);
}

/* ── UDP echo handler (port 7) ───────────────────────────────────── */

static void udp_echo_handler(net_t *n, uint32_t src_ip, uint16_t src_port,
                             const uint8_t *src_mac, uint16_t payload_offset,
                             uint16_t payload_len) {
  uint8_t buf[512];
  uint16_t copy = (payload_len < (uint16_t)sizeof(buf)) ? payload_len
                                                        : (uint16_t)sizeof(buf);
  n->mac_driver->peek(n->mac_ctx, payload_offset, buf, copy);
  udp_send(n, src_ip, src_mac, ECHO_PORT, src_port, buf, copy);
}

/* ── UDP port table ──────────────────────────────────────────────── */

static const udp_port_entry_t udp_handlers[] = {
    {ECHO_PORT, udp_echo_handler},
    {68, dhcp_udp_handler},
};

/* ── TCP event callback ──────────────────────────────────────────── */

static void on_tcp_event(tcp_conn_t *conn, uint8_t events) {
  (void)conn;
  if (events & TCP_EVT_DATA)
    want_echo = 1;
  if (events & TCP_EVT_CLOSED)
    want_close = 1;
  if (events & TCP_EVT_RESET)
    want_listen = 1;
  if (events & TCP_EVT_ERROR)
    want_listen = 1;
}

/* ── TCP helpers ─────────────────────────────────────────────────── */

static void do_echo(void) {
  uint8_t buf[256];
  uint16_t n;
  while ((n = tcp_recv(&echo_conn, buf, sizeof(buf))) > 0)
    tcp_send(&net, &echo_conn, buf, n);
}

static void do_listen(void) {
  tcp_saw_tx_init(&tx_ctx, tcp_tx_mem, TX_BUF_SIZE);
  tcp_saw_rx_init(&rx_ctx, tcp_rx_mem, RX_BUF_SIZE);
  tcp_conn_init(&echo_conn, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops, &rx_ctx,
                on_tcp_event);
  tcp_listen(&echo_conn, ECHO_PORT);
  want_echo = want_close = want_listen = 0;
  printf("[tcp_echo] listening on port %u\n", ECHO_PORT);
}

/* ── Monotonic ms clock ──────────────────────────────────────────── */

static uint32_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}

/* ── main ────────────────────────────────────────────────────────── */

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
  const char *ifname = (argc > 1) ? argv[1] : "feth1";
  bpf_ctx_init(&mac_ctx, ifname);
#endif

  net_init(&net, net_rx_mem, sizeof(net_rx_mem), net_tx_mem, sizeof(net_tx_mem),
           NULL, drv, &mac_ctx);

  if (drv->init(&mac_ctx) != 0) {
    fprintf(stderr, "[dhcp_echo] Failed to open MAC driver\n");
    return 1;
  }
  printf("[TAP] Opened tap0\n");
  fflush(stdout);

  /* TCP connection table */
  conn_table[0] = &echo_conn;
  tcp_connections.conns = conn_table;
  tcp_connections.count = 1;

  /* UDP port table */
  udp_ports.entries = udp_handlers;
  udp_ports.count = 2;

  /* DHCP client — sends DISCOVER immediately */
  dhcpv4_client_init(&dhcp, on_dhcp_event, NULL, NULL);
  dhcpv4_client_start(&net, &dhcp);
  printf("[DHCP] Discovery started\n");
  fflush(stdout);

  /* TCP listener (will accept once DHCP binds) */
  do_listen();

  uint32_t last_tick = now_ms();

  while (running) {
    if (net_poll(&net) > 0)
      eth_input(&net, net.rx.buf, net.rx.frame_len);

    uint32_t now = now_ms();
    uint32_t delta = now - last_tick;
    if (delta >= 10u) {
      tcp_tick(&net, delta);
      dhcpv4_client_tick(&net, &dhcp, delta);
      last_tick = now;
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
    if (want_listen) {
      usleep(50000);
      do_listen();
    }
  }

  printf("[dhcp_echo] shutting down\n");
  if (echo_conn.state == TCP_ESTABLISHED || echo_conn.state == TCP_CLOSE_WAIT)
    tcp_abort(&net, &echo_conn);

  if (g_bound)
    dhcpv4_client_release(&net, &dhcp);

  drv->close(&mac_ctx);
  return 0;
}
