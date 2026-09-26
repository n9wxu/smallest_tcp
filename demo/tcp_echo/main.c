/**
 * @file demo/tcp_echo/main.c
 * @brief TCP echo server demo (port 7).
 *
 * Listens on TCP port 7. For every incoming connection:
 *   1. Accepts the connection.
 *   2. Echoes every received byte back to the sender.
 *   3. When the peer closes the connection, we close ours.
 *
 * Suitable for testing with: nc 10.0.0.2 7
 *
 * Usage (Linux TAP):         sudo ./tcp_echo_demo [tap0]
 * Usage (Linux raw socket):  sudo ./tcp_echo_demo raw:<if_name>
 * Usage (macOS BPF):         sudo ./tcp_echo_demo [feth1]
 *
 * The program polls the network driver in a tight loop and calls
 * tcp_tick() every ~10ms for timer management.
 */

#include "eth.h"
#include "net.h"
#include "net_endian.h"
#include "tcp.h"
#include "tcp_buf.h"
#include "udp.h"
#include <stdio.h>
#include <string.h>

#include "demo_ipv6.h"
#include "demo_mac.h"

#if NET_USE_IPV6
#include "dhcpv6_client.h"
#endif

#include <signal.h>
#include <time.h>
#include <unistd.h>

/* ── Network configuration ───────────────────────────────────────── */
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

/* Flags set by event callback, acted on in the main loop */
static volatile int want_echo = 0;   /* Data arrived → echo it back */
static volatile int want_close = 0;  /* Peer closed → we should close */
static volatile int want_listen = 0; /* Connection closed → re-listen */

static volatile int running = 1;
static void sig_handler(int s) {
  (void)s;
  running = 0;
}

/* ── UDP echo handler (port 7) ──────────────────────────────────── */

static void udp_echo_handler(net_t *n, uint32_t src_ip, uint16_t src_port,
                             const uint8_t *src_mac, uint16_t payload_offset,
                             uint16_t payload_len) {
  uint8_t buf[512];
  uint16_t n_read = (payload_len < (uint16_t)sizeof(buf))
                        ? payload_len
                        : (uint16_t)sizeof(buf);
  n->mac_driver->peek(n->mac_ctx, payload_offset, buf, n_read);
  udp_send(n, src_ip, src_mac, ECHO_PORT, src_port, buf, n_read);
}

static const udp_port_entry_t udp_handlers[] = {
    {ECHO_PORT, udp_echo_handler},
};

#if NET_USE_IPV6
static void udp6_echo_handler(net_t *n, const uint8_t *src_ip,
                              uint16_t src_port, const uint8_t *src_mac,
                              uint16_t payload_offset, uint16_t payload_len) {
  uint8_t buf[512];
  uint16_t n_read = (payload_len < (uint16_t)sizeof(buf))
                        ? payload_len
                        : (uint16_t)sizeof(buf);
  n->mac_driver->peek(n->mac_ctx, payload_offset, buf, n_read);
  udp6_send(n, src_ip, src_mac, ECHO_PORT, src_port, buf, n_read);
}

/* ── DHCPv6, started when a Router Advertisement asks for it ───── */

static dhcpv6_client_t dhcp6;
static int dhcp6_started;

static void dhcp6_handler(net_t *n, const uint8_t *src_ip, uint16_t src_port,
                          const uint8_t *src_mac, uint16_t payload_offset,
                          uint16_t payload_len) {
  uint8_t buf[512];
  uint16_t n_read = (payload_len < (uint16_t)sizeof(buf))
                        ? payload_len
                        : (uint16_t)sizeof(buf);
  (void)src_port;
  (void)src_mac;
  n->mac_driver->peek(n->mac_ctx, payload_offset, buf, n_read);
  dhcpv6_client_input(n, &dhcp6, src_ip, buf, n_read);
}

static void on_dns6(uint16_t option, const uint8_t *data, uint16_t len,
                    void *ctx) {
  uint16_t i;
  (void)option;
  (void)ctx;
  for (i = 0; i + 16 <= len; i += 16) {
    printf("[tcp_echo] DHCPv6 DNS server ");
    demo_ipv6_print_addr(data + i);
    printf("\n");
  }
  fflush(stdout);
}

static const dhcpv6_opt_entry_t dhcp6_opt_entries[] = {
    {DHCPV6_OPT_DNS_SERVERS, on_dns6, NULL},
};
static const dhcpv6_opt_table_t dhcp6_opts = {dhcp6_opt_entries, 1};

static void on_dhcp6_event(uint8_t event, void *ctx) {
  static const char *const names[] = {"", "configured", "bound", "renewed",
                                      "expired"};
  (void)ctx;
  printf("[tcp_echo] DHCPv6 %s\n", event <= 4 ? names[event] : "?");
  fflush(stdout);
}

static const udp6_port_entry_t udp6_handlers[] = {
    {ECHO_PORT, udp6_echo_handler},
    {DHCPV6_CLIENT_PORT, dhcp6_handler},
};
#endif

/* ── TCP event callback (called from tcp_input / tcp_tick) ──────── */

static void on_event(tcp_conn_t *conn, uint8_t events) {
  (void)conn;

  if (events & TCP_EVT_CONNECTED) {
    printf("[tcp_echo] connection established\n");
  }

  if (events & TCP_EVT_DATA) {
    want_echo = 1;
  }

  if (events & TCP_EVT_WRITABLE) {
    if (want_echo)
      want_echo = 1; /* re-arm flush */
  }

  if (events & TCP_EVT_CLOSED) {
    printf("[tcp_echo] connection closing\n");
    want_close = 1;
  }

  if (events & TCP_EVT_RESET) {
    printf("[tcp_echo] connection reset\n");
    want_listen = 1;
  }

  if (events & TCP_EVT_ERROR) {
    printf("[tcp_echo] connection error\n");
    want_listen = 1;
  }
}

/* ── Echo: drain RX buffer, feed back to TX ─────────────────────── */

static void do_echo(void) {
  uint8_t buf[256];
  uint16_t n;

  while ((n = tcp_recv(&echo_conn, buf, sizeof(buf))) > 0) {
    int sent = tcp_send(&net, &echo_conn, buf, n);
    if (sent < (int)n) {
      /* TX buffer temporarily full — data lost in this demo (V1 SAW) */
      fprintf(stderr, "[tcp_echo] warn: TX buffer full, %u bytes dropped\n",
              (unsigned)(n - (uint16_t)sent));
    }
  }
}

/* ── Restart listener ────────────────────────────────────────────── */

static void do_listen(void) {
  /* Re-initialise the buffer contexts (clear any leftover state) */
  tcp_saw_tx_init(&tx_ctx, tcp_tx_mem, TX_BUF_SIZE);
  tcp_saw_rx_init(&rx_ctx, tcp_rx_mem, RX_BUF_SIZE);

  tcp_conn_init(&echo_conn, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops, &rx_ctx,
                on_event);

  tcp_listen(&echo_conn, ECHO_PORT);

  want_echo = 0;
  want_close = 0;
  want_listen = 0;

  printf("[tcp_echo] listening on port %u\n", ECHO_PORT);
}

/* ── Monotonic millisecond clock ─────────────────────────────────── */

static uint32_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* ── Platform MAC driver: argv[1] names the interface ───────── */
  demo_mac_t nic;
  if (demo_mac_select(&nic, (argc > 1) ? argv[1] : NULL) != 0) {
    return 1;
  }
  const net_mac_t *drv = nic.ops;

  /* ── Network context init ───────────────────────────────────── */
  net_init(&net, net_rx_mem, sizeof(net_rx_mem), net_tx_mem, sizeof(net_tx_mem),
           NULL, drv, &nic.ctx);

  /* ── Open the MAC driver (TAP / raw socket / BPF) ────────────── */
  if (drv->init(&nic.ctx) != 0) {
    fprintf(stderr, "[tcp_echo] Failed to open MAC driver\n");
    return 1;
  }

#if NET_USE_IPV6
  /* ── IPv6: link-local address + Duplicate Address Detection ─── */
  ipv6_start(&net);
#endif

  /* ── UDP port table ─────────────────────────────────────────── */
  udp_ports.entries = udp_handlers;
  udp_ports.count = 1;
#if NET_USE_IPV6
  udp6_ports.entries = udp6_handlers;
  udp6_ports.count = 2;
  dhcpv6_client_init(&dhcp6, on_dhcp6_event, NULL, &dhcp6_opts);
#endif

  /* ── TCP connection table ───────────────────────────────────── */
  conn_table[0] = &echo_conn;
  tcp_connections.conns = conn_table;
  tcp_connections.count = 1;

  printf("[tcp_echo] IP: %u.%u.%u.%u\n", (net.ipv4_addr >> 24) & 0xFF,
         (net.ipv4_addr >> 16) & 0xFF, (net.ipv4_addr >> 8) & 0xFF,
         net.ipv4_addr & 0xFF);

  do_listen();

  /* ── Main loop ──────────────────────────────────────────────── */
  uint32_t last_tick = now_ms();

  while (running) {
    /* Poll for one frame; net_poll() fills net.rx.buf / net.rx.frame_len.
     * eth_input() dispatches ARP + IPv4 (TCP/UDP/ICMP) and calls
     * mac_driver->discard() on exit, releasing the caching driver's
     * internal buffer so the next poll() reads a fresh frame. */
    if (net_poll(&net) > 0) {
      eth_input(&net, net.rx.buf, net.rx.frame_len);
    }

    /* Timer tick */
    uint32_t now = now_ms();
    uint32_t elapsed = now - last_tick;
    if (elapsed >= 10u) {
      tcp_tick(&net, elapsed);
#if NET_USE_IPV6
      ipv6_tick(&net, elapsed);
      dhcpv6_client_tick(&net, &dhcp6, elapsed);
      demo_ipv6_report(&net, "tcp_echo");
      /* RFC 4861 §4.2: an RA with M asks for DHCPv6 addresses, with O
       * for other configuration (DNS) only */
      if (!dhcp6_started && net.ip6_ra_flags) {
        dhcp6_started = 1;
        dhcpv6_client_start(&net, &dhcp6,
                            (net.ip6_ra_flags & 0x80) ? DHCPV6_MODE_STATEFUL
                                                      : DHCPV6_MODE_STATELESS);
      }
#endif
      last_tick = now;
    }

    /* Act on events set by callback */
    if (want_echo) {
      want_echo = 0;
      do_echo();
    }
    if (want_close) {
      want_close = 0;
      /* Reply to peer's FIN with our own FIN */
      if (echo_conn.state == TCP_CLOSE_WAIT) {
        tcp_close(&net, &echo_conn);
      } else if (echo_conn.state == TCP_CLOSED) {
        /* Close sequence complete — re-arm the listener */
        want_listen = 1;
      }
    }
    if (want_listen) {
      /* Brief delay to allow final ACKs to drain, then re-arm */
      usleep(50000); /* 50ms */
      do_listen();
    }
  }

  printf("[tcp_echo] shutting down\n");
  if (echo_conn.state == TCP_ESTABLISHED || echo_conn.state == TCP_CLOSE_WAIT)
    tcp_abort(&net, &echo_conn);
#if NET_USE_IPV6
  dhcpv6_client_release(&net, &dhcp6);
#endif

  drv->close(&nic.ctx);
  return 0;
}
