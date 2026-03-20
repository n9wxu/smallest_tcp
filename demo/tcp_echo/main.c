/**
 * @file demo/tcp_echo/main.c
 * @brief TCP echo server demo (port 7).
 *
 * Listens on TCP port 7. For every incoming connection:
 *   1. Accepts the connection.
 *   2. Echoes every received byte back to the sender.
 *   3. When the peer closes the connection, we close ours.
 *
 * Suitable for testing with: nc <tap_ip> 7
 *
 * Usage (Linux TAP):
 *   sudo ./tcp_echo_demo
 *
 * Usage (macOS BPF):
 *   sudo ./tcp_echo_demo <if_name>
 *
 * The program polls the network driver in a tight loop and calls
 * tcp_tick() every ~10ms for timer management.
 */

#include "arp.h"
#include "eth.h"
#include "ipv4.h"
#include "net.h"
#include "net_endian.h"
#include "tcp.h"
#include "tcp_buf.h"
#include <stdio.h>
#include <string.h>

#if defined(__linux__)
#include "driver/tap.h"
#elif defined(__APPLE__)
#include "driver/bpf.h"
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

  /* ── MAC driver init ────────────────────────────────────────── */
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
#else
  (void)argc;
  (void)argv;
  fprintf(stderr, "Platform not supported\n");
  return 1;
#endif

  /* ── Network context init ───────────────────────────────────── */
  net_init(&net, net_rx_mem, sizeof(net_rx_mem), net_tx_mem, sizeof(net_tx_mem),
           NULL, drv, &mac_ctx);

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
    /* Receive one frame */
    int r = drv->recv(&mac_ctx, net.rx.buf, net.rx.capacity);
    if (r > 0) {
      net.rx.frame_len = (uint16_t)r;
      eth_frame_t eth;
      if (eth_parse(net.rx.buf, net.rx.frame_len, &eth) == NET_OK) {
        switch (eth.ethertype) {
        case NET_ETHERTYPE_ARP:
          arp_input(&net, &eth);
          break;
        case NET_ETHERTYPE_IPV4:
          ipv4_input(&net, &eth);
          break;
        default:
          break;
        }
      }
    }

    /* Timer tick */
    uint32_t now = now_ms();
    uint32_t elapsed = now - last_tick;
    if (elapsed >= 10u) {
      tcp_tick(&net, elapsed);
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
      if (echo_conn.state == TCP_CLOSE_WAIT)
        tcp_close(&net, &echo_conn);
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

  drv->close(&mac_ctx);
  return 0;
}
