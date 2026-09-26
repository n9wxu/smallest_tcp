/**
 * @file bench/size_measure.c
 * @brief Minimal bare-metal application for ARM code size measurement.
 *
 * This file exercises all implemented stack layers so the linker keeps them.
 * No OS dependencies (no stdio, no malloc, no syscalls).
 *
 * Two configurations are measured:
 *   make arm-size      — UDP echo (ETH + ARP + IPv4 + ICMP + UDP),
 *                        built with -DNET_USE_TCP=0 (lwIP comparison baseline)
 *   make arm-size-tcp  — UDP echo + TCP echo (adds tcp.c + tcp_buf_saw.c)
 */

#include "arp.h"
#include "driver/stub.h"
#include "eth.h"
#include "icmp.h"
#include "ipv4.h"
#include "net.h"
#include "udp.h"

#if NET_USE_TCP
#include "tcp.h"
#include "tcp_buf.h"
#endif

/* Application-owned memory (typical small MCU sizes) */
static uint8_t rx_buf[300];
static uint8_t tx_buf[300];
static net_t net;

/* UDP handler — peeks the payload out of the MAC and echoes it back */
static void echo_handler(net_t *n, uint32_t src_ip, uint16_t src_port,
                         const uint8_t *src_mac, uint16_t payload_offset,
                         uint16_t payload_len) {
  uint8_t buf[64];
  uint16_t len = (payload_len < sizeof(buf)) ? payload_len : sizeof(buf);
  n->mac_driver->peek(n->mac_ctx, payload_offset, buf, len);
  udp_send(n, src_ip, src_mac, 7, src_port, buf, len);
}

static const udp_port_entry_t ports[] = {{7, echo_handler}};

#if NET_USE_TCP
/* TCP echo server — one connection, stop-and-wait buffers */
static uint8_t tcp_tx_mem[128];
static uint8_t tcp_rx_mem[128];
static tcp_saw_tx_ctx_t tcp_tx_ctx;
static tcp_saw_rx_ctx_t tcp_rx_ctx;
static tcp_conn_t echo_conn;
static tcp_conn_t *conn_table[] = {&echo_conn};
#endif

/* Prevent the compiler from optimizing away the entire program */
volatile int dummy;

void app_main(void) {
  static const uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf), mac,
           &stub_mac_ops, (void *)0);

  udp_ports.entries = ports;
  udp_ports.count = 1;

#if NET_USE_TCP
  tcp_saw_tx_init(&tcp_tx_ctx, tcp_tx_mem, sizeof(tcp_tx_mem));
  tcp_saw_rx_init(&tcp_rx_ctx, tcp_rx_mem, sizeof(tcp_rx_mem));
  tcp_conn_init(&echo_conn, &tcp_saw_tx_ops, &tcp_tx_ctx, &tcp_saw_rx_ops,
                &tcp_rx_ctx, (void (*)(tcp_conn_t *, uint8_t))0);
  tcp_connections.conns = conn_table;
  tcp_connections.count = 1;
  tcp_listen(&echo_conn, 7);
#endif

  /* Simulate receiving a frame */
  int n = net_poll(&net);
  if (n > 0) {
    eth_input(&net, net.rx.buf, net.rx.frame_len);
  }

#if NET_USE_TCP
  {
    uint8_t buf[64];
    uint16_t got = tcp_recv(&echo_conn, buf, sizeof(buf));
    if (got > 0) {
      tcp_send(&net, &echo_conn, buf, got);
    }
    tcp_tick(&net, 10);
  }
#endif

  /* Simulate sending a UDP packet */
  static const uint8_t dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  static const uint8_t payload[] = "hello";
  udp_send(&net, 0x0A000001, dst_mac, 7, 1234, payload, 5);

  /* Force ARP request to be linked */
  arp_request(&net, 0x0A000001);

  dummy = n;
}

/* Bare-metal entry point — no libc startup */
void _start(void) {
  app_main();
  while (1) {
  }
}

/* ARM vector table minimum — reset vector only */
__attribute__((section(".vectors"))) void (*const vectors[])(void) = {
    (void (*)(void))0x20001000, /* Initial SP (4KB RAM) */
    _start,                     /* Reset handler */
};
