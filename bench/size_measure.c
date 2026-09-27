/**
 * @file bench/size_measure.c
 * @brief Minimal bare-metal application for ARM code size measurement.
 *
 * This file exercises all implemented stack layers so the linker keeps them.
 * No OS dependencies (no stdio, no malloc, no syscalls).
 *
 * Four configurations are measured:
 *   make arm-size      — UDP echo (ETH + ARP + IPv4 + ICMP + UDP),
 *                        built with -DNET_USE_TCP=0 (lwIP comparison baseline)
 *   make arm-size-tcp  — UDP echo + TCP echo (adds tcp.c + tcp_buf_saw.c)
 *   make arm-size-mdns — UDP echo + mDNS/DNS-SD responder (-DBENCH_MDNS)
 *   make arm-size-http — UDP echo + HTTP server, one slot (-DBENCH_HTTP)
 *   make arm-size-ipv6 — UDP echo over IPv4 and IPv6: + IPv6, ICMPv6, ND,
 *                        DAD, router discovery, SLAAC, MLD (-DBENCH_IPV6)
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

#ifdef BENCH_MDNS
#include "mdns.h"
#endif

#ifdef BENCH_HTTP
#include "http.h"
#endif

#ifdef BENCH_IPV6
#include "ipv6.h"
#endif

/* Application-owned memory (typical small MCU sizes) */
static uint8_t rx_buf[300];
static uint8_t tx_buf[300];
static net_t net;

static void echo_handler(net_t *n, uint32_t src_ip, uint16_t src_port,
                         const uint8_t *src_mac, const uint8_t *payload,
                         uint16_t len) {
  udp_send(n, src_ip, src_mac, 7, src_port, payload, len);
}

#ifdef BENCH_IPV6
static void echo6_handler(net_t *n, const uint8_t *src_ip, uint16_t src_port,
                          const uint8_t *src_mac, const uint8_t *payload,
                          uint16_t len) {
  udp6_send(n, src_ip, src_mac, 7, src_port, payload, len);
}
static const udp6_port_entry_t ports6[] = {{7, echo6_handler}};
#endif

#ifdef BENCH_MDNS
/* mDNS + DNS-SD: host name plus one advertised service */
static const char *const txt[] = {"txtvers=1", NULL};
static const mdns_record_t records[] = {
    {.type = DNS_TYPE_A,
     .ttl = MDNS_TTL_HOST,
     .name = "dev.local",
     .rdata.a = 0},
    {.type = DNS_TYPE_PTR,
     .ttl = MDNS_TTL_OTHER,
     .name = "_x._udp.local",
     .rdata.ptr = "Dev._x._udp.local"},
    {.type = DNS_TYPE_SRV,
     .ttl = MDNS_TTL_HOST,
     .name = "Dev._x._udp.local",
     .rdata.srv = {0, 0, 7, "dev.local"}},
    {.type = DNS_TYPE_TXT,
     .ttl = MDNS_TTL_HOST,
     .name = "Dev._x._udp.local",
     .rdata.txt = txt},
};
static mdns_t mdns;

static void mdns_handler(net_t *n, uint32_t src_ip, uint16_t src_port,
                         const uint8_t *src_mac, const uint8_t *payload,
                         uint16_t len) {
  (void)n;
  mdns_input(&mdns, src_ip, src_mac, src_port, payload, len);
}

static const udp_port_entry_t ports[] = {{7, echo_handler},
                                         {MDNS_PORT, mdns_handler}};
#else
static const udp_port_entry_t ports[] = {{7, echo_handler}};
#endif

#ifdef BENCH_HTTP
/* HTTP server — one slot serving a static page */
static const char page[] = "<h1>ok</h1>";
static int page_root(const http_request_t *rq, http_response_t *rs, void *c) {
  (void)rq;
  (void)c;
  rs->body = (const uint8_t *)page;
  rs->body_len = sizeof(page) - 1;
  return 0;
}
static const http_route_t routes[] = {{"/", HTTP_GET, page_root, (void *)0}};
static uint8_t http_tx[256], http_rx[256];
static char http_req[256];
static http_conn_t http_slot;
static tcp_conn_t *conn_table[1];
static http_server_t http;
#elif NET_USE_TCP
/* TCP echo server — one connection, stop-and-wait buffers */
static uint8_t tcp_tx_mem[128];
static uint8_t tcp_rx_mem[128];
static tcp_saw_tx_ctx_t tcp_tx_ctx;
static tcp_saw_rx_ctx_t tcp_rx_ctx;
static tcp_conn_t echo_conn;
static tcp_conn_t *const conn_table[] = {&echo_conn};
#endif

/* Prevent the compiler from optimizing away the entire program */
volatile int dummy;

void app_main(void) {
  static const uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf), mac,
           &stub_mac_ops, (void *)0);

  udp_set_ports(&net, ports, sizeof(ports) / sizeof(ports[0]));

#ifdef BENCH_IPV6
  udp6_set_ports(&net, ports6, 1);
  ipv6_start(&net); /* link-local address, DAD, then router discovery */
#endif

#ifdef BENCH_MDNS
  mdns_init(&mdns, &net, records, sizeof(records) / sizeof(records[0]),
            (mdns_conflict_fn_t)0, (void *)0);
  mdns_start(&mdns);
#endif

#ifdef BENCH_HTTP
  http_conn_init(&http_slot, http_tx, sizeof(http_tx), http_rx, sizeof(http_rx),
                 http_req, sizeof(http_req));
  conn_table[0] = http_conn_tcp(&http_slot);
  tcp_set_connections(&net, conn_table, 1);
  http_server_init(&http, &net, 80, routes, 1, &http_slot, 1);
#elif NET_USE_TCP
  tcp_saw_tx_init(&tcp_tx_ctx, tcp_tx_mem, sizeof(tcp_tx_mem));
  tcp_saw_rx_init(&tcp_rx_ctx, tcp_rx_mem, sizeof(tcp_rx_mem));
  tcp_conn_init(&echo_conn, &tcp_saw_tx_ops, &tcp_tx_ctx, &tcp_saw_rx_ops,
                &tcp_rx_ctx, (void (*)(tcp_conn_t *, uint8_t))0);
  tcp_set_connections(&net, conn_table, 1);
  tcp_listen(&echo_conn, 7);
#endif

  int n = net_poll(&net); /* receive and process a frame */

  net_tick(&net, 10); /* TCP and IPv6 timers */
#ifdef BENCH_HTTP
  http_server_poll(&http);
  http_server_tick(&http, 10);
#elif NET_USE_TCP
  {
    uint8_t buf[64];
    uint16_t got = tcp_recv(&echo_conn, buf, sizeof(buf));
    if (got > 0) {
      tcp_send(&net, &echo_conn, buf, got);
    }
  }
#endif

  /* Simulate sending a UDP packet */
  static const uint8_t dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  static const uint8_t payload[] = "hello";
  udp_send(&net, 0x0A000001, dst_mac, 7, 1234, payload, 5);

  /* Force ARP request to be linked */
  arp_request(&net, 0x0A000001);

#ifdef BENCH_MDNS
  mdns_tick(&mdns, 10);
  mdns_stop(&mdns);
#endif

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
