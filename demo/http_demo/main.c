/**
 * @file demo/http_demo/main.c
 * @brief HTTP server demo, discoverable as http://pyro-dead01.local/.
 *
 * Serves a status page, a JSON API and a POST echo on port 80 with two
 * connection slots, and advertises itself over mDNS + DNS-SD as the
 * "_http._tcp" service "Pyro Unit 1" (browsers and `dns-sd -B _http._tcp`
 * find it).  SIGINT / SIGTERM sends mDNS goodbyes before exiting.
 *
 * Also the SUT for tests/blackbox/test_http_conform.py.
 *
 * Linux:  sudo ip tuntap add dev tap0 mode tap
 *         sudo ip addr add 10.0.0.100/24 dev tap0 && sudo ip link set tap0 up
 *         sudo ./build/demo/http_demo
 *         curl http://10.0.0.2/   (or http://pyro-dead01.local/ with nss-mdns)
 *         raw socket on an existing interface (NIC or veth end):
 *           sudo ./build/demo/http_demo raw:veth-sut
 * macOS:  (feth pair, see README) ./build/demo/http_demo feth1
 *         curl http://pyro-dead01.local/
 *
 * Routes:
 *   GET  /            HTML status page
 *   GET  /api/status  JSON, generated per request (uptime, request count, query)
 *   POST /api/echo    echoes the request body as text/plain
 *   GET  /big         8000-byte text body (streams over many segments)
 */

#define _POSIX_C_SOURCE 200809L

#include "eth.h"
#include "http.h"
#include "mdns.h"
#include "net.h"
#include "tcp.h"
#include "udp.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "demo_mac.h"

#define HTTP_PORT 80u
#define N_SLOTS 2
#define NET_BUF_SIZE 1514u

/* ── Memory (application-owned) ───────────────────────────────────── */

static uint8_t net_rx_mem[NET_BUF_SIZE];
static uint8_t net_tx_mem[NET_BUF_SIZE];
static net_t net;

static uint8_t tcp_tx[N_SLOTS][1460];
static uint8_t tcp_rx[N_SLOTS][1024];
static char req_buf[N_SLOTS][1024];
static http_conn_t slots[N_SLOTS];
static tcp_conn_t *conn_table[N_SLOTS];
static http_server_t http;

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

/* ── Pages ────────────────────────────────────────────────────────── */

static uint32_t start_ms;
static uint32_t request_count;
static uint8_t big_page[8000];

static const char index_html[] =
    "<!DOCTYPE html>\n"
    "<html><head><title>Pyro Unit 1</title></head>\n"
    "<body><h1>Pyro Unit 1</h1>\n"
    "<p>Served by smallest_tcp from pyro-dead01.local.</p>\n"
    "<ul><li><a href=\"/api/status\">/api/status</a> (JSON)</li>\n"
    "<li><a href=\"/big\">/big</a> (8000 bytes)</li></ul>\n"
    "</body></html>\n";

static int page_index(const http_request_t *rq, http_response_t *rs,
                      void *ctx) {
  (void)rq;
  (void)ctx;
  request_count++;
  rs->body = (const uint8_t *)index_html;
  rs->body_len = sizeof(index_html) - 1;
  return 0;
}

static int page_status(const http_request_t *rq, http_response_t *rs,
                       void *ctx) {
  (void)ctx;
  request_count++;
  int n = snprintf((char *)rs->scratch, rs->scratch_size,
                   "{\"uptime_ms\":%lu,\"requests\":%lu,"
                   "\"ip\":\"%u.%u.%u.%u\",\"query\":\"%s\"}\n",
                   (unsigned long)(now_ms() - start_ms),
                   (unsigned long)request_count,
                   (unsigned)((net.ipv4_addr >> 24) & 0xFF),
                   (unsigned)((net.ipv4_addr >> 16) & 0xFF),
                   (unsigned)((net.ipv4_addr >> 8) & 0xFF),
                   (unsigned)(net.ipv4_addr & 0xFF), rq->query);
  if (n < 0 || n >= (int)rs->scratch_size)
    return -1; /* → 500 */
  rs->content_type = "application/json";
  rs->body = rs->scratch;
  rs->body_len = (uint32_t)n;
  return 0;
}

static int page_echo(const http_request_t *rq, http_response_t *rs,
                     void *ctx) {
  (void)ctx;
  request_count++;
  rs->content_type = "text/plain";
  rs->body = rq->body;
  rs->body_len = rq->body_len;
  return 0;
}

static int page_big(const http_request_t *rq, http_response_t *rs, void *ctx) {
  (void)rq;
  (void)ctx;
  request_count++;
  rs->content_type = "text/plain";
  rs->body = big_page;
  rs->body_len = sizeof(big_page);
  return 0;
}

static const http_route_t routes[] = {
    {"/", HTTP_GET, page_index, NULL},
    {"/api/status", HTTP_GET, page_status, NULL},
    {"/api/echo", HTTP_POST, page_echo, NULL},
    {"/big", HTTP_GET, page_big, NULL},
};

/* ── mDNS: pyro-dead01.local + "Pyro Unit 1" as _http._tcp ────────── */

static const char *const txt[] = {"path=/", NULL}; /* DNS-SD _http TXT key */

static const mdns_record_t records[] = {
    {.type = DNS_TYPE_A,
     .ttl = MDNS_TTL_HOST,
     .name = "pyro-dead01.local",
     .rdata.a = 0},
    {.type = DNS_TYPE_PTR,
     .ttl = MDNS_TTL_OTHER,
     .name = "_http._tcp.local",
     .rdata.ptr = "Pyro Unit 1._http._tcp.local"},
    {.type = DNS_TYPE_SRV,
     .ttl = MDNS_TTL_HOST,
     .name = "Pyro Unit 1._http._tcp.local",
     .rdata.srv = {0, 0, HTTP_PORT, "pyro-dead01.local"}},
    {.type = DNS_TYPE_TXT,
     .ttl = MDNS_TTL_HOST,
     .name = "Pyro Unit 1._http._tcp.local",
     .rdata.txt = txt},
};
static mdns_t mdns;

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

/* ── Main ─────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
  int i;
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* ── Platform MAC driver: argv[1] names the interface ───────── */
  demo_mac_t nic;
  if (demo_mac_select(&nic, (argc > 1) ? argv[1] : NULL) != 0) {
    return 1;
  }
  const net_mac_t *drv = nic.ops;

  net_init(&net, net_rx_mem, sizeof(net_rx_mem), net_tx_mem, sizeof(net_tx_mem),
           NULL, drv, &nic.ctx);
  if (drv->init(&nic.ctx) != 0) {
    fprintf(stderr, "[http] failed to open MAC driver\n");
    return 1;
  }

  for (i = 0; i < (int)sizeof(big_page); i++)
    big_page[i] = (uint8_t)((i % 64 == 63) ? '\n' : 'a' + (i % 64) % 26);

  for (i = 0; i < N_SLOTS; i++) {
    http_conn_init(&slots[i], tcp_tx[i], sizeof(tcp_tx[i]), tcp_rx[i],
                   sizeof(tcp_rx[i]), req_buf[i], sizeof(req_buf[i]));
    conn_table[i] = http_conn_tcp(&slots[i]);
  }
  tcp_connections.conns = conn_table;
  tcp_connections.count = N_SLOTS;
  http_server_init(&http, &net, HTTP_PORT, routes,
                   sizeof(routes) / sizeof(routes[0]), slots, N_SLOTS);

  udp_ports.entries = udp_handlers;
  udp_ports.count = 1;
  mdns_init(&mdns, &net, records, sizeof(records) / sizeof(records[0]), NULL,
            NULL);
  mdns_start(&mdns);

  start_ms = now_ms();
  printf("[http] listening on http://%u.%u.%u.%u:%u/ (pyro-dead01.local), "
         "%d slots\n",
         (unsigned)((net.ipv4_addr >> 24) & 0xFF),
         (unsigned)((net.ipv4_addr >> 16) & 0xFF),
         (unsigned)((net.ipv4_addr >> 8) & 0xFF),
         (unsigned)(net.ipv4_addr & 0xFF), HTTP_PORT, N_SLOTS);
  fflush(stdout);

  uint32_t last_tick = now_ms();
  while (running) {
    int got = net_poll(&net);
    if (got > 0)
      eth_input(&net, net.rx.buf, net.rx.frame_len);
    http_server_poll(&http);

    uint32_t now = now_ms();
    uint32_t elapsed = now - last_tick;
    if (elapsed >= 5u) {
      tcp_tick(&net, elapsed);
      mdns_tick(&mdns, elapsed);
      http_server_tick(&http, elapsed);
      last_tick = now;
    }
    if (got <= 0) {
      struct timespec idle = {0, 500000}; /* 0.5 ms */
      nanosleep(&idle, NULL);
    }
  }

  printf("[http] shutting down\n");
  fflush(stdout);
  mdns_stop(&mdns);
  drv->close(&nic.ctx);
  return 0;
}
