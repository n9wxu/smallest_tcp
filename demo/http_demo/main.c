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
 *   GET  /api/status  JSON, generated per request (uptime, request count,
 * query) POST /api/echo    echoes the request body as text/plain GET  /big
 * 8000-byte text body (streams over many segments)
 */

#include "http.h"
#include "mdns.h"
#include "net.h"
#include "udp.h"
#include <stdio.h>
#include <string.h>

#include "demo_loop.h"

#define HTTP_PORT 80u
#define N_SLOTS 2

static net_t net;
static demo_mac_t nic;

static uint8_t tcp_tx[N_SLOTS][1460];
static uint8_t tcp_rx[N_SLOTS][1024];
static char req_buf[N_SLOTS][1024];
static http_conn_t slots[N_SLOTS];
static tcp_conn_t *conn_table[N_SLOTS];
static http_server_t http;

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
                   (unsigned long)(demo_now_ms() - start_ms),
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

static int page_echo(const http_request_t *rq, http_response_t *rs, void *ctx) {
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

/* mDNS: pyro-dead01.local, and "Pyro Unit 1" as an _http._tcp service */

static const char *const txt[] = {"path=/", NULL}; /* DNS-SD _http TXT key */

static const mdns_record_t records[] = {
    {.type = DNS_TYPE_A,
     .ttl = MDNS_TTL_HOST,
     .name = "pyro-dead01.local",
     .rdata.a = 0},
#if NET_USE_IPV6
    {.type = DNS_TYPE_AAAA,
     .ttl = MDNS_TTL_HOST,
     .name = "pyro-dead01.local",
     .rdata.aaaa = NULL}, /* our IPv6 addresses */
#endif
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

static void mdns_udp_input(net_t *n, uint32_t src_ip, uint16_t src_port,
                           const uint8_t *src_mac, const uint8_t *payload,
                           uint16_t len) {
  (void)n;
  mdns_input(&mdns, src_ip, src_mac, src_port, payload, len);
}

static const udp_port_entry_t udp_ports[] = {{MDNS_PORT, mdns_udp_input}};

#if NET_USE_IPV6
static void mdns_udp6_input(net_t *n, const uint8_t *src_ip, uint16_t src_port,
                            const uint8_t *src_mac, const uint8_t *payload,
                            uint16_t len) {
  (void)n;
  mdns_input6(&mdns, src_ip, src_mac, src_port, payload, len);
}

static const udp6_port_entry_t udp6_ports[] = {{MDNS_PORT, mdns_udp6_input}};

/* RFC 6762 §8.4: announce the new address */
static void ipv6_address_ready(void) { mdns_readdress6(&mdns); }
#endif

static void tick(uint32_t elapsed_ms) {
  mdns_tick(&mdns, elapsed_ms);
  http_server_tick(&http, elapsed_ms);
}

static void service(void) { http_server_poll(&http); }

int main(int argc, char *argv[]) {
  demo_hooks_t hooks = {tick, service, NULL};
  int i;

  if (demo_net_open(&net, &nic, argc > 1 ? argv[1] : NULL, "http") != 0)
    return 1;
  for (i = 0; i < (int)sizeof(big_page); i++)
    big_page[i] = (uint8_t)((i % 64 == 63) ? '\n' : 'a' + (i % 64) % 26);

  for (i = 0; i < N_SLOTS; i++) {
    http_conn_init(&slots[i], tcp_tx[i], sizeof(tcp_tx[i]), tcp_rx[i],
                   sizeof(tcp_rx[i]), req_buf[i], sizeof(req_buf[i]));
    conn_table[i] = http_conn_tcp(&slots[i]);
  }
  tcp_set_connections(&net, conn_table, N_SLOTS);
  http_server_init(&http, &net, HTTP_PORT, routes,
                   sizeof(routes) / sizeof(routes[0]), slots, N_SLOTS);

  udp_set_ports(&net, udp_ports, 1);
#if NET_USE_IPV6
  udp6_set_ports(&net, udp6_ports, 1);
  hooks.ipv6_address_ready = ipv6_address_ready;
#endif
  mdns_init(&mdns, &net, records, sizeof(records) / sizeof(records[0]), NULL,
            NULL);
  mdns_start(&mdns);

  start_ms = demo_now_ms();
  printf("[http] listening on http://");
  demo_print_ipv4(net.ipv4_addr);
  printf(":%u/ (pyro-dead01.local), %d slots\n", HTTP_PORT, N_SLOTS);
  fflush(stdout);

  demo_run(&net, "http", &hooks);

  printf("[http] shutting down\n");
  fflush(stdout);
  mdns_stop(&mdns);
  demo_net_close(&nic);
  return 0;
}
