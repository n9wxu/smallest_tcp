/**
 * @file demo/https_demo/main.c
 * @brief HTTPS: http.c's server over smallest_tcp's TLS 1.3 over its TCP,
 *        with Mbed TLS for the cryptography — https://10.0.0.2/.
 *
 * One connection at a time on port 443; every response ends the
 * connection (close_notify, then FIN).
 *
 *   GET  /            HTML status page
 *   GET  /api/status  JSON: uptime, requests, the connection's TLS
 *                     parameters
 *   GET  /big         20000 bytes (many records, many TCP segments)
 *
 *   sudo ./build/demo/https_demo [tap0 | raw:<ifname> | feth1]
 *   curl --cacert tests/tls/ca.pem https://10.0.0.2/
 *
 * Credentials as demo_tls.h: tests/tls (TEST ONLY) unless TLS_CERT and
 * TLS_KEY name others.  The certificate comes from a file, so the demo
 * does not know its names and sets no http_server_t.https_hosts: a
 * request is answered whatever host it names (no 421 for a host the
 * certificate is not valid for, REQ-HTTP-056).  The SUT of
 * tests/blackbox/test_https_conform.py.
 */

#include "http.h"
#include "http_tls.h"
#include "net.h"
#include "tls.h"
#include <stdio.h>
#include <string.h>

#include "demo_loop.h"
#include "demo_tls.h"

#define HTTPS_PORT 443u
#define TCP_TX_SIZE 1460u
#define TCP_RX_SIZE 4096u
#define REQ_SIZE 2048u

#ifndef HTTPS_DEFAULT_CERT
#define HTTPS_DEFAULT_CERT "tests/tls/server.pem"
#define HTTPS_DEFAULT_KEY "tests/tls/server.key"
#endif

static net_t net;
static demo_mac_t nic;

static uint8_t tcp_tx[TCP_TX_SIZE];
static uint8_t tcp_rx[TCP_RX_SIZE];
static char req_buf[REQ_SIZE];
static http_conn_t slot;
static tcp_conn_t *conn_table[1];
static http_server_t https;

static demo_tls_t credentials;
static tls_config_t cfg;
static uint8_t tls_rx[DEMO_TLS_RX_SIZE];
static uint8_t tls_tx[DEMO_TLS_TX_SIZE];
static tls_conn_t tls;

static uint32_t start_ms, requests;
static uint8_t big[20000];

static const char index_html[] =
    "<!DOCTYPE html>\n"
    "<html><head><title>Pyro Unit 1 (HTTPS)</title></head>\n"
    "<body><h1>Pyro Unit 1</h1>\n"
    "<p>Served over TLS 1.3 by smallest_tcp.</p>\n"
    "<ul><li><a href=\"/api/status\">/api/status</a> (JSON)</li>\n"
    "<li><a href=\"/big\">/big</a> (20000 bytes)</li></ul>\n"
    "</body></html>\n";

static int page_index(const http_request_t *rq, http_response_t *rs,
                      void *ctx) {
  (void)rq;
  (void)ctx;
  requests++;
  rs->body = (const uint8_t *)index_html;
  rs->body_len = sizeof(index_html) - 1;
  return 0;
}

static int page_status(const http_request_t *rq, http_response_t *rs,
                       void *ctx) {
  int n;
  (void)rq;
  (void)ctx;
  requests++;
  n = snprintf((char *)rs->scratch, rs->scratch_size,
               "{\"uptime_ms\":%lu,\"requests\":%lu,"
               "\"tls\":\"TLSv1.3\",\"cipher\":\"TLS_AES_128_GCM_SHA256\","
               "\"group\":\"%s\",\"auth\":\"%s\"}\n",
               (unsigned long)(demo_now_ms() - start_ms),
               (unsigned long)requests,
               tls.group ? demo_tls_group_name(&tls) : "none",
               tls_psk_used(&tls) ? "psk" : "certificate");
  if (n < 0 || n >= (int)rs->scratch_size)
    return -1;
  rs->content_type = "application/json";
  rs->body = rs->scratch;
  rs->body_len = (uint32_t)n;
  return 0;
}

static int page_big(const http_request_t *rq, http_response_t *rs, void *ctx) {
  (void)rq;
  (void)ctx;
  requests++;
  rs->content_type = "text/plain";
  rs->body = big;
  rs->body_len = sizeof(big);
  return 0;
}

static const http_route_t routes[] = {
    {"/", HTTP_GET, page_index, NULL},
    {"/api/status", HTTP_GET, page_status, NULL},
    {"/big", HTTP_GET, page_big, NULL},
};

static void tick(uint32_t elapsed_ms) { http_server_tick(&https, elapsed_ms); }

static void service(void) { http_server_poll(&https); }

int main(int argc, char *argv[]) {
  const demo_hooks_t hooks = {tick, service, NULL};
  size_t i;

  for (i = 0; i < sizeof(big); i++) /* 'a'..'z', a newline every 64th */
    big[i] = (uint8_t)((i & 63u) == 63u ? '\n' : 'a' + (i % 26u));
  if (demo_tls_server(&credentials, &cfg, HTTPS_DEFAULT_CERT, HTTPS_DEFAULT_KEY,
                      "https") != 0)
    return 1;
  if (demo_net_open(&net, &nic, argc > 1 ? argv[1] : NULL, "https") != 0)
    return 1;

  tls_init(&tls, &cfg, tls_rx, sizeof(tls_rx), tls_tx, sizeof(tls_tx));
  http_conn_init(&slot, tcp_tx, sizeof(tcp_tx), tcp_rx, sizeof(tcp_rx), req_buf,
                 sizeof(req_buf));
  http_conn_use_tls(&slot, &tls);
  conn_table[0] = http_conn_tcp(&slot);
  tcp_set_connections(&net, conn_table, 1);
  http_server_init(&https, &net, HTTPS_PORT, routes,
                   sizeof(routes) / sizeof(routes[0]), &slot, 1);

  start_ms = demo_now_ms();
  printf("[https] https://");
  demo_print_ipv4(net.ipv4_addr);
  printf("/ (port %u)\n", HTTPS_PORT);
  fflush(stdout);

  demo_run(&net, "https", &hooks);

  printf("[https] shutting down\n");
  if (slot.tcp.state == TCP_ESTABLISHED || slot.tcp.state == TCP_CLOSE_WAIT)
    tcp_abort(&net, &slot.tcp);
  demo_net_close(&nic);
  demo_tls_free(&credentials);
  return 0;
}
