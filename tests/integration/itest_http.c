/**
 * @file itest_http.c
 * @brief The HTTP server, black box: a client on the wire talks to
 *        http_server_t over the stack's TCP.
 */

#include "http.h"
#include "itest.h"
#include "tcp.h"
#include <string.h>

#define PORT 80
#define REQ_SIZE 512

static itest_t t;
static http_server_t srv;
static http_conn_t slot;
static tcp_conn_t *table[1];
static uint8_t tx_mem[1024], rx_mem[1024];
static char req_mem[REQ_SIZE];
static peer_client_t cl;
static uint16_t next_port = 41000;

static const char page[] = "<h1>hi</h1>";

static int page_root(const http_request_t *rq, http_response_t *rs, void *c) {
  (void)rq;
  (void)c;
  rs->body = (const uint8_t *)page;
  rs->body_len = sizeof(page) - 1;
  return 0;
}

static int page_none(const http_request_t *rq, http_response_t *rs, void *c) {
  (void)rq;
  (void)c;
  rs->status = 204;
  rs->body = (const uint8_t *)"not sent";
  rs->body_len = 8;
  return 0;
}

static const http_route_t routes[] = {
    {"/", HTTP_GET, page_root, NULL},
    {"/none", HTTP_GET, page_none, NULL},
    {"/off", 0, page_root, NULL},
};

static void serve(itest_t *it) {
  (void)it;
  http_server_poll(&srv);
}

static void up(void) {
  itest_up(&t, 1514, 1514);
  t.service = serve;
  http_conn_init(&slot, tx_mem, sizeof(tx_mem), rx_mem, sizeof(rx_mem), req_mem,
                 sizeof(req_mem));
  table[0] = http_conn_tcp(&slot);
  tcp_set_connections(&t.net, table, 1);
  http_server_init(&srv, &t.net, PORT, routes,
                   sizeof(routes) / sizeof(routes[0]), &slot, 1);
}

/* One request on a new connection; the response, NUL-terminated, in
 * cl.data.  @return 1 if the server answered and closed. */
static int exchange(const char *request) {
  up();
  if (!peer_connect(&t, &cl, next_port++, PORT))
    return 0;
  peer_send(&t, &cl, request, (uint16_t)strlen(request));
  if (!cl.fin)
    peer_close(&t, &cl);
  cl.data[cl.len < sizeof(cl.data) ? cl.len : sizeof(cl.data) - 1] = 0;
  return cl.len > 0 && cl.fin;
}

static const char *body(void) {
  const char *e = strstr((const char *)cl.data, "\r\n\r\n");
  return e ? e + 4 : "";
}

static int status_is(int status) {
  char want[16];
  snprintf(want, sizeof(want), "HTTP/1.0 %d ", status);
  return strncmp((const char *)cl.data, want, strlen(want)) == 0;
}

/* REQ-HTTP-002, 013, 020, 029: GET answered with the page, closed */
TEST(itest_http_002_get) {
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(strstr((char *)cl.data, "Content-Length: 11\r\n") != NULL);
  ASSERT_TRUE(strcmp(body(), page) == 0);
}

/* REQ-HTTP-004, 023: HEAD gets the headers only — an error response too,
 * even about a request that could not be parsed (RFC 9110 §9.3.2) */
TEST(itest_http_023_head_never_has_a_body) {
  static const char *const requests[] = {
      "HEAD / HTTP/1.0\r\n\r\n",     /* 200 */
      "HEAD /nope HTTP/1.0\r\n\r\n", /* 404 */
      "HEAD / HTTP/2.0\r\n\r\n",     /* 505 */
      "HEAD / HTTP/1.1\r\n\r\n",     /* 400: no Host */
      "HEAD /x y HTTP/1.0\r\n\r\n",  /* 400 */
      "\r\nHEAD / HTTP/1.0\r\n\r\n", /* empty line first */
  };
  unsigned i;
  for (i = 0; i < sizeof(requests) / sizeof(requests[0]); i++) {
    ASSERT_TRUE(exchange(requests[i]));
    ASSERT_TRUE(strstr((char *)cl.data, "Content-Length: ") != NULL);
    ASSERT_EQ(strlen(body()), 0u);
  }
}

/* REQ-HTTP-039 (414) and REQ-HTTP-023: a request line too long for the
 * buffer, from a HEAD, is answered without a body */
TEST(itest_http_023_head_414_without_a_body) {
  static char line[REQ_SIZE + 64];
  memset(line, 'a', sizeof(line) - 1);
  memcpy(line, "HEAD /", 6);
  line[sizeof(line) - 1] = 0;
  ASSERT_TRUE(exchange(line));
  ASSERT_TRUE(status_is(414));
  ASSERT_EQ(strlen(body()), 0u);
}

/* REQ-HTTP-018, 020: a 204 has no content, whatever the handler gave */
TEST(itest_http_020_204_without_content) {
  ASSERT_TRUE(exchange("GET /none HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(204));
  ASSERT_EQ(strlen(body()), 0u);
  ASSERT_TRUE(strstr((char *)cl.data, "Content-Length") == NULL);
}

/* REQ-HTTP-024: a 405 names what is allowed — nothing, for a route that
 * allows nothing (RFC 9110 §15.5.6) */
TEST(itest_http_024_405_always_has_allow) {
  ASSERT_TRUE(exchange("POST / HTTP/1.0\r\nContent-Length: 0\r\n\r\n"));
  ASSERT_TRUE(status_is(405));
  ASSERT_TRUE(strstr((char *)cl.data, "\r\nAllow: GET, HEAD\r\n") != NULL);
  ASSERT_TRUE(exchange("GET /off HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(405));
  ASSERT_TRUE(strstr((char *)cl.data, "\r\nAllow: \r\n") != NULL);
}

/* REQ-HTTP-010: an HTTP/1.1 request needs one Host line, no more */
TEST(itest_http_010_one_host_line) {
  ASSERT_TRUE(exchange("GET / HTTP/1.1\r\nHost: a\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(exchange("GET / HTTP/1.1\r\n\r\n"));
  ASSERT_TRUE(status_is(400));
  ASSERT_TRUE(exchange("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"));
  ASSERT_TRUE(status_is(400));
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\nHost: a\r\nhost: a\r\n\r\n"));
  ASSERT_TRUE(status_is(400));
}

int main(void) {
  fprintf(stderr, "=== itest_http ===\n");
  RUN_TEST(itest_http_002_get);
  RUN_TEST(itest_http_023_head_never_has_a_body);
  RUN_TEST(itest_http_023_head_414_without_a_body);
  RUN_TEST(itest_http_020_204_without_content);
  RUN_TEST(itest_http_024_405_always_has_allow);
  RUN_TEST(itest_http_010_one_host_line);
  ITEST_REPORT();
  return test_failures;
}
