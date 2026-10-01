/**
 * @file itest_http.c
 * @brief The HTTP server, black box: a client on the wire talks to
 *        http_server_t over the stack's TCP — and, with ITEST_HTTPS, over
 *        TLS 1.3 (the client's TLS is the stack's own TLS client, used
 *        here only as the transport for the HTTP under test).
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

/* The response under examination, NUL-terminated */
static const char *resp = "";

/* The clock the server is given after http_server_init() */
static uint32_t (*use_clock)(void);

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

/* The request's content, back */
static int echo_calls;
static int page_echo(const http_request_t *rq, http_response_t *rs, void *c) {
  (void)c;
  echo_calls++;
  rs->content_type = "application/octet-stream";
  rs->body = rq->body;
  rs->body_len = rq->body_len;
  return 0;
}

/* The query string, back */
static int page_query(const http_request_t *rq, http_response_t *rs, void *c) {
  (void)c;
  rs->content_type = "text/plain";
  rs->body = (const uint8_t *)rq->query;
  rs->body_len = (uint32_t)strlen(rq->query);
  return 0;
}

/* Whatever status and content type the test sets */
static uint16_t h_status;
static const char *h_type;
static int page_custom(const http_request_t *rq, http_response_t *rs, void *c) {
  (void)rq;
  (void)c;
  rs->status = h_status;
  rs->content_type = h_type;
  rs->body = (const uint8_t *)"x";
  rs->body_len = 1;
  return 0;
}

static const http_route_t routes[] = {
    {"/", HTTP_GET, page_root, NULL},
    {"/none", HTTP_GET, page_none, NULL},
    {"/off", 0, page_root, NULL},
    {"/echo", HTTP_POST, page_echo, NULL},
    {"/q", HTTP_GET, page_query, NULL},
    {"/h", HTTP_GET | HTTP_POST, page_custom, NULL},
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
  srv.clock = use_clock;
}

static void got(void) {
  cl.data[cl.len < sizeof(cl.data) ? cl.len : sizeof(cl.data) - 1] = 0;
  resp = (const char *)cl.data;
}

/* A new connection, @p len bytes of request on it, and what came back
 * (in resp) — the client has not closed. */
static int send_only(const char *request, uint16_t len) {
  up();
  if (!peer_connect(&t, &cl, next_port++, PORT))
    return 0;
  peer_send(&t, &cl, request, len);
  got();
  return 1;
}

/* One request on a new connection; the response in resp.  @return 1 if
 * the server answered and closed. */
static int exchange_n(const char *request, uint16_t len) {
  if (!send_only(request, len))
    return 0;
  if (!cl.fin)
    peer_close(&t, &cl);
  got();
  return cl.len > 0 && cl.fin;
}

static int exchange(const char *request) {
  return exchange_n(request, (uint16_t)strlen(request));
}

static const char *body(void) {
  const char *e = strstr(resp, "\r\n\r\n");
  return e ? e + 4 : "";
}

static int status_is(int status) {
  char want[16];
  snprintf(want, sizeof(want), "HTTP/1.0 %d ", status);
  return strncmp(resp, want, strlen(want)) == 0;
}

static int has(const char *text) { return strstr(resp, text) != NULL; }

/* REQ-HTTP-002, 013, 020, 029: GET answered with the page, closed */
TEST(itest_http_002_get) {
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(has("Content-Length: 11\r\n"));
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
    ASSERT_TRUE(has("Content-Length: "));
    ASSERT_EQ(strlen(body()), 0u);
  }
}

/* REQ-HTTP-039, 041 (414) and REQ-HTTP-023: a request line too long for
 * the buffer, from a HEAD, is answered without a body */
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
  ASSERT_TRUE(!has("Content-Length"));
}

/* REQ-HTTP-020: a response to HEAD carries the Content-Length a GET of
 * the same request gets (RFC 9110 §8.6) */
TEST(itest_http_020_head_length_is_gets) {
  static const char *const targets[] = {"/", "/nope"};
  unsigned i;
  for (i = 0; i < 2; i++) {
    char req[64], get_len[32];
    const char *l;
    snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\n\r\n", targets[i]);
    ASSERT_TRUE(exchange(req));
    l = strstr(resp, "Content-Length: ");
    ASSERT_TRUE(l != NULL);
    memcpy(get_len, l, sizeof(get_len) - 1);
    get_len[strcspn(get_len, "\r")] = 0;
    snprintf(req, sizeof(req), "HEAD %s HTTP/1.0\r\n\r\n", targets[i]);
    ASSERT_TRUE(exchange(req));
    ASSERT_TRUE(has(get_len));
  }
}

/* REQ-HTTP-024: a 405 names what is allowed — nothing, for a route that
 * allows nothing (RFC 9110 §15.5.6) */
TEST(itest_http_024_405_always_has_allow) {
  ASSERT_TRUE(exchange("POST / HTTP/1.0\r\nContent-Length: 0\r\n\r\n"));
  ASSERT_TRUE(status_is(405));
  ASSERT_TRUE(has("\r\nAllow: GET, HEAD\r\n"));
  ASSERT_TRUE(exchange("GET /off HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(405));
  ASSERT_TRUE(has("\r\nAllow: \r\n"));
}

/* REQ-HTTP-024: a 405 the handler answers lists what its route allows
 * (RFC 9110 §15.5.6: "MUST generate an Allow header field in a 405
 * response containing a list of the target resource's currently
 * supported methods") */
TEST(itest_http_024_handler_405_lists_the_routes_methods) {
  h_status = 405;
  h_type = "text/plain";
  ASSERT_TRUE(exchange("GET /h HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(405));
  ASSERT_TRUE(has("\r\nAllow: GET, HEAD, POST\r\n"));
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

/* REQ-HTTP-044: a bare CR or a NUL in the request line or a field value
 * is rejected, never handed to the application (RFC 9112 §2.2, RFC 9110
 * §5.5) */
TEST(itest_http_044_bare_cr_and_nul_rejected) {
  static const char cr_query[] = "GET /q?a\rb HTTP/1.0\r\n\r\n";
  static const char nul_target[] = "GET /\0x HTTP/1.0\r\n\r\n";
  static const char cr_value[] = "GET / HTTP/1.0\r\nX-A: a\rb\r\n\r\n";
  static const char cr_end[] = "GET / HTTP/1.0\r\nX-A: a\r\r\n\r\n";
  static const char nul_value[] = "GET / HTTP/1.0\r\nX-A: a\0b\r\n\r\n";
  ASSERT_TRUE(exchange_n(cr_query, sizeof(cr_query) - 1));
  ASSERT_TRUE(status_is(400));
  ASSERT_TRUE(exchange_n(nul_target, sizeof(nul_target) - 1));
  ASSERT_TRUE(status_is(400));
  ASSERT_TRUE(exchange_n(cr_value, sizeof(cr_value) - 1));
  ASSERT_TRUE(status_is(400));
  ASSERT_TRUE(exchange_n(cr_end, sizeof(cr_end) - 1));
  ASSERT_TRUE(status_is(400));
  ASSERT_TRUE(exchange_n(nul_value, sizeof(nul_value) - 1));
  ASSERT_TRUE(status_is(400));
}

/* REQ-HTTP-045: a Host field whose value is not uri-host [":" port] is a
 * 400, in any request; an empty one is valid (RFC 9112 §3.2) */
TEST(itest_http_045_invalid_host_value) {
  static const char *const good[] = {
      "a.example", "a.example:8080", "10.0.0.2", "[fe80::1]:80", "a%41b", "",
  };
  static const char *const bad[] = {
      "a b", "a/b", "a@b", "a:8x", "[fe80::1", "a%4", "a?b", "a,b c",
  };
  char req[96];
  unsigned i;
  for (i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
    snprintf(req, sizeof(req), "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", good[i]);
    ASSERT_TRUE(exchange(req));
    ASSERT_TRUE(status_is(200));
  }
  for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    snprintf(req, sizeof(req), "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", bad[i]);
    ASSERT_TRUE(exchange(req));
    ASSERT_TRUE(status_is(400));
  }
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\nHost: a b\r\n\r\n"));
  ASSERT_TRUE(status_is(400));
}

/* REQ-HTTP-046, 043: a Transfer-Encoding not ending in chunked is a 400,
 * and so is any in an HTTP/1.0 request (faulty framing); chunked last is
 * a 501 — no chunked request bodies.  The connection closes after each
 * (RFC 9112 §6.1, §6.3) */
TEST(itest_http_046_transfer_encoding) {
  static const char *const not_chunked[] = {"gzip", "chunked, gzip",
                                            "chunked;x=1, identity"};
  static const char *const chunked[] = {"chunked", "gzip, chunked", "CHUNKED"};
  char req[128];
  unsigned i;
  echo_calls = 0;
  for (i = 0; i < 3; i++) {
    snprintf(req, sizeof(req),
             "POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: %s\r\n\r\n",
             chunked[i]);
    ASSERT_TRUE(exchange(req));
    ASSERT_TRUE(status_is(501));
  }
  for (i = 0; i < 3; i++) {
    snprintf(req, sizeof(req),
             "POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: %s\r\n\r\n",
             not_chunked[i]);
    ASSERT_TRUE(exchange(req));
    ASSERT_TRUE(status_is(400));
  }
  ASSERT_TRUE(exchange("POST /echo HTTP/1.0\r\nTransfer-Encoding: chunked\r\n"
                       "Content-Length: 5\r\n\r\nhello"));
  ASSERT_TRUE(status_is(400));
  ASSERT_EQ(echo_calls, 0);
}

/* REQ-HTTP-047: absolute-form targets are accepted — reduced to the path
 * and query after the authority — but an http URI with an empty host is
 * invalid, and a scheme the server does not serve is misdirected (RFC
 * 9112 §3.2.2, RFC 9110 §4.2.1, §15.5.20) */
TEST(itest_http_047_absolute_form) {
  ASSERT_TRUE(exchange("GET http://a.example/q?x=1 HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(strcmp(body(), "x=1") == 0);
  ASSERT_TRUE(exchange("GET HTTP://a.example HTTP/1.1\r\nHost: b\r\n\r\n"));
  ASSERT_TRUE(strcmp(body(), page) == 0);
  ASSERT_TRUE(exchange("GET http://a.example?x=/q HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(strcmp(body(), page) == 0);
  ASSERT_TRUE(exchange("GET http:///q HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(400));
  ASSERT_TRUE(exchange("GET http:// HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(400));
  ASSERT_TRUE(exchange("GET http://:80/ HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(400));
  ASSERT_TRUE(exchange("GET ftp://a.example/ HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(421));
}

/* A clock for the server: whatever the test sets */
static uint32_t now;
static uint32_t clock_now(void) { return now; }

/* exchange() with the server's clock at @p when (0: time unknown) */
static int exchange_at(uint32_t when, const char *request) {
  int ok;
  use_clock = clock_now;
  now = when;
  ok = exchange(request);
  use_clock = NULL;
  return ok;
}

static int date_is(const char *imf) {
  char want[48];
  snprintf(want, sizeof(want), "\r\nDate: %s\r\n", imf);
  return has(want);
}

/* REQ-HTTP-048: with a clock, responses carry Date as an IMF-fixdate;
 * without one — or before it knows the time — none (RFC 9110 §6.6.1,
 * §5.6.7) */
TEST(itest_http_048_date_from_the_clock) {
  static const struct {
    uint32_t t;
    const char *imf;
  } dates[] = {
      {784111777u, "Sun, 06 Nov 1994 08:49:37 GMT"},
      {1u, "Thu, 01 Jan 1970 00:00:01 GMT"},
      {951782400u, "Tue, 29 Feb 2000 00:00:00 GMT"},
      {1790858096u, "Thu, 01 Oct 2026 12:34:56 GMT"},
      {4102444799u, "Thu, 31 Dec 2099 23:59:59 GMT"},
      {4107542400u, "Mon, 01 Mar 2100 00:00:00 GMT"}, /* 2100: no Feb 29 */
      {4294967295u, "Sun, 07 Feb 2106 06:28:15 GMT"},
  };
  unsigned i;
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(!has("Date:"));
  ASSERT_TRUE(exchange_at(0, "GET / HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(!has("Date:"));
  for (i = 0; i < sizeof(dates) / sizeof(dates[0]); i++) {
    ASSERT_TRUE(exchange_at(dates[i].t, "GET / HTTP/1.0\r\n\r\n"));
    ASSERT_TRUE(status_is(200));
    ASSERT_TRUE(date_is(dates[i].imf));
  }
  /* 4xx and 3xx have it too */
  ASSERT_TRUE(exchange_at(784111777u, "GET /nope HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(404));
  ASSERT_TRUE(date_is("Sun, 06 Nov 1994 08:49:37 GMT"));
  h_status = 301;
  h_type = "text/plain";
  ASSERT_TRUE(exchange_at(784111777u, "GET /h HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(301));
  ASSERT_TRUE(date_is("Sun, 06 Nov 1994 08:49:37 GMT"));
}

/* REQ-HTTP-049: a handler's status outside 100..599, or a content type
 * with control characters, would put a protocol element outside the
 * grammar on the wire: 500 instead (RFC 9110 §2.2, §15, §5.5) */
TEST(itest_http_049_status_and_type_follow_the_grammar) {
  static const uint16_t bad_status[] = {0, 99, 600, 1000, 65535};
  static const char *const bad_type[] = {"text/html\r\nX-Evil: 1", "a\nb",
                                         "a\x01z", "a\x7fz"};
  unsigned i;
  h_type = "text/plain; charset=utf-8";
  h_status = 599;
  ASSERT_TRUE(exchange("GET /h HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(599));
  ASSERT_TRUE(has("\r\nContent-Type: text/plain; charset=utf-8\r\n"));
  for (i = 0; i < sizeof(bad_status) / sizeof(bad_status[0]); i++) {
    h_status = bad_status[i];
    ASSERT_TRUE(exchange("GET /h HTTP/1.0\r\n\r\n"));
    ASSERT_TRUE(status_is(500));
  }
  h_status = 200;
  for (i = 0; i < sizeof(bad_type) / sizeof(bad_type[0]); i++) {
    h_type = bad_type[i];
    ASSERT_TRUE(exchange("GET /h HTTP/1.0\r\n\r\n"));
    ASSERT_TRUE(status_is(500));
    ASSERT_TRUE(!has("X-Evil"));
  }
}

/* REQ-HTTP-050: no 1xx: the server answers HTTP/1.0 with one final
 * response, so a handler's 1xx is a 500 (RFC 9110 §15.2) */
TEST(itest_http_050_no_1xx) {
  static const uint16_t informational[] = {100, 101, 103, 199};
  unsigned i;
  h_type = "text/plain";
  for (i = 0; i < 4; i++) {
    h_status = informational[i];
    ASSERT_TRUE(exchange("GET /h HTTP/1.1\r\nHost: a\r\n\r\n"));
    ASSERT_TRUE(status_is(500));
  }
}

/* REQ-HTTP-051: a 205 has no content, whatever the handler gave (RFC 9110
 * §15.3.6) */
TEST(itest_http_051_205_without_content) {
  h_type = "text/plain";
  h_status = 205;
  ASSERT_TRUE(exchange("POST /h HTTP/1.0\r\nContent-Length: 0\r\n\r\n"));
  ASSERT_TRUE(status_is(205));
  ASSERT_TRUE(has("\r\nContent-Length: 0\r\n"));
  ASSERT_EQ(strlen(body()), 0u);
}

/* REQ-HTTP-052: 206, 401 and 426 need header fields the server cannot add
 * (Content-Range, WWW-Authenticate, Upgrade): a handler's is a 500 (RFC
 * 9110 §15.3.7.1, §15.5.2, §15.5.22) */
TEST(itest_http_052_statuses_needing_fields) {
  static const uint16_t need_fields[] = {206, 401, 426};
  unsigned i;
  h_type = "text/plain";
  for (i = 0; i < 3; i++) {
    h_status = need_fields[i];
    ASSERT_TRUE(exchange("GET /h HTTP/1.0\r\n\r\n"));
    ASSERT_TRUE(status_is(500));
  }
}

/* REQ-HTTP-053: "Expect: 100-continue" in an HTTP/1.1 request is answered
 * at once, before the content: 417, since an HTTP/1.0 server cannot send
 * 100 (Continue) — or the error the header section already decides.  The
 * content already arriving, or an HTTP/1.0 request, is processed (RFC
 * 9110 §10.1.1) */
TEST(itest_http_053_expect_100_continue) {
  static const char head[] = "POST /echo HTTP/1.1\r\nHost: a\r\n"
                             "Content-Length: 5\r\nExpect: 100-continue\r\n"
                             "\r\n";
  static const char nope[] = "POST /nope HTTP/1.1\r\nHost: a\r\n"
                             "Content-Length: 5\r\nExpect: 100-Continue\r\n"
                             "\r\n";
  static const char http10[] = "POST /echo HTTP/1.0\r\nContent-Length: 5\r\n"
                               "Expect: 100-continue\r\n\r\n";
  echo_calls = 0;
  ASSERT_TRUE(send_only(head, sizeof(head) - 1));
  ASSERT_TRUE(status_is(417));
  ASSERT_EQ(echo_calls, 0);
  ASSERT_TRUE(send_only(nope, sizeof(nope) - 1));
  ASSERT_TRUE(status_is(404));
  ASSERT_TRUE(exchange("POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n"
                       "Expect: 100-continue\r\n\r\nhello"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(strcmp(body(), "hello") == 0);
  ASSERT_TRUE(send_only(http10, sizeof(http10) - 1));
  ASSERT_EQ(cl.len, 0); /* waiting for the content */
  peer_send(&t, &cl, "hello", 5);
  got();
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(strcmp(body(), "hello") == 0);
}

/* REQ-HTTP-054: If-Match is evaluated before the method: "*" holds for a
 * route; entity tags never match (the server sends none): 412.  A 404
 * takes precedence (RFC 9110 §13.1.1, §13.2) */
TEST(itest_http_054_if_match) {
  echo_calls = 0;
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\nIf-Match: *\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\nIf-Match: \"abc\"\r\n\r\n"));
  ASSERT_TRUE(status_is(412));
  ASSERT_TRUE(exchange("POST /echo HTTP/1.0\r\nIf-Match: \"a\", W/\"b\"\r\n"
                       "Content-Length: 2\r\n\r\nhi"));
  ASSERT_TRUE(status_is(412));
  ASSERT_EQ(echo_calls, 0);
  ASSERT_TRUE(exchange("GET /nope HTTP/1.0\r\nIf-Match: \"abc\"\r\n\r\n"));
  ASSERT_TRUE(status_is(404));
}

/* REQ-HTTP-055: If-None-Match is evaluated before the method: "*" fails
 * for a route — 304 for GET and HEAD, 412 otherwise; entity tags never
 * match, so the request proceeds (RFC 9110 §13.1.2, §13.2) */
TEST(itest_http_055_if_none_match) {
  echo_calls = 0;
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\nIf-None-Match: \"abc\"\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\nIf-None-Match: *\r\n\r\n"));
  ASSERT_TRUE(status_is(304));
  ASSERT_EQ(strlen(body()), 0u);
  ASSERT_TRUE(exchange("HEAD / HTTP/1.0\r\nIf-None-Match: *\r\n\r\n"));
  ASSERT_TRUE(status_is(304));
  ASSERT_TRUE(exchange("POST /echo HTTP/1.0\r\nIf-None-Match: *\r\n"
                       "Content-Length: 2\r\n\r\nhi"));
  ASSERT_TRUE(status_is(412));
  ASSERT_EQ(echo_calls, 0);
  ASSERT_TRUE(exchange("GET /off HTTP/1.0\r\nIf-None-Match: *\r\n\r\n"));
  ASSERT_TRUE(status_is(405));
}

/* REQ-HTTP-056: a request for an https resource that did not come over
 * TLS is misdirected: 421 (RFC 9110 §7.4) */
TEST(itest_http_056_https_target_over_plain_tcp) {
  ASSERT_TRUE(exchange("GET https://a.example/ HTTP/1.1\r\n"
                       "Host: a.example\r\n\r\n"));
  ASSERT_TRUE(status_is(421));
}

/* REQ-HTTP-057: an invalid Content-Length is a 400 and the connection
 * closes; numerals too large for 32 bits cannot wrap around (RFC 9112
 * §6.3, RFC 9110 §8.6) */
TEST(itest_http_057_invalid_content_length) {
  static const char *const values[] = {
      "1a",
      "-1",
      "",
      "5, 5",
      "4294967296",
      "18446744073709551621",
      "5\r\nContent-Length: 6",
  };
  char req[128];
  unsigned i;
  echo_calls = 0;
  for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    snprintf(req, sizeof(req),
             "POST /echo HTTP/1.0\r\nContent-Length: %s\r\n\r\nhello",
             values[i]);
    ASSERT_TRUE(exchange(req)); /* answered, and closed */
    ASSERT_TRUE(status_is(400));
  }
  ASSERT_EQ(echo_calls, 0);
}

/* REQ-HTTP-058: content cut short by the client's close, or by the
 * request timeout, makes the request incomplete: the connection closes
 * and nothing is processed (RFC 9112 §6.3) */
TEST(itest_http_058_incomplete_content) {
  static const char req[] = "POST /echo HTTP/1.0\r\nContent-Length: 10\r\n\r\n"
                            "abc";
  echo_calls = 0;
  ASSERT_TRUE(send_only(req, sizeof(req) - 1));
  ASSERT_EQ(cl.len, 0);
  peer_close(&t, &cl);
  ASSERT_TRUE(cl.fin);
  ASSERT_EQ(cl.len, 0);
  ASSERT_TRUE(send_only(req, sizeof(req) - 1));
  http_server_tick(&srv, HTTP_REQUEST_TIMEOUT_MS);
  peer_collect(&t, &cl);
  ASSERT_TRUE(cl.rst);
  ASSERT_EQ(cl.len, 0);
  ASSERT_EQ(echo_calls, 0);
}

/* REQ-HTTP-059: whitespace between a field name and its colon is a 400;
 * whitespace around a field value is not part of it (RFC 9112 §5.1, RFC
 * 9110 §5.5) */
TEST(itest_http_059_field_whitespace) {
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\nHost : a\r\n\r\n"));
  ASSERT_TRUE(status_is(400));
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\nX-A\t: b\r\n\r\n"));
  ASSERT_TRUE(status_is(400));
  ASSERT_TRUE(exchange("POST /echo HTTP/1.0\r\nContent-Length: \t 3 \t \r\n"
                       "\r\nabc"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(strcmp(body(), "abc") == 0);
}

/* REQ-HTTP-060: obsolete line folding, and whitespace between the request
 * line and the first field, are a 400 (RFC 9112 §5.2, §2.2) */
TEST(itest_http_060_folding_and_leading_whitespace) {
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\nX-A: a\r\n b\r\n\r\n"));
  ASSERT_TRUE(status_is(400));
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\nX-A: a\r\n\tb\r\n\r\n"));
  ASSERT_TRUE(status_is(400));
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\n X-A: a\r\n\r\n"));
  ASSERT_TRUE(status_is(400));
}

/* REQ-HTTP-061: nothing is applied to the resource until the whole header
 * section has arrived (RFC 9110 §5.3) */
TEST(itest_http_061_whole_header_section_first) {
  static const char part[] = "POST /echo HTTP/1.0\r\nContent-Length: 0\r\n";
  echo_calls = 0;
  ASSERT_TRUE(send_only(part, sizeof(part) - 1));
  ASSERT_EQ(cl.len, 0);
  ASSERT_EQ(echo_calls, 0);
  peer_send(&t, &cl, "\r\n", 2);
  got();
  ASSERT_TRUE(status_is(200));
  ASSERT_EQ(echo_calls, 1);
}

/* REQ-HTTP-062: the request is parsed as octets: an LF always ends a line,
 * and other octets — UTF-8, an overlong LF, obs-text — are opaque (RFC
 * 9112 §2.2) */
TEST(itest_http_062_parsed_as_octets) {
  ASSERT_TRUE(exchange("GET /q?caf\xc3\xa9 HTTP/1.0\r\n"
                       "X-A: \xe2\x80\xa8\xc0\x8a\xff\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(strcmp(body(), "caf\xc3\xa9") == 0);
  ASSERT_TRUE(exchange("GET /q?a HTTP/1.0\nX-A: b\nHost : c\n\n"));
  ASSERT_TRUE(status_is(400)); /* the third line is a field of its own */
}

/* REQ-HTTP-063: every response is HTTP/1.0, the version the server
 * conforms to, whatever the request's (RFC 9110 §6.2) */
TEST(itest_http_063_always_http_1_0) {
  ASSERT_TRUE(exchange("GET / HTTP/1.1\r\nHost: a\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(exchange("GET / HTTP/1.9\r\nHost: a\r\n\r\n"));
  ASSERT_TRUE(status_is(505));
  ASSERT_TRUE(exchange("GET / HTTP/2.0\r\n\r\n"));
  ASSERT_TRUE(status_is(505));
}

/* REQ-HTTP-064: no Transfer-Encoding in any response — not in a 204, not
 * to HTTP/1.0, never beside Content-Length (RFC 9112 §6.1, §6.2) */
TEST(itest_http_064_never_transfer_encoding) {
  static const char *const requests[] = {
      "GET / HTTP/1.0\r\n\r\n",
      "GET / HTTP/1.1\r\nHost: a\r\n\r\n",
      "GET /none HTTP/1.1\r\nHost: a\r\n\r\n",
      "HEAD / HTTP/1.1\r\nHost: a\r\n\r\n",
      "POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi",
      "GET /nope HTTP/1.1\r\nHost: a\r\n\r\n",
  };
  unsigned i;
  for (i = 0; i < sizeof(requests) / sizeof(requests[0]); i++) {
    ASSERT_TRUE(exchange(requests[i]));
    ASSERT_TRUE(!has("Transfer-Encoding"));
  }
}

#ifdef ITEST_HTTPS
/* ── Over TLS: the slot carried by http_conn_use_tls() ── */

#include "http_tls.h"
#include "tls_crypto_mbedtls.h"

#define HOST "device.example"

static tls_mbedtls_t backend;
static tls_crypto_t crypto;
static tls_config_t srv_cfg, cli_cfg;
static tls_conn_t srv_tls, cli_tls;
static uint8_t srv_tls_rx[4096], srv_tls_tx[2048];
static uint8_t cli_tls_rx[4096], cli_tls_tx[2048];
static char tls_resp[2048];
static const char *const cert_hosts[] = {"10.0.0.2", HOST};
static const uint8_t psk[32] = {0x69, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x70, 0x73,
                                0x6b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

static int tls_setup(void) {
  if (tls_mbedtls_init(&backend, &crypto) != 0)
    return 0;
  srv_cfg.crypto = &crypto;
  srv_cfg.psk = psk;
  srv_cfg.psk_len = sizeof(psk);
  srv_cfg.psk_id = (const uint8_t *)"itest";
  srv_cfg.psk_id_len = 5;
  srv_cfg.psk_modes = TLS_PSK_KE | TLS_PSK_DHE_KE;
  cli_cfg = srv_cfg;
  cli_cfg.psk_modes = 0;
  return 1;
}

/* Ciphertext both ways between the client and the wire; 1 if any moved */
static int tls_carry(uint16_t *taken) {
  const uint8_t *p;
  size_t n;
  int moved = 0;
  while ((n = tls_tx_pending(&cli_tls, &p)) > 0) {
    uint16_t k = (uint16_t)(n > 1200 ? 1200 : n);
    peer_send(&t, &cl, p, k);
    tls_tx_done(&cli_tls, k);
    moved = 1;
  }
  if (cl.len > *taken) {
    size_t took = tls_input(&cli_tls, cl.data + *taken, cl.len - *taken);
    *taken = (uint16_t)(*taken + took);
    moved |= took > 0;
  }
  return moved;
}

/* One request over TLS on a new connection; the response in resp.
 * @return 1 if the server answered. */
static int tls_exchange(const char *request) {
  uint16_t taken = 0;
  size_t n = 0;
  int sent = 0, rounds;
  up();
  tls_init(&srv_tls, &srv_cfg, srv_tls_rx, sizeof(srv_tls_rx), srv_tls_tx,
           sizeof(srv_tls_tx));
  http_conn_use_tls(&slot, &srv_tls);
  srv.https_hosts = cert_hosts;
  srv.n_https_hosts = 2;
  tls_init(&cli_tls, &cli_cfg, cli_tls_rx, sizeof(cli_tls_rx), cli_tls_tx,
           sizeof(cli_tls_tx));
  tls_connect(&cli_tls, NULL);
  if (!peer_connect(&t, &cl, next_port++, PORT))
    return 0;
  for (rounds = 0; rounds < 100; rounds++) {
    int moved;
    if (!sent && tls_state(&cli_tls) == TLS_STATE_CONNECTED) {
      tls_write(&cli_tls, (const uint8_t *)request, strlen(request));
      sent = 1;
    }
    moved = tls_carry(&taken);
    n += tls_read(&cli_tls, (uint8_t *)tls_resp + n, sizeof(tls_resp) - 1 - n);
    if (!moved && sent)
      break;
  }
  tls_resp[n] = 0;
  resp = tls_resp;
  return n > 0;
}

/* REQ-HTTP-047: an https target in absolute-form is accepted over TLS;
 * its authority, not Host, names the host */
TEST(itest_http_047_https_absolute_form_over_tls) {
  ASSERT_TRUE(tls_exchange("GET https://" HOST "/ HTTP/1.1\r\n"
                           "Host: other.example\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(strcmp(body(), page) == 0);
}

/* REQ-HTTP-056: over TLS, a host the certificate is not valid for — not
 * among the names the application lists — is misdirected: 421; the
 * absolute-form authority decides, not Host (RFC 9110 §7.4) */
TEST(itest_http_056_host_not_in_the_certificate) {
  static const struct {
    const char *request;
    int status;
  } cases[] = {
      {"GET / HTTP/1.1\r\nHost: " HOST "\r\n\r\n", 200},
      {"GET / HTTP/1.1\r\nHost: Device.Example:443\r\n\r\n", 200},
      {"GET / HTTP/1.1\r\nHost: 10.0.0.2\r\n\r\n", 200},
      {"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n", 421},
      {"GET https://other.example/ HTTP/1.1\r\nHost: " HOST "\r\n\r\n", 421},
      {"GET / HTTP/1.0\r\n\r\n", 421}, /* no host at all */
  };
  unsigned i;
  for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ASSERT_TRUE(tls_exchange(cases[i].request));
    ASSERT_TRUE(status_is(cases[i].status));
  }
}
#endif

int main(void) {
  fprintf(stderr, "=== itest_http ===\n");
  RUN_TEST(itest_http_002_get);
  RUN_TEST(itest_http_023_head_never_has_a_body);
  RUN_TEST(itest_http_023_head_414_without_a_body);
  RUN_TEST(itest_http_020_204_without_content);
  RUN_TEST(itest_http_020_head_length_is_gets);
  RUN_TEST(itest_http_024_405_always_has_allow);
  RUN_TEST(itest_http_024_handler_405_lists_the_routes_methods);
  RUN_TEST(itest_http_010_one_host_line);
  RUN_TEST(itest_http_044_bare_cr_and_nul_rejected);
  RUN_TEST(itest_http_045_invalid_host_value);
  RUN_TEST(itest_http_046_transfer_encoding);
  RUN_TEST(itest_http_047_absolute_form);
  RUN_TEST(itest_http_048_date_from_the_clock);
  RUN_TEST(itest_http_049_status_and_type_follow_the_grammar);
  RUN_TEST(itest_http_050_no_1xx);
  RUN_TEST(itest_http_051_205_without_content);
  RUN_TEST(itest_http_052_statuses_needing_fields);
  RUN_XFAIL(itest_http_053_expect_100_continue);
  RUN_XFAIL(itest_http_054_if_match);
  RUN_XFAIL(itest_http_055_if_none_match);
  RUN_TEST(itest_http_056_https_target_over_plain_tcp);
  RUN_TEST(itest_http_057_invalid_content_length);
  RUN_TEST(itest_http_058_incomplete_content);
  RUN_TEST(itest_http_059_field_whitespace);
  RUN_TEST(itest_http_060_folding_and_leading_whitespace);
  RUN_TEST(itest_http_061_whole_header_section_first);
  RUN_TEST(itest_http_062_parsed_as_octets);
  RUN_TEST(itest_http_063_always_http_1_0);
  RUN_TEST(itest_http_064_never_transfer_encoding);
#ifdef ITEST_HTTPS
  if (!tls_setup()) {
    fprintf(stderr, "TLS backend init failed\n");
    return 1;
  }
  RUN_TEST(itest_http_047_https_absolute_form_over_tls);
  RUN_TEST(itest_http_056_host_not_in_the_certificate);
  tls_mbedtls_free(&backend);
#endif
  ITEST_REPORT();
  return test_failures;
}
