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

#define SLOTS 2
#define TCP_BUF 1024

static itest_t t;
static http_server_t srv;
static http_conn_t slot[SLOTS];
static tcp_conn_t *table[SLOTS];
static uint8_t tx_mem[SLOTS][TCP_BUF], rx_mem[SLOTS][TCP_BUF];
static char req_mem[SLOTS][REQ_SIZE];
static peer_client_t cl;
/* How many slots the server is given: one, unless a test asks for two */
static uint8_t use_slots = 1;
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

/* What the handler was given, and a body generated in its scratch space */
static http_request_t seen;
static char seen_path[32], seen_query[32], seen_host[32], seen_body[32];
static int info_ctx;

static int page_info(const http_request_t *rq, http_response_t *rs, void *c) {
  int n;
  seen = *rq;
  snprintf(seen_path, sizeof(seen_path), "%s", rq->path);
  snprintf(seen_query, sizeof(seen_query), "%s", rq->query);
  snprintf(seen_host, sizeof(seen_host), "%.*s", (int)rq->host_len,
           rq->host ? rq->host : "");
  snprintf(seen_body, sizeof(seen_body), "%.*s", (int)rq->body_len,
           rq->body ? (const char *)rq->body : "");
  (*(int *)c)++;
  n = snprintf((char *)rs->scratch, rs->scratch_size, "{\"path\":\"%s\"}",
               rq->path);
  rs->status = 201;
  rs->content_type = "application/json";
  rs->body = rs->scratch;
  rs->body_len = (uint32_t)n;
  return 0;
}

static int page_fail(const http_request_t *rq, http_response_t *rs, void *c) {
  (void)rq;
  (void)rs;
  (void)c;
  return -1;
}

/* Three times the TCP transmit buffer */
static uint8_t big[3 * TCP_BUF];
static int page_big(const http_request_t *rq, http_response_t *rs, void *c) {
  (void)rq;
  (void)c;
  rs->content_type = "application/octet-stream";
  rs->body = big;
  rs->body_len = sizeof(big);
  return 0;
}

static const http_route_t routes[] = {
    {"/", HTTP_GET, page_root, NULL},
    {"/none", HTTP_GET, page_none, NULL},
    {"/off", 0, page_root, NULL},
    {"/echo", HTTP_POST, page_echo, NULL},
    {"/q", HTTP_GET, page_query, NULL},
    {"/h", HTTP_GET | HTTP_POST, page_custom, NULL},
    {"/info", HTTP_GET | HTTP_POST, page_info, &info_ctx},
    {"/fail", HTTP_GET, page_fail, NULL},
    {"/big", HTTP_GET, page_big, NULL},
};

static void serve(itest_t *it) {
  (void)it;
  http_server_poll(&srv);
}

static void up(void) {
  uint8_t i;
  itest_up(&t, 1514, 1514);
  t.service = serve;
  for (i = 0; i < use_slots; i++) {
    http_conn_init(&slot[i], tx_mem[i], TCP_BUF, rx_mem[i], TCP_BUF, req_mem[i],
                   REQ_SIZE);
    table[i] = http_conn_tcp(&slot[i]);
  }
  tcp_set_connections(&t.net, table, use_slots);
  http_server_init(&srv, &t.net, PORT, routes,
                   sizeof(routes) / sizeof(routes[0]), slot, use_slots);
  srv.clock = use_clock;
}

static void got(void) {
  cl.data[cl.len < sizeof(cl.data) ? cl.len : sizeof(cl.data) - 1] = 0;
  resp = (const char *)cl.data;
}

/* A new connection to the running server, @p len bytes of request on it,
 * and what came back (in resp) — the client has not closed. */
static int send_more(const char *request, uint16_t len) {
  if (!peer_connect(&t, &cl, next_port++, PORT))
    return 0;
  peer_send(&t, &cl, request, len);
  got();
  return 1;
}

/* The same to a server just started */
static int send_only(const char *request, uint16_t len) {
  up();
  return send_more(request, len);
}

/* One more request to the running server, on a new connection the client
 * then closes; the response in resp.  @return 1 if the server answered
 * and closed. */
static int next_exchange(const char *request) {
  if (!send_more(request, (uint16_t)strlen(request)))
    return 0;
  peer_close(&t, &cl);
  got();
  return cl.len > 0 && cl.fin;
}

/* A segment from the client, built here so a test can choose its flags
 * and when to acknowledge; what the server sends stays on the wire */
static void segment(uint8_t flags, const void *data, uint16_t len) {
  static uint8_t f[WIRE_FRAME_MAX];
  peer_tcp_seg_t s;
  memset(&s, 0, sizeof(s));
  s.sport = cl.sport;
  s.dport = cl.dport;
  s.seq = cl.snd_nxt;
  s.ack = cl.rcv_nxt;
  s.flags = flags;
  s.window = 8192;
  s.data = data;
  s.len = len;
  cl.snd_nxt += len + ((flags & (TCPF_SYN | TCPF_FIN)) ? 1u : 0u);
  wire_clear(&t);
  cl.seen = 0;
  itest_receive(&t, f, peer_tcp_frame(f, &t.net, PEER_IP, &s));
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

/* REQ-HTTP-002, 011, 013, 020, 029: GET — HTTP/1.0, which needs no Host —
 * answered with the page, closed */
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
  ASSERT_TRUE(exchange("GET /echo HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(405));
  ASSERT_TRUE(has("\r\nAllow: POST\r\n"));
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
      "a b", "a/b",   "a@b",        "a:8x",        "[fe80::1", "a%4",
      "a?b", "a,b c", "[fe80::1]x", "[fe80::g h]", "[]",
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
  static const char *const chunked[] = {"chunked", "gzip, chunked", "CHUNKED",
                                        "chunked, ,"};
  char req[128];
  unsigned i;
  echo_calls = 0;
  for (i = 0; i < 4; i++) {
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

/* REQ-HTTP-001, 005, 006, 026: the request line is method SP target SP
 * HTTP-version; the target's path selects the route and its query reaches
 * the handler.  A line of any other shape is a 400, a version other than
 * HTTP/1.0 and HTTP/1.1 a 505 (RFC 9112 §3, §2.3) */
TEST(itest_http_001_request_line) {
  static const char *const malformed[] = {
      "GET  / HTTP/1.0\r\n\r\n",         /* two spaces */
      "GET index.html HTTP/1.0\r\n\r\n", /* neither a path nor a URI */
      "GET 1http://a/ HTTP/1.0\r\n\r\n",
      " GET / HTTP/1.0\r\n\r\n", /* no method */
      "GET / HTTP/1.0 extra\r\n\r\n",
      "G\x01T / HTTP/1.0\r\n\r\n", /* not a token */
      "GET /\r\n\r\n",             /* no version */
      "GET / HTTP/1.x\r\n\r\n",
      "GET / FTP/1.0\r\n\r\n",
  };
  unsigned i;
  ASSERT_TRUE(exchange("GET /q?x=1&y=2 HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(strcmp(body(), "x=1&y=2") == 0);
  ASSERT_TRUE(exchange("GET /q? HTTP/1.1\r\nHost: a\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(has("\r\nContent-Length: 0\r\n"));
  for (i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
    ASSERT_TRUE(exchange(malformed[i]));
    ASSERT_TRUE(status_is(400));
  }
  ASSERT_TRUE(exchange("GET / HTTP/2.0\r\n\r\n"));
  ASSERT_TRUE(status_is(505));
  ASSERT_TRUE(exchange("GET / HTTP/0.9\r\n\r\n"));
  ASSERT_TRUE(status_is(505));
}

/* REQ-HTTP-007, 009, 012: fields are name ":" value lines; names are
 * compared without case, fields the server does not know are ignored, and
 * a line without a colon or without a name is a 400 (RFC 9112 §5, RFC
 * 9110 §5.1) */
TEST(itest_http_007_field_lines) {
  ASSERT_TRUE(exchange("GET / HTTP/1.1\r\nHost: h\r\nUser-Agent: curl/8\r\n"
                       "Accept: */*\r\nX-Weird: a: b: c\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(exchange("POST /echo HTTP/1.0\r\ncontent-LENGTH: 3\r\n\r\nabc"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(strcmp(body(), "abc") == 0);
  ASSERT_TRUE(exchange("POST /echo HTTP/1.0\r\nContent-Length: 3\r\n"
                       "Content-Length: 3\r\n\r\nabc")); /* the same twice */
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\nNoColonHere\r\n\r\n"));
  ASSERT_TRUE(status_is(400));
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\n: no-name\r\n\r\n"));
  ASSERT_TRUE(status_is(400));
}

/* REQ-HTTP-008, 032, 061: the header section ends at the empty line —
 * CRLF or bare LF line endings, empty lines before the request line
 * skipped (RFC 9112 §2.2) — however the segments cut it; then the content
 * is read to its Content-Length */
TEST(itest_http_008_end_of_the_header_section) {
  static const char post[] = "POST /echo HTTP/1.1\r\nHost: h\r\n"
                             "Content-Length: 6\r\n\r\n";
  ASSERT_TRUE(exchange("GET /q?lf HTTP/1.1\nHost: h\n\n"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(strcmp(body(), "lf") == 0);
  ASSERT_TRUE(exchange("\r\n\r\nGET / HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(200));

  ASSERT_TRUE(send_only("GET / HT", 8));
  peer_send(&t, &cl, "TP/1.0\r\n\r", 9);
  ASSERT_EQ(cl.len, 0);
  peer_send(&t, &cl, "\n", 1);
  got();
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(strcmp(body(), page) == 0);

  echo_calls = 0;
  ASSERT_TRUE(send_only(post, sizeof(post) - 1));
  peer_send(&t, &cl, "wor", 3);
  ASSERT_EQ(cl.len, 0);
  ASSERT_EQ(echo_calls, 0);
  peer_send(&t, &cl, "ld!", 3);
  got();
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(strcmp(body(), "world!") == 0);
}

/* REQ-HTTP-003, 013, 014, 015: the route's handler gets the method, version,
 * path, query, host, content and client address — and its own context —
 * and what it answers is sent: status, content type, a body it generated
 * in its scratch space.  HEAD runs the GET handler */
TEST(itest_http_014_handler_gets_the_request) {
  info_ctx = 0;
  ASSERT_TRUE(exchange("POST /info?a=1 HTTP/1.1\r\nHost: dev.example:8080\r\n"
                       "Content-Length: 5\r\n\r\nhello"));
  ASSERT_EQ(info_ctx, 1);
  ASSERT_EQ(seen.method, HTTP_POST);
  ASSERT_EQ(seen.version, 11);
  ASSERT_TRUE(strcmp(seen_path, "/info") == 0);
  ASSERT_TRUE(strcmp(seen_query, "a=1") == 0);
  ASSERT_TRUE(strcmp(seen_host, "dev.example") == 0);
  ASSERT_TRUE(strcmp(seen_body, "hello") == 0);
  ASSERT_EQ(seen.remote_ip, PEER_IP);
#if NET_USE_IPV6
  ASSERT_TRUE(seen.remote_ip6 == NULL);
#endif
  ASSERT_TRUE(has("HTTP/1.0 201 Created\r\n"));
  ASSERT_TRUE(has("\r\nContent-Type: application/json\r\n"));
  ASSERT_TRUE(has("\r\nContent-Length: 16\r\n"));
  ASSERT_TRUE(strcmp(body(), "{\"path\":\"/info\"}") == 0);

  ASSERT_TRUE(exchange("GET /info HTTP/1.0\r\n\r\n"));
  ASSERT_EQ(seen.method, HTTP_GET);
  ASSERT_EQ(seen.version, 10);
  ASSERT_TRUE(seen.host == NULL);
  ASSERT_TRUE(seen.body == NULL);
  ASSERT_EQ(seen.body_len, 0);
  ASSERT_TRUE(strcmp(seen_query, "") == 0);

  ASSERT_TRUE(exchange("HEAD /info HTTP/1.0\r\n\r\n"));
  ASSERT_EQ(seen.method, HTTP_HEAD);
  ASSERT_EQ(info_ctx, 3);
}

/* REQ-HTTP-016, 017, 018, 019, 021, 022: the status line is HTTP-version
 * SP status SP reason CRLF, with the reason phrase of every status the
 * server knows (none for one it does not); then the fields, the empty
 * line, the body.  The server's own errors carry their reason phrase as
 * text/plain */
TEST(itest_http_016_status_line_fields_body) {
  static const struct {
    uint16_t status;
    const char *reason;
  } known[] = {
      {201, "Created"},
      {301, "Moved Permanently"},
      {302, "Found"},
      {303, "See Other"},
      {403, "Forbidden"},
      {404, "Not Found"},
      {408, "Request Timeout"},
      {413, "Content Too Large"},
      {500, "Internal Server Error"},
      {503, "Service Unavailable"},
      {299, ""},
  };
  char want[64];
  unsigned i;
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(strcmp(resp, "HTTP/1.0 200 OK\r\n"
                           "Content-Type: text/html\r\n"
                           "Content-Length: 11\r\n"
                           "Connection: close\r\n"
                           "\r\n"
                           "<h1>hi</h1>") == 0);
  h_type = "text/plain";
  for (i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
    h_status = known[i].status;
    ASSERT_TRUE(exchange("GET /h HTTP/1.0\r\n\r\n"));
    snprintf(want, sizeof(want), "HTTP/1.0 %u %s\r\n", known[i].status,
             known[i].reason);
    ASSERT_TRUE(strncmp(resp, want, strlen(want)) == 0);
    ASSERT_TRUE(strcmp(body(), "x") == 0);
  }
  ASSERT_TRUE(exchange("GET / HTTP/1.1\r\n\r\n"));
  ASSERT_TRUE(strcmp(resp, "HTTP/1.0 400 Bad Request\r\n"
                           "Content-Type: text/plain\r\n"
                           "Content-Length: 11\r\n"
                           "Connection: close\r\n"
                           "\r\n"
                           "Bad Request") == 0);
}

/* REQ-HTTP-019, 035, 036, 037, 038: the handler's content type is sent —
 * text/html unless it says otherwise — and none if it sets none */
TEST(itest_http_019_content_type) {
  static const char *const types[] = {"text/plain", "application/json",
                                      "application/octet-stream"};
  char want[64];
  unsigned i;
  ASSERT_TRUE(exchange("GET / HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(has("\r\nContent-Type: text/html\r\n"));
  h_status = 200;
  for (i = 0; i < 3; i++) {
    h_type = types[i];
    ASSERT_TRUE(exchange("GET /h HTTP/1.0\r\n\r\n"));
    snprintf(want, sizeof(want), "\r\nContent-Type: %s\r\n", types[i]);
    ASSERT_TRUE(has(want));
  }
  h_type = NULL;
  ASSERT_TRUE(exchange("GET /h HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(!has("Content-Type"));
  ASSERT_TRUE(strcmp(body(), "x") == 0);
}

/* REQ-HTTP-020, 022, 038: a response larger than the TCP transmit buffer
 * is streamed whole, in order, with its length announced; a small one
 * leaves as one segment, header and body together */
TEST(itest_http_022_response_of_any_length) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  const char *b;
  unsigned i;
  for (i = 0; i < sizeof(big); i++)
    big[i] = (uint8_t)('A' + (i & 15) + ((i >> 8) & 7));
  ASSERT_TRUE(exchange("GET /big HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
  ASSERT_TRUE(has("\r\nContent-Length: 3072\r\n"));
  ASSERT_TRUE(has("\r\nContent-Type: application/octet-stream\r\n"));
  b = body();
  ASSERT_EQ(cl.len, (size_t)(b - resp) + sizeof(big));
  ASSERT_MEM_EQ(b, big, sizeof(big));

  up();
  ASSERT_TRUE(peer_connect(&t, &cl, next_port++, PORT));
  segment(TCPF_PSH | TCPF_ACK, "GET / HTTP/1.0\r\n\r\n", 18);
  ASSERT_TRUE(wire_find_tcp(&t, 0, &ip, &tcp) >= 0);
  if (tcp.data_len == 0) /* an acknowledgement first */
    ASSERT_TRUE(wire_find_tcp(&t, 1, &ip, &tcp) >= 0);
  ASSERT_TRUE(tcp.data_len > sizeof(page));
  ASSERT_MEM_EQ(tcp.data, "HTTP/1.0 200 OK\r\n", 17);
  ASSERT_MEM_EQ(tcp.data + tcp.data_len - (sizeof(page) - 1), page,
                sizeof(page) - 1);
}

/* REQ-HTTP-024: a method the server does not implement is a 501 (RFC 9110
 * §9.1, §15.6.2); method names are case-sensitive */
TEST(itest_http_024_unimplemented_method_501) {
  static const char *const requests[] = {
      "PUT / HTTP/1.0\r\n\r\n",
      "DELETE / HTTP/1.0\r\n\r\n",
      "OPTIONS * HTTP/1.0\r\n\r\n",
      "get / HTTP/1.0\r\n\r\n",
  };
  unsigned i;
  for (i = 0; i < sizeof(requests) / sizeof(requests[0]); i++) {
    ASSERT_TRUE(exchange(requests[i]));
    ASSERT_TRUE(has("HTTP/1.0 501 Not Implemented\r\n"));
  }
}

/* REQ-HTTP-025: a path no route has is a 404; paths are compared exactly */
TEST(itest_http_025_unknown_path_404) {
  static const char *const requests[] = {
      "GET /nope HTTP/1.0\r\n\r\n",
      "GET /Q HTTP/1.0\r\n\r\n",
      "GET /q/ HTTP/1.0\r\n\r\n",
      "GET /%71 HTTP/1.0\r\n\r\n",
      "POST /nope HTTP/1.0\r\nContent-Length: 0\r\n\r\n",
  };
  unsigned i;
  for (i = 0; i < sizeof(requests) / sizeof(requests[0]); i++) {
    ASSERT_TRUE(exchange(requests[i]));
    ASSERT_TRUE(has("HTTP/1.0 404 Not Found\r\n"));
    ASSERT_TRUE(strcmp(body(), "Not Found") == 0);
  }
}

/* REQ-HTTP-027, 049: a handler that fails is a 500, and so is a response
 * whose header block the server cannot format whole (a content type too
 * long for it) */
TEST(itest_http_027_handler_failure_500) {
  static char long_type[HTTP_HDR_MAX + 1];
  ASSERT_TRUE(exchange("GET /fail HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(has("HTTP/1.0 500 Internal Server Error\r\n"));
  ASSERT_TRUE(strcmp(body(), "Internal Server Error") == 0);
  memset(long_type, 'a', sizeof(long_type) - 1);
  h_status = 200;
  h_type = long_type;
  ASSERT_TRUE(exchange("GET /h HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(has("HTTP/1.0 500 Internal Server Error\r\n"));
  ASSERT_TRUE(has("\r\nContent-Type: text/plain\r\n"));
}

/* REQ-HTTP-021, 028, 029, 031: every response says "Connection: close"
 * and the server then closes, whatever the request's Connection field
 * asked for; a second request on the connection is never processed (RFC
 * 9112 §9.6) */
TEST(itest_http_031_closes_after_one_response) {
  static const char *const connection[] = {"", "Connection: close\r\n",
                                           "Connection: keep-alive\r\n"};
  char req[192];
  unsigned i;
  for (i = 0; i < 3; i++) {
    int n = snprintf(req, sizeof(req),
                     "GET / HTTP/1.1\r\nHost: a\r\n%s\r\n"
                     "POST /echo HTTP/1.1\r\nHost: a\r\n"
                     "Content-Length: 2\r\n\r\nhi",
                     connection[i]);
    echo_calls = 0;
    ASSERT_TRUE(send_only(req, (uint16_t)n));
    ASSERT_TRUE(cl.fin); /* the server closed, the client has not */
    ASSERT_TRUE(status_is(200));
    ASSERT_TRUE(has("\r\nConnection: close\r\n"));
    ASSERT_TRUE(strcmp(body(), page) == 0); /* and nothing after it */
    ASSERT_EQ(echo_calls, 0);
  }
}

/* REQ-HTTP-032, 033, 034: content up to the request buffer's free space
 * reaches the handler; a Content-Length beyond it is a 413 at once, and
 * the handler does not run */
TEST(itest_http_033_content_bounded_by_the_request_buffer) {
  static char req[REQ_SIZE + 64];
  int h;
  echo_calls = 0;
  h = snprintf(req, sizeof(req),
               "POST /echo HTTP/1.0\r\nContent-Length: %u\r\n\r\n", 468u);
  ASSERT_EQ(h + 468, REQ_SIZE); /* the request fills the buffer exactly */
  memset(req + h, 'b', 468);
  ASSERT_TRUE(exchange_n(req, REQ_SIZE));
  ASSERT_TRUE(status_is(200));
  ASSERT_EQ(echo_calls, 1);
  ASSERT_EQ(strlen(body()), 468u);

  h = snprintf(req, sizeof(req),
               "POST /echo HTTP/1.0\r\nContent-Length: %u\r\n\r\n", 469u);
  memset(req + h, 'b', 469);
  ASSERT_TRUE(exchange_n(req, (uint16_t)(h + 469)));
  ASSERT_TRUE(has("HTTP/1.0 413 Content Too Large\r\n"));

  ASSERT_TRUE(
      send_only("POST /echo HTTP/1.0\r\nContent-Length: 10000\r\n\r\n", 46));
  ASSERT_TRUE(status_is(413)); /* before any content arrives */
  ASSERT_EQ(echo_calls, 1);
}

/* REQ-HTTP-039, 040, 041: a request line longer than the request buffer
 * is a 414, a header section longer than it a 431 (RFC 9112 §3, RFC 6585
 * §5); neither reaches a handler.  A request buffer too small for any
 * request is refused when the slot is set up */
TEST(itest_http_040_request_larger_than_the_buffer) {
  static char req[REQ_SIZE + 64];
  static http_conn_t c;
  static uint8_t tx[64], rx[64];
  static char small[31];
  info_ctx = 0;
  memset(req, 'a', sizeof(req) - 1);
  memcpy(req, "GET /info?", 10);
  ASSERT_TRUE(exchange(req));
  ASSERT_TRUE(has("HTTP/1.0 414 URI Too Long\r\n"));
  memset(req, 'p', sizeof(req) - 1);
  memcpy(req, "GET /info HTTP/1.0\r\nX-Pad: ", 27);
  ASSERT_TRUE(exchange(req));
  ASSERT_TRUE(has("HTTP/1.0 431 Request Header Fields Too Large\r\n"));
  ASSERT_EQ(info_ctx, 0);
  ASSERT_EQ(
      http_conn_init(&c, tx, sizeof(tx), rx, sizeof(rx), small, sizeof(small)),
      NET_ERR_INVALID_PARAM);
  ASSERT_EQ(http_conn_init(&c, tx, sizeof(tx), rx, sizeof(rx), req, 32),
            NET_OK);
}

/* REQ-HTTP-028, 029: one slot serves client after client: the connection
 * is closed after each response and the slot listens again at once — also
 * when the request came with the client's FIN, and when the client's FIN
 * crosses the server's */
TEST(itest_http_028_one_slot_client_after_client) {
  static const char get[] = "GET / HTTP/1.0\r\n\r\n";
  peer_ip_t ip;
  peer_tcp_t tcp;
  int i;
  up();
  for (i = 0; i < 5; i++) {
    ASSERT_TRUE(next_exchange(get));
    ASSERT_TRUE(strcmp(body(), page) == 0);
  }
  /* the request and the FIN in one segment */
  ASSERT_TRUE(peer_connect(&t, &cl, next_port++, PORT));
  segment(TCPF_PSH | TCPF_ACK | TCPF_FIN, get, sizeof(get) - 1);
  peer_collect(&t, &cl);
  got();
  ASSERT_TRUE(strcmp(body(), page) == 0);
  ASSERT_TRUE(cl.fin);
  /* the response acknowledged, then a FIN that does not acknowledge the
   * server's */
  ASSERT_TRUE(peer_connect(&t, &cl, next_port++, PORT));
  segment(TCPF_PSH | TCPF_ACK, get, sizeof(get) - 1);
  for (i = 0; (i = wire_find_tcp(&t, (uint16_t)i, &ip, &tcp)) >= 0; i++)
    cl.rcv_nxt += tcp.data_len;
  segment(TCPF_ACK, NULL, 0);
  ASSERT_TRUE(wire_find_tcp(&t, 0, &ip, &tcp) >= 0);
  ASSERT_TRUE(tcp.flags & TCPF_FIN);
  segment(TCPF_FIN | TCPF_ACK, NULL, 0);
  ASSERT_TRUE(next_exchange(get));
  ASSERT_TRUE(strcmp(body(), page) == 0);
}

/* REQ-HTTP-013, 028: each slot serves one connection, so two slots serve
 * two clients at once; a third finds no listener and is refused.  A
 * server without a slot, or without a port, is refused at init */
TEST(itest_http_028_a_connection_per_slot) {
  static peer_client_t a, b, c;
  static http_server_t none;
  ASSERT_EQ(http_server_init(&none, &t.net, PORT, routes, 1, slot, 0),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(http_server_init(&none, &t.net, 0, routes, 1, slot, 1),
            NET_ERR_INVALID_PARAM);
  use_slots = 2;
  up();
  use_slots = 1;
  ASSERT_TRUE(peer_connect(&t, &a, next_port++, PORT));
  ASSERT_TRUE(peer_connect(&t, &b, next_port++, PORT));
  ASSERT_TRUE(!peer_connect(&t, &c, next_port++, PORT));
  peer_send(&t, &b, "GET /q?second HTTP/1.0\r\n\r\n", 26);
  peer_send(&t, &a, "GET /q?first HTTP/1.0\r\n\r\n", 25);
  a.data[a.len] = 0;
  b.data[b.len] = 0;
  ASSERT_TRUE(strstr((const char *)a.data, "\r\n\r\nfirst") != NULL);
  ASSERT_TRUE(strstr((const char *)b.data, "\r\n\r\nsecond") != NULL);
  ASSERT_TRUE(a.fin && b.fin);
}

/* The server reset the client's connection: a RST on the wire */
static int reset_on_the_wire(void) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  int i;
  for (i = 0; (i = wire_find_tcp(&t, (uint16_t)i, &ip, &tcp)) >= 0; i++) {
    if (tcp.dport == cl.sport && (tcp.flags & TCPF_RST))
      return 1;
  }
  return 0;
}

/* REQ-HTTP-029, 065: after an error about a request too large, the server
 * goes on reading and discarding what the client still sends, its window
 * open again, so the client can finish and close (RFC 9112 §9.6) — the
 * slot then serves the next client */
TEST(itest_http_029_reads_on_after_the_response) {
  static char line[TCP_BUF];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint16_t window = 0;
  int i;
  memset(line, 'a', sizeof(line));
  memcpy(line, "GET /", 5);
  up();
  ASSERT_TRUE(peer_connect(&t, &cl, next_port++, PORT));
  segment(TCPF_PSH | TCPF_ACK, line, sizeof(line)); /* fills the RX buffer */
  for (i = 0; (i = wire_find_tcp(&t, (uint16_t)i, &ip, &tcp)) >= 0; i++)
    window = tcp.window;
  ASSERT_EQ(window, TCP_BUF);
  peer_collect(&t, &cl);
  got();
  ASSERT_TRUE(status_is(414));
  ASSERT_TRUE(cl.fin);
  peer_send(&t, &cl, line, 300); /* still sending */
  ASSERT_TRUE(!cl.rst);
  peer_close(&t, &cl);
  ASSERT_TRUE(!cl.rst);
  ASSERT_TRUE(next_exchange("GET / HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
}

/* REQ-HTTP-065: a client that resets — during the TCP handshake or in the
 * middle of its request — frees the slot for the next one */
TEST(itest_http_065_reset_frees_the_slot) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  up();
  ASSERT_TRUE(send_more("GET / HT", 8));
  segment(TCPF_RST | TCPF_ACK, NULL, 0);
  ASSERT_TRUE(next_exchange("GET / HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(200));

  memset(&cl, 0, sizeof(cl));
  cl.sport = next_port++;
  cl.dport = PORT;
  cl.snd_nxt = 7000;
  segment(TCPF_SYN, NULL, 0);
  ASSERT_TRUE(wire_find_tcp(&t, 0, &ip, &tcp) >= 0);
  ASSERT_EQ(tcp.flags, TCPF_SYN | TCPF_ACK);
  cl.rcv_nxt = tcp.seq + 1u;
  segment(TCPF_RST, NULL, 0);
  ASSERT_TRUE(next_exchange("GET / HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
}

/* REQ-HTTP-065, 058: a client that closes before its request is complete
 * gets no answer, only the close */
TEST(itest_http_065_early_close_frees_the_slot) {
  up();
  ASSERT_TRUE(send_more("GET / HTTP/1.0\r\nX-A: ", 21));
  peer_close(&t, &cl);
  ASSERT_EQ(cl.len, 0);
  ASSERT_TRUE(cl.fin);
  ASSERT_TRUE(next_exchange("GET / HTTP/1.0\r\n\r\n"));
  ASSERT_TRUE(status_is(200));
}

/* REQ-HTTP-065: a slot is held no longer than the timeouts allow — a TCP
 * handshake never completed, a request never completed, a response never
 * acknowledged: the connection is reset and the slot listens again.  A
 * listener with no client is not timed */
TEST(itest_http_065_timeouts_free_the_slot) {
  static peer_client_t other;
  static const char get[] = "GET / HTTP/1.0\r\n\r\n";
  peer_ip_t ip;
  peer_tcp_t tcp;
  up();
  http_server_tick(&srv, 3 * HTTP_REQUEST_TIMEOUT_MS);
  ASSERT_TRUE(next_exchange(get));
  ASSERT_TRUE(status_is(200));

  /* a SYN and nothing more */
  memset(&cl, 0, sizeof(cl));
  cl.sport = next_port++;
  cl.dport = PORT;
  cl.snd_nxt = 7000;
  segment(TCPF_SYN, NULL, 0);
  ASSERT_TRUE(wire_find_tcp(&t, 0, &ip, &tcp) >= 0);
  ASSERT_EQ(tcp.flags, TCPF_SYN | TCPF_ACK);
  http_server_tick(&srv, HTTP_REQUEST_TIMEOUT_MS - 1);
  ASSERT_TRUE(!peer_connect(&t, &other, next_port++, PORT)); /* still held */
  http_server_tick(&srv, 1);
  ASSERT_TRUE(next_exchange(get));
  ASSERT_TRUE(status_is(200));

  /* half a request */
  ASSERT_TRUE(send_more("GET / HT", 8));
  http_server_tick(&srv, HTTP_REQUEST_TIMEOUT_MS - 1);
  ASSERT_TRUE(!reset_on_the_wire());
  http_server_tick(&srv, 1);
  ASSERT_TRUE(reset_on_the_wire());
  ASSERT_TRUE(next_exchange(get));
  ASSERT_TRUE(status_is(200));

  /* a response the client never acknowledges */
  ASSERT_TRUE(peer_connect(&t, &cl, next_port++, PORT));
  segment(TCPF_PSH | TCPF_ACK, get, sizeof(get) - 1);
  http_server_tick(&srv, HTTP_RESPONSE_TIMEOUT_MS - 1);
  ASSERT_TRUE(!reset_on_the_wire());
  http_server_tick(&srv, 1);
  ASSERT_TRUE(reset_on_the_wire());
  ASSERT_TRUE(next_exchange(get));
  ASSERT_TRUE(status_is(200));
}

/* REQ-HTTP-065: the slot's transport is told (release()) each time the
 * slot is freed — after a response, a reset, a timeout — so that it can
 * forget the client (over TLS, wipe its secrets) */
static int releases;
static void count_release(http_conn_t *c) {
  (void)c;
  releases++;
}

TEST(itest_http_065_transport_released_with_the_slot) {
  static http_transport_t spy;
  up();
  spy = *slot[0].transport;
  spy.release = count_release;
  slot[0].transport = &spy;
  releases = 0;
  ASSERT_TRUE(next_exchange("GET / HTTP/1.0\r\n\r\n"));
  ASSERT_EQ(releases, 1);
  ASSERT_TRUE(send_more("GET / HT", 8));
  segment(TCPF_RST | TCPF_ACK, NULL, 0);
  ASSERT_EQ(releases, 2);
  ASSERT_TRUE(peer_connect(&t, &cl, next_port++, PORT));
  http_server_tick(&srv, HTTP_REQUEST_TIMEOUT_MS);
  ASSERT_EQ(releases, 3);
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
  http_conn_use_tls(&slot[0], &srv_tls);
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
  RUN_TEST(itest_http_053_expect_100_continue);
  RUN_TEST(itest_http_054_if_match);
  RUN_TEST(itest_http_055_if_none_match);
  RUN_TEST(itest_http_056_https_target_over_plain_tcp);
  RUN_TEST(itest_http_057_invalid_content_length);
  RUN_TEST(itest_http_058_incomplete_content);
  RUN_TEST(itest_http_059_field_whitespace);
  RUN_TEST(itest_http_060_folding_and_leading_whitespace);
  RUN_TEST(itest_http_061_whole_header_section_first);
  RUN_TEST(itest_http_062_parsed_as_octets);
  RUN_TEST(itest_http_063_always_http_1_0);
  RUN_TEST(itest_http_064_never_transfer_encoding);
  RUN_TEST(itest_http_001_request_line);
  RUN_TEST(itest_http_007_field_lines);
  RUN_TEST(itest_http_008_end_of_the_header_section);
  RUN_TEST(itest_http_014_handler_gets_the_request);
  RUN_TEST(itest_http_016_status_line_fields_body);
  RUN_TEST(itest_http_019_content_type);
  RUN_TEST(itest_http_022_response_of_any_length);
  RUN_TEST(itest_http_024_unimplemented_method_501);
  RUN_TEST(itest_http_025_unknown_path_404);
  RUN_TEST(itest_http_027_handler_failure_500);
  RUN_TEST(itest_http_031_closes_after_one_response);
  RUN_TEST(itest_http_033_content_bounded_by_the_request_buffer);
  RUN_TEST(itest_http_040_request_larger_than_the_buffer);
  RUN_TEST(itest_http_028_one_slot_client_after_client);
  RUN_TEST(itest_http_028_a_connection_per_slot);
  RUN_TEST(itest_http_029_reads_on_after_the_response);
  RUN_TEST(itest_http_065_reset_frees_the_slot);
  RUN_TEST(itest_http_065_early_close_frees_the_slot);
  RUN_TEST(itest_http_065_timeouts_free_the_slot);
  RUN_TEST(itest_http_065_transport_released_with_the_slot);
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
