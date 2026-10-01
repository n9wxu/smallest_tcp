/**
 * @file test_http.c
 * @brief Unit tests for the HTTP server: request parser, header formatter.
 *
 * Tests REQ-HTTP-001..012 (parsing), 016..022 (response header),
 * 024, 026, 039..041 (error statuses).
 */

#include "http.h"
#include "test_main.h"
#include <string.h>

/* ══ Parser helpers ═══════════════════════════════════════════════════ */

static char pbuf[512];
static http_request_t preq;
static uint32_t pcl;

/* Copy @p text into pbuf and parse it; returns the parse status. */
static uint16_t parse(const char *text) {
  uint16_t len = (uint16_t)strlen(text);
  memcpy(pbuf, text, len + 1);
  memset(&preq, 0xA5, sizeof(preq));
  pcl = 0xDEADBEEFu;
  uint16_t end = http_header_end(pbuf, len);
  if (end == 0)
    return 0xFFFF; /* header block incomplete */
  return http_parse_request(pbuf, end, &preq, &pcl);
}

/* ══ Header block detection (REQ-HTTP-008) ════════════════════════════ */

TEST(test_header_end_crlf) {
  const char *r = "GET / HTTP/1.0\r\nHost: x\r\n\r\nBODY";
  ASSERT_EQ(http_header_end(r, (uint16_t)strlen(r)), strlen(r) - 4);
}

TEST(test_header_end_bare_lf) {
  const char *r = "GET / HTTP/1.0\n\n";
  ASSERT_EQ(http_header_end(r, (uint16_t)strlen(r)), strlen(r));
}

TEST(test_header_end_incomplete) {
  const char *r = "GET / HTTP/1.0\r\nHost: x\r\n";
  ASSERT_EQ(http_header_end(r, (uint16_t)strlen(r)), 0);
  ASSERT_EQ(http_header_end("", 0), 0);
  ASSERT_EQ(http_header_end("GET / HTTP/1.0\r\n\r", 17), 0);
}

/* ══ Request line (REQ-HTTP-001..006) ═════════════════════════════════ */

TEST(test_parse_simple_get) {
  ASSERT_EQ(parse("GET / HTTP/1.0\r\n\r\n"), HTTP_PARSE_OK);
  ASSERT_EQ(preq.method, HTTP_GET);
  ASSERT_EQ(preq.version, 10);
  ASSERT_TRUE(strcmp(preq.path, "/") == 0);
  ASSERT_TRUE(strcmp(preq.query, "") == 0);
  ASSERT_NULL(preq.body);
  ASSERT_EQ(preq.body_len, 0);
  ASSERT_EQ(pcl, 0u);
}

TEST(test_parse_head_and_post) {
  ASSERT_EQ(parse("HEAD /x HTTP/1.0\r\n\r\n"), HTTP_PARSE_OK);
  ASSERT_EQ(preq.method, HTTP_HEAD);
  ASSERT_EQ(parse("POST /api HTTP/1.0\r\nContent-Length: 5\r\n\r\n"),
            HTTP_PARSE_OK);
  ASSERT_EQ(preq.method, HTTP_POST);
  ASSERT_EQ(pcl, 5u);
}

TEST(test_parse_http11_needs_host) {
  ASSERT_EQ(parse("GET / HTTP/1.1\r\n\r\n"), 400); /* RFC 9112 §3.2 */
  ASSERT_EQ(parse("GET / HTTP/1.1\r\nHost: pyro-dead01.local\r\n\r\n"),
            HTTP_PARSE_OK);
  ASSERT_EQ(preq.version, 11);
  ASSERT_EQ(parse("GET / HTTP/1.0\r\n\r\n"), HTTP_PARSE_OK); /* REQ-HTTP-011 */
}

/* RFC 9112 §3.2: more than one Host line is a 400 */
TEST(test_parse_duplicate_host_rejected) {
  ASSERT_EQ(parse("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"), 400);
  ASSERT_EQ(parse("GET / HTTP/1.0\r\nHost: a\r\nhost: a\r\n\r\n"), 400);
}

TEST(test_parse_query_split) {
  ASSERT_EQ(parse("GET /api/status?x=1&y=2 HTTP/1.0\r\n\r\n"), HTTP_PARSE_OK);
  ASSERT_TRUE(strcmp(preq.path, "/api/status") == 0);
  ASSERT_TRUE(strcmp(preq.query, "x=1&y=2") == 0);
  ASSERT_EQ(parse("GET /a? HTTP/1.0\r\n\r\n"), HTTP_PARSE_OK);
  ASSERT_TRUE(strcmp(preq.path, "/a") == 0);
  ASSERT_TRUE(strcmp(preq.query, "") == 0);
}

TEST(test_parse_absolute_form) {
  ASSERT_EQ(parse("GET http://pyro-dead01.local:80/cfg?a=b HTTP/1.0\r\n\r\n"),
            HTTP_PARSE_OK);
  ASSERT_TRUE(strcmp(preq.path, "/cfg") == 0);
  ASSERT_TRUE(strcmp(preq.query, "a=b") == 0);
  ASSERT_EQ(parse("GET HTTP://10.0.0.2 HTTP/1.0\r\n\r\n"), HTTP_PARSE_OK);
  ASSERT_TRUE(strcmp(preq.path, "/") == 0);
}

TEST(test_parse_bare_lf_lines) {
  ASSERT_EQ(parse("GET /lf HTTP/1.1\nHost: h\n\n"), HTTP_PARSE_OK);
  ASSERT_TRUE(strcmp(preq.path, "/lf") == 0);
}

/* RFC 9112 §2.2: ignore empty lines before the request line */
TEST(test_parse_leading_empty_lines) {
  ASSERT_EQ(parse("\r\n\r\nGET / HTTP/1.0\r\n\r\n"), HTTP_PARSE_OK);
  ASSERT_EQ(preq.method, HTTP_GET);
}

/* REQ-HTTP-024: 501 for methods the server does not implement */
TEST(test_parse_unimplemented_methods) {
  ASSERT_EQ(parse("PUT / HTTP/1.0\r\n\r\n"), 501);
  ASSERT_EQ(parse("DELETE / HTTP/1.0\r\n\r\n"), 501);
  ASSERT_EQ(parse("OPTIONS * HTTP/1.0\r\n\r\n"), 501);
  ASSERT_EQ(parse("get / HTTP/1.0\r\n\r\n"),
            501); /* methods are case-sensitive */
}

TEST(test_parse_versions) {
  ASSERT_EQ(parse("GET / HTTP/2.0\r\n\r\n"), 505);
  ASSERT_EQ(parse("GET / HTTP/0.9\r\n\r\n"), 505);
  ASSERT_EQ(parse("GET / HTTP/1.x\r\n\r\n"), 400);
  ASSERT_EQ(parse("GET / FTP/1.0\r\n\r\n"), 400);
  ASSERT_EQ(parse("GET /\r\n\r\n"), 400); /* HTTP/0.9 simple request */
}

/* REQ-HTTP-026: malformed requests → 400 */
TEST(test_parse_malformed_request_line) {
  ASSERT_EQ(parse("GET  / HTTP/1.0\r\n\r\n"), 400);         /* double SP */
  ASSERT_EQ(parse("GET index.html HTTP/1.0\r\n\r\n"), 400); /* not a path */
  ASSERT_EQ(parse(" GET / HTTP/1.0\r\n\r\n"), 400);         /* empty method */
  ASSERT_EQ(parse("GET / HTTP/1.0 extra\r\n\r\n"), 400);
  ASSERT_EQ(parse("G\x01T / HTTP/1.0\r\n\r\n"), 400); /* not a token */
}

/* ══ Headers (REQ-HTTP-007, 009, 012) ═════════════════════════════════ */

TEST(test_parse_content_length_variants) {
  ASSERT_EQ(parse("POST / HTTP/1.0\r\ncontent-LENGTH:   42  \r\n\r\n"),
            HTTP_PARSE_OK);
  ASSERT_EQ(pcl, 42u);
  ASSERT_EQ(parse("POST / HTTP/1.0\r\nContent-Length: 7\r\n"
                  "Content-Length: 7\r\n\r\n"),
            HTTP_PARSE_OK); /* identical duplicates are fine */
  ASSERT_EQ(pcl, 7u);
  ASSERT_EQ(parse("POST / HTTP/1.0\r\nContent-Length: 7\r\n"
                  "Content-Length: 8\r\n\r\n"),
            400);
  ASSERT_EQ(parse("POST / HTTP/1.0\r\nContent-Length: 12a\r\n\r\n"), 400);
  ASSERT_EQ(parse("POST / HTTP/1.0\r\nContent-Length: -1\r\n\r\n"), 400);
  ASSERT_EQ(parse("POST / HTTP/1.0\r\nContent-Length:\r\n\r\n"), 400);
  ASSERT_EQ(parse("POST / HTTP/1.0\r\nContent-Length: 99999999999\r\n\r\n"),
            400);
}

TEST(test_parse_unknown_headers_ignored) {
  ASSERT_EQ(parse("GET / HTTP/1.1\r\nHost: h\r\nUser-Agent: curl/8\r\n"
                  "Accept: */*\r\nX-Weird: a: b: c\r\n\r\n"),
            HTTP_PARSE_OK);
}

TEST(test_parse_malformed_headers) {
  ASSERT_EQ(parse("GET / HTTP/1.0\r\nNoColonHere\r\n\r\n"), 400);
  ASSERT_EQ(parse("GET / HTTP/1.0\r\nHost : x\r\n\r\n"), 400); /* §5.1 */
  ASSERT_EQ(parse("GET / HTTP/1.0\r\nX-A: 1\r\n  folded\r\n\r\n"), 400);
  ASSERT_EQ(parse("GET / HTTP/1.0\r\n: empty-name\r\n\r\n"), 400);
}

/* ══ Reason phrases + header formatting (REQ-HTTP-016..022) ═══════════ */

TEST(test_reason_phrases) {
  ASSERT_TRUE(strcmp(http_reason(200), "OK") == 0);
  ASSERT_TRUE(strcmp(http_reason(404), "Not Found") == 0);
  ASSERT_TRUE(strcmp(http_reason(405), "Method Not Allowed") == 0);
  ASSERT_TRUE(strcmp(http_reason(413), "Content Too Large") == 0);
  ASSERT_TRUE(strcmp(http_reason(414), "URI Too Long") == 0);
  ASSERT_TRUE(strcmp(http_reason(431), "Request Header Fields Too Large") == 0);
  ASSERT_TRUE(strcmp(http_reason(500), "Internal Server Error") == 0);
  ASSERT_TRUE(strcmp(http_reason(501), "Not Implemented") == 0);
  ASSERT_TRUE(strcmp(http_reason(505), "HTTP Version Not Supported") == 0);
  ASSERT_TRUE(strcmp(http_reason(299), "") == 0);
}

TEST(test_format_header_200) {
  char out[HTTP_HDR_MAX];
  const char *expect = "HTTP/1.0 200 OK\r\n"
                       "Content-Type: text/html\r\n"
                       "Content-Length: 1234\r\n"
                       "Connection: close\r\n"
                       "\r\n";
  uint16_t n = http_format_header(out, sizeof(out), 200, "text/html", 1234, 0);
  ASSERT_EQ(n, strlen(expect));
  ASSERT_MEM_EQ(out, expect, n);
}

TEST(test_format_header_405_allow) {
  char out[HTTP_HDR_MAX];
  const char *expect = "HTTP/1.0 405 Method Not Allowed\r\n"
                       "Content-Type: text/plain\r\n"
                       "Content-Length: 0\r\n"
                       "Allow: GET, HEAD\r\n"
                       "Connection: close\r\n"
                       "\r\n";
  uint16_t n = http_format_header(out, sizeof(out), 405, "text/plain", 0,
                                  HTTP_GET | HTTP_HEAD);
  ASSERT_EQ(n, strlen(expect));
  ASSERT_MEM_EQ(out, expect, n);
  n = http_format_header(out, sizeof(out), 405, "text/plain", 0, HTTP_POST);
  ASSERT_TRUE(strstr(out, "Allow: POST\r\n") != NULL);
  (void)n;
}

/* RFC 9110 §10.2.1: a 405 always has Allow, empty when nothing is */
TEST(test_format_header_405_allows_nothing) {
  char out[HTTP_HDR_MAX];
  http_format_header(out, sizeof(out), 405, "text/plain", 0, 0);
  ASSERT_TRUE(strstr(out, "\r\nAllow: \r\n") != NULL);
  http_format_header(out, sizeof(out), 404, "text/plain", 0, 0);
  ASSERT_TRUE(strstr(out, "Allow") == NULL);
}

TEST(test_format_header_204_has_no_body_fields) {
  char out[HTTP_HDR_MAX];
  const char *expect = "HTTP/1.0 204 No Content\r\n"
                       "Connection: close\r\n"
                       "\r\n";
  uint16_t n = http_format_header(out, sizeof(out), 204, "text/html", 0, 0);
  ASSERT_EQ(n, strlen(expect));
  ASSERT_MEM_EQ(out, expect, n);
}

TEST(test_format_header_large_length_and_no_fit) {
  char out[HTTP_HDR_MAX];
  uint16_t n = http_format_header(out, sizeof(out), 200, "application/json",
                                  4294967295u, 0);
  ASSERT_TRUE(n > 0);
  ASSERT_TRUE(strstr(out, "Content-Length: 4294967295\r\n") != NULL);
  ASSERT_EQ(http_format_header(out, 20, 200, "text/html", 1, 0), 0);
}

/* ══ Server: a simulated client drives the real TCP stack ═════════════ */

#include "eth.h"
#include "ipv4.h"
#include "net_endian.h"

#define MAX_FRAMES 96
static uint8_t frames[MAX_FRAMES][1514];
static uint16_t frame_lens[MAX_FRAMES];
static int n_frames;

static int stub_init(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_send(void *ctx, const uint8_t *f, uint16_t l) {
  (void)ctx;
  if (n_frames < MAX_FRAMES) {
    memcpy(frames[n_frames], f, l);
    frame_lens[n_frames] = l;
  }
  n_frames++;
  return l;
}
static int stub_poll(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_peek(void *ctx, uint16_t o, uint8_t *b, uint16_t l) {
  (void)ctx;
  (void)o;
  (void)b;
  (void)l;
  return -1;
}
static void stub_discard(void *ctx) { (void)ctx; }
static void stub_close(void *ctx) { (void)ctx; }
static const net_mac_t stub_mac = {
    .init = stub_init,
    .send = stub_send,
    .poll = stub_poll,
    .peek = stub_peek,
    .discard = stub_discard,
    .close = stub_close,
};

#define SRV_PORT 80u
#define CLIENT_IP 0x0A000064u /* 10.0.0.100 */
#define REQ_SIZE 256u
#define N_SLOTS 2

static uint8_t net_rx[1514], net_tx[1514];
static net_t net;
static uint8_t tx_mem[N_SLOTS][600], rx_mem[N_SLOTS][600];
static char req_mem[N_SLOTS][REQ_SIZE];
static http_conn_t conns[N_SLOTS];
static tcp_conn_t *conn_table[N_SLOTS];
static http_server_t srv;
static const uint8_t client_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01};
static const uint8_t server_mac[6] = NET_DEFAULT_MAC;

/* ── Routes ── */

static const char root_page[] = "<h1>hi</h1>";
static uint8_t big_page[3000];

static int page_root(const http_request_t *rq, http_response_t *rs, void *c) {
  (void)rq;
  (void)c;
  rs->body = (const uint8_t *)root_page;
  rs->body_len = sizeof(root_page) - 1;
  return 0;
}
static int page_big(const http_request_t *rq, http_response_t *rs, void *c) {
  (void)rq;
  (void)c;
  rs->content_type = "application/octet-stream";
  rs->body = big_page;
  rs->body_len = sizeof(big_page);
  return 0;
}
static int page_echo(const http_request_t *rq, http_response_t *rs, void *c) {
  (void)c;
  rs->content_type = "text/plain";
  rs->body = rq->body;
  rs->body_len = rq->body_len;
  return 0;
}
static int page_gen(const http_request_t *rq, http_response_t *rs, void *c) {
  (void)c;
  size_t n = (size_t)(strlen(rq->path) + strlen(rq->query) + 13);
  if (n > rs->scratch_size)
    return -1;
  strcpy((char *)rs->scratch, "path=");
  strcat((char *)rs->scratch, rq->path);
  strcat((char *)rs->scratch, " query=");
  strcat((char *)rs->scratch, rq->query);
  rs->content_type = "text/plain";
  rs->body = rs->scratch;
  rs->body_len = (uint32_t)strlen((char *)rs->scratch);
  return 0;
}
static int page_fail(const http_request_t *rq, http_response_t *rs, void *c) {
  (void)rq;
  (void)rs;
  (void)c;
  return -1;
}

static const http_route_t routes[] = {
    {"/", HTTP_GET, page_root, NULL},      {"/big", HTTP_GET, page_big, NULL},
    {"/echo", HTTP_POST, page_echo, NULL}, {"/gen", HTTP_GET, page_gen, NULL},
    {"/fail", HTTP_GET, page_fail, NULL},
};

static void server_setup(void) {
  static int ctx;
  int i;
  for (i = 0; i < (int)sizeof(big_page); i++)
    big_page[i] = (uint8_t)('A' + i % 26);
  net_init(&net, net_rx, sizeof(net_rx), net_tx, sizeof(net_tx), NULL,
           &stub_mac, &ctx);
  for (i = 0; i < N_SLOTS; i++) {
    http_conn_init(&conns[i], tx_mem[i], sizeof(tx_mem[i]), rx_mem[i],
                   sizeof(rx_mem[i]), req_mem[i], REQ_SIZE);
    conn_table[i] = http_conn_tcp(&conns[i]);
  }
  tcp_set_connections(&net, conn_table, N_SLOTS);
  http_server_init(&srv, &net, SRV_PORT, routes,
                   sizeof(routes) / sizeof(routes[0]), conns, N_SLOTS);
  n_frames = 0;
}

/* ── Simulated client ── */

typedef struct {
  uint16_t port;
  uint32_t seq; /* next sequence number we send */
  uint32_t ack; /* next sequence number we expect from the server */
  uint8_t fin, rst;
  int scan; /* next captured frame to look at */
  uint8_t resp[4096];
  uint16_t resp_len;
  int data_segs;
  uint16_t first_seg_len;
} client_t;

static void inject_tcp(client_t *c, uint8_t flags, const void *data,
                       uint16_t len, uint16_t mss) {
  uint8_t frame[1514];
  uint8_t *ip = frame + ETH_HDR_SIZE;
  uint8_t *tcp = ip + IPV4_HDR_SIZE;
  uint16_t hlen = mss ? 24 : 20;
  memcpy(frame, server_mac, 6);
  memcpy(frame + 6, client_mac, 6);
  net_write16be(frame + 12, NET_ETHERTYPE_IPV4);
  memset(tcp, 0, hlen);
  net_write16be(tcp + TCP_OFF_SPORT, c->port);
  net_write16be(tcp + TCP_OFF_DPORT, SRV_PORT);
  net_write32be(tcp + TCP_OFF_SEQ, c->seq);
  net_write32be(tcp + TCP_OFF_ACK, (flags & TCP_FLAG_ACK) ? c->ack : 0);
  tcp[TCP_OFF_DOFF] = (uint8_t)((hlen / 4) << 4);
  tcp[TCP_OFF_FLAGS] = flags;
  net_write16be(tcp + TCP_OFF_WINDOW, 8192);
  if (mss) {
    tcp[TCP_OFF_OPT] = TCP_OPT_MSS;
    tcp[TCP_OFF_OPT + 1] = 4;
    net_write16be(tcp + TCP_OFF_OPT + 2, mss);
  }
  if (len)
    memcpy(tcp + hlen, data, len);
  net_write16be(tcp + TCP_OFF_CKSUM,
                ipv4_cksum(CLIENT_IP, net.ipv4_addr, IPV4_PROTO_TCP, tcp,
                           (uint16_t)(hlen + len)));
  ipv4_build(ip, (uint16_t)(hlen + len), IPV4_PROTO_TCP, CLIENT_IP,
             net.ipv4_addr);
  eth_input(&net, frame, (uint16_t)(ETH_HDR_SIZE + IPV4_HDR_SIZE + hlen + len));
  c->seq += len + ((flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)) ? 1u : 0u);
}

/* Consume new server segments for this client; returns 1 on progress */
static int client_scan(client_t *c) {
  int progress = 0;
  for (; c->scan < n_frames && c->scan < MAX_FRAMES; c->scan++) {
    const uint8_t *f = frames[c->scan];
    const uint8_t *tcp = f + ETH_HDR_SIZE + IPV4_HDR_SIZE;
    if (net_read16be(f + 12) != NET_ETHERTYPE_IPV4 ||
        f[ETH_HDR_SIZE + IPV4_OFF_PROTO] != IPV4_PROTO_TCP ||
        net_read16be(tcp + TCP_OFF_DPORT) != c->port)
      continue;
    uint8_t flags = tcp[TCP_OFF_FLAGS];
    uint32_t seq = net_read32be(tcp + TCP_OFF_SEQ);
    uint16_t hlen = (uint16_t)((tcp[TCP_OFF_DOFF] >> 4) * 4);
    uint16_t plen =
        (uint16_t)(net_read16be(f + ETH_HDR_SIZE + IPV4_OFF_TOTLEN) -
                   IPV4_HDR_SIZE - hlen);
    if (flags & TCP_FLAG_RST)
      c->rst = 1;
    if (flags & TCP_FLAG_SYN) {
      c->ack = seq + 1;
      progress = 1;
      continue;
    }
    if (plen > 0 && seq == c->ack) {
      if (c->data_segs == 0)
        c->first_seg_len = plen;
      if ((uint32_t)c->resp_len + plen <= sizeof(c->resp)) {
        memcpy(c->resp + c->resp_len, tcp + hlen, plen);
        c->resp_len = (uint16_t)(c->resp_len + plen);
      }
      c->ack += plen;
      c->data_segs++;
      progress = 1;
    }
    if ((flags & TCP_FLAG_FIN) && seq + plen == c->ack) {
      c->ack += 1;
      c->fin = 1;
      progress = 1;
    }
  }
  return progress;
}

static void client_connect(client_t *c, uint16_t port, uint16_t mss) {
  memset(c, 0, sizeof(*c));
  c->port = port;
  c->seq = 1000u * port;
  c->scan = n_frames;
  inject_tcp(c, TCP_FLAG_SYN, NULL, 0, mss);
  client_scan(c); /* SYN-ACK */
  inject_tcp(c, TCP_FLAG_ACK, NULL, 0, 0);
  http_server_poll(&srv);
}

static void client_send(client_t *c, const char *data, uint8_t extra_flags) {
  inject_tcp(c, (uint8_t)(TCP_FLAG_ACK | TCP_FLAG_PSH | extra_flags), data,
             (uint16_t)strlen(data), 0);
  http_server_poll(&srv);
}

/* Poll the server and ACK everything it sends until it goes quiet */
static void client_pump(client_t *c) {
  int rounds;
  for (rounds = 0; rounds < 200; rounds++) {
    http_server_poll(&srv);
    if (!client_scan(c))
      break;
    inject_tcp(c, TCP_FLAG_ACK, NULL, 0, 0);
  }
  http_server_poll(&srv);
}

/* Full exchange: connect, send, collect the response, close our side */
static void exchange(client_t *c, uint16_t port, const char *request) {
  client_connect(c, port, 1460);
  client_send(c, request, 0);
  client_pump(c);
  if (c->fin) {
    inject_tcp(c, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0, 0);
    http_server_poll(&srv);
  }
  c->resp[c->resp_len < sizeof(c->resp) ? c->resp_len : sizeof(c->resp) - 1] =
      0;
}

static const char *resp_body(const client_t *c) {
  const char *e = strstr((const char *)c->resp, "\r\n\r\n");
  return e ? e + 4 : "";
}

static client_t cl, cl2;

/* ── GET / HEAD / POST (REQ-HTTP-002..004, 013..023) ── */

TEST(test_server_get_root) {
  server_setup();
  exchange(&cl, 40001, "GET / HTTP/1.0\r\n\r\n");
  ASSERT_TRUE(strncmp((char *)cl.resp, "HTTP/1.0 200 OK\r\n", 17) == 0);
  ASSERT_TRUE(strstr((char *)cl.resp, "Content-Type: text/html\r\n") != NULL);
  ASSERT_TRUE(strstr((char *)cl.resp, "Content-Length: 11\r\n") != NULL);
  ASSERT_TRUE(strstr((char *)cl.resp, "Connection: close\r\n") != NULL);
  ASSERT_TRUE(strcmp(resp_body(&cl), root_page) == 0);
  ASSERT_EQ(cl.fin, 1); /* REQ-HTTP-029: server closes */
  ASSERT_EQ(cl.rst, 0);
}

/* Header and body leave in the same segment (tcp_write + tcp_output) */
TEST(test_server_small_response_is_one_segment) {
  server_setup();
  exchange(&cl, 40002, "GET / HTTP/1.0\r\n\r\n");
  ASSERT_EQ(cl.data_segs, 1);
  ASSERT_EQ(cl.first_seg_len, cl.resp_len);
}

TEST(test_server_head_has_no_body) {
  server_setup();
  exchange(&cl, 40003, "HEAD / HTTP/1.0\r\n\r\n");
  ASSERT_TRUE(strncmp((char *)cl.resp, "HTTP/1.0 200 OK\r\n", 17) == 0);
  ASSERT_TRUE(strstr((char *)cl.resp, "Content-Length: 11\r\n") != NULL);
  ASSERT_EQ(strlen(resp_body(&cl)), 0u);
}

TEST(test_server_post_echo) {
  server_setup();
  exchange(&cl, 40004, "POST /echo HTTP/1.0\r\nContent-Length: 5\r\n\r\nhello");
  ASSERT_TRUE(strncmp((char *)cl.resp, "HTTP/1.0 200 OK\r\n", 17) == 0);
  ASSERT_TRUE(strstr((char *)cl.resp, "Content-Type: text/plain\r\n") != NULL);
  ASSERT_TRUE(strcmp(resp_body(&cl), "hello") == 0);
}

/* Body in a later segment than the headers (REQ-HTTP-032) */
TEST(test_server_post_body_arrives_later) {
  server_setup();
  client_connect(&cl, 40005, 1460);
  client_send(&cl,
              "POST /echo HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\n\r\n", 0);
  client_pump(&cl);
  ASSERT_EQ(cl.resp_len, 0); /* still waiting for the body */
  client_send(&cl, "wor", 0);
  client_pump(&cl);
  ASSERT_EQ(cl.resp_len, 0);
  client_send(&cl, "ld!", 0);
  client_pump(&cl);
  cl.resp[cl.resp_len] = 0;
  ASSERT_TRUE(strcmp(resp_body(&cl), "world!") == 0);
}

TEST(test_server_request_in_pieces) {
  server_setup();
  client_connect(&cl, 40006, 1460);
  client_send(&cl, "GET / HT", 0);
  client_send(&cl, "TP/1.0\r\n\r", 0);
  client_pump(&cl);
  ASSERT_EQ(cl.resp_len, 0);
  client_send(&cl, "\n", 0);
  client_pump(&cl);
  cl.resp[cl.resp_len] = 0;
  ASSERT_TRUE(strcmp(resp_body(&cl), root_page) == 0);
}

/* Response far larger than the 600-byte TX buffer, small peer MSS */
TEST(test_server_large_response_streams) {
  server_setup();
  client_connect(&cl, 40007, 536);
  client_send(&cl, "GET /big HTTP/1.0\r\n\r\n", 0);
  client_pump(&cl);
  ASSERT_TRUE(strstr((char *)cl.resp, "Content-Length: 3000\r\n") != NULL);
  const char *e = strstr((char *)cl.resp, "\r\n\r\n");
  ASSERT_NOT_NULL(e);
  uint16_t hdr = (uint16_t)(e + 4 - (char *)cl.resp);
  ASSERT_EQ(cl.resp_len, hdr + sizeof(big_page));
  ASSERT_MEM_EQ(cl.resp + hdr, big_page, sizeof(big_page));
  ASSERT_TRUE(cl.data_segs >= 6);
  ASSERT_EQ(cl.fin, 1);
}

TEST(test_server_generated_body_and_query) {
  server_setup();
  exchange(&cl, 40008, "GET /gen?x=1 HTTP/1.0\r\n\r\n");
  ASSERT_TRUE(strcmp(resp_body(&cl), "path=/gen query=x=1") == 0);
}

/* ── Error statuses (REQ-HTTP-017, 024..027, 034, 039..041) ── */

TEST(test_server_404) {
  server_setup();
  exchange(&cl, 40009, "GET /nope HTTP/1.0\r\n\r\n");
  ASSERT_TRUE(strncmp((char *)cl.resp, "HTTP/1.0 404 Not Found\r\n", 24) == 0);
  ASSERT_EQ(cl.fin, 1);
}

TEST(test_server_405_lists_allowed) {
  server_setup();
  exchange(&cl, 40010, "POST / HTTP/1.0\r\nContent-Length: 0\r\n\r\n");
  ASSERT_TRUE(strncmp((char *)cl.resp, "HTTP/1.0 405 ", 13) == 0);
  ASSERT_TRUE(strstr((char *)cl.resp, "Allow: GET, HEAD\r\n") != NULL);
  server_setup();
  exchange(&cl, 40011, "GET /echo HTTP/1.0\r\n\r\n");
  ASSERT_TRUE(strstr((char *)cl.resp, "Allow: POST\r\n") != NULL);
}

TEST(test_server_501_and_400) {
  server_setup();
  exchange(&cl, 40012, "PUT / HTTP/1.0\r\n\r\n");
  ASSERT_TRUE(strncmp((char *)cl.resp, "HTTP/1.0 501 ", 13) == 0);
  server_setup();
  exchange(&cl, 40013, "GET / HTTP/1.1\r\n\r\n"); /* no Host */
  ASSERT_TRUE(strncmp((char *)cl.resp, "HTTP/1.0 400 ", 13) == 0);
}

TEST(test_server_handler_failure_is_500) {
  server_setup();
  exchange(&cl, 40014, "GET /fail HTTP/1.0\r\n\r\n");
  ASSERT_TRUE(strncmp((char *)cl.resp, "HTTP/1.0 500 ", 13) == 0);
}

TEST(test_server_413_body_too_large) {
  server_setup();
  exchange(&cl, 40015,
           "POST /echo HTTP/1.0\r\nContent-Length: 10000\r\n\r\nxx");
  ASSERT_TRUE(strncmp((char *)cl.resp, "HTTP/1.0 413 ", 13) == 0);
}

TEST(test_server_414_uri_too_long) {
  char line[REQ_SIZE + 32];
  server_setup();
  memset(line, 'a', sizeof(line));
  memcpy(line, "GET /", 5);
  line[sizeof(line) - 1] = '\0'; /* never reaches the end of the line */
  exchange(&cl, 40016, line);
  ASSERT_TRUE(strncmp((char *)cl.resp, "HTTP/1.0 414 ", 13) == 0);
}

TEST(test_server_431_headers_too_large) {
  char req[REQ_SIZE + 64];
  server_setup();
  strcpy(req, "GET / HTTP/1.0\r\nX-Pad: ");
  size_t base = strlen(req);
  memset(req + base, 'p', sizeof(req) - base - 1); /* header never ends */
  req[sizeof(req) - 1] = '\0';
  exchange(&cl, 40017, req);
  ASSERT_TRUE(strncmp((char *)cl.resp, "HTTP/1.0 431 ", 13) == 0);
}

/* ── Connection lifecycle (REQ-HTTP-028, 029) ── */

/* Recycled straight to LISTEN — no 240 s TIME_WAIT lock-out */
TEST(test_server_slot_recycled_after_close) {
  int i;
  server_setup();
  for (i = 0; i < 5; i++) {
    exchange(&cl, (uint16_t)(40100 + i), "GET / HTTP/1.0\r\n\r\n");
    ASSERT_TRUE(strcmp(resp_body(&cl), root_page) == 0);
    ASSERT_EQ(conns[0].tcp.state, TCP_LISTEN);
    ASSERT_EQ(conns[1].tcp.state, TCP_LISTEN);
  }
}

TEST(test_server_two_concurrent_connections) {
  server_setup();
  client_connect(&cl, 40201, 1460);
  client_connect(&cl2, 40202, 1460);
  ASSERT_EQ(conns[0].tcp.state, TCP_ESTABLISHED);
  ASSERT_EQ(conns[1].tcp.state, TCP_ESTABLISHED);
  client_send(&cl2, "GET /gen?b HTTP/1.0\r\n\r\n", 0);
  client_send(&cl, "GET /gen?a HTTP/1.0\r\n\r\n", 0);
  client_pump(&cl);
  client_pump(&cl2);
  cl.resp[cl.resp_len] = 0;
  cl2.resp[cl2.resp_len] = 0;
  ASSERT_TRUE(strcmp(resp_body(&cl), "path=/gen query=a") == 0);
  ASSERT_TRUE(strcmp(resp_body(&cl2), "path=/gen query=b") == 0);
}

/* A client that sends the request and its FIN together still gets served */
TEST(test_server_request_with_half_close) {
  server_setup();
  client_connect(&cl, 40301, 1460);
  client_send(&cl, "GET / HTTP/1.0\r\n\r\n", TCP_FLAG_FIN);
  client_pump(&cl);
  cl.resp[cl.resp_len] = 0;
  ASSERT_TRUE(strcmp(resp_body(&cl), root_page) == 0);
  ASSERT_EQ(cl.fin, 1);
  ASSERT_EQ(conns[0].tcp.state, TCP_LISTEN); /* LAST_ACK → CLOSED → LISTEN */
}

/* Both sides close at once (curl closes as soon as it has the body):
 * TCP lands in CLOSING; the slot must not wait there for a retransmit. */
TEST(test_server_simultaneous_close_recycles) {
  server_setup();
  client_connect(&cl, 40601, 1460);
  client_send(&cl, "GET / HTTP/1.0\r\n\r\n", 0);
  client_scan(&cl);                          /* the response */
  inject_tcp(&cl, TCP_FLAG_ACK, NULL, 0, 0); /* ACK the data only */
  http_server_poll(&srv);                    /* server sends its FIN */
  ASSERT_EQ(conns[0].tcp.state, TCP_FIN_WAIT_1);
  inject_tcp(&cl, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0, 0); /* crosses it */
  ASSERT_EQ(conns[0].tcp.state, TCP_CLOSING);
  http_server_poll(&srv);
  ASSERT_EQ(conns[0].tcp.state, TCP_LISTEN);
}

/* Window the server last advertised to this client */
static uint16_t last_window_to(const client_t *c) {
  uint16_t wnd = 0;
  int i;
  for (i = 0; i < n_frames && i < MAX_FRAMES; i++) {
    const uint8_t *tcp = frames[i] + ETH_HDR_SIZE + IPV4_HDR_SIZE;
    if (frames[i][ETH_HDR_SIZE + IPV4_OFF_PROTO] == IPV4_PROTO_TCP &&
        net_read16be(tcp + TCP_OFF_DPORT) == c->port)
      wnd = net_read16be(tcp + TCP_OFF_WINDOW);
  }
  return wnd;
}

/* After answering an oversized request the server keeps reading and
 * discarding (lingering close, RFC 9112 §9.6) and re-opens its window,
 * so the client can finish sending and close instead of stalling on a
 * zero window until the slot times out. */
TEST(test_server_drains_after_error_response) {
  char big[600];
  server_setup();
  memset(big, 'a', sizeof(big));
  memcpy(big, "GET /", 5);
  big[sizeof(big) - 1] = '\0'; /* 599 bytes: fills the 600-byte RX buffer */
  client_connect(&cl, 40701, 1460);
  client_send(&cl, big, 0);
  client_pump(&cl);
  ASSERT_TRUE(strncmp((char *)cl.resp, "HTTP/1.0 414 ", 13) == 0);
  ASSERT_EQ(conns[0].rx_ctx.data_len, 0); /* rest of the request discarded */
  ASSERT_EQ(last_window_to(&cl), sizeof(rx_mem[0]));
}

TEST(test_server_idle_client_times_out) {
  server_setup();
  client_connect(&cl, 40401, 1460);
  client_send(&cl, "GET / HT", 0);
  http_server_tick(&srv, HTTP_REQUEST_TIMEOUT_MS - 1);
  http_server_poll(&srv);
  client_scan(&cl);
  ASSERT_EQ(cl.rst, 0);
  http_server_tick(&srv, 1);
  http_server_poll(&srv);
  client_scan(&cl);
  ASSERT_EQ(cl.rst, 1);
  ASSERT_EQ(conns[0].tcp.state, TCP_LISTEN);
}

TEST(test_server_rst_mid_request_recycles) {
  server_setup();
  client_connect(&cl, 40501, 1460);
  client_send(&cl, "GET / HT", 0);
  inject_tcp(&cl, TCP_FLAG_RST | TCP_FLAG_ACK, NULL, 0, 0);
  http_server_poll(&srv);
  ASSERT_EQ(conns[0].tcp.state, TCP_LISTEN);
  exchange(&cl2, 40502, "GET / HTTP/1.0\r\n\r\n"); /* slot usable again */
  ASSERT_TRUE(strcmp(resp_body(&cl2), root_page) == 0);
}

/* The transport forgets each client when its slot listens again — after a
 * response, a reset or a timeout alike (HTTPS wipes the TLS secrets) */
static int releases;
static void count_release(http_conn_t *c) {
  (void)c;
  releases++;
}

TEST(test_server_transport_released_when_client_gone) {
  static http_transport_t spy;
  server_setup();
  spy = *conns[0].transport;
  spy.release = count_release;
  conns[0].transport = &spy;
  releases = 0;
  exchange(&cl, 40801, "GET / HTTP/1.0\r\n\r\n");
  ASSERT_EQ(conns[0].tcp.state, TCP_LISTEN);
  ASSERT_EQ(releases, 1);
  client_connect(&cl, 40802, 1460);
  inject_tcp(&cl, TCP_FLAG_RST | TCP_FLAG_ACK, NULL, 0, 0);
  http_server_poll(&srv);
  ASSERT_EQ(releases, 2);
  client_connect(&cl, 40803, 1460);
  http_server_tick(&srv, HTTP_REQUEST_TIMEOUT_MS);
  ASSERT_EQ(conns[0].tcp.state, TCP_LISTEN);
  ASSERT_EQ(releases, 3);
}

TEST(test_server_init_validates) {
  static http_server_t s2;
  static http_conn_t c2;
  static uint8_t t[600], r[600];
  static char q[8];
  ASSERT_EQ(http_conn_init(&c2, t, sizeof(t), r, sizeof(r), q, sizeof(q)),
            NET_ERR_INVALID_PARAM); /* request buffer too small */
  ASSERT_EQ(http_server_init(&s2, &net, 80, routes, 1, conns, 0),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(http_server_init(&s2, &net, 0, routes, 1, conns, 1),
            NET_ERR_INVALID_PARAM);
}

int main(void) {
  RUN_TEST(test_header_end_crlf);
  RUN_TEST(test_header_end_bare_lf);
  RUN_TEST(test_header_end_incomplete);
  RUN_TEST(test_parse_simple_get);
  RUN_TEST(test_parse_head_and_post);
  RUN_TEST(test_parse_http11_needs_host);
  RUN_TEST(test_parse_duplicate_host_rejected);
  RUN_TEST(test_parse_query_split);
  RUN_TEST(test_parse_absolute_form);
  RUN_TEST(test_parse_bare_lf_lines);
  RUN_TEST(test_parse_leading_empty_lines);
  RUN_TEST(test_parse_unimplemented_methods);
  RUN_TEST(test_parse_versions);
  RUN_TEST(test_parse_malformed_request_line);
  RUN_TEST(test_parse_content_length_variants);
  RUN_TEST(test_parse_unknown_headers_ignored);
  RUN_TEST(test_parse_malformed_headers);
  RUN_TEST(test_reason_phrases);
  RUN_TEST(test_format_header_200);
  RUN_TEST(test_format_header_405_allow);
  RUN_TEST(test_format_header_204_has_no_body_fields);
  RUN_TEST(test_format_header_405_allows_nothing);
  RUN_TEST(test_format_header_large_length_and_no_fit);
  RUN_TEST(test_server_get_root);
  RUN_TEST(test_server_small_response_is_one_segment);
  RUN_TEST(test_server_head_has_no_body);
  RUN_TEST(test_server_post_echo);
  RUN_TEST(test_server_post_body_arrives_later);
  RUN_TEST(test_server_request_in_pieces);
  RUN_TEST(test_server_large_response_streams);
  RUN_TEST(test_server_generated_body_and_query);
  RUN_TEST(test_server_404);
  RUN_TEST(test_server_405_lists_allowed);
  RUN_TEST(test_server_501_and_400);
  RUN_TEST(test_server_handler_failure_is_500);
  RUN_TEST(test_server_413_body_too_large);
  RUN_TEST(test_server_414_uri_too_long);
  RUN_TEST(test_server_431_headers_too_large);
  RUN_TEST(test_server_slot_recycled_after_close);
  RUN_TEST(test_server_two_concurrent_connections);
  RUN_TEST(test_server_request_with_half_close);
  RUN_TEST(test_server_simultaneous_close_recycles);
  RUN_TEST(test_server_drains_after_error_response);
  RUN_TEST(test_server_idle_client_times_out);
  RUN_TEST(test_server_rst_mid_request_recycles);
  RUN_TEST(test_server_transport_released_when_client_gone);
  RUN_TEST(test_server_init_validates);
  TEST_REPORT();
  return test_failures;
}
