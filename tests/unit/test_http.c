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
  ASSERT_EQ(parse("get / HTTP/1.0\r\n\r\n"), 501); /* methods are case-sensitive */
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
  ASSERT_EQ(parse("GET  / HTTP/1.0\r\n\r\n"), 400);        /* double SP */
  ASSERT_EQ(parse("GET index.html HTTP/1.0\r\n\r\n"), 400); /* not a path */
  ASSERT_EQ(parse(" GET / HTTP/1.0\r\n\r\n"), 400);         /* empty method */
  ASSERT_EQ(parse("GET / HTTP/1.0 extra\r\n\r\n"), 400);
  ASSERT_EQ(parse("G\x01T / HTTP/1.0\r\n\r\n"), 400);       /* not a token */
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

TEST(test_parse_transfer_encoding_not_implemented) {
  ASSERT_EQ(parse("POST / HTTP/1.1\r\nHost: h\r\n"
                  "Transfer-Encoding: chunked\r\n\r\n"),
            501);
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

int main(void) {
  RUN_TEST(test_header_end_crlf);
  RUN_TEST(test_header_end_bare_lf);
  RUN_TEST(test_header_end_incomplete);
  RUN_TEST(test_parse_simple_get);
  RUN_TEST(test_parse_head_and_post);
  RUN_TEST(test_parse_http11_needs_host);
  RUN_TEST(test_parse_query_split);
  RUN_TEST(test_parse_absolute_form);
  RUN_TEST(test_parse_bare_lf_lines);
  RUN_TEST(test_parse_leading_empty_lines);
  RUN_TEST(test_parse_unimplemented_methods);
  RUN_TEST(test_parse_versions);
  RUN_TEST(test_parse_malformed_request_line);
  RUN_TEST(test_parse_content_length_variants);
  RUN_TEST(test_parse_transfer_encoding_not_implemented);
  RUN_TEST(test_parse_unknown_headers_ignored);
  RUN_TEST(test_parse_malformed_headers);
  RUN_TEST(test_reason_phrases);
  RUN_TEST(test_format_header_200);
  RUN_TEST(test_format_header_405_allow);
  RUN_TEST(test_format_header_204_has_no_body_fields);
  RUN_TEST(test_format_header_large_length_and_no_fit);
  TEST_REPORT();
  return test_failures;
}
