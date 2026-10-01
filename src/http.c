/**
 * @file http.c
 * @brief Minimal HTTP/1.0 server (RFC 9110 semantics, RFC 9112 syntax).
 *
 * Implements REQ-HTTP-001..064, but for 042, 043 (chunked coding, MAY).
 * See docs/design/http.md.
 */

#include "http.h"
#include "net_text.h"
#include <string.h>

/* RFC 9110 §5.6.2 token characters */
static int is_tchar(char c) {
  if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
      (c >= '0' && c <= '9'))
    return 1;
  return c != '\0' && strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

static int is_ows(char c) { return c == ' ' || c == '\t'; }

/* REQ-HTTP-044: a bare CR (RFC 9112 §2.2) or a NUL (RFC 9110 §5.5) in
 * s[0..len) — a CR before the line's LF is already gone */
static int has_cr_or_nul(const char *s, uint16_t len) {
  uint16_t i;
  for (i = 0; i < len; i++) {
    if (s[i] == '\r' || s[i] == '\0')
      return 1;
  }
  return 0;
}

/* RFC 9112 §3.2: no whitespace or other control octet in a request target
 * (a bare CR and a NUL among them, REQ-HTTP-044) */
static int target_valid(const char *t, uint16_t len) {
  uint16_t i;
  for (i = 0; i < len; i++) {
    if ((uint8_t)t[i] <= ' ' || t[i] == 0x7F)
      return 0;
  }
  return 1;
}

static int is_digit(char c) { return c >= '0' && c <= '9'; }

static int is_alpha(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int is_hex(char c) {
  return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/* RFC 3986 §2.2, §2.3: unreserved and sub-delims, what a host is made of
 * besides percent-encoded octets (and ':' in an IP-literal) */
static int is_host_char(char c) {
  if (is_alpha(c) || is_digit(c))
    return 1;
  return c != '\0' && strchr("-._~!$&'()*+,;=", c) != NULL;
}

/* RFC 9110 §7.2, RFC 3986 §3.2.2, §3.2.3: a[0..len) is uri-host
 * [ ":" port ] — an IP-literal in brackets or a reg-name (which an IPv4
 * address also is), possibly empty.  *host_len: the host's length. */
static int authority_valid(const char *a, uint16_t len, uint16_t *host_len) {
  uint16_t i = 0;
  if (len > 0 && a[0] == '[') {
    for (i = 1; i < len && a[i] != ']'; i++) {
      if (!is_host_char(a[i]) && a[i] != ':')
        return 0;
    }
    if (i >= len || i == 1)
      return 0;
    i++;
  } else {
    for (; i < len && a[i] != ':'; i++) {
      if (a[i] == '%' && (uint32_t)i + 2 < len && is_hex(a[i + 1]) &&
          is_hex(a[i + 2]))
        i = (uint16_t)(i + 2);
      else if (!is_host_char(a[i]))
        return 0;
    }
  }
  *host_len = i;
  if (i < len && a[i++] != ':')
    return 0;
  for (; i < len; i++) {
    if (!is_digit(a[i]))
      return 0;
  }
  return 1;
}

/* Case-insensitive: a[0..alen) equals the string b */
static int eq_ci(const char *a, uint16_t alen, const char *b) {
  uint16_t i;
  for (i = 0; i < alen; i++) {
    if (b[i] == '\0' || net_tolower(a[i]) != net_tolower(b[i]))
      return 0;
  }
  return b[alen] == '\0';
}

/* ── Header block detection ── */

uint16_t http_header_end(const char *buf, uint16_t len) {
  uint16_t i = 0;
  /* RFC 9112 §2.2: empty lines before the request line are ignored */
  while (i < len && (buf[i] == '\r' || buf[i] == '\n'))
    i++;
  for (; i < len; i++) {
    if (buf[i] != '\n')
      continue;
    if ((uint32_t)i + 1 < len && buf[i + 1] == '\n')
      return (uint16_t)(i + 2);
    if ((uint32_t)i + 2 < len && buf[i + 1] == '\r' && buf[i + 2] == '\n')
      return (uint16_t)(i + 3);
  }
  return 0;
}

/* ── Request parsing ── */

/* Return the next line (NUL-terminated in place, CR/LF stripped) and
 * advance *pos past it.  Lines end at LF; a CR before the LF is dropped. */
static char *next_line(char *buf, uint16_t *pos, uint16_t end, uint16_t *len) {
  char *line = buf + *pos;
  uint16_t i = *pos;
  while (i < end && buf[i] != '\n')
    i++;
  uint16_t stop = i;
  if (stop > *pos && buf[stop - 1] == '\r')
    stop--;
  *len = (uint16_t)(stop - *pos);
  if (stop < end)
    buf[stop] = '\0'; /* never past the header block */
  *pos = (uint16_t)(i < end ? i + 1 : end);
  return line;
}

/* "HTTP/d.d" → 10 or 11; 505 for other versions; 400 if malformed */
static uint16_t parse_version(const char *v, uint16_t len, uint8_t *out) {
  if (len != 8 || memcmp(v, "HTTP/", 5) != 0 || v[6] != '.' || v[5] < '0' ||
      v[5] > '9' || v[7] < '0' || v[7] > '9')
    return 400;
  if (v[5] == '1' && (v[7] == '0' || v[7] == '1')) {
    *out = (uint8_t)(v[7] == '0' ? 10 : 11);
    return HTTP_PARSE_OK;
  }
  return 505;
}

/* Content-Length: 1-10 digits, <= 0xFFFFFFFF */
static int parse_content_length(const char *v, uint16_t len, uint32_t *out) {
  uint32_t n = 0;
  uint16_t i;
  if (len == 0 || len > 10)
    return -1;
  for (i = 0; i < len; i++) {
    uint32_t d;
    if (!is_digit(v[i]))
      return -1;
    d = (uint32_t)(v[i] - '0');
    if (n > 429496729u || (n == 429496729u && d > 5u)) /* > 0xFFFFFFFF */
      return -1;
    n = n * 10u + d;
  }
  *out = n;
  return 0;
}

/* RFC 3986 §3.1: t[0..len) begins with a scheme and its ':' */
static int has_scheme(const char *t, uint16_t len) {
  uint16_t i = 1;
  if (len == 0 || !is_alpha(t[0]))
    return 0;
  while (i < len && (is_alpha(t[i]) || is_digit(t[i]) || t[i] == '+' ||
                     t[i] == '-' || t[i] == '.'))
    i++;
  return i < len && t[i] == ':';
}

/* REQ-HTTP-047: a target in absolute-form (RFC 9112 §3.2.2).  An http or
 * https URI's authority names the host — one with an empty host is
 * invalid (RFC 9110 §4.2.1, §4.2.2) — and *rest is left at its path and
 * query; any other scheme names an origin this server does not serve. */
static uint16_t absolute_form(char *t, uint16_t len, char **rest,
                              http_request_t *req) {
  uint16_t s, end;
  if (len >= 7 && eq_ci(t, 7, "http://")) {
    s = 7;
  } else if (len >= 8 && eq_ci(t, 8, "https://")) {
    s = 8;
    req->flags |= HTTP_RQ_HTTPS;
  } else {
    return has_scheme(t, len) ? 421 : 400;
  }
  for (end = s; end < len && t[end] != '/' && t[end] != '?'; end++)
    ;
  if (!authority_valid(t + s, (uint16_t)(end - s), &req->host_len) ||
      req->host_len == 0)
    return 400;
  req->host = t + s;
  *rest = t + end;
  return HTTP_PARSE_OK;
}

/* Transfer-Encoding's last coding (RFC 9112 §6.1): 1 if it is chunked */
static int ends_in_chunked(const char *v, uint16_t len) {
  uint16_t start;
  while (len > 0 && (is_ows(v[len - 1]) || v[len - 1] == ','))
    len--; /* empty list elements */
  for (start = len; start > 0 && v[start - 1] != ','; start--)
    ;
  while (start < len && is_ows(v[start]))
    start++;
  return eq_ci(v + start, (uint16_t)(len - start), "chunked");
}

uint16_t http_parse_request(char *buf, uint16_t hdr_len, http_request_t *req,
                            uint32_t *content_length) {
  uint16_t pos = 0, len, i;
  uint16_t sp1 = 0, sp2 = 0, status;
  uint8_t version = 0, method = 0;
  uint32_t cl = 0;
  int cl_seen = 0, host_seen = 0, te = 0; /* te: 1 chunked last, 2 not */
  char *line;

  while (pos < hdr_len && (buf[pos] == '\r' || buf[pos] == '\n'))
    pos++;

  /* ── Request line: method SP request-target SP HTTP-version ── */
  line = next_line(buf, &pos, hdr_len, &len);
  for (i = 0; i < len && line[i] != ' '; i++) {
    if (!is_tchar(line[i]))
      return 400;
  }
  sp1 = i;
  if (sp1 == 0 || sp1 >= len)
    return 400;
  for (i = (uint16_t)(sp1 + 1); i < len && line[i] != ' '; i++)
    ;
  sp2 = i;
  if (sp2 == sp1 + 1 || sp2 >= len)
    return 400; /* empty target (double SP) or no version */
  for (i = (uint16_t)(sp2 + 1); i < len; i++) {
    if (line[i] == ' ')
      return 400;
  }
  status = parse_version(line + sp2 + 1, (uint16_t)(len - sp2 - 1), &version);
  if (status != HTTP_PARSE_OK)
    return status;

  if (sp1 == 3 && memcmp(line, "GET", 3) == 0)
    method = HTTP_GET;
  else if (sp1 == 4 && memcmp(line, "HEAD", 4) == 0)
    method = HTTP_HEAD;
  else if (sp1 == 4 && memcmp(line, "POST", 4) == 0)
    method = HTTP_POST;
  else
    return 501; /* RFC 9110 §15.6.2 */

  /* ── Request target: origin-form, or absolute-form reduced to its path ── */
  char *target = line + sp1 + 1, *path = target;
  uint16_t target_len = (uint16_t)(sp2 - sp1 - 1);
  if (!target_valid(target, target_len))
    return 400;
  line[sp2] = '\0';
  req->flags = 0;
  req->host = NULL;
  req->host_len = 0;
  if (target[0] != '/') {
    status = absolute_form(target, target_len, &path, req);
    if (status != HTTP_PARSE_OK)
      return status;
  }
  char *q = strchr(path, '?');
  if (q) {
    *q = '\0';
    req->query = q + 1;
  } else {
    req->query = path + strlen(path); /* "" */
  }
  req->path = *path ? path : "/";

  /* ── Header fields ── */
  for (;;) {
    line = next_line(buf, &pos, hdr_len, &len);
    if (len == 0)
      break;
    if (is_ows(line[0]))
      return 400; /* obsolete line folding (RFC 9112 §5.2) */
    for (i = 0; i < len && line[i] != ':'; i++) {
      if (!is_tchar(line[i]))
        return 400; /* includes whitespace before ':' (§5.1) */
    }
    if (i == 0 || i >= len || has_cr_or_nul(line + i, (uint16_t)(len - i)))
      return 400;
    uint16_t name_len = i;
    const char *v = line + i + 1;
    uint16_t vlen = (uint16_t)(len - i - 1);
    while (vlen > 0 && is_ows(*v)) {
      v++;
      vlen--;
    }
    while (vlen > 0 && is_ows(v[vlen - 1]))
      vlen--;

    if (eq_ci(line, name_len, "content-length")) {
      uint32_t n;
      if (parse_content_length(v, vlen, &n) < 0 || (cl_seen && n != cl))
        return 400;
      cl = n;
      cl_seen = 1;
    } else if (eq_ci(line, name_len, "expect")) {
      if (version == 11 && eq_ci(v, vlen, "100-continue"))
        req->flags |= HTTP_RQ_CONTINUE; /* HTTP/1.0's is ignored */
    } else if (eq_ci(line, name_len, "if-match")) {
      if (!eq_ci(v, vlen, "*")) /* entity tags: none can match ours */
        req->flags |= HTTP_RQ_IF_MATCH;
    } else if (eq_ci(line, name_len, "if-none-match")) {
      if (eq_ci(v, vlen, "*"))
        req->flags |= HTTP_RQ_IF_NONE_ANY;
    } else if (eq_ci(line, name_len, "transfer-encoding")) {
      te = ends_in_chunked(v, vlen) ? 1 : 2; /* the last line's last */
    } else if (eq_ci(line, name_len, "host")) {
      uint16_t host_len;
      if (host_seen || !authority_valid(v, vlen, &host_len))
        return 400; /* RFC 9112 §3.2: one Host line at most, valid */
      host_seen = 1;
      if (!req->host) { /* an absolute-form target's host wins (§3.2.2) */
        req->host = v;
        req->host_len = host_len;
      }
    }
  }

  if (version == 11 && !host_seen)
    return 400; /* RFC 9112 §3.2 */
  /* REQ-HTTP-046: a length that cannot be determined (RFC 9112 §6.3), or
   * framing faulty in HTTP/1.0 (§6.1), is a 400; chunked, not
   * implemented, a 501 (REQ-HTTP-043) */
  if (te)
    return (te == 2 || version == 10) ? 400 : 501;

  req->method = method;
  req->version = version;
  req->body = NULL;
  req->body_len = 0;
#if NET_USE_IPV4
  req->remote_ip = 0;
#endif
#if NET_USE_IPV6
  req->remote_ip6 = NULL;
#endif
  *content_length = cl;
  return HTTP_PARSE_OK;
}

/* ── Response header ── */

const char *http_reason(uint16_t status) {
  switch (status) {
  case 200:
    return "OK";
  case 201:
    return "Created";
  case 204:
    return "No Content";
  case 205:
    return "Reset Content";
  case 301:
    return "Moved Permanently";
  case 302:
    return "Found";
  case 303:
    return "See Other";
  case 304:
    return "Not Modified";
  case 400:
    return "Bad Request";
  case 403:
    return "Forbidden";
  case 404:
    return "Not Found";
  case 405:
    return "Method Not Allowed";
  case 412:
    return "Precondition Failed";
  case 408:
    return "Request Timeout";
  case 413:
    return "Content Too Large";
  case 414:
    return "URI Too Long";
  case 417:
    return "Expectation Failed";
  case 421:
    return "Misdirected Request";
  case 431:
    return "Request Header Fields Too Large";
  case 500:
    return "Internal Server Error";
  case 501:
    return "Not Implemented";
  case 503:
    return "Service Unavailable";
  case 505:
    return "HTTP Version Not Supported";
  default:
    return "";
  }
}

typedef struct {
  char *p;
  uint16_t n;
  uint16_t cap;
  uint8_t ok;
} sbuf_t;

static void put(sbuf_t *b, const char *s) {
  size_t l = strlen(s);
  if (!b->ok || (size_t)b->n + l > b->cap) {
    b->ok = 0;
    return;
  }
  memcpy(b->p + b->n, s, l);
  b->n = (uint16_t)(b->n + l);
}

static void put_u32(sbuf_t *b, uint32_t v) {
  char digits[NET_U32_DEC_MAX];
  net_u32_to_dec(digits, v);
  put(b, digits);
}

/* *n / d, leaving the remainder in *n: shift and subtract (no '/', which
 * Cortex-M0 would have to call a library divide for) */
static uint32_t take(uint32_t *n, uint32_t d) {
  uint32_t q = 0, bit = 1;
  while (d <= (*n >> 1)) {
    d <<= 1;
    bit <<= 1;
  }
  for (; bit; d >>= 1, bit >>= 1) {
    if (*n >= d) {
      *n -= d;
      q |= bit;
    }
  }
  return q;
}

/* Two digits of @p v < 100 */
static void two_digits(char *p, uint32_t v) {
  p[0] = '0';
  while (v >= 10) {
    v -= 10;
    p[0]++;
  }
  p[1] = (char)('0' + v);
}

/* Seconds in uint32_t end in 2106: 2100 is the only year divisible by 4
 * that is not a leap year */
static int leap_year(uint32_t y) { return (y & 3) == 0 && y != 2100; }

/* REQ-HTTP-048: "Date: Sun, 06 Nov 1994 08:49:37 GMT", an IMF-fixdate
 * (RFC 9110 §5.6.7, §6.6.1), for @p t seconds since 1970-01-01 UTC */
static void put_date(sbuf_t *b, uint32_t t) {
  static const char wday[] = "ThuFriSatSunMonTueWed"; /* from 1970-01-01 */
  static const char mon[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
  static const uint8_t mdays[12] = {31, 28, 31, 30, 31, 30,
                                    31, 31, 30, 31, 30, 31};
  char d[30];
  uint32_t days = take(&t, 86400u), w = days, year = 1970, m = 0;
  take(&w, 7);
  while (days >= 365u + (uint32_t)leap_year(year)) {
    days -= 365u + (uint32_t)leap_year(year);
    year++;
  }
  while (days >= mdays[m] + (uint32_t)(m == 1 && leap_year(year))) {
    days -= mdays[m] + (uint32_t)(m == 1 && leap_year(year));
    m++;
  }
  memcpy(d, wday + w * 3, 3);
  memcpy(d + 3, ", ", 2);
  two_digits(d + 5, days + 1);
  d[7] = ' ';
  memcpy(d + 8, mon + m * 3, 3);
  d[11] = ' ';
  net_u32_to_dec(d + 12, year);
  d[16] = ' ';
  two_digits(d + 17, take(&t, 3600));
  d[19] = ':';
  two_digits(d + 20, take(&t, 60));
  d[22] = ':';
  two_digits(d + 23, t);
  memcpy(d + 25, " GMT", 5);
  put(b, "Date: ");
  put(b, d);
  put(b, "\r\n");
}

uint16_t http_format_header(char *out, uint16_t cap, uint16_t status,
                            const char *content_type, uint32_t content_length,
                            uint8_t allow, uint32_t date) {
  sbuf_t b;
  b.p = out;
  b.n = 0;
  b.cap = cap;
  b.ok = 1;

  put(&b, "HTTP/1.0 ");
  put_u32(&b, status);
  put(&b, " ");
  put(&b, http_reason(status));
  put(&b, "\r\n");
  if (date)
    put_date(&b, date);
  if (status != 204 && status != 304) { /* RFC 9110 §8.6: no body fields */
    if (content_type) {
      put(&b, "Content-Type: ");
      put(&b, content_type);
      put(&b, "\r\n");
    }
    put(&b, "Content-Length: ");
    put_u32(&b, content_length);
    put(&b, "\r\n");
  }
  if (allow || status == 405) { /* RFC 9110 §15.5.6: 405 always has it */
    const char *sep = "";
    put(&b, "Allow: ");
    if (allow & HTTP_GET) {
      put(&b, "GET");
      sep = ", ";
    }
    if (allow & HTTP_HEAD) {
      put(&b, sep);
      put(&b, "HEAD");
      sep = ", ";
    }
    if (allow & HTTP_POST) {
      put(&b, sep);
      put(&b, "POST");
    }
    put(&b, "\r\n");
  }
  put(&b, "Connection: close\r\n\r\n");
  if (!b.ok)
    return 0;
  if (b.n < cap)
    out[b.n] = '\0';
  return b.n;
}

/* ── Transport: plain TCP ── */

static void tcp_accepted(net_t *net, http_conn_t *c) {
  (void)net;
  (void)c;
}

/* The window is advertised again once a read empties the RX buffer */
static uint16_t tcp_read(net_t *net, http_conn_t *c, uint8_t *buf,
                         uint16_t len) {
  uint16_t n = tcp_recv(&c->tcp, buf, len);
  if (n < len)
    tcp_window_update(net, &c->tcp);
  return n;
}

static uint16_t tcp_write_some(http_conn_t *c, const uint8_t *data,
                               uint16_t len) {
  int n = tcp_write(&c->tcp, data, len);
  return n > 0 ? (uint16_t)n : 0;
}

static void tcp_flush(net_t *net, http_conn_t *c) { tcp_output(net, &c->tcp); }

static void tcp_finish(net_t *net, http_conn_t *c) {
  (void)net;
  (void)c;
}

static int tcp_client_done(const http_conn_t *c) {
  return c->tcp.state == TCP_CLOSE_WAIT;
}

static int tcp_delivered(http_conn_t *c) { return tcp_tx_idle(&c->tcp); }

static const http_transport_t tcp_transport = {
    tcp_accepted,    tcp_read,      tcp_write_some, tcp_flush, tcp_finish,
    tcp_client_done, tcp_delivered, NULL,           0,
};

/* ── Server ── */

/* Slot states (http_conn_t.state) */
#define S_LISTEN 0    /* TCP listening or handshaking */
#define S_RECV 1      /* reading the request */
#define S_SEND 2      /* streaming the response */
#define S_FINISHING 3 /* ending the stream (TLS: close_notify) */
#define S_CLOSING 4   /* our FIN sent, waiting for the close to finish */

#define HTTP_MIN_REQ 32

net_err_t http_conn_init(http_conn_t *c, uint8_t *tx_mem, uint16_t tx_size,
                         uint8_t *rx_mem, uint16_t rx_size, char *req_buf,
                         uint16_t req_size) {
  if (!c || !tx_mem || !rx_mem || !req_buf || tx_size == 0 || rx_size == 0 ||
      req_size < HTTP_MIN_REQ)
    return NET_ERR_INVALID_PARAM;
  memset(c, 0, sizeof(*c));
  c->transport = &tcp_transport;
  c->req = req_buf;
  c->req_size = req_size;
  tcp_saw_tx_init(&c->tx_ctx, tx_mem, tx_size);
  tcp_saw_rx_init(&c->rx_ctx, rx_mem, rx_size);
  return tcp_conn_init(&c->tcp, &tcp_saw_tx_ops, &c->tx_ctx, &tcp_saw_rx_ops,
                       &c->rx_ctx, NULL);
}

/* (Re)arm a slot: the last client's stream released, fresh TCP state and
 * buffers, LISTEN on the port — also how a slot leaves TIME-WAIT at once
 * (docs/design/http.md) */
static void slot_listen(http_server_t *s, http_conn_t *c) {
  if (c->transport->release)
    c->transport->release(c);
  tcp_saw_tx_init(&c->tx_ctx, c->tx_ctx.buf, c->tx_ctx.capacity);
  tcp_saw_rx_init(&c->rx_ctx, c->rx_ctx.buf, c->rx_ctx.capacity);
  tcp_conn_init(&c->tcp, &tcp_saw_tx_ops, &c->tx_ctx, &tcp_saw_rx_ops,
                &c->rx_ctx, NULL);
  tcp_listen(&c->tcp, s->port);
  c->state = S_LISTEN;
  c->req_len = 0;
  c->hdr_len = 0;
  c->content_length = 0;
  c->timer_ms = HTTP_REQUEST_TIMEOUT_MS;
  c->head_only = 0;
  c->allow = 0;
  c->body = NULL;
  c->body_len = 0;
  c->sent = 0;
}

net_err_t http_server_init(http_server_t *s, net_t *net, uint16_t port,
                           const http_route_t *routes, uint8_t n_routes,
                           http_conn_t *conns, uint8_t n_conns) {
  uint8_t i;
  if (!s || !net || !conns || n_conns == 0 || port == 0 ||
      (!routes && n_routes))
    return NET_ERR_INVALID_PARAM;
  s->net = net;
  s->port = port;
  s->routes = routes;
  s->n_routes = n_routes;
  s->conns = conns;
  s->n_conns = n_conns;
  s->clock = NULL;
  s->https_hosts = NULL;
  s->n_https_hosts = 0;
  for (i = 0; i < n_conns; i++)
    slot_listen(s, &conns[i]);
  return NET_OK;
}

/* REQ-HTTP-048: the Date of a response — from the application's clock,
 * if it has one and knows the time (RFC 9110 §6.6.1) */
static void respond(const http_server_t *s, http_conn_t *c, uint16_t status,
                    const char *content_type, const uint8_t *body,
                    uint32_t body_len, uint8_t allow) {
  char hdr[HTTP_HDR_MAX];
  if (status == 204 || status == 205 || status == 304)
    body_len = 0; /* RFC 9110 §15.3.5, §15.3.6, §15.4.5; REQ-HTTP-051 */
  c->date = s->clock ? s->clock() : 0;
  c->resp_hdr_len = http_format_header(hdr, sizeof(hdr), status, content_type,
                                       body_len, allow, c->date);
  if (c->resp_hdr_len == 0) { /* e.g. a very long content type */
    status = 500;
    content_type = "text/plain";
    body = (const uint8_t *)http_reason(500);
    body_len = (uint32_t)strlen((const char *)body);
    allow = 0;
    c->resp_hdr_len = http_format_header(hdr, sizeof(hdr), status, content_type,
                                         body_len, 0, c->date);
  }
  c->status = status;
  c->content_type = content_type;
  c->body = body;
  c->body_len = body_len;
  c->allow = allow;
  c->sent = 0;
  c->state = S_SEND;
  c->timer_ms = HTTP_RESPONSE_TIMEOUT_MS;
}

/* RFC 9110 §9.3.2: no content in a response to HEAD, an error included —
 * so this looks at the request line itself, parsed or not (the parser
 * skips empty lines before it too) */
static int is_head(const char *req, uint16_t len) {
  while (len > 0 && (*req == '\r' || *req == '\n')) {
    req++;
    len--;
  }
  return len >= 5 && memcmp(req, "HEAD ", 5) == 0;
}

/* Error responses carry the reason phrase as a text/plain body */
static void respond_error(const http_server_t *s, http_conn_t *c,
                          uint16_t status, uint8_t allow) {
  const char *reason = http_reason(status);
  respond(s, c, status, "text/plain", (const uint8_t *)reason,
          (uint32_t)strlen(reason), allow);
}

/* Send our FIN once the stream's last bytes reached the client */
static void close_when_delivered(http_server_t *s, http_conn_t *c) {
  c->transport->flush(s->net, c);
  if (!c->transport->delivered(c))
    return;
  tcp_close(s->net, &c->tcp);
  c->state = S_CLOSING;
  c->timer_ms = HTTP_RESPONSE_TIMEOUT_MS;
}

static void end_stream(http_server_t *s, http_conn_t *c) {
  c->transport->finish(s->net, c);
  c->state = S_FINISHING;
  c->timer_ms = HTTP_RESPONSE_TIMEOUT_MS;
  close_when_delivered(s, c);
}

/* REQ-HTTP-049, 050, 052: what a handler answers must make a response the
 * server can send whole: a final status of three digits (RFC 9110 §15,
 * §2.2) — no 1xx, since this HTTP/1.0 server sends one final response
 * (§15.2), and no 206, 401 or 426, which need fields it cannot add
 * (§15.3.7.1, §15.5.2, §15.5.22) — and a content type without control
 * characters (§5.5) */
static int response_valid(const http_response_t *rs) {
  const char *t = rs->content_type;
  if (rs->status < 200 || rs->status > 599 || rs->status == 206 ||
      rs->status == 401 || rs->status == 426)
    return 0;
  for (; t && *t; t++) {
    if (((uint8_t)*t < ' ' && *t != '\t') || *t == 0x7F)
      return 0;
  }
  return 1;
}

static const http_route_t *find_route(const http_server_t *s,
                                      const char *path) {
  uint8_t i;
  for (i = 0; i < s->n_routes; i++) {
    if (strcmp(s->routes[i].path, path) == 0)
      return &s->routes[i];
  }
  return NULL;
}

/* HEAD comes with GET */
static uint8_t route_methods(const http_route_t *r) {
  return (uint8_t)(r->methods | ((r->methods & HTTP_GET) ? HTTP_HEAD : 0));
}

/* Run the handler of the request admit() let through */
static void dispatch(http_server_t *s, http_conn_t *c) {
  http_request_t *rq = &c->request;
  uint32_t need = (uint32_t)c->hdr_len + c->content_length;
  const http_route_t *route = find_route(s, rq->path);
  uint8_t allowed = route_methods(route);
  http_response_t rs;

  rq->body = c->content_length ? (const uint8_t *)c->req + c->hdr_len : NULL;
  rq->body_len = (uint16_t)c->content_length;
#if NET_USE_IPV4
  rq->remote_ip = c->tcp.remote_ip;
#endif
#if NET_USE_IPV6
  rq->remote_ip6 = c->tcp.ip_ver == 6 ? c->tcp.remote_ip6 : NULL;
#endif
  rs.status = 200;
  rs.content_type = "text/html";
  rs.body = NULL;
  rs.body_len = 0;
  rs.scratch = (uint8_t *)c->req + need;
  rs.scratch_size = (uint16_t)(c->req_size - need);
  if (route->handler(rq, &rs, route->ctx) < 0 || !response_valid(&rs)) {
    respond_error(s, c, 500, 0); /* REQ-HTTP-027 */
    return;
  }
  respond(s, c, rs.status, rs.content_type, rs.body, rs.body ? rs.body_len : 0,
          rs.status == 405 ? allowed : 0); /* REQ-HTTP-024 */
}

/* Discard whatever the client still sends once the request has been
 * answered (lingering close, RFC 9112 §9.6), so it can finish sending and
 * close instead of stalling on a zero window */
static void drain(http_server_t *s, http_conn_t *c) {
  uint8_t sink[64];
  while (c->transport->read(s->net, c, sink, sizeof(sink)) > 0)
    ;
}

/* REQ-HTTP-056: a request for an https resource must arrive over TLS with
 * a certificate valid for its host (RFC 9110 §7.4) — over TLS, one of the
 * hosts the application lists for its certificate */
static int misdirected(const http_server_t *s, const http_conn_t *c) {
  const http_request_t *rq = &c->request;
  uint8_t i;
  if (!c->transport->secure)
    return (rq->flags & HTTP_RQ_HTTPS) != 0;
  if (!s->https_hosts)
    return 0;
  for (i = 0; rq->host && i < s->n_https_hosts; i++) {
    if (eq_ci(rq->host, rq->host_len, s->https_hosts[i]))
      return 0;
  }
  return 1;
}

/* What the header section alone decides, before any content is read: the
 * status to answer with (*allow: for a 405), or HTTP_PARSE_OK to read the
 * content and run the handler.  REQ-HTTP-053: a client waiting for 100
 * (Continue) before it sends the content must not be kept waiting (RFC
 * 9110 §10.1.1), and this HTTP/1.0 server cannot send a 1xx (§15.2): 417
 * at once, which tells the client to repeat the request without the
 * expectation — unless content has begun to arrive, so it did not wait.
 * REQ-HTTP-054, 055: the preconditions come last, once the request would
 * otherwise succeed (RFC 9110 §13.2.1), in §13.2.2's order.  The server sends
 * no entity tags, so If-Match with tags fails and If-None-Match with tags
 * holds; "*" names the route's representation, which exists. */
static uint16_t admit(const http_server_t *s, const http_conn_t *c,
                      uint8_t *allow) {
  const http_request_t *rq = &c->request;
  const http_route_t *route = find_route(s, rq->path);
  if ((uint32_t)c->hdr_len + c->content_length > c->req_size)
    return 413; /* REQ-HTTP-033, 034 */
  if (misdirected(s, c))
    return 421;
  if (!route)
    return 404; /* REQ-HTTP-025 */
  if (!(route_methods(route) & rq->method)) {
    *allow = route_methods(route);
    return 405; /* REQ-HTTP-024 */
  }
  if (rq->flags & HTTP_RQ_IF_MATCH)
    return 412;
  if (rq->flags & HTTP_RQ_IF_NONE_ANY)
    return (rq->method & (HTTP_GET | HTTP_HEAD)) ? 304 : 412;
  if ((rq->flags & HTTP_RQ_CONTINUE) && c->content_length &&
      c->req_len == c->hdr_len)
    return 417; /* REQ-HTTP-053 */
  return HTTP_PARSE_OK;
}

static void do_recv(http_server_t *s, http_conn_t *c) {
  uint16_t n;
  while (c->req_len < c->req_size &&
         (n = c->transport->read(s->net, c, (uint8_t *)c->req + c->req_len,
                                 (uint16_t)(c->req_size - c->req_len))) > 0)
    c->req_len = (uint16_t)(c->req_len + n);

  if (c->hdr_len == 0) {
    uint16_t end = http_header_end(c->req, c->req_len);
    c->head_only = (uint8_t)is_head(c->req, c->req_len);
    if (end == 0) {
      if (c->req_len >= c->req_size) /* REQ-HTTP-039..041 */
        respond_error(s, c, memchr(c->req, '\n', c->req_len) ? 431 : 414, 0);
      else if (c->transport->client_done(c))
        end_stream(s, c); /* the request never ended */
      return;
    }
    uint16_t status =
        http_parse_request(c->req, end, &c->request, &c->content_length);
    uint8_t allow = 0;
    c->hdr_len = end;
    if (status == HTTP_PARSE_OK)
      status = admit(s, c, &allow);
    if (status != HTTP_PARSE_OK) {
      respond_error(s, c, status, allow);
      return;
    }
  }

  if ((uint32_t)c->req_len < (uint32_t)c->hdr_len + c->content_length) {
    if (c->transport->client_done(c))
      end_stream(s, c); /* the body can no longer arrive */
    return;
  }
  dispatch(s, c);
}

/* Queue as much of header + body as the transport takes, then push it;
 * end the stream once all of it is delivered (REQ-HTTP-029).  The header
 * is formatted again on each call rather than kept. */
static void do_send(http_server_t *s, http_conn_t *c) {
  uint32_t total =
      (uint32_t)c->resp_hdr_len + (c->head_only ? 0u : c->body_len);

  drain(s, c); /* the request is complete; anything more is discarded */

  if (c->sent < c->resp_hdr_len) {
    char hdr[HTTP_HDR_MAX];
    http_format_header(hdr, sizeof(hdr), c->status, c->content_type,
                       c->body_len, c->allow, c->date);
    c->sent += c->transport->write(c, (const uint8_t *)hdr + c->sent,
                                   (uint16_t)(c->resp_hdr_len - c->sent));
  }
  while (c->sent >= c->resp_hdr_len && c->sent < total) {
    uint32_t off = c->sent - c->resp_hdr_len;
    uint32_t left = c->body_len - off;
    uint16_t w = c->transport->write(
        c, c->body + off, (uint16_t)(left > 0xFFFFu ? 0xFFFFu : left));
    if (w == 0)
      break;
    c->sent += w;
  }
  c->transport->flush(s->net, c);
  if (c->sent >= total && c->transport->delivered(c))
    end_stream(s, c);
}

static int tcp_open(const http_conn_t *c) {
  return c->tcp.state == TCP_ESTABLISHED || c->tcp.state == TCP_CLOSE_WAIT;
}

void http_server_poll(http_server_t *s) {
  uint8_t i;
  for (i = 0; i < s->n_conns; i++) {
    http_conn_t *c = &s->conns[i];
    tcp_state_t st = c->tcp.state;

    if (c->state != S_LISTEN && c->state != S_CLOSING && !tcp_open(c)) {
      slot_listen(s, c); /* RST or unexpected close */
      continue;
    }
    switch (c->state) {
    case S_LISTEN:
      if (!tcp_open(c)) {
        if (st == TCP_CLOSED) /* e.g. RST during the handshake */
          slot_listen(s, c);
        break;
      }
      c->state = S_RECV;
      c->timer_ms = HTTP_REQUEST_TIMEOUT_MS;
      c->transport->accepted(s->net, c);
      /* data may be waiting already */
      /* fall through */
    case S_RECV:
      do_recv(s, c);
      if (c->state == S_SEND)
        do_send(s, c);
      break;
    case S_SEND:
      do_send(s, c);
      break;
    case S_FINISHING:
      drain(s, c);
      close_when_delivered(s, c);
      break;
    case S_CLOSING:
      /* Both sides have closed (TIME-WAIT, or CLOSING after a simultaneous
       * close) or the close is complete: the response was delivered, so
       * recycle now instead of waiting 2×MSL or for a FIN resend */
      if (st == TCP_TIME_WAIT || st == TCP_CLOSING || st == TCP_CLOSED)
        slot_listen(s, c);
      else
        drain(s, c);
      break;
    default:
      slot_listen(s, c);
      break;
    }
  }
}

void http_server_tick(http_server_t *s, uint32_t elapsed_ms) {
  uint8_t i;
  for (i = 0; i < s->n_conns; i++) {
    http_conn_t *c = &s->conns[i];
    if (c->state == S_LISTEN && c->tcp.state != TCP_SYN_RECEIVED) {
      c->timer_ms = HTTP_REQUEST_TIMEOUT_MS; /* idle listener */
      continue;
    }
    if (!net_countdown(&c->timer_ms, elapsed_ms))
      continue;
    /* Timed out: free the slot for the next client */
    if (c->tcp.state != TCP_CLOSED && c->tcp.state != TCP_LISTEN)
      tcp_abort(s->net, &c->tcp);
    slot_listen(s, c);
  }
}
