/**
 * @file http.c
 * @brief Minimal HTTP/1.0 server (RFC 9110 semantics, RFC 9112 syntax).
 *
 * Implements REQ-HTTP-001..041 (V1 scope).  See docs/design/http.md.
 */

#include "http.h"
#include <string.h>

/* ══ Small string helpers ═════════════════════════════════════════════ */

static char lower(char c) {
  return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

/* RFC 9110 §5.6.2 token characters */
static int is_tchar(char c) {
  if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
      (c >= '0' && c <= '9'))
    return 1;
  return c != '\0' && strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

static int is_ows(char c) { return c == ' ' || c == '\t'; }

/* Case-insensitive: a[0..alen) equals the lower-case string b */
static int eq_ci(const char *a, uint16_t alen, const char *b) {
  uint16_t i;
  for (i = 0; i < alen; i++) {
    if (b[i] == '\0' || lower(a[i]) != b[i])
      return 0;
  }
  return b[alen] == '\0';
}

/* ══ Header block detection ═══════════════════════════════════════════ */

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

/* ══ Request parsing ══════════════════════════════════════════════════ */

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
    if (v[i] < '0' || v[i] > '9')
      return -1;
    d = (uint32_t)(v[i] - '0');
    if (n > 429496729u || (n == 429496729u && d > 5u)) /* > 0xFFFFFFFF */
      return -1;
    n = n * 10u + d;
  }
  *out = n;
  return 0;
}

uint16_t http_parse_request(char *buf, uint16_t hdr_len, http_request_t *req,
                            uint32_t *content_length) {
  uint16_t pos = 0, len, i;
  uint16_t sp1 = 0, sp2 = 0, status;
  uint8_t version = 0, method = 0;
  uint32_t cl = 0;
  int cl_seen = 0, host_seen = 0;
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

  /* ── Request target: origin-form, or absolute-form reduced to its path */
  char *target = line + sp1 + 1;
  const char *path = target;
  line[sp2] = '\0';
  if (target[0] != '/') {
    if (sp2 - sp1 - 1 < 7 || !eq_ci(target, 7, "http://"))
      return 400;
    path = strchr(target + 7, '/');
    if (!path)
      path = "/";
  }
  char *q = strchr(path, '?');
  if (q) {
    *q = '\0';
    req->query = q + 1;
  } else {
    req->query = path + strlen(path); /* "" */
  }
  req->path = path;

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
    if (i == 0 || i >= len)
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
    } else if (eq_ci(line, name_len, "transfer-encoding")) {
      return 501; /* no chunked request bodies in V1 */
    } else if (eq_ci(line, name_len, "host")) {
      host_seen = 1;
    }
  }

  if (version == 11 && !host_seen)
    return 400; /* RFC 9112 §3.2 */

  req->method = method;
  req->version = version;
  req->body = NULL;
  req->body_len = 0;
  req->remote_ip = 0;
  *content_length = cl;
  return HTTP_PARSE_OK;
}

/* ══ Response header ══════════════════════════════════════════════════ */

const char *http_reason(uint16_t status) {
  switch (status) {
  case 200:
    return "OK";
  case 201:
    return "Created";
  case 204:
    return "No Content";
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
  case 408:
    return "Request Timeout";
  case 413:
    return "Content Too Large";
  case 414:
    return "URI Too Long";
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

/* Decimal without division: Cortex-M0 has no divide instruction, and a
 * '/' or '%' would link libgcc's software divide. */
static void put_u32(sbuf_t *b, uint32_t v) {
  static const uint32_t pow10[] = {1000000000u, 100000000u, 10000000u,
                                   1000000u,    100000u,    10000u,
                                   1000u,       100u,       10u,
                                   1u};
  char digits[11];
  uint8_t n = 0, i;
  for (i = 0; i < 10; i++) {
    char d = '0';
    while (v >= pow10[i]) {
      v -= pow10[i];
      d++;
    }
    if (d != '0' || n > 0 || i == 9)
      digits[n++] = d;
  }
  digits[n] = '\0';
  put(b, digits);
}

uint16_t http_format_header(char *out, uint16_t cap, uint16_t status,
                            const char *content_type, uint32_t content_length,
                            uint8_t allow) {
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
  if (allow) {
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
