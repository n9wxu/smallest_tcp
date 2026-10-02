/**
 * @file dns_wire.c
 * @brief DNS wire-format helpers (RFC 1035 §3-4), and the rdata order of
 *        RFC 6762 §8.2.
 *
 * Implements REQ-MDNS-003 (wire format), REQ-MDNS-043, 048 (name
 * compression, written and read) and REQ-MDNS-051, REQ-DNSSD-031 (label /
 * name length limits: 63 and 255 bytes, the name's terminating zero not
 * counted, RFC 6762 App. C).
 */

#include "dns_wire.h"
#include "net_endian.h"
#include "net_text.h"
#include <string.h>

/* Compression-pointer hops allowed while reading one name.  A legitimate
 * name has at most 127 labels; this bound stops pointer loops early. */
#define DNS_MAX_HOPS 32

/* "." is the root name; treat it like "". */
static const char *dotted_begin(const char *name) {
  return (name[0] == '.' && name[1] == '\0') ? name + 1 : name;
}

/**
 * Return the next label of a dotted name: its length (>0), 0 at the end of
 * the name, or -1 if the label is empty or longer than 63 bytes.
 */
static int dotted_next(const char **pp, const char **label) {
  const char *s = *pp;
  const char *e = s;
  if (*s == '\0')
    return 0;
  while (*e != '\0' && *e != '.')
    e++;
  if (e == s || e - s > DNS_MAX_LABEL)
    return -1;
  *label = s;
  *pp = (*e == '.') ? e + 1 : e; /* a trailing dot ends the name */
  return (int)(e - s);
}

int dns_dotted_equal(const char *a, const char *b) {
  const char *la, *lb;
  int na, nb, i;
  a = dotted_begin(a);
  b = dotted_begin(b);
  for (;;) {
    na = dotted_next(&a, &la);
    nb = dotted_next(&b, &lb);
    if (na != nb || na < 0)
      return 0;
    if (na == 0)
      return 1;
    for (i = 0; i < na; i++) {
      if (net_tolower(la[i]) != net_tolower(lb[i]))
        return 0;
    }
  }
}

int dns_name_wire_len(const char *name) {
  const char *p = dotted_begin(name);
  const char *label;
  int n, total = 0; /* the labels, before the terminating zero */
  while ((n = dotted_next(&p, &label)) > 0) {
    total += 1 + n;
    if (total > DNS_MAX_NAME)
      return -2;
  }
  return (n < 0) ? -2 : total + 1;
}

typedef struct {
  const uint8_t *msg;
  uint16_t len;
  uint16_t off;
  uint16_t total; /* uncompressed wire length so far, without the zero */
  uint8_t hops;
} wire_iter_t;

/**
 * Return the next label of a wire name: its length (>0) with *label set,
 * 0 at the terminating root label, or -1 if the name is malformed.
 */
static int wire_next(wire_iter_t *it, const uint8_t **label) {
  for (;;) {
    if (it->off >= it->len)
      return -1;
    uint8_t b = it->msg[it->off];
    if ((b & 0xC0) == 0xC0) {
      if ((uint32_t)it->off + 1 >= it->len)
        return -1;
      uint16_t target = (uint16_t)(((b & 0x3F) << 8) | it->msg[it->off + 1]);
      if (target >= it->len || ++it->hops > DNS_MAX_HOPS)
        return -1;
      it->off = target;
      continue;
    }
    if (b & 0xC0)
      return -1; /* 01/10 label types are not supported */
    if (b == 0)
      return 0;
    if ((uint32_t)it->off + 1 + b > it->len)
      return -1;
    it->total = (uint16_t)(it->total + 1 + b);
    if (it->total > DNS_MAX_NAME)
      return -1;
    *label = it->msg + it->off + 1;
    it->off = (uint16_t)(it->off + 1 + b);
    return b;
  }
}

static void wire_begin(wire_iter_t *it, const uint8_t *msg, uint16_t len,
                       uint16_t off) {
  it->msg = msg;
  it->len = len;
  it->off = off;
  it->total = 0;
  it->hops = 0;
}

void dns_writer_init(dns_writer_t *w, uint8_t *buf, uint16_t cap) {
  w->buf = buf;
  w->cap = cap;
  w->len = 0;
  w->overflow = 0;
  w->n_offsets = 0;
}

int dns_write_bytes(dns_writer_t *w, const uint8_t *data, uint16_t n) {
  if ((uint32_t)w->len + n > w->cap) {
    w->overflow = 1;
    return -1;
  }
  if (n > 0)
    memcpy(w->buf + w->len, data, n);
  w->len = (uint16_t)(w->len + n);
  return 0;
}

int dns_write_u16(dns_writer_t *w, uint16_t v) {
  uint8_t b[2];
  net_write16be(b, v);
  return dns_write_bytes(w, b, 2);
}

int dns_write_u32(dns_writer_t *w, uint32_t v) {
  uint8_t b[4];
  net_write32be(b, v);
  return dns_write_bytes(w, b, 4);
}

dns_writer_mark_t dns_writer_mark(const dns_writer_t *w) {
  dns_writer_mark_t m;
  m.len = w->len;
  m.n_offsets = w->n_offsets;
  return m;
}

void dns_writer_rollback(dns_writer_t *w, dns_writer_mark_t mark) {
  w->len = mark.len;
  w->n_offsets = mark.n_offsets;
}

/* Find an earlier label sequence equal to the dotted suffix @p s. */
static int find_compress_target(const dns_writer_t *w, const char *s) {
  uint8_t i;
  for (i = 0; i < w->n_offsets; i++) {
    if (dns_name_equals(w->buf, w->len, w->offsets[i], s))
      return w->offsets[i];
  }
  return -1;
}

static int write_name(dns_writer_t *w, const char *name, int compress) {
  if (dns_name_wire_len(name) < 0)
    return -2;

  dns_writer_mark_t start = dns_writer_mark(w);
  const char *p = dotted_begin(name);
  const char *label;
  int n;

  for (;;) {
    /* REQ-MDNS-043: replace the longest already-written suffix */
    if (compress && *p != '\0') {
      int target = find_compress_target(w, p);
      if (target >= 0) {
        if (dns_write_u16(w, (uint16_t)(0xC000 | target)) < 0)
          goto overflow;
        return 0;
      }
    }
    n = dotted_next(&p, &label);
    if (n == 0)
      break;
    uint16_t pos = w->len;
    uint8_t lenbyte = (uint8_t)n;
    if (dns_write_bytes(w, &lenbyte, 1) < 0 ||
        dns_write_bytes(w, (const uint8_t *)label, (uint16_t)n) < 0)
      goto overflow;
    if (pos <= 0x3FFF && w->n_offsets < DNS_COMPRESS_MAX)
      w->offsets[w->n_offsets++] = pos;
  }
  {
    uint8_t root = 0;
    if (dns_write_bytes(w, &root, 1) < 0)
      goto overflow;
  }
  return 0;

overflow:
  dns_writer_rollback(w, start);
  w->overflow = 1;
  return -1;
}

int dns_write_name(dns_writer_t *w, const char *name) {
  return write_name(w, name, 1);
}

int dns_write_name_flat(dns_writer_t *w, const char *name) {
  return write_name(w, name, 0);
}

int dns_write_header(dns_writer_t *w, uint16_t id, uint16_t flags,
                     uint16_t qdcount, uint16_t ancount, uint16_t nscount,
                     uint16_t arcount) {
  uint8_t h[DNS_HDR_SIZE];
  net_write16be(h + DNS_OFF_ID, id);
  net_write16be(h + DNS_OFF_FLAGS, flags);
  dns_set_counts(h, qdcount, ancount, nscount, arcount);
  return dns_write_bytes(w, h, DNS_HDR_SIZE);
}

void dns_set_counts(uint8_t *msg, uint16_t qdcount, uint16_t ancount,
                    uint16_t nscount, uint16_t arcount) {
  net_write16be(msg + DNS_OFF_QDCOUNT, qdcount);
  net_write16be(msg + DNS_OFF_ANCOUNT, ancount);
  net_write16be(msg + DNS_OFF_NSCOUNT, nscount);
  net_write16be(msg + DNS_OFF_ARCOUNT, arcount);
}

int dns_name_skip(const uint8_t *msg, uint16_t len, uint16_t off) {
  uint16_t start = off;
  for (;;) {
    if (off >= len)
      return -1;
    uint8_t b = msg[off];
    if ((b & 0xC0) == 0xC0)
      return ((uint32_t)off + 1 < len) ? off + 2 : -1;
    if (b & 0xC0)
      return -1;
    if (b == 0)
      return off + 1;
    if ((uint32_t)off + 1 + b > len)
      return -1;
    off = (uint16_t)(off + 1 + b);
    if (off - start > DNS_MAX_NAME)
      return -1;
  }
}

int dns_name_equals(const uint8_t *msg, uint16_t len, uint16_t off,
                    const char *name) {
  wire_iter_t it;
  const char *p = dotted_begin(name);
  wire_begin(&it, msg, len, off);
  for (;;) {
    const uint8_t *wl;
    const char *dl;
    int wn = wire_next(&it, &wl);
    int dn = dotted_next(&p, &dl);
    if (wn < 0 || dn < 0 || wn != dn)
      return 0;
    if (wn == 0)
      return 1;
    int i;
    for (i = 0; i < wn; i++) {
      if (net_tolower((char)wl[i]) != net_tolower(dl[i]))
        return 0;
    }
  }
}

int dns_name_decode(const uint8_t *msg, uint16_t len, uint16_t off, char *out,
                    uint16_t out_len) {
  wire_iter_t it;
  const uint8_t *label;
  uint16_t pos = 0;
  int n;
  if (out_len == 0)
    return -1;
  wire_begin(&it, msg, len, off);
  while ((n = wire_next(&it, &label)) > 0) {
    uint16_t need = (uint16_t)((pos ? 1 : 0) + n);
    if ((uint32_t)pos + need + 1 > out_len)
      return -1;
    if (pos)
      out[pos++] = '.';
    memcpy(out + pos, label, (size_t)n);
    pos = (uint16_t)(pos + n);
  }
  if (n < 0)
    return -1;
  out[pos] = '\0';
  return pos;
}

int dns_read_question(const uint8_t *msg, uint16_t len, uint16_t off,
                      dns_question_t *q) {
  int p = dns_name_skip(msg, len, off);
  if (p < 0 || (uint32_t)p + 4 > len)
    return -1;
  q->name_off = off;
  q->type = net_read16be(msg + p);
  q->class_ = net_read16be(msg + p + 2);
  return p + 4;
}

/* Where a type's rdata holds a name that may be compressed (RFC 6762
 * §18.14), or NO_NAME */
#define NO_NAME 0xFFFFu
static uint16_t rdata_name_at(uint16_t type) {
  switch (type) {
  case 2:  /* NS */
  case 5:  /* CNAME */
  case 39: /* DNAME */
  case DNS_TYPE_PTR:
  case DNS_TYPE_NSEC:
    return 0;
  case 15: /* MX */
  case 18: /* AFSDB */
  case 21: /* RT */
  case 36: /* KX */
    return 2;
  case DNS_TYPE_SRV:
    return 6;
  default:
    return NO_NAME;
  }
}

/* The bytes of a record's rdata, its name uncompressed */
typedef struct {
  wire_iter_t it; /* in the name */
  const uint8_t *label;
  uint16_t pos, end; /* raw bytes left: [pos, end) */
  uint16_t name;     /* where the name starts, or NO_NAME */
  uint8_t left;      /* bytes of the label left */
  uint8_t in_name;
} rdata_iter_t;

static void rdata_begin(rdata_iter_t *c, const uint8_t *msg, uint16_t len,
                        const dns_rr_t *rr) {
  uint16_t at = rdata_name_at(rr->type);
  wire_begin(&c->it, msg, len, rr->rdata_off);
  c->pos = rr->rdata_off;
  c->end = (uint16_t)(rr->rdata_off + rr->rdlen);
  c->name = (at < rr->rdlen) ? (uint16_t)(rr->rdata_off + at) : NO_NAME;
  c->left = 0;
  c->in_name = 0;
}

/* The next byte, or -1 at the end */
static int rdata_next(rdata_iter_t *c) {
  for (;;) {
    if (c->in_name) {
      int n, after;
      if (c->left) {
        c->left--;
        return *c->label++;
      }
      n = wire_next(&c->it, &c->label);
      if (n > 0) {
        c->left = (uint8_t)n;
        return n;
      }
      /* the root label ends the name (a malformed one ends the rdata) */
      after = dns_name_skip(c->it.msg, c->it.len, c->name);
      c->pos = (n < 0 || after < 0) ? c->end : (uint16_t)after;
      c->name = NO_NAME;
      c->in_name = 0;
      return 0;
    }
    if (c->pos == c->name) {
      wire_begin(&c->it, c->it.msg, c->it.len, c->pos);
      c->in_name = 1;
      continue;
    }
    if (c->pos >= c->end)
      return -1;
    return c->it.msg[c->pos++];
  }
}

int dns_rdata_compare(const uint8_t *ma, uint16_t la, const dns_rr_t *a,
                      const uint8_t *mb, uint16_t lb, const dns_rr_t *b) {
  rdata_iter_t x, y;
  rdata_begin(&x, ma, la, a);
  rdata_begin(&y, mb, lb, b);
  for (;;) {
    int p = rdata_next(&x), q = rdata_next(&y);
    if (p != q || p < 0)
      return p - q;
  }
}

int dns_read_rr(const uint8_t *msg, uint16_t len, uint16_t off, dns_rr_t *rr) {
  int p = dns_name_skip(msg, len, off);
  if (p < 0 || (uint32_t)p + 10 > len)
    return -1;
  rr->name_off = off;
  rr->type = net_read16be(msg + p);
  rr->class_ = net_read16be(msg + p + 2);
  rr->ttl = net_read32be(msg + p + 4);
  rr->rdlen = net_read16be(msg + p + 8);
  rr->rdata_off = (uint16_t)(p + 10);
  if ((uint32_t)rr->rdata_off + rr->rdlen > len)
    return -1;
  return rr->rdata_off + rr->rdlen;
}
