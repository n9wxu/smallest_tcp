/**
 * @file mdns.c
 * @brief Multicast DNS responder (RFC 6762) with DNS-SD advertising (RFC 6763).
 *
 * Implements the V1 responder requirements REQ-MDNS-001..033, 041..043 and
 * REQ-DNSSD-001..018, 030..032.  See mdns.h for the API and scope.
 *
 * Messages are built directly in net->tx.buf at UDP_PAYLOAD_OFFSET and sent
 * with udp_send_inplace() (IP TTL 255).  Record sets are addressed by bitmask
 * (bit i = records[i]), which keeps the state in mdns_t to a few words.
 */

#include "mdns.h"
#include "net_endian.h"
#include "udp.h"
#include <string.h>

#if NET_USE_IPV4
#include "igmp.h"
#include "ipv4.h"
#endif
#if NET_USE_IPV6
#include "ipv6.h"

const uint8_t mdns_group6[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                 0,    0,    0, 0, 0, 0, 0, 0xFB};
#endif

#define ALL_FAMILIES                                                           \
  ((NET_USE_IPV4 ? MDNS_FAMILY_V4 : 0u) | (NET_USE_IPV6 ? MDNS_FAMILY_V6 : 0u))

#if NET_USE_IPV4 && NET_MAX_MCAST_GROUPS < 1
#error "mDNS needs NET_MAX_MCAST_GROUPS >= 1 to receive 224.0.0.251"
#endif
#if NET_USE_IPV6 && NET_MAX_MCAST6_GROUPS < 1
#error "mDNS needs NET_MAX_MCAST6_GROUPS >= 1 to receive ff02::fb"
#endif

/*
 * @p v4 or @p v6, for the address family of @p d (a dest_t).  A single-
 * stack build keeps only its own family's expression: the other's names
 * need not exist.
 */
#if NET_USE_IPV4 && NET_USE_IPV6
#define BY_FAMILY(d, v4, v6) ((d)->ip6 ? (v6) : (v4))
#elif NET_USE_IPV6
#define BY_FAMILY(d, v4, v6) ((void)(d), (v6))
#else
#define BY_FAMILY(d, v4, v6) ((void)(d), (v4))
#endif

#define BIT(i) ((uint32_t)1u << (i))

/* PTR records are shared (many hosts advertise the same service type);
 * A, SRV and TXT records are unique to this host (RFC 6762 §2). */
static int is_shared(const mdns_record_t *r) { return r->type == DNS_TYPE_PTR; }

/* A PTR whose owner is a service type ("_x._tcp.local") */
static int is_service_type(const mdns_record_t *r) {
  return r->type == DNS_TYPE_PTR && r->name[0] == '_';
}

#if NET_USE_IPV4
static uint32_t rec_addr(const mdns_t *m, const mdns_record_t *r) {
  return r->rdata.a ? r->rdata.a : m->net->ipv4_addr;
}
#endif

#if NET_USE_IPV6
/* The addresses an AAAA record stands for: its own, or every usable IPv6
 * address of the interface (not tentative ones, RFC 4862 §5.4). */
static uint8_t aaaa_addrs(const mdns_t *m, const mdns_record_t *r,
                          const uint8_t *out[NET_IPV6_ADDRS]) {
  uint8_t i, n = 0;
  if (r->rdata.aaaa) {
    out[0] = r->rdata.aaaa;
    return 1;
  }
  for (i = 0; i < NET_IPV6_ADDRS; i++) {
    const net_ip6_addr_t *a = &m->net->ip6.addr[i];
    if (a->state == NET_IP6_PREFERRED || a->state == NET_IP6_DEPRECATED)
      out[n++] = a->addr;
  }
  return n;
}
#endif

static uint32_t all_mask(const mdns_t *m) {
  return (m->count >= 32) ? 0xFFFFFFFFu : (BIT(m->count) - 1u);
}

static uint32_t shared_mask(const mdns_t *m) {
  uint32_t mask = 0;
  uint8_t i;
  for (i = 0; i < m->count; i++) {
    if (is_shared(&m->records[i]))
      mask |= BIT(i);
  }
  return mask;
}

/* Index of the first unique record carrying the same name as record i */
static uint8_t name_rep(const mdns_t *m, uint8_t i) {
  uint8_t j;
  for (j = 0; j < i; j++) {
    if (!is_shared(&m->records[j]) &&
        dns_dotted_equal(m->records[j].name, m->records[i].name))
      return j;
  }
  return i;
}

/* ── Record matching ── */

static int txt_equals(const char *const *txt, const uint8_t *d, uint16_t n) {
  uint16_t pos = 0;
  int k = 0;
  if (txt) {
    for (; txt[k]; k++) {
      size_t l = strlen(txt[k]);
      if ((uint32_t)pos + 1 + l > n || d[pos] != l ||
          memcmp(d + pos + 1, txt[k], l) != 0)
        return 0;
      pos = (uint16_t)(pos + 1 + l);
    }
  }
  if (k == 0)
    return n == 1 && d[0] == 0;
  return pos == n;
}

/* True if the received RR is exactly our record (name, type, rdata) */
static int rr_matches(const mdns_t *m, const mdns_record_t *r,
                      const uint8_t *msg, uint16_t len, const dns_rr_t *rr) {
  const uint8_t *d = msg + rr->rdata_off;
  if (rr->type != r->type || !dns_name_equals(msg, len, rr->name_off, r->name))
    return 0;
  switch (r->type) {
#if NET_USE_IPV4
  case DNS_TYPE_A:
    return rr->rdlen == 4 && net_read32be(d) == rec_addr(m, r);
#endif
  case DNS_TYPE_PTR:
    return dns_name_equals(msg, len, rr->rdata_off, r->rdata.ptr);
  case DNS_TYPE_SRV:
    return rr->rdlen >= 7 && net_read16be(d) == r->rdata.srv.priority &&
           net_read16be(d + 2) == r->rdata.srv.weight &&
           net_read16be(d + 4) == r->rdata.srv.port &&
           dns_name_equals(msg, len, (uint16_t)(rr->rdata_off + 6),
                           r->rdata.srv.target);
  case DNS_TYPE_TXT:
    return txt_equals(r->rdata.txt, d, rr->rdlen);
#if NET_USE_IPV6
  case DNS_TYPE_AAAA: {
    const uint8_t *addrs[NET_IPV6_ADDRS];
    uint8_t n = aaaa_addrs(m, r, addrs), k;
    for (k = 0; k < n && rr->rdlen == 16; k++) {
      if (memcmp(d, addrs[k], 16) == 0)
        return 1;
    }
    return 0;
  }
#endif
  default:
    return 0;
  }
}

/* ── Message building ── */

typedef struct {
#if NET_USE_IPV4
  uint32_t ip; /* destination IPv4 */
#endif
  const uint8_t *mac; /* destination MAC, NULL = the group's MAC */
  uint16_t port;      /* destination port */
#if NET_USE_IPV6
  const uint8_t *ip6; /* destination IPv6; NULL = IPv4 in a dual stack */
#endif
} dest_t;

typedef struct {
  dns_writer_t w;
  uint16_t qd, an, ns, ar;
} pkt_t;

typedef struct {
  const dest_t *dest;
  uint16_t id;
  uint8_t legacy;    /* RFC 6762 §6.7: echo question, cap TTL, no flush bit */
  uint8_t goodbye;   /* TTL 0 */
  const char *qname; /* legacy: question to repeat */
  uint16_t qtype;
} resp_opts_t;

#if NET_USE_IPV4
static const dest_t mcast_dest = {.ip = MDNS_GROUP, .port = MDNS_PORT};
#endif
#if NET_USE_IPV6
static const dest_t mcast6_dest = {.port = MDNS_PORT, .ip6 = mdns_group6};
#endif

static const dest_t *family_group(uint8_t family) {
#if NET_USE_IPV4 && NET_USE_IPV6
  return family == MDNS_FAMILY_V6 ? &mcast6_dest : &mcast_dest;
#elif NET_USE_IPV6
  (void)family;
  return &mcast6_dest;
#else
  (void)family;
  return &mcast_dest;
#endif
}

static int pkt_begin(mdns_t *m, pkt_t *p, const dest_t *d, uint16_t id,
                     uint16_t flags) {
  uint16_t off = BY_FAMILY(d, UDP_PAYLOAD_OFFSET, UDP6_PAYLOAD_OFFSET);
  uint16_t cap =
      (m->net->tx.capacity > off) ? (uint16_t)(m->net->tx.capacity - off) : 0;
  dns_writer_init(&p->w, m->net->tx.buf + off, cap);
  p->qd = p->an = p->ns = p->ar = 0;
  return dns_write_header(&p->w, id, flags, 0, 0, 0, 0);
}

/* REQ-MDNS-001, 006: from port 5353, IP TTL or Hop Limit 255 (RFC 6762
 * §11) */
static void pkt_send(mdns_t *m, pkt_t *p, const dest_t *d) {
  uint8_t mac[6];
  const uint8_t *dst_mac = d->mac;
  if (!dst_mac) {
    BY_FAMILY(d, ipv4_mcast_mac(MDNS_GROUP, mac), ipv6_mcast_mac(d->ip6, mac));
    dst_mac = mac;
  }
  dns_set_counts(p->w.buf, p->qd, p->an, p->ns, p->ar);
  (void)BY_FAMILY(d,
                  udp_send_inplace(m->net, d->ip, dst_mac, MDNS_PORT, d->port,
                                   p->w.len, MDNS_IP_TTL),
                  udp6_send_inplace(m->net, d->ip6, dst_mac, MDNS_PORT, d->port,
                                    p->w.len, MDNS_IP_TTL));
}

static int write_txt(dns_writer_t *w, const char *const *txt) {
  int k = 0;
  if (txt) {
    for (; txt[k]; k++) {
      uint8_t l = (uint8_t)strlen(txt[k]);
      if (dns_write_bytes(w, &l, 1) < 0 ||
          dns_write_bytes(w, (const uint8_t *)txt[k], l) < 0)
        return -1;
    }
  }
  if (k == 0) { /* REQ-DNSSD-012: empty TXT is a single zero byte */
    uint8_t zero = 0;
    return dns_write_bytes(w, &zero, 1);
  }
  return 0;
}

/* Write one resource record (for AAAA, the address @p a6); on overflow
 * nothing is left behind. */
static int write_one(mdns_t *m, dns_writer_t *w, const mdns_record_t *r,
                     uint32_t ttl, uint16_t class_, const uint8_t *a6) {
  dns_writer_mark_t mark = dns_writer_mark(w);
  int err;
  (void)m; /* used by A records only */
  (void)a6;
  if (dns_write_name(w, r->name) < 0 || dns_write_u16(w, r->type) < 0 ||
      dns_write_u16(w, class_) < 0 || dns_write_u32(w, ttl) < 0)
    goto fail;
  uint16_t rdlen_pos = w->len;
  if (dns_write_u16(w, 0) < 0)
    goto fail;
  switch (r->type) {
#if NET_USE_IPV4
  case DNS_TYPE_A:
    err = dns_write_u32(w, rec_addr(m, r));
    break;
#endif
  case DNS_TYPE_PTR:
    err = dns_write_name(w, r->rdata.ptr);
    break;
  case DNS_TYPE_SRV:
    err = (dns_write_u16(w, r->rdata.srv.priority) < 0 ||
           dns_write_u16(w, r->rdata.srv.weight) < 0 ||
           dns_write_u16(w, r->rdata.srv.port) < 0)
              ? -1
              : dns_write_name(w, r->rdata.srv.target);
    break;
  case DNS_TYPE_TXT:
    err = write_txt(w, r->rdata.txt);
    break;
#if NET_USE_IPV6
  case DNS_TYPE_AAAA:
    err = dns_write_bytes(w, a6, 16);
    break;
#endif
  default:
    err = -1;
    break;
  }
  if (err < 0)
    goto fail;
  net_write16be(w->buf + rdlen_pos, (uint16_t)(w->len - rdlen_pos - 2));
  return 0;
fail:
  dns_writer_rollback(w, mark);
  return -1;
}

/* Write a record's RRs — one, or for an AAAA record one per address.
 * @return RRs written (0 if an AAAA record has no usable address), or -1
 *         on overflow (then nothing is left behind). */
static int write_rr(mdns_t *m, dns_writer_t *w, const mdns_record_t *r,
                    uint32_t ttl, uint16_t class_) {
#if NET_USE_IPV6
  if (r->type == DNS_TYPE_AAAA) {
    const uint8_t *addrs[NET_IPV6_ADDRS];
    dns_writer_mark_t mark = dns_writer_mark(w);
    uint8_t n = aaaa_addrs(m, r, addrs), k;
    for (k = 0; k < n; k++) {
      if (write_one(m, w, r, ttl, class_, addrs[k]) < 0) {
        dns_writer_rollback(w, mark);
        return -1;
      }
    }
    return n;
  }
#endif
  return write_one(m, w, r, ttl, class_, NULL) < 0 ? -1 : 1;
}

/* NSEC for the unique name of record @p r, restricted form (RFC 6762
 * §6.1): Next Domain Name = the name itself (a 2-byte pointer once
 * compressed), one bitmap block (0) listing the types the name has. */
static int write_nsec(mdns_t *m, dns_writer_t *w, const mdns_record_t *r,
                      uint32_t ttl, uint16_t class_) {
  uint8_t bitmap[8]; /* types 0..63 — all we can hold */
  uint8_t used = 0, j;
  dns_writer_mark_t mark = dns_writer_mark(w);
  memset(bitmap, 0, sizeof(bitmap));
  for (j = 0; j < m->count; j++) {
    const mdns_record_t *o = &m->records[j];
    if (is_shared(o) || o->type >= 64 || !dns_dotted_equal(o->name, r->name))
      continue;
    bitmap[o->type >> 3] |= (uint8_t)(0x80u >> (o->type & 7));
    if ((uint8_t)((o->type >> 3) + 1) > used)
      used = (uint8_t)((o->type >> 3) + 1);
  }
  if (dns_write_name(w, r->name) < 0 || dns_write_u16(w, DNS_TYPE_NSEC) < 0 ||
      dns_write_u16(w, class_) < 0 || dns_write_u32(w, ttl) < 0)
    goto fail;
  uint16_t rdlen_pos = w->len;
  uint8_t block[2];
  block[0] = 0;    /* window block 0 */
  block[1] = used; /* bitmap length */
  if (dns_write_u16(w, 0) < 0 || dns_write_name(w, r->name) < 0 ||
      dns_write_bytes(w, block, 2) < 0 || dns_write_bytes(w, bitmap, used) < 0)
    goto fail;
  net_write16be(w->buf + rdlen_pos, (uint16_t)(w->len - rdlen_pos - 2));
  return 1;
fail:
  dns_writer_rollback(w, mark);
  return -1;
}

/* ── Responses (announcements, answers, goodbyes) ── */

static uint32_t rr_ttl(const resp_opts_t *o, uint32_t ttl) {
  if (o->goodbye)
    return 0;
  if (o->legacy && ttl > MDNS_LEGACY_TTL_MAX)
    return MDNS_LEGACY_TTL_MAX;
  return ttl;
}

static uint16_t rr_class(const resp_opts_t *o, const mdns_record_t *r) {
  /* RFC 6762 §10.2: cache-flush bit on unique records, never in legacy */
  return (uint16_t)(DNS_CLASS_IN |
                    ((!o->legacy && !is_shared(r)) ? DNS_CLASS_TOPBIT : 0));
}

static void resp_begin(mdns_t *m, pkt_t *p, const resp_opts_t *o) {
  /* REQ-MDNS-004, 005: QR + AA, ID 0 on multicast */
  pkt_begin(m, p, o->dest, o->id, DNS_FLAG_QR | DNS_FLAG_AA);
  if (o->legacy && o->qname) {
    if (dns_write_name(&p->w, o->qname) == 0 &&
        dns_write_u16(&p->w, o->qtype) == 0 &&
        dns_write_u16(&p->w, DNS_CLASS_IN) == 0)
      p->qd = 1;
  }
}

/* Add an answer; when the packet is full, send it and start another
 * (REQ-MDNS-042, REQ-DNSSD-030).  A record too big for any packet is
 * dropped. */
static int write_answer(mdns_t *m, pkt_t *p, const resp_opts_t *o,
                        const mdns_record_t *r, int nsec) {
  return nsec ? write_nsec(m, &p->w, r, rr_ttl(o, r->ttl), rr_class(o, r))
              : write_rr(m, &p->w, r, rr_ttl(o, r->ttl), rr_class(o, r));
}

static void add_answer(mdns_t *m, pkt_t *p, const resp_opts_t *o,
                       const mdns_record_t *r, int nsec) {
  int n = write_answer(m, p, o, r, nsec);
  if (n >= 0) {
    p->an = (uint16_t)(p->an + n);
    return;
  }
  if (p->an == 0)
    return;
  pkt_send(m, p, o->dest);
  resp_begin(m, p, o);
  n = write_answer(m, p, o, r, nsec);
  if (n > 0)
    p->an = (uint16_t)(p->an + n);
}

static void send_response(mdns_t *m, uint32_t answers, uint32_t meta,
                          uint32_t nsec, uint32_t additionals,
                          const resp_opts_t *o) {
  pkt_t p;
  uint8_t i, j;
  resp_begin(m, &p, o);

  for (i = 0; i < m->count; i++) {
    if (answers & BIT(i))
      add_answer(m, &p, o, &m->records[i], 0);
  }

  /* RFC 6762 §6.1: negative answers for types our names don't have */
  for (i = 0; i < m->count; i++) {
    if (nsec & BIT(i))
      add_answer(m, &p, o, &m->records[i], 1);
  }

  /* REQ-DNSSD-014, 015: one PTR per distinct service type */
  for (i = 0; i < m->count; i++) {
    if (!(meta & BIT(i)))
      continue;
    for (j = 0; j < i; j++) {
      if ((meta & BIT(j)) &&
          dns_dotted_equal(m->records[j].name, m->records[i].name))
        break;
    }
    if (j < i)
      continue;
    mdns_record_t svc;
    memset(&svc, 0, sizeof(svc));
    svc.type = DNS_TYPE_PTR;
    svc.ttl = MDNS_TTL_OTHER;
    svc.name = MDNS_META_QUERY;
    svc.rdata.ptr = m->records[i].name;
    add_answer(m, &p, o, &svc, 0);
  }

  /* REQ-DNSSD-007, 008: additionals are best effort in the last packet */
  for (i = 0; i < m->count; i++) {
    const mdns_record_t *r = &m->records[i];
    int n;
    if ((additionals & BIT(i)) &&
        (n = write_rr(m, &p.w, r, rr_ttl(o, r->ttl), rr_class(o, r))) > 0)
      p.ar = (uint16_t)(p.ar + n);
  }

  if (p.an > 0)
    pkt_send(m, &p, o->dest);
}

/* RFC 6763 §12: PTR → SRV + TXT of the instance; SRV → A of the target */
static uint32_t additionals_for(const mdns_t *m, uint32_t answers) {
  uint32_t add = 0;
  uint8_t i, j;
  for (i = 0; i < m->count; i++) {
    const mdns_record_t *r = &m->records[i];
    if (!(answers & BIT(i)) || r->type != DNS_TYPE_PTR)
      continue;
    for (j = 0; j < m->count; j++) {
      const mdns_record_t *s = &m->records[j];
      if ((s->type == DNS_TYPE_SRV || s->type == DNS_TYPE_TXT) &&
          dns_dotted_equal(s->name, r->rdata.ptr))
        add |= BIT(j);
    }
  }
  uint32_t have = answers | add;
  for (i = 0; i < m->count; i++) {
    const mdns_record_t *r = &m->records[i];
    if (!(have & BIT(i)) || r->type != DNS_TYPE_SRV)
      continue;
    for (j = 0; j < m->count; j++) {
      const mdns_record_t *s = &m->records[j];
      if ((s->type == DNS_TYPE_A
#if NET_USE_IPV6
           || s->type == DNS_TYPE_AAAA
#endif
           ) &&
          dns_dotted_equal(s->name, r->rdata.srv.target))
        add |= BIT(j);
    }
  }
#if NET_USE_IPV6
  /* RFC 6762 §6.2: an answer with one address family's records carries
   * the name's records of the other family as additionals */
  for (i = 0; i < m->count; i++) {
    const mdns_record_t *r = &m->records[i];
    if (!(answers & BIT(i)) ||
        (r->type != DNS_TYPE_A && r->type != DNS_TYPE_AAAA))
      continue;
    for (j = 0; j < m->count; j++) {
      const mdns_record_t *s = &m->records[j];
      if ((s->type == DNS_TYPE_A || s->type == DNS_TYPE_AAAA) &&
          s->type != r->type && dns_dotted_equal(s->name, r->name))
        add |= BIT(j);
    }
  }
#endif
  return add & ~answers;
}

/* Send a multicast response to the groups of @p families */
static void send_to_groups(mdns_t *m, uint8_t families, uint32_t answers,
                           uint32_t service_types, uint32_t nsec,
                           uint8_t goodbye) {
  uint8_t family;
  resp_opts_t o;
  memset(&o, 0, sizeof(o));
  o.goodbye = goodbye;
  for (family = MDNS_FAMILY_V4; family <= MDNS_FAMILY_V6; family <<= 1) {
    if (!(families & family))
      continue;
    o.dest = family_group(family);
    send_response(m, answers, service_types, nsec, additionals_for(m, answers),
                  &o);
  }
}

static void announce(mdns_t *m, int goodbye) {
  send_to_groups(m, m->announce_families, all_mask(m), 0, 0, (uint8_t)goodbye);
}

/* ── Probing (RFC 6762 §8.1) ── */

/* One probe for the unique names whose representative bits are in
 * @p names: an ANY/QU question per name, their records in Authority. */
static int build_probe(mdns_t *m, pkt_t *p, const dest_t *d, uint32_t names) {
  uint8_t i;
  if (pkt_begin(m, p, d, 0, 0) < 0)
    return -1;
  for (i = 0; i < m->count; i++) {
    if (!(names & BIT(i)))
      continue;
    if (dns_write_name(&p->w, m->records[i].name) < 0 ||
        dns_write_u16(&p->w, DNS_TYPE_ANY) < 0 ||
        dns_write_u16(&p->w, DNS_CLASS_IN | DNS_CLASS_TOPBIT) < 0)
      return -1;
    p->qd++;
  }
  for (i = 0; i < m->count; i++) {
    const mdns_record_t *r = &m->records[i];
    if (is_shared(r) || !(names & BIT(name_rep(m, i))))
      continue;
    int n = write_rr(m, &p->w, r, r->ttl, DNS_CLASS_IN);
    if (n < 0)
      return -1;
    p->ns = (uint16_t)(p->ns + n);
  }
  return 0;
}

static void send_probes_to(mdns_t *m, const dest_t *d) {
  uint32_t pending = 0;
  uint8_t i;
  pkt_t p;
  for (i = 0; i < m->count; i++) {
    if (!is_shared(&m->records[i]) && name_rep(m, i) == i)
      pending |= BIT(i);
  }
  /* Greedily pack names into as few probes as the TX buffer allows */
  while (pending) {
    uint32_t chosen = 0;
    for (i = 0; i < m->count; i++) {
      if (!(pending & BIT(i)))
        continue;
      if (build_probe(m, &p, d, chosen | BIT(i)) == 0)
        chosen |= BIT(i);
      else if (chosen == 0)
        pending &= ~BIT(i); /* cannot fit even alone */
      else
        break;
    }
    if (!chosen)
      break;
    build_probe(m, &p, d, chosen);
    pkt_send(m, &p, d);
    pending &= ~chosen;
  }
}

/* RFC 6762 §8.1: probe on every family the host answers on */
static void send_probes(mdns_t *m) {
  uint8_t family;
  for (family = MDNS_FAMILY_V4; family <= MDNS_FAMILY_V6; family <<= 1) {
    if (ALL_FAMILIES & family)
      send_probes_to(m, family_group(family));
  }
}

/* ── State machine ── */

static void enter_conflict(mdns_t *m, uint8_t index) {
  m->state = MDNS_STATE_CONFLICT;
  m->timer_ms = 0;
  memset(&m->pending, 0, sizeof(m->pending));
  if (m->on_conflict) /* REQ-MDNS-019, 020: may rename and mdns_start() */
    m->on_conflict(m, index, m->ctx);
}

static void timer_fired(mdns_t *m) {
  if (m->state == MDNS_STATE_PROBING) {
    if (m->step < MDNS_PROBE_COUNT) {
      send_probes(m); /* REQ-MDNS-016, 018 */
      m->step++;
      m->timer_ms = MDNS_PROBE_WAIT_MS;
      return;
    }
    /* REQ-MDNS-021: no conflict after three probes */
    m->state = MDNS_STATE_ANNOUNCING;
    m->step = 0;
#if NET_USE_IPV4
    igmp_report(m->net, MDNS_GROUP); /* RFC 2236 §3: repeat the report */
#endif
  }
  if (m->state == MDNS_STATE_ANNOUNCING) {
    announce(m, 0); /* REQ-MDNS-022, 023 */
    if (++m->step >= MDNS_ANNOUNCE_COUNT)
      m->state = MDNS_STATE_RUNNING;
    else
      m->timer_ms = MDNS_ANNOUNCE_WAIT_MS;
  }
}

static void send_pending(mdns_t *m) {
  mdns_pending_t owed = m->pending;
  memset(&m->pending, 0, sizeof(m->pending));
  send_to_groups(m, owed.families, owed.answers, owed.service_types, owed.nsec,
                 0);
}

/* Shared records: aggregated and delayed 20-120 ms (RFC 6762 §6) */
static void owe_response(mdns_t *m, uint8_t family, uint32_t answers,
                         uint32_t service_types, uint32_t nsec) {
  mdns_pending_t *p = &m->pending;
  p->families |= family;
  p->answers |= answers;
  p->service_types |= service_types;
  p->nsec |= nsec;
  if (!p->timer_ms)
    p->timer_ms = MDNS_RESP_DELAY_MIN_MS +
                  net_random_below(m->net, MDNS_RESP_DELAY_MAX_MS -
                                               MDNS_RESP_DELAY_MIN_MS + 1);
}

/* ── Conflict detection (RFC 6762 §8.1, §9) ── */

static void check_conflicts(mdns_t *m, const uint8_t *msg, uint16_t len) {
  uint16_t qd = net_read16be(msg + DNS_OFF_QDCOUNT);
  uint32_t nrr = (uint32_t)net_read16be(msg + DNS_OFF_ANCOUNT) +
                 net_read16be(msg + DNS_OFF_NSCOUNT) +
                 net_read16be(msg + DNS_OFF_ARCOUNT);
  int off = DNS_HDR_SIZE;
  uint32_t k;
  dns_question_t q;
  dns_rr_t rr;

  for (k = 0; k < qd; k++) {
    off = dns_read_question(msg, len, (uint16_t)off, &q);
    if (off < 0)
      return;
  }
  for (k = 0; k < nrr; k++) {
    int name_idx = -1, type_idx = -1, exact = 0;
    uint8_t i;
    off = dns_read_rr(msg, len, (uint16_t)off, &rr);
    if (off < 0)
      return;
    if (rr.ttl == 0 || (rr.class_ & DNS_CLASS_MASK) != DNS_CLASS_IN)
      continue; /* goodbyes and other classes never conflict */
    for (i = 0; i < m->count; i++) {
      const mdns_record_t *r = &m->records[i];
      if (is_shared(r) || !dns_name_equals(msg, len, rr.name_off, r->name))
        continue;
      if (name_idx < 0)
        name_idx = i;
      if (rr.type == r->type) {
        if (type_idx < 0)
          type_idx = i;
        if (rr_matches(m, r, msg, len, &rr))
          exact = 1;
      }
    }
    if (exact || name_idx < 0)
      continue;
    /* Probing: any record under a name we want is a conflict.  Running:
     * only a same-type record with different data (RFC 6762 §9). */
    if (m->state == MDNS_STATE_PROBING) {
      enter_conflict(m, (uint8_t)name_idx);
      return;
    }
    if (type_idx >= 0) {
      enter_conflict(m, (uint8_t)type_idx);
      return;
    }
  }
}

net_err_t mdns_init(mdns_t *m, net_t *net, const mdns_record_t *records,
                    uint8_t count, mdns_conflict_fn_t on_conflict, void *ctx) {
  uint8_t i;
  if (!m || !net || !records || count == 0 || count > MDNS_MAX_RECORDS)
    return NET_ERR_INVALID_PARAM;
  for (i = 0; i < count; i++) {
    const mdns_record_t *r = &records[i];
    if (!r->name || dns_name_wire_len(r->name) < 0)
      return NET_ERR_INVALID_PARAM;
    switch (r->type) {
#if NET_USE_IPV4
    case DNS_TYPE_A:
#endif
#if NET_USE_IPV6
    case DNS_TYPE_AAAA:
#endif
      break;
    case DNS_TYPE_PTR:
      if (!r->rdata.ptr || dns_name_wire_len(r->rdata.ptr) < 0)
        return NET_ERR_INVALID_PARAM;
      break;
    case DNS_TYPE_SRV:
      if (!r->rdata.srv.target || dns_name_wire_len(r->rdata.srv.target) < 0)
        return NET_ERR_INVALID_PARAM;
      break;
    case DNS_TYPE_TXT:
      if (r->rdata.txt) {
        const char *const *t;
        for (t = r->rdata.txt; *t; t++) {
          if (strlen(*t) > 255) /* REQ-DNSSD-032 */
            return NET_ERR_INVALID_PARAM;
        }
      }
      break;
    default:
      return NET_ERR_INVALID_PARAM;
    }
  }

  memset(m, 0, sizeof(*m));
  m->net = net;
  m->records = records;
  m->count = count;
  m->on_conflict = on_conflict;
  m->ctx = ctx;
  m->state = MDNS_STATE_STOPPED;
  return NET_OK;
}

void mdns_start(mdns_t *m) {
#if NET_USE_IPV4
  igmp_join(m->net, MDNS_GROUP); /* REQ-MDNS-002 */
#endif
#if NET_USE_IPV6
  ipv6_mcast_join(m->net, mdns_group6); /* RFC 6762 §20, reported by MLD */
#endif
  m->announce_families = ALL_FAMILIES;
  memset(&m->pending, 0, sizeof(m->pending));
  m->state = MDNS_STATE_PROBING;
  m->step = 0;
  m->timer_ms = net_random_below(m->net, MDNS_PROBE_WAIT_MS + 1); /* -017 */
}

static int silent(const mdns_t *m) {
  return m->state == MDNS_STATE_STOPPED || m->state == MDNS_STATE_CONFLICT;
}

void mdns_tick(mdns_t *m, uint32_t elapsed_ms) {
  if (silent(m))
    return;
  if (m->pending.timer_ms && net_countdown(&m->pending.timer_ms, elapsed_ms))
    send_pending(m);
  if ((m->state == MDNS_STATE_PROBING || m->state == MDNS_STATE_ANNOUNCING) &&
      net_countdown(&m->timer_ms, elapsed_ms))
    timer_fired(m);
}

/* What a query asks of us; record sets as bitmasks */
typedef struct {
  uint32_t answers;
  uint32_t service_types; /* answers to the DNS-SD meta-query */
  uint32_t nsec;          /* our unique names, asked for a type they lack */
  const char *qname;      /* the first question we answer, for legacy */
  uint16_t qtype;
  uint8_t all_unicast; /* every question had the QU bit */
} wanted_t;

static uint8_t from_family(const dest_t *from) {
  return BY_FAMILY(from, MDNS_FAMILY_V4, MDNS_FAMILY_V6);
}

static int is_in_class(uint16_t class_) {
  uint16_t c = class_ & DNS_CLASS_MASK;
  return c == DNS_CLASS_IN || c == DNS_CLASS_ANY;
}

/* One question: our records it asks for, into @p w */
static void match_question(const mdns_t *m, const uint8_t *msg, uint16_t len,
                           const dns_question_t *q, wanted_t *w) {
  uint32_t hit = 0, types = 0, nsec = 0;
  uint8_t i;
  for (i = 0; i < m->count; i++) {
    const mdns_record_t *r = &m->records[i];
    if ((q->type == DNS_TYPE_ANY || q->type == r->type) &&
        dns_name_equals(msg, len, q->name_off, r->name))
      hit |= BIT(i);
  }
  if ((q->type == DNS_TYPE_PTR || q->type == DNS_TYPE_ANY) &&
      dns_name_equals(msg, len, q->name_off, MDNS_META_QUERY)) {
    for (i = 0; i < m->count; i++) {
      if (is_service_type(&m->records[i]))
        types |= BIT(i);
    }
  }
  if (!(hit | types) && q->type != DNS_TYPE_ANY) {
    /* One of our unique names, a type it doesn't have (RFC 6762 §6.1) */
    for (i = 0; i < m->count && !nsec; i++) {
      const mdns_record_t *r = &m->records[i];
      if (!is_shared(r) && dns_name_equals(msg, len, q->name_off, r->name))
        nsec = BIT(name_rep(m, i));
    }
  }
  if (!(hit | types | nsec))
    return;
  w->answers |= hit;
  w->service_types |= types;
  w->nsec |= nsec;
  if (!(q->class_ & DNS_CLASS_TOPBIT))
    w->all_unicast = 0;
  if (!w->qname) {
    w->qtype = q->type;
    w->qname = MDNS_META_QUERY;
    for (i = 0; i < m->count; i++) {
      if ((hit | nsec) & BIT(i)) {
        w->qname = m->records[i].name;
        break;
      }
    }
  }
}

/* REQ-MDNS-029, RFC 6762 §7.1: drop what the querier already knows, from
 * the answer section at @p off */
static void suppress_known_answers(const mdns_t *m, const uint8_t *msg,
                                   uint16_t len, int off, wanted_t *w) {
  uint16_t an = net_read16be(msg + DNS_OFF_ANCOUNT), k;
  dns_rr_t rr;
  uint8_t i;
  for (k = 0; k < an; k++) {
    if ((off = dns_read_rr(msg, len, (uint16_t)off, &rr)) < 0)
      return;
    if ((rr.class_ & DNS_CLASS_MASK) != DNS_CLASS_IN)
      continue;
    for (i = 0; i < m->count; i++) {
      const mdns_record_t *r = &m->records[i];
      if ((w->answers & BIT(i)) && rr.ttl >= r->ttl / 2 &&
          rr_matches(m, r, msg, len, &rr))
        w->answers &= ~BIT(i);
    }
    if (w->service_types && rr.type == DNS_TYPE_PTR &&
        rr.ttl >= MDNS_TTL_OTHER / 2 &&
        dns_name_equals(msg, len, rr.name_off, MDNS_META_QUERY)) {
      for (i = 0; i < m->count; i++) {
        if ((w->service_types & BIT(i)) &&
            dns_name_equals(msg, len, rr.rdata_off, m->records[i].name))
          w->service_types &= ~BIT(i);
      }
    }
  }
}

static int wants_anything(const wanted_t *w) {
  return (w->answers | w->service_types | w->nsec) != 0;
}

static int has_address(const dest_t *from) {
  return BY_FAMILY(from, from->ip != 0, !ipv6_is_unspecified(from->ip6));
}

/* RFC 6762 §6, §6.7: legacy unicast, unicast (QU), at once, or delayed */
static void answer(mdns_t *m, const dest_t *from, uint16_t id,
                   const wanted_t *w) {
  resp_opts_t o;
  memset(&o, 0, sizeof(o));
  o.dest = family_group(from_family(from));

  if (from->port != MDNS_PORT) {
    /* Legacy: to the querier's port with its ID and question, TTL <= 10 s,
     * no cache-flush bits */
    if (!has_address(from))
      return;
    o.dest = from;
    o.id = id;
    o.legacy = 1;
    o.qname = w->qname;
    o.qtype = w->qtype;
  } else if (w->all_unicast && has_address(from)) {
    o.dest = from; /* REQ-MDNS-028 */
  } else if (w->service_types || (w->answers & shared_mask(m))) {
    owe_response(m, from_family(from), w->answers, w->service_types, w->nsec);
    return;
  }
  send_response(m, w->answers, w->service_types, w->nsec,
                additionals_for(m, w->answers), &o);
}

/* A query: answered unless malformed (REQ-MDNS-041) or while probing */
static void query_input(mdns_t *m, const dest_t *from, const uint8_t *msg,
                        uint16_t len) {
  uint16_t qd = net_read16be(msg + DNS_OFF_QDCOUNT), k;
  int off = DNS_HDR_SIZE;
  dns_question_t q;
  wanted_t w;

  memset(&w, 0, sizeof(w));
  w.all_unicast = 1;
  for (k = 0; k < qd; k++) {
    if ((off = dns_read_question(msg, len, (uint16_t)off, &q)) < 0)
      return;
    if (is_in_class(q.class_))
      match_question(m, msg, len, &q, &w);
  }
  if (!wants_anything(&w))
    return;
  suppress_known_answers(m, msg, len, off, &w);
  if (wants_anything(&w))
    answer(m, from, net_read16be(msg + DNS_OFF_ID), &w);
}

static void input(mdns_t *m, const dest_t *from, const uint8_t *msg,
                  uint16_t len) {
  uint16_t flags;
  if (silent(m) || len < DNS_HDR_SIZE)
    return;
  flags = net_read16be(msg + DNS_OFF_FLAGS);
  if (flags & DNS_FLAG_QR)
    check_conflicts(m, msg, len);
  else if ((flags & DNS_OPCODE_MASK) == 0 && m->state != MDNS_STATE_PROBING)
    query_input(m, from, msg, len);
}

#if NET_USE_IPV4
void mdns_input(mdns_t *m, uint32_t src_ip, const uint8_t *src_mac,
                uint16_t src_port, const uint8_t *msg, uint16_t len) {
  dest_t from;
  memset(&from, 0, sizeof(from));
  from.ip = src_ip;
  from.mac = src_mac;
  from.port = src_port;
  input(m, &from, msg, len);
}
#endif

#if NET_USE_IPV6
void mdns_input6(mdns_t *m, const uint8_t *src_ip, const uint8_t *src_mac,
                 uint16_t src_port, const uint8_t *msg, uint16_t len) {
  dest_t from;
  memset(&from, 0, sizeof(from));
  from.ip6 = src_ip;
  from.mac = src_mac;
  from.port = src_port;
  input(m, &from, msg, len);
}

void mdns_readdress6(mdns_t *m) {
  if (m->state == MDNS_STATE_ANNOUNCING) {
    /* Announce again from the start, IPv6 included, without cutting the
     * sequence other families are in */
    m->announce_families |= MDNS_FAMILY_V6;
    m->step = 0;
  } else if (m->state == MDNS_STATE_RUNNING) {
    m->state = MDNS_STATE_ANNOUNCING;
    m->step = 0;
    m->timer_ms = 0;
    m->announce_families = MDNS_FAMILY_V6;
  }
}
#endif

void mdns_stop(mdns_t *m) {
  if (m->state == MDNS_STATE_STOPPED)
    return;
  /* REQ-MDNS-032, 033, REQ-DNSSD-018: withdraw what was announced */
  m->announce_families = ALL_FAMILIES;
  if (m->state == MDNS_STATE_ANNOUNCING || m->state == MDNS_STATE_RUNNING)
    announce(m, 1);
#if NET_USE_IPV4
  igmp_leave(m->net, MDNS_GROUP);
#endif
#if NET_USE_IPV6
  ipv6_mcast_leave(m->net, mdns_group6);
#endif
  m->state = MDNS_STATE_STOPPED;
  m->timer_ms = 0;
  memset(&m->pending, 0, sizeof(m->pending));
}
