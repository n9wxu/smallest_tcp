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
#include "igmp.h"
#include "ipv4.h"
#include "net_endian.h"
#include "udp.h"
#include <string.h>

#if NET_MAX_MCAST_GROUPS < 1
#error "mDNS needs NET_MAX_MCAST_GROUPS >= 1 to receive 224.0.0.251"
#endif

#define BIT(i) ((uint32_t)1u << (i))

/* ── Small helpers ────────────────────────────────────────────────── */

/* xorshift32: jitter for probe and response timing (RFC 6762 §6, §8.1) */
static uint32_t rnd(mdns_t *m) {
  uint32_t x = m->rng;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  m->rng = x;
  return x;
}

/* Uniform value in [0, n) by scaling, not '%': Cortex-M0 has no divide
 * instruction and a modulo would link libgcc's __udivsi3. */
static uint32_t rnd_below(mdns_t *m, uint32_t n) {
  return ((rnd(m) & 0xFFFFu) * n) >> 16;
}

/* PTR records are shared (many hosts advertise the same service type);
 * A, SRV and TXT records are unique to this host (RFC 6762 §2). */
static int is_shared(const mdns_record_t *r) { return r->type == DNS_TYPE_PTR; }

/* A PTR whose owner is a service type ("_x._tcp.local") */
static int is_service_type(const mdns_record_t *r) {
  return r->type == DNS_TYPE_PTR && r->name[0] == '_';
}

static uint32_t rec_addr(const mdns_t *m, const mdns_record_t *r) {
  return r->rdata.a ? r->rdata.a : m->net->ipv4_addr;
}

static char lower(char c) {
  return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

/* Case-insensitive comparison of two dotted names; trailing dot ignored */
static int names_equal(const char *a, const char *b) {
  for (;; a++, b++) {
    char ca = (a[0] == '.' && a[1] == '\0') ? '\0' : lower(a[0]);
    char cb = (b[0] == '.' && b[1] == '\0') ? '\0' : lower(b[0]);
    if (ca != cb)
      return 0;
    if (ca == '\0')
      return 1;
  }
}

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
        names_equal(m->records[j].name, m->records[i].name))
      return j;
  }
  return i;
}

/* ── Record matching ──────────────────────────────────────────────── */

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
  case DNS_TYPE_A:
    return rr->rdlen == 4 && net_read32be(d) == rec_addr(m, r);
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
  default:
    return 0;
  }
}

/* ── Message building ─────────────────────────────────────────────── */

typedef struct {
  uint32_t ip;        /* destination IP */
  const uint8_t *mac; /* destination MAC, NULL = 224.0.0.251's MAC */
  uint16_t port;      /* destination port */
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

static const dest_t mcast_dest = {MDNS_GROUP, NULL, MDNS_PORT};

static int pkt_begin(mdns_t *m, pkt_t *p, uint16_t id, uint16_t flags) {
  uint16_t cap = (m->net->tx.capacity > UDP_PAYLOAD_OFFSET)
                     ? (uint16_t)(m->net->tx.capacity - UDP_PAYLOAD_OFFSET)
                     : 0;
  dns_writer_init(&p->w, m->net->tx.buf + UDP_PAYLOAD_OFFSET, cap);
  p->qd = p->an = p->ns = p->ar = 0;
  return dns_write_header(&p->w, id, flags, 0, 0, 0, 0);
}

static void pkt_send(mdns_t *m, pkt_t *p, const dest_t *d) {
  uint8_t mac[6];
  const uint8_t *dst_mac = d->mac;
  if (!dst_mac) {
    ipv4_mcast_mac(MDNS_GROUP, mac);
    dst_mac = mac;
  }
  dns_set_counts(p->w.buf, p->qd, p->an, p->ns, p->ar);
  /* REQ-MDNS-001, 006: port 5353, IP TTL 255 */
  udp_send_inplace(m->net, d->ip, dst_mac, MDNS_PORT, d->port, p->w.len,
                   MDNS_IP_TTL);
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

/* Write one resource record; on overflow nothing is left behind. */
static int write_rr(mdns_t *m, dns_writer_t *w, const mdns_record_t *r,
                    uint32_t ttl, uint16_t class_) {
  dns_writer_mark_t mark = dns_writer_mark(w);
  int err;
  if (dns_write_name(w, r->name) < 0 || dns_write_u16(w, r->type) < 0 ||
      dns_write_u16(w, class_) < 0 || dns_write_u32(w, ttl) < 0)
    goto fail;
  uint16_t rdlen_pos = w->len;
  if (dns_write_u16(w, 0) < 0)
    goto fail;
  switch (r->type) {
  case DNS_TYPE_A:
    err = dns_write_u32(w, rec_addr(m, r));
    break;
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

/* ── Responses (announcements, answers, goodbyes) ─────────────────── */

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
  pkt_begin(m, p, o->id, DNS_FLAG_QR | DNS_FLAG_AA);
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
static void add_answer(mdns_t *m, pkt_t *p, const resp_opts_t *o,
                       const mdns_record_t *r) {
  if (write_rr(m, &p->w, r, rr_ttl(o, r->ttl), rr_class(o, r)) == 0) {
    p->an++;
    return;
  }
  if (p->an == 0)
    return;
  pkt_send(m, p, o->dest);
  resp_begin(m, p, o);
  if (write_rr(m, &p->w, r, rr_ttl(o, r->ttl), rr_class(o, r)) == 0)
    p->an++;
}

static void send_response(mdns_t *m, uint32_t answers, uint32_t meta,
                          uint32_t additionals, const resp_opts_t *o) {
  pkt_t p;
  uint8_t i, j;
  resp_begin(m, &p, o);

  for (i = 0; i < m->count; i++) {
    if (answers & BIT(i))
      add_answer(m, &p, o, &m->records[i]);
  }

  /* REQ-DNSSD-014, 015: one PTR per distinct service type */
  for (i = 0; i < m->count; i++) {
    if (!(meta & BIT(i)))
      continue;
    for (j = 0; j < i; j++) {
      if ((meta & BIT(j)) && names_equal(m->records[j].name, m->records[i].name))
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
    add_answer(m, &p, o, &svc);
  }

  /* REQ-DNSSD-007, 008: additionals are best effort in the last packet */
  for (i = 0; i < m->count; i++) {
    const mdns_record_t *r = &m->records[i];
    if ((additionals & BIT(i)) &&
        write_rr(m, &p.w, r, rr_ttl(o, r->ttl), rr_class(o, r)) == 0)
      p.ar++;
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
          names_equal(s->name, r->rdata.ptr))
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
      if (s->type == DNS_TYPE_A && names_equal(s->name, r->rdata.srv.target))
        add |= BIT(j);
    }
  }
  return add & ~answers;
}

static void announce(mdns_t *m, int goodbye) {
  resp_opts_t o;
  memset(&o, 0, sizeof(o));
  o.dest = &mcast_dest;
  o.goodbye = (uint8_t)goodbye;
  send_response(m, all_mask(m), 0, 0, &o);
}

/* ── Probing (RFC 6762 §8.1) ──────────────────────────────────────── */

/* One probe for the unique names whose representative bits are in
 * @p names: an ANY/QU question per name, their records in Authority. */
static int build_probe(mdns_t *m, pkt_t *p, uint32_t names) {
  uint8_t i;
  if (pkt_begin(m, p, 0, 0) < 0)
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
    if (write_rr(m, &p->w, r, r->ttl, DNS_CLASS_IN) < 0)
      return -1;
    p->ns++;
  }
  return 0;
}

static void send_probes(mdns_t *m) {
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
      if (build_probe(m, &p, chosen | BIT(i)) == 0)
        chosen |= BIT(i);
      else if (chosen == 0)
        pending &= ~BIT(i); /* cannot fit even alone */
      else
        break;
    }
    if (!chosen)
      break;
    build_probe(m, &p, chosen);
    pkt_send(m, &p, &mcast_dest);
    pending &= ~chosen;
  }
}

/* ── State machine ────────────────────────────────────────────────── */

static void enter_conflict(mdns_t *m, uint8_t index) {
  m->state = MDNS_STATE_CONFLICT;
  m->timer_ms = 0;
  m->resp_timer_ms = 0;
  m->resp_answers = 0;
  m->resp_meta = 0;
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
    igmp_report(m->net, MDNS_GROUP); /* RFC 2236 §3: repeat the report */
  }
  if (m->state == MDNS_STATE_ANNOUNCING) {
    announce(m, 0); /* REQ-MDNS-022, 023 */
    if (++m->step >= MDNS_ANNOUNCE_COUNT)
      m->state = MDNS_STATE_RUNNING;
    else
      m->timer_ms = MDNS_ANNOUNCE_WAIT_MS;
  }
}

static void flush_delayed(mdns_t *m) {
  resp_opts_t o;
  uint32_t answers = m->resp_answers;
  uint32_t meta = m->resp_meta;
  m->resp_timer_ms = 0;
  m->resp_answers = 0;
  m->resp_meta = 0;
  memset(&o, 0, sizeof(o));
  o.dest = &mcast_dest;
  send_response(m, answers, meta, additionals_for(m, answers), &o);
}

/* ── Conflict detection (RFC 6762 §8.1, §9) ───────────────────────── */

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

/* ── Public API ───────────────────────────────────────────────────── */

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
    case DNS_TYPE_A:
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
  m->rng = 0x6D646E73u ^ ((uint32_t)net->mac[2] << 24) ^
           ((uint32_t)net->mac[3] << 16) ^ ((uint32_t)net->mac[4] << 8) ^
           net->mac[5] ^ net->ipv4_addr;
  if (m->rng == 0)
    m->rng = 1;
  return NET_OK;
}

void mdns_start(mdns_t *m) {
  igmp_join(m->net, MDNS_GROUP); /* REQ-MDNS-002 */
  m->state = MDNS_STATE_PROBING;
  m->step = 0;
  m->timer_ms = rnd_below(m, MDNS_PROBE_WAIT_MS + 1); /* REQ-MDNS-017 */
  m->resp_timer_ms = 0;
  m->resp_answers = 0;
  m->resp_meta = 0;
}

void mdns_tick(mdns_t *m, uint32_t elapsed_ms) {
  if (m->state == MDNS_STATE_STOPPED || m->state == MDNS_STATE_CONFLICT)
    return;
  if (m->resp_timer_ms) {
    if (m->resp_timer_ms <= elapsed_ms)
      flush_delayed(m);
    else
      m->resp_timer_ms -= elapsed_ms;
  }
  if (m->state == MDNS_STATE_PROBING || m->state == MDNS_STATE_ANNOUNCING) {
    if (m->timer_ms <= elapsed_ms) {
      m->timer_ms = 0;
      timer_fired(m);
    } else {
      m->timer_ms -= elapsed_ms;
    }
  }
}

void mdns_input(mdns_t *m, uint32_t src_ip, const uint8_t *src_mac,
                uint16_t src_port, const uint8_t *msg, uint16_t len) {
  uint32_t answers = 0, meta = 0;
  const char *qname = NULL;
  uint16_t qtype = 0, qd, an, k;
  int all_qu = 1, off = DNS_HDR_SIZE;
  uint8_t i;
  dns_question_t q;
  dns_rr_t rr;

  if (m->state == MDNS_STATE_STOPPED || m->state == MDNS_STATE_CONFLICT)
    return;
  if (len < DNS_HDR_SIZE)
    return;
  uint16_t flags = net_read16be(msg + DNS_OFF_FLAGS);
  if (flags & DNS_FLAG_QR) {
    check_conflicts(m, msg, len);
    return;
  }
  if ((flags & DNS_OPCODE_MASK) != 0 || m->state == MDNS_STATE_PROBING)
    return; /* never answer for names still being probed */

  /* ── Questions ── */
  qd = net_read16be(msg + DNS_OFF_QDCOUNT);
  an = net_read16be(msg + DNS_OFF_ANCOUNT);
  for (k = 0; k < qd; k++) {
    uint32_t hit = 0, mhit = 0;
    off = dns_read_question(msg, len, (uint16_t)off, &q);
    if (off < 0)
      return; /* REQ-MDNS-041: malformed → ignore */
    uint16_t qclass = q.class_ & DNS_CLASS_MASK;
    if (qclass != DNS_CLASS_IN && qclass != DNS_CLASS_ANY)
      continue;
    for (i = 0; i < m->count; i++) {
      const mdns_record_t *r = &m->records[i];
      if ((q.type == DNS_TYPE_ANY || q.type == r->type) &&
          dns_name_equals(msg, len, q.name_off, r->name))
        hit |= BIT(i);
    }
    if ((q.type == DNS_TYPE_PTR || q.type == DNS_TYPE_ANY) &&
        dns_name_equals(msg, len, q.name_off, MDNS_META_QUERY)) {
      for (i = 0; i < m->count; i++) {
        if (is_service_type(&m->records[i]))
          mhit |= BIT(i);
      }
    }
    if (!(hit | mhit))
      continue;
    answers |= hit;
    meta |= mhit;
    if (!(q.class_ & DNS_CLASS_TOPBIT))
      all_qu = 0;
    if (!qname) {
      qtype = q.type;
      qname = MDNS_META_QUERY;
      for (i = 0; i < m->count; i++) {
        if (hit & BIT(i)) {
          qname = m->records[i].name;
          break;
        }
      }
    }
  }
  if (!(answers | meta))
    return;

  /* ── Known-answer suppression (REQ-MDNS-029, RFC 6762 §7.1) ── */
  for (k = 0; k < an; k++) {
    off = dns_read_rr(msg, len, (uint16_t)off, &rr);
    if (off < 0)
      break;
    if ((rr.class_ & DNS_CLASS_MASK) != DNS_CLASS_IN)
      continue;
    for (i = 0; i < m->count; i++) {
      const mdns_record_t *r = &m->records[i];
      if ((answers & BIT(i)) && rr.ttl >= r->ttl / 2 &&
          rr_matches(m, r, msg, len, &rr))
        answers &= ~BIT(i);
    }
    if (meta && rr.type == DNS_TYPE_PTR && rr.ttl >= MDNS_TTL_OTHER / 2 &&
        dns_name_equals(msg, len, rr.name_off, MDNS_META_QUERY)) {
      for (i = 0; i < m->count; i++) {
        if ((meta & BIT(i)) &&
            dns_name_equals(msg, len, rr.rdata_off, m->records[i].name))
          meta &= ~BIT(i);
      }
    }
  }
  if (!(answers | meta))
    return;

  resp_opts_t o;
  dest_t d;
  memset(&o, 0, sizeof(o));
  d.ip = src_ip;
  d.mac = src_mac;
  d.port = src_port;

  if (src_port != MDNS_PORT) {
    /* Legacy unicast (RFC 6762 §6.7): reply to the querier's port with its
     * ID and question, TTL <= 10 s, no cache-flush bits.  A querier with no
     * address cannot be answered this way. */
    if (src_ip == 0)
      return;
    o.dest = &d;
    o.id = net_read16be(msg + DNS_OFF_ID);
    o.legacy = 1;
    o.qname = qname;
    o.qtype = qtype;
    send_response(m, answers, meta, additionals_for(m, answers), &o);
    return;
  }
  if (all_qu && src_ip != 0) {
    /* REQ-MDNS-028: every question asked for a unicast response (a querier
     * still at 0.0.0.0 gets the multicast answer instead) */
    o.dest = &d;
    send_response(m, answers, meta, additionals_for(m, answers), &o);
    return;
  }
  if (!meta && !(answers & shared_mask(m))) {
    /* Unique records only: answer immediately (RFC 6762 §6) */
    o.dest = &mcast_dest;
    send_response(m, answers, meta, additionals_for(m, answers), &o);
    return;
  }
  /* Shared records: aggregate and delay 20-120 ms (RFC 6762 §6) */
  m->resp_answers |= answers;
  m->resp_meta |= meta;
  if (!m->resp_timer_ms)
    m->resp_timer_ms =
        MDNS_RESP_DELAY_MIN_MS +
        rnd_below(m, MDNS_RESP_DELAY_MAX_MS - MDNS_RESP_DELAY_MIN_MS + 1);
}

void mdns_stop(mdns_t *m) {
  if (m->state == MDNS_STATE_STOPPED)
    return;
  /* REQ-MDNS-032, 033, REQ-DNSSD-018: withdraw what was announced */
  if (m->state == MDNS_STATE_ANNOUNCING || m->state == MDNS_STATE_RUNNING)
    announce(m, 1);
  igmp_leave(m->net, MDNS_GROUP);
  m->state = MDNS_STATE_STOPPED;
  m->timer_ms = 0;
  m->resp_timer_ms = 0;
  m->resp_answers = 0;
  m->resp_meta = 0;
}
