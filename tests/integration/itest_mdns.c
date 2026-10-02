/**
 * @file itest_mdns.c
 * @brief The mDNS responder, black box: queries and responses on the wire
 *        to 224.0.0.251 (and unicast), the mdns_* API, and what it sends.
 */

#include "itest.h"
#include "mdns.h"
#include "udp.h"
#include <ctype.h>
#include <string.h>

#define HOST "pyro-dead01.local"
#define SVC "_pyro._tcp.local"
#define INST "Pyro Unit 1._pyro._tcp.local"
#define META "_services._dns-sd._udp.local"
#define T_A 1
#define T_PTR 12
#define T_HINFO 13
#define T_TXT 16
#define T_SRV 33
#define T_NSEC 47
#define T_ANY 255
#define C_IN 1
#define C_TOP 0x8000 /* QU in questions, cache-flush in records */
#define FLAG_QR 0x8000
#define FLAG_AA 0x0400
#define FLAG_TC 0x0200
#define OUR_IP 0x0A000002u /* the stack's default address */
#define RIVAL 0x0A00004Du  /* 10.0.0.77: another host's address for HOST */
#define LEGACY_PORT 40000

static itest_t t;
static mdns_t m;
static int conflicts;
static uint8_t conflict_index;
static void (*on_conflict_do)(void);

static void on_conflict(mdns_t *mm, uint8_t index, void *ctx) {
  (void)mm;
  (void)ctx;
  conflicts++;
  conflict_index = index;
  if (on_conflict_do)
    on_conflict_do();
}

static void on_mdns(net_t *net, uint32_t src_ip, uint16_t src_port,
                    const uint8_t *src_mac, const uint8_t *data, uint16_t len) {
  (void)net;
  mdns_input(&m, src_ip, src_mac, src_port, data, len);
}

static const udp_port_entry_t ports[] = {{MDNS_PORT, on_mdns}};
static const char *const txt[] = {"txtvers=1", NULL};
enum { R_A, R_PTR, R_SRV, R_TXT, N_REC };
static const mdns_record_t records[N_REC] = {
    {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
    {.type = DNS_TYPE_PTR, .ttl = 4500, .name = SVC, .rdata.ptr = INST},
    {.type = DNS_TYPE_SRV,
     .ttl = 120,
     .name = INST,
     .rdata.srv = {0, 0, 80, HOST}},
    {.type = DNS_TYPE_TXT, .ttl = 4500, .name = INST, .rdata.txt = txt},
};
#define SERVICE ((1u << R_PTR) | (1u << R_SRV) | (1u << R_TXT))

static net_err_t up_with(const mdns_record_t *recs, uint8_t n, uint16_t tx) {
  itest_up(&t, 1514, tx);
  udp_set_ports(&t.net, ports, 1);
  conflicts = 0;
  conflict_index = 0xFF;
  on_conflict_do = NULL;
  return mdns_init(&m, &t.net, recs, n, on_conflict, NULL);
}

/* Probed and announced, the second during which the announced records
 * may not be multicast again over (RFC 6762 §6), the wire log cleared */
static void running(const mdns_record_t *recs, uint8_t n) {
  up_with(recs, n, 1514);
  mdns_start(&m);
  mdns_tick(&m, 250);
  mdns_tick(&m, 250);
  mdns_tick(&m, 250);
  mdns_tick(&m, 250);
  mdns_tick(&m, 1000);
  mdns_tick(&m, 2000);
  wire_clear(&t);
}

/* Started, the first probe sent (0-250 ms), the wire log cleared */
static void probing(const mdns_record_t *recs, uint8_t n) {
  up_with(recs, n, 1514);
  mdns_start(&m);
  mdns_tick(&m, 250);
  wire_clear(&t);
}

/* mdns_tick() for @p ms, in steps of @p step */
static void ticks(uint32_t ms, uint32_t step) {
  while (ms) {
    uint32_t n = ms < step ? ms : step;
    mdns_tick(&m, n);
    ms -= n;
  }
}

/* ── The peer ── */

static const uint8_t group_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};

/* @p len bytes of DNS from @p src:@p sport to @p dst (the group, or us)
 * port 5353 */
static void deliver(uint32_t src, uint32_t dst, uint16_t sport,
                    const uint8_t *msg, uint16_t len) {
  uint8_t f[1600], seg[1520];
  peer_ip_t ip = peer_ip(src, dst, 17);
  uint16_t n;
  ip.ttl = 255;
  n = peer_udp(seg, &ip, sport, MDNS_PORT, msg, len);
  itest_receive(&t, f,
                peer_ipv4_frame(f, dst == MDNS_GROUP ? group_mac : t.net.mac,
                                peer_mac, &ip, seg, n));
}

/* A DNS message multicast from @p src:@p sport */
static void send_from(uint32_t src, uint16_t sport, peer_dns_t *q) {
  peer_dns_end(q);
  deliver(src, MDNS_GROUP, sport, q->buf, q->len);
}

/* A multicast DNS message from the peer, port 5353 */
static void multicast(peer_dns_t *q) { send_from(PEER_IP, MDNS_PORT, q); }

static void query(const char *name, uint16_t type, uint16_t flags) {
  peer_dns_t q;
  peer_dns_begin(&q, 0, flags);
  peer_dns_question(&q, name, type, C_IN);
  multicast(&q);
}

/* A response with one record, @p name's A record @p addr */
static void claim_a(uint32_t src, uint32_t dst, uint16_t sport, uint16_t flags,
                    const char *name, uint32_t addr, uint32_t ttl) {
  peer_dns_t r;
  uint8_t rd[4];
  peer_dns_begin(&r, 0, flags);
  peer_put32(rd, addr);
  peer_dns_rr(&r, 0, name, T_A, C_IN | C_TOP, ttl, rd, 4);
  peer_dns_end(&r);
  deliver(src, dst, sport, r.buf, r.len);
}

/* Another host multicasts an A record for our host name */
static void rival_a(void) {
  claim_a(PEER_IP, MDNS_GROUP, MDNS_PORT, FLAG_QR | FLAG_AA, HOST, RIVAL, 120);
}

static uint16_t srv_rdata(uint8_t *rd, uint16_t port, const char *target) {
  peer_put16(rd, 0);
  peer_put16(rd + 2, 0);
  peer_put16(rd + 4, port);
  return (uint16_t)(6u + peer_dns_name(rd + 6, target));
}

/* Another host multicasts an SRV record for our instance name */
static void rival_srv(void) {
  peer_dns_t r;
  uint8_t rd[64];
  peer_dns_begin(&r, 0, FLAG_QR | FLAG_AA);
  peer_dns_rr(&r, 0, INST, T_SRV, C_IN | C_TOP, 120, rd,
              srv_rdata(rd, 8080, "other.local"));
  multicast(&r);
}

/* A DNS message written byte by byte, for compression pointers */
typedef struct {
  uint8_t b[512];
  uint16_t n;
} raw_t;

static void raw_init(raw_t *r, uint16_t flags, uint16_t qd, uint16_t an,
                     uint16_t ns, uint16_t ar) {
  memset(r, 0, sizeof(*r));
  peer_put16(r->b + 2, flags);
  peer_put16(r->b + 4, qd);
  peer_put16(r->b + 6, an);
  peer_put16(r->b + 8, ns);
  peer_put16(r->b + 10, ar);
  r->n = 12;
}

static void raw_u16(raw_t *r, uint16_t v) {
  peer_put16(r->b + r->n, v);
  r->n = (uint16_t)(r->n + 2);
}

/* A whole name; @return where it starts */
static uint16_t raw_name(raw_t *r, const char *name) {
  uint16_t at = r->n;
  r->n = (uint16_t)(r->n + peer_dns_name(r->b + r->n, name));
  return at;
}

/* The labels of @p labels ("" for none), then a pointer to @p target */
static void raw_name_ptr(raw_t *r, const char *labels, uint16_t target) {
  if (*labels)
    r->n = (uint16_t)(r->n + peer_dns_name(r->b + r->n, labels) - 1);
  raw_u16(r, (uint16_t)(0xC000u | target));
}

/* A record's type, class and TTL; @return where its rdlen goes */
static uint16_t raw_rr(raw_t *r, uint16_t type, uint16_t class_, uint32_t ttl) {
  uint16_t at;
  raw_u16(r, type);
  raw_u16(r, class_);
  peer_put32(r->b + r->n, ttl);
  r->n = (uint16_t)(r->n + 4);
  at = r->n;
  raw_u16(r, 0);
  return at;
}

static void raw_rr_end(raw_t *r, uint16_t at) {
  peer_put16(r->b + at, (uint16_t)(r->n - at - 2));
}

/* Offsets of the labels of INST written at @p at */
#define INST_SVC(at) ((uint16_t)((at) + 12))   /* "_pyro._tcp.local" */
#define INST_LOCAL(at) ((uint16_t)((at) + 23)) /* "local" */

/* ── What the stack sent ── */

/* The @p k-th mDNS message sent over IPv4 (probe or response), parsed,
 * with its IP and UDP headers and frame index; 0 if none */
static int sent(int k, peer_dns_msg_t *msg, peer_ip_t *ip, peer_udp_t *udp,
                uint16_t *frame) {
  uint16_t i;
  for (i = 0; wire_sent(&t, i); i++) {
    if (peer_parse_ipv4(wire_sent(&t, i), ip) && peer_parse_udp(ip, udp) &&
        udp->sport == MDNS_PORT && k-- == 0) {
      if (frame)
        *frame = i;
      return peer_dns_parse(udp->data, udp->data_len, msg);
    }
  }
  return 0;
}

/* The @p k-th mDNS message sent over IPv4, parsed; 0 if none */
static int response(int k, peer_dns_msg_t *msg) {
  peer_ip_t ip;
  peer_udp_t udp;
  return sent(k, msg, &ip, &udp, NULL);
}

static int responses(void) {
  peer_dns_msg_t msg;
  int k = 0;
  while (response(k, &msg))
    k++;
  return k;
}

/* The @p k-th sent message that is a response (@p qr 1) or a query (0) */
static int nth(int qr, int k, peer_dns_msg_t *msg) {
  int i;
  for (i = 0; response(i, msg); i++) {
    if (((msg->flags & FLAG_QR) != 0) == qr && k-- == 0)
      return 1;
  }
  return 0;
}

static int count(int qr) {
  peer_dns_msg_t msg;
  int k = 0;
  while (nth(qr, k, &msg))
    k++;
  return k;
}

#define nth_response(k, msg) nth(1, k, msg)
#define nth_probe(k, msg) nth(0, k, msg)
#define probes() count(0)
#define answers() count(1)

/* Records of @p name and @p type in section @p section of every response
 * sent */
static int records_sent(int section, const char *name, uint16_t type) {
  peer_dns_msg_t msg;
  int k, n = 0;
  uint16_t i;
  for (k = 0; nth_response(k, &msg); k++) {
    for (i = 0; i < msg.n_rr; i++) {
      const peer_rr_t *r = &msg.rr[i];
      size_t j, len = strlen(name);
      if (r->section != section || r->type != type || strlen(r->name) != len)
        continue;
      for (j = 0; j < len && tolower((unsigned char)r->name[j]) ==
                                 tolower((unsigned char)name[j]);
           j++)
        ;
      if (j == len)
        n++;
    }
  }
  return n;
}

/* The first response sent that answers @p name's @p type, and that
 * record; NULL if none */
static const peer_rr_t *answered(peer_dns_msg_t *msg, const char *name,
                                 uint16_t type) {
  const peer_rr_t *r;
  int k;
  for (k = 0; nth_response(k, msg); k++) {
    if ((r = peer_dns_find(msg, 0, name, type)) != NULL)
      return r;
  }
  return NULL;
}

/* Question @p k of @p msg: its name into @p name; @return its class */
static uint16_t question(const peer_dns_msg_t *msg, int k, char *name) {
  uint16_t off = 12;
  for (;;) {
    peer_dns_read_name(msg, off, name);
    while (msg->msg[off] && (msg->msg[off] & 0xC0) != 0xC0)
      off = (uint16_t)(off + 1 + msg->msg[off]);
    off = (uint16_t)(off + (msg->msg[off] ? 2 : 1));
    if (k-- == 0)
      return peer_get16(msg->msg + off + 2);
    off = (uint16_t)(off + 4);
  }
}

/* @p needle occurs in the @p len bytes at @p hay */
static int contains(const uint8_t *hay, uint16_t len, const void *needle,
                    uint16_t n) {
  uint16_t i;
  for (i = 0; i + n <= len; i++) {
    if (memcmp(hay + i, needle, n) == 0)
      return 1;
  }
  return 0;
}

/* The next second, in which nothing sent before is held back (RFC 6762
 * §6), and a clean wire log */
static void later(void) {
  mdns_tick(&m, 2000);
  wire_clear(&t);
}

/* ══ Goodbyes, withdrawals, truncated queries ═══════════════════════ */

/* REQ-MDNS-032, 033, REQ-DNSSD-018: the goodbye withdraws every record and
 * the service type's meta-query listing, TTL 0 */
TEST(itest_mdns_033_goodbye_includes_the_meta_query_ptr) {
  peer_dns_msg_t g;
  const peer_rr_t *r;
  uint16_t i;
  char target[256];
  running(records, N_REC);
  mdns_stop(&m);
  ASSERT_TRUE(response(0, &g));
  for (i = 0; i < g.n_rr; i++)
    ASSERT_EQ(g.rr[i].ttl, 0u);
  ASSERT_NOT_NULL(peer_dns_find(&g, 0, HOST, T_A));
  ASSERT_NOT_NULL(peer_dns_find(&g, 0, SVC, T_PTR));
  ASSERT_NOT_NULL(peer_dns_find(&g, 0, INST, T_SRV));
  ASSERT_NOT_NULL(r = peer_dns_find(&g, 0, META, T_PTR));
  ASSERT_TRUE(peer_dns_read_name(&g, r->rdata_off, target));
  ASSERT_TRUE(strcmp(target, SVC) == 0);
}

/* REQ-DNSSD-029, REQ-MDNS-042: a record that no packet could carry is
 * refused at init */
TEST(itest_dnssd_029_record_too_big_for_any_packet_refused) {
  static char e1[201], e2[201], e3[201];
  static const char *const big[] = {e1, e2, e3, NULL};
  static const mdns_record_t recs[] = {
      {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
      {.type = DNS_TYPE_TXT, .ttl = 4500, .name = INST, .rdata.txt = big},
  };
  memset(e1, 'a', 200);
  memset(e2, 'b', 200);
  memset(e3, 'c', 200);
  ASSERT_EQ(up_with(recs, 2, 300), NET_ERR_BUF_TOO_SMALL);
  ASSERT_EQ(up_with(recs, 2, 1514), NET_OK);
}

/* REQ-MDNS-027 (RFC 6762 §7.2): a truncated query is answered after
 * 400-500 ms, even for a unique record */
TEST(itest_mdns_027_truncated_query_waits_400_to_500ms) {
  running(records, N_REC);
  query(HOST, T_A, FLAG_TC);
  mdns_tick(&m, 399);
  ASSERT_EQ(responses(), 0);
  mdns_tick(&m, 101);
  ASSERT_EQ(responses(), 1);
}

/* REQ-MDNS-027, 029: known answers that follow a truncated query strike
 * what it would have been answered */
TEST(itest_mdns_029_known_answers_after_truncated_query) {
  peer_dns_t q;
  peer_dns_msg_t r;
  uint8_t rd[256];
  running(records, N_REC);
  peer_dns_begin(&q, 0, FLAG_TC);
  peer_dns_question(&q, SVC, T_PTR, 1);
  peer_dns_question(&q, HOST, T_A, 1);
  multicast(&q);
  peer_dns_begin(&q, 0, 0); /* the continuation: answers only */
  peer_dns_rr(&q, 0, SVC, T_PTR, 1, 4500, rd, peer_dns_name(rd, INST));
  multicast(&q);
  mdns_tick(&m, 500);
  ASSERT_EQ(responses(), 1);
  ASSERT_TRUE(response(0, &r));
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, HOST, T_A));
  ASSERT_NULL(peer_dns_find(&r, 0, SVC, T_PTR));
}

/* REQ-MDNS-032, REQ-DNSSD-018: one service withdrawn while the host stays:
 * a goodbye for its records and its type, then silence about them */
TEST(itest_dnssd_018_withdraw_one_service) {
  peer_dns_msg_t g;
  running(records, N_REC);
  mdns_withdraw(&m, SERVICE);
  ASSERT_EQ(responses(), 1);
  ASSERT_TRUE(response(0, &g));
  ASSERT_EQ(g.an, 4);
  ASSERT_EQ(g.ar, 0);
  ASSERT_NOT_NULL(peer_dns_find(&g, 0, SVC, T_PTR));
  ASSERT_NOT_NULL(peer_dns_find(&g, 0, INST, T_SRV));
  ASSERT_NOT_NULL(peer_dns_find(&g, 0, INST, T_TXT));
  ASSERT_NOT_NULL(peer_dns_find(&g, 0, META, T_PTR));
  ASSERT_NULL(peer_dns_find(&g, 0, HOST, T_A));
  ASSERT_EQ(g.rr[0].ttl, 0u);

  wire_clear(&t);
  mdns_withdraw(&m, SERVICE); /* gone already: nothing more to say */
  query(SVC, T_PTR, 0);
  query(INST, T_SRV, 0);
  query(INST, T_A, 0); /* an NSEC, were the name still ours */
  query(META, T_PTR, 0);
  mdns_tick(&m, 200);
  ASSERT_EQ(responses(), 0);
  query(HOST, T_A, 0);
  ASSERT_EQ(responses(), 1);

  wire_clear(&t);
  mdns_stop(&m); /* goodbye to what is left */
  ASSERT_TRUE(response(0, &g));
  ASSERT_EQ(g.an, 1);
  ASSERT_NOT_NULL(peer_dns_find(&g, 0, HOST, T_A));
}

/* REQ-DNSSD-018: a type another instance still offers keeps its listing */
TEST(itest_dnssd_018_withdraw_one_of_two_instances) {
  static const mdns_record_t recs[] = {
      {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
      {.type = DNS_TYPE_PTR, .ttl = 4500, .name = SVC, .rdata.ptr = INST},
      {.type = DNS_TYPE_PTR,
       .ttl = 4500,
       .name = SVC,
       .rdata.ptr = "Pyro Unit 2._pyro._tcp.local"},
  };
  peer_dns_msg_t g;
  running(recs, 3);
  mdns_withdraw(&m, 1u << 1);
  ASSERT_TRUE(response(0, &g));
  ASSERT_EQ(g.an, 1);
  ASSERT_NULL(peer_dns_find(&g, 0, META, T_PTR));
}

/* REQ-MDNS-016, REQ-DNSSD-018: withdrawn before announcing: no goodbye,
 * and the withdrawn name is not probed */
TEST(itest_dnssd_018_withdraw_while_probing) {
  peer_dns_msg_t p;
  up_with(records, N_REC, 1514);
  mdns_start(&m);
  wire_clear(&t);
  mdns_withdraw(&m, SERVICE);
  ASSERT_EQ(t.wire.tx_count, 0);
  mdns_tick(&m, 250);
  ASSERT_EQ(responses(), 1); /* the first probe */
  ASSERT_TRUE(response(0, &p));
  ASSERT_EQ(p.qd, 1);
  ASSERT_TRUE(strcmp(p.qname, HOST) == 0);
  ASSERT_NULL(peer_dns_find(&p, 1, INST, T_SRV));
}

/* ══ Message format (RFC 6762 §18) ══════════════════════════════════ */

/* REQ-MDNS-016, 046 (RFC 6762 §8.1, §18): a probe is a query with every
 * header bit 0, asking for each unique name with a QU question of type
 * ANY, the proposed records in Authority without the cache-flush bit */
TEST(itest_mdns_016_probes_are_qu_any_with_proposed_records) {
  peer_dns_msg_t p;
  const peer_rr_t *a;
  char name[256];
  up_with(records, N_REC, 1514);
  mdns_start(&m);
  mdns_tick(&m, 250);
  ASSERT_TRUE(nth_probe(0, &p));
  ASSERT_EQ(p.flags, 0);
  ASSERT_EQ(p.id, 0);
  ASSERT_EQ(p.qd, 2);
  ASSERT_EQ(p.an, 0);
  ASSERT_EQ(question(&p, 0, name), C_IN | C_TOP);
  ASSERT_TRUE(strcmp(name, HOST) == 0);
  ASSERT_EQ(p.qtype, T_ANY);
  ASSERT_EQ(question(&p, 1, name), C_IN | C_TOP);
  ASSERT_TRUE(strcmp(name, INST) == 0);
  ASSERT_NOT_NULL(a = peer_dns_find(&p, 1, HOST, T_A));
  ASSERT_EQ(a->class_, C_IN);
  ASSERT_EQ(peer_get32(a->rdata), OUR_IP);
  ASSERT_NOT_NULL(peer_dns_find(&p, 1, INST, T_SRV));
  ASSERT_NOT_NULL(peer_dns_find(&p, 1, INST, T_TXT));
  ASSERT_NULL(peer_dns_find(&p, 1, SVC, T_PTR)); /* shared: not probed */
}

/* REQ-MDNS-046, 070 (RFC 6762 §18.2-18.11): probes have every header bit
 * 0, responses only QR and AA; IDs 0; no questions in responses */
TEST(itest_mdns_046_header_bits_on_transmission) {
  peer_dns_msg_t r;
  int k, probes = 0, announcements = 0;
  up_with(records, N_REC, 1514);
  mdns_start(&m);
  ticks(2000, 250);
  for (k = 0; response(k, &r); k++) {
    ASSERT_EQ(r.id, 0);
    if (r.flags & FLAG_QR) {
      ASSERT_EQ(r.flags, FLAG_QR | FLAG_AA);
      ASSERT_EQ(r.qd, 0);
      announcements++;
    } else {
      ASSERT_EQ(r.flags, 0);
      probes++;
    }
  }
  ASSERT_EQ(probes, 3);
  ASSERT_EQ(announcements, 2);
  mdns_tick(&m, 2000);
  wire_clear(&t);
  query(HOST, T_A, 0);
  ASSERT_TRUE(nth_response(0, &r));
  ASSERT_EQ(r.flags, FLAG_QR | FLAG_AA);
}

/* REQ-MDNS-047 (RFC 6762 §18.1, §18.4-18.10): AA, RD, RA, Z, AD and CD
 * are ignored in what arrives, and so are a response's TC bit and ID */
TEST(itest_mdns_047_header_bits_ignored_on_reception) {
  peer_dns_t q;
  peer_dns_msg_t r;
  running(records, N_REC);
  peer_dns_begin(&q, 0x1234, 0x05F0); /* AA, RD, RA, Z, AD, CD */
  peer_dns_question(&q, HOST, T_A, C_IN);
  multicast(&q);
  ASSERT_NOT_NULL(answered(&r, HOST, T_A));
  ASSERT_EQ(r.id, 0);

  probing(records, N_REC);
  peer_dns_begin(&q, 0x4321, FLAG_QR | FLAG_TC | 0x01F0); /* AA clear */
  {
    uint8_t rd[4];
    peer_put32(rd, RIVAL);
    peer_dns_rr(&q, 0, HOST, T_A, C_IN | C_TOP, 120, rd, 4);
  }
  multicast(&q);
  ASSERT_EQ(conflicts, 1);
}

/* REQ-MDNS-048 (RFC 6762 §18.14): compressed names are decoded in
 * questions, record names, and PTR and SRV rdata */
TEST(itest_mdns_048_compressed_names_decoded) {
  raw_t q;
  uint16_t inst_at, svc_at, rd;
  peer_dns_msg_t r;
  running(records, N_REC);
  /* the second question's "local" points into the first */
  raw_init(&q, 0, 2, 0, 0, 0);
  inst_at = raw_name(&q, INST);
  raw_u16(&q, T_SRV);
  raw_u16(&q, C_IN);
  raw_name_ptr(&q, "pyro-dead01", INST_LOCAL(inst_at));
  raw_u16(&q, T_A);
  raw_u16(&q, C_IN);
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, q.b, q.n);
  mdns_tick(&m, 150);
  ASSERT_NOT_NULL(answered(&r, INST, T_SRV));
  ASSERT_NOT_NULL(answered(&r, HOST, T_A));

  /* a known answer whose owner and target are pointers: suppresses */
  wire_clear(&t);
  raw_init(&q, 0, 1, 1, 0, 0);
  svc_at = raw_name(&q, SVC);
  raw_u16(&q, T_PTR);
  raw_u16(&q, C_IN);
  raw_name_ptr(&q, "", svc_at);
  rd = raw_rr(&q, T_PTR, C_IN, 4500);
  raw_name_ptr(&q, "Pyro Unit 1", svc_at);
  raw_rr_end(&q, rd);
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, q.b, q.n);
  mdns_tick(&m, 200);
  ASSERT_EQ(responses(), 0);

  /* while probing: our own SRV and TXT, the SRV target compressed — no
   * conflict; another port — a conflict */
  probing(records, N_REC);
  raw_init(&q, FLAG_QR | FLAG_AA, 0, 2, 0, 0);
  inst_at = raw_name(&q, INST);
  rd = raw_rr(&q, T_SRV, C_IN | C_TOP, 120);
  raw_u16(&q, 0);
  raw_u16(&q, 0);
  raw_u16(&q, 80);
  raw_name_ptr(&q, "pyro-dead01", INST_LOCAL(inst_at));
  raw_rr_end(&q, rd);
  raw_name_ptr(&q, "", inst_at);
  rd = raw_rr(&q, T_TXT, C_IN | C_TOP, 4500);
  memcpy(q.b + q.n, "\x09txtvers=1", 10);
  q.n = (uint16_t)(q.n + 10);
  raw_rr_end(&q, rd);
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, q.b, q.n);
  ASSERT_EQ(conflicts, 0);
  rival_srv();
  ASSERT_EQ(conflicts, 1);
}

/* REQ-MDNS-049 (RFC 6762 §18.14): names in the rdata of other types are
 * not compressed — a TXT record goes out byte for byte, even where its
 * bytes spell a name already in the message */
TEST(itest_mdns_049_no_compression_in_other_rdata) {
  static const char *const labels[] = {"_tcp", "local", NULL};
  static const mdns_record_t recs[] = {
      {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
      {.type = DNS_TYPE_PTR, .ttl = 4500, .name = SVC, .rdata.ptr = INST},
      {.type = DNS_TYPE_TXT, .ttl = 4500, .name = INST, .rdata.txt = labels},
  };
  peer_dns_msg_t r;
  const peer_rr_t *x;
  up_with(recs, 3, 1514);
  mdns_start(&m);
  ticks(1000, 250);
  ASSERT_TRUE(nth_response(0, &r));
  ASSERT_NOT_NULL(x = peer_dns_find(&r, 0, INST, T_TXT));
  ASSERT_EQ(x->rdlen, 11);
  ASSERT_MEM_EQ(x->rdata, "\x04_tcp\x05local", 11);
  ASSERT_NOT_NULL(x = peer_dns_find(&r, 0, HOST, T_A));
  ASSERT_EQ(x->rdlen, 4);
}

/* ══ Names ══════════════════════════════════════════════════════════ */

static mdns_record_t one[3];

/* mdns_init() of a host named @p host */
static net_err_t init_host(const char *host) {
  memset(one, 0, sizeof(one));
  one[0].type = DNS_TYPE_A;
  one[0].ttl = 120;
  one[0].name = host;
  return up_with(one, 1, 1514);
}

/* mdns_init() of a service instance @p inst on @p target */
static net_err_t init_instance(const char *inst, const char *target) {
  memset(one, 0, sizeof(one));
  one[0].type = DNS_TYPE_PTR;
  one[0].ttl = 4500;
  one[0].name = SVC;
  one[0].rdata.ptr = inst;
  one[1].type = DNS_TYPE_SRV;
  one[1].ttl = 120;
  one[1].name = inst;
  one[1].rdata.srv.port = 80;
  one[1].rdata.srv.target = target;
  return up_with(one, 2, 1514);
}

/* REQ-MDNS-050 (RFC 6762 §16): names are UTF-8 without a byte order
 * mark — anything else is refused at init */
TEST(itest_mdns_050_names_utf8_without_bom) {
  ASSERT_EQ(init_host("caf\xC3\xA9.local"), NET_OK);
  ASSERT_EQ(init_host("\xE6\x97\xA5\xE6\x9C\xAC.local"), NET_OK);
  ASSERT_EQ(init_host("\xF0\x9F\x94\xA5.local"), NET_OK);
  ASSERT_EQ(init_host("a\xEF\xBB\xBF\x62.local"), NET_OK);       /* ZWNBSP */
  ASSERT_EQ(init_host("caf\xE9.local"), NET_ERR_INVALID_PARAM);  /* Latin-1 */
  ASSERT_EQ(init_host("caf\xC3.local"), NET_ERR_INVALID_PARAM);  /* cut */
  ASSERT_EQ(init_host("\xC0\xAF.local"), NET_ERR_INVALID_PARAM); /* overlong */
  ASSERT_EQ(init_host("\xE0\x80\xAF.local"), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(init_host("\xED\xA0\x80.local"), NET_ERR_INVALID_PARAM); /* D800 */
  ASSERT_EQ(init_host("\xF4\x90\x80\x80.local"), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(init_host("\xBF.local"), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(init_host("\xEF\xBB\xBFpyro.local"), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(init_instance("\xEF\xBB\xBFPyro._pyro._tcp.local", HOST),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(init_instance(INST, "pyro\xFF.local"), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(init_instance(INST, HOST), NET_OK);
}

/* REQ-MDNS-051, REQ-DNSSD-031 (RFC 6762 App. C): a name of 255 bytes on
 * the wire, not counting its terminating zero, is used; one more is not,
 * nor a label of more than 63 bytes */
TEST(itest_mdns_051_names_of_255_bytes) {
  static char name[300];
  static mdns_record_t recs[1];
  peer_dns_msg_t r;
  /* 3 × (1 + 63) + (1 + 56) + (1 + 5) = 255, then the zero byte */
  memset(name, 'a', 63);
  name[63] = '.';
  memset(name + 64, 'b', 63);
  name[127] = '.';
  memset(name + 128, 'c', 63);
  name[191] = '.';
  memset(name + 192, 'd', 57);
  strcpy(name + 249, ".local");
  recs[0].type = DNS_TYPE_A;
  recs[0].ttl = 120;
  recs[0].name = name;
  ASSERT_EQ(up_with(recs, 1, 1514), NET_ERR_INVALID_PARAM); /* 256 */
  memmove(name + 248, name + 249, 7);                       /* 255 */
  ASSERT_EQ(up_with(recs, 1, 1514), NET_OK);
  running(recs, 1);
  query(name, T_A, 0);
  ASSERT_NOT_NULL(answered(&r, name, T_A));
  memset(name, 'a', 64);
  strcpy(name + 64, ".local");
  ASSERT_EQ(up_with(recs, 1, 1514), NET_ERR_INVALID_PARAM);
  memmove(name + 63, name + 64, 7);
  ASSERT_EQ(up_with(recs, 1, 1514), NET_OK);
}

/* REQ-DNSSD-033 (RFC 6763 §4.1.1): no ASCII control characters in
 * instance names */
TEST(itest_dnssd_033_instance_name_control_characters_refused) {
  ASSERT_EQ(init_instance("Pyro\x01Unit._pyro._tcp.local", HOST),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(init_instance("Pyro\x1FUnit._pyro._tcp.local", HOST),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(init_instance("Pyro\x7FUnit._pyro._tcp.local", HOST),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(init_instance("Pyro Unit (2)._pyro._tcp.local", HOST), NET_OK);
}

/* REQ-DNSSD-034 (deviation): a dot always separates labels — an instance
 * name "Pyro.Unit" is sent as the two labels "Pyro" and "Unit" */
TEST(itest_dnssd_034_dots_separate_labels) {
  peer_ip_t ip;
  peer_udp_t udp;
  peer_dns_msg_t r;
  int k;
  ASSERT_EQ(init_instance("Pyro.Unit._pyro._tcp.local", HOST), NET_OK);
  mdns_start(&m);
  ticks(1000, 250);
  for (k = 0; sent(k, &r, &ip, &udp, NULL); k++) {
    if (r.flags & FLAG_QR)
      break;
  }
  ASSERT_TRUE(r.flags & FLAG_QR); /* the announcement */
  ASSERT_TRUE(contains(udp.data, udp.data_len, "\x04Pyro\x04Unit", 10));
}

/* mdns_init() of an instance whose TXT record is @p strings */
static net_err_t init_txt(const char *const *strings) {
  memset(one, 0, sizeof(one));
  one[0].type = DNS_TYPE_TXT;
  one[0].ttl = 4500;
  one[0].name = INST;
  one[0].rdata.txt = strings;
  return up_with(one, 1, 1514);
}

/* REQ-DNSSD-035 (RFC 6763 §6.4): every key at least one character, all
 * printable US-ASCII; values are any bytes */
TEST(itest_dnssd_035_txt_keys_checked) {
  static const char *const no_key[] = {"=value", NULL};
  static const char *const control[] = {"ke\x01y=1", NULL};
  static const char *const utf8[] = {"k\xC3\xA9y=1", NULL};
  static const char *const empty_among[] = {"txtvers=1", "", NULL};
  static const char *const binary[] = {"key=\x01\xFF=", NULL};
  static const char *const boolean[] = {"flag", "paper size=A4", NULL};
  static const char *const empty_alone[] = {"", NULL};
  ASSERT_EQ(init_txt(no_key), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(init_txt(control), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(init_txt(utf8), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(init_txt(empty_among), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(init_txt(binary), NET_OK);
  ASSERT_EQ(init_txt(boolean), NET_OK);
  ASSERT_EQ(init_txt(empty_alone), NET_OK); /* the empty TXT record */
}

/* REQ-DNSSD-038 (RFC 6763 §8): an SRV target is never the root label */
TEST(itest_dnssd_038_srv_target_never_root) {
  ASSERT_EQ(init_instance(INST, ""), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(init_instance(INST, "."), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(init_instance(INST, HOST), NET_OK);
}

/* REQ-MDNS-043 (RFC 6762 §18.14): in a legacy unicast response the SRV
 * target is not compressed */
TEST(itest_mdns_043_legacy_srv_target_uncompressed) {
  peer_dns_t q;
  peer_dns_msg_t r;
  const peer_rr_t *srv;
  uint8_t target[64];
  uint16_t n = peer_dns_name(target, HOST);
  running(records, N_REC);
  peer_dns_begin(&q, 0x77, 0);
  peer_dns_question(&q, INST, T_SRV, C_IN);
  send_from(PEER_IP, LEGACY_PORT, &q);
  ASSERT_NOT_NULL(srv = answered(&r, INST, T_SRV));
  ASSERT_EQ(srv->rdlen, 6 + n);
  ASSERT_MEM_EQ(srv->rdata + 6, target, n);
}

/* ══ Receiving ══════════════════════════════════════════════════════ */

/* REQ-MDNS-044 (RFC 6762 §18.3): a message whose OPCODE is not 0 is
 * ignored, query or response */
TEST(itest_mdns_044_nonzero_opcode_ignored) {
  running(records, N_REC);
  query(HOST, T_A, 0x0800);
  mdns_tick(&m, 200);
  ASSERT_EQ(responses(), 0);
  probing(records, N_REC);
  claim_a(PEER_IP, MDNS_GROUP, MDNS_PORT, FLAG_QR | FLAG_AA | 0x0800, HOST,
          RIVAL, 120);
  ASSERT_EQ(conflicts, 0);
  rival_a();
  ASSERT_EQ(conflicts, 1);
}

/* REQ-MDNS-045 (RFC 6762 §18.11): a message whose RCODE is not 0 is
 * ignored, query or response */
TEST(itest_mdns_045_nonzero_rcode_ignored) {
  running(records, N_REC);
  query(HOST, T_A, 0x0003);
  mdns_tick(&m, 200);
  ASSERT_EQ(responses(), 0);
  probing(records, N_REC);
  claim_a(PEER_IP, MDNS_GROUP, MDNS_PORT, FLAG_QR | FLAG_AA | 0x0003, HOST,
          RIVAL, 120);
  ASSERT_EQ(conflicts, 0);
}

/* REQ-MDNS-061 (RFC 6762 §6): a response not from port 5353 is ignored */
TEST(itest_mdns_061_responses_from_other_ports_ignored) {
  probing(records, N_REC);
  claim_a(PEER_IP, MDNS_GROUP, 5354, FLAG_QR | FLAG_AA, HOST, RIVAL, 120);
  ASSERT_EQ(conflicts, 0);
  rival_a();
  ASSERT_EQ(conflicts, 1);
}

/* REQ-MDNS-062 (RFC 6762 §11): responses count only from the local link —
 * multicast to 224.0.0.251 whatever the source, unicast only from our
 * subnet */
TEST(itest_mdns_062_responses_only_from_the_local_link) {
  probing(records, N_REC);
  claim_a(REMOTE_IP, OUR_IP, MDNS_PORT, FLAG_QR | FLAG_AA, HOST, RIVAL, 120);
  ASSERT_EQ(conflicts, 0);
  claim_a(REMOTE_IP, MDNS_GROUP, MDNS_PORT, FLAG_QR | FLAG_AA, HOST, RIVAL,
          120);
  ASSERT_EQ(conflicts, 1);
  probing(records, N_REC);
  claim_a(PEER2_IP, OUR_IP, MDNS_PORT, FLAG_QR | FLAG_AA, HOST, RIVAL, 120);
  ASSERT_EQ(conflicts, 1);

  /* a message the application hands to mdns_input() from a buffer of its
   * own counts as unicast: only from the subnet */
  {
    peer_dns_t r;
    uint8_t rd[4];
    probing(records, N_REC);
    peer_dns_begin(&r, 0, FLAG_QR | FLAG_AA);
    peer_put32(rd, RIVAL);
    peer_dns_rr(&r, 0, HOST, T_A, C_IN | C_TOP, 120, rd, 4);
    peer_dns_end(&r);
    mdns_input(&m, REMOTE_IP, peer_mac, MDNS_PORT, r.buf, r.len);
    ASSERT_EQ(conflicts, 0);
    mdns_input(&m, PEER2_IP, peer_mac, MDNS_PORT, r.buf, r.len);
    ASSERT_EQ(conflicts, 1);
  }
}

/* REQ-MDNS-080 (RFC 6762 §6): a unicast response counts only as the
 * answer to a recent query that asked for unicast responses — our probes'
 * QU questions.  Once running, one sent to our own address is ignored: no
 * conflict, no low TTL corrected; the same by multicast counts */
TEST(itest_mdns_080_unicast_responses_only_to_our_probes) {
  running(records, N_REC);
  claim_a(PEER2_IP, OUR_IP, MDNS_PORT, FLAG_QR | FLAG_AA, HOST, RIVAL, 120);
  ticks(1000, 250);
  ASSERT_EQ(probes(), 0);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
  claim_a(PEER2_IP, OUR_IP, MDNS_PORT, FLAG_QR | FLAG_AA, HOST, OUR_IP, 0);
  mdns_tick(&m, 150);
  ASSERT_EQ(responses(), 0);
  rival_a();
  mdns_tick(&m, 250);
  ASSERT_EQ(probes(), 1);

  probing(records, N_REC); /* the first probe is out: its answer counts */
  claim_a(PEER2_IP, OUR_IP, MDNS_PORT, FLAG_QR | FLAG_AA, HOST, RIVAL, 120);
  ASSERT_EQ(conflicts, 1);
}

/* REQ-MDNS-070 (RFC 6762 §6): a question in a response is ignored */
TEST(itest_mdns_070_questions_in_responses_ignored) {
  peer_dns_t r;
  running(records, N_REC);
  peer_dns_begin(&r, 0, FLAG_QR | FLAG_AA);
  peer_dns_question(&r, HOST, T_A, C_IN);
  multicast(&r);
  mdns_tick(&m, 200);
  ASSERT_EQ(responses(), 0);
  ASSERT_EQ(conflicts, 0);
}

/* ══ Probing (RFC 6762 §8.1, §8.2) ══════════════════════════════════ */

/* REQ-MDNS-052 (RFC 6762 §8.1): a conflicting response before the first
 * probe is ignored */
TEST(itest_mdns_052_responses_before_the_first_probe_ignored) {
  up_with(records, N_REC, 1514);
  mdns_start(&m);
  rival_a();
  ASSERT_EQ(conflicts, 0);
  ticks(2000, 250);
  ASSERT_EQ(probes(), 3);
  ASSERT_EQ(answers(), 2);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
}

/* REQ-MDNS-053 (RFC 6762 §8.1): while probing, any record of the name, of
 * any type, conflicts — but not a copy of our own */
TEST(itest_mdns_053_any_record_of_the_name_conflicts_while_probing) {
  peer_dns_t r;
  probing(records, N_REC);
  claim_a(PEER_IP, MDNS_GROUP, MDNS_PORT, FLAG_QR | FLAG_AA, HOST, OUR_IP, 120);
  ASSERT_EQ(conflicts, 0);
  peer_dns_begin(&r, 0, FLAG_QR | FLAG_AA);
  peer_dns_rr(&r, 0, HOST, T_TXT, C_IN | C_TOP, 4500, "\x03x=1", 4);
  multicast(&r);
  ASSERT_EQ(conflicts, 1);
  ASSERT_EQ(conflict_index, R_A);
}

static void restart(void) { mdns_start(&m); }

/* REQ-MDNS-054 (RFC 6762 §8.1): after fifteen conflicts in ten seconds,
 * five seconds at least before the next probe — until ten seconds have
 * passed without a conflict */
TEST(itest_mdns_054_fifteen_conflicts_slow_probing_down) {
  int k;
  up_with(records, N_REC, 1514);
  on_conflict_do = restart;
  mdns_start(&m);
  for (k = 0; k < 15; k++) {
    mdns_tick(&m, 250); /* the first probe */
    rival_a();
  }
  ASSERT_EQ(conflicts, 15);
  wire_clear(&t);
  ticks(4950, 50);
  ASSERT_EQ(probes(), 0);
  ticks(100, 50);
  ASSERT_EQ(probes(), 1);
  /* ten seconds without a conflict: probing is quick again */
  ticks(10000, 250);
  mdns_start(&m);
  wire_clear(&t);
  ticks(250, 50);
  ASSERT_EQ(probes(), 1);
}

/* Another host's probe for @p name proposing the A record @p addr */
static void probe_a(const char *name, uint32_t addr, uint16_t qclass) {
  peer_dns_t q;
  uint8_t rd[4];
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, name, T_ANY, qclass);
  peer_put32(rd, addr);
  peer_dns_rr(&q, 1, name, T_A, C_IN, 120, rd, 4);
  multicast(&q);
}

/* REQ-MDNS-055 (RFC 6762 §8.2): a simultaneous probe with later data
 * wins: we wait one second, then probe again — no conflict */
TEST(itest_mdns_055_simultaneous_probe_lost_waits_a_second) {
  probing(records, N_REC);
  probe_a(HOST, 0x0A0000C8u, C_IN | C_TOP); /* 10.0.0.200 > 10.0.0.2 */
  ticks(990, 10);
  ASSERT_EQ(probes(), 0);
  ticks(260, 10);
  ASSERT_TRUE(probes() >= 1);
  ticks(1000, 10);
  ASSERT_EQ(probes(), 3);
  ASSERT_TRUE(answers() >= 1);
  ASSERT_EQ(conflicts, 0);
}

/* REQ-MDNS-055 (RFC 6762 §8.2, §8.2.1): a simultaneous probe with earlier
 * or identical data is ignored; names are compared uncompressed — a
 * compressed SRV target that is lexicographically earlier loses */
TEST(itest_mdns_055_simultaneous_probe_won_or_tied) {
  raw_t q;
  uint16_t inst_at, rd;
  probing(records, N_REC);
  probe_a(HOST, 0x0A000001u, C_IN | C_TOP); /* 10.0.0.1 < 10.0.0.2 */
  probe_a(HOST, OUR_IP, C_IN | C_TOP);      /* the same: no conflict */
  /* For the instance: our TXT, and an SRV whose target is a pointer to
   * the instance name — "\x0bPyro Unit 1" sorts before "\x0bpyro-dead01",
   * though 0xC0 would sort after it */
  raw_init(&q, 0, 1, 0, 2, 0);
  inst_at = raw_name(&q, INST);
  raw_u16(&q, T_ANY);
  raw_u16(&q, C_IN | C_TOP);
  raw_name_ptr(&q, "", inst_at);
  rd = raw_rr(&q, T_TXT, C_IN, 4500);
  memcpy(q.b + q.n, "\x09txtvers=1", 10);
  q.n = (uint16_t)(q.n + 10);
  raw_rr_end(&q, rd);
  raw_name_ptr(&q, "", inst_at);
  rd = raw_rr(&q, T_SRV, C_IN, 120);
  raw_u16(&q, 0);
  raw_u16(&q, 0);
  raw_u16(&q, 80);
  raw_name_ptr(&q, "", inst_at);
  raw_rr_end(&q, rd);
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, q.b, q.n);
  ticks(500, 10);
  ASSERT_EQ(probes(), 2);
  ticks(250, 10);
  ASSERT_EQ(answers(), 1);
  ASSERT_EQ(conflicts, 0);
}

/* ══ Announcing and updating (RFC 6762 §8.3, §8.4, §9) ══════════════ */

/* REQ-MDNS-057 (RFC 6762 §9): a conflict while running sends the name
 * back to probing; only when that probing fails is the name given up */
TEST(itest_mdns_057_conflict_while_running_probes_again) {
  peer_dns_msg_t p;
  char name[256];
  running(records, N_REC);
  rival_a();
  ASSERT_EQ(conflicts, 0);
  mdns_tick(&m, 250);
  ASSERT_TRUE(nth_probe(0, &p));
  ASSERT_EQ(p.qd, 1);
  ASSERT_EQ(question(&p, 0, name), C_IN | C_TOP);
  ASSERT_TRUE(strcmp(name, HOST) == 0);
  rival_a();
  ASSERT_EQ(conflicts, 1);
  ASSERT_EQ(conflict_index, R_A);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_CONFLICT);
}

/* REQ-MDNS-057 (RFC 6762 §9): a conflict nobody defends: the name is
 * probed and announced again and kept; the other records are answered
 * meanwhile */
TEST(itest_mdns_057_conflict_while_running_undefended_keeps_name) {
  peer_dns_msg_t r;
  running(records, N_REC);
  rival_a();
  query(INST, T_SRV, 0);
  ASSERT_NOT_NULL(answered(&r, INST, T_SRV));
  query(HOST, T_A, 0);
  ASSERT_EQ(records_sent(0, HOST, T_A), 0);
  wire_clear(&t);
  ticks(1000, 10);
  ASSERT_EQ(probes(), 3);
  ASSERT_NOT_NULL(answered(&r, HOST, T_A)); /* announced again */
  ASSERT_NULL(peer_dns_find(&r, 0, INST, T_SRV));
  ASSERT_NULL(peer_dns_find(&r, 0, SVC, T_PTR));
  ticks(1000, 10);
  ASSERT_EQ(answers(), 2);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
  ASSERT_EQ(conflicts, 0);
}

/* REQ-MDNS-058 (RFC 6762 §8.3): no announcements without a reason */
TEST(itest_mdns_058_no_periodic_announcements) {
  int s;
  running(records, N_REC);
  for (s = 0; s < 3600; s++)
    mdns_tick(&m, 1000);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-MDNS-059 (RFC 6762 §8.4): a new IPv4 address is announced —
 * mdns_start() after the change */
TEST(itest_mdns_059_new_ipv4_address_announced) {
  peer_dns_msg_t r;
  const peer_rr_t *a;
  running(records, N_REC);
  t.net.ipv4_addr = 0x0A00002Au;
  mdns_start(&m);
  ticks(1000, 250);
  ASSERT_NOT_NULL(a = answered(&r, HOST, T_A));
  ASSERT_EQ(peer_get32(a->rdata), 0x0A00002Au);
  ASSERT_EQ(a->class_, C_IN | C_TOP);
  ticks(1000, 250);
  ASSERT_EQ(answers(), 2);
}

static char inst_name[64];
static const mdns_record_t renamable[N_REC] = {
    {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
    {.type = DNS_TYPE_PTR, .ttl = 4500, .name = SVC, .rdata.ptr = inst_name},
    {.type = DNS_TYPE_SRV,
     .ttl = 120,
     .name = inst_name,
     .rdata.srv = {0, 0, 80, HOST}},
    {.type = DNS_TYPE_TXT, .ttl = 4500, .name = inst_name, .rdata.txt = txt},
};

/* The conflict callback of an application that renames its instance */
static void rename_instance(void) {
  mdns_withdraw(&m, 1u << R_PTR); /* goodbye to the old PTR rdata */
  strcpy(inst_name, "Pyro Unit 1 (2)._pyro._tcp.local");
  mdns_start(&m);
}

/* REQ-MDNS-060, REQ-DNSSD-019, 020 (RFC 6762 §8.4, §9): an instance name
 * lost in a conflict: the application's callback picks another — "(2)"
 * appended — and starts again.  That changes the PTR's rdata: the old
 * rdata gets a goodbye before the new is announced — mdns_withdraw() from
 * the callback */
TEST(itest_mdns_060_goodbye_for_old_ptr_rdata_before_renaming) {
  peer_dns_msg_t r;
  const peer_rr_t *ptr;
  char target[256];
  int k, goodbye = -1, renamed = -1;
  strcpy(inst_name, INST);
  running(renamable, N_REC);
  on_conflict_do = rename_instance;
  rival_srv();
  mdns_tick(&m, 250);
  rival_srv(); /* defended */
  ASSERT_EQ(conflicts, 1);
  ticks(2000, 250);
  for (k = 0; nth_response(k, &r); k++) {
    if (!(ptr = peer_dns_find(&r, 0, SVC, T_PTR)))
      continue;
    ASSERT_TRUE(peer_dns_read_name(&r, ptr->rdata_off, target));
    if (strcmp(target, INST) == 0 && ptr->ttl == 0 && goodbye < 0)
      goodbye = k;
    if (strcmp(target, inst_name) == 0 && ptr->ttl == 4500 && renamed < 0)
      renamed = k;
  }
  ASSERT_TRUE(goodbye >= 0);
  ASSERT_TRUE(renamed > goodbye);
}

/* ══ Answering (RFC 6762 §6) ════════════════════════════════════════ */

/* REQ-MDNS-063 (RFC 6762 §6): a record is multicast at most once a second
 * — except to answer a probe, 250 ms after its last multicast at the
 * soonest; unicast answers are not limited */
TEST(itest_mdns_063_record_multicast_at_most_once_a_second) {
  peer_dns_t q;
  peer_dns_msg_t r;
  running(records, N_REC);
  query(HOST, T_A, 0);
  ASSERT_EQ(records_sent(0, HOST, T_A), 1);
  mdns_tick(&m, 500);
  query(HOST, T_A, 0);
  mdns_tick(&m, 200);
  ASSERT_EQ(records_sent(0, HOST, T_A), 1);
  mdns_tick(&m, 2000);
  query(HOST, T_A, 0);
  ASSERT_EQ(records_sent(0, HOST, T_A), 2);

  /* QU: unicast at once */
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, HOST, T_A, C_IN | C_TOP);
  multicast(&q);
  ASSERT_EQ(records_sent(0, HOST, T_A), 3);

  /* a probe (QM) for our name just after the multicast answer */
  wire_clear(&t);
  probe_a(HOST, RIVAL, C_IN);
  mdns_tick(&m, 249);
  ASSERT_EQ(answers(), 0);
  mdns_tick(&m, 251);
  ASSERT_NOT_NULL(answered(&r, HOST, T_A));
  ASSERT_EQ(conflicts, 0);
}

/* REQ-MDNS-007, 030, 064 (RFC 6762 §6): only positive answers, or negative
 * ones for what we own — nothing for names we have no record of, in
 * .local or any other domain; names match whatever their case */
TEST(itest_mdns_064_only_positive_or_owned_negative_answers) {
  peer_dns_msg_t r;
  running(records, N_REC);
  query("nobody.local", T_A, 0);
  query("pyro-dead01.example", T_A, 0);
  query("pyro-dead01", T_A, 0);
  query("local", T_A, 0);
  mdns_tick(&m, 200);
  ASSERT_EQ(responses(), 0);
  query("PYRO-DEAD01.Local", T_A, 0);
  ASSERT_NOT_NULL(answered(&r, HOST, T_A));
  ASSERT_EQ(r.flags & 0x000F, 0);
}

/* REQ-MDNS-065 (RFC 6762 §6.1): a type our unique name lacks gets NSEC */
TEST(itest_mdns_065_nsec_for_missing_type) {
  peer_dns_t q;
  peer_dns_msg_t r;
  running(records, N_REC);
  query(HOST, T_HINFO, 0);
  ASSERT_NOT_NULL(answered(&r, HOST, T_NSEC));
  query(INST, T_A, 0);
  ASSERT_NOT_NULL(answered(&r, INST, T_NSEC));

  /* a type it has and one it lacks, in one query: both in one response */
  later();
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, HOST, T_A, C_IN);
  peer_dns_question(&q, HOST, T_HINFO, C_IN);
  multicast(&q);
  ASSERT_EQ(responses(), 1);
  ASSERT_TRUE(response(0, &r));
  ASSERT_EQ(r.an, 2);
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, HOST, T_A));
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, HOST, T_NSEC));
}

/* REQ-MDNS-066 (RFC 6762 §6): a shared name is not answered negatively —
 * no NSEC, no NXDOMAIN, nothing */
TEST(itest_mdns_066_no_negative_answer_for_shared_records) {
  running(records, N_REC);
  query(SVC, T_TXT, 0);
  query(SVC, T_SRV, 0);
  mdns_tick(&m, 200);
  ASSERT_EQ(responses(), 0);
}

/* REQ-MDNS-067 (RFC 6762 §6.1): NSEC in the restricted form: the own name
 * as Next Domain Name, block 0 of 1-32 bytes, the NSEC bit clear */
TEST(itest_mdns_067_nsec_restricted_form) {
  peer_dns_msg_t r;
  const peer_rr_t *n;
  char next[256];
  uint8_t len;
  running(records, N_REC);
  query(HOST, T_HINFO, 0);
  ASSERT_NOT_NULL(n = answered(&r, HOST, T_NSEC));
  ASSERT_EQ(n->ttl, 120u);
  ASSERT_EQ(n->rdata[0] & 0xC0, 0xC0); /* two bytes, compressed */
  ASSERT_TRUE(peer_dns_read_name(&r, n->rdata_off, next));
  ASSERT_TRUE(strcmp(next, HOST) == 0);
  ASSERT_EQ(n->rdata[2], 0);
  len = n->rdata[3];
  ASSERT_TRUE(len >= 1 && len <= 32);
  ASSERT_EQ(n->rdlen, 4 + len);
  ASSERT_EQ(n->rdata[4], 0x40); /* A */
  if (len > 5)
    ASSERT_EQ(n->rdata[4 + 5] & 0x01, 0); /* NSEC (47) */
  ASSERT_EQ(len, 1); /* the host has an A record and nothing else */

  query(INST, T_A, 0); /* the instance: TXT (16) and SRV (33) */
  ASSERT_NOT_NULL(n = answered(&r, INST, T_NSEC));
  ASSERT_EQ(n->rdlen, 2 + 2 + 5);
  ASSERT_MEM_EQ(n->rdata + 2, "\x00\x05\x00\x00\x80\x00\x40", 7);
}

/* REQ-MDNS-068 (RFC 6762 §6.1): negative answers only for names we own:
 * not another host's, not a shared one, not while probing */
TEST(itest_mdns_068_negative_answers_only_for_owned_names) {
  running(records, N_REC);
  query("other.local", T_HINFO, 0);
  query(SVC, T_HINFO, 0);
  query(META, T_HINFO, 0);
  mdns_tick(&m, 200);
  ASSERT_EQ(responses(), 0);
  query(HOST, T_ANY, 0); /* ANY: what there is, and no NSEC */
  ASSERT_EQ(records_sent(0, HOST, T_A), 1);
  ASSERT_EQ(records_sent(0, HOST, T_NSEC), 0);
  probing(records, N_REC);
  query(HOST, T_HINFO, 0);
  query(INST, T_A, 0);
  mdns_tick(&m, 200);
  ASSERT_EQ(answers(), 0);
}

/* REQ-MDNS-069 (RFC 6762 §6.1): an NSEC record that cannot be parsed does
 * not make the message be ignored */
TEST(itest_mdns_069_unparseable_nsec_does_not_hide_the_message) {
  peer_dns_t r;
  uint8_t rd[32], a[4];
  uint16_t n;
  probing(records, N_REC);
  peer_dns_begin(&r, 0, FLAG_QR | FLAG_AA);
  n = peer_dns_name(rd, "x.local");
  rd[n] = 5; /* block 5, length 0 */
  rd[n + 1] = 0;
  peer_dns_rr(&r, 0, "x.local", T_NSEC, C_IN | C_TOP, 120, rd,
              (uint16_t)(n + 2));
  peer_put32(a, RIVAL);
  peer_dns_rr(&r, 0, HOST, T_A, C_IN | C_TOP, 120, a, 4);
  multicast(&r);
  ASSERT_EQ(conflicts, 1);
}

/* REQ-MDNS-071, 028 (RFC 6762 §6): responses go from 5353 to
 * 224.0.0.251:5353, unicast only to a QU question (port 5353) or a legacy
 * query (its port) */
TEST(itest_mdns_071_response_destinations) {
  peer_dns_t q;
  peer_dns_msg_t r;
  peer_ip_t ip;
  peer_udp_t udp;
  uint16_t f;
  running(records, N_REC);
  query(HOST, T_A, 0);
  ASSERT_TRUE(sent(0, &r, &ip, &udp, &f));
  ASSERT_EQ(ip.dst, MDNS_GROUP);
  ASSERT_MEM_EQ(wire_sent(&t, f)->data, group_mac, 6);
  ASSERT_EQ(udp.sport, MDNS_PORT);
  ASSERT_EQ(udp.dport, MDNS_PORT);

  wire_clear(&t);
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, INST, T_SRV, C_IN | C_TOP);
  multicast(&q);
  ASSERT_TRUE(sent(0, &r, &ip, &udp, &f));
  ASSERT_EQ(ip.dst, PEER_IP);
  ASSERT_MEM_EQ(wire_sent(&t, f)->data, peer_mac, 6);
  ASSERT_EQ(udp.dport, MDNS_PORT);

  wire_clear(&t);
  peer_dns_begin(&q, 9, 0);
  peer_dns_question(&q, INST, T_TXT, C_IN);
  send_from(PEER_IP, LEGACY_PORT, &q);
  ASSERT_TRUE(sent(0, &r, &ip, &udp, &f));
  ASSERT_EQ(ip.dst, PEER_IP);
  ASSERT_EQ(udp.sport, MDNS_PORT);
  ASSERT_EQ(udp.dport, LEGACY_PORT);
}

/* REQ-MDNS-072 (RFC 6762 §6, §6.5): qclass ANY and qtype ANY match */
TEST(itest_mdns_072_any_type_and_class) {
  peer_dns_msg_t r;
  peer_dns_t q;
  running(records, N_REC);
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, HOST, T_A, 255);
  multicast(&q);
  ASSERT_NOT_NULL(answered(&r, HOST, T_A));
  query(INST, T_ANY, 0);
  ASSERT_NOT_NULL(answered(&r, INST, T_SRV));
  ASSERT_NOT_NULL(answered(&r, INST, T_TXT));
}

/* REQ-MDNS-073 (RFC 6762 §6.3): a query with several questions gets the
 * answers we have */
TEST(itest_mdns_073_several_questions) {
  peer_dns_t q;
  peer_dns_msg_t r;
  running(records, N_REC);
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, "nobody.local", T_A, C_IN);
  peer_dns_question(&q, HOST, T_A, C_IN);
  peer_dns_question(&q, INST, T_TXT, C_IN);
  multicast(&q);
  mdns_tick(&m, 150);
  ASSERT_NOT_NULL(answered(&r, HOST, T_A));
  ASSERT_NOT_NULL(answered(&r, INST, T_TXT));
}

/* No A record with @p addr sent; an NSEC for HOST without A instead */
static int no_a_but_nsec(uint32_t addr) {
  peer_dns_msg_t r;
  const peer_rr_t *n;
  int k;
  uint16_t i;
  for (k = 0; nth_response(k, &r); k++) {
    for (i = 0; i < r.n_rr; i++) {
      if (r.rr[i].type == T_A && peer_get32(r.rr[i].rdata) == addr)
        return 0;
    }
  }
  n = answered(&r, HOST, T_NSEC);
  return n && n->rdlen >= 5 && (n->rdata[4] & 0x40) == 0;
}

/* REQ-MDNS-074 (RFC 6762 §6.2): an A record carries the interface's
 * address only — not a fixed address that is not the interface's, and
 * nothing while the interface has none; it follows the interface to a
 * new address */
TEST(itest_mdns_074_only_valid_ipv4_addresses) {
  static const mdns_record_t fixed[] = {
      {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = PEER2_IP},
  };
  peer_dns_msg_t r;
  const peer_rr_t *a;
  running(fixed, 1);
  query(HOST, T_A, 0);
  ASSERT_TRUE(no_a_but_nsec(PEER2_IP));

  running(records, N_REC);
  t.net.ipv4_addr = 0; /* the lease lost */
  query(HOST, T_A, 0);
  ASSERT_TRUE(no_a_but_nsec(0));

  running(records, N_REC);
  t.net.ipv4_addr = 0x0A00002Au; /* another address: the record follows */
  query(HOST, T_A, 0);
  ASSERT_NOT_NULL(a = answered(&r, HOST, T_A));
  ASSERT_EQ(peer_get32(a->rdata), 0x0A00002Au);
}

/* REQ-MDNS-075 (RFC 6762 §6.6): another host multicasting our record with
 * less than half its TTL — a goodbye too — gets our own multicast */
TEST(itest_mdns_075_low_ttl_copy_of_our_record_corrected) {
  peer_dns_msg_t r;
  const peer_rr_t *a;
  running(records, N_REC);
  claim_a(PEER_IP, MDNS_GROUP, MDNS_PORT, FLAG_QR | FLAG_AA, HOST, OUR_IP, 0);
  mdns_tick(&m, 150);
  ASSERT_NOT_NULL(a = answered(&r, HOST, T_A));
  ASSERT_EQ(a->ttl, 120u);
  wire_clear(&t);
  mdns_tick(&m, 2000);
  claim_a(PEER_IP, MDNS_GROUP, MDNS_PORT, FLAG_QR | FLAG_AA, HOST, OUR_IP, 59);
  mdns_tick(&m, 150);
  ASSERT_NOT_NULL(answered(&r, HOST, T_A));
  wire_clear(&t);
  mdns_tick(&m, 2000);
  claim_a(PEER_IP, MDNS_GROUP, MDNS_PORT, FLAG_QR | FLAG_AA, HOST, OUR_IP, 60);
  mdns_tick(&m, 150);
  ASSERT_EQ(responses(), 0);
  ASSERT_EQ(conflicts, 0);
}

/* REQ-MDNS-076 (RFC 6762 §6.7): no cache-flush bit in a legacy response */
TEST(itest_mdns_076_no_cache_flush_in_legacy_responses) {
  peer_dns_t q;
  peer_dns_msg_t r;
  uint16_t i;
  running(records, N_REC);
  peer_dns_begin(&q, 5, 0);
  peer_dns_question(&q, INST, T_SRV, C_IN);
  send_from(PEER_IP, LEGACY_PORT, &q);
  ASSERT_NOT_NULL(answered(&r, INST, T_SRV));
  ASSERT_TRUE(r.n_rr >= 2); /* the A record too */
  for (i = 0; i < r.n_rr; i++)
    ASSERT_EQ(r.rr[i].class_, C_IN);
}

/* A truncated query for the service type from @p src */
static void truncated_ptr_query(uint32_t src) {
  peer_dns_t q;
  peer_dns_begin(&q, 0, FLAG_TC);
  peer_dns_question(&q, SVC, T_PTR, C_IN);
  send_from(src, MDNS_PORT, &q);
}

/* Known answers from @p src: our PTR */
static void known_ptr(uint32_t src) {
  peer_dns_t q;
  uint8_t rd[64];
  peer_dns_begin(&q, 0, 0);
  peer_dns_rr(&q, 0, SVC, T_PTR, C_IN, 4500, rd, peer_dns_name(rd, INST));
  send_from(src, MDNS_PORT, &q);
}

/* REQ-MDNS-077 (RFC 6762 §7.2): known answers after a truncated query
 * strike an answer only if they come from the querier and nobody else
 * asked for it */
TEST(itest_mdns_077_known_answers_only_from_the_querier) {
  peer_dns_t q;
  peer_dns_msg_t r;
  running(records, N_REC);
  truncated_ptr_query(PEER_IP);
  known_ptr(PEER2_IP); /* another host's */
  mdns_tick(&m, 500);
  ASSERT_NOT_NULL(answered(&r, SVC, T_PTR));

  running(records, N_REC);
  truncated_ptr_query(PEER_IP);
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, SVC, T_PTR, C_IN);
  send_from(PEER2_IP, MDNS_PORT, &q); /* someone else waits too */
  known_ptr(PEER_IP);
  mdns_tick(&m, 500);
  ASSERT_NOT_NULL(answered(&r, SVC, T_PTR));

  running(records, N_REC);
  truncated_ptr_query(PEER_IP);
  truncated_ptr_query(PEER2_IP); /* the querier now; the first still waits */
  known_ptr(PEER2_IP);
  known_ptr(PEER_IP);
  mdns_tick(&m, 500);
  ASSERT_NOT_NULL(answered(&r, SVC, T_PTR));
}

/* REQ-MDNS-078 (RFC 6762 §10.2): the cache-flush bit on every unique
 * record, never on a shared one */
TEST(itest_mdns_078_cache_flush_on_unique_records_only) {
  peer_dns_msg_t r;
  int k;
  uint16_t i;
  up_with(records, N_REC, 1514);
  mdns_start(&m);
  ticks(2000, 250);
  mdns_stop(&m);
  for (k = 0; nth_response(k, &r); k++) {
    for (i = 0; i < r.n_rr; i++)
      ASSERT_EQ(r.rr[i].class_, r.rr[i].type == T_PTR ? C_IN : C_IN | C_TOP);
  }
  ASSERT_EQ(k, 3); /* two announcements, the goodbye */
}

/* REQ-MDNS-079 (RFC 6762 §10.2): a unique RRSet goes out whole — a known
 * answer for one SRV of two does not leave the other alone */
TEST(itest_mdns_079_whole_unique_rrset) {
  static const mdns_record_t two_srv[] = {
      {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
      {.type = DNS_TYPE_SRV,
       .ttl = 120,
       .name = INST,
       .rdata.srv = {0, 0, 80, HOST}},
      {.type = DNS_TYPE_SRV,
       .ttl = 120,
       .name = INST,
       .rdata.srv = {0, 0, 81, HOST}},
  };
  peer_dns_t q;
  uint8_t rd[64];
  running(two_srv, 3);
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, INST, T_SRV, C_IN);
  peer_dns_rr(&q, 0, INST, T_SRV, C_IN, 120, rd, srv_rdata(rd, 80, HOST));
  multicast(&q);
  mdns_tick(&m, 150);
  ASSERT_EQ(records_sent(0, INST, T_SRV), 2);
}

/* ══ Starting, stopping, and what every message has ════════════════ */

#define IGMP_REPORT 0x16
#define IGMP_LEAVE 0x17
#define ALL_ROUTERS 0xE0000002u /* 224.0.0.2 */

/* IGMP messages of @p type about 224.0.0.251 sent to @p dst */
static int igmp_sent(uint8_t type, uint32_t dst) {
  peer_ip_t ip;
  uint16_t i;
  int n = 0;
  for (i = 0; wire_sent(&t, i); i++) {
    if (peer_parse_ipv4(wire_sent(&t, i), &ip) && ip.proto == 2 &&
        ip.dst == dst && ip.payload_len >= 8 && ip.payload[0] == type &&
        peer_get32(ip.payload + 4) == MDNS_GROUP)
      n++;
  }
  return n;
}

/* mdns_tick() a millisecond at a time until the stack sends an mDNS
 * message: how many it took, or 0 if none came within @p limit */
static uint32_t ms_until_sent(uint32_t limit) {
  int before = responses();
  uint32_t ms;
  for (ms = 1; ms <= limit; ms++) {
    mdns_tick(&m, 1);
    if (responses() != before)
      return ms;
  }
  return 0;
}

/* A query for @p name's @p type from a querier that already knows the
 * record with @p rdata and @p ttl (a known answer, RFC 6762 §7.1) */
static void query_knowing(const char *name, uint16_t type, uint16_t class_,
                          const void *rdata, uint16_t rdlen, uint32_t ttl) {
  peer_dns_t q;
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, name, type, C_IN);
  peer_dns_rr(&q, 0, name, type, class_, ttl, rdata, rdlen);
  multicast(&q);
}

/* The TTL of @p name's @p type record in @p section of @p msg */
static uint32_t ttl_of(const peer_dns_msg_t *msg, int section, const char *name,
                       uint16_t type) {
  const peer_rr_t *r = peer_dns_find(msg, section, name, type);
  return r ? r->ttl : 0xFFFFFFFFu;
}

/* REQ-MDNS-002, 025: before mdns_start() the responder hears nothing on
 * 224.0.0.251 and sends nothing; mdns_start() joins the group — an IGMP
 * report, repeated once — and queries to it are answered; mdns_stop()
 * leaves the group and the responder is silent again */
TEST(itest_mdns_002_group_joined_at_start_left_at_stop) {
  peer_dns_msg_t r;
  up_with(records, N_REC, 1514);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_STOPPED);
  mdns_tick(&m, 5000);
  query(HOST, T_A, 0);
  ASSERT_EQ(t.wire.tx_count, 0);

  mdns_start(&m);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_PROBING);
  ASSERT_EQ(igmp_sent(IGMP_REPORT, MDNS_GROUP), 1);
  ticks(4000, 250);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
  ASSERT_EQ(igmp_sent(IGMP_REPORT, MDNS_GROUP), 2);
  wire_clear(&t);
  query(HOST, T_A, 0);
  ASSERT_NOT_NULL(answered(&r, HOST, T_A));

  wire_clear(&t);
  mdns_stop(&m);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_STOPPED);
  ASSERT_EQ(igmp_sent(IGMP_LEAVE, ALL_ROUTERS), 1);
  wire_clear(&t);
  mdns_tick(&m, 5000);
  query(HOST, T_A, 0);
  mdns_stop(&m); /* stopped already: nothing more */
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-MDNS-001, 003, 004, 005, 006, 031 (RFC 6762 §5.2, §6, §11, §18):
 * every message — probe, announcement, answer, goodbye — is a DNS message
 * from port 5353 to 224.0.0.251:5353 with IP TTL 255 and ID 0, the
 * responses authoritative; a unicast answer has TTL 255 too */
TEST(itest_mdns_001_port_ttl_and_id_of_everything_sent) {
  peer_dns_t q;
  peer_dns_msg_t r;
  peer_ip_t ip;
  peer_udp_t udp;
  uint16_t i;
  int k;
  up_with(records, N_REC, 1514);
  mdns_start(&m);
  ticks(4000, 250);
  query(HOST, T_A, 0);
  mdns_stop(&m);
  for (k = 0; sent(k, &r, &ip, &udp, NULL); k++) {
    ASSERT_EQ(udp.sport, MDNS_PORT);
    ASSERT_EQ(udp.dport, MDNS_PORT);
    ASSERT_TRUE(udp.cksum_ok);
    ASSERT_EQ(ip.src, OUR_IP);
    ASSERT_EQ(ip.dst, MDNS_GROUP);
    ASSERT_EQ(ip.ttl, 255);
    ASSERT_EQ(r.id, 0);
    ASSERT_EQ(r.flags, k < 3 ? 0 : FLAG_QR | FLAG_AA);
    for (i = 0; i < r.n_rr && k < 6; i++) /* all but the goodbye */
      ASSERT_TRUE(r.rr[i].ttl > 0);
  }
  ASSERT_EQ(k, 7); /* three probes, two announcements, an answer, a goodbye */

  running(records, N_REC);
  peer_dns_begin(&q, 0x99, 0);
  peer_dns_question(&q, HOST, T_A, C_IN | C_TOP);
  multicast(&q);
  ASSERT_TRUE(sent(0, &r, &ip, &udp, NULL));
  ASSERT_EQ(ip.dst, PEER_IP);
  ASSERT_EQ(ip.ttl, 255);
  ASSERT_EQ(udp.sport, MDNS_PORT);
  ASSERT_EQ(r.flags, FLAG_QR | FLAG_AA);
}

/* REQ-MDNS-008, REQ-DNSSD-009, 010: the records are the application's
 * table, given at mdns_init(), which checks it and sends nothing: no
 * records, more than MDNS_MAX_RECORDS, a type the responder does not
 * serve, a PTR without a target or a name with an empty label are
 * refused; a full table is taken, and all of it announced */
TEST(itest_mdns_008_record_table_given_at_init) {
  static const mdns_record_t hinfo[] = {
      {.type = T_HINFO, .ttl = 120, .name = HOST}};
  static const mdns_record_t no_target[] = {
      {.type = DNS_TYPE_PTR, .ttl = 4500, .name = SVC, .rdata.ptr = NULL}};
  static const mdns_record_t empty_label[] = {
      {.type = DNS_TYPE_A, .ttl = 120, .name = "a..local"}};
  static mdns_record_t full[MDNS_MAX_RECORDS + 1];
  static char names[MDNS_MAX_RECORDS + 1][12];
  peer_dns_msg_t r;
  unsigned i;
  for (i = 0; i <= MDNS_MAX_RECORDS; i++) {
    snprintf(names[i], sizeof(names[i]), "h%02u.local", i);
    full[i].type = DNS_TYPE_A;
    full[i].ttl = 120;
    full[i].name = names[i];
  }
  ASSERT_EQ(up_with(records, 0, 1514), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(up_with(NULL, 1, 1514), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(up_with(full, MDNS_MAX_RECORDS + 1, 1514), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(up_with(hinfo, 1, 1514), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(up_with(no_target, 1, 1514), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(up_with(empty_label, 1, 1514), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(up_with(full, MDNS_MAX_RECORDS, 1514), NET_OK);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_STOPPED);
  ASSERT_EQ(t.wire.tx_count, 0);
  mdns_start(&m);
  ticks(1000, 250);
  ASSERT_TRUE(nth_response(0, &r));
  ASSERT_EQ(r.an, MDNS_MAX_RECORDS);
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, names[0], T_A));
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, names[MDNS_MAX_RECORDS - 1], T_A));
}

/* REQ-MDNS-009, 010, 011, 012, 026, REQ-DNSSD-001, 002, 003, 006, 011: each
 * record of the table is answered, its rdata as RFC 1035 and RFC 2782 lay
 * it out: the A record's address, the PTR's target, the SRV's priority,
 * weight, port and target, the TXT's strings behind a length byte each.
 * REQ-DNSSD-036, 037: the TXT strings are the application's, sent as
 * given: nothing added, quoted, or repeated from the SRV record */
TEST(itest_mdns_009_each_record_answered_with_its_rdata) {
  static const char *const strings[] = {"txtvers=1", "fw=1.2.3",
                                        "serial=DEAD01", NULL};
  static const mdns_record_t recs[] = {
      {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
      {.type = DNS_TYPE_PTR, .ttl = 4500, .name = SVC, .rdata.ptr = INST},
      {.type = DNS_TYPE_SRV,
       .ttl = 120,
       .name = INST,
       .rdata.srv = {1, 2, 8080, HOST}},
      {.type = DNS_TYPE_TXT, .ttl = 4500, .name = INST, .rdata.txt = strings},
  };
  static const char txt_rdata[] = "\x09txtvers=1\x08"
                                  "fw=1.2.3\x0dserial=DEAD01";
  peer_dns_msg_t r;
  const peer_rr_t *rr;
  char name[256];
  running(recs, 4);
  query(HOST, T_A, 0);
  ASSERT_NOT_NULL(rr = answered(&r, HOST, T_A));
  ASSERT_EQ(rr->rdlen, 4);
  ASSERT_EQ(peer_get32(rr->rdata), OUR_IP);

  query(INST, T_SRV, 0);
  ASSERT_NOT_NULL(rr = answered(&r, INST, T_SRV));
  ASSERT_EQ(peer_get16(rr->rdata), 1);
  ASSERT_EQ(peer_get16(rr->rdata + 2), 2);
  ASSERT_EQ(peer_get16(rr->rdata + 4), 8080);
  ASSERT_TRUE(peer_dns_read_name(&r, (uint16_t)(rr->rdata_off + 6), name));
  ASSERT_TRUE(strcmp(name, HOST) == 0);

  query(INST, T_TXT, 0);
  ASSERT_NOT_NULL(rr = answered(&r, INST, T_TXT));
  ASSERT_EQ(rr->rdlen, sizeof(txt_rdata) - 1);
  ASSERT_MEM_EQ(rr->rdata, txt_rdata, sizeof(txt_rdata) - 1);

  query(SVC, T_PTR, 0);
  mdns_tick(&m, 150);
  ASSERT_NOT_NULL(rr = answered(&r, SVC, T_PTR));
  ASSERT_TRUE(peer_dns_read_name(&r, rr->rdata_off, name));
  ASSERT_TRUE(strcmp(name, INST) == 0);
}

/* REQ-MDNS-014, 015, REQ-DNSSD-016, 017 (RFC 6762 §10): the TTLs are the
 * table's — 120 s for the records with a host name as their name or in
 * their rdata (A, SRV), 75 minutes for the others (PTR, TXT) */
TEST(itest_mdns_014_ttls_as_the_table_gives_them) {
  peer_dns_msg_t r;
  ASSERT_EQ(MDNS_TTL_HOST, 120);
  ASSERT_EQ(MDNS_TTL_OTHER, 4500);
  up_with(records, N_REC, 1514);
  mdns_start(&m);
  ticks(1000, 250);
  ASSERT_TRUE(nth_response(0, &r));
  ASSERT_EQ(ttl_of(&r, 0, HOST, T_A), 120u);
  ASSERT_EQ(ttl_of(&r, 0, INST, T_SRV), 120u);
  ASSERT_EQ(ttl_of(&r, 0, SVC, T_PTR), 4500u);
  ASSERT_EQ(ttl_of(&r, 0, INST, T_TXT), 4500u);
}

/* ══ Probing and announcing: the timing ═════════════════════════════ */

/* REQ-MDNS-016, 017, 018, 021, 022, 023 (RFC 6762 §8.1, §8.3): the first
 * probe after a random 0-250 ms, the second and third 250 ms apart; 250
 * ms after the third, with no conflict, the first announcement — a
 * multicast response with every record in its Answer section — and the
 * second a second later; then nothing */
TEST(itest_mdns_017_probe_and_announcement_timing) {
  peer_dns_msg_t r;
  uint32_t least = 1000, most = 0, ms;
  int k;
  up_with(records, N_REC, 1514);
  for (k = 0; k < 40; k++) {
    mdns_start(&m);
    wire_clear(&t);
    ms = ms_until_sent(300);
    ASSERT_TRUE(ms >= 1 && ms <= 250);
    least = ms < least ? ms : least;
    most = ms > most ? ms : most;
  }
  ASSERT_TRUE(least < 50 && most > 200); /* spread over the range */
  ASSERT_EQ(probes(), 1);
  ASSERT_EQ(ms_until_sent(300), 250u);
  ASSERT_EQ(ms_until_sent(300), 250u);
  ASSERT_EQ(probes(), 3);
  ASSERT_EQ(answers(), 0);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_PROBING);
  ASSERT_EQ(ms_until_sent(300), 250u);
  ASSERT_EQ(probes(), 3);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_ANNOUNCING);
  ASSERT_TRUE(nth_response(0, &r));
  ASSERT_EQ(r.qd, 0);
  ASSERT_EQ(r.an, N_REC);
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, HOST, T_A));
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, SVC, T_PTR));
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, INST, T_SRV));
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, INST, T_TXT));
  ASSERT_EQ(ms_until_sent(1100), 1000u);
  ASSERT_EQ(answers(), 2);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
  ASSERT_EQ(ms_until_sent(5000), 0u);
}

/* REQ-MDNS-019, 020, REQ-DNSSD-019 (RFC 6762 §8.1, §9): a conflicting
 * response while probing: the host defers — the application is told
 * which record, and the responder uses none of its names: no more
 * probes, no announcement, no answers.  A goodbye (TTL 0) under the name
 * is no conflict; a responder without a callback gives up as well */
TEST(itest_mdns_019_failed_probe_gives_up_the_names) {
  probing(records, N_REC);
  claim_a(PEER_IP, MDNS_GROUP, MDNS_PORT, FLAG_QR | FLAG_AA, HOST, RIVAL, 0);
  ASSERT_EQ(conflicts, 0);
  rival_a();
  ASSERT_EQ(conflicts, 1);
  ASSERT_EQ(conflict_index, R_A);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_CONFLICT);
  ticks(5000, 250);
  query(HOST, T_A, 0);
  query(INST, T_SRV, 0);
  query(SVC, T_PTR, 0);
  mdns_tick(&m, 200);
  ASSERT_EQ(responses(), 0);

  probing(records, N_REC);
  rival_srv();
  ASSERT_EQ(conflicts, 1);
  ASSERT_EQ(conflict_index, R_SRV);

  up_with(records, N_REC, 1514);
  mdns_init(&m, &t.net, records, N_REC, NULL, NULL);
  mdns_start(&m);
  mdns_tick(&m, 250);
  rival_a();
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_CONFLICT);
}

static char host_name[32];
static const mdns_record_t renamable_host[] = {
    {.type = DNS_TYPE_A, .ttl = 120, .name = host_name, .rdata.a = 0},
};

/* The conflict callback of an application that renames its host */
static void rename_host(void) {
  strcpy(host_name, "pyro-dead01-2.local");
  mdns_start(&m);
}

/* REQ-MDNS-020 (RFC 6762 §9): from its conflict callback the application
 * renames the record and starts again: the new name is probed for and
 * announced, the old one never */
TEST(itest_mdns_020_callback_renames_and_starts_again) {
  peer_dns_msg_t p, r;
  strcpy(host_name, HOST);
  probing(renamable_host, 1);
  on_conflict_do = rename_host;
  rival_a();
  ASSERT_EQ(conflicts, 1);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_PROBING);
  ticks(2000, 250);
  ASSERT_EQ(probes(), 3);
  ASSERT_TRUE(nth_probe(0, &p));
  ASSERT_TRUE(strcmp(p.qname, "pyro-dead01-2.local") == 0);
  ASSERT_NOT_NULL(answered(&r, "pyro-dead01-2.local", T_A));
  ASSERT_EQ(records_sent(0, HOST, T_A), 0);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
}

/* REQ-MDNS-021, 068: while probing, a name that is not ours yet is not
 * answered for — neither with its records nor negatively; once probing
 * is over, while the announcements are still going out, it is */
TEST(itest_mdns_021_answers_only_once_probing_is_over) {
  peer_dns_msg_t r;
  uint8_t inst[64];
  probing(records, N_REC);
  query(HOST, T_A, 0);
  query(HOST, T_HINFO, 0);
  query(SVC, T_PTR, 0);
  query_knowing(SVC, T_PTR, C_IN, inst, peer_dns_name(inst, INST), 100);
  ticks(700, 250);
  ASSERT_EQ(answers(), 0);
  mdns_tick(&m, 50);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_ANNOUNCING);
  wire_clear(&t);
  query(HOST, T_HINFO, 0);
  ASSERT_NOT_NULL(answered(&r, HOST, T_NSEC));
}

/* REQ-MDNS-024 (RFC 6762 §8): after a change of connectivity — the
 * application calls mdns_start() again on link-up — every record is
 * probed for and announced again, and the group joined again */
TEST(itest_mdns_024_start_again_probes_and_announces_again) {
  peer_dns_msg_t r;
  running(records, N_REC);
  mdns_start(&m);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_PROBING);
  ASSERT_EQ(igmp_sent(IGMP_REPORT, MDNS_GROUP), 1);
  ticks(2000, 250);
  ASSERT_EQ(probes(), 3);
  ASSERT_EQ(answers(), 2);
  ASSERT_TRUE(nth_response(0, &r));
  ASSERT_EQ(r.an, N_REC);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
}

/* ══ Answering: when, and with what besides ═════════════════════════ */

/* REQ-MDNS-027, REQ-DNSSD-004, 007, 008 (RFC 6762 §6, RFC 6763 §12): an
 * answer of unique records goes out at once; one with a shared record
 * after a random 20-120 ms, and what is asked meanwhile joins it.  A PTR
 * answer brings the instance's SRV and TXT and the host's A as
 * additional records, an SRV answer the A */
TEST(itest_mdns_027_unique_at_once_shared_after_20_to_120_ms) {
  peer_dns_msg_t r;
  uint32_t least = 1000, most = 0, ms;
  int k;
  running(records, N_REC);
  query(INST, T_SRV, 0);
  ASSERT_EQ(responses(), 1);
  ASSERT_TRUE(response(0, &r));
  ASSERT_EQ(r.an, 1);
  ASSERT_EQ(r.ar, 1);
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, INST, T_SRV));
  ASSERT_NOT_NULL(peer_dns_find(&r, 2, HOST, T_A));

  for (k = 0; k < 40; k++) {
    later();
    query(SVC, T_PTR, 0);
    ASSERT_EQ(responses(), 0);
    ms = ms_until_sent(200);
    ASSERT_TRUE(ms >= 20 && ms <= 120);
    least = ms < least ? ms : least;
    most = ms > most ? ms : most;
  }
  ASSERT_TRUE(least < 40 && most > 100); /* spread over the range */
  ASSERT_TRUE(response(0, &r));
  ASSERT_EQ(r.an, 1);
  ASSERT_EQ(r.ar, 3);
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, SVC, T_PTR));
  ASSERT_NOT_NULL(peer_dns_find(&r, 2, INST, T_SRV));
  ASSERT_NOT_NULL(peer_dns_find(&r, 2, INST, T_TXT));
  ASSERT_NOT_NULL(peer_dns_find(&r, 2, HOST, T_A));

  later();
  query(SVC, T_PTR, 0);
  mdns_tick(&m, 10);
  query(META, T_PTR, 0);
  ms = ms_until_sent(200);
  ASSERT_TRUE(ms >= 1 && ms <= 110);
  ASSERT_TRUE(response(0, &r));
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, SVC, T_PTR));
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, META, T_PTR));
  mdns_tick(&m, 1000);
  ASSERT_EQ(responses(), 1); /* sent once */
}

/* REQ-MDNS-028 (RFC 6762 §5.4): a question with the QU bit is answered by
 * unicast to the querier — but by multicast if the querier has no
 * address yet (0.0.0.0) */
TEST(itest_mdns_028_qu_question_answered_by_unicast) {
  peer_dns_t q;
  peer_dns_msg_t r;
  peer_ip_t ip;
  peer_udp_t udp;
  uint16_t f;
  running(records, N_REC);
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, HOST, T_A, C_IN | C_TOP);
  multicast(&q);
  ASSERT_TRUE(sent(0, &r, &ip, &udp, &f));
  ASSERT_EQ(ip.dst, PEER_IP);
  ASSERT_MEM_EQ(wire_sent(&t, f)->data, peer_mac, 6);
  ASSERT_EQ(udp.dport, MDNS_PORT);
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, HOST, T_A));

  wire_clear(&t);
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, HOST, T_A, C_IN | C_TOP);
  send_from(0, MDNS_PORT, &q);
  ASSERT_TRUE(sent(0, &r, &ip, &udp, &f));
  ASSERT_EQ(ip.dst, MDNS_GROUP);
  ASSERT_MEM_EQ(wire_sent(&t, f)->data, group_mac, 6);
}

/* REQ-MDNS-029 (RFC 6762 §7.1): an answer the query's Answer section
 * already holds, with at least half its TTL, is not sent — one with less,
 * with other rdata or of another class is */
TEST(itest_mdns_029_known_answer_suppression) {
  peer_dns_msg_t r;
  uint8_t inst[64], other[64], svc[64], addr[4], srv[64];
  uint16_t inst_len = peer_dns_name(inst, INST);
  uint16_t other_len = peer_dns_name(other, "Someone Else._pyro._tcp.local");
  uint16_t svc_len = peer_dns_name(svc, SVC);
  running(records, N_REC);
  query_knowing(SVC, T_PTR, C_IN, inst, inst_len, 2250);
  mdns_tick(&m, 200);
  ASSERT_EQ(responses(), 0);
  query_knowing(SVC, T_PTR, C_IN, inst, inst_len, 2249);
  mdns_tick(&m, 200);
  ASSERT_NOT_NULL(answered(&r, SVC, T_PTR));
  later();
  query_knowing(SVC, T_PTR, C_IN, other, other_len, 4500);
  mdns_tick(&m, 200);
  ASSERT_NOT_NULL(answered(&r, SVC, T_PTR));
  later();
  query_knowing(SVC, T_PTR, 3, inst, inst_len, 4500); /* class CH */
  mdns_tick(&m, 200);
  ASSERT_NOT_NULL(answered(&r, SVC, T_PTR));

  /* unique records too */
  later();
  peer_put32(addr, OUR_IP);
  query_knowing(HOST, T_A, C_IN, addr, 4, 120);
  query_knowing(INST, T_SRV, C_IN, srv, srv_rdata(srv, 80, HOST), 60);
  query_knowing(INST, T_TXT, C_IN, "\x09txtvers=1", 10, 4500);
  mdns_tick(&m, 200);
  ASSERT_EQ(responses(), 0);
  peer_put32(addr, RIVAL);
  query_knowing(HOST, T_A, C_IN, addr, 4, 120);
  query_knowing(INST, T_SRV, C_IN, srv, srv_rdata(srv, 81, HOST), 120);
  query_knowing(INST, T_TXT, C_IN, "\x09txtvers=2", 10, 4500);
  query_knowing(INST, T_TXT, C_IN, "\x09txtvers=1\x03x=1", 14, 4500);
  ASSERT_NOT_NULL(answered(&r, HOST, T_A));
  ASSERT_NOT_NULL(answered(&r, INST, T_SRV));
  ASSERT_NOT_NULL(answered(&r, INST, T_TXT));

  /* and the service type's listing under the meta-query */
  later();
  query_knowing(META, T_PTR, C_IN, svc, svc_len, 4500);
  mdns_tick(&m, 200);
  ASSERT_EQ(responses(), 0);
  query_knowing(META, T_PTR, C_IN, svc, svc_len, 2249);
  mdns_tick(&m, 200);
  ASSERT_NOT_NULL(answered(&r, META, T_PTR));
}

/* REQ-MDNS-032, 033 (RFC 6762 §10.1): a goodbye only for what was sent:
 * none from a responder stopped while still probing; a response still
 * owed when it stops is not sent */
TEST(itest_mdns_032_goodbye_only_for_what_was_announced) {
  probing(records, N_REC);
  mdns_stop(&m);
  ASSERT_EQ(responses(), 0);
  ASSERT_EQ(igmp_sent(IGMP_LEAVE, ALL_ROUTERS), 1);

  running(records, N_REC);
  query(SVC, T_PTR, 0);
  mdns_stop(&m);
  ASSERT_EQ(responses(), 1); /* the goodbye */
  wire_clear(&t);
  mdns_tick(&m, 1000);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-MDNS-041 (RFC 6762 §6.7): a query from another port than 5353 is a
 * legacy unicast query: answered at once, by unicast to that port, with
 * its ID and its question, TTLs of at most 10 s — a shared record too.
 * One from 0.0.0.0 cannot be answered */
TEST(itest_mdns_041_legacy_unicast_query_answered) {
  peer_dns_t q;
  peer_dns_msg_t r;
  peer_ip_t ip;
  peer_udp_t udp;
  char name[256];
  uint16_t i;
  running(records, N_REC);
  peer_dns_begin(&q, 0x1234, 0);
  peer_dns_question(&q, HOST, T_A, C_IN);
  send_from(PEER_IP, LEGACY_PORT, &q);
  ASSERT_TRUE(sent(0, &r, &ip, &udp, NULL));
  ASSERT_EQ(ip.dst, PEER_IP);
  ASSERT_EQ(ip.ttl, 255);
  ASSERT_EQ(udp.sport, MDNS_PORT);
  ASSERT_EQ(udp.dport, LEGACY_PORT);
  ASSERT_EQ(r.id, 0x1234);
  ASSERT_EQ(r.flags, FLAG_QR | FLAG_AA);
  ASSERT_EQ(r.qd, 1);
  ASSERT_EQ(question(&r, 0, name), C_IN);
  ASSERT_TRUE(strcmp(name, HOST) == 0);
  ASSERT_EQ(r.qtype, T_A);
  ASSERT_EQ(ttl_of(&r, 0, HOST, T_A), 10u);

  wire_clear(&t);
  peer_dns_begin(&q, 0x1235, 0);
  peer_dns_question(&q, SVC, T_PTR, C_IN);
  send_from(PEER_IP, LEGACY_PORT, &q);
  ASSERT_EQ(responses(), 1); /* not delayed */
  ASSERT_TRUE(response(0, &r));
  ASSERT_EQ(r.id, 0x1235);
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, SVC, T_PTR));
  ASSERT_EQ(r.ar, 3);
  for (i = 0; i < r.n_rr; i++)
    ASSERT_TRUE(r.rr[i].ttl <= 10);

  wire_clear(&t);
  send_from(0, LEGACY_PORT, &q);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-MDNS-041: malformed messages — too short for a header, counts
 * without the data, a compression pointer to itself, a record cut off —
 * draw no reply and leave the responder running */
TEST(itest_mdns_041_malformed_messages_ignored) {
  static const uint8_t short_msg[5] = {0};
  static const uint8_t no_question[12] = {0, 0, 0, 0, 0, 1};
  static const uint8_t loop[] = {0, 0, 0, 0,   0,    1,  0, 0, 0, 0,
                                 0, 0, 1, 'a', 0xC0, 12, 0, 1, 0, 1};
  static const uint8_t huge_counts[12] = {0,    0,    0, 0, 0xFF, 0xFF,
                                          0xFF, 0xFF, 0, 0, 0,    0};
  peer_dns_t q;
  peer_dns_msg_t r;
  uint8_t addr[4];
  running(records, N_REC);
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, short_msg, sizeof(short_msg));
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, no_question, sizeof(no_question));
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, loop, sizeof(loop));
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, huge_counts, sizeof(huge_counts));
  /* responses: a question cut off; two records announced, one there */
  peer_dns_begin(&q, 0, FLAG_QR | FLAG_AA);
  peer_dns_question(&q, HOST, T_A, C_IN);
  peer_dns_end(&q);
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, q.buf, (uint16_t)(q.len - 3));
  peer_dns_begin(&q, 0, FLAG_QR | FLAG_AA);
  peer_put32(addr, OUR_IP);
  peer_dns_rr(&q, 0, HOST, T_A, C_IN | C_TOP, 120, addr, 4);
  peer_dns_end(&q);
  peer_put16(q.buf + 6, 2);
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, q.buf, q.len);
  mdns_tick(&m, 200);
  ASSERT_EQ(responses(), 0);
  ASSERT_EQ(conflicts, 0);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);

  /* a query whose known answer is cut off is still a query */
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, HOST, T_A, C_IN);
  peer_dns_end(&q);
  peer_put16(q.buf + 6, 1);
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, q.buf, q.len);
  ASSERT_NOT_NULL(answered(&r, HOST, T_A));
}

/* REQ-MDNS-041: names that cannot be read — half a compression pointer,
 * a pointer past the message, a label type other than 00 and 11, a label
 * that runs past the end, more than 255 bytes — and records cut short
 * draw no reply and no conflict */
TEST(itest_mdns_041_malformed_names_ignored) {
  static const uint8_t half_pointer[] = {0, 0, 0, 0, 0, 1,   0,
                                         0, 0, 0, 0, 0, 0xC0};
  static const uint8_t far_pointer[] = {0, 0, 0, 0,    0,    1, 0, 0, 0,
                                        0, 0, 0, 0xC0, 0xFF, 0, 1, 0, 1};
  static const uint8_t label_type[] = {0, 0, 0,    0,   0, 1, 0, 0, 0, 0,
                                       0, 0, 0x41, 'a', 0, 0, 1, 0, 1};
  static const uint8_t long_label[] = {0, 0, 0, 0, 0, 1,    0,
                                       0, 0, 0, 0, 0, 0x3F, 'a'};
  static uint8_t long_name[12 + 4 * 64 + 1 + 4];
  peer_dns_t r;
  peer_dns_msg_t a;
  uint8_t addr[4];
  unsigned i;
  long_name[5] = 1;
  for (i = 0; i < 4; i++) {
    long_name[12 + i * 64] = 63;
    memset(long_name + 13 + i * 64, 'a', 63);
  }
  long_name[sizeof(long_name) - 3] = 1; /* type A, class IN */
  long_name[sizeof(long_name) - 1] = 1;
  running(records, N_REC);
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, half_pointer, sizeof(half_pointer));
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, far_pointer, sizeof(far_pointer));
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, label_type, sizeof(label_type));
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, long_label, sizeof(long_label));
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, long_name, sizeof(long_name));
  mdns_tick(&m, 200);
  ASSERT_EQ(t.wire.tx_count, 0);

  /* a response whose record says more rdata than there is, or stops in
   * its header: nothing in it counts */
  probing(records, N_REC);
  peer_dns_begin(&r, 0, FLAG_QR | FLAG_AA);
  peer_put32(addr, RIVAL);
  peer_dns_rr(&r, 0, HOST, T_A, C_IN | C_TOP, 120, addr, 4);
  peer_dns_end(&r);
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, r.buf, (uint16_t)(r.len - 1));
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, r.buf, (uint16_t)(r.len - 6));
  ASSERT_EQ(conflicts, 0);
  ticks(2000, 250);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
  later();
  query(HOST, T_A, 0);
  ASSERT_NOT_NULL(answered(&a, HOST, T_A));
}

/* Three names whose TXT records do not fit one small packet together */
static const char *const t1[] = {
    "k=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NULL};
static const char *const t2[] = {
    "k=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", NULL};
static const char *const t3[] = {
    "k=ccccccccccccccccccccccccccccccccccccccccccc", NULL};
static const mdns_record_t many[] = {
    {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
    {.type = DNS_TYPE_TXT, .ttl = 120, .name = "one.local", .rdata.txt = t1},
    {.type = DNS_TYPE_TXT, .ttl = 120, .name = "two.local", .rdata.txt = t2},
    {.type = DNS_TYPE_TXT, .ttl = 120, .name = "three.local", .rdata.txt = t3},
};
#define SMALL_TX 162 /* 120 bytes of DNS behind the IPv4 and UDP headers */

/* Messages sent that are responses (@p qr 1) or probes (0): how many,
 * none longer than @p max; their questions, answers and authority
 * records added up */
static int sent_within(int qr, uint16_t max, int *qd, int *an, int *ns) {
  peer_dns_msg_t r;
  peer_ip_t ip;
  peer_udp_t udp;
  uint16_t f;
  int k, n = 0;
  *qd = *an = *ns = 0;
  for (k = 0; sent(k, &r, &ip, &udp, &f); k++) {
    if (((r.flags & FLAG_QR) != 0) != qr)
      continue;
    if (wire_sent(&t, f)->len > max)
      return -1;
    *qd += r.qd;
    *an += r.an;
    *ns += r.ns;
    n++;
  }
  return n;
}

/* REQ-MDNS-042, REQ-DNSSD-030 (RFC 6762 §17, §8.3): a message is one
 * frame of at most the TX frame buffer; records that do not fit one are
 * split across several — probes, announcements and answers alike */
TEST(itest_mdns_042_records_split_across_packets) {
  peer_dns_t q;
  int qd, an, ns;
  ASSERT_EQ(up_with(many, 4, SMALL_TX), NET_OK);
  mdns_start(&m);
  mdns_tick(&m, 250); /* the first round of probes */
  ASSERT_TRUE(sent_within(0, SMALL_TX, &qd, &an, &ns) >= 2);
  ASSERT_EQ(qd, 4);
  ASSERT_EQ(ns, 4);
  wire_clear(&t);
  ticks(750, 250); /* two more rounds, then the announcement */
  ASSERT_TRUE(sent_within(1, SMALL_TX, &qd, &an, &ns) >= 2);
  ASSERT_EQ(an, 4);
  ASSERT_EQ(qd, 0);

  /* an answer, and negative answers, more than one packet holds */
  mdns_tick(&m, 1000);
  later();
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, "one.local", T_TXT, C_IN);
  peer_dns_question(&q, "two.local", T_HINFO, C_IN);
  peer_dns_question(&q, "three.local", T_HINFO, C_IN);
  peer_dns_question(&q, HOST, T_HINFO, C_IN);
  multicast(&q);
  ASSERT_TRUE(sent_within(1, SMALL_TX, &qd, &an, &ns) >= 2);
  ASSERT_EQ(an, 4);
  ASSERT_EQ(records_sent(0, "one.local", T_TXT), 1);
  ASSERT_EQ(records_sent(0, "two.local", T_NSEC), 1);
  ASSERT_EQ(records_sent(0, "three.local", T_NSEC), 1);
  ASSERT_EQ(records_sent(0, HOST, T_NSEC), 1);
}

/* REQ-MDNS-043 (RFC 1035 §4.1.4, RFC 6762 §18.14): names are compressed:
 * in an announcement each label is spelled out once, later names
 * pointing back to it */
TEST(itest_mdns_043_names_compressed) {
  peer_dns_msg_t r;
  peer_ip_t ip;
  peer_udp_t udp;
  int k, spelled = 0;
  uint16_t i;
  up_with(records, N_REC, 1514);
  mdns_start(&m);
  ticks(1000, 250);
  for (k = 0; sent(k, &r, &ip, &udp, NULL); k++) {
    if (r.flags & FLAG_QR)
      break;
  }
  ASSERT_TRUE(r.flags & FLAG_QR);
  ASSERT_EQ(r.an, N_REC);
  for (i = 0; i + 12u <= udp.data_len; i++)
    spelled += memcmp(udp.data + i, "\x0bPyro Unit 1", 12) == 0;
  ASSERT_EQ(spelled, 1);
  for (i = 0, spelled = 0; i + 6u <= udp.data_len; i++)
    spelled += memcmp(udp.data + i, "\x05local", 6) == 0;
  ASSERT_EQ(spelled, 1);
  ASSERT_TRUE(udp.data_len < 180);
}

/* REQ-MDNS-056 (RFC 6762 §6, §8.1): no record learned from another host
 * is ever used: what another host announced is not answered from here,
 * and a record heard before probing began does not count against it */
TEST(itest_mdns_056_other_hosts_records_never_used) {
  peer_dns_t a;
  peer_dns_msg_t r;
  const peer_rr_t *ptr;
  uint8_t rd[64];
  char target[256];
  running(records, N_REC);
  claim_a(PEER_IP, MDNS_GROUP, MDNS_PORT, FLAG_QR | FLAG_AA, "other.local",
          RIVAL, 120);
  peer_dns_begin(&a, 0, FLAG_QR | FLAG_AA);
  peer_dns_rr(&a, 0, SVC, T_PTR, C_IN, 4500, rd,
              peer_dns_name(rd, "Other Unit._pyro._tcp.local"));
  multicast(&a);
  query("other.local", T_A, 0);
  query("Other Unit._pyro._tcp.local", T_SRV, 0);
  mdns_tick(&m, 200);
  ASSERT_EQ(responses(), 0);
  query(SVC, T_PTR, 0);
  mdns_tick(&m, 200);
  ASSERT_EQ(records_sent(0, SVC, T_PTR), 1); /* ours alone */
  ASSERT_NOT_NULL(ptr = answered(&r, SVC, T_PTR));
  ASSERT_TRUE(peer_dns_read_name(&r, ptr->rdata_off, target));
  ASSERT_TRUE(strcmp(target, INST) == 0);

  up_with(records, N_REC, 1514);
  rival_a(); /* heard before the responder starts */
  mdns_start(&m);
  ticks(2000, 250);
  ASSERT_EQ(conflicts, 0);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
}

/* REQ-MDNS-057 (RFC 6762 §9): once a name is ours, only a record of its
 * name and type with other rdata conflicts — not one of another type or
 * class, not a copy of our own data, not a shared record with another
 * target */
TEST(itest_mdns_057_what_is_no_conflict_while_running) {
  static const uint8_t aaaa[16] = {0xFE, 0x80};
  peer_dns_t r;
  uint8_t rd[64], addr[4];
  running(records, N_REC);
  peer_dns_begin(&r, 0, FLAG_QR | FLAG_AA);
  peer_dns_rr(&r, 0, HOST, 28, C_IN | C_TOP, 120, aaaa, 16);
  peer_put32(addr, RIVAL);
  peer_dns_rr(&r, 0, HOST, T_A, 3, 120, addr, 4); /* class CH */
  peer_dns_rr(&r, 0, SVC, T_PTR, C_IN, 4500, rd,
              peer_dns_name(rd, "Other Unit._pyro._tcp.local"));
  peer_dns_rr(&r, 0, INST, T_TXT, C_IN | C_TOP, 4500, "\x09txtvers=1", 10);
  peer_put32(addr, OUR_IP);
  peer_dns_rr(&r, 2, HOST, T_A, C_IN | C_TOP, 120, addr, 4);
  multicast(&r);
  ticks(1000, 250);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(conflicts, 0);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
}

/* REQ-MDNS-055 (RFC 6762 §8.2): a probe that cannot be parsed — its
 * question cut off, or its Authority records — is no simultaneous probe:
 * ours go on */
TEST(itest_mdns_055_malformed_probes_ignored) {
  peer_dns_t q;
  uint8_t rd[4];
  probing(records, N_REC);
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, HOST, T_ANY, C_IN | C_TOP);
  peer_dns_end(&q);
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, q.buf, (uint16_t)(q.len - 3));
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, HOST, T_ANY, C_IN | C_TOP);
  peer_put32(rd, 0x0A0000C8u);
  peer_dns_rr(&q, 1, HOST, T_A, C_IN, 120, rd, 4);
  peer_dns_end(&q);
  peer_put16(q.buf + 8, 3); /* three announced, one there */
  deliver(PEER_IP, MDNS_GROUP, MDNS_PORT, q.buf, (uint16_t)(q.len - 2));
  ticks(500, 250);
  ASSERT_EQ(probes(), 2);
  ticks(1500, 250);
  ASSERT_EQ(answers(), 2);
  ASSERT_EQ(conflicts, 0);
}

/* ms of 1-ms ticks until HOST's A record has been multicast @p n times */
static uint32_t ms_until_a_sent(int n, uint32_t limit) {
  uint32_t ms;
  for (ms = 1; ms <= limit; ms++) {
    mdns_tick(&m, 1);
    if (records_sent(0, HOST, T_A) >= n)
      return ms;
  }
  return 0;
}

/* REQ-MDNS-063, 057, 075 (RFC 6762 §6): the one-second rule holds for
 * what the responder sends unasked too: the announcement after a name
 * was probed for again, and the correction of a low TTL, wait until a
 * second after the record's last multicast */
TEST(itest_mdns_063_announcements_and_corrections_wait_too) {
  uint32_t ms;
  running(records, N_REC);
  mdns_tick(&m, 300);
  query(HOST, T_A, 0);
  ASSERT_EQ(records_sent(0, HOST, T_A), 1);
  rival_a(); /* probed for again: the announcement is due within 1 s */
  ms = ms_until_a_sent(2, 3000);
  ASSERT_TRUE(ms >= 1000 && ms <= 2000);
  ASSERT_EQ(probes(), 3);

  running(records, N_REC);
  mdns_tick(&m, 300);
  query(HOST, T_A, 0);
  claim_a(PEER_IP, MDNS_GROUP, MDNS_PORT, FLAG_QR | FLAG_AA, HOST, OUR_IP, 0);
  ms = ms_until_a_sent(2, 3000);
  ASSERT_TRUE(ms >= 1000 && ms <= 2000);
  ASSERT_EQ(ms_until_a_sent(3, 3000), 0u); /* corrected once */
}

/* ══ DNS-SD ═════════════════════════════════════════════════════════ */

/* REQ-DNSSD-005, 014, 015 (RFC 6763 §9): several instances, of one type
 * or more: a browse lists every instance of the type; the meta-query
 * lists each type once, as a shared PTR record from
 * _services._dns-sd._udp.local to the type */
TEST(itest_dnssd_014_service_types_enumerated) {
  static const mdns_record_t recs[] = {
      {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
      {.type = DNS_TYPE_PTR, .ttl = 4500, .name = SVC, .rdata.ptr = INST},
      {.type = DNS_TYPE_PTR,
       .ttl = 4500,
       .name = SVC,
       .rdata.ptr = "Pyro Unit 2._pyro._tcp.local"},
      {.type = DNS_TYPE_PTR,
       .ttl = 4500,
       .name = "_http._tcp.local",
       .rdata.ptr = "Web._http._tcp.local"},
  };
  peer_dns_msg_t r;
  char target[256];
  int pyro = 0, http = 0;
  uint16_t i;
  running(recs, 4);
  query(SVC, T_PTR, 0);
  mdns_tick(&m, 150);
  ASSERT_EQ(records_sent(0, SVC, T_PTR), 2);

  later();
  query(META, T_PTR, 0);
  ASSERT_EQ(responses(), 0); /* shared: delayed */
  mdns_tick(&m, 150);
  ASSERT_EQ(responses(), 1);
  ASSERT_TRUE(response(0, &r));
  ASSERT_EQ(r.an, 2);
  for (i = 0; i < r.n_rr; i++) {
    ASSERT_EQ(r.rr[i].type, T_PTR);
    ASSERT_EQ(r.rr[i].class_, C_IN);
    ASSERT_EQ(r.rr[i].ttl, 4500u);
    ASSERT_TRUE(strcmp(r.rr[i].name, META) == 0);
    ASSERT_TRUE(peer_dns_read_name(&r, r.rr[i].rdata_off, target));
    pyro += strcmp(target, SVC) == 0;
    http += strcmp(target, "_http._tcp.local") == 0;
  }
  ASSERT_EQ(pyro, 1);
  ASSERT_EQ(http, 1);

  later();
  query(META, T_ANY, 0);
  mdns_tick(&m, 150);
  ASSERT_EQ(records_sent(0, META, T_PTR), 2);
}

/* REQ-DNSSD-012 (RFC 6763 §6.1): a TXT record without strings is sent as
 * a single zero byte, never empty — and known as such */
TEST(itest_dnssd_012_empty_txt_is_one_zero_byte) {
  static const char *const none[] = {NULL};
  static const mdns_record_t recs[] = {
      {.type = DNS_TYPE_TXT,
       .ttl = 4500,
       .name = "a._x._tcp.local",
       .rdata.txt = NULL},
      {.type = DNS_TYPE_TXT,
       .ttl = 4500,
       .name = "b._x._tcp.local",
       .rdata.txt = none},
  };
  peer_dns_msg_t r;
  const peer_rr_t *x;
  running(recs, 2);
  query("a._x._tcp.local", T_TXT, 0);
  ASSERT_NOT_NULL(x = answered(&r, "a._x._tcp.local", T_TXT));
  ASSERT_EQ(x->rdlen, 1);
  ASSERT_EQ(x->rdata[0], 0);
  query("b._x._tcp.local", T_TXT, 0);
  ASSERT_NOT_NULL(x = answered(&r, "b._x._tcp.local", T_TXT));
  ASSERT_EQ(x->rdlen, 1);
  ASSERT_EQ(x->rdata[0], 0);
  later();
  query_knowing("a._x._tcp.local", T_TXT, C_IN, "", 1, 4500);
  ASSERT_EQ(responses(), 0);
  query_knowing("a._x._tcp.local", T_TXT, C_IN, "\x01x", 2, 4500);
  ASSERT_EQ(responses(), 1);
}

/* REQ-DNSSD-032 (RFC 6763 §6.1): a TXT string is at most 255 bytes, what
 * its length byte can say: one of 255 is sent whole, one of 256 refused */
TEST(itest_dnssd_032_txt_strings_of_255_bytes) {
  static char s[257];
  static const char *const strings[] = {s, NULL};
  peer_dns_msg_t r;
  const peer_rr_t *x;
  memset(s, 'x', 256);
  s[1] = '=';
  ASSERT_EQ(init_txt(strings), NET_ERR_INVALID_PARAM);
  s[255] = 0;
  ASSERT_EQ(init_txt(strings), NET_OK);
  mdns_start(&m);
  ticks(2000, 250);
  later();
  query(INST, T_TXT, 0);
  ASSERT_NOT_NULL(x = answered(&r, INST, T_TXT));
  ASSERT_EQ(x->rdlen, 256);
  ASSERT_EQ(x->rdata[0], 255);
  ASSERT_MEM_EQ(x->rdata + 1, s, 255);
}

/* Two services on one host; their records fit a packet one name at a
 * time, not all together */
static const char *const long_txt[] = {
    "note=0123456789012345678901234567890123456789012345678901234567890123",
    NULL};
static const mdns_record_t two_services[] = {
    {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
    {.type = DNS_TYPE_PTR, .ttl = 4500, .name = SVC, .rdata.ptr = INST},
    {.type = DNS_TYPE_SRV,
     .ttl = 120,
     .name = INST,
     .rdata.srv = {0, 0, 80, HOST}},
    {.type = DNS_TYPE_TXT, .ttl = 4500, .name = INST, .rdata.txt = long_txt},
    {.type = DNS_TYPE_PTR,
     .ttl = 4500,
     .name = "_http._tcp.local",
     .rdata.ptr = "Web._http._tcp.local"},
    {.type = DNS_TYPE_SRV,
     .ttl = 120,
     .name = "Web._http._tcp.local",
     .rdata.srv = {0, 0, 80, HOST}},
    {.type = DNS_TYPE_TXT,
     .ttl = 4500,
     .name = "Web._http._tcp.local",
     .rdata.txt = long_txt},
};
#define TWO_SERVICES_TX 300

/* REQ-DNSSD-007, REQ-MDNS-042 (RFC 6763 §12, RFC 6762 §17): additional
 * records are added as far as the packet has room — the answers are all
 * there, and an additional record is whole or absent */
TEST(itest_dnssd_007_additionals_as_far_as_they_fit) {
  peer_dns_t q;
  peer_dns_msg_t r;
  peer_ip_t ip;
  peer_udp_t udp;
  uint16_t f;
  ASSERT_EQ(up_with(two_services, 7, TWO_SERVICES_TX), NET_OK);
  mdns_start(&m);
  ticks(2000, 250);
  later();
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, SVC, T_PTR, C_IN);
  peer_dns_question(&q, "_http._tcp.local", T_PTR, C_IN);
  multicast(&q);
  mdns_tick(&m, 150);
  ASSERT_EQ(responses(), 1);
  ASSERT_TRUE(sent(0, &r, &ip, &udp, &f));
  ASSERT_TRUE(wire_sent(&t, f)->len <= TWO_SERVICES_TX);
  ASSERT_EQ(r.an, 2);
  ASSERT_TRUE(r.ar >= 1 && r.ar < 5);
  ASSERT_EQ(r.n_rr, r.an + r.ar); /* every record counted is there, whole */
}

/* REQ-MDNS-040, REQ-DNSSD-026, 027, 028: browsing and resolving a
 * service in the two ways RFC 6762 §5.4 gives a querier — as Bonjour
 * (macOS, iOS) does: the first question of a series with the QU bit, the
 * questions of one step in one message, later ones by multicast with the
 * known answers; and as Avahi does, by multicast.  Either way the
 * querier learns the instance, its host and port, its TXT strings and
 * the host's address, and that the host has no other address type */
TEST(itest_dnssd_026_browse_and_resolve_as_resolvers_ask) {
  peer_dns_t q;
  peer_dns_msg_t r;
  peer_ip_t ip;
  peer_udp_t udp;
  const peer_rr_t *rr;
  uint8_t inst[64];
  char name[256];
  running(records, N_REC);
  peer_dns_begin(&q, 0, 0); /* browse */
  peer_dns_question(&q, SVC, T_PTR, C_IN | C_TOP);
  multicast(&q);
  ASSERT_TRUE(sent(0, &r, &ip, &udp, NULL));
  ASSERT_EQ(ip.dst, PEER_IP);
  ASSERT_NOT_NULL(rr = peer_dns_find(&r, 0, SVC, T_PTR));
  ASSERT_TRUE(peer_dns_read_name(&r, rr->rdata_off, name));
  ASSERT_TRUE(strcmp(name, INST) == 0);

  wire_clear(&t);
  peer_dns_begin(&q, 0, 0); /* resolve */
  peer_dns_question(&q, INST, T_SRV, C_IN | C_TOP);
  peer_dns_question(&q, INST, T_TXT, C_IN | C_TOP);
  multicast(&q);
  ASSERT_TRUE(sent(0, &r, &ip, &udp, NULL));
  ASSERT_EQ(ip.dst, PEER_IP);
  ASSERT_NOT_NULL(rr = peer_dns_find(&r, 0, INST, T_SRV));
  ASSERT_EQ(peer_get16(rr->rdata + 4), 80);
  ASSERT_TRUE(peer_dns_read_name(&r, (uint16_t)(rr->rdata_off + 6), name));
  ASSERT_TRUE(strcmp(name, HOST) == 0);
  ASSERT_NOT_NULL(rr = peer_dns_find(&r, 0, INST, T_TXT));
  ASSERT_MEM_EQ(rr->rdata, "\x09txtvers=1", 10);

  wire_clear(&t);
  peer_dns_begin(&q, 0, 0); /* the host's addresses, both types */
  peer_dns_question(&q, HOST, T_A, C_IN | C_TOP);
  peer_dns_question(&q, HOST, 28, C_IN | C_TOP);
  multicast(&q);
  ASSERT_TRUE(sent(0, &r, &ip, &udp, NULL));
  ASSERT_NOT_NULL(rr = peer_dns_find(&r, 0, HOST, T_A));
  ASSERT_EQ(peer_get32(rr->rdata), OUR_IP);
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, HOST, T_NSEC));

  wire_clear(&t); /* the browse goes on, knowing the instance */
  query_knowing(SVC, T_PTR, C_IN, inst, peer_dns_name(inst, INST), 4500);
  mdns_tick(&m, 200);
  ASSERT_EQ(t.wire.tx_count, 0);

  /* by multicast: one response tells a browser all it needs */
  running(records, N_REC);
  query(SVC, T_PTR, 0);
  mdns_tick(&m, 150);
  ASSERT_TRUE(sent(0, &r, &ip, &udp, NULL));
  ASSERT_EQ(ip.dst, MDNS_GROUP);
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, SVC, T_PTR));
  ASSERT_NOT_NULL(peer_dns_find(&r, 2, INST, T_SRV));
  ASSERT_NOT_NULL(peer_dns_find(&r, 2, INST, T_TXT));
  ASSERT_NOT_NULL(peer_dns_find(&r, 2, HOST, T_A));
  later(); /* and each record asked for by itself is answered */
  query(HOST, T_A, 0);
  query(HOST, 28, 0);
  query(INST, T_SRV, 0);
  query(INST, T_TXT, 0);
  ASSERT_EQ(records_sent(0, INST, T_SRV), 1);
  ASSERT_EQ(records_sent(0, INST, T_TXT), 1);
  ASSERT_EQ(records_sent(0, HOST, T_A), 1);
  ASSERT_EQ(records_sent(0, HOST, T_NSEC), 1);
}

int main(void) {
  fprintf(stderr, "=== itest_mdns ===\n");
  RUN_TEST(itest_mdns_033_goodbye_includes_the_meta_query_ptr);
  RUN_TEST(itest_dnssd_029_record_too_big_for_any_packet_refused);
  RUN_TEST(itest_mdns_027_truncated_query_waits_400_to_500ms);
  RUN_TEST(itest_mdns_029_known_answers_after_truncated_query);
  RUN_TEST(itest_dnssd_018_withdraw_one_service);
  RUN_TEST(itest_dnssd_018_withdraw_one_of_two_instances);
  RUN_TEST(itest_dnssd_018_withdraw_while_probing);
  RUN_TEST(itest_mdns_016_probes_are_qu_any_with_proposed_records);
  RUN_TEST(itest_mdns_046_header_bits_on_transmission);
  RUN_TEST(itest_mdns_047_header_bits_ignored_on_reception);
  RUN_TEST(itest_mdns_048_compressed_names_decoded);
  RUN_TEST(itest_mdns_049_no_compression_in_other_rdata);
  RUN_TEST(itest_mdns_050_names_utf8_without_bom);
  RUN_TEST(itest_mdns_051_names_of_255_bytes);
  RUN_TEST(itest_dnssd_033_instance_name_control_characters_refused);
  RUN_TEST(itest_dnssd_034_dots_separate_labels);
  RUN_TEST(itest_dnssd_035_txt_keys_checked);
  RUN_TEST(itest_dnssd_038_srv_target_never_root);
  RUN_TEST(itest_mdns_043_legacy_srv_target_uncompressed);
  RUN_TEST(itest_mdns_044_nonzero_opcode_ignored);
  RUN_TEST(itest_mdns_045_nonzero_rcode_ignored);
  RUN_TEST(itest_mdns_061_responses_from_other_ports_ignored);
  RUN_TEST(itest_mdns_062_responses_only_from_the_local_link);
  RUN_TEST(itest_mdns_080_unicast_responses_only_to_our_probes);
  RUN_TEST(itest_mdns_070_questions_in_responses_ignored);
  RUN_TEST(itest_mdns_052_responses_before_the_first_probe_ignored);
  RUN_TEST(itest_mdns_053_any_record_of_the_name_conflicts_while_probing);
  RUN_TEST(itest_mdns_054_fifteen_conflicts_slow_probing_down);
  RUN_TEST(itest_mdns_055_simultaneous_probe_lost_waits_a_second);
  RUN_TEST(itest_mdns_055_simultaneous_probe_won_or_tied);
  RUN_TEST(itest_mdns_057_conflict_while_running_probes_again);
  RUN_TEST(itest_mdns_057_conflict_while_running_undefended_keeps_name);
  RUN_TEST(itest_mdns_058_no_periodic_announcements);
  RUN_TEST(itest_mdns_059_new_ipv4_address_announced);
  RUN_TEST(itest_mdns_060_goodbye_for_old_ptr_rdata_before_renaming);
  RUN_TEST(itest_mdns_063_record_multicast_at_most_once_a_second);
  RUN_TEST(itest_mdns_064_only_positive_or_owned_negative_answers);
  RUN_TEST(itest_mdns_065_nsec_for_missing_type);
  RUN_TEST(itest_mdns_066_no_negative_answer_for_shared_records);
  RUN_TEST(itest_mdns_067_nsec_restricted_form);
  RUN_TEST(itest_mdns_068_negative_answers_only_for_owned_names);
  RUN_TEST(itest_mdns_069_unparseable_nsec_does_not_hide_the_message);
  RUN_TEST(itest_mdns_071_response_destinations);
  RUN_TEST(itest_mdns_072_any_type_and_class);
  RUN_TEST(itest_mdns_073_several_questions);
  RUN_TEST(itest_mdns_074_only_valid_ipv4_addresses);
  RUN_TEST(itest_mdns_075_low_ttl_copy_of_our_record_corrected);
  RUN_TEST(itest_mdns_076_no_cache_flush_in_legacy_responses);
  RUN_TEST(itest_mdns_077_known_answers_only_from_the_querier);
  RUN_TEST(itest_mdns_078_cache_flush_on_unique_records_only);
  RUN_TEST(itest_mdns_079_whole_unique_rrset);
  RUN_TEST(itest_mdns_002_group_joined_at_start_left_at_stop);
  RUN_TEST(itest_mdns_001_port_ttl_and_id_of_everything_sent);
  RUN_TEST(itest_mdns_008_record_table_given_at_init);
  RUN_TEST(itest_mdns_009_each_record_answered_with_its_rdata);
  RUN_TEST(itest_mdns_014_ttls_as_the_table_gives_them);
  RUN_TEST(itest_mdns_017_probe_and_announcement_timing);
  RUN_TEST(itest_mdns_019_failed_probe_gives_up_the_names);
  RUN_TEST(itest_mdns_020_callback_renames_and_starts_again);
  RUN_TEST(itest_mdns_021_answers_only_once_probing_is_over);
  RUN_TEST(itest_mdns_024_start_again_probes_and_announces_again);
  RUN_TEST(itest_mdns_027_unique_at_once_shared_after_20_to_120_ms);
  RUN_TEST(itest_mdns_028_qu_question_answered_by_unicast);
  RUN_TEST(itest_mdns_029_known_answer_suppression);
  RUN_TEST(itest_mdns_032_goodbye_only_for_what_was_announced);
  RUN_TEST(itest_mdns_041_legacy_unicast_query_answered);
  RUN_TEST(itest_mdns_041_malformed_messages_ignored);
  RUN_TEST(itest_mdns_041_malformed_names_ignored);
  RUN_TEST(itest_mdns_042_records_split_across_packets);
  RUN_TEST(itest_mdns_043_names_compressed);
  RUN_TEST(itest_mdns_056_other_hosts_records_never_used);
  RUN_TEST(itest_mdns_057_what_is_no_conflict_while_running);
  RUN_TEST(itest_mdns_055_malformed_probes_ignored);
  RUN_TEST(itest_mdns_063_announcements_and_corrections_wait_too);
  RUN_TEST(itest_dnssd_014_service_types_enumerated);
  RUN_TEST(itest_dnssd_012_empty_txt_is_one_zero_byte);
  RUN_TEST(itest_dnssd_032_txt_strings_of_255_bytes);
  RUN_TEST(itest_dnssd_007_additionals_as_far_as_they_fit);
  RUN_TEST(itest_dnssd_026_browse_and_resolve_as_resolvers_ask);
  ITEST_REPORT();
  return test_failures;
}
