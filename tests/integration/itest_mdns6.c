/**
 * @file itest_mdns6.c
 * @brief The mDNS responder in a dual-stack build, black box: AAAA
 *        records, the interface's IPv6 addresses coming and going, and
 *        responses over IPv6 to ff02::fb.  The peer's IPv6 frames are
 *        built and parsed here, with the harness's checksum.
 */

#include "eth.h"
#include "ipv6.h"
#include "itest.h"
#include "mdns.h"
#include "udp.h"
#include <string.h>

#define HOST "pyro-dead01.local"
#define SVC "_pyro._tcp.local"
#define INST "Pyro Unit 1._pyro._tcp.local"
#define T_A 1
#define T_PTR 12
#define T_AAAA 28
#define T_SRV 33
#define T_NSEC 47
#define C_IN 1
#define C_TOP 0x8000
#define FLAG_QR 0x8000
#define FLAG_AA 0x0400
#define RIVAL 0x0A00004Du /* 10.0.0.77: another host's address for HOST */

static itest_t t;
static mdns_t m;
static int conflicts;

static const uint8_t group6_mac[6] = {0x33, 0x33, 0, 0, 0, 0xFB};
static const uint8_t global[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 1, 0, 0,
                                   0,    0,    0,    0,    0, 0, 0, 0x42};
static const uint8_t elsewhere[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 7, 0, 0,
                                      0,    0,    0,    0,    0, 0, 0, 7};
static const uint8_t peer_ll[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                    0,    0,    0, 0, 0, 0, 0, 0x99};
/* Off the link: another /64 */
static const uint8_t remote6[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 9, 0, 0,
                                    0,    0,    0,    0,    0, 0, 0, 9};
static uint8_t our_ll[16];

static void on_conflict(mdns_t *mm, uint8_t index, void *ctx) {
  (void)mm;
  (void)index;
  (void)ctx;
  conflicts++;
}

static void on_mdns(net_t *net, uint32_t src_ip, uint16_t src_port,
                    const uint8_t *src_mac, const uint8_t *data, uint16_t len) {
  (void)net;
  mdns_input(&m, src_ip, src_mac, src_port, data, len);
}

static void on_mdns6(net_t *net, const uint8_t *src_ip, uint16_t src_port,
                     const uint8_t *src_mac, const uint8_t *data,
                     uint16_t len) {
  (void)net;
  mdns_input6(&m, src_ip, src_mac, src_port, data, len);
}

static const udp_port_entry_t ports[] = {{MDNS_PORT, on_mdns}};
static const udp6_port_entry_t ports6[] = {{MDNS_PORT, on_mdns6}};

static const char *const txt[] = {"txtvers=1", NULL};
static const mdns_record_t records[] = {
    {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
    {.type = DNS_TYPE_AAAA, .ttl = 120, .name = HOST, .rdata.aaaa = NULL},
    {.type = DNS_TYPE_PTR, .ttl = 4500, .name = SVC, .rdata.ptr = INST},
    {.type = DNS_TYPE_SRV,
     .ttl = 120,
     .name = INST,
     .rdata.srv = {0, 0, 80, HOST}},
    {.type = DNS_TYPE_TXT, .ttl = 4500, .name = INST, .rdata.txt = txt},
};
#define N_REC ((uint8_t)(sizeof(records) / sizeof(records[0])))

/* The stack up — with IPv6 (a link-local and a global address, both past
 * DAD) if @p v6 — and the responder initialised */
static void up(const mdns_record_t *recs, uint8_t n, int v6) {
  itest_up(&t, 1514, 1514);
  udp_set_ports(&t.net, ports, 1);
  udp6_set_ports(&t.net, ports6, 1);
  if (v6) {
    ipv6_start(&t.net);
    itest_advance(&t, 15000, 100);
    ipv6_addr_add(&t.net, global, NET_IP6_INFINITE, NET_IP6_INFINITE);
    itest_advance(&t, 3000, 100);
  }
  ipv6_link_local_from_mac(t.net.mac, our_ll);
  conflicts = 0;
  mdns_init(&m, &t.net, recs, n, on_conflict, NULL);
  wire_clear(&t);
}

static void ticks(uint32_t ms, uint32_t step) {
  while (ms) {
    uint32_t k = ms < step ? ms : step;
    mdns_tick(&m, k);
    ms -= k;
  }
}

/* Probed, announced, and the second after the announcements over */
static void running(const mdns_record_t *recs, uint8_t n, int v6) {
  up(recs, n, v6);
  mdns_start(&m);
  ticks(4000, 250);
  wire_clear(&t);
}

/* Started, the first probe sent */
static void probing(void) {
  up(records, N_REC, 1);
  mdns_start(&m);
  mdns_tick(&m, 250);
  wire_clear(&t);
}

/* ── The peer over IPv6 ── */

/* The port the peer sends from: 5353, or another for a legacy query */
static uint16_t peer_sport = MDNS_PORT;

/* An IPv6 UDP frame from @p src, port peer_sport, to @p dst:5353 carrying
 * @p len bytes of DNS */
static uint16_t frame6(uint8_t *f, const uint8_t *dst_mac, const uint8_t *src,
                       const uint8_t *dst, const uint8_t *msg, uint16_t len) {
  static uint8_t pseudo[40 + 1520];
  uint8_t *ip = f + 14, *udp = ip + 40;
  uint16_t ulen = (uint16_t)(8u + len), ck;
  memcpy(f, dst_mac, 6);
  memcpy(f + 6, peer_mac, 6);
  peer_put16(f + 12, 0x86DD);
  memset(ip, 0, 40);
  ip[0] = 0x60;
  peer_put16(ip + 4, ulen);
  ip[6] = 17;
  ip[7] = 255;
  memcpy(ip + 8, src, 16);
  memcpy(ip + 24, dst, 16);
  peer_put16(udp, peer_sport);
  peer_put16(udp + 2, MDNS_PORT);
  peer_put16(udp + 4, ulen);
  peer_put16(udp + 6, 0);
  memcpy(udp + 8, msg, len);
  memcpy(pseudo, src, 16);
  memcpy(pseudo + 16, dst, 16);
  peer_put32(pseudo + 32, ulen);
  peer_put32(pseudo + 36, 17);
  memcpy(pseudo + 40, udp, ulen);
  ck = peer_cksum(pseudo, (uint16_t)(40u + ulen));
  peer_put16(udp + 6, ck ? ck : 0xFFFF);
  return (uint16_t)(14u + 40u + ulen);
}

static void deliver6(const uint8_t *src, const uint8_t *dst, peer_dns_t *d) {
  uint8_t f[1600];
  const uint8_t *mac = ipv6_is_multicast(dst) ? group6_mac : t.net.mac;
  peer_dns_end(d);
  itest_receive(&t, f, frame6(f, mac, src, dst, d->buf, d->len));
}

/* A response claiming our host name with another address */
static void rival(peer_dns_t *r) {
  uint8_t rd[4];
  peer_dns_begin(r, 0, FLAG_QR | FLAG_AA);
  peer_put32(rd, RIVAL);
  peer_dns_rr(r, 0, HOST, T_A, C_IN | C_TOP, 120, rd, 4);
}

/* A query over IPv4, multicast from the peer */
static void query4(const char *name, uint16_t type) {
  static const uint8_t group_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};
  peer_dns_t q;
  uint8_t f[1600], seg[1520];
  peer_ip_t ip = peer_ip(PEER_IP, MDNS_GROUP, 17);
  uint16_t n;
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, name, type, C_IN);
  peer_dns_end(&q);
  ip.ttl = 255;
  n = peer_udp(seg, &ip, MDNS_PORT, MDNS_PORT, q.buf, q.len);
  itest_receive(&t, f, peer_ipv4_frame(f, group_mac, peer_mac, &ip, seg, n));
}

/* ── What the stack sent ── */

/* The @p k-th mDNS response (@p qr 1) or probe (0) sent over IPv6 (@p v6)
 * or IPv4, parsed; its IP header into @p ip; 0 if none */
static int message(int v6, int qr, int k, peer_dns_msg_t *msg,
                   const uint8_t **ip) {
  uint16_t i;
  const wire_frame_t *f;
  for (i = 0; (f = wire_sent(&t, i)) != NULL; i++) {
    const uint8_t *udp;
    uint16_t len;
    if (v6) {
      if (f->len < 62 || peer_get16(f->data + 12) != 0x86DD ||
          f->data[20] != 17)
        continue;
      udp = f->data + 54;
    } else {
      if (f->len < 42 || peer_get16(f->data + 12) != 0x0800 ||
          f->data[23] != 17)
        continue;
      udp = f->data + 14 + 4u * (f->data[14] & 0x0F);
    }
    len = (uint16_t)(peer_get16(udp + 4) - 8u);
    if (peer_get16(udp) != MDNS_PORT || !peer_dns_parse(udp + 8, len, msg) ||
        ((msg->flags & FLAG_QR) != 0) != qr || k-- != 0)
      continue;
    if (ip)
      *ip = f->data + 14;
    return 1;
  }
  return 0;
}

/* The @p k-th mDNS response sent over IPv6 (@p v6) or IPv4, parsed; its
 * IPv6 destination into @p dst; 0 if none */
static int response(int v6, int k, peer_dns_msg_t *msg, const uint8_t **dst) {
  const uint8_t *ip;
  if (!message(v6, 1, k, msg, &ip))
    return 0;
  if (dst)
    *dst = ip + 24;
  return 1;
}

/* AAAA records answered in @p msg: how many, and whether @p addr is one */
static int aaaa(const peer_dns_msg_t *msg, const uint8_t *addr, int *has) {
  uint16_t i;
  int n = 0;
  *has = 0;
  for (i = 0; i < msg->n_rr; i++) {
    const peer_rr_t *r = &msg->rr[i];
    if (r->section != 0 || r->type != T_AAAA)
      continue;
    n++;
    if (r->rdlen == 16 && memcmp(r->rdata, addr, 16) == 0)
      *has = 1;
  }
  return n;
}

/* REQ-MDNS-059 (RFC 6762 §8.4): an IPv6 address that is no longer usable
 * leads to a new announcement of the address records — the application
 * calls mdns_readdress6() — listing only the addresses left: twice, a
 * second apart, to ff02::fb.  Nothing goes to 224.0.0.251 (the row's
 * deviation) */
TEST(itest_mdns6_059_lost_address_reannounced) {
  peer_dns_msg_t r;
  const uint8_t *dst;
  const peer_rr_t *a;
  int has;
  running(records, N_REC, 1);
  ipv6_addr_remove(&t.net, global);
  mdns_readdress6(&m);
  ticks(2500, 50);
  ASSERT_TRUE(response(1, 0, &r, &dst));
  ASSERT_MEM_EQ(dst, mdns_group6, 16);
  ASSERT_EQ(aaaa(&r, our_ll, &has), 1);
  ASSERT_TRUE(has);
  ASSERT_NOT_NULL(a = peer_dns_find(&r, 0, HOST, T_AAAA));
  ASSERT_EQ(a->class_, C_IN | C_TOP);
  ASSERT_TRUE(response(1, 1, &r, &dst));
  ASSERT_FALSE(response(1, 2, &r, &dst));
  ASSERT_FALSE(response(0, 0, &r, NULL));
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
}

/* REQ-MDNS-062 (RFC 6762 §11): over IPv6, a unicast response counts only
 * from a link-local or on-link source; one to ff02::fb from anywhere */
TEST(itest_mdns6_062_ipv6_responses_only_from_the_link) {
  peer_dns_t r;
  probing();
  rival(&r);
  deliver6(remote6, global, &r);
  ASSERT_EQ(conflicts, 0);
  rival(&r);
  deliver6(remote6, mdns_group6, &r);
  ASSERT_EQ(conflicts, 1);
  probing();
  rival(&r);
  deliver6(peer_ll, our_ll, &r);
  ASSERT_EQ(conflicts, 1);
}

/* REQ-MDNS-062, REQ-ETH-026: over IPv6 too, a response to ff02::fb in a
 * frame the driver hands to eth_input() from memory of its own is one
 * sent to the group: it counts though its source is off the link */
TEST(itest_mdns6_062_group_response_in_the_drivers_own_buffer) {
  static uint8_t own[1600];
  peer_dns_t r;
  uint16_t n;
  probing();
  rival(&r);
  peer_dns_end(&r);
  n = frame6(own, group6_mac, remote6, mdns_group6, r.buf, r.len);
  eth_input(&t.net, own, n);
  ASSERT_EQ(conflicts, 1);
}

/* REQ-MDNS-065 (RFC 6762 §6, §6.1): with no usable IPv6 address, an AAAA
 * query gets an NSEC that lists A and not AAAA */
TEST(itest_mdns6_065_nsec_for_aaaa_without_an_address) {
  peer_dns_msg_t r;
  const peer_rr_t *n;
  int k;
  running(records, N_REC, 0);
  query4(HOST, T_AAAA);
  for (k = 0; response(0, k, &r, NULL); k++) {
    if ((n = peer_dns_find(&r, 0, HOST, T_NSEC)) != NULL)
      break;
  }
  ASSERT_TRUE(response(0, k, &r, NULL));
  ASSERT_TRUE(n->rdlen >= 5);
  ASSERT_EQ(n->rdata[4] & 0x40, 0x40); /* A */
  if (n->rdlen >= 8)
    ASSERT_EQ(n->rdata[7] & 0x08, 0); /* AAAA (28) */
  ASSERT_NULL(peer_dns_find(&r, 0, HOST, T_AAAA));
}

/* REQ-MDNS-074 (RFC 6762 §6.2): AAAA records carry every usable address
 * of the interface and no other — not a fixed one that is not ours, not
 * one still tentative; a fixed one that is ours is carried */
TEST(itest_mdns6_074_aaaa_only_for_usable_addresses) {
  static const mdns_record_t recs[] = {
      {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
      {.type = DNS_TYPE_AAAA, .ttl = 120, .name = HOST, .rdata.aaaa = NULL},
      {.type = DNS_TYPE_AAAA,
       .ttl = 120,
       .name = HOST,
       .rdata.aaaa = elsewhere},
  };
  static const mdns_record_t fixed[] = {
      {.type = DNS_TYPE_AAAA, .ttl = 120, .name = HOST, .rdata.aaaa = global},
  };
  peer_dns_msg_t r;
  int has;
  running(recs, 3, 1);
  query4(HOST, T_AAAA);
  ASSERT_TRUE(response(0, 0, &r, NULL));
  ASSERT_EQ(aaaa(&r, our_ll, &has), 2);
  ASSERT_TRUE(has);
  aaaa(&r, global, &has);
  ASSERT_TRUE(has);
  aaaa(&r, elsewhere, &has);
  ASSERT_FALSE(has);

  /* the global address replaced by one whose DAD has not finished */
  ipv6_addr_remove(&t.net, global);
  ASSERT_EQ(
      ipv6_addr_add(&t.net, elsewhere, NET_IP6_INFINITE, NET_IP6_INFINITE),
      NET_OK);
  mdns_tick(&m, 2000);
  wire_clear(&t);
  query4(HOST, T_AAAA);
  ASSERT_TRUE(response(0, 0, &r, NULL));
  ASSERT_EQ(aaaa(&r, our_ll, &has), 1);
  ASSERT_TRUE(has);

  running(fixed, 1, 1);
  query4(HOST, T_AAAA);
  ASSERT_TRUE(response(0, 0, &r, NULL));
  ASSERT_EQ(aaaa(&r, global, &has), 1);
  ASSERT_TRUE(has);
}

/* A query over IPv6, multicast from the peer's link-local address */
static void query6(const char *name, uint16_t type, uint16_t class_) {
  peer_dns_t q;
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, name, type, class_);
  deliver6(peer_ll, mdns_group6, &q);
}

/* A response from the peer, to ff02::fb, with an AAAA record @p addr for
 * our host name */
static void claim_aaaa(const uint8_t *addr) {
  peer_dns_t r;
  peer_dns_begin(&r, 0, FLAG_QR | FLAG_AA);
  peer_dns_rr(&r, 0, HOST, T_AAAA, C_IN | C_TOP, 120, addr, 16);
  deliver6(peer_ll, mdns_group6, &r);
}

/* Records of @p type in @p section of @p msg */
static int count_type(const peer_dns_msg_t *msg, int section, uint16_t type) {
  uint16_t i;
  int n = 0;
  for (i = 0; i < msg->n_rr; i++)
    n += msg->rr[i].section == section && msg->rr[i].type == type;
  return n;
}

/* Responses (@p qr 1) or probes (0) sent over IPv6 (@p v6) or IPv4 */
static int count(int v6, int qr) {
  peer_dns_msg_t msg;
  int k = 0;
  while (message(v6, qr, k, &msg, NULL))
    k++;
  return k;
}

/* REQ-MDNS-013, 038, 039 (RFC 6762 §20): a dual-stack responder joins
 * ff02::fb as well as 224.0.0.251, and probes and announces on both:
 * the same probe, from the link-local address with Hop Limit 255, the
 * AAAA records proposed — one for each usable address — beside the A */
TEST(itest_mdns6_038_both_groups_probed_and_announced) {
  peer_dns_msg_t p4, p6, r;
  const uint8_t *ip;
  const peer_rr_t *a;
  int has;
  up(records, N_REC, 1);
  ASSERT_FALSE(ipv6_mcast_is_member(&t.net, mdns_group6));
  mdns_start(&m);
  ASSERT_TRUE(ipv6_mcast_is_member(&t.net, mdns_group6));
  wire_clear(&t);
  mdns_tick(&m, 250);
  ASSERT_EQ(count(0, 0), 1);
  ASSERT_EQ(count(1, 0), 1);
  ASSERT_TRUE(message(0, 0, 0, &p4, NULL));
  ASSERT_TRUE(message(1, 0, 0, &p6, &ip));
  ASSERT_MEM_EQ(ip - 14, group6_mac, 6);
  ASSERT_MEM_EQ(ip + 24, mdns_group6, 16);
  ASSERT_MEM_EQ(ip + 8, our_ll, 16);
  ASSERT_EQ(ip[7], 255);
  ASSERT_EQ(peer_get16(ip + 40), MDNS_PORT);
  ASSERT_EQ(peer_get16(ip + 42), MDNS_PORT);
  ASSERT_EQ(p4.len, p6.len);
  ASSERT_MEM_EQ(p4.msg, p6.msg, p4.len);
  ASSERT_EQ(count_type(&p6, 1, T_AAAA), 2);
  ASSERT_EQ(count_type(&p6, 1, T_A), 1);

  wire_clear(&t);
  ticks(750, 250); /* two more probes, the first announcement */
  ASSERT_EQ(count(0, 1), 1);
  ASSERT_EQ(count(1, 1), 1);
  ASSERT_TRUE(message(1, 1, 0, &r, &ip));
  ASSERT_MEM_EQ(ip + 24, mdns_group6, 16);
  ASSERT_EQ(ip[7], 255);
  ASSERT_EQ(aaaa(&r, our_ll, &has), 2);
  ASSERT_TRUE(has);
  aaaa(&r, global, &has);
  ASSERT_TRUE(has);
  ASSERT_NOT_NULL(a = peer_dns_find(&r, 0, HOST, T_AAAA));
  ASSERT_EQ(a->class_, C_IN | C_TOP);
  ASSERT_EQ(count_type(&r, 0, T_A), 1);
  ASSERT_TRUE(message(0, 1, 0, &r, NULL)); /* all addresses on IPv4 too */
  ASSERT_EQ(count_type(&r, 0, T_AAAA), 2);

  mdns_stop(&m);
  ASSERT_FALSE(ipv6_mcast_is_member(&t.net, mdns_group6));
}

/* REQ-MDNS-039, 013, 071, REQ-DNSSD-008 (RFC 6762 §6, §6.2): a query is
 * answered on the family it came over; an answer with the addresses of
 * one family brings those of the other as additional records, and an SRV
 * answer brings both; a shared record's answer is delayed, and goes to
 * the family that asked */
TEST(itest_mdns6_039_answered_on_the_family_that_asked) {
  peer_dns_msg_t r;
  const uint8_t *ip;
  int has;
  running(records, N_REC, 1);
  query6(HOST, T_AAAA, C_IN);
  ASSERT_EQ(count(0, 1), 0);
  ASSERT_EQ(count(1, 1), 1);
  ASSERT_TRUE(message(1, 1, 0, &r, &ip));
  ASSERT_MEM_EQ(ip + 24, mdns_group6, 16);
  ASSERT_EQ(aaaa(&r, global, &has), 2);
  ASSERT_TRUE(has);
  ASSERT_EQ(count_type(&r, 2, T_A), 1);

  mdns_tick(&m, 2000);
  wire_clear(&t);
  query6(HOST, T_A, C_IN);
  ASSERT_TRUE(message(1, 1, 0, &r, NULL));
  ASSERT_EQ(count_type(&r, 0, T_A), 1);
  ASSERT_EQ(count_type(&r, 2, T_AAAA), 2);

  mdns_tick(&m, 2000);
  wire_clear(&t);
  query4(HOST, T_AAAA);
  ASSERT_EQ(count(1, 1), 0);
  ASSERT_EQ(count(0, 1), 1);
  ASSERT_TRUE(message(0, 1, 0, &r, NULL));
  ASSERT_EQ(count_type(&r, 0, T_AAAA), 2);

  mdns_tick(&m, 2000);
  wire_clear(&t);
  query6(INST, T_SRV, C_IN);
  ASSERT_TRUE(message(1, 1, 0, &r, NULL));
  ASSERT_EQ(count_type(&r, 0, T_SRV), 1);
  ASSERT_EQ(count_type(&r, 2, T_A), 1);
  ASSERT_EQ(count_type(&r, 2, T_AAAA), 2);

  mdns_tick(&m, 2000);
  wire_clear(&t);
  query6(SVC, T_PTR, C_IN);
  ASSERT_EQ(t.wire.tx_count, 0);
  mdns_tick(&m, 150);
  ASSERT_EQ(count(0, 1), 0);
  ASSERT_EQ(count(1, 1), 1);
}

/* REQ-MDNS-028, 041, 076 (RFC 6762 §5.4, §6.7): over IPv6 too, a QU
 * question is answered by unicast to the querier, and a legacy query to
 * its port, with its ID and question, TTLs of at most 10 s and no
 * cache-flush bit */
TEST(itest_mdns6_028_unicast_and_legacy_answers_over_ipv6) {
  peer_dns_t q;
  peer_dns_msg_t r;
  const uint8_t *ip;
  uint16_t i;
  running(records, N_REC, 1);
  query6(HOST, T_AAAA, C_IN | C_TOP);
  ASSERT_EQ(count(0, 1), 0);
  ASSERT_EQ(count(1, 1), 1);
  ASSERT_TRUE(message(1, 1, 0, &r, &ip));
  ASSERT_MEM_EQ(ip - 14, peer_mac, 6);
  ASSERT_MEM_EQ(ip + 24, peer_ll, 16);
  ASSERT_EQ(ip[7], 255);
  ASSERT_EQ(peer_get16(ip + 42), MDNS_PORT);
  ASSERT_EQ(count_type(&r, 0, T_AAAA), 2);

  wire_clear(&t);
  peer_dns_begin(&q, 0x4242, 0);
  peer_dns_question(&q, HOST, T_AAAA, C_IN);
  peer_sport = 40000;
  deliver6(peer_ll, mdns_group6, &q);
  peer_sport = MDNS_PORT;
  ASSERT_TRUE(message(1, 1, 0, &r, &ip));
  ASSERT_MEM_EQ(ip + 24, peer_ll, 16);
  ASSERT_EQ(peer_get16(ip + 40), MDNS_PORT);
  ASSERT_EQ(peer_get16(ip + 42), 40000);
  ASSERT_EQ(r.id, 0x4242);
  ASSERT_EQ(r.qd, 1);
  ASSERT_TRUE(strcmp(r.qname, HOST) == 0);
  ASSERT_EQ(count_type(&r, 0, T_AAAA), 2);
  for (i = 0; i < r.n_rr; i++) {
    ASSERT_TRUE(r.rr[i].ttl <= 10);
    ASSERT_EQ(r.rr[i].class_, C_IN);
  }
}

/* REQ-MDNS-029, 067 (RFC 6762 §7.1, §6.1): an AAAA answer the querier
 * already knows is not sent; the NSEC of a name with addresses of both
 * families lists A and AAAA */
TEST(itest_mdns6_029_known_aaaa_and_the_nsec_of_both_families) {
  peer_dns_t q;
  peer_dns_msg_t r;
  const peer_rr_t *n;
  running(records, N_REC, 1);
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, HOST, T_AAAA, C_IN);
  peer_dns_rr(&q, 0, HOST, T_AAAA, C_IN, 120, global, 16);
  deliver6(peer_ll, mdns_group6, &q);
  ASSERT_EQ(t.wire.tx_count, 0);
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, HOST, T_AAAA, C_IN);
  peer_dns_rr(&q, 0, HOST, T_AAAA, C_IN, 120, elsewhere, 16);
  deliver6(peer_ll, mdns_group6, &q);
  ASSERT_EQ(count(1, 1), 1);

  wire_clear(&t);
  query6(HOST, 13 /* HINFO */, C_IN);
  ASSERT_TRUE(message(1, 1, 0, &r, NULL));
  ASSERT_NOT_NULL(n = peer_dns_find(&r, 0, HOST, T_NSEC));
  ASSERT_EQ(n->rdlen, 2 + 2 + 4); /* its own name, block 0, 4 bytes */
  ASSERT_MEM_EQ(n->rdata + 2, "\x00\x04\x40\x00\x00\x08", 6);
}

/* REQ-MDNS-053, 057 (RFC 6762 §8.1, §9): an AAAA record of our name with
 * an address that is not ours conflicts — while probing, and once the
 * name is ours (it is probed for again); one with an address of ours
 * does not */
TEST(itest_mdns6_053_another_hosts_aaaa_conflicts) {
  probing();
  claim_aaaa(global);
  ASSERT_EQ(conflicts, 0);
  claim_aaaa(elsewhere);
  ASSERT_EQ(conflicts, 1);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_CONFLICT);

  running(records, N_REC, 1);
  claim_aaaa(our_ll);
  ticks(500, 250);
  ASSERT_EQ(t.wire.tx_count, 0);
  claim_aaaa(elsewhere);
  ticks(500, 250);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_PROBING);
  ASSERT_EQ(count(1, 0), 2);
  ASSERT_EQ(conflicts, 0);
}

/* REQ-MDNS-059 (RFC 6762 §8.4): mdns_readdress6() while the announcements
 * are still going out starts them over, so that both families get two
 * with the addresses usable now; while still probing, the announcements
 * to come carry them anyway */
TEST(itest_mdns6_059_readdressed_before_running) {
  peer_dns_msg_t r;
  int has;
  up(records, N_REC, 1);
  mdns_start(&m);
  ticks(1000, 250); /* three probes, the first announcement */
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_ANNOUNCING);
  ipv6_addr_remove(&t.net, global);
  mdns_readdress6(&m);
  wire_clear(&t);
  ticks(2500, 250);
  ASSERT_EQ(count(0, 1), 2);
  ASSERT_EQ(count(1, 1), 2);
  ASSERT_TRUE(message(1, 1, 0, &r, NULL));
  ASSERT_EQ(aaaa(&r, our_ll, &has), 1);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);

  up(records, N_REC, 1);
  mdns_start(&m);
  mdns_tick(&m, 250); /* the first probe */
  ipv6_addr_remove(&t.net, global);
  mdns_readdress6(&m);
  wire_clear(&t);
  ticks(2500, 250);
  ASSERT_EQ(count(0, 0), 2); /* the two probes left */
  ASSERT_EQ(count(0, 1), 2);
  ASSERT_EQ(count(1, 1), 2);
  ASSERT_TRUE(message(0, 1, 0, &r, NULL));
  ASSERT_EQ(aaaa(&r, our_ll, &has), 1);
}

/* REQ-MDNS-032, 033, 039 (RFC 6762 §10.1): the goodbye goes to both
 * groups, the AAAA records in it */
TEST(itest_mdns6_032_goodbye_on_both_families) {
  peer_dns_msg_t r;
  uint16_t i;
  running(records, N_REC, 1);
  mdns_readdress6(&m); /* the announcements narrowed to IPv6 */
  ticks(3000, 250);
  wire_clear(&t);
  mdns_stop(&m);
  ASSERT_EQ(count(0, 1), 1);
  ASSERT_EQ(count(1, 1), 1);
  ASSERT_TRUE(message(1, 1, 0, &r, NULL));
  ASSERT_EQ(count_type(&r, 0, T_AAAA), 2);
  for (i = 0; i < r.n_rr; i++)
    ASSERT_EQ(r.rr[i].ttl, 0u);
}

int main(void) {
  fprintf(stderr, "=== itest_mdns6 ===\n");
  RUN_TEST(itest_mdns6_059_lost_address_reannounced);
  RUN_TEST(itest_mdns6_062_ipv6_responses_only_from_the_link);
  RUN_TEST(itest_mdns6_062_group_response_in_the_drivers_own_buffer);
  RUN_TEST(itest_mdns6_065_nsec_for_aaaa_without_an_address);
  RUN_TEST(itest_mdns6_074_aaaa_only_for_usable_addresses);
  RUN_TEST(itest_mdns6_038_both_groups_probed_and_announced);
  RUN_TEST(itest_mdns6_039_answered_on_the_family_that_asked);
  RUN_TEST(itest_mdns6_028_unicast_and_legacy_answers_over_ipv6);
  RUN_TEST(itest_mdns6_029_known_aaaa_and_the_nsec_of_both_families);
  RUN_TEST(itest_mdns6_053_another_hosts_aaaa_conflicts);
  RUN_TEST(itest_mdns6_059_readdressed_before_running);
  RUN_TEST(itest_mdns6_032_goodbye_on_both_families);
  ITEST_REPORT();
  return test_failures;
}
