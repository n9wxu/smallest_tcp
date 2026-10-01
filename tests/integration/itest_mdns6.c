/**
 * @file itest_mdns6.c
 * @brief The mDNS responder in a dual-stack build, black box: AAAA
 *        records, the interface's IPv6 addresses coming and going, and
 *        responses over IPv6 to ff02::fb.  The peer's IPv6 frames are
 *        built and parsed here, with the harness's checksum.
 */

#include "ipv6.h"
#include "itest.h"
#include "mdns.h"
#include "udp.h"
#include <string.h>

#define HOST "pyro-dead01.local"
#define SVC "_pyro._tcp.local"
#define INST "Pyro Unit 1._pyro._tcp.local"
#define T_A 1
#define T_AAAA 28
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

/* An IPv6 UDP frame from @p src:5353 to @p dst:5353 carrying @p len bytes
 * of DNS */
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
  peer_put16(udp, MDNS_PORT);
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

/* The @p k-th mDNS response sent over IPv6 (@p v6) or IPv4, parsed; its
 * IPv6 destination into @p dst; 0 if none */
static int response(int v6, int k, peer_dns_msg_t *msg, const uint8_t **dst) {
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
        !(msg->flags & FLAG_QR) || k-- != 0)
      continue;
    if (dst)
      *dst = f->data + 38;
    return 1;
  }
  return 0;
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
 * calls mdns_readdress6() — listing only the addresses left */
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
 * of the interface and no other — not a fixed one that is not ours */
TEST(itest_mdns6_074_aaaa_only_for_usable_addresses) {
  static const mdns_record_t recs[] = {
      {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
      {.type = DNS_TYPE_AAAA, .ttl = 120, .name = HOST, .rdata.aaaa = NULL},
      {.type = DNS_TYPE_AAAA,
       .ttl = 120,
       .name = HOST,
       .rdata.aaaa = elsewhere},
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
}

int main(void) {
  fprintf(stderr, "=== itest_mdns6 ===\n");
  RUN_TEST(itest_mdns6_059_lost_address_reannounced);
  RUN_TEST(itest_mdns6_062_ipv6_responses_only_from_the_link);
  RUN_TEST(itest_mdns6_065_nsec_for_aaaa_without_an_address);
  RUN_TEST(itest_mdns6_074_aaaa_only_for_usable_addresses);
  ITEST_REPORT();
  return test_failures;
}
