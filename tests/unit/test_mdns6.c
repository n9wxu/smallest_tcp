/**
 * @file test_mdns6.c
 * @brief Unit tests for mDNS over IPv6 (RFC 6762 §6.2, §20): ff02::fb,
 *        AAAA records, answering on the query's address family, probing
 *        and announcing on both.  Built with NET_USE_IPV6=1; without IPv4
 *        the responder has no A record and IPv6 is the only family (V4 is
 *        0 in the expected counts).
 */

#include "dns_wire.h"
#include "ipv6.h"
#include "mdns.h"
#include "ndp.h"
#include "net.h"
#include "net_endian.h"
#include "test_main.h"
#include "udp.h"
#include <string.h>

#if !NET_USE_IPV6
#error "test_mdns6 needs NET_USE_IPV6=1"
#endif

#define V4 NET_USE_IPV4 /* 1 when IPv4 is a family too */

/* ── Stub MAC driver (MLD frames are test_mld's business) ─────────── */

#define MAX_FRAMES 24
static uint8_t frames[MAX_FRAMES][1514];
static uint16_t frame_lens[MAX_FRAMES];
static int n_frames;

static int stub_init(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_send(void *ctx, const uint8_t *f, uint16_t l) {
  (void)ctx;
  if (l > 62 && f[12] == 0x86 && f[13] == 0xDD && f[20] == 0 && f[54] == 58 &&
      (f[62] == 143 || f[62] == 131 || f[62] == 132))
    return (int)l;
  if (n_frames < MAX_FRAMES) {
    memcpy(frames[n_frames], f, l);
    frame_lens[n_frames] = l;
  }
  n_frames++;
  return (int)l;
}
static int stub_poll(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_peek(void *ctx, uint16_t off, uint8_t *buf, uint16_t n) {
  (void)ctx;
  (void)off;
  (void)buf;
  (void)n;
  return -1;
}
static void stub_discard(void *ctx) { (void)ctx; }
static void stub_close(void *ctx) { (void)ctx; }

static const net_mac_t stub_drv = {
    .init = stub_init,
    .send = stub_send,
    .poll = stub_poll,
    .peek = stub_peek,
    .discard = stub_discard,
    .close = stub_close,
};

/* ── Records and addresses ────────────────────────────────────────── */

#define HOST "pyro-dead01.local"
#define SVC "_pyro._tcp.local"
#define INST "Pyro Unit 1._pyro._tcp.local"

static const char *const txt[] = {"txtvers=1", NULL};
static const mdns_record_t records[] = {
#if NET_USE_IPV4
    {.type = DNS_TYPE_A, .ttl = MDNS_TTL_HOST, .name = HOST, .rdata.a = 0},
#endif
    {.type = DNS_TYPE_AAAA,
     .ttl = MDNS_TTL_HOST,
     .name = HOST,
     .rdata.aaaa = NULL}, /* every usable IPv6 address */
    {.type = DNS_TYPE_PTR,
     .ttl = MDNS_TTL_OTHER,
     .name = SVC,
     .rdata.ptr = INST},
    {.type = DNS_TYPE_SRV,
     .ttl = MDNS_TTL_HOST,
     .name = INST,
     .rdata.srv = {0, 0, 80, HOST}},
    {.type = DNS_TYPE_TXT,
     .ttl = MDNS_TTL_HOST,
     .name = INST,
     .rdata.txt = txt},
};
#define N_RECS (sizeof(records) / sizeof(records[0]))

static const uint8_t our_ll[16] = {0xFE, 0x80, 0, 0,    0,    0,    0,    0,
                                   0,    0,    0, 0xFF, 0xFE, 0xDE, 0xAD, 0x01};
static const uint8_t our_global[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 1, 0, 0,
                                       0,    0,    0,    0,    0, 0, 0, 0x42};
static const uint8_t peer_ll[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                    0,    0,    0, 0, 0, 0, 0, 0x99};
static const uint8_t other_addr[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 9, 0, 0,
                                       0,    0,    0,    0,    0, 0, 0, 9};
static const uint8_t peer_mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t group6[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                   0,    0,    0, 0, 0, 0, 0, 0xFB};
static const uint8_t group6_mac[6] = {0x33, 0x33, 0, 0, 0, 0xFB};

#if NET_USE_IPV4
#define PEER_IP 0x0A000064u
#endif

/* ── Fixture ──────────────────────────────────────────────────────── */

static uint8_t rx_buf[1514], tx_buf[1514];
static net_t net;
static mdns_t m;
static int conflicts;

static void on_conflict(mdns_t *mm, uint8_t idx, void *ctx) {
  (void)mm;
  (void)idx;
  (void)ctx;
  conflicts++;
}

/** IPv4 (if built) + IPv6 up with a link-local and a global address. */
static void setup_recs(const mdns_record_t *recs, uint8_t n) {
  static int ctx;
  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf), NULL,
           &stub_drv, &ctx);
  ipv6_start(&net);
  for (int i = 0; i < 6; i++)
    ipv6_tick(&net, NDP_RTR_SOLICITATION_INTERVAL_MS);
  ipv6_addr_add(&net, our_global, NET_IP6_INFINITE, NET_IP6_INFINITE);
  ipv6_tick(&net, 1000);
  ipv6_tick(&net, 1000);
  n_frames = 0;
  conflicts = 0;
  mdns_init(&m, &net, recs, n, on_conflict, NULL);
}

static void setup(void) { setup_recs(records, (uint8_t)N_RECS); }

static void to_running(void) {
  mdns_start(&m);
  for (int i = 0; i < 4; i++)
    mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  mdns_tick(&m, MDNS_ANNOUNCE_WAIT_MS);
  n_frames = 0;
}

/* ── Frame helpers ────────────────────────────────────────────────── */

static int is_v4(int i) {
  return net_read16be(frames[i] + 12) == NET_ETHERTYPE_IPV4 &&
         frames[i][14 + 9] == 17;
}
static int is_v6(int i) {
  return net_read16be(frames[i] + 12) == NET_ETHERTYPE_IPV6 &&
         frames[i][14 + 6] == IPV6_NH_UDP;
}
static const uint8_t *msg_of(int i, uint16_t *len) {
  uint16_t off = is_v6(i) ? UDP6_PAYLOAD_OFFSET : 14u + 20u + UDP_HDR_SIZE;
  *len = (uint16_t)(frame_lens[i] - off);
  return frames[i] + off;
}
static int count_family(int v6) {
  int n = 0;
  for (int i = 0; i < n_frames && i < MAX_FRAMES; i++)
    if (v6 ? is_v6(i) : is_v4(i))
      n++;
  return n;
}
static int first_family(int v6) {
  for (int i = 0; i < n_frames && i < MAX_FRAMES; i++)
    if (v6 ? is_v6(i) : is_v4(i))
      return i;
  return -1;
}

/** RRs of @p type in a section (0 answer, 1 authority, 2 additional);
 *  copies up to 4 AAAA rdatas into @p aaaa. */
static int count_rr(int i, int section, uint16_t type, uint8_t aaaa[][16],
                    uint32_t *ttl_out, uint16_t *class_out) {
  uint16_t len;
  const uint8_t *msg = msg_of(i, &len);
  uint16_t qd = net_read16be(msg + DNS_OFF_QDCOUNT);
  uint16_t cnt[3] = {net_read16be(msg + DNS_OFF_ANCOUNT),
                     net_read16be(msg + DNS_OFF_NSCOUNT),
                     net_read16be(msg + DNS_OFF_ARCOUNT)};
  int off = DNS_HDR_SIZE, n = 0;
  dns_question_t q;
  dns_rr_t rr;
  for (uint16_t k = 0; k < qd; k++)
    off = dns_read_question(msg, len, (uint16_t)off, &q);
  for (int s = 0; s < 3; s++) {
    for (uint16_t k = 0; k < cnt[s]; k++) {
      off = dns_read_rr(msg, len, (uint16_t)off, &rr);
      if (off < 0)
        return -1;
      if (s != section || rr.type != type)
        continue;
      if (aaaa && n < 4 && rr.rdlen == 16)
        memcpy(aaaa[n], msg + rr.rdata_off, 16);
      if (ttl_out)
        *ttl_out = rr.ttl;
      if (class_out)
        *class_out = rr.class_;
      n++;
    }
  }
  return n;
}

static int has_addr(uint8_t aaaa[][16], int n, const uint8_t *addr) {
  for (int k = 0; k < n; k++)
    if (memcmp(aaaa[k], addr, 16) == 0)
      return 1;
  return 0;
}

/* ── Queries ──────────────────────────────────────────────────────── */

static uint8_t q[256];

/** One question (QU if qu), optionally one known answer (AAAA). */
static uint16_t query(const char *name, uint16_t type, int qu, uint16_t id,
                      const uint8_t *known_aaaa) {
  dns_writer_t w;
  dns_writer_init(&w, q, sizeof(q));
  dns_write_header(&w, id, 0, 1, known_aaaa ? 1 : 0, 0, 0);
  dns_write_name(&w, name);
  dns_write_u16(&w, type);
  dns_write_u16(&w, (uint16_t)(DNS_CLASS_IN | (qu ? DNS_CLASS_TOPBIT : 0)));
  if (known_aaaa) {
    dns_write_name(&w, name);
    dns_write_u16(&w, DNS_TYPE_AAAA);
    dns_write_u16(&w, DNS_CLASS_IN);
    dns_write_u32(&w, MDNS_TTL_HOST);
    dns_write_u16(&w, 16);
    dns_write_bytes(&w, known_aaaa, 16);
  }
  return w.len;
}

static void input6(uint16_t port, uint16_t len) {
  mdns_input6(&m, peer_ll, peer_mac, port, q, len);
}

/* ══ Start, probes, announcements ═════════════════════════════════ */

TEST(test_mdns6_start_joins_ff02_fb) {
  setup();
  ASSERT_FALSE(ipv6_mcast_is_member(&net, group6));
  mdns_start(&m);
  ASSERT_TRUE(ipv6_mcast_is_member(&net, group6));
  ASSERT_TRUE(ipv6_mac_accepted(&net, group6_mac));
}

TEST(test_mdns6_probes_on_both_families) {
  setup();
  mdns_start(&m);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  ASSERT_EQ(count_family(0), V4);
  ASSERT_EQ(count_family(1), 1);
  int v6 = first_family(1);
  const uint8_t *ip = frames[v6] + 14;
  ASSERT_MEM_EQ(frames[v6], group6_mac, 6);
  ASSERT_MEM_EQ(ip + 24, group6, 16);
  ASSERT_MEM_EQ(ip + 8, our_ll, 16);
  ASSERT_EQ(ip[7], 255); /* RFC 6762 §11 */
  ASSERT_EQ(net_read16be(ip + 40), MDNS_PORT);
  ASSERT_EQ(net_read16be(ip + 42), MDNS_PORT);
#if NET_USE_IPV4
  int v4 = first_family(0);
  uint16_t l4, l6;
  const uint8_t *m4 = msg_of(v4, &l4), *m6 = msg_of(v6, &l6);
  ASSERT_EQ(l4, l6);
  ASSERT_MEM_EQ(m4, m6, l4); /* the same probe on both */
#endif
  /* the probe proposes our AAAA records in Authority */
  uint8_t a[4][16];
  ASSERT_EQ(count_rr(v6, 1, DNS_TYPE_AAAA, a, NULL, NULL), 2);
}

TEST(test_mdns6_announcement_aaaa_for_each_usable_address) {
  setup();
  mdns_start(&m);
  for (int i = 0; i < 4; i++)
    mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  /* the first announcement just went out, on both families */
  int v6 = -1, v4 = -1;
  for (int i = 0; i < n_frames; i++) {
    uint16_t len;
    const uint8_t *msg = msg_of(i, &len);
    if (net_read16be(msg + DNS_OFF_FLAGS) & DNS_FLAG_QR) {
      if (is_v6(i))
        v6 = i;
      else if (is_v4(i))
        v4 = i;
    }
  }
  ASSERT_TRUE(v6 >= 0);
  ASSERT_EQ(v4 >= 0, V4);
  uint8_t a[4][16];
  uint16_t cls = 0;
  int n = count_rr(v6, 0, DNS_TYPE_AAAA, a, NULL, &cls);
  ASSERT_EQ(n, 2);
  ASSERT_TRUE(has_addr(a, n, our_ll));
  ASSERT_TRUE(has_addr(a, n, our_global));
  ASSERT_TRUE(cls & DNS_CLASS_TOPBIT); /* unique: cache-flush */
  ASSERT_EQ(count_rr(v6, 0, DNS_TYPE_A, NULL, NULL, NULL), V4);
#if NET_USE_IPV4
  /* RFC 6762 §6.2: all addresses valid on the interface, on IPv4 too */
  ASSERT_EQ(count_rr(v4, 0, DNS_TYPE_AAAA, NULL, NULL, NULL), 2);
#endif
}

TEST(test_mdns6_tentative_address_not_advertised) {
  static const uint8_t extra[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 7, 0, 0,
                                    0,    0,    0,    0,    0, 0, 0, 7};
  static const mdns_record_t recs[] = {
#if NET_USE_IPV4
      {.type = DNS_TYPE_A, .ttl = MDNS_TTL_HOST, .name = HOST, .rdata.a = 0},
#endif
      {.type = DNS_TYPE_AAAA,
       .ttl = MDNS_TTL_HOST,
       .name = HOST,
       .rdata.aaaa = NULL}};
  setup_recs(recs, (uint8_t)(sizeof(recs) / sizeof(recs[0])));
  /* one global slot only: make the global tentative instead */
  ipv6_addr_remove(&net, our_global);
  ipv6_addr_add(&net, extra, NET_IP6_INFINITE, NET_IP6_INFINITE);
  to_running();
  uint16_t len = query(HOST, DNS_TYPE_AAAA, 0, 0, NULL);
  input6(MDNS_PORT, len);
  int r = first_family(1);
  ASSERT_TRUE(r >= 0);
  uint8_t a[4][16];
  int n = count_rr(r, 0, DNS_TYPE_AAAA, a, NULL, NULL);
  /* the tentative address finished DAD while running? not ticked: no */
  ASSERT_EQ(n, 1);
  ASSERT_TRUE(has_addr(a, n, our_ll));
}

/* ══ Answers ══════════════════════════════════════════════════════ */

TEST(test_mdns6_aaaa_query_over_ipv6) {
  setup();
  to_running();
  uint16_t len = query(HOST, DNS_TYPE_AAAA, 0, 0, NULL);
  input6(MDNS_PORT, len);
  ASSERT_EQ(count_family(0), 0); /* answered on the query's family */
  ASSERT_EQ(count_family(1), 1);
  int r = first_family(1);
  ASSERT_MEM_EQ(frames[r] + 14 + 24, group6, 16);
  uint8_t a[4][16];
  int n = count_rr(r, 0, DNS_TYPE_AAAA, a, NULL, NULL);
  ASSERT_EQ(n, 2);
  ASSERT_TRUE(has_addr(a, n, our_global));
  /* RFC 6762 §6.2: the A record as an additional */
  ASSERT_EQ(count_rr(r, 2, DNS_TYPE_A, NULL, NULL, NULL), V4);
}

#if NET_USE_IPV4
TEST(test_mdns6_a_query_adds_aaaa) {
  setup();
  to_running();
  uint16_t len = query(HOST, DNS_TYPE_A, 0, 0, NULL);
  input6(MDNS_PORT, len);
  int r = first_family(1);
  ASSERT_TRUE(r >= 0);
  ASSERT_EQ(count_rr(r, 0, DNS_TYPE_A, NULL, NULL, NULL), 1);
  ASSERT_EQ(count_rr(r, 2, DNS_TYPE_AAAA, NULL, NULL, NULL), 2);
}

TEST(test_mdns6_aaaa_query_over_ipv4) {
  setup();
  to_running();
  uint16_t len = query(HOST, DNS_TYPE_AAAA, 0, 0, NULL);
  mdns_input(&m, PEER_IP, peer_mac, MDNS_PORT, q, len);
  ASSERT_EQ(count_family(1), 0);
  ASSERT_EQ(count_family(0), 1);
  ASSERT_EQ(count_rr(first_family(0), 0, DNS_TYPE_AAAA, NULL, NULL, NULL), 2);
}
#endif

TEST(test_mdns6_srv_additionals_include_aaaa) {
  setup();
  to_running();
  uint16_t len = query(INST, DNS_TYPE_SRV, 0, 0, NULL);
  input6(MDNS_PORT, len);
  int r = first_family(1);
  ASSERT_TRUE(r >= 0);
  ASSERT_EQ(count_rr(r, 2, DNS_TYPE_A, NULL, NULL, NULL), V4);
  ASSERT_EQ(count_rr(r, 2, DNS_TYPE_AAAA, NULL, NULL, NULL), 2);
}

TEST(test_mdns6_qu_query_unicast_reply) {
  setup();
  to_running();
  uint16_t len = query(HOST, DNS_TYPE_AAAA, 1, 0, NULL);
  input6(MDNS_PORT, len);
  ASSERT_EQ(n_frames, 1);
  ASSERT_TRUE(is_v6(0));
  ASSERT_MEM_EQ(frames[0], peer_mac, 6);
  ASSERT_MEM_EQ(frames[0] + 14 + 24, peer_ll, 16);
  ASSERT_EQ(net_read16be(frames[0] + 14 + 42), MDNS_PORT);
}

TEST(test_mdns6_legacy_unicast_reply) {
  setup();
  to_running();
  uint16_t len = query(HOST, DNS_TYPE_AAAA, 0, 0x4242, NULL);
  input6(40000, len);
  ASSERT_EQ(n_frames, 1);
  ASSERT_TRUE(is_v6(0));
  ASSERT_MEM_EQ(frames[0] + 14 + 24, peer_ll, 16);
  ASSERT_EQ(net_read16be(frames[0] + 14 + 42), 40000);
  uint16_t l;
  const uint8_t *msg = msg_of(0, &l);
  ASSERT_EQ(net_read16be(msg + DNS_OFF_ID), 0x4242);
  ASSERT_EQ(net_read16be(msg + DNS_OFF_QDCOUNT), 1);
  uint32_t ttl = 0;
  uint16_t cls = 0;
  ASSERT_EQ(count_rr(0, 0, DNS_TYPE_AAAA, NULL, &ttl, &cls), 2);
  ASSERT_TRUE(ttl <= MDNS_LEGACY_TTL_MAX);
  ASSERT_FALSE(cls & DNS_CLASS_TOPBIT);
}

TEST(test_mdns6_known_answer_suppression) {
  setup();
  to_running();
  uint16_t len = query(HOST, DNS_TYPE_AAAA, 0, 0, our_global);
  input6(MDNS_PORT, len);
  ASSERT_EQ(n_frames, 0);
}

TEST(test_mdns6_nsec_lists_aaaa) {
  setup();
  to_running();
  uint16_t len = query(HOST, 13 /* HINFO */, 0, 0, NULL);
  input6(MDNS_PORT, len);
  int r = first_family(1);
  ASSERT_TRUE(r >= 0);
  uint16_t l;
  const uint8_t *msg = msg_of(r, &l);
  int off = DNS_HDR_SIZE;
  dns_rr_t rr;
  off = dns_read_rr(msg, l, (uint16_t)off, &rr);
  ASSERT_TRUE(off > 0);
  ASSERT_EQ(rr.type, DNS_TYPE_NSEC);
  /* next name (2-byte pointer), window 0, bitmap length, bitmap */
  const uint8_t *bm = msg + rr.rdata_off + 2;
  ASSERT_EQ(bm[0], 0);
  ASSERT_TRUE(bm[1] >= 4);
  ASSERT_EQ((bm[2] & 0x40) != 0, V4);   /* type 1: A */
  ASSERT_TRUE(bm[2 + 3] & (0x80 >> 4)); /* type 28: AAAA */
}

TEST(test_mdns6_shared_query_delayed_on_ipv6_only) {
  setup();
  to_running();
  uint16_t len = query(SVC, DNS_TYPE_PTR, 0, 0, NULL);
  input6(MDNS_PORT, len);
  ASSERT_EQ(n_frames, 0);
  mdns_tick(&m, MDNS_RESP_DELAY_MAX_MS);
  ASSERT_EQ(count_family(0), 0);
  ASSERT_EQ(count_family(1), 1);
}

TEST(test_mdns6_explicit_aaaa_record) {
  static const mdns_record_t recs[1] = {{.type = DNS_TYPE_AAAA,
                                         .ttl = MDNS_TTL_HOST,
                                         .name = HOST,
                                         .rdata.aaaa = our_global}};
  setup_recs(recs, 1);
  to_running();
  uint16_t len = query(HOST, DNS_TYPE_AAAA, 0, 0, NULL);
  input6(MDNS_PORT, len);
  uint8_t a[4][16];
  ASSERT_EQ(count_rr(first_family(1), 0, DNS_TYPE_AAAA, a, NULL, NULL), 1);
  ASSERT_MEM_EQ(a[0], our_global, 16);
}

/* ══ Conflicts, re-announcing, goodbye ════════════════════════════ */

TEST(test_mdns6_conflict_on_foreign_aaaa_while_probing) {
  dns_writer_t w;
  setup();
  mdns_start(&m);
  mdns_tick(&m, MDNS_PROBE_WAIT_MS);
  dns_writer_init(&w, q, sizeof(q));
  dns_write_header(&w, 0, DNS_FLAG_QR | DNS_FLAG_AA, 0, 1, 0, 0);
  dns_write_name(&w, HOST);
  dns_write_u16(&w, DNS_TYPE_AAAA);
  dns_write_u16(&w, DNS_CLASS_IN | DNS_CLASS_TOPBIT);
  dns_write_u32(&w, MDNS_TTL_HOST);
  dns_write_u16(&w, 16);
  dns_write_bytes(&w, other_addr, 16);
  mdns_input6(&m, peer_ll, peer_mac, MDNS_PORT, q, w.len);
  ASSERT_EQ(conflicts, 1);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_CONFLICT);
}

TEST(test_mdns6_own_aaaa_is_not_a_conflict) {
  dns_writer_t w;
  setup();
  to_running();
  dns_writer_init(&w, q, sizeof(q));
  dns_write_header(&w, 0, DNS_FLAG_QR | DNS_FLAG_AA, 0, 1, 0, 0);
  dns_write_name(&w, HOST);
  dns_write_u16(&w, DNS_TYPE_AAAA);
  dns_write_u16(&w, DNS_CLASS_IN | DNS_CLASS_TOPBIT);
  dns_write_u32(&w, MDNS_TTL_HOST);
  dns_write_u16(&w, 16);
  dns_write_bytes(&w, our_global, 16);
  mdns_input6(&m, peer_ll, peer_mac, MDNS_PORT, q, w.len);
  ASSERT_EQ(conflicts, 0);
}

TEST(test_mdns6_readdress_announces_on_ipv6) {
  setup();
  to_running();
  mdns_readdress6(&m);
  mdns_tick(&m, 0);
  ASSERT_EQ(count_family(0), 0);
  ASSERT_EQ(count_family(1), 1);
  mdns_tick(&m, MDNS_ANNOUNCE_WAIT_MS);
  ASSERT_EQ(count_family(0), 0);
  ASSERT_EQ(count_family(1), 2); /* two announcements, IPv6 only */
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
}

TEST(test_mdns6_readdress_while_announcing) {
  /* IPv6 came up mid-sequence: both families still get two announcements */
  setup();
  mdns_start(&m);
  for (int i = 0; i < 4; i++)
    mdns_tick(&m, MDNS_PROBE_WAIT_MS); /* 3 probes + announcement 1 */
  n_frames = 0;
  mdns_readdress6(&m);
  mdns_tick(&m, MDNS_ANNOUNCE_WAIT_MS);
  mdns_tick(&m, MDNS_ANNOUNCE_WAIT_MS);
  ASSERT_EQ(count_family(0), 2 * V4);
  ASSERT_EQ(count_family(1), 2);
  ASSERT_EQ(mdns_state(&m), MDNS_STATE_RUNNING);
}

TEST(test_mdns6_goodbye_on_both_families) {
  setup();
  to_running();
  mdns_stop(&m);
  ASSERT_EQ(count_family(0), V4);
  ASSERT_EQ(count_family(1), 1);
  uint32_t ttl = 1;
  ASSERT_EQ(count_rr(first_family(1), 0, DNS_TYPE_AAAA, NULL, &ttl, NULL), 2);
  ASSERT_EQ(ttl, 0u);
  ASSERT_FALSE(ipv6_mcast_is_member(&net, group6));
}

int main(void) {
  fprintf(stderr, "=== mDNS over IPv6 tests ===\n");
  RUN_TEST(test_mdns6_start_joins_ff02_fb);
  RUN_TEST(test_mdns6_probes_on_both_families);
  RUN_TEST(test_mdns6_announcement_aaaa_for_each_usable_address);
  RUN_TEST(test_mdns6_tentative_address_not_advertised);
  RUN_TEST(test_mdns6_aaaa_query_over_ipv6);
#if NET_USE_IPV4
  RUN_TEST(test_mdns6_a_query_adds_aaaa);
  RUN_TEST(test_mdns6_aaaa_query_over_ipv4);
#endif
  RUN_TEST(test_mdns6_srv_additionals_include_aaaa);
  RUN_TEST(test_mdns6_qu_query_unicast_reply);
  RUN_TEST(test_mdns6_legacy_unicast_reply);
  RUN_TEST(test_mdns6_known_answer_suppression);
  RUN_TEST(test_mdns6_nsec_lists_aaaa);
  RUN_TEST(test_mdns6_shared_query_delayed_on_ipv6_only);
  RUN_TEST(test_mdns6_explicit_aaaa_record);
  RUN_TEST(test_mdns6_conflict_on_foreign_aaaa_while_probing);
  RUN_TEST(test_mdns6_own_aaaa_is_not_a_conflict);
  RUN_TEST(test_mdns6_readdress_announces_on_ipv6);
  RUN_TEST(test_mdns6_readdress_while_announcing);
  RUN_TEST(test_mdns6_goodbye_on_both_families);
  TEST_REPORT();
  return test_failures;
}
