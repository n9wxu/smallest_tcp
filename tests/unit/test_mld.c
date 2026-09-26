/**
 * @file test_mld.c
 * @brief Unit tests for Multicast Listener Discovery (RFC 3810 MLDv2,
 *        RFC 2710 MLDv1 compatibility) and IPv6 multicast membership.
 *
 * Built with NET_USE_IPV6=1.
 */

#include "eth.h"
#include "icmpv6.h"
#include "ipv6.h"
#include "mld.h"
#include "ndp.h"
#include "net.h"
#include "net_endian.h"
#include "test_main.h"
#include "udp.h"
#include <string.h>

#if !NET_USE_IPV6
#error "test_mld needs NET_USE_IPV6=1"
#endif

/* ── Stub MAC driver ──────────────────────────────────────────────── */

#define MAX_SENT 16
static uint8_t sent[MAX_SENT][600];
static uint16_t sent_len[MAX_SENT];
static int send_count;
static uint8_t rx_frame[600];
static uint16_t rx_len;

static int stub_init(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_send(void *ctx, const uint8_t *f, uint16_t l) {
  (void)ctx;
  int i = send_count < MAX_SENT ? send_count : MAX_SENT - 1;
  memcpy(sent[i], f, l < 600 ? l : 600);
  sent_len[i] = l;
  send_count++;
  return (int)l;
}
static int stub_poll(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_peek(void *ctx, uint16_t o, uint8_t *b, uint16_t l) {
  (void)ctx;
  if (o >= rx_len)
    return -1;
  if ((uint16_t)(o + l) > rx_len)
    l = (uint16_t)(rx_len - o);
  memcpy(b, rx_frame + o, l);
  return l;
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

/* ── Addresses ────────────────────────────────────────────────────── */

static const uint8_t our_ll[16] = {0xFE, 0x80, 0, 0,    0,    0,    0,    0,
                                   0,    0,    0, 0xFF, 0xFE, 0xDE, 0xAD, 0x01};
static const uint8_t our_snm[16] = {0xFF, 0x02, 0, 0, 0,    0,    0,    0,
                                    0,    0,    0, 1, 0xFF, 0xDE, 0xAD, 0x01};
static const uint8_t rtr_ll[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                   0,    0,    0, 0, 0, 0, 0, 1};
static const uint8_t all_nodes[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                      0,    0,    0, 0, 0, 0, 0, 1};
static const uint8_t all_mldv2[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                      0,    0,    0, 0, 0, 0, 0, 0x16};
static const uint8_t mdns6[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                  0,    0,    0, 0, 0, 0, 0, 0xFB};
static const uint8_t mac_mdns6[6] = {0x33, 0x33, 0, 0, 0, 0xFB};
static const uint8_t unspec[16] = {0};
static const uint8_t other_ll_iid[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
                                         0,    0,    0,    0,    0, 0x12, 0x34,
                                         0x56};
static const uint8_t mac_mldv2[6] = {0x33, 0x33, 0, 0, 0, 0x16};
static const uint8_t our_mac[6] = NET_DEFAULT_MAC;

/* ── Fixture ──────────────────────────────────────────────────────── */

static uint8_t rx_buf[1514], tx_buf[1514];
static net_t net;

static void reset_sent(void) {
  memset(sent_len, 0, sizeof(sent_len));
  send_count = 0;
}

static void setup_new(void) {
  int ctx = 0;
  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf), NULL,
           &stub_drv, &ctx);
  reset_sent();
}

/** IPv6 up, DAD and router solicitations done, sends cleared. */
static void setup_up(void) {
  setup_new();
  ipv6_start(&net);
  for (int i = 0; i < 6; i++)
    ipv6_tick(&net, NDP_RTR_SOLICITATION_INTERVAL_MS);
  reset_sent();
}

/* ── Sent-frame helpers ───────────────────────────────────────────── */

static const uint8_t *s_ip(int i) { return sent[i] + 14; }
/** ICMPv6 message behind the 8-byte Hop-by-Hop header of an MLD frame. */
static const uint8_t *s_mld(int i) { return sent[i] + 14 + 40 + 8; }

static int is_mld(int i, uint8_t type) {
  const uint8_t *ip = s_ip(i);
  return net_read16be(sent[i] + 12) == NET_ETHERTYPE_IPV6 &&
         ip[6] == IPV6_NH_HOPOPT && ip[40] == IPV6_NH_ICMPV6 &&
         s_mld(i)[0] == type;
}

/** Index of the first sent MLD message of @p type at or after @p from. */
static int find_mld(int from, uint8_t type) {
  for (int i = from; i < send_count && i < MAX_SENT; i++)
    if (is_mld(i, type))
      return i;
  return -1;
}

/** Well-formed MLD frame: hop limit 1, Router Alert, valid checksum. */
static int mld_frame_ok(int i) {
  const uint8_t *ip = s_ip(i);
  const uint8_t *hbh = ip + 40;
  uint16_t plen = net_read16be(ip + 4);
  return ip[7] == 1 && hbh[1] == 0 && hbh[2] == 5 && hbh[3] == 2 &&
         hbh[4] == 0 && hbh[5] == 0 &&
         ipv6_cksum(ip + 8, ip + 24, IPV6_NH_ICMPV6, s_mld(i),
                    (uint16_t)(plen - 8)) == 0;
}

/** Records of an MLDv2 report: the index of @p group's, or -1. */
static int v2_record(int i, const uint8_t *group, uint8_t *type_out) {
  const uint8_t *m = s_mld(i);
  uint16_t n = net_read16be(m + 6);
  const uint8_t *r = m + 8;
  for (uint16_t k = 0; k < n; k++, r += 20) {
    if (memcmp(r + 4, group, 16) == 0) {
      if (type_out)
        *type_out = r[0];
      return k;
    }
  }
  return -1;
}

static uint16_t v2_count(int i) { return net_read16be(s_mld(i) + 6); }

/** Deliver an MLD query (v2 if v2, else v1) from src with hop limit. */
static void query(const uint8_t *src, const uint8_t *dst, const uint8_t *group,
                  uint16_t max_resp_ms, int v2, uint8_t hlim) {
  uint8_t f[160], m[32];
  uint16_t mlen = v2 ? 28 : 24;
  memset(m, 0, sizeof(m));
  m[0] = MLD_QUERY;
  net_write16be(m + 4, max_resp_ms);
  memcpy(m + 8, group, 16);
  if (v2)
    m[25] = 125; /* QQIC */
  net_write16be(m + 2, ipv6_cksum(src, dst, IPV6_NH_ICMPV6, m, mlen));
  uint8_t dmac[6];
  ipv6_mcast_mac(dst, dmac);
  memcpy(f, dmac, 6);
  memcpy(f + 6, our_mac, 6);
  f[6] = 0x52; /* a router's MAC */
  net_write16be(f + 12, NET_ETHERTYPE_IPV6);
  ipv6_build(f + 14, (uint16_t)(8 + mlen), IPV6_NH_HOPOPT, src, dst, hlim);
  uint8_t hbh[8] = {IPV6_NH_ICMPV6, 0, 5, 2, 0, 0, 1, 0};
  memcpy(f + 54, hbh, 8);
  memcpy(f + 62, m, mlen);
  eth_input(&net, f, (uint16_t)(62 + mlen));
}

/* ══ Reports while joining (DAD) ══════════════════════════════════ */

TEST(test_mld_report_before_dad_probe) {
  setup_new();
  ipv6_start(&net);
  ipv6_tick(&net, 1000);
  int r = find_mld(0, MLD_V2_REPORT);
  ASSERT_TRUE(r >= 0);
  ASSERT_TRUE(mld_frame_ok(r));
  ASSERT_MEM_EQ(sent[r], mac_mldv2, 6);
  ASSERT_MEM_EQ(s_ip(r) + 8, unspec, 16); /* no link-local yet */
  ASSERT_MEM_EQ(s_ip(r) + 24, all_mldv2, 16);
  uint8_t type = 0;
  ASSERT_TRUE(v2_record(r, our_snm, &type) >= 0);
  ASSERT_EQ(type, MLD_CHANGE_TO_EXCLUDE);
  ASSERT_EQ(v2_count(r), 1); /* all-nodes is never reported */
  /* the report precedes the DAD probe */
  int ns = -1;
  for (int i = 0; i < send_count; i++)
    if (net_read16be(sent[i] + 12) == NET_ETHERTYPE_IPV6 &&
        s_ip(i)[6] == IPV6_NH_ICMPV6 && sent[i][54] == ICMPV6_NS)
      ns = i;
  ASSERT_TRUE(ns > r);
}

TEST(test_mld_unsolicited_report_repeated) {
  setup_new();
  ipv6_start(&net);
  ipv6_tick(&net, 1000);
  int first = find_mld(0, MLD_V2_REPORT);
  ASSERT_TRUE(first >= 0);
  ipv6_tick(&net, MLD_UNSOLICITED_INTERVAL_MS);
  ASSERT_TRUE(find_mld(first + 1, MLD_V2_REPORT) > first);
}

TEST(test_mld_same_group_reported_once) {
  /* A SLAAC address with our interface identifier shares the link-local
   * address's solicited-node group */
  static const uint8_t slaac[16] = {0x20, 0x01, 0x0D, 0xB8, 0,    1,
                                    0,    0,    0,    0,    0,    0xFF,
                                    0xFE, 0xDE, 0xAD, 0x01};
  setup_up();
  ipv6_addr_add(&net, slaac, NET_IP6_INFINITE, NET_IP6_INFINITE);
  ipv6_tick(&net, 10);
  int r = find_mld(0, MLD_V2_REPORT);
  ASSERT_TRUE(r >= 0);
  ASSERT_EQ(v2_count(r), 1);
}

TEST(test_mld_new_group_for_other_iid) {
  uint8_t snm2[16];
  setup_up();
  ipv6_addr_add(&net, other_ll_iid, NET_IP6_INFINITE, NET_IP6_INFINITE);
  ipv6_tick(&net, 10);
  int r = find_mld(0, MLD_V2_REPORT);
  ASSERT_TRUE(r >= 0);
  ASSERT_EQ(v2_count(r), 2);
  ipv6_solicited_node(other_ll_iid, snm2);
  ASSERT_TRUE(v2_record(r, snm2, NULL) >= 0);
  ASSERT_TRUE(v2_record(r, our_snm, NULL) >= 0);
}

/* ══ Joining groups ═══════════════════════════════════════════════ */

TEST(test_mcast_join_reports_and_accepts) {
  setup_up();
  ASSERT_FALSE(ipv6_mac_accepted(&net, mac_mdns6));
  ASSERT_EQ(ipv6_mcast_join(&net, mdns6), NET_OK);
  ASSERT_TRUE(ipv6_mcast_is_member(&net, mdns6));
  ASSERT_TRUE(ipv6_mac_accepted(&net, mac_mdns6));
  int r = find_mld(0, MLD_V2_REPORT);
  ASSERT_TRUE(r >= 0);
  ASSERT_TRUE(mld_frame_ok(r));
  ASSERT_MEM_EQ(s_ip(r) + 8, our_ll, 16); /* from the link-local address */
  uint8_t type = 0;
  ASSERT_TRUE(v2_record(r, mdns6, &type) >= 0);
  ASSERT_EQ(type, MLD_CHANGE_TO_EXCLUDE);
  ASSERT_EQ(ipv6_mcast_join(&net, mdns6), NET_OK); /* again: no-op */
}

TEST(test_mcast_join_rejects_non_multicast_and_full_table) {
  static const uint8_t other_group[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                          0,    0,    0, 0, 0, 0, 0, 0x42};
  setup_up();
  ASSERT_EQ(ipv6_mcast_join(&net, our_ll), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(ipv6_mcast_join(&net, mdns6), NET_OK);
  ASSERT_EQ(ipv6_mcast_join(&net, other_group),
            NET_ERR_BUF_TOO_SMALL); /* NET_MAX_MCAST6_GROUPS = 1 */
}

static int udp6_calls;
static void on_udp6(net_t *n, const uint8_t *src, uint16_t sport,
                    const uint8_t *mac, uint16_t off, uint16_t len) {
  (void)n;
  (void)src;
  (void)sport;
  (void)mac;
  (void)off;
  (void)len;
  udp6_calls++;
}
static const udp6_port_entry_t ports6[] = {{5353, on_udp6}};

TEST(test_joined_group_datagrams_delivered) {
  uint8_t f[128];
  setup_up();
  udp6_ports.entries = ports6;
  udp6_ports.count = 1;
  udp6_calls = 0;
  /* UDP to ff02::fb before and after joining */
  for (int joined = 0; joined < 2; joined++) {
    if (joined)
      ipv6_mcast_join(&net, mdns6);
    memcpy(f, mac_mdns6, 6);
    memcpy(f + 6, our_mac, 6);
    f[6] = 0xAA;
    net_write16be(f + 12, NET_ETHERTYPE_IPV6);
    ipv6_build(f + 14, 12, IPV6_NH_UDP, rtr_ll, mdns6, 255);
    uint8_t *u = f + 54;
    net_write16be(u, 5353);
    net_write16be(u + 2, 5353);
    net_write16be(u + 4, 12);
    net_write16be(u + 6, 0);
    memcpy(u + 8, "mdns", 4);
    net_write16be(u + 6, ipv6_cksum(rtr_ll, mdns6, IPV6_NH_UDP, u, 12));
    memcpy(rx_frame, f, 66);
    rx_len = 66;
    eth_input(&net, f, 66);
    ASSERT_EQ(udp6_calls, joined);
  }
}

TEST(test_mcast_leave) {
  setup_up();
  ipv6_mcast_join(&net, mdns6);
  reset_sent();
  ipv6_mcast_leave(&net, mdns6);
  ASSERT_FALSE(ipv6_mcast_is_member(&net, mdns6));
  ASSERT_FALSE(ipv6_mac_accepted(&net, mac_mdns6));
  int r = find_mld(0, MLD_V2_REPORT);
  ASSERT_TRUE(r >= 0);
  uint8_t type = 0;
  ASSERT_TRUE(v2_record(r, mdns6, &type) >= 0);
  ASSERT_EQ(type, MLD_CHANGE_TO_INCLUDE); /* with no sources: left */
}

/* ══ Queries ══════════════════════════════════════════════════════ */

TEST(test_general_query_answered) {
  setup_up();
  ipv6_mcast_join(&net, mdns6);
  ipv6_tick(&net, 2000); /* unsolicited reports done */
  reset_sent();
  query(rtr_ll, all_nodes, unspec, 1000, 1, 1);
  ASSERT_EQ(find_mld(0, MLD_V2_REPORT), -1); /* not before the delay */
  for (int t = 0; t < 1000; t += 10)
    ipv6_tick(&net, 10);
  int r = find_mld(0, MLD_V2_REPORT);
  ASSERT_TRUE(r >= 0);
  ASSERT_TRUE(mld_frame_ok(r));
  ASSERT_MEM_EQ(s_ip(r) + 8, our_ll, 16);
  uint8_t type = 0;
  ASSERT_TRUE(v2_record(r, mdns6, &type) >= 0);
  ASSERT_EQ(type, MLD_MODE_IS_EXCLUDE);
  ASSERT_TRUE(v2_record(r, our_snm, &type) >= 0);
  ASSERT_EQ(find_mld(r + 1, MLD_V2_REPORT), -1); /* just one answer */
}

TEST(test_query_validation) {
  static const uint8_t global_src[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
                                         0,    0,    0,    0,    0, 0, 0, 1};
  setup_up();
  query(rtr_ll, all_nodes, unspec, 100, 1, 2);     /* hop limit 2 */
  query(global_src, all_nodes, unspec, 100, 1, 1); /* not link-local */
  for (int t = 0; t < 500; t += 10)
    ipv6_tick(&net, 10);
  ASSERT_EQ(find_mld(0, MLD_V2_REPORT), -1);
}

TEST(test_group_query_for_other_group_ignored) {
  static const uint8_t other_group[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                          0,    0,    0, 0, 0, 0, 0, 0x42};
  setup_up();
  query(rtr_ll, all_nodes, other_group, 100, 1, 1);
  for (int t = 0; t < 500; t += 10)
    ipv6_tick(&net, 10);
  ASSERT_EQ(find_mld(0, MLD_V2_REPORT), -1);
}

TEST(test_mldv1_query_answered_with_v1_reports) {
  setup_up();
  ipv6_mcast_join(&net, mdns6);
  ipv6_tick(&net, 2000);
  reset_sent();
  query(rtr_ll, all_nodes, unspec, 500, 0, 1);
  for (int t = 0; t < 500; t += 10)
    ipv6_tick(&net, 10);
  ASSERT_EQ(find_mld(0, MLD_V2_REPORT), -1);
  int a = find_mld(0, MLD_V1_REPORT);
  ASSERT_TRUE(a >= 0);
  int b = find_mld(a + 1, MLD_V1_REPORT);
  ASSERT_TRUE(b > a); /* one per group: solicited-node and ff02::fb */
  ASSERT_TRUE(mld_frame_ok(a));
  /* each goes to its group, which it names */
  ASSERT_MEM_EQ(s_ip(a) + 24, s_mld(a) + 8, 16);
  ASSERT_MEM_EQ(s_ip(b) + 24, s_mld(b) + 8, 16);
}

TEST(test_mldv1_mode_for_later_reports) {
  setup_up();
  query(rtr_ll, all_nodes, unspec, 100, 0, 1);
  ipv6_tick(&net, 200);
  reset_sent();
  ipv6_mcast_join(&net, mdns6);
  ASSERT_EQ(find_mld(0, MLD_V2_REPORT), -1);
  int a = find_mld(0, MLD_V1_REPORT);
  ASSERT_TRUE(a >= 0);
  /* leaving in MLDv1 mode sends a Done to all-routers */
  reset_sent();
  ipv6_mcast_leave(&net, mdns6);
  int d = find_mld(0, MLD_V1_DONE);
  ASSERT_TRUE(d >= 0);
  ASSERT_MEM_EQ(s_mld(d) + 8, mdns6, 16);
  /* after the Older Version Querier Present timeout, back to MLDv2 */
  for (int s = 0; s < MLD_OLDER_QUERIER_S; s++)
    ipv6_tick(&net, 1000);
  reset_sent();
  ipv6_mcast_join(&net, mdns6);
  ASSERT_TRUE(find_mld(0, MLD_V2_REPORT) >= 0);
}

int main(void) {
  fprintf(stderr, "=== MLD tests ===\n");
  RUN_TEST(test_mld_report_before_dad_probe);
  RUN_TEST(test_mld_unsolicited_report_repeated);
  RUN_TEST(test_mld_same_group_reported_once);
  RUN_TEST(test_mld_new_group_for_other_iid);
  RUN_TEST(test_mcast_join_reports_and_accepts);
  RUN_TEST(test_mcast_join_rejects_non_multicast_and_full_table);
  RUN_TEST(test_joined_group_datagrams_delivered);
  RUN_TEST(test_mcast_leave);
  RUN_TEST(test_general_query_answered);
  RUN_TEST(test_query_validation);
  RUN_TEST(test_group_query_for_other_group_ignored);
  RUN_TEST(test_mldv1_query_answered_with_v1_reports);
  RUN_TEST(test_mldv1_mode_for_later_reports);
  TEST_REPORT();
  return test_failures;
}
