/**
 * @file itest_mld.c
 * @brief Multicast Listener Discovery, black box: the reports the stack
 *        sends for the groups it listens to, its answers to a router's
 *        queries, and ipv6_mcast_join() / ipv6_mcast_leave().
 */

#include "ipv6.h"
#include "itest.h"
#include "udp.h"
#include <string.h>

#define T_QUERY 130
#define T_V1_REPORT 131
#define T_V1_DONE 132
#define T_V2_REPORT 143
#define T_NS 135

#define REC_MODE_IS_EXCLUDE 2
#define REC_CHANGE_TO_INCLUDE 3
#define REC_CHANGE_TO_EXCLUDE 4

#define APP_PORT 5353

static itest_t t;
static const uint8_t unspec[16] = {0};
static const uint8_t mldv2_routers[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                          0,    0,    0, 0, 0, 0, 0, 0x16};
static const uint8_t mldv2_routers_mac[6] = {0x33, 0x33, 0, 0, 0, 0x16};
static const uint8_t group[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                  0,    0,    0, 0, 0, 0, 0, 0xFB};
static const uint8_t group_mac[6] = {0x33, 0x33, 0, 0, 0, 0xFB};
static const uint8_t group2[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                   0,    0,    0, 0, 0, 1, 0, 3};
/* The Hop-by-Hop header every MLD message carries: a Router Alert for
 * MLD, padded to 8 octets */
static const uint8_t router_alert[8] = {58, 0, 5, 2, 0, 0, 1, 0};
static uint8_t ll[16], sn[16];
static int delivered;

static void on_datagram6(net_t *net, const uint8_t *src_ip, uint16_t src_port,
                         const uint8_t *src_mac, const uint8_t *data,
                         uint16_t len) {
  (void)net;
  (void)src_ip;
  (void)src_port;
  (void)src_mac;
  (void)data;
  (void)len;
  delivered++;
}

static const udp6_port_entry_t ports6[] = {{APP_PORT, on_datagram6}};

/* net_init() done and IPv6 started: the link-local address is tentative */
static void starting(void) {
  itest_up(&t, 1514, 1514);
  udp6_set_ports(&t.net, ports6, 1);
  peer_link_local(t.net.mac, ll);
  peer_solicited_node(ll, sn);
  delivered = 0;
  ipv6_start(&t.net);
}

/* The link-local address past DAD, the Router Solicitations over */
static void up(void) {
  starting();
  itest_advance(&t, 15000, 100);
  wire_clear(&t);
}

/* ── What the stack sent ── */

/* The @p k-th MLD message of @p type sent since wire_clear(): 1 if there
 * is one, well formed — Hop Limit 1, the Router Alert in a Hop-by-Hop
 * header, a valid checksum */
static int mld_sent(uint8_t type, int k, peer_ip6_t *ip, peer_icmp_t *icmp) {
  int i = 0;
  while ((i = wire_find_icmp6(&t, (uint16_t)i, type, ip, icmp)) >= 0) {
    if (k-- == 0)
      return ip->hop_limit == 1 && ip->nh == 0 && ip->ext_len == 8 &&
             ip->ext[0] == 58 && ip->ext[2] == 5 && ip->ext[3] == 2 &&
             peer_get16(ip->ext + 4) == 0 && icmp->code == 0 && icmp->cksum_ok;
    i++;
  }
  return 0;
}

/* How many records an MLDv2 report has; -1 if they are not all of
 * @p type, without sources or auxiliary data */
static int records(const peer_icmp_t *icmp, uint8_t type) {
  uint16_t n = peer_get16(icmp->rest + 2), k;
  if (icmp->data_len != n * 20u)
    return -1;
  for (k = 0; k < n; k++) {
    const uint8_t *r = icmp->data + 20u * k;
    if (r[0] != type || r[1] != 0 || peer_get16(r + 2) != 0)
      return -1;
  }
  return n;
}

/* 1 if the report has a record for @p g */
static int reports(const peer_icmp_t *icmp, const uint8_t *g) {
  uint16_t n = peer_get16(icmp->rest + 2), k;
  for (k = 0; k < n && 20u * (k + 1u) <= icmp->data_len; k++) {
    if (memcmp(icmp->data + 20u * k + 4, g, 16) == 0)
      return 1;
  }
  return 0;
}

/* ── The router's queries ── */

/* A query from @p src: MLDv2 if @p v2 (28 octets), else MLDv1 (24), for
 * @p g (NULL: a general query) with a Maximum Response Delay of
 * @p max_ms; @p hop_limit and @p cut bytes left off let a test get it
 * wrong */
static void query(const uint8_t *src, int v2, const uint8_t *g, uint16_t max_ms,
                  uint8_t hop_limit, uint16_t cut) {
  static uint8_t msg[64], f[160];
  uint8_t body[20], rest[4] = {0, 0, 0, 0}, mac[6];
  peer_ip6_t ip = peer_ip6(src, g ? g : all_nodes6, 0), inner;
  uint16_t n;
  ip.hop_limit = hop_limit;
  ip.ext = router_alert;
  ip.ext_len = 8;
  inner = ip;
  peer_put16(rest, max_ms);
  memset(body, 0, sizeof(body));
  if (g)
    memcpy(body, g, 16);
  body[16] = 2;   /* QRV */
  body[17] = 125; /* QQIC */
  n = peer_icmp6(msg, &inner, T_QUERY, 0, rest, body,
                 (uint16_t)((v2 ? 20 : 16) - cut));
  peer_mcast6_mac(ip.dst, mac);
  itest_receive(&t, f, peer_ipv6_frame(f, mac, router6_mac, &ip, msg, n));
}

/* ── Reports ── */

/* REQ-IPv6-049, 050, 051: before the first DAD probe the interface
 * reports the solicited-node group of its address: an MLDv2 report to
 * ff02::16 — Hop Limit 1, a Router Alert, from :: while no address is
 * valid — with a CHANGE_TO_EXCLUDE record without sources; all-nodes is
 * not reported.  The report is sent once more a second later. */
TEST(itest_mld_049_groups_reported_at_start) {
  peer_ip6_t ip;
  peer_icmp_t icmp;
  int report_at, probe_at;
  starting();
  while (t.wire.tx_count == 0)
    itest_advance(&t, 1, 1);
  report_at = wire_find_icmp6(&t, 0, T_V2_REPORT, &ip, &icmp);
  ASSERT_TRUE(mld_sent(T_V2_REPORT, 0, &ip, &icmp));
  probe_at = wire_find_icmp6(&t, 0, T_NS, &ip, &icmp);
  ASSERT_TRUE(report_at == 0 && probe_at == 1);
  ASSERT_TRUE(mld_sent(T_V2_REPORT, 0, &ip, &icmp));
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, mldv2_routers_mac, 6);
  ASSERT_MEM_EQ(ip.dst, mldv2_routers, 16);
  ASSERT_MEM_EQ(ip.src, unspec, 16);
  ASSERT_EQ(peer_get16(icmp.rest), 0);
  ASSERT_EQ(records(&icmp, REC_CHANGE_TO_EXCLUDE), 1);
  ASSERT_TRUE(reports(&icmp, sn));
  ASSERT_FALSE(reports(&icmp, all_nodes6));
  wire_clear(&t);
  itest_advance(&t, 999, 1);
  ASSERT_EQ(wire_count_icmp6(&t, T_V2_REPORT), 0);
  itest_advance(&t, 1, 1);
  ASSERT_TRUE(mld_sent(T_V2_REPORT, 0, &ip, &icmp));
  ASSERT_EQ(records(&icmp, REC_CHANGE_TO_EXCLUDE), 1);
}

/* REQ-IPv6-054: once the link-local address is valid, the groups are
 * reported from it — routers discard the reports sent from :: */
TEST(itest_mld_054_reported_from_the_link_local_address) {
  peer_ip6_t ip;
  peer_icmp_t icmp;
  int k, from_ll = 0;
  starting();
  ipv6_mcast_join(&t.net, group);
  itest_advance(&t, 15000, 100);
  for (k = 0; mld_sent(T_V2_REPORT, k, &ip, &icmp); k++) {
    if (memcmp(ip.src, ll, 16) == 0 && reports(&icmp, sn) &&
        reports(&icmp, group))
      from_ll++;
  }
  ASSERT_TRUE(from_ll >= 1);
}

/* REQ-IPv6-049, 055: ipv6_mcast_join() makes the interface listen to a
 * group — its frames and packets are taken — and reports it, with the
 * other groups, at once and again a second later; joining twice is one
 * membership; a unicast address or one group too many is refused */
TEST(itest_mld_049_join_reported_and_received) {
  static uint8_t seg[64], f[160];
  peer_ip6_t ip = peer_ip6(peer6_ll, group, 17), rip;
  peer_icmp_t icmp;
  uint16_t n = peer_udp6(seg, &ip, 40000, APP_PORT, "x", 1);
  uint16_t len = peer_ipv6_frame(f, group_mac, peer_mac, &ip, seg, n);
  up();
  itest_receive(&t, f, len);
  ASSERT_EQ(delivered, 0); /* not listening yet */
  ASSERT_FALSE(ipv6_mcast_is_member(&t.net, group));
  ASSERT_EQ(ipv6_mcast_join(&t.net, group), NET_OK);
  ASSERT_TRUE(ipv6_mcast_is_member(&t.net, group));
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(mld_sent(T_V2_REPORT, 0, &rip, &icmp));
  ASSERT_MEM_EQ(rip.src, ll, 16);
  ASSERT_MEM_EQ(rip.dst, mldv2_routers, 16);
  ASSERT_EQ(records(&icmp, REC_CHANGE_TO_EXCLUDE), 2);
  ASSERT_TRUE(reports(&icmp, sn));
  ASSERT_TRUE(reports(&icmp, group));
  itest_receive(&t, f, len);
  ASSERT_EQ(delivered, 1);
  wire_clear(&t);
  itest_advance(&t, 1000, 100);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(mld_sent(T_V2_REPORT, 0, &rip, &icmp));
  ASSERT_EQ(records(&icmp, REC_CHANGE_TO_EXCLUDE), 2);
  wire_clear(&t);
  ASSERT_EQ(ipv6_mcast_join(&t.net, group), NET_OK); /* already a member */
  ASSERT_EQ(ipv6_mcast_join(&t.net, peer6_ll), NET_ERR_INVALID_PARAM);
  if (NET_MAX_MCAST6_GROUPS == 1)
    ASSERT_EQ(ipv6_mcast_join(&t.net, group2), NET_ERR_BUF_TOO_SMALL);
  itest_advance(&t, 5000, 100);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-IPv6-055, 051: ipv6_mcast_leave() stops the listening and reports
 * the group with one CHANGE_TO_INCLUDE record without sources — once
 * (deviation: not repeated) */
TEST(itest_mld_055_leave_reported) {
  static uint8_t seg[64], f[160];
  peer_ip6_t ip = peer_ip6(peer6_ll, group, 17), rip;
  peer_icmp_t icmp;
  uint16_t n = peer_udp6(seg, &ip, 40000, APP_PORT, "x", 1);
  uint16_t len = peer_ipv6_frame(f, group_mac, peer_mac, &ip, seg, n);
  up();
  ipv6_mcast_join(&t.net, group);
  itest_advance(&t, 3000, 100);
  wire_clear(&t);
  ipv6_mcast_leave(&t.net, group);
  ASSERT_FALSE(ipv6_mcast_is_member(&t.net, group));
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(mld_sent(T_V2_REPORT, 0, &rip, &icmp));
  ASSERT_EQ(records(&icmp, REC_CHANGE_TO_INCLUDE), 1);
  ASSERT_TRUE(reports(&icmp, group));
  itest_receive(&t, f, len);
  ASSERT_EQ(delivered, 0);
  wire_clear(&t);
  ipv6_mcast_leave(&t.net, group); /* not a member: nothing */
  itest_advance(&t, 5000, 100);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-IPv6-049: an address added later has its solicited-node group
 * reported before its DAD probe; a group two addresses share is reported
 * once */
TEST(itest_mld_049_solicited_node_group_of_each_address) {
  uint8_t same_iid[16], other[16], other_sn[16];
  peer_ip6_t ip;
  peer_icmp_t icmp;
  up();
  memcpy(same_iid, prefix6, 8);
  memcpy(same_iid + 8, ll + 8, 8);
  ipv6_addr_add(&t.net, same_iid, 0xFFFFFFFFu, 0xFFFFFFFFu);
  itest_advance(&t, 1, 1);
  ASSERT_TRUE(mld_sent(T_V2_REPORT, 0, &ip, &icmp));
  ASSERT_EQ(records(&icmp, REC_CHANGE_TO_EXCLUDE), 1);
  ASSERT_TRUE(reports(&icmp, sn));
  ASSERT_EQ(wire_find_icmp6(&t, 0, T_V2_REPORT, &ip, &icmp), 0);
  ASSERT_EQ(wire_find_icmp6(&t, 0, T_NS, &ip, &icmp), 1);

  up();
  memcpy(other, prefix6, 16);
  other[13] = 0x12;
  other[14] = 0x34;
  other[15] = 0x56;
  peer_solicited_node(other, other_sn);
  ipv6_addr_add(&t.net, other, 0xFFFFFFFFu, 0xFFFFFFFFu);
  itest_advance(&t, 1, 1);
  ASSERT_TRUE(mld_sent(T_V2_REPORT, 0, &ip, &icmp));
  ASSERT_EQ(records(&icmp, REC_CHANGE_TO_EXCLUDE), 2);
  ASSERT_TRUE(reports(&icmp, sn));
  ASSERT_TRUE(reports(&icmp, other_sn));
}

/* ── Queries ── */

/* REQ-IPv6-052: a general query is answered, after a random delay within
 * its Maximum Response Delay, with one report of every group
 * (MODE_IS_EXCLUDE records, no sources), from the link-local address */
TEST(itest_mld_052_general_query_answered) {
  peer_ip6_t ip;
  peer_icmp_t icmp;
  uint8_t seed;
  int early = 0;
  for (seed = 0; seed < 8; seed++) {
    uint32_t ms = 0;
    up();
    net_random_seed(&t.net, &seed, 1);
    ipv6_mcast_join(&t.net, group);
    itest_advance(&t, 3000, 100);
    wire_clear(&t);
    query(router6_ll, 1, NULL, 2000, 1, 0);
    ASSERT_EQ(t.wire.tx_count, 0); /* not at once */
    while (t.wire.tx_count == 0 && ms < 5000) {
      itest_advance(&t, 1, 1);
      ms++;
    }
    ASSERT_TRUE(ms >= 1 && ms <= 2000);
    early += ms < 1900;
    ASSERT_TRUE(mld_sent(T_V2_REPORT, 0, &ip, &icmp));
    ASSERT_MEM_EQ(ip.src, ll, 16);
    ASSERT_MEM_EQ(ip.dst, mldv2_routers, 16);
    ASSERT_EQ(records(&icmp, REC_MODE_IS_EXCLUDE), 2);
    ASSERT_TRUE(reports(&icmp, sn));
    ASSERT_TRUE(reports(&icmp, group));
    itest_advance(&t, 5000, 100);
    ASSERT_EQ(t.wire.tx_count, 1); /* an answer is not repeated */
  }
  ASSERT_TRUE(early > 0); /* random, not the maximum each time */
}

/* REQ-IPv6-052: MLDv2's Maximum Response Code above 32767 is a
 * floating-point value — 0x8000 is 32.768 s — and the answer comes within
 * it, at a random time */
TEST(itest_mld_052_maximum_response_code_decoded) {
  uint8_t seed;
  int late = 0;
  for (seed = 0; seed < 8; seed++) {
    uint32_t ms = 0;
    up();
    net_random_seed(&t.net, &seed, 1);
    query(router6_ll, 1, NULL, 0x8000, 1, 0);
    while (t.wire.tx_count == 0 && ms < 40000) {
      itest_advance(&t, 8, 8);
      ms += 8;
    }
    ASSERT_TRUE(ms <= 32768);
    late += ms > 1000;
  }
  ASSERT_TRUE(late > 0);
}

/* REQ-IPv6-052: a second query does not put off the answer already due */
TEST(itest_mld_052_pending_answer_stands) {
  uint8_t seed;
  for (seed = 0; seed < 8; seed++) {
    up();
    net_random_seed(&t.net, &seed, 1);
    query(router6_ll, 1, NULL, 100, 1, 0);
    query(router6_ll, 1, NULL, 60000, 1, 0);
    itest_advance(&t, 100, 1);
    ASSERT_EQ(wire_count_icmp6(&t, T_V2_REPORT), 1);
  }
}

/* REQ-IPv6-049: the solicited-node group of a duplicate address is not
 * reported; with no group at all, nothing is */
TEST(itest_mld_049_duplicate_address_not_reported) {
  static uint8_t msg[64], f[160];
  uint8_t other[16], other_sn[16], body[24], rest[4] = {0x20, 0, 0, 0};
  uint8_t mac[6];
  peer_ip6_t ip, na_ip = peer_ip6(peer6_ll, all_nodes6, 58);
  peer_icmp_t icmp;
  uint16_t len;
  na_ip.hop_limit = 255;
  peer_mcast6_mac(all_nodes6, mac);
  up();
  memcpy(other, prefix6, 16);
  other[13] = 0x12;
  other[14] = 0x34;
  other[15] = 0x56;
  peer_solicited_node(other, other_sn);
  ipv6_addr_add(&t.net, other, 0xFFFFFFFFu, 0xFFFFFFFFu);
  itest_advance(&t, 100, 100);
  memcpy(body, other, 16); /* another node has it */
  peer_nd_lla(body + 16, 2, peer_mac);
  len = peer_icmp6(msg, &na_ip, 136, 0, rest, body, 24);
  itest_receive(&t, f, peer_ipv6_frame(f, mac, peer_mac, &na_ip, msg, len));
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_DUPLICATE);
  itest_advance(&t, 3000, 100);
  wire_clear(&t);
  query(router6_ll, 1, NULL, 100, 1, 0);
  itest_advance(&t, 200, 10);
  ASSERT_TRUE(mld_sent(T_V2_REPORT, 0, &ip, &icmp));
  ASSERT_EQ(records(&icmp, REC_MODE_IS_EXCLUDE), 1);
  ASSERT_TRUE(reports(&icmp, sn));
  ASSERT_FALSE(reports(&icmp, other_sn));

  starting(); /* the link-local address itself a duplicate: no group left */
  memcpy(body, ll, 16);
  len = peer_icmp6(msg, &na_ip, 136, 0, rest, body, 24);
  itest_receive(&t, f, peer_ipv6_frame(f, mac, peer_mac, &na_ip, msg, len));
  ASSERT_EQ(ipv6_addr_state(&t.net, 0), NET_IP6_DUPLICATE);
  itest_advance(&t, 3000, 100);
  wire_clear(&t);
  query(router6_ll, 1, NULL, 100, 1, 0);
  itest_advance(&t, 200, 10);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-IPv6-052: a query is dropped unless it comes from a link-local
 * address with Hop Limit 1 and is 24 or at least 28 octets long */
TEST(itest_mld_052_queries_validated) {
  up();
  query(router6_ll, 1, NULL, 100, 2, 0);
  query(router6_ll, 1, NULL, 100, 255, 0);
  query(offlink6, 1, NULL, 100, 1, 0);
  query(router6_ll, 1, NULL, 100, 1, 2); /* 26 octets */
  query(router6_ll, 0, NULL, 100, 1, 4); /* 20 octets */
  itest_advance(&t, 2000, 10);
  ASSERT_EQ(t.wire.tx_count, 0);
  query(router6_ll, 1, NULL, 100, 1, 0);
  itest_advance(&t, 200, 10);
  ASSERT_EQ(wire_count_icmp6(&t, T_V2_REPORT), 1);
}

/* REQ-IPv6-052: a query for one group is answered if the group is ours —
 * (deviation) with a report of every group — and not otherwise */
TEST(itest_mld_052_group_query) {
  peer_ip6_t ip;
  peer_icmp_t icmp;
  up();
  query(router6_ll, 1, group, 100, 1, 0); /* not joined: its MAC not ours */
  query(router6_ll, 1, sn, 100, 1, 0);
  itest_advance(&t, 200, 10);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(mld_sent(T_V2_REPORT, 0, &ip, &icmp));
  ASSERT_EQ(records(&icmp, REC_MODE_IS_EXCLUDE), 1);
  ASSERT_TRUE(reports(&icmp, sn));
  ipv6_mcast_join(&t.net, group);
  itest_advance(&t, 3000, 100);
  wire_clear(&t);
  query(router6_ll, 1, group, 100, 1, 0);
  itest_advance(&t, 200, 10);
  ASSERT_TRUE(mld_sent(T_V2_REPORT, 0, &ip, &icmp));
  ASSERT_EQ(records(&icmp, REC_MODE_IS_EXCLUDE), 2);
}

/* REQ-IPv6-053: an MLDv1 query (24 octets) puts the interface in MLDv1
 * compatibility mode for 260 s: it answers with one MLDv1 Report per
 * group, sent to the group; a join is reported so, a leave with a Done
 * to all-routers; then it reports in MLDv2 again */
TEST(itest_mld_053_mldv1_querier) {
  peer_ip6_t ip;
  peer_icmp_t icmp;
  uint8_t mac[6];
  up();
  query(router6_ll, 0, NULL, 1000, 1, 0);
  itest_advance(&t, 1000, 10);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(mld_sent(T_V1_REPORT, 0, &ip, &icmp));
  ASSERT_MEM_EQ(ip.dst, sn, 16);
  ASSERT_MEM_EQ(ip.src, ll, 16);
  peer_mcast6_mac(sn, mac);
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, mac, 6);
  ASSERT_EQ(icmp.data_len, 16);
  ASSERT_MEM_EQ(icmp.data, sn, 16);
  ASSERT_EQ(peer_get32(icmp.rest), 0);
  wire_clear(&t);
  ipv6_mcast_join(&t.net, group);
  ASSERT_EQ(wire_count_icmp6(&t, T_V1_REPORT), 2); /* one per group */
  ASSERT_EQ(wire_count_icmp6(&t, T_V2_REPORT), 0);
  itest_advance(&t, 3000, 100);
  wire_clear(&t);
  ipv6_mcast_leave(&t.net, group);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(mld_sent(T_V1_DONE, 0, &ip, &icmp));
  ASSERT_MEM_EQ(ip.dst, all_routers6, 16);
  ASSERT_MEM_EQ(icmp.data, group, 16);
  itest_advance(&t, 255000, 1000); /* 259 s after the query */
  wire_clear(&t);
  ipv6_mcast_join(&t.net, group);
  ASSERT_EQ(wire_count_icmp6(&t, T_V1_REPORT), 2);
  ipv6_mcast_leave(&t.net, group);
  itest_advance(&t, 2000, 1000); /* 261 s */
  wire_clear(&t);
  ipv6_mcast_join(&t.net, group);
  ASSERT_EQ(wire_count_icmp6(&t, T_V1_REPORT), 0);
  ASSERT_TRUE(mld_sent(T_V2_REPORT, 0, &ip, &icmp));
}

/* REQ-IPv6-052: the reports and Dones of other listeners need nothing
 * from a host */
TEST(itest_mld_052_other_listeners_ignored) {
  static uint8_t msg[64], f[160];
  peer_ip6_t ip = peer_ip6(peer6_ll, all_nodes6, 0), inner;
  uint8_t mac[6], type;
  up();
  ip.hop_limit = 1;
  ip.ext = router_alert;
  ip.ext_len = 8;
  inner = ip;
  peer_mcast6_mac(all_nodes6, mac);
  for (type = T_V1_REPORT; type <= T_V1_DONE; type++) {
    uint16_t n = peer_icmp6(msg, &inner, type, 0, NULL, sn, 16);
    itest_receive(&t, f, peer_ipv6_frame(f, mac, peer_mac, &ip, msg, n));
  }
  itest_advance(&t, 3000, 100);
  ASSERT_EQ(t.wire.tx_count, 0);
}

int main(void) {
  fprintf(stderr, "=== itest_mld ===\n");
  RUN_TEST(itest_mld_049_groups_reported_at_start);
  RUN_TEST(itest_mld_054_reported_from_the_link_local_address);
  RUN_TEST(itest_mld_049_join_reported_and_received);
  RUN_TEST(itest_mld_055_leave_reported);
  RUN_TEST(itest_mld_049_solicited_node_group_of_each_address);
  RUN_TEST(itest_mld_052_general_query_answered);
  RUN_TEST(itest_mld_052_maximum_response_code_decoded);
  RUN_TEST(itest_mld_052_pending_answer_stands);
  RUN_TEST(itest_mld_049_duplicate_address_not_reported);
  RUN_TEST(itest_mld_052_queries_validated);
  RUN_TEST(itest_mld_052_group_query);
  RUN_TEST(itest_mld_053_mldv1_querier);
  RUN_TEST(itest_mld_052_other_listeners_ignored);
  ITEST_REPORT();
  return test_failures;
}
