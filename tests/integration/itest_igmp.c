/**
 * @file itest_igmp.c
 * @brief IGMPv2 host, black box: igmp_join()/igmp_leave() and queries on
 *        the wire, the reports and leaves sent (RFC 2236).
 */

#include "igmp.h"
#include "itest.h"
#include <string.h>

#define GROUP 0xE00000FBu /* 224.0.0.251 */
#define ALL_HOSTS 0xE0000001u
#define V1_REPORT 0x12
#define V2_REPORT 0x16

static itest_t t;
static const uint8_t router_mac[6] = {0x02, 0x52, 0x54, 0x52, 0x00, 0x01};
static const uint8_t router_alert[4] = {148, 4, 0, 0};

static void joined(void) {
  itest_up(&t, 1514, 1514);
  igmp_join(&t.net, GROUP);
  wire_clear(&t);
}

/* An IGMP message from @p src to @p dst: type, max resp time, group;
 * @p extra bytes appended (a longer, v3-style message); the checksum
 * broken if @p bad */
static void igmp_message(uint32_t src, uint32_t dst, uint8_t type,
                         uint8_t max_resp, uint32_t group, uint8_t extra,
                         int bad) {
  uint8_t msg[16], f[128], mac[6] = {0x01, 0x00, 0x5E, 0, 0, 0};
  peer_ip_t ip = peer_ip(src, dst, 2);
  uint16_t n = (uint16_t)(8 + extra);
  memset(msg, 0, sizeof(msg));
  msg[0] = type;
  msg[1] = max_resp;
  peer_put32(msg + 4, group);
  peer_put16(msg + 2, peer_cksum(msg, n));
  if (bad)
    msg[2] ^= 0x55;
  ip.ttl = 1;
  ip.options = router_alert;
  ip.options_len = 4;
  mac[3] = (uint8_t)((dst >> 16) & 0x7F);
  mac[4] = (uint8_t)(dst >> 8);
  mac[5] = (uint8_t)dst;
  itest_receive(&t, f,
                peer_ipv4_frame(f, mac,
                                src == 0x0A0000FEu ? router_mac : peer_mac, &ip,
                                msg, n));
}

static void query(uint8_t max_resp, uint32_t group) {
  igmp_message(0x0A0000FEu, group ? group : ALL_HOSTS, 0x11, max_resp, group, 0,
               0);
}

/* The IGMP messages sent so far: how many of @p type for @p group */
static int sent(uint8_t type, uint32_t group) {
  uint16_t i;
  int n = 0;
  peer_ip_t ip;
  for (i = 0; wire_sent(&t, i); i++) {
    if (peer_parse_ipv4(wire_sent(&t, i), &ip) && ip.proto == 2 &&
        ip.payload_len >= 8 && ip.payload[0] == type &&
        peer_get32(ip.payload + 4) == group)
      n++;
  }
  return n;
}

static int igmp_sent(void) {
  uint16_t i;
  int n = 0;
  peer_ip_t ip;
  for (i = 0; wire_sent(&t, i); i++)
    n += peer_parse_ipv4(wire_sent(&t, i), &ip) && ip.proto == 2;
  return n;
}

/* REQ-IGMP-001, 003, 006: joining reports at once: to the group, TTL 1,
 * Router Alert, a correct checksum */
TEST(itest_igmp_001_report_format) {
  peer_ip_t ip;
  itest_up(&t, 1514, 1514);
  ASSERT_EQ(igmp_join(&t.net, GROUP), NET_OK);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip));
  ASSERT_EQ(ip.dst, GROUP);
  ASSERT_EQ(ip.ttl, 1);
  ASSERT_EQ(ip.options_len, 4);
  ASSERT_MEM_EQ(ip.options, router_alert, 4);
  ASSERT_EQ(ip.payload[0], V2_REPORT);
  ASSERT_EQ(peer_get32(ip.payload + 4), GROUP);
  ASSERT_EQ(peer_cksum(ip.payload, ip.payload_len), 0);
}

/* REQ-IGMP-007: Leave Group goes to all-routers */
TEST(itest_igmp_007_leave_to_all_routers) {
  peer_ip_t ip;
  joined();
  ASSERT_EQ(igmp_leave(&t.net, GROUP), NET_OK);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip));
  ASSERT_EQ(ip.dst, IGMP_ALL_ROUTERS);
  ASSERT_EQ(ip.payload[0], IGMP_TYPE_LEAVE);
  ASSERT_EQ(peer_get32(ip.payload + 4), GROUP);
}

/* REQ-IGMP-009, 008: a General Query is answered, for each group, within
 * the Max Response Time (here 1 s) — never for all-hosts */
TEST(itest_igmp_009_general_query_answered) {
  joined();
  query(10, 0);
  ASSERT_EQ(igmp_sent(), 0); /* a random delay first */
  itest_advance(&t, 1000, 10);
  ASSERT_EQ(sent(V2_REPORT, GROUP), 1);
  ASSERT_EQ(sent(V2_REPORT, ALL_HOSTS), 0);
  query(10, GROUP); /* Group-Specific */
  itest_advance(&t, 1000, 10);
  ASSERT_EQ(sent(V2_REPORT, GROUP), 2);
}

/* REQ-IGMP-002, 005: a query with a bad checksum is no query */
TEST(itest_igmp_002_bad_checksum_ignored) {
  joined();
  igmp_message(0x0A0000FEu, ALL_HOSTS, 0x11, 10, 0, 0, 1);
  itest_advance(&t, 2000, 10);
  ASSERT_EQ(igmp_sent(), 0);
  query(10, 0);
  itest_advance(&t, 1000, 10);
  ASSERT_EQ(sent(V2_REPORT, GROUP), 1);
}

/* REQ-IGMP-004: a longer (IGMPv3-style) query is read by its first 8
 * octets */
TEST(itest_igmp_004_longer_query_answered) {
  joined();
  igmp_message(0x0A0000FEu, ALL_HOSTS, 0x11, 10, 0, 4, 0);
  itest_advance(&t, 1000, 10);
  ASSERT_EQ(sent(V2_REPORT, GROUP), 1);
}

/* REQ-IGMP-010: a query with a shorter Max Response Time brings the
 * report forward */
TEST(itest_igmp_010_shorter_query_resets_timer) {
  joined();
  query(100, 0); /* within 10 s */
  query(10, 0);  /* within 1 s */
  itest_advance(&t, 1000, 10);
  ASSERT_EQ(sent(V2_REPORT, GROUP), 1);
}

/* REQ-IGMP-011: another host's report for the group, heard first, stops
 * ours */
TEST(itest_igmp_011_report_suppressed) {
  joined();
  query(100, 0);
  itest_advance(&t, 10000, 10);
  ASSERT_EQ(sent(V2_REPORT, GROUP), 1); /* unsuppressed, it goes */
  wire_clear(&t);
  query(100, 0);
  igmp_message(PEER_IP, GROUP, V1_REPORT, 0, GROUP, 0, 0);
  itest_advance(&t, 10000, 10);
  ASSERT_EQ(igmp_sent(), 0);
}

/* REQ-IGMP-012, 013, 014: an IGMPv1 query (Max Resp 0 = 10 s) is answered
 * with a v1 report; for 400 s every report is v1 and no Leave is sent */
TEST(itest_igmp_012_v1_querier) {
  joined();
  query(0, 0);
  itest_advance(&t, 10000, 10);
  ASSERT_EQ(sent(V1_REPORT, GROUP), 1);
  ASSERT_EQ(sent(V2_REPORT, GROUP), 0);
  wire_clear(&t);
  igmp_leave(&t.net, GROUP);
  ASSERT_EQ(igmp_sent(), 0);
  igmp_join(&t.net, GROUP);
  ASSERT_EQ(sent(V1_REPORT, GROUP), 1);
  itest_advance(&t, 400000, 1000);
  wire_clear(&t);
  igmp_report(&t.net, GROUP);
  ASSERT_EQ(sent(V2_REPORT, GROUP), 1);
}

int main(void) {
  fprintf(stderr, "=== itest_igmp ===\n");
  RUN_TEST(itest_igmp_001_report_format);
  RUN_TEST(itest_igmp_007_leave_to_all_routers);
  RUN_XFAIL(itest_igmp_009_general_query_answered);
  RUN_XFAIL(itest_igmp_002_bad_checksum_ignored);
  RUN_XFAIL(itest_igmp_004_longer_query_answered);
  RUN_XFAIL(itest_igmp_010_shorter_query_resets_timer);
  RUN_XFAIL(itest_igmp_011_report_suppressed);
  RUN_XFAIL(itest_igmp_012_v1_querier);
  ITEST_REPORT();
  return test_failures;
}
