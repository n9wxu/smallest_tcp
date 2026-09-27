/**
 * @file test_mcast.c
 * @brief Unit tests for IPv4 multicast receive, TTL control and IGMP.
 *
 * Tests REQ-MDNS-002 (join 224.0.0.251), REQ-MDNS-006 (IP TTL 255 on mDNS),
 * RFC 1122 §3.2.2 / REQ-UDP-031 (no ICMP errors for multicast datagrams),
 * REQ-ICMPv4-009 (no echo reply to multicast pings) and RFC 2236 IGMPv2
 * join/leave messages.
 */

#include "eth.h"
#include "icmp.h"
#include "igmp.h"
#include "ipv4.h"
#include "net.h"
#include "net_cksum.h"
#include "net_endian.h"
#include "test_main.h"
#include "udp.h"
#include <string.h>

#define MDNS_GROUP 0xE00000FBu  /* 224.0.0.251 */
#define OTHER_GROUP 0xEF800001u /* 239.128.0.1 */

/* The UDP checksum as sent: a computed 0 goes out as 0xFFFF */
static uint16_t udp_cksum(uint32_t src, uint32_t dst, const uint8_t *udp,
                          uint16_t len) {
  uint16_t c = ipv4_cksum(src, dst, IPV4_PROTO_UDP, udp, len);
  return c ? c : 0xFFFF;
}

/* ── Stub MAC driver ──────────────────────────────────────────────── */

static uint8_t sent_frame[1514];
static uint16_t sent_len;
static int send_count;

static uint8_t rx_frame[1514];
static uint16_t rx_len;

static int stub_init(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_send(void *ctx, const uint8_t *f, uint16_t l) {
  (void)ctx;
  memcpy(sent_frame, f, l);
  sent_len = l;
  send_count++;
  return l;
}
static int stub_poll(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_peek(void *ctx, uint16_t off, uint8_t *buf, uint16_t n) {
  (void)ctx;
  if (off >= rx_len)
    return -1;
  if ((uint16_t)(off + n) > rx_len)
    n = (uint16_t)(rx_len - off);
  memcpy(buf, rx_frame + off, n);
  return n;
}
static void stub_discard(void *ctx) { (void)ctx; }
static void stub_close(void *ctx) { (void)ctx; }

static const net_mac_t stub_mac = {
    .init = stub_init,
    .send = stub_send,
    .poll = stub_poll,
    .peek = stub_peek,
    .discard = stub_discard,
    .close = stub_close,
};

static uint8_t rx_buf[1514], tx_buf[1514];
static net_t net;
static const uint8_t peer_mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
#define PEER_IP 0x0A000064u /* 10.0.0.100 */

/* ── UDP handler on 5353 ──────────────────────────────────────────── */

static int handler_called;
static uint8_t handler_data[64];
static uint16_t handler_len;

static void mdns_handler(net_t *n, uint32_t src_ip, uint16_t src_port,
                         const uint8_t *src_mac, const uint8_t *payload,
                         uint16_t payload_len) {
  (void)n;
  (void)src_ip;
  (void)src_port;
  (void)src_mac;
  handler_called = 1;
  handler_len = payload_len;
  if (payload_len <= sizeof(handler_data))
    memcpy(handler_data, payload, payload_len);
}

static const udp_port_entry_t ports[] = {{5353, mdns_handler}};

static void setup(void) {
  static int ctx;
  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf), NULL,
           &stub_mac, &ctx);
  udp_set_ports(&net, ports, 1);
  send_count = 0;
  sent_len = 0;
  handler_called = 0;
  handler_len = 0;
}

/* ── Frame builders ───────────────────────────────────────────────── */

/* Ethernet + IPv4 header with @p proto and @p payload, returns length. */
static uint16_t build_ip_frame(const uint8_t *dst_mac, uint32_t dst_ip,
                               uint8_t proto, const uint8_t *payload,
                               uint16_t plen) {
  memcpy(rx_frame, dst_mac, 6);
  memcpy(rx_frame + 6, peer_mac, 6);
  net_write16be(rx_frame + 12, NET_ETHERTYPE_IPV4);
  memcpy(rx_frame + 34, payload, plen);
  ipv4_build(rx_frame + 14, plen, proto, PEER_IP, dst_ip);
  rx_len = (uint16_t)(34 + plen);
  return rx_len;
}

static uint16_t build_udp_frame(const uint8_t *dst_mac, uint32_t dst_ip,
                                uint16_t dst_port, const uint8_t *data,
                                uint16_t dlen) {
  uint8_t udp[128];
  uint16_t ulen = (uint16_t)(8 + dlen);
  net_write16be(udp, 5353);
  net_write16be(udp + 2, dst_port);
  net_write16be(udp + 4, ulen);
  net_write16be(udp + 6, 0);
  memcpy(udp + 8, data, dlen);
  net_write16be(udp + 6, udp_cksum(PEER_IP, dst_ip, udp, ulen));
  return build_ip_frame(dst_mac, dst_ip, IPV4_PROTO_UDP, udp, ulen);
}

static void deliver(void) { eth_input(&net, rx_frame, rx_len); }

static const uint8_t mdns_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};

/* ── Address helpers ──────────────────────────────────────────────── */

TEST(test_ipv4_is_multicast) {
  ASSERT_TRUE(ipv4_is_multicast(0xE00000FBu));
  ASSERT_TRUE(ipv4_is_multicast(0xEFFFFFFFu));
  ASSERT_FALSE(ipv4_is_multicast(0xDFFFFFFFu));
  ASSERT_FALSE(ipv4_is_multicast(0xF0000000u));
  ASSERT_FALSE(ipv4_is_multicast(0x0A000002u));
}

TEST(test_mcast_mac_mapping) {
  uint8_t mac[6];
  static const uint8_t expect1[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};
  static const uint8_t expect2[6] = {0x01, 0x00, 0x5E, 0x01, 0x02, 0x03};
  ipv4_mcast_mac(MDNS_GROUP, mac);
  ASSERT_MEM_EQ(mac, expect1, 6);
  ipv4_mcast_mac(0xEF810203u, mac); /* 239.129.2.3: top bit of .129 dropped */
  ASSERT_MEM_EQ(mac, expect2, 6);
}

/* ── Membership table ─────────────────────────────────────────────── */

TEST(test_join_leave_membership) {
  setup();
  ASSERT_FALSE(ipv4_mcast_is_member(&net, MDNS_GROUP));
  ASSERT_EQ(ipv4_mcast_join(&net, MDNS_GROUP), NET_OK);
  ASSERT_TRUE(ipv4_mcast_is_member(&net, MDNS_GROUP));
  ASSERT_TRUE(ipv4_mcast_mac_accepted(&net, mdns_mac));
  ASSERT_EQ(ipv4_mcast_join(&net, MDNS_GROUP), NET_OK); /* idempotent */
  ipv4_mcast_leave(&net, MDNS_GROUP);
  ASSERT_FALSE(ipv4_mcast_is_member(&net, MDNS_GROUP));
  ASSERT_FALSE(ipv4_mcast_mac_accepted(&net, mdns_mac));
  ASSERT_EQ(send_count, 0); /* purely local — no IGMP */
}

TEST(test_join_rejects_unicast) {
  setup();
  ASSERT_EQ(ipv4_mcast_join(&net, 0x0A000001u), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(ipv4_mcast_join(&net, 0), NET_ERR_INVALID_PARAM);
}

TEST(test_join_table_full) {
  setup();
  ASSERT_EQ(NET_MAX_MCAST_GROUPS, 1);
  ASSERT_EQ(ipv4_mcast_join(&net, MDNS_GROUP), NET_OK);
  ASSERT_EQ(ipv4_mcast_join(&net, OTHER_GROUP), NET_ERR_BUF_TOO_SMALL);
  ipv4_mcast_leave(&net, MDNS_GROUP);
  ASSERT_EQ(ipv4_mcast_join(&net, OTHER_GROUP), NET_OK); /* slot reused */
}

/* ── Receive path (REQ-MDNS-002) ──────────────────────────────────── */

TEST(test_unjoined_group_dropped) {
  static const uint8_t data[] = "hello";
  setup();
  build_udp_frame(mdns_mac, MDNS_GROUP, 5353, data, 5);
  deliver();
  ASSERT_EQ(handler_called, 0);
  ASSERT_EQ(send_count, 0);
}

TEST(test_joined_group_delivered) {
  static const uint8_t data[] = "hello";
  setup();
  ASSERT_EQ(ipv4_mcast_join(&net, MDNS_GROUP), NET_OK);
  build_udp_frame(mdns_mac, MDNS_GROUP, 5353, data, 5);
  deliver();
  ASSERT_EQ(handler_called, 1);
  ASSERT_EQ(handler_len, 5);
  ASSERT_MEM_EQ(handler_data, "hello", 5);
}

TEST(test_other_group_mac_dropped) {
  static const uint8_t data[] = "hello";
  static const uint8_t other_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFC};
  setup();
  ASSERT_EQ(ipv4_mcast_join(&net, MDNS_GROUP), NET_OK);
  build_udp_frame(other_mac, 0xE00000FCu, 5353, data, 5);
  deliver();
  ASSERT_EQ(handler_called, 0);
}

/* 239.128.0.251 maps to the same MAC as 224.0.0.251 but is not joined */
TEST(test_aliased_mac_wrong_group_dropped) {
  static const uint8_t data[] = "hello";
  setup();
  ASSERT_EQ(ipv4_mcast_join(&net, MDNS_GROUP), NET_OK);
  build_udp_frame(mdns_mac, 0xEF8000FBu, 5353, data, 5);
  deliver();
  ASSERT_EQ(handler_called, 0);
}

/* ── No ICMP errors or echo replies for multicast ─────────────────── */

TEST(test_no_port_unreachable_for_multicast) {
  static const uint8_t data[] = "hello";
  setup();
  ASSERT_EQ(ipv4_mcast_join(&net, MDNS_GROUP), NET_OK);
  build_udp_frame(mdns_mac, MDNS_GROUP, 9999, data, 5);
  deliver();
  ASSERT_EQ(send_count, 0);
}

/* Other hosts' IGMP reports are sent to the group address itself */
TEST(test_no_proto_unreachable_for_multicast) {
  uint8_t igmp[8] = {IGMP_TYPE_V2_REPORT, 0, 0, 0, 0xE0, 0x00, 0x00, 0xFB};
  setup();
  ASSERT_EQ(ipv4_mcast_join(&net, MDNS_GROUP), NET_OK);
  net_write16be(igmp + 2, net_cksum(igmp, sizeof(igmp)));
  build_ip_frame(mdns_mac, MDNS_GROUP, 2, igmp, sizeof(igmp));
  deliver();
  ASSERT_EQ(send_count, 0);
}

TEST(test_no_echo_reply_to_multicast_ping) {
  uint8_t echo[12] = {8, 0, 0, 0, 0x12, 0x34, 0, 1, 'p', 'i', 'n', 'g'};
  setup();
  ASSERT_EQ(ipv4_mcast_join(&net, MDNS_GROUP), NET_OK);
  net_write16be(echo + 2, net_cksum(echo, sizeof(echo)));
  build_ip_frame(mdns_mac, MDNS_GROUP, IPV4_PROTO_ICMP, echo, sizeof(echo));
  deliver();
  ASSERT_EQ(send_count, 0);
}

/* ── TTL control + in-place send (REQ-MDNS-006) ───────────────────── */

TEST(test_udp_send_inplace_ttl_255) {
  setup();
  memcpy(net.tx.buf + UDP_PAYLOAD_OFFSET, "mdns!", 5);
  ASSERT_EQ(udp_send_inplace(&net, MDNS_GROUP, mdns_mac, 5353, 5353, 5, 255),
            NET_OK);
  ASSERT_EQ(send_count, 1);
  ASSERT_EQ(sent_len, UDP_PAYLOAD_OFFSET + 5);
  ASSERT_MEM_EQ(sent_frame, mdns_mac, 6);
  const uint8_t *ip = sent_frame + 14;
  ASSERT_EQ(ip[IPV4_OFF_TTL], 255);
  ASSERT_EQ(ip[IPV4_OFF_PROTO], IPV4_PROTO_UDP);
  ASSERT_EQ(net_read32be(ip + IPV4_OFF_DST), MDNS_GROUP);
  ASSERT_EQ(net_read32be(ip + IPV4_OFF_SRC), net.ipv4_addr);
  ASSERT_TRUE(net_cksum_verify(ip, IPV4_HDR_SIZE));
  const uint8_t *udp = ip + IPV4_HDR_SIZE;
  ASSERT_EQ(net_read16be(udp), 5353);
  ASSERT_EQ(net_read16be(udp + 2), 5353);
  ASSERT_EQ(net_read16be(udp + 4), 13);
  ASSERT_MEM_EQ(udp + 8, "mdns!", 5);
  /* checksum over pseudo-header verifies to zero */
  uint16_t stored = net_read16be(udp + 6);
  uint8_t copy[13];
  memcpy(copy, udp, 13);
  net_write16be(copy + 6, 0);
  ASSERT_EQ(udp_cksum(net.ipv4_addr, MDNS_GROUP, copy, 13), stored);
}

TEST(test_udp_send_inplace_too_big) {
  setup();
  ASSERT_EQ(udp_send_inplace(
                &net, MDNS_GROUP, mdns_mac, 5353, 5353,
                (uint16_t)(sizeof(tx_buf) - UDP_PAYLOAD_OFFSET + 1), 255),
            NET_ERR_BUF_TOO_SMALL);
  ASSERT_EQ(send_count, 0);
}

TEST(test_udp_send_default_ttl_unchanged) {
  setup();
  ASSERT_EQ(udp_send(&net, PEER_IP, peer_mac, 7, 7, (const uint8_t *)"x", 1),
            NET_OK);
  ASSERT_EQ(sent_frame[14 + IPV4_OFF_TTL], NET_DEFAULT_TTL);
}

/* ── IGMPv2 (RFC 2236) ────────────────────────────────────────────── */

static void check_igmp_frame(uint8_t type, uint32_t dst_ip, uint32_t group) {
  uint8_t mac[6];
  ipv4_mcast_mac(dst_ip, mac);
  ASSERT_EQ(sent_len, IGMP_FRAME_SIZE);
  ASSERT_MEM_EQ(sent_frame, mac, 6);
  ASSERT_MEM_EQ(sent_frame + 6, net.mac, 6);
  ASSERT_EQ(net_read16be(sent_frame + 12), NET_ETHERTYPE_IPV4);
  const uint8_t *ip = sent_frame + 14;
  ASSERT_EQ(ip[0], 0x46); /* IHL 6: Router Alert */
  ASSERT_EQ(net_read16be(ip + IPV4_OFF_TOTLEN), 32);
  ASSERT_EQ(ip[IPV4_OFF_TTL], 1); /* RFC 2236 §2 */
  ASSERT_EQ(ip[IPV4_OFF_PROTO], 2);
  ASSERT_EQ(net_read32be(ip + IPV4_OFF_SRC), net.ipv4_addr);
  ASSERT_EQ(net_read32be(ip + IPV4_OFF_DST), dst_ip);
  ASSERT_EQ(ip[20], 0x94); /* Router Alert option */
  ASSERT_EQ(ip[21], 0x04);
  ASSERT_EQ(ip[22], 0x00);
  ASSERT_EQ(ip[23], 0x00);
  ASSERT_TRUE(net_cksum_verify(ip, 24));
  const uint8_t *igmp = ip + 24;
  ASSERT_EQ(igmp[0], type);
  ASSERT_EQ(igmp[1], 0);
  ASSERT_EQ(net_read32be(igmp + 4), group);
  ASSERT_TRUE(net_cksum_verify(igmp, 8));
}

TEST(test_igmp_join_sends_report) {
  setup();
  ASSERT_EQ(igmp_join(&net, MDNS_GROUP), NET_OK);
  ASSERT_TRUE(ipv4_mcast_is_member(&net, MDNS_GROUP));
  ASSERT_EQ(send_count, 1);
  check_igmp_frame(IGMP_TYPE_V2_REPORT, MDNS_GROUP, MDNS_GROUP);
}

TEST(test_igmp_report_resend) {
  setup();
  ASSERT_EQ(igmp_join(&net, MDNS_GROUP), NET_OK);
  ASSERT_EQ(igmp_report(&net, MDNS_GROUP), NET_OK);
  ASSERT_EQ(send_count, 2);
  check_igmp_frame(IGMP_TYPE_V2_REPORT, MDNS_GROUP, MDNS_GROUP);
}

TEST(test_igmp_leave_sends_leave) {
  setup();
  ASSERT_EQ(igmp_join(&net, MDNS_GROUP), NET_OK);
  ASSERT_EQ(igmp_leave(&net, MDNS_GROUP), NET_OK);
  ASSERT_FALSE(ipv4_mcast_is_member(&net, MDNS_GROUP));
  ASSERT_EQ(send_count, 2);
  check_igmp_frame(IGMP_TYPE_LEAVE, IGMP_ALL_ROUTERS, MDNS_GROUP);
}

TEST(test_igmp_join_non_multicast_fails) {
  setup();
  ASSERT_EQ(igmp_join(&net, 0x0A000001u), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(send_count, 0);
}

int main(void) {
  RUN_TEST(test_ipv4_is_multicast);
  RUN_TEST(test_mcast_mac_mapping);
  RUN_TEST(test_join_leave_membership);
  RUN_TEST(test_join_rejects_unicast);
  RUN_TEST(test_join_table_full);
  RUN_TEST(test_unjoined_group_dropped);
  RUN_TEST(test_joined_group_delivered);
  RUN_TEST(test_other_group_mac_dropped);
  RUN_TEST(test_aliased_mac_wrong_group_dropped);
  RUN_TEST(test_no_port_unreachable_for_multicast);
  RUN_TEST(test_no_proto_unreachable_for_multicast);
  RUN_TEST(test_no_echo_reply_to_multicast_ping);
  RUN_TEST(test_udp_send_inplace_ttl_255);
  RUN_TEST(test_udp_send_inplace_too_big);
  RUN_TEST(test_udp_send_default_ttl_unchanged);
  RUN_TEST(test_igmp_join_sends_report);
  RUN_TEST(test_igmp_report_resend);
  RUN_TEST(test_igmp_leave_sends_leave);
  RUN_TEST(test_igmp_join_non_multicast_fails);
  TEST_REPORT();
  return test_failures;
}
