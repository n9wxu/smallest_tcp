/**
 * @file itest_ipv4.c
 * @brief IPv4 and ICMPv4, black box: datagrams on the wire, a UDP port
 *        the test registers, and what the stack sends back.
 */

#include "icmp.h"
#include "itest.h"
#include "udp.h"
#include <string.h>

static itest_t t;
static int delivered;

static void on_datagram(net_t *net, uint32_t src_ip, uint16_t src_port,
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

#define OPEN_PORT 7000
#define CLOSED_PORT 7001

static const udp_port_entry_t ports[] = {{OPEN_PORT, on_datagram}};

static void up(void) {
  ASSERT_EQ(itest_up(&t, 1514, 1514), NET_OK);
  udp_set_ports(&t.net, ports, 1);
  delivered = 0;
}

/* A UDP datagram from @p src to @p dst at our MAC, port @p port */
static void datagram(uint32_t src, uint32_t dst, uint16_t port) {
  uint8_t f[128];
  wire_clear(&t);
  itest_receive(&t, f, peer_udp_frame(f, &t.net, src, dst, 5000, port, "x", 1));
}

/* The ICMP message the stack sent, if exactly one frame went out */
static int sent_icmp(peer_ip_t *ip, peer_icmp_t *icmp) {
  return t.wire.tx_count == 1 && peer_parse_ipv4(wire_sent(&t, 0), ip) &&
         peer_parse_icmp(ip, icmp);
}

/* ── Destination addresses ── */

/* REQ-IPv4-008, 009, 010: ours, the limited broadcast and our subnet's */
TEST(itest_ipv4_008_010_accepts_ours_and_our_broadcasts) {
  up();
  datagram(PEER_IP, t.net.ipv4_addr, OPEN_PORT);
  datagram(PEER_IP, 0xFFFFFFFFu, OPEN_PORT);
  datagram(PEER_IP, (t.net.ipv4_addr & t.net.subnet_mask) | ~t.net.subnet_mask,
           OPEN_PORT);
  ASSERT_EQ(delivered, 3);
}

/* REQ-IPv4-010, 011: another subnet's directed broadcast is not ours */
TEST(itest_ipv4_011_drops_another_subnets_broadcast) {
  up();
  datagram(PEER_IP, 0x0A0001FFu, OPEN_PORT); /* 10.0.1.255 on 10.0.0.0/24 */
  datagram(PEER_IP, 0xC0A807FFu, OPEN_PORT); /* 192.168.7.255 */
  ASSERT_EQ(delivered, 0);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-IPv4-010, 011 (RFC 3021): a /31 or /32 has no directed broadcast */
TEST(itest_ipv4_011_point_to_point_masks_have_no_broadcast) {
  up();
  t.net.subnet_mask = 0xFFFFFFFEu; /* 10.0.0.2/31: 10.0.0.3 is the peer */
  datagram(PEER_IP, 0x0A000003u, OPEN_PORT);
  ASSERT_EQ(delivered, 0);
  datagram(PEER_IP, t.net.ipv4_addr, OPEN_PORT);
  ASSERT_EQ(delivered, 1);

  up();
  t.net.subnet_mask = 0xFFFFFFFFu; /* /32: nothing but us */
  datagram(PEER_IP, 0x08080808u, OPEN_PORT);
  ASSERT_EQ(delivered, 0);
  datagram(PEER_IP, t.net.ipv4_addr, OPEN_PORT);
  ASSERT_EQ(delivered, 1);
}

/* REQ-IPv4-009, 011: before DHCP configures an address (0.0.0.0, mask 0)
 * only the limited broadcast is a broadcast */
TEST(itest_ipv4_011_unconfigured_only_the_limited_broadcast) {
  up();
  t.net.ipv4_addr = 0;
  t.net.subnet_mask = 0;
  datagram(PEER_IP, 0x0A0000FFu, OPEN_PORT);
  ASSERT_EQ(delivered, 0);
  datagram(PEER_IP, 0xFFFFFFFFu, OPEN_PORT);
  ASSERT_EQ(delivered, 1);
}

/* ── Source addresses ── */

/* REQ-IPv4-013, 014, 015: a source that names no single host, loopback, or
 * our own address is dropped */
TEST(itest_ipv4_013_015_drops_invalid_sources) {
  static const uint32_t bad[] = {
      0xFFFFFFFFu, /* limited broadcast */
      0x0A0000FFu, /* our subnet's broadcast */
      0xE00000FBu, /* multicast */
      0xF0000001u, /* class E */
      0x7F000001u, /* loopback */
      0x0A000002u, /* ourselves */
  };
  unsigned i;
  up();
  for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    datagram(bad[i], t.net.ipv4_addr, OPEN_PORT);
    datagram(bad[i], t.net.ipv4_addr, CLOSED_PORT); /* and no ICMP */
    ASSERT_EQ(t.wire.tx_count, 0);
  }
  ASSERT_EQ(delivered, 0);
}

/* REQ-IPv4-016, REQ-DHCPv4: 0.0.0.0 is a DHCP client's source, accepted */
TEST(itest_ipv4_016_accepts_unspecified_source) {
  up();
  datagram(0, 0xFFFFFFFFu, OPEN_PORT);
  ASSERT_EQ(delivered, 1);
}

/* ── ICMP errors ── */

/* REQ-UDP-017, REQ-ICMPv4-018, 038: a closed port draws Port Unreachable
 * quoting the datagram */
TEST(itest_icmpv4_018_port_unreachable_to_a_host) {
  peer_ip_t ip;
  peer_icmp_t icmp;
  up();
  datagram(PEER_IP, t.net.ipv4_addr, CLOSED_PORT);
  ASSERT_TRUE(sent_icmp(&ip, &icmp));
  ASSERT_EQ(ip.dst, PEER_IP);
  ASSERT_EQ(icmp.type, 3);
  ASSERT_EQ(icmp.code, 3);
  ASSERT_TRUE(icmp.cksum_ok);
  ASSERT_EQ(peer_get32(icmp.data + 16), t.net.ipv4_addr); /* quoted dst */
  ASSERT_EQ(peer_get16(icmp.data + 22), CLOSED_PORT);
}

/* REQ-ICMPv4-035, 036: no error about a datagram sent to a broadcast, nor
 * one from 0.0.0.0 */
TEST(itest_icmpv4_035_036_no_error_about_broadcasts_or_unspecified) {
  up();
  datagram(PEER_IP, 0xFFFFFFFFu, CLOSED_PORT);
  ASSERT_EQ(t.wire.tx_count, 0);
  datagram(0, t.net.ipv4_addr, CLOSED_PORT);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-ICMPv4-001, 002, 003, 005: Echo Reply, Code 0, the request's
 * identifier, sequence and data, to its source */
TEST(itest_icmpv4_001_echo_reply_code_zero) {
  static const uint8_t rest[4] = {0x12, 0x34, 0x00, 0x07};
  uint8_t msg[64], f[128];
  peer_ip_t ip = peer_ip(PEER_IP, 0, 1), rip;
  peer_icmp_t icmp;
  uint16_t n;
  up();
  ip.dst = t.net.ipv4_addr;
  n = peer_icmp(msg, 8, 9 /* a non-zero Code */, rest, "ping", 4);
  wire_clear(&t);
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, msg, n));
  ASSERT_TRUE(sent_icmp(&rip, &icmp));
  ASSERT_EQ(rip.dst, PEER_IP);
  ASSERT_EQ(icmp.type, 0);
  ASSERT_EQ(icmp.code, 0);
  ASSERT_TRUE(icmp.cksum_ok);
  ASSERT_MEM_EQ(icmp.rest, rest, 4);
  ASSERT_EQ(icmp.data_len, 4);
  ASSERT_MEM_EQ(icmp.data, "ping", 4);
}

int main(void) {
  fprintf(stderr, "=== itest_ipv4 ===\n");
  RUN_TEST(itest_ipv4_008_010_accepts_ours_and_our_broadcasts);
  RUN_TEST(itest_ipv4_011_drops_another_subnets_broadcast);
  RUN_TEST(itest_ipv4_011_point_to_point_masks_have_no_broadcast);
  RUN_TEST(itest_ipv4_011_unconfigured_only_the_limited_broadcast);
  RUN_TEST(itest_ipv4_013_015_drops_invalid_sources);
  RUN_TEST(itest_ipv4_016_accepts_unspecified_source);
  RUN_TEST(itest_icmpv4_018_port_unreachable_to_a_host);
  RUN_TEST(itest_icmpv4_035_036_no_error_about_broadcasts_or_unspecified);
  RUN_TEST(itest_icmpv4_001_echo_reply_code_zero);
  ITEST_REPORT();
  return test_failures;
}
