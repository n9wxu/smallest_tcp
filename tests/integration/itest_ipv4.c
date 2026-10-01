/**
 * @file itest_ipv4.c
 * @brief IPv4 and ICMPv4, black box: datagrams on the wire, a UDP port
 *        the test registers, and what the stack sends back.
 */

#include "icmp.h"
#include "ipv4.h"
#include "itest.h"
#include "udp.h"
#include <string.h>

static itest_t t;
static int delivered;
static uint8_t got[4096]; /* the last datagram delivered */
static uint16_t got_len;

static void on_datagram(net_t *net, uint32_t src_ip, uint16_t src_port,
                        const uint8_t *src_mac, const uint8_t *data,
                        uint16_t len) {
  (void)net;
  (void)src_ip;
  (void)src_port;
  (void)src_mac;
  delivered++;
  got_len = len < sizeof(got) ? len : (uint16_t)sizeof(got);
  memcpy(got, data, got_len);
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

/* ── More of RFC 1122 §3.2–3.3 (2026-10-01) ── */

/* A UDP datagram to OPEN_PORT carrying @p len bytes, sent as the IPv4
 * header @p ip describes (options, fragment fields), payload bytes
 * [@p from, @p from + @p n) of the UDP segment */
static uint8_t seg[4096];
static uint16_t seg_len;

static void make_datagram(uint16_t len) {
  static uint8_t data[4000];
  peer_ip_t ip = peer_ip(PEER_IP, t.net.ipv4_addr, 17);
  uint16_t i;
  for (i = 0; i < len; i++)
    data[i] = (uint8_t)(i * 7 + 3);
  seg_len = peer_udp(seg, &ip, 5000, OPEN_PORT, data, len);
}

static void fragment(uint16_t from, uint16_t n, int more, uint16_t id) {
  uint8_t f[1600];
  peer_ip_t ip = peer_ip(PEER_IP, t.net.ipv4_addr, 17);
  ip.id = id;
  ip.mf = (uint8_t)more;
  ip.frag_offset = from;
  itest_receive(&t, f,
                peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, seg + from, n));
}

/* REQ-IPv4-059 (RFC 1122 §3.3.6): our network's directed and all-subnets
 * broadcast (10.255.255.255 for 10.0.0.0/24) are broadcasts too — as a
 * destination accepted, as a source (REQ-IPv4-013) not a host */
TEST(itest_ipv4_059_every_broadcast_form) {
  up();
  datagram(PEER_IP, 0x0AFFFFFFu, OPEN_PORT);
  ASSERT_EQ(delivered, 1);
  datagram(0x0AFFFFFFu, t.net.ipv4_addr, OPEN_PORT);
  ASSERT_EQ(delivered, 1);
}

/* REQ-IPv4-059: with a mask shorter than the class's (a supernet, here
 * 192.168.0.0/16), x.y.z.255 is a host, not a classful broadcast */
TEST(itest_ipv4_059_supernet_has_no_classful_broadcast) {
  up();
  t.net.ipv4_addr = 0xC0A80002u;
  t.net.subnet_mask = 0xFFFF0000u;
  datagram(0xC0A800FFu, t.net.ipv4_addr, OPEN_PORT);
  ASSERT_EQ(delivered, 1);
}

/* REQ-IPv4-020, 021, REQ-ICMPv4-017, 046: an unknown protocol draws
 * Protocol Unreachable */
TEST(itest_ipv4_021_unknown_protocol_unreachable) {
  uint8_t f[128];
  peer_ip_t ip = peer_ip(PEER_IP, 0, 253), rip;
  peer_icmp_t icmp;
  up();
  ip.dst = t.net.ipv4_addr;
  wire_clear(&t);
  itest_receive(&t, f,
                peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, "abcdefgh", 8));
  ASSERT_TRUE(sent_icmp(&rip, &icmp));
  ASSERT_EQ(icmp.type, 3);
  ASSERT_EQ(icmp.code, 2);
}

/* REQ-IPv4-024: fragments, out of order and overlapping, reassembled in the
 * application's buffer and delivered whole */
TEST(itest_ipv4_024_reassembly) {
  static uint8_t reasm[IPV4_REASSEMBLY_BUFFER(1500)];
  up();
  ASSERT_EQ(ipv4_set_reassembly(&t.net, reasm, sizeof(reasm)), NET_OK);
  make_datagram(1000); /* 1008 bytes of UDP */
  fragment(512, 496, 0, 77);
  ASSERT_EQ(delivered, 0);
  fragment(256, 512, 1, 77); /* overlaps both */
  ASSERT_EQ(delivered, 0);
  fragment(0, 512, 1, 77);
  ASSERT_EQ(delivered, 1);
  ASSERT_EQ(got_len, 1000);
  ASSERT_MEM_EQ(got, seg + 8, 1000);
  fragment(0, 512, 1, 77); /* a late copy starts nothing that completes */
  ASSERT_EQ(delivered, 1);
}

/* REQ-IPv4-025, 060, REQ-ICMPv4-025: after 60 s an incomplete datagram is
 * discarded; Time Exceeded (code 1) goes to its source if fragment zero
 * arrived, quoting it */
TEST(itest_ipv4_025_reassembly_timeout) {
  static uint8_t reasm[IPV4_REASSEMBLY_BUFFER(1500)];
  peer_ip_t ip;
  peer_icmp_t icmp;
  up();
  ASSERT_EQ(ipv4_set_reassembly(&t.net, reasm, sizeof(reasm)), NET_OK);
  make_datagram(1000);
  fragment(0, 512, 1, 78);
  wire_clear(&t);
  itest_advance(&t, 59000, 1000);
  ASSERT_EQ(t.wire.tx_count, 0);
  itest_advance(&t, 2000, 1000);
  ASSERT_TRUE(sent_icmp(&ip, &icmp));
  ASSERT_EQ(ip.dst, PEER_IP);
  ASSERT_EQ(icmp.type, 11);
  ASSERT_EQ(icmp.code, 1);
  ASSERT_EQ(peer_get16(icmp.data + 4), 78); /* fragment zero's header */
  fragment(512, 496, 0, 78);                /* too late: nothing completes */
  ASSERT_EQ(delivered, 0);

  /* Fragment zero never came: discarded without a word */
  wire_clear(&t);
  fragment(512, 496, 0, 79);
  itest_advance(&t, 61000, 1000);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-IPv4-061: with an RX buffer of 590 bytes a datagram of 576 octets is
 * taken whole (smaller buffers are allowed but do not comply) */
TEST(itest_ipv4_061_576_octet_datagrams) {
  uint8_t f[600];
  static uint8_t data[548];
  ASSERT_EQ(itest_up(&t, 590, 590), NET_OK);
  udp_set_ports(&t.net, ports, 1);
  delivered = 0;
  itest_receive(&t, f,
                peer_udp_frame(f, &t.net, PEER_IP, t.net.ipv4_addr, 5000,
                               OPEN_PORT, data, sizeof(data)));
  ASSERT_EQ(delivered, 1);
  ASSERT_EQ(got_len, 548);
}

/* REQ-IPv4-062: MMS_R is the larger of what a frame and the reassembly
 * buffer hold, less the IP header */
TEST(itest_ipv4_062_mms_r) {
  static uint8_t reasm[IPV4_REASSEMBLY_BUFFER(4000)];
  up();
  ASSERT_EQ(ipv4_mms_r(&t.net), 1480);
  ASSERT_EQ(ipv4_set_reassembly(&t.net, reasm, sizeof(reasm)), NET_OK);
  ASSERT_EQ(ipv4_mms_r(&t.net), 3980);
}

/* REQ-IPv4-063, REQ-UDP-043: MMS_S follows the TX buffer and the MTU, and
 * UDP sends no more */
TEST(itest_ipv4_063_mms_s) {
  static uint8_t data[1500];
  itest_up(&t, 1514, 600);
  ASSERT_EQ(ipv4_mms_s(&t.net), 566);
  ASSERT_EQ(udp_send(&t.net, PEER_IP, peer_mac, 7, 7, data, 558), NET_OK);
  ASSERT_EQ(udp_send(&t.net, PEER_IP, peer_mac, 7, 7, data, 559),
            NET_ERR_BUF_TOO_SMALL);
  itest_up(&t, 1514, 1514);
  ASSERT_EQ(ipv4_mms_s(&t.net), 1480);
}

/* REQ-IPv4-064: the MTU is configurable, and nothing sent exceeds it */
TEST(itest_ipv4_064_mtu_configurable) {
  static uint8_t data[1500];
  itest_up(&t, 1514, 1514);
  ASSERT_EQ(t.net.mtu, 1500);
  t.net.mtu = 576;
  ASSERT_EQ(ipv4_mms_s(&t.net), 556);
  ASSERT_EQ(udp_send(&t.net, PEER_IP, peer_mac, 7, 7, data, 549),
            NET_ERR_BUF_TOO_SMALL);
  ASSERT_EQ(udp_send(&t.net, PEER_IP, peer_mac, 7, 7, data, 548), NET_OK);
  ASSERT_EQ(wire_sent(&t, 0)->len, 14 + 576);
}

/* REQ-IPv4-028, 031, 032, 082, REQ-IPv4-023: what UDP sends has a 20-byte
 * header, no options, the right Total Length, reserved bit 0, DF set */
TEST(itest_ipv4_028_no_options_sent) {
  peer_ip_t ip;
  up();
  udp_send(&t.net, PEER_IP, peer_mac, 7, 7, (const uint8_t *)"abc", 3);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip));
  ASSERT_EQ(ip.ihl_bytes, 20);
  ASSERT_EQ(ip.total_len, 20 + 8 + 3);
  ASSERT_EQ(wire_sent(&t, 0)->data[14 + 6] & 0x80, 0);
  ASSERT_TRUE(ip.df);
  ASSERT_TRUE(ip.header_cksum_ok);
}

/* A UDP datagram for OPEN_PORT with the IP options @p opt (a multiple of 4
 * bytes) */
static void datagram_with_options(const uint8_t *opt, uint8_t n) {
  uint8_t f[128], s2[64];
  peer_ip_t ip = peer_ip(PEER_IP, 0, 17);
  uint16_t len;
  ip.dst = t.net.ipv4_addr;
  ip.options = opt;
  ip.options_len = n;
  len = peer_udp(s2, &ip, 5000, OPEN_PORT, "opts", 4);
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, s2, len));
}

/* REQ-IPv4-026, 027, 066: options are skipped and the payload delivered
 * (options are not passed up: a deviation) */
TEST(itest_ipv4_026_options_skipped) {
  static const uint8_t nop_eol[4] = {1, 1, 1, 0};
  up();
  datagram_with_options(nop_eol, 4);
  ASSERT_EQ(delivered, 1);
  ASSERT_EQ(got_len, 4);
  ASSERT_MEM_EQ(got, "opts", 4);
}

/* REQ-IPv4-067 (deviation): a datagram carrying a Loose or Strict Source
 * Route — even a completed one, wherever it is among the options — is
 * dropped without an answer */
TEST(itest_ipv4_067_source_routed_dropped) {
  /* LSRR, length 7, pointer 8 (route completed), one address, then EOL */
  static const uint8_t lsrr[8] = {131, 7, 8, 10, 0, 0, 1, 0};
  static const uint8_t ssrr[8] = {137, 7, 8, 10, 0, 0, 1, 0};
  static const uint8_t after_nop[8] = {1, 131, 6, 4, 10, 0, 0, 1};
  static const uint8_t after_other[12] = {0x9E, 4,  0, 0, 137, 7,
                                          8,    10, 0, 0, 1,   0};
  static const uint8_t record_route[8] = {7, 7, 4, 0, 0, 0, 0, 0};
  up();
  wire_clear(&t);
  datagram_with_options(lsrr, 8);
  datagram_with_options(ssrr, 8);
  datagram_with_options(after_nop, 8);
  datagram_with_options(after_other, 12);
  ASSERT_EQ(delivered, 0);
  ASSERT_EQ(t.wire.tx_count, 0);
  datagram_with_options(record_route, 8); /* not a source route */
  ASSERT_EQ(delivered, 1);
}

/* REQ-IPv4-068: unknown options and Stream ID are ignored; a malformed
 * option length does not upset the IP layer */
TEST(itest_ipv4_068_unknown_and_malformed_options) {
  static const uint8_t unknown[4] = {0x9E, 4, 0xAB, 0xCD};
  static const uint8_t stream_id[4] = {136, 4, 0x12, 0x34};
  static const uint8_t zero_len[4] = {0x9E, 0, 0, 0};
  static const uint8_t too_long[4] = {0x9E, 40, 0, 0};
  up();
  datagram_with_options(unknown, 4);
  datagram_with_options(stream_id, 4);
  ASSERT_EQ(delivered, 2);
  datagram_with_options(zero_len, 4);
  datagram_with_options(too_long, 4);
  datagram(PEER_IP, t.net.ipv4_addr, OPEN_PORT); /* still alive */
  ASSERT_TRUE(delivered >= 3);
}

/* REQ-IPv4-035: the default TTL is 64 */
TEST(itest_ipv4_035_default_ttl) {
  peer_ip_t ip;
  up();
  udp_send(&t.net, PEER_IP, peer_mac, 7, 7, (const uint8_t *)"x", 1);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip));
  ASSERT_EQ(ip.ttl, 64);
}

/* REQ-IPv4-069: the transport sets the TTL of each datagram */
TEST(itest_ipv4_069_ttl_settable) {
  peer_ip_t ip;
  up();
  memcpy(t.net.tx.buf + UDP_PAYLOAD_OFFSET, "x", 1);
  udp_send_inplace(&t.net, PEER_IP, peer_mac, 7, 7, 1, 17);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip));
  ASSERT_EQ(ip.ttl, 17);
}

/* REQ-IPv4-041, REQ-UDP-044: the transport sets the TOS of each datagram */
TEST(itest_ipv4_041_tos_settable) {
  peer_ip_t ip;
  udp_tx_opts_t o;
  up();
  o.src_ip = t.net.ipv4_addr;
  o.ttl = 64;
  o.tos = 0xB8; /* DSCP EF */
  memcpy(t.net.tx.buf + UDP_PAYLOAD_OFFSET, "x", 1);
  ASSERT_EQ(udp_send_inplace_opts(&t.net, PEER_IP, peer_mac, 7, 7, 1, &o),
            NET_OK);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip));
  ASSERT_EQ(ip.tos, 0xB8);
}

/* REQ-IPv4-083: the Identification of atomic datagrams is ignored: two
 * with the same ID are two datagrams */
TEST(itest_ipv4_083_atomic_id_ignored) {
  up();
  datagram(PEER_IP, t.net.ipv4_addr, OPEN_PORT);
  datagram(PEER_IP, t.net.ipv4_addr, OPEN_PORT);
  ASSERT_EQ(delivered, 2);
}

/* An Echo Request from @p src to @p dst carrying @p len bytes */
static void echo_request(uint32_t src, uint32_t dst, uint16_t len) {
  static uint8_t data[1500], msg[1600], f[1700];
  static const uint8_t rest[4] = {0, 1, 0, 1};
  peer_ip_t ip = peer_ip(src, dst, 1);
  uint16_t n, i;
  for (i = 0; i < len; i++)
    data[i] = (uint8_t)i;
  n = peer_icmp(msg, 8, 0, rest, data, len);
  wire_clear(&t);
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, msg, n));
}

/* REQ-IPv4-070, REQ-ICMPv4-005: nothing is sent to 0.0.0.0, nor from it
 * once an address is configured */
TEST(itest_ipv4_070_never_to_or_from_unspecified) {
  up();
  echo_request(0, t.net.ipv4_addr, 4); /* reply would go to 0.0.0.0 */
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(udp_send(&t.net, 0, peer_mac, 7, 7, (const uint8_t *)"x", 1),
            NET_ERR_INVALID_PARAM);
  t.net.ipv4_addr = 0; /* unconfigured: no reply from 0.0.0.0 */
  echo_request(PEER_IP, 0, 4);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-IPv4-071: nothing is sent to or from 127/8 */
TEST(itest_ipv4_071_never_loopback) {
  up();
  ASSERT_EQ(
      udp_send(&t.net, 0x7F000001u, peer_mac, 7, 7, (const uint8_t *)"x", 1),
      NET_ERR_INVALID_PARAM);
  memcpy(t.net.tx.buf + UDP_PAYLOAD_OFFSET, "x", 1);
  ASSERT_EQ(udp_send_inplace_from(&t.net, 0x7F000001u, PEER_IP, peer_mac, 7, 7,
                                  1, 64),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-IPv4-072: the link-layer broadcast carries only IP broadcasts or
 * multicasts */
TEST(itest_ipv4_072_link_broadcast_needs_ip_broadcast) {
  up();
  ASSERT_EQ(
      udp_send(&t.net, PEER_IP, broadcast_mac, 7, 7, (const uint8_t *)"x", 1),
      NET_ERR_INVALID_PARAM);
  ASSERT_EQ(udp_send(&t.net, 0xFFFFFFFFu, broadcast_mac, 7, 7,
                     (const uint8_t *)"x", 1),
            NET_OK);
}

/* REQ-IPv4-050: a host with a multicast table is in the all-hosts group */
TEST(itest_ipv4_050_all_hosts_group) {
  static const uint8_t all_hosts_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01};
  uint8_t f[128], s2[64];
  peer_ip_t ip = peer_ip(PEER_IP, 0xE0000001u, 17);
  uint16_t n;
  up();
  n = peer_udp(s2, &ip, 5000, OPEN_PORT, "x", 1);
  itest_receive(&t, f, peer_ipv4_frame(f, all_hosts_mac, peer_mac, &ip, s2, n));
  ASSERT_EQ(delivered, 1);
}

/* REQ-IPv4-073 (deviation): what the host multicasts is never delivered
 * back to itself */
TEST(itest_ipv4_073_no_multicast_loopback) {
  static const uint8_t group_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};
  up();
  ASSERT_EQ(ipv4_mcast_join(&t.net, 0xE00000FBu), NET_OK);
  udp_send(&t.net, 0xE00000FBu, group_mac, OPEN_PORT, OPEN_PORT,
           (const uint8_t *)"x", 1);
  itest_poll(&t);
  ASSERT_EQ(delivered, 0);
}

/* REQ-IPv4-079: the gateway is never pinged to check it */
TEST(itest_ipv4_079_never_pings_the_gateway) {
  up();
  t.net.gateway_ipv4 = 0x0A0000FEu;
  itest_advance(&t, 3600000u, 1000);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-ICMPv4-008: an echo too big for the TX buffer is answered, truncated
 * to what fits (RFC 1122 §3.2.2.6) */
TEST(itest_icmpv4_008_large_echo_truncated) {
  peer_ip_t ip;
  peer_icmp_t icmp;
  itest_up(&t, 1514, 300);
  echo_request(PEER_IP, t.net.ipv4_addr, 1000);
  ASSERT_TRUE(sent_icmp(&ip, &icmp));
  ASSERT_EQ(icmp.type, 0);
  ASSERT_TRUE(icmp.cksum_ok);
  ASSERT_EQ(wire_sent(&t, 0)->len, 300);
  ASSERT_EQ(icmp.data[0], 0);
  ASSERT_EQ(icmp.data[100], 100);
}

/* REQ-ICMPv4-019..022 (deviation): Redirects are ignored and answered with
 * nothing */
TEST(itest_icmpv4_019_redirect_ignored) {
  static const uint8_t gw[6] = {0x02, 0x47, 0x57, 0x00, 0x00, 0x01};
  uint8_t msg[64], f[128], quoted[28];
  uint8_t rest[4];
  peer_ip_t ip = peer_ip(0x0A0000FEu, 0, 1);
  uint16_t n;
  up();
  t.net.gateway_ipv4 = 0x0A0000FEu;
  memcpy(t.net.gateway_mac, gw, 6);
  t.net.gateway_mac_valid = 1;
  ip.dst = t.net.ipv4_addr;
  peer_put32(rest, PEER2_IP); /* the "better" gateway */
  memset(quoted, 0, sizeof(quoted));
  n = peer_icmp(msg, 5, 1, rest, quoted, sizeof(quoted));
  wire_clear(&t);
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, gw, &ip, msg, n));
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(t.net.gateway_ipv4, 0x0A0000FEu);
  ASSERT_MEM_EQ(t.net.gateway_mac, gw, 6);
}

/* REQ-ICMPv4-038, 043, 047: an error quotes the datagram's header and
 * first 8 data bytes unchanged; its unused field is zero */
TEST(itest_icmpv4_043_quote_unchanged) {
  uint8_t f[128];
  peer_ip_t ip, rip;
  peer_icmp_t icmp;
  uint16_t n;
  up();
  n = peer_udp_frame(f, &t.net, PEER_IP, t.net.ipv4_addr, 5000, CLOSED_PORT,
                     "0123456789", 10);
  wire_clear(&t);
  itest_receive(&t, f, n);
  ASSERT_TRUE(sent_icmp(&rip, &icmp));
  ASSERT_EQ(peer_get32(icmp.rest), 0u);
  ASSERT_EQ(icmp.data_len, 28);
  ASSERT_MEM_EQ(icmp.data, f + 14, 28);
  (void)ip;
}

/* REQ-ICMPv4-045: Address Mask Requests get no reply; replies are ignored */
TEST(itest_icmpv4_045_address_mask_ignored) {
  uint8_t msg[16], f[64];
  static const uint8_t mask[4] = {255, 255, 0, 0};
  peer_ip_t ip = peer_ip(PEER_IP, 0, 1);
  uint16_t n;
  up();
  ip.dst = t.net.ipv4_addr;
  n = peer_icmp(msg, 17, 0, NULL, mask, 4);
  wire_clear(&t);
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, msg, n));
  n = peer_icmp(msg, 18, 0, NULL, mask, 4);
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, msg, n));
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(t.net.subnet_mask, 0xFFFFFF00u);
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
  RUN_TEST(itest_ipv4_059_every_broadcast_form);
  RUN_TEST(itest_ipv4_059_supernet_has_no_classful_broadcast);
  RUN_TEST(itest_ipv4_021_unknown_protocol_unreachable);
  RUN_XFAIL(itest_ipv4_024_reassembly);
  RUN_XFAIL(itest_ipv4_025_reassembly_timeout);
  RUN_TEST(itest_ipv4_061_576_octet_datagrams);
  RUN_XFAIL(itest_ipv4_062_mms_r);
  RUN_XFAIL(itest_ipv4_063_mms_s);
  RUN_XFAIL(itest_ipv4_064_mtu_configurable);
  RUN_TEST(itest_ipv4_028_no_options_sent);
  RUN_TEST(itest_ipv4_026_options_skipped);
  RUN_TEST(itest_ipv4_067_source_routed_dropped);
  RUN_TEST(itest_ipv4_068_unknown_and_malformed_options);
  RUN_TEST(itest_ipv4_035_default_ttl);
  RUN_TEST(itest_ipv4_069_ttl_settable);
  RUN_XFAIL(itest_ipv4_041_tos_settable);
  RUN_TEST(itest_ipv4_083_atomic_id_ignored);
  RUN_TEST(itest_ipv4_070_never_to_or_from_unspecified);
  RUN_TEST(itest_ipv4_071_never_loopback);
  RUN_TEST(itest_ipv4_072_link_broadcast_needs_ip_broadcast);
  RUN_XFAIL(itest_ipv4_050_all_hosts_group);
  RUN_TEST(itest_ipv4_073_no_multicast_loopback);
  RUN_TEST(itest_ipv4_079_never_pings_the_gateway);
  RUN_XFAIL(itest_icmpv4_008_large_echo_truncated);
  RUN_TEST(itest_icmpv4_019_redirect_ignored);
  RUN_TEST(itest_icmpv4_043_quote_unchanged);
  RUN_TEST(itest_icmpv4_045_address_mask_ignored);
  ITEST_REPORT();
  return test_failures;
}
