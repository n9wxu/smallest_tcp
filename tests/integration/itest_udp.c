/**
 * @file itest_udp.c
 * @brief UDP, black box: datagrams checked and dispatched to the port
 *        table, datagrams sent, what a handler learns, what a sender may
 *        choose, and the ICMP errors reported back; over IPv6, the
 *        checksum.
 */

#include "arp.h"
#include "itest.h"
#include "udp.h"
#include <string.h>
#if NET_USE_IPV6
#include "ipv6.h"
#endif

#define OPEN_PORT 7000
#define OTHER_PORT 7001
#define CLOSED_PORT 7999
#define APP_PORT 5000
#define PEER_PORT 6000

static itest_t t;
static int delivered, delivered_other;
static uint32_t seen_dst, seen_src;
static uint16_t seen_sport, seen_len;
static uint8_t seen_data[1500];
static const uint8_t *seen_ptr;
static int errors;
static uint16_t err_port, err_dst_port, err_mtu;
static uint32_t err_dst;
static uint8_t err_type, err_code;

static void on_datagram(net_t *net, uint32_t src_ip, uint16_t src_port,
                        const uint8_t *src_mac, const uint8_t *data,
                        uint16_t len) {
  (void)src_mac;
  delivered++;
  seen_dst = udp_rx_dst_ip(net);
  seen_src = src_ip;
  seen_sport = src_port;
  seen_len = len;
  seen_ptr = data;
  memcpy(seen_data, data, len < sizeof(seen_data) ? len : sizeof(seen_data));
}

static void on_other(net_t *net, uint32_t src_ip, uint16_t src_port,
                     const uint8_t *src_mac, const uint8_t *data,
                     uint16_t len) {
  (void)net;
  (void)src_ip;
  (void)src_port;
  (void)src_mac;
  (void)data;
  (void)len;
  delivered_other++;
}

static uint8_t err_quote[64];
static uint16_t err_quote_len;

static void on_error(net_t *net, const udp_icmp_error_t *e) {
  (void)net;
  errors++;
  err_port = e->local_port;
  err_dst = e->dst_ip;
  err_dst_port = e->dst_port;
  err_type = e->type;
  err_code = e->code;
  err_mtu = e->mtu;
  err_quote_len = e->quote_len;
  memcpy(err_quote, e->quote,
         e->quote_len < sizeof(err_quote) ? e->quote_len : sizeof(err_quote));
}

static const udp_port_entry_t ports[] = {{OPEN_PORT, on_datagram},
                                         {OTHER_PORT, on_other}};

static void up(void) {
  itest_up(&t, 1514, 1514);
  udp_set_ports(&t.net, ports, 2);
  udp_set_error_handler(&t.net, on_error);
  delivered = delivered_other = errors = 0;
  seen_dst = seen_src = 0;
  seen_sport = seen_len = 0;
  seen_ptr = NULL;
}

/* ── The peer's datagrams, malformed on purpose ── */

/* The checksum of @p len bytes of UDP from @p src to @p dst, with the
 * IPv4 pseudo-header carrying @p pseudo_len, by the peer's arithmetic */
static uint16_t udp_cksum4(uint32_t src, uint32_t dst, uint16_t pseudo_len,
                           const uint8_t *udp, uint16_t len) {
  static uint8_t buf[12 + WIRE_FRAME_MAX];
  peer_put32(buf, src);
  peer_put32(buf + 4, dst);
  buf[8] = 0;
  buf[9] = 17;
  peer_put16(buf + 10, pseudo_len);
  memcpy(buf + 12, udp, len);
  return peer_cksum(buf, (uint16_t)(12u + len));
}

/* A UDP datagram from the peer to our @p dport, whose IPv4 payload is
 * @p ip_len bytes (header and data, padded with zeros), with Length field
 * @p udp_len and checksum @p cksum; delivered */
static void raw_datagram(uint16_t dport, const void *data, uint16_t data_len,
                         uint16_t udp_len, uint16_t ip_len, uint16_t cksum) {
  static uint8_t seg[WIRE_FRAME_MAX], f[WIRE_FRAME_MAX];
  peer_ip_t ip = peer_ip(PEER_IP, t.net.ipv4_addr, 17);
  memset(seg, 0, ip_len);
  peer_put16(seg, PEER_PORT);
  peer_put16(seg + 2, dport);
  peer_put16(seg + 4, udp_len);
  peer_put16(seg + 6, cksum);
  memcpy(seg + 8, data, data_len);
  itest_receive(&t, f,
                peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, seg, ip_len));
}

/* The checksum the peer would send for @p data to @p dport */
static uint16_t good_cksum(uint16_t dport, const void *data, uint16_t len) {
  uint8_t seg[64];
  uint16_t ck;
  peer_put16(seg, PEER_PORT);
  peer_put16(seg + 2, dport);
  peer_put16(seg + 4, (uint16_t)(8u + len));
  peer_put16(seg + 6, 0);
  memcpy(seg + 8, data, len);
  ck = udp_cksum4(PEER_IP, t.net.ipv4_addr, (uint16_t)(8u + len), seg,
                  (uint16_t)(8u + len));
  return ck ? ck : 0xFFFF;
}

/* ── Reception ── */

/* REQ-UDP-001, 016, 018, 019, 020, 035, 037: each datagram reaches the
 * handler its destination port has in the application's table, with the
 * source address and port; the payload is read in place, in the frame
 * buffer the application gave net_init() */
TEST(itest_udp_016_dispatched_by_destination_port) {
  uint8_t f[128];
  up();
  itest_receive(&t, f,
                peer_udp_frame(f, &t.net, PEER2_IP, t.net.ipv4_addr, 4242,
                               OPEN_PORT, "hello", 5));
  ASSERT_EQ(delivered, 1);
  ASSERT_EQ(delivered_other, 0);
  ASSERT_EQ(seen_src, PEER2_IP);
  ASSERT_EQ(seen_sport, 4242);
  ASSERT_EQ(seen_len, 5);
  ASSERT_MEM_EQ(seen_data, "hello", 5);
  ASSERT_TRUE(seen_ptr >= t.rx_buf && seen_ptr + 5 <= t.rx_buf + 1514);
  itest_receive(&t, f,
                peer_udp_frame(f, &t.net, PEER_IP, t.net.ipv4_addr, PEER_PORT,
                               OTHER_PORT, "x", 1));
  ASSERT_EQ(delivered, 1);
  ASSERT_EQ(delivered_other, 1);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-UDP-002, 005: a Length below 8 is dropped silently — no handler,
 * no ICMP */
TEST(itest_udp_002_length_below_header_dropped) {
  up();
  raw_datagram(OPEN_PORT, "abcd", 4, 7, 12, 0);
  raw_datagram(CLOSED_PORT, "abcd", 4, 7, 12, 0);
  ASSERT_EQ(delivered, 0);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-UDP-003, 005: a Length beyond the IP payload is dropped silently */
TEST(itest_udp_003_length_beyond_ip_payload_dropped) {
  up();
  raw_datagram(OPEN_PORT, "abcd", 4, 13, 12, 0);
  raw_datagram(CLOSED_PORT, "abcd", 4, 13, 12, 0);
  ASSERT_EQ(delivered, 0);
  ASSERT_EQ(t.wire.tx_count, 0);
  raw_datagram(OPEN_PORT, "abcd", 4, 12, 12, 0); /* the same, consistent */
  ASSERT_EQ(delivered, 1);
}

/* REQ-UDP-004: the Length field, not the IP payload, says where the data
 * ends: bytes after it are not delivered */
TEST(itest_udp_004_length_field_bounds_the_data) {
  up();
  raw_datagram(OPEN_PORT, "abcdef", 6, 11, 14, good_cksum(OPEN_PORT, "abc", 3));
  ASSERT_EQ(delivered, 1);
  ASSERT_EQ(seen_len, 3);
  ASSERT_MEM_EQ(seen_data, "abc", 3);
}

/* REQ-UDP-006, 007: a non-zero checksum is verified; a datagram that
 * fails is dropped silently, even to a closed port */
TEST(itest_udp_006_bad_checksum_dropped) {
  uint16_t ck;
  up();
  ck = good_cksum(OPEN_PORT, "abcd", 4);
  raw_datagram(OPEN_PORT, "abcd", 4, 12, 12, (uint16_t)(ck ^ 0x0100));
  ck = good_cksum(CLOSED_PORT, "abcd", 4);
  raw_datagram(CLOSED_PORT, "abcd", 4, 12, 12, (uint16_t)(ck ^ 0x0100));
  ASSERT_EQ(delivered, 0);
  ASSERT_EQ(t.wire.tx_count, 0);
  raw_datagram(OPEN_PORT, "abcd", 4, 12, 12, good_cksum(OPEN_PORT, "abcd", 4));
  ASSERT_EQ(delivered, 1);
}

/* REQ-UDP-008: a checksum of 0 over IPv4 means none: accepted */
TEST(itest_udp_008_zero_checksum_accepted) {
  up();
  raw_datagram(OPEN_PORT, "abcd", 4, 12, 12, 0);
  ASSERT_EQ(delivered, 1);
  ASSERT_MEM_EQ(seen_data, "abcd", 4);
}

/* REQ-UDP-028: datagrams to the limited and the subnet broadcast address
 * are received */
TEST(itest_udp_028_broadcast_received) {
  uint8_t f[128];
  peer_ip_t ip;
  uint8_t seg[32];
  uint16_t n;
  up();
  ip = peer_ip(PEER_IP, 0xFFFFFFFFu, 17);
  n = peer_udp(seg, &ip, PEER_PORT, OPEN_PORT, "b1", 2);
  itest_receive(&t, f,
                peer_ipv4_frame(f, broadcast_mac, peer_mac, &ip, seg, n));
  ASSERT_EQ(delivered, 1);
  ASSERT_EQ(seen_dst, 0xFFFFFFFFu);
  ip = peer_ip(PEER_IP, 0x0A0000FFu, 17);
  n = peer_udp(seg, &ip, PEER_PORT, OPEN_PORT, "b2", 2);
  itest_receive(&t, f,
                peer_ipv4_frame(f, broadcast_mac, peer_mac, &ip, seg, n));
  ASSERT_EQ(delivered, 2);
  ASSERT_EQ(seen_dst, 0x0A0000FFu);
}

/* REQ-UDP-031: no Port Unreachable about a datagram sent to a broadcast
 * or multicast address, or in a link-layer broadcast */
TEST(itest_udp_031_no_port_unreachable_for_broadcast) {
  static const uint8_t group_mac[6] = {0x01, 0x00, 0x5E, 0x01, 0x02, 0x03};
  uint8_t f[128], seg[32];
  peer_ip_t ip;
  uint16_t n;
  up();
  ASSERT_EQ(ipv4_mcast_join(&t.net, 0xE0010203u), NET_OK);
  ip = peer_ip(PEER_IP, 0xFFFFFFFFu, 17);
  n = peer_udp(seg, &ip, PEER_PORT, CLOSED_PORT, "b", 1);
  itest_receive(&t, f,
                peer_ipv4_frame(f, broadcast_mac, peer_mac, &ip, seg, n));
  ip = peer_ip(PEER_IP, 0x0A0000FFu, 17);
  n = peer_udp(seg, &ip, PEER_PORT, CLOSED_PORT, "b", 1);
  itest_receive(&t, f,
                peer_ipv4_frame(f, broadcast_mac, peer_mac, &ip, seg, n));
  ip = peer_ip(PEER_IP, 0xE0010203u, 17);
  n = peer_udp(seg, &ip, PEER_PORT, CLOSED_PORT, "m", 1);
  itest_receive(&t, f, peer_ipv4_frame(f, group_mac, peer_mac, &ip, seg, n));
  ip = peer_ip(PEER_IP, t.net.ipv4_addr, 17); /* unicast, link broadcast */
  n = peer_udp(seg, &ip, PEER_PORT, CLOSED_PORT, "u", 1);
  itest_receive(&t, f,
                peer_ipv4_frame(f, broadcast_mac, peer_mac, &ip, seg, n));
  ASSERT_EQ(t.wire.tx_count, 0);
  /* the same to our address: Port Unreachable (REQ-UDP-017) */
  itest_receive(&t, f,
                peer_udp_frame(f, &t.net, PEER_IP, t.net.ipv4_addr, PEER_PORT,
                               CLOSED_PORT, "u", 1));
  ASSERT_EQ(t.wire.tx_count, 1);
}

/* REQ-UDP-034: a datagram larger than the RX frame buffer is not
 * delivered (net_poll() truncates it, and IPv4 drops it) */
TEST(itest_udp_034_datagram_beyond_rx_buffer_dropped) {
  static uint8_t data[200];
  uint8_t f[300];
  itest_up(&t, 128, 1514);
  udp_set_ports(&t.net, ports, 2);
  delivered = 0;
  itest_receive(&t, f,
                peer_udp_frame(f, &t.net, PEER_IP, t.net.ipv4_addr, PEER_PORT,
                               OPEN_PORT, data, sizeof(data)));
  ASSERT_EQ(delivered, 0);
  itest_receive(&t, f,
                peer_udp_frame(f, &t.net, PEER_IP, t.net.ipv4_addr, PEER_PORT,
                               OPEN_PORT, data, 128 - 42));
  ASSERT_EQ(delivered, 1);
}

/* REQ-UDP-042 (deviation): a datagram carrying IP options is delivered;
 * the options are not passed up */
TEST(itest_udp_042_ip_options_not_passed_up) {
  static const uint8_t nops[4] = {1, 1, 1, 0}; /* NOP NOP NOP EOL */
  uint8_t f[128], seg[32];
  peer_ip_t ip;
  uint16_t n;
  up();
  ip = peer_ip(PEER_IP, t.net.ipv4_addr, 17);
  ip.options = nops;
  ip.options_len = 4;
  n = peer_udp(seg, &ip, PEER_PORT, OPEN_PORT, "opts", 4);
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, seg, n));
  ASSERT_EQ(delivered, 1);
  ASSERT_EQ(seen_len, 4);
  ASSERT_MEM_EQ(seen_data, "opts", 4);
}

/* ── Transmission ── */

/* REQ-UDP-009, 014, 021, 022, 023, 024: a datagram sent has the ports,
 * Length = 8 + data, and a checksum over the IPv4 pseudo-header that the
 * peer verifies, in an IPv4 packet of protocol 17; the source port may be
 * 0.  A computed checksum of 0 goes as 0xFFFF (RFC 768) */
TEST(itest_udp_009_datagram_sent) {
  uint8_t data[2] = {0, 0}, probe[10];
  peer_ip_t ip;
  peer_udp_t u;
  uint16_t sum;
  up();
  ASSERT_EQ(udp_send(&t.net, PEER_IP, peer_mac, APP_PORT, PEER_PORT,
                     (const uint8_t *)"hello", 5),
            NET_OK);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip));
  ASSERT_EQ(ip.proto, 17);
  ASSERT_EQ(ip.src, t.net.ipv4_addr);
  ASSERT_EQ(ip.dst, PEER_IP);
  ASSERT_TRUE(ip.header_cksum_ok);
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, peer_mac, 6);
  ASSERT_TRUE(peer_parse_udp(&ip, &u));
  ASSERT_EQ(u.sport, APP_PORT);
  ASSERT_EQ(u.dport, PEER_PORT);
  ASSERT_EQ(u.len, 13);
  ASSERT_TRUE(u.cksum != 0);
  ASSERT_TRUE(u.cksum_ok);
  ASSERT_EQ(u.data_len, 5);
  ASSERT_MEM_EQ(u.data, "hello", 5);

  ASSERT_EQ(udp_send(&t.net, PEER_IP, peer_mac, 0, PEER_PORT,
                     (const uint8_t *)"x", 1),
            NET_OK);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 1), &ip));
  ASSERT_TRUE(peer_parse_udp(&ip, &u));
  ASSERT_EQ(u.sport, 0);

  /* two data bytes chosen so that the checksum computes to 0 */
  peer_put16(probe, APP_PORT);
  peer_put16(probe + 2, PEER_PORT);
  peer_put16(probe + 4, 10);
  peer_put16(probe + 6, 0);
  peer_put16(probe + 8, 0);
  sum = (uint16_t)~udp_cksum4(t.net.ipv4_addr, PEER_IP, 10, probe, 10);
  peer_put16(data, (uint16_t)~sum);
  ASSERT_EQ(udp_send(&t.net, PEER_IP, peer_mac, APP_PORT, PEER_PORT, data, 2),
            NET_OK);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 2), &ip));
  ASSERT_TRUE(peer_parse_udp(&ip, &u));
  ASSERT_EQ(u.cksum, 0xFFFF);
  ASSERT_TRUE(u.cksum_ok);
}

/* REQ-UDP-036: the application writes the payload in place in the TX
 * frame buffer, and the stack builds the headers around it there */
TEST(itest_udp_036_built_in_place) {
  peer_ip_t ip;
  peer_udp_t u;
  up();
  memcpy(t.tx_buf + UDP_PAYLOAD_OFFSET, "inplace", 7);
  ASSERT_EQ(
      udp_send_inplace(&t.net, PEER_IP, peer_mac, APP_PORT, PEER_PORT, 7, 64),
      NET_OK);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip));
  ASSERT_TRUE(peer_parse_udp(&ip, &u));
  ASSERT_MEM_EQ(u.data, "inplace", 7);
  ASSERT_MEM_EQ(t.tx_buf, wire_sent(&t, 0)->data, wire_sent(&t, 0)->len);
}

/* REQ-UDP-025: the stack names the next hop — the destination on the
 * link, else the gateway — and UDP sends to the MAC the caller gives */
TEST(itest_udp_025_next_hop) {
  static const uint8_t gw_mac[6] = {0x02, 0, 0, 0, 0, 0xFE};
  peer_ip_t ip;
  up();
  ASSERT_EQ(arp_next_hop(&t.net, PEER2_IP), PEER2_IP);
  ASSERT_EQ(arp_next_hop(&t.net, REMOTE_IP), t.net.gateway_ipv4);
  ASSERT_EQ(udp_send(&t.net, REMOTE_IP, gw_mac, APP_PORT, PEER_PORT,
                     (const uint8_t *)"far", 3),
            NET_OK);
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, gw_mac, 6);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip));
  ASSERT_EQ(ip.dst, REMOTE_IP);
}

/* REQ-UDP-029, 030: a datagram to the limited broadcast address, at the
 * broadcast MAC */
TEST(itest_udp_029_broadcast_sent) {
  peer_ip_t ip;
  peer_udp_t u;
  up();
  ASSERT_EQ(arp_next_hop(&t.net, 0xFFFFFFFFu), 0xFFFFFFFFu);
  ASSERT_EQ(udp_send(&t.net, 0xFFFFFFFFu, broadcast_mac, APP_PORT, PEER_PORT,
                     (const uint8_t *)"all", 3),
            NET_OK);
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, broadcast_mac, 6);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip));
  ASSERT_EQ(ip.dst, 0xFFFFFFFFu);
  ASSERT_TRUE(peer_parse_udp(&ip, &u));
  ASSERT_TRUE(u.cksum_ok);
}

/* REQ-UDP-044: the application sets the TTL and the TOS of a datagram */
TEST(itest_udp_044_ttl_and_tos) {
  peer_ip_t ip;
  udp_tx_opts_t o;
  up();
  o.src_ip = t.net.ipv4_addr;
  o.ttl = 9;
  o.tos = 0x28;
  memcpy(t.net.tx.buf + UDP_PAYLOAD_OFFSET, "t", 1);
  ASSERT_EQ(udp_send_inplace_opts(&t.net, PEER_IP, peer_mac, APP_PORT,
                                  PEER_PORT, 1, &o),
            NET_OK);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip));
  ASSERT_EQ(ip.ttl, 9);
  ASSERT_EQ(ip.tos, 0x28);
}

/* REQ-UDP-040: a handler learns the datagram's destination address */
TEST(itest_udp_040_destination_address_passed_up) {
  uint8_t f[128];
  up();
  itest_receive(&t, f,
                peer_udp_frame(f, &t.net, PEER_IP, t.net.ipv4_addr, PEER_PORT,
                               OPEN_PORT, "x", 1));
  ASSERT_EQ(seen_dst, t.net.ipv4_addr);
  itest_receive(&t, f,
                peer_udp_frame(f, &t.net, PEER_IP, 0xFFFFFFFFu, PEER_PORT,
                               OPEN_PORT, "x", 1));
  ASSERT_EQ(seen_dst, 0xFFFFFFFFu);
  ASSERT_EQ(delivered, 2);
}

/* REQ-UDP-041: the source is ours, or 0.0.0.0 while acquiring an address */
TEST(itest_udp_041_source_must_be_ours) {
  up();
  memcpy(t.net.tx.buf + UDP_PAYLOAD_OFFSET, "x", 1);
  ASSERT_EQ(udp_send_inplace_from(&t.net, 0x0A00004Du, PEER_IP, peer_mac,
                                  APP_PORT, PEER_PORT, 1, 64),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(udp_send_inplace_from(&t.net, t.net.ipv4_addr, PEER_IP, peer_mac,
                                  APP_PORT, PEER_PORT, 1, 64),
            NET_OK);
  t.net.ipv4_addr = 0;
  ASSERT_EQ(udp_send_inplace_from(&t.net, 0, 0xFFFFFFFFu, broadcast_mac,
                                  APP_PORT, PEER_PORT, 1, 64),
            NET_OK);
}

/* The datagram the application sent, quoted in an ICMP error of @p type
 * and @p code (and @p rest) from @p from */
static void icmp_error_about_last_send(uint32_t from, uint8_t type,
                                       uint8_t code, const uint8_t rest[4]) {
  uint8_t msg[128], f[192];
  const wire_frame_t *sent = wire_sent(&t, 0);
  peer_ip_t ip = peer_ip(from, t.net.ipv4_addr, 1);
  uint16_t n = peer_icmp(msg, type, code, rest, sent->data + 14, 28);
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, msg, n));
}

/* REQ-UDP-038, REQ-ICMPv4-011, 012, 015, 042, REQ-IPv4-053: Port
 * Unreachable about a datagram we sent reaches the application, by the
 * quoted protocol and ports */
TEST(itest_udp_038_port_unreachable_reported) {
  up();
  udp_send(&t.net, PEER_IP, peer_mac, APP_PORT, PEER_PORT,
           (const uint8_t *)"hello", 5);
  icmp_error_about_last_send(PEER_IP, 3, 3, NULL);
  ASSERT_EQ(errors, 1);
  ASSERT_EQ(err_port, APP_PORT);
  ASSERT_EQ(err_dst, PEER_IP);
  ASSERT_EQ(err_dst_port, PEER_PORT);
  ASSERT_EQ(err_type, 3);
  ASSERT_EQ(err_code, 3);
  ASSERT_EQ(err_mtu, 0);
  ASSERT_EQ(err_quote_len, 28); /* all the error quoted, unchanged */
  ASSERT_MEM_EQ(err_quote, wire_sent(&t, 0)->data + 14, 28);
}

/* REQ-UDP-038, REQ-ICMPv4-042: an error about a datagram that was not ours
 * (another source), that quotes TCP, or whose quote stops short of the UDP
 * ports, reaches no UDP handler */
TEST(itest_udp_038_only_our_datagrams_errors) {
  uint8_t msg[128], f[192], quoted[28];
  peer_ip_t ip = peer_ip(PEER_IP, t.net.ipv4_addr, 1);
  uint16_t n;
  up();
  udp_send(&t.net, PEER_IP, peer_mac, APP_PORT, PEER_PORT,
           (const uint8_t *)"hello", 5);
  memcpy(quoted, wire_sent(&t, 0)->data + 14, 28);
  quoted[12] = 0x0A; /* another source: 10.0.0.99 */
  quoted[15] = 99;
  n = peer_icmp(msg, 3, 3, NULL, quoted, 28);
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, msg, n));
  memcpy(quoted, wire_sent(&t, 0)->data + 14, 28);
  quoted[9] = 6; /* TCP */
  n = peer_icmp(msg, 3, 3, NULL, quoted, 28);
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, msg, n));
  memcpy(quoted, wire_sent(&t, 0)->data + 14, 28);
  n = peer_icmp(msg, 3, 3, NULL, quoted, 22); /* half the ports */
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, msg, n));
  ASSERT_EQ(errors, 0);
}

/* REQ-UDP-039, REQ-ICMPv4-016, 024, 029, 028: Fragmentation Needed (with
 * the next-hop MTU), Time Exceeded and Parameter Problem are reported;
 * Source Quench is discarded */
TEST(itest_udp_038_errors_of_every_kind_reported) {
  static const uint8_t mtu_1280[4] = {0, 0, 0x05, 0x00};
  up();
  udp_send(&t.net, REMOTE_IP, peer_mac, APP_PORT, PEER_PORT,
           (const uint8_t *)"hello", 5);
  icmp_error_about_last_send(0x0A0000FEu, 3, 4, mtu_1280);
  ASSERT_EQ(errors, 1);
  ASSERT_EQ(err_code, 4);
  ASSERT_EQ(err_mtu, 1280);
  icmp_error_about_last_send(0x0A0000FEu, 11, 0, NULL);
  ASSERT_EQ(err_type, 11);
  icmp_error_about_last_send(0x0A0000FEu, 12, 0, NULL);
  ASSERT_EQ(err_type, 12);
  ASSERT_EQ(errors, 3);
  icmp_error_about_last_send(0x0A0000FEu, 4, 0, NULL);
  ASSERT_EQ(errors, 3);
}

#if NET_USE_IPV6
/* ── UDP over IPv6 ── */

static const uint8_t peer_ll6[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                     0,    0,    0, 0, 0, 0, 0, 0x99};
static uint8_t our_ll6[16];
static int delivered6;
static uint8_t seen6[16];

static void on_datagram6(net_t *net, const uint8_t *src_ip, uint16_t src_port,
                         const uint8_t *src_mac, const uint8_t *data,
                         uint16_t len) {
  (void)net;
  (void)src_port;
  (void)src_mac;
  (void)len;
  delivered6++;
  memcpy(seen6, data, len < 16 ? len : 16);
  (void)src_ip;
}

static const udp6_port_entry_t ports6[] = {{OPEN_PORT, on_datagram6}};

/* The stack with its link-local address, past Duplicate Address Detection */
static void up6(void) {
  up();
  udp6_set_ports(&t.net, ports6, 1);
  ipv6_start(&t.net);
  itest_advance(&t, 3000, 100);
  ipv6_link_local_from_mac(t.net.mac, our_ll6);
  wire_clear(&t);
  delivered6 = 0;
}

/* The UDP checksum over the IPv6 pseudo-header (RFC 8200 §8.1), by the
 * peer's arithmetic */
static uint16_t udp_cksum6(const uint8_t *src, const uint8_t *dst,
                           const uint8_t *udp, uint16_t len) {
  static uint8_t buf[40 + WIRE_FRAME_MAX];
  memcpy(buf, src, 16);
  memcpy(buf + 16, dst, 16);
  peer_put32(buf + 32, len);
  peer_put32(buf + 36, 17);
  memcpy(buf + 40, udp, len);
  return peer_cksum(buf, (uint16_t)(40u + len));
}

/* A datagram from the peer's link-local address to ours, with checksum
 * @p cksum, or the right one if @p cksum is -1 */
static void datagram6(const void *data, uint16_t len, long cksum) {
  static uint8_t f[WIRE_FRAME_MAX];
  uint8_t *ip = f + 14, *udp = ip + 40;
  uint16_t ulen = (uint16_t)(8u + len), ck;
  memcpy(f, t.net.mac, 6);
  memcpy(f + 6, peer_mac, 6);
  peer_put16(f + 12, 0x86DD);
  memset(ip, 0, 40);
  ip[0] = 0x60;
  peer_put16(ip + 4, ulen);
  ip[6] = 17;
  ip[7] = 64;
  memcpy(ip + 8, peer_ll6, 16);
  memcpy(ip + 24, our_ll6, 16);
  peer_put16(udp, PEER_PORT);
  peer_put16(udp + 2, OPEN_PORT);
  peer_put16(udp + 4, ulen);
  peer_put16(udp + 6, 0);
  memcpy(udp + 8, data, len);
  ck = udp_cksum6(peer_ll6, our_ll6, udp, ulen);
  peer_put16(udp + 6, cksum >= 0 ? (uint16_t)cksum : (ck ? ck : 0xFFFF));
  itest_receive(&t, f, (uint16_t)(54u + ulen));
}

/* REQ-UDP-011, 015: over IPv6 every datagram carries a checksum, over
 * the IPv6 pseudo-header, never 0 */
TEST(itest_udp_011_ipv6_checksum_sent) {
  const wire_frame_t *f;
  const uint8_t *udp;
  up6();
  ASSERT_EQ(udp6_send(&t.net, peer_ll6, peer_mac, APP_PORT, PEER_PORT,
                      (const uint8_t *)"six", 3),
            NET_OK);
  ASSERT_EQ(t.wire.tx_count, 1);
  f = wire_sent(&t, 0);
  ASSERT_EQ(peer_get16(f->data + 12), 0x86DD);
  ASSERT_EQ(f->data[20], 17);
  ASSERT_MEM_EQ(f->data + 22, our_ll6, 16);
  udp = f->data + 54;
  ASSERT_EQ(peer_get16(udp + 4), 11);
  ASSERT_TRUE(peer_get16(udp + 6) != 0);
  ASSERT_EQ(udp_cksum6(our_ll6, peer_ll6, udp, 11), 0);
}

/* REQ-UDP-012, 013, 015: over IPv6 the checksum is verified, and a
 * datagram with a bad or a zero checksum is dropped — a zero even where
 * the checksum computes to 0, which 0 and 0xFFFF both verify */
TEST(itest_udp_012_ipv6_checksum_verified) {
  uint8_t udp[10], data[2];
  uint16_t sum;
  up6();
  datagram6("good", 4, -1);
  ASSERT_EQ(delivered6, 1);
  ASSERT_MEM_EQ(seen6, "good", 4);
  datagram6("bad!", 4, 0x1234);
  /* two data bytes that make the checksum compute to 0 */
  peer_put16(udp, PEER_PORT);
  peer_put16(udp + 2, OPEN_PORT);
  peer_put16(udp + 4, 10);
  peer_put16(udp + 6, 0);
  peer_put16(udp + 8, 0);
  sum = (uint16_t)~udp_cksum6(peer_ll6, our_ll6, udp, 10);
  peer_put16(data, (uint16_t)~sum);
  datagram6(data, 2, 0);
  ASSERT_EQ(delivered6, 1);
  datagram6(data, 2, 0xFFFF); /* the same, its checksum sent as 0xFFFF */
  ASSERT_EQ(delivered6, 2);
  ASSERT_EQ(t.wire.tx_count, 0);
}
#endif

int main(void) {
  fprintf(stderr, "=== itest_udp ===\n");
  RUN_TEST(itest_udp_040_destination_address_passed_up);
  RUN_TEST(itest_udp_041_source_must_be_ours);
  RUN_TEST(itest_udp_038_port_unreachable_reported);
  RUN_TEST(itest_udp_038_errors_of_every_kind_reported);
  RUN_TEST(itest_udp_038_only_our_datagrams_errors);
  RUN_TEST(itest_udp_016_dispatched_by_destination_port);
  RUN_TEST(itest_udp_002_length_below_header_dropped);
  RUN_TEST(itest_udp_003_length_beyond_ip_payload_dropped);
  RUN_TEST(itest_udp_004_length_field_bounds_the_data);
  RUN_TEST(itest_udp_006_bad_checksum_dropped);
  RUN_TEST(itest_udp_008_zero_checksum_accepted);
  RUN_TEST(itest_udp_028_broadcast_received);
  RUN_TEST(itest_udp_031_no_port_unreachable_for_broadcast);
  RUN_TEST(itest_udp_034_datagram_beyond_rx_buffer_dropped);
  RUN_TEST(itest_udp_042_ip_options_not_passed_up);
  RUN_TEST(itest_udp_009_datagram_sent);
  RUN_TEST(itest_udp_036_built_in_place);
  RUN_TEST(itest_udp_025_next_hop);
  RUN_TEST(itest_udp_029_broadcast_sent);
  RUN_TEST(itest_udp_044_ttl_and_tos);
#if NET_USE_IPV6
  RUN_TEST(itest_udp_011_ipv6_checksum_sent);
  RUN_TEST(itest_udp_012_ipv6_checksum_verified);
#endif
  ITEST_REPORT();
  return test_failures;
}
