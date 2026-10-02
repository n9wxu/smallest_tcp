/**
 * @file itest_ipv4.c
 * @brief IPv4 and ICMPv4, black box: datagrams on the wire, a UDP port
 *        and an error handler the test registers, and what the stack sends
 *        back.
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
static int errors;
static udp_icmp_error_t err; /* the last error reported */

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

static void on_error(net_t *net, const udp_icmp_error_t *e) {
  (void)net;
  errors++;
  err = *e;
}

#define OPEN_PORT 7000
#define CLOSED_PORT 7001

static const udp_port_entry_t ports[] = {{OPEN_PORT, on_datagram}};

static void up(void) {
  ASSERT_EQ(itest_up(&t, 1514, 1514), NET_OK);
  udp_set_ports(&t.net, ports, 1);
  udp_set_error_handler(&t.net, on_error);
  delivered = errors = 0;
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

/* ── The header ── */

/* The header checksum of the IPv4 frame @p f written again, over its first
 * 20 bytes */
static void rechecksum(uint8_t *f) {
  peer_put16(f + 14 + 10, 0);
  peer_put16(f + 14 + 10, peer_cksum(f + 14, 20));
}

/* REQ-IPv4-001, 002, 003, 004, 005, 006: a datagram whose version is not
 * 4, whose header length is less than 5 words, whose Total Length is less
 * than its header or more than the frame holds, or whose header checksum
 * is wrong, is discarded — to an open port or a closed one — without a
 * word */
TEST(itest_ipv4_001_invalid_headers_discarded) {
  uint16_t port;
  up();
  for (port = OPEN_PORT; port <= CLOSED_PORT; port++) {
    uint8_t f[128], good[128];
    uint16_t n = peer_udp_frame(good, &t.net, PEER_IP, t.net.ipv4_addr, 5000,
                                port, "x", 1);
    wire_clear(&t);
    memcpy(f, good, n);
    f[14] = 0x55; /* version 5 */
    rechecksum(f);
    itest_receive(&t, f, n);
    f[14] = 0x65; /* version 6 */
    rechecksum(f);
    itest_receive(&t, f, n);
    f[14] = 0x05; /* version 0 */
    rechecksum(f);
    itest_receive(&t, f, n);
    memcpy(f, good, n);
    f[14] = 0x44; /* a header of 16 bytes */
    rechecksum(f);
    itest_receive(&t, f, n);
    f[14] = 0x40; /* a header of none */
    rechecksum(f);
    itest_receive(&t, f, n);
    memcpy(f, good, n);
    peer_put16(f + 14 + 2, 19); /* Total Length less than the header */
    rechecksum(f);
    itest_receive(&t, f, n);
    memcpy(f, good, n);
    peer_put16(f + 14 + 2, (uint16_t)(n - 14 + 1)); /* more than the frame */
    rechecksum(f);
    itest_receive(&t, f, n);
    memcpy(f, good, n);
    itest_receive(&t, f, (uint16_t)(n - 1)); /* the frame cut short */
    itest_receive(&t, f, 14 + 19);           /* less than a header */
    f[14 + 10] ^= 0x01;                      /* the checksum wrong */
    itest_receive(&t, f, n);
    memcpy(f, good, n);
    f[14 + 8] ^= 0x01; /* a field changed under the checksum */
    itest_receive(&t, f, n);
    ASSERT_EQ(delivered, 0);
    ASSERT_EQ(t.wire.tx_count, 0);
  }
  datagram(PEER_IP, t.net.ipv4_addr, OPEN_PORT);
  ASSERT_EQ(delivered, 1);
}

/* REQ-IPv4-007: the datagram ends where its Total Length says, not where
 * the frame does: an Echo Request in a frame padded with other bytes is
 * answered with its own four data bytes */
TEST(itest_ipv4_007_total_length_bounds_the_datagram) {
  static const uint8_t rest[4] = {0, 1, 0, 1};
  uint8_t msg[64], f[128];
  peer_ip_t ip = peer_ip(PEER_IP, 0, 1), rip;
  peer_icmp_t icmp;
  uint16_t n;
  up();
  ip.dst = t.net.ipv4_addr;
  memset(f, 0xA5, sizeof(f));
  n = peer_icmp(msg, 8, 0, rest, "ping", 4);
  n = peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, msg, n);
  ASSERT_EQ(n, 14 + 20 + 12);
  wire_clear(&t);
  itest_receive(&t, f, 60);
  ASSERT_TRUE(sent_icmp(&rip, &icmp));
  ASSERT_EQ(rip.total_len, 20 + 12);
  ASSERT_EQ(wire_sent(&t, 0)->len, 14 + 20 + 12);
  ASSERT_EQ(icmp.data_len, 4);
  ASSERT_MEM_EQ(icmp.data, "ping", 4);
}

/* REQ-IPv4-019, 018, 036: the Protocol field chooses the transport — 17
 * goes to UDP, 6 to TCP (which answers a SYN for a port nobody listens on
 * with a RST, itself sent as protocol 6) */
TEST(itest_ipv4_018_protocol_dispatch) {
  up();
  datagram(PEER_IP, t.net.ipv4_addr, OPEN_PORT);
  ASSERT_EQ(delivered, 1);
#if NET_USE_TCP
  {
    uint8_t f[128];
    peer_tcp_seg_t syn;
    peer_ip_t ip;
    peer_tcp_t tcp;
    memset(&syn, 0, sizeof(syn));
    syn.sport = 40000;
    syn.dport = 81;
    syn.seq = 1000;
    syn.flags = TCPF_SYN;
    syn.window = 4096;
    wire_clear(&t);
    itest_receive(&t, f, peer_tcp_frame(f, &t.net, PEER_IP, &syn));
    ASSERT_EQ(wire_find_tcp(&t, 0, &ip, &tcp), 0);
    ASSERT_EQ(ip.proto, 6);
    ASSERT_TRUE(tcp.flags & TCPF_RST);
    ASSERT_EQ(delivered, 1);
  }
#endif
}

/* REQ-IPv4-042, 044: a datagram is taken whatever its TOS and its TTL — a
 * TTL of 1 or 0 included */
TEST(itest_ipv4_042_any_tos_and_ttl_accepted) {
  static const struct {
    uint8_t tos, ttl;
  } field[] = {{0xFF, 64}, {0xB8, 64}, {0x01, 64}, {0, 1}, {0, 0}, {0, 255}};
  uint8_t f[128], seg[64];
  peer_ip_t ip = peer_ip(PEER_IP, 0, 17);
  uint16_t n, i;
  up();
  ip.dst = t.net.ipv4_addr;
  n = peer_udp(seg, &ip, 5000, OPEN_PORT, "x", 1);
  for (i = 0; i < sizeof(field) / sizeof(field[0]); i++) {
    ip.tos = field[i].tos;
    ip.ttl = field[i].ttl;
    itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, seg, n));
    ASSERT_EQ(delivered, i + 1);
  }
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-IPv4-011, 043: a datagram for another host that reaches our MAC is
 * discarded: not delivered, not forwarded — on-link or through the
 * gateway — and not answered */
TEST(itest_ipv4_043_never_forwards) {
  static const uint8_t gw[6] = {0x02, 0x47, 0x57, 0x00, 0x00, 0x01};
  up();
  t.net.gateway_ipv4 = 0x0A0000FEu;
  memcpy(t.net.gateway_mac, gw, 6);
  t.net.gateway_mac_valid = 1;
  datagram(PEER_IP, PEER2_IP, OPEN_PORT);
  ASSERT_EQ(t.wire.tx_count, 0);
  datagram(PEER_IP, REMOTE_IP, OPEN_PORT);
  ASSERT_EQ(t.wire.tx_count, 0);
  datagram(PEER_IP, PEER2_IP, CLOSED_PORT);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(delivered, 0);
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

/* REQ-IPv4-010, 011, 080 (RFC 3021): the subnet mask is set by hand; a /31
 * or /32 has no directed broadcast */
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

/* REQ-IPv4-009, 011, 012: before DHCP configures an address (0.0.0.0, mask
 * 0) only the limited broadcast is a broadcast; a datagram to 0.0.0.0 is
 * taken then, and only then */
TEST(itest_ipv4_011_unconfigured_only_the_limited_broadcast) {
  up();
  datagram(PEER_IP, 0, OPEN_PORT);
  ASSERT_EQ(delivered, 0);
  t.net.ipv4_addr = 0;
  t.net.subnet_mask = 0;
  datagram(PEER_IP, 0x0A0000FFu, OPEN_PORT);
  ASSERT_EQ(delivered, 0);
  datagram(PEER_IP, 0xFFFFFFFFu, OPEN_PORT);
  ASSERT_EQ(delivered, 1);
  datagram(PEER_IP, 0, OPEN_PORT);
  ASSERT_EQ(delivered, 2);
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

/* REQ-ICMPv4-001, 002, 003, 004, 005, 006, 007, 032, 033, REQ-CKSUM-015,
 * REQ-IPv4-017: Echo Reply, Code 0, the request's identifier, sequence and
 * data, from our address to its source, the checksum over the whole ICMP
 * message; the reply is built in the TX buffer, the request left as it
 * came in the RX buffer */
TEST(itest_icmpv4_001_echo_reply_code_zero) {
  static const uint8_t rest[4] = {0x12, 0x34, 0x00, 0x07};
  uint8_t msg[64], f[128];
  peer_ip_t ip = peer_ip(PEER_IP, 0, 1), rip;
  peer_icmp_t icmp;
  uint16_t n;
  up();
  ip.dst = t.net.ipv4_addr;
  n = peer_icmp(msg, 8, 9 /* a non-zero Code */, rest, "ping", 4);
  n = peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, msg, n);
  wire_clear(&t);
  itest_receive(&t, f, n);
  ASSERT_TRUE(sent_icmp(&rip, &icmp));
  ASSERT_MEM_EQ(t.rx_buf, f, n);
  ASSERT_MEM_EQ(t.tx_buf, wire_sent(&t, 0)->data, n);
  ASSERT_EQ(rip.src, t.net.ipv4_addr);
  ASSERT_EQ(rip.dst, PEER_IP);
  ASSERT_EQ(rip.proto, 1);
  ASSERT_EQ(icmp.type, 0);
  ASSERT_EQ(icmp.code, 0);
  ASSERT_TRUE(icmp.cksum_ok);
  ASSERT_MEM_EQ(icmp.rest, rest, 4);
  ASSERT_EQ(icmp.data_len, 4);
  ASSERT_MEM_EQ(icmp.data, "ping", 4);
}

/* ── Broadcasts, reassembly, sizes, options (RFC 1122 §3.2–3.3) ── */

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

/* REQ-IPv4-024, 062: a datagram larger than any frame the RX buffer takes
 * is reassembled whole, up to MMS_R */
TEST(itest_ipv4_024_larger_than_a_frame) {
  static uint8_t reasm[IPV4_REASSEMBLY_BUFFER(4000)];
  up();
  ASSERT_EQ(ipv4_set_reassembly(&t.net, reasm, sizeof(reasm)), NET_OK);
  ASSERT_EQ(ipv4_mms_r(&t.net), 3980);
  make_datagram(3972); /* 3980 bytes of UDP: all MMS_R allows */
  fragment(2960, 1020, 0, 80);
  fragment(1480, 1480, 1, 80);
  fragment(0, 1480, 1, 80);
  ASSERT_EQ(delivered, 1);
  ASSERT_EQ(got_len, 3972);
  ASSERT_MEM_EQ(got, seg + 8, 3972);
}

/* REQ-IPv4-024: a datagram larger than the buffer is dropped — and the
 * buffer is free again for the next */
TEST(itest_ipv4_024_too_large_dropped) {
  static uint8_t reasm[IPV4_REASSEMBLY_BUFFER(1500)];
  up();
  ASSERT_EQ(ipv4_set_reassembly(&t.net, reasm, sizeof(reasm)), NET_OK);
  make_datagram(2000);
  fragment(0, 1480, 1, 81);
  fragment(1480, 528, 0, 81);
  ASSERT_EQ(delivered, 0);
  make_datagram(1000);
  fragment(0, 512, 1, 82);
  fragment(512, 496, 0, 82);
  ASSERT_EQ(delivered, 1);
}

/* REQ-IPv4-024: one datagram at a time — another's fragments are dropped
 * until the first is complete */
TEST(itest_ipv4_024_one_at_a_time) {
  static uint8_t reasm[IPV4_REASSEMBLY_BUFFER(1500)];
  up();
  ASSERT_EQ(ipv4_set_reassembly(&t.net, reasm, sizeof(reasm)), NET_OK);
  make_datagram(1000);
  fragment(0, 512, 1, 83);
  fragment(0, 512, 1, 84);
  fragment(512, 496, 0, 84);
  ASSERT_EQ(delivered, 0);
  fragment(512, 496, 0, 83);
  ASSERT_EQ(delivered, 1);
}

/* REQ-IPv4-024: without a reassembly buffer, fragments are dropped */
TEST(itest_ipv4_024_no_buffer_no_reassembly) {
  up();
  ASSERT_EQ(ipv4_mms_r(&t.net), 1480);
  make_datagram(1000);
  fragment(0, 512, 1, 85);
  fragment(512, 496, 0, 85);
  ASSERT_EQ(delivered, 0);
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

/* REQ-ICMPv4-034: a reassembly timeout draws no Time Exceeded about an
 * ICMP error message */
TEST(itest_icmpv4_034_no_error_about_an_error) {
  static uint8_t reasm[IPV4_REASSEMBLY_BUFFER(1500)];
  uint8_t msg[64], quoted[28], f[128];
  peer_ip_t ip = peer_ip(PEER_IP, 0, 1);
  up();
  ASSERT_EQ(ipv4_set_reassembly(&t.net, reasm, sizeof(reasm)), NET_OK);
  memset(quoted, 0, sizeof(quoted));
  peer_icmp(msg, 3, 1, NULL, quoted, 28); /* Host Unreachable, 36 bytes */
  ip.dst = t.net.ipv4_addr;
  ip.id = 86;
  ip.mf = 1;
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, msg, 16));
  wire_clear(&t);
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

/* REQ-IPv4-064, 022: the MTU is configurable, and nothing sent exceeds it:
 * a datagram that does not fit is refused, never fragmented */
TEST(itest_ipv4_064_mtu_configurable) {
  static uint8_t data[1500];
  itest_up(&t, 1514, 1514);
  ASSERT_EQ(t.net.mtu, 1500);
  t.net.mtu = 576;
  ASSERT_EQ(ipv4_mms_s(&t.net), 556);
  ASSERT_EQ(udp_send(&t.net, PEER_IP, peer_mac, 7, 7, data, 549),
            NET_ERR_BUF_TOO_SMALL);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(udp_send(&t.net, PEER_IP, peer_mac, 7, 7, data, 548), NET_OK);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_EQ(wire_sent(&t, 0)->len, 14 + 576);
}

/* REQ-IPv4-028, 030, 031, 032, 033, 034, 036, 037, 038, 039, 040, 082,
 * REQ-IPv4-023, REQ-IPv4-065 (deviation: no options from the transport):
 * what UDP sends has version 4, a 20-byte header without options, TOS 0,
 * the right Total Length, an Identification of 0, the reserved bit 0, DF
 * set, MF clear, offset 0, protocol 17, a correct header checksum, our
 * address as source and the destination asked for */
TEST(itest_ipv4_028_no_options_sent) {
  peer_ip_t ip;
  up();
  udp_send(&t.net, PEER_IP, peer_mac, 7, 7, (const uint8_t *)"abc", 3);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip));
  ASSERT_EQ(wire_sent(&t, 0)->data[14] >> 4, 4);
  ASSERT_EQ(ip.ihl_bytes, 20);
  ASSERT_EQ(ip.tos, 0);
  ASSERT_EQ(ip.total_len, 20 + 8 + 3);
  ASSERT_EQ(ip.id, 0);
  ASSERT_EQ(wire_sent(&t, 0)->data[14 + 6] & 0x80, 0);
  ASSERT_TRUE(ip.df);
  ASSERT_FALSE(ip.mf);
  ASSERT_EQ(ip.frag_offset, 0);
  ASSERT_EQ(ip.proto, 17);
  ASSERT_TRUE(ip.header_cksum_ok);
  ASSERT_EQ(ip.src, t.net.ipv4_addr);
  ASSERT_EQ(ip.dst, PEER_IP);
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

/* REQ-IPv4-068, 029: unknown options and Stream ID are ignored, their
 * content unread; a malformed option length does not upset the IP layer */
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

/* REQ-IPv4-035, 045: the default TTL is 64 */
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

/* REQ-IPv4-041, REQ-UDP-044, REQ-ETH-023: the transport sets the TOS of each
 * datagram, and the frame handed to the link carries it */
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

/* REQ-IPv4-048, 038: a datagram goes out from our address and from no
 * other: not from a broadcast address, a group, or another host's */
TEST(itest_ipv4_048_never_from_a_broadcast) {
  static const uint32_t not_ours[] = {0xFFFFFFFFu, 0x0A0000FFu, 0x0AFFFFFFu,
                                      0xE00000FBu, PEER2_IP};
  peer_ip_t ip;
  unsigned i;
  up();
  for (i = 0; i < sizeof(not_ours) / sizeof(not_ours[0]); i++) {
    memcpy(t.net.tx.buf + UDP_PAYLOAD_OFFSET, "x", 1);
    ASSERT_EQ(udp_send_inplace_from(&t.net, not_ours[i], PEER_IP, peer_mac, 7,
                                    7, 1, 64),
              NET_ERR_INVALID_PARAM);
  }
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(udp_send(&t.net, PEER_IP, peer_mac, 7, 7, (const uint8_t *)"x", 1),
            NET_OK);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip));
  ASSERT_EQ(ip.src, t.net.ipv4_addr);
}

/* REQ-IPv4-075 (deviation): there is no route cache: a datagram goes to
 * the MAC its sender names, whatever its destination, with no ARP request
 * and nothing remembered for the next */
TEST(itest_ipv4_075_next_hop_is_the_senders) {
  static const uint8_t hop1[6] = {0x02, 0x48, 0x4F, 0x50, 0x00, 0x01};
  static const uint8_t hop2[6] = {0x02, 0x48, 0x4F, 0x50, 0x00, 0x02};
  up();
  t.net.gateway_mac_valid = 0;
  ASSERT_EQ(udp_send(&t.net, REMOTE_IP, hop1, 7, 7, (const uint8_t *)"x", 1),
            NET_OK);
  ASSERT_EQ(udp_send(&t.net, REMOTE_IP, hop2, 7, 7, (const uint8_t *)"x", 1),
            NET_OK);
  ASSERT_EQ(t.wire.tx_count, 2);
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, hop1, 6);
  ASSERT_MEM_EQ(wire_sent(&t, 1)->data, hop2, 6);
  ASSERT_EQ(peer_get16(wire_sent(&t, 1)->data + 12), 0x0800);
}

/* REQ-IPv4-078: with no gateway configured the host works on its link:
 * it answers and sends to on-link hosts, and asks no one for a gateway */
TEST(itest_ipv4_078_works_without_a_gateway) {
  peer_ip_t ip;
  peer_icmp_t icmp;
  up();
  t.net.gateway_ipv4 = 0;
  t.net.gateway_mac_valid = 0;
  echo_request(PEER_IP, t.net.ipv4_addr, 4);
  ASSERT_TRUE(sent_icmp(&ip, &icmp));
  ASSERT_EQ(icmp.type, 0);
  wire_clear(&t);
  ASSERT_EQ(udp_send(&t.net, PEER2_IP, peer_mac, 7, 7, (const uint8_t *)"x", 1),
            NET_OK);
  datagram(PEER_IP, t.net.ipv4_addr, OPEN_PORT);
  ASSERT_EQ(delivered, 1);
  itest_advance(&t, 600000u, 1000);
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

/* REQ-IPv4-072, 046, 047, 049: the link-layer broadcast carries only IP
 * broadcasts or multicasts; a datagram to the limited broadcast, or to the
 * subnet's, goes out in a frame for the broadcast MAC */
TEST(itest_ipv4_072_link_broadcast_needs_ip_broadcast) {
  peer_ip_t ip;
  up();
  ASSERT_EQ(
      udp_send(&t.net, PEER_IP, broadcast_mac, 7, 7, (const uint8_t *)"x", 1),
      NET_ERR_INVALID_PARAM);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(udp_send(&t.net, 0xFFFFFFFFu, broadcast_mac, 7, 7,
                     (const uint8_t *)"x", 1),
            NET_OK);
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, broadcast_mac, 6);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip));
  ASSERT_EQ(ip.dst, 0xFFFFFFFFu);
  ASSERT_EQ(ip.src, t.net.ipv4_addr);
  ASSERT_EQ(udp_send(&t.net, 0x0A0000FFu, broadcast_mac, 7, 7,
                     (const uint8_t *)"x", 1),
            NET_OK);
  ASSERT_MEM_EQ(wire_sent(&t, 1)->data, broadcast_mac, 6);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 1), &ip));
  ASSERT_EQ(ip.dst, 0x0A0000FFu);
}

/* REQ-IPv4-050, REQ-ETH-010: a host with a multicast table is in the
 * all-hosts group from the start, whatever it joins and leaves, and takes
 * the frames for the group's MAC */
TEST(itest_ipv4_050_all_hosts_group) {
  static const uint8_t all_hosts_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01};
  uint8_t f[128], s2[64];
  peer_ip_t ip = peer_ip(PEER_IP, 0xE0000001u, 17);
  uint16_t n;
  uint32_t g;
  up();
  n = peer_udp(s2, &ip, 5000, OPEN_PORT, "x", 1);
  itest_receive(&t, f, peer_ipv4_frame(f, all_hosts_mac, peer_mac, &ip, s2, n));
  ASSERT_EQ(delivered, 1);
  /* joining it takes no slot; leaving it does nothing */
  ASSERT_EQ(ipv4_mcast_join(&t.net, IPV4_ALL_HOSTS), NET_OK);
  for (g = 0; g < NET_MAX_MCAST_GROUPS; g++)
    ASSERT_EQ(ipv4_mcast_join(&t.net, 0xE0000100u + g), NET_OK);
  ipv4_mcast_leave(&t.net, IPV4_ALL_HOSTS);
  itest_receive(&t, f, peer_ipv4_frame(f, all_hosts_mac, peer_mac, &ip, s2, n));
  ASSERT_EQ(delivered, 2);
}

/* REQ-IPv4-073 (deviation), REQ-IPv4-051: what the host multicasts — to
 * the group's MAC, which the sender passes — is never delivered back to
 * itself */
TEST(itest_ipv4_073_no_multicast_loopback) {
  static const uint8_t group_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};
  up();
  ASSERT_EQ(ipv4_mcast_join(&t.net, 0xE00000FBu), NET_OK);
  udp_send(&t.net, 0xE00000FBu, group_mac, OPEN_PORT, OPEN_PORT,
           (const uint8_t *)"x", 1);
  itest_poll(&t);
  ASSERT_EQ(delivered, 0);
}

/* REQ-IPv4-079, REQ-IPv4-077 (deviation: no dead-gateway detection): the
 * gateway is never pinged, nor probed in any other way, to check it */
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

/* REQ-ICMPv4-019..022, REQ-IPv4-054, 055 (deviation): Redirects, Host and
 * Network, are ignored and answered with nothing */
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

/* ── ICMP messages received, and the ones never sent ── */

/* An ICMP message of @p type and @p code from the peer to us, with
 * @p len bytes after its 8-byte header; its checksum made wrong if @p bad */
static void icmp_message(uint8_t type, uint8_t code, const void *data,
                         uint16_t len, int bad) {
  uint8_t msg[128], f[192];
  peer_ip_t ip = peer_ip(PEER_IP, t.net.ipv4_addr, 1);
  uint16_t n = peer_icmp(msg, type, code, NULL, data, len);
  if (bad)
    msg[n - 1] ^= 0x01;
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, msg, n));
}

/* A datagram sent from port 5000 to the peer's port 6000; what an ICMP
 * error about it quotes — its IP header and 8 bytes — into @p quote */
static void send_and_quote(uint8_t quote[28]) {
  wire_clear(&t);
  udp_send(&t.net, PEER_IP, peer_mac, 5000, 6000, (const uint8_t *)"hello", 5);
  memcpy(quote, wire_sent(&t, 0)->data + 14, 28);
  wire_clear(&t);
}

/* REQ-ICMPv4-011, 013, 014, 015: Destination Unreachable about a datagram
 * of ours goes up to its transport, whatever the code — Net, Host,
 * Protocol, Port, Source Route Failed, administratively prohibited */
TEST(itest_icmpv4_014_unreachable_codes_reported) {
  static const uint8_t codes[] = {0, 1, 2, 3, 5, 13};
  uint8_t quote[28];
  unsigned i;
  up();
  send_and_quote(quote);
  for (i = 0; i < sizeof(codes); i++) {
    icmp_message(3, codes[i], quote, 28, 0);
    ASSERT_EQ(errors, (int)i + 1);
    ASSERT_EQ(err.type, 3);
    ASSERT_EQ(err.code, codes[i]);
    ASSERT_EQ(err.local_port, 5000);
    ASSERT_EQ(err.dst_port, 6000);
    ASSERT_EQ(err.dst_ip, PEER_IP);
  }
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-ICMPv4-012, 042: an error is taken by the IP header it quotes; a
 * quote that is no whole IPv4 header — its header length less than 5
 * words, or cut short — names no transport, and the error is discarded */
TEST(itest_icmpv4_012_quote_must_be_an_ip_header) {
  uint8_t quote[28];
  up();
  send_and_quote(quote);
  icmp_message(3, 3, quote, 28, 0);
  ASSERT_EQ(errors, 1);
  ASSERT_EQ(err.quote_len, 28);
  quote[0] = 0x44; /* a header of 16 bytes */
  icmp_message(3, 3, quote, 28, 0);
  quote[0] = 0x40; /* a header of none */
  icmp_message(3, 3, quote, 28, 0);
  quote[0] = 0x4F; /* a header of 60 bytes, 28 of them here */
  icmp_message(3, 3, quote, 28, 0);
  quote[0] = 0x65; /* not IPv4 */
  icmp_message(3, 3, quote, 28, 0);
  quote[0] = 0x45;
  icmp_message(3, 3, quote, 19, 0); /* less than a header */
  ASSERT_EQ(errors, 1);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-ICMPv4-041: an error is parsed where it lies: the quote its
 * transport is handed points into the application's RX buffer */
TEST(itest_icmpv4_041_error_parsed_in_place) {
  uint8_t quote[28];
  up();
  send_and_quote(quote);
  icmp_message(3, 3, quote, 28, 0);
  ASSERT_EQ(errors, 1);
  ASSERT_TRUE(err.quote == t.rx_buf + 14 + 20 + 8);
  ASSERT_MEM_EQ(err.quote, quote, 28);
}

/* REQ-ICMPv4-031, 033: the checksum is checked over the whole message —
 * header and data — before anything else: an Echo Request or an error with
 * one bit of its data wrong is discarded */
TEST(itest_icmpv4_031_bad_checksum_discarded) {
  uint8_t quote[28];
  up();
  send_and_quote(quote);
  icmp_message(8, 0, "ping", 4, 1);
  icmp_message(3, 3, quote, 28, 1);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(errors, 0);
  icmp_message(8, 0, "ping", 4, 0);
  ASSERT_EQ(t.wire.tx_count, 1);
  icmp_message(3, 3, quote, 28, 0);
  ASSERT_EQ(errors, 1);
}

/* REQ-ICMPv4-040, REQ-ICMPv4-010 (deviation: no ping client): a message of
 * a type the host does not implement — unknown, Timestamp, Information
 * Request, an Echo Reply nobody asked for — is discarded without a word */
TEST(itest_icmpv4_040_unknown_types_discarded) {
  static const uint8_t types[] = {42, 255, 13, 14, 15, 16, 0, 9, 10};
  static const uint8_t body[12] = {0};
  unsigned i;
  up();
  wire_clear(&t);
  for (i = 0; i < sizeof(types); i++)
    icmp_message(types[i], 0, body, sizeof(body), 0);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(errors, 0);
  ASSERT_EQ(delivered, 0);
  icmp_message(8, 0, "ping", 4, 0); /* still alive */
  ASSERT_EQ(t.wire.tx_count, 1);
}

/* REQ-ICMPv4-009: an Echo Request to a broadcast address or a group is
 * not answered */
TEST(itest_icmpv4_009_no_echo_reply_to_many) {
  static const uint8_t all_hosts_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01};
  static const uint8_t rest[4] = {0, 1, 0, 1};
  static const uint32_t many[] = {0xFFFFFFFFu, 0x0A0000FFu, 0x0AFFFFFFu,
                                  0xE0000001u};
  uint8_t msg[32], f[64];
  unsigned i;
  up();
  wire_clear(&t);
  for (i = 0; i < sizeof(many) / sizeof(many[0]); i++) {
    peer_ip_t ip = peer_ip(PEER_IP, many[i], 1);
    uint16_t n = peer_icmp(msg, 8, 0, rest, "ping", 4);
    itest_receive(&t, f,
                  peer_ipv4_frame(f, i == 3 ? all_hosts_mac : broadcast_mac,
                                  peer_mac, &ip, msg, n));
  }
  ASSERT_EQ(t.wire.tx_count, 0);
  echo_request(PEER_IP, t.net.ipv4_addr, 4);
  ASSERT_EQ(t.wire.tx_count, 1);
}

/* REQ-ICMPv4-028, 048: a Source Quench is discarded — nothing goes up,
 * nothing is answered — and nothing reacts to it: the next datagrams to
 * that destination go out at once, as before (no RFC 1016 delay) */
TEST(itest_icmpv4_028_source_quench_changes_nothing) {
  uint8_t quote[28];
  int i;
  up();
  send_and_quote(quote);
  for (i = 0; i < 5; i++)
    icmp_message(4, 0, quote, 28, 0);
  ASSERT_EQ(errors, 0);
  ASSERT_EQ(t.wire.tx_count, 0);
  for (i = 0; i < 5; i++)
    ASSERT_EQ(udp_send(&t.net, PEER_IP, peer_mac, 5000, 6000,
                       (const uint8_t *)"hello", 5),
              NET_OK);
  ASSERT_EQ(t.wire.tx_count, 5);
}

/* REQ-ICMPv4-037: no error is sent about a fragment that is not the
 * first: fragments of a datagram for a closed port, or of an unknown
 * protocol, draw nothing while they are fragments; reassembled, the
 * datagram draws one error, quoting fragment zero */
TEST(itest_icmpv4_037_no_error_about_a_fragment) {
  static uint8_t reasm[IPV4_REASSEMBLY_BUFFER(1500)];
  static uint8_t data[1000];
  uint8_t f[1600];
  peer_ip_t ip = peer_ip(PEER_IP, 0, 17), rip;
  peer_icmp_t icmp;
  uint16_t n;
  up();
  ip.dst = t.net.ipv4_addr;
  seg_len = peer_udp(seg, &ip, 5000, CLOSED_PORT, data, sizeof(data));
  wire_clear(&t);
  fragment(512, 496, 0, 90); /* no buffer: every fragment is dropped */
  fragment(0, 512, 1, 90);
  ip.proto = 253; /* an unknown protocol, in fragments */
  ip.id = 91;
  ip.mf = 1;
  n = peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, data, 512);
  itest_receive(&t, f, n);
  ip.mf = 0;
  ip.frag_offset = 512;
  n = peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, data, 96);
  itest_receive(&t, f, n);
  ASSERT_EQ(t.wire.tx_count, 0);

  ASSERT_EQ(ipv4_set_reassembly(&t.net, reasm, sizeof(reasm)), NET_OK);
  fragment(512, 496, 0, 92);
  ASSERT_EQ(t.wire.tx_count, 0);
  fragment(0, 512, 1, 92);
  ASSERT_TRUE(sent_icmp(&rip, &icmp)); /* one error, about the whole */
  ASSERT_EQ(icmp.type, 3);
  ASSERT_EQ(icmp.code, 3);
  ASSERT_EQ(peer_get16(icmp.data + 4), 92);         /* its ID */
  ASSERT_EQ(peer_get16(icmp.data + 6) & 0x1FFF, 0); /* offset 0 */
  ASSERT_EQ(peer_get16(icmp.data + 22), CLOSED_PORT);
}

/* The ICMP messages among the frames sent: how many, and in @p other how
 * many of them are not Destination Unreachable with code 2 or 3 */
static int icmp_sent(int *other) {
  peer_ip_t ip;
  peer_icmp_t icmp;
  uint16_t i;
  int n = 0;
  *other = 0;
  for (i = 0; wire_sent(&t, i); i++) {
    if (!peer_parse_ipv4(wire_sent(&t, i), &ip) || !peer_parse_icmp(&ip, &icmp))
      continue;
    n++;
    if (icmp.type != 3 || (icmp.code != 2 && icmp.code != 3))
      (*other)++;
  }
  return n;
}

/* REQ-ICMPv4-023, 026, 027, REQ-ICMPv4-030 (deviation): what a router
 * would answer with a Redirect, Time Exceeded in transit, Source Quench
 * or Parameter Problem draws none of them from the host: a datagram for
 * another host, datagrams whose TTL has run out, a burst, a malformed
 * option.  The only errors sent are Protocol and Port Unreachable. */
TEST(itest_icmpv4_023_only_host_errors_sent) {
  static const uint8_t bad_option[4] = {0x9E, 40, 0, 0};
  uint8_t f[128], s2[64];
  peer_ip_t ip = peer_ip(PEER_IP, 0, 17);
  uint16_t n;
  int i, other;
  up();
  wire_clear(&t);
  ip.dst = t.net.ipv4_addr;
  n = peer_udp(s2, &ip, 5000, CLOSED_PORT, "x", 1);
  ip.ttl = 0;
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, s2, n));
  ip.ttl = 1;
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, s2, n));
  ip.ttl = 64;
  for (i = 0; i < 10; i++)
    itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, s2, n));
  ip.options = bad_option;
  ip.options_len = 4;
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, s2, n));
  ip.options_len = 0;
  ip.proto = 253;
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, s2, n));
  itest_receive(
      &t, f,
      peer_udp_frame(f, &t.net, PEER_IP, PEER2_IP, 5000, CLOSED_PORT, "x", 1));
  itest_receive(
      &t, f,
      peer_udp_frame(f, &t.net, PEER_IP, REMOTE_IP, 5000, CLOSED_PORT, "x", 1));
  itest_advance(&t, 120000, 1000);
  ASSERT_EQ(icmp_sent(&other), 14);
  ASSERT_EQ(other, 0);
  ASSERT_EQ(t.wire.tx_count, 14);
}

int main(void) {
  fprintf(stderr, "=== itest_ipv4 ===\n");
  RUN_TEST(itest_ipv4_001_invalid_headers_discarded);
  RUN_TEST(itest_ipv4_007_total_length_bounds_the_datagram);
  RUN_TEST(itest_ipv4_018_protocol_dispatch);
  RUN_TEST(itest_ipv4_042_any_tos_and_ttl_accepted);
  RUN_TEST(itest_ipv4_043_never_forwards);
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
  RUN_TEST(itest_ipv4_024_reassembly);
  RUN_TEST(itest_ipv4_024_larger_than_a_frame);
  RUN_TEST(itest_ipv4_024_too_large_dropped);
  RUN_TEST(itest_ipv4_024_one_at_a_time);
  RUN_TEST(itest_ipv4_024_no_buffer_no_reassembly);
  RUN_TEST(itest_ipv4_025_reassembly_timeout);
  RUN_TEST(itest_icmpv4_034_no_error_about_an_error);
  RUN_TEST(itest_ipv4_061_576_octet_datagrams);
  RUN_TEST(itest_ipv4_062_mms_r);
  RUN_TEST(itest_ipv4_063_mms_s);
  RUN_TEST(itest_ipv4_064_mtu_configurable);
  RUN_TEST(itest_ipv4_028_no_options_sent);
  RUN_TEST(itest_ipv4_026_options_skipped);
  RUN_TEST(itest_ipv4_067_source_routed_dropped);
  RUN_TEST(itest_ipv4_068_unknown_and_malformed_options);
  RUN_TEST(itest_ipv4_035_default_ttl);
  RUN_TEST(itest_ipv4_069_ttl_settable);
  RUN_TEST(itest_ipv4_041_tos_settable);
  RUN_TEST(itest_ipv4_083_atomic_id_ignored);
  RUN_TEST(itest_ipv4_070_never_to_or_from_unspecified);
  RUN_TEST(itest_ipv4_048_never_from_a_broadcast);
  RUN_TEST(itest_ipv4_075_next_hop_is_the_senders);
  RUN_TEST(itest_ipv4_078_works_without_a_gateway);
  RUN_TEST(itest_ipv4_071_never_loopback);
  RUN_TEST(itest_ipv4_072_link_broadcast_needs_ip_broadcast);
  RUN_TEST(itest_ipv4_050_all_hosts_group);
  RUN_TEST(itest_ipv4_073_no_multicast_loopback);
  RUN_TEST(itest_ipv4_079_never_pings_the_gateway);
  RUN_TEST(itest_icmpv4_008_large_echo_truncated);
  RUN_TEST(itest_icmpv4_019_redirect_ignored);
  RUN_TEST(itest_icmpv4_043_quote_unchanged);
  RUN_TEST(itest_icmpv4_045_address_mask_ignored);
  RUN_TEST(itest_icmpv4_014_unreachable_codes_reported);
  RUN_TEST(itest_icmpv4_012_quote_must_be_an_ip_header);
  RUN_TEST(itest_icmpv4_041_error_parsed_in_place);
  RUN_TEST(itest_icmpv4_031_bad_checksum_discarded);
  RUN_TEST(itest_icmpv4_040_unknown_types_discarded);
  RUN_TEST(itest_icmpv4_009_no_echo_reply_to_many);
  RUN_TEST(itest_icmpv4_028_source_quench_changes_nothing);
  RUN_TEST(itest_icmpv4_037_no_error_about_a_fragment);
  RUN_TEST(itest_icmpv4_023_only_host_errors_sent);
  ITEST_REPORT();
  return test_failures;
}
