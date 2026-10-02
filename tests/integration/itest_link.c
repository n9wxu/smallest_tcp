/**
 * @file itest_link.c
 * @brief Ethernet, ARP, UDP sending and the checksum API, black box.
 */

#include "arp.h"
#include "itest.h"
#include "net_cksum.h"
#include "udp.h"
#include <string.h>

#if NET_USE_IPV6
#include "ipv6.h"
#endif

static itest_t t;
static int delivered;
static const uint8_t *seen_data, *seen_mac; /* what the handler was given */
static int errors;

static void on_datagram(net_t *net, uint32_t src_ip, uint16_t src_port,
                        const uint8_t *src_mac, const uint8_t *data,
                        uint16_t len) {
  (void)net;
  (void)src_ip;
  (void)src_port;
  (void)len;
  seen_data = data;
  seen_mac = src_mac;
  delivered++;
}

static void on_error(net_t *net, const udp_icmp_error_t *e) {
  (void)net;
  (void)e;
  errors++;
}

#define OPEN_PORT 7000
#define CLOSED_PORT 7001
static const udp_port_entry_t ports[] = {{OPEN_PORT, on_datagram}};

/* A station that is neither the stack nor the peer */
static const uint8_t other_mac[6] = {0x02, 0x4F, 0x54, 0x48, 0x45, 0x52};
static const uint8_t zero_mac[6] = {0};

static void up(void) {
  itest_up(&t, 1514, 1514);
  udp_set_ports(&t.net, ports, 1);
  udp_set_error_handler(&t.net, on_error);
  delivered = errors = 0;
}

/* A one-byte UDP datagram for OPEN_PORT from the peer to the IP address
 * @p dst, in a frame for @p dst_mac; @return the frame's length */
static uint16_t datagram_frame(uint8_t *f, const uint8_t *dst_mac,
                               uint32_t dst) {
  uint8_t seg[64];
  peer_ip_t ip = peer_ip(PEER_IP, dst, 17);
  uint16_t n = peer_udp(seg, &ip, 5000, OPEN_PORT, "x", 1);
  return peer_ipv4_frame(f, dst_mac, peer_mac, &ip, seg, n);
}

/* An ARP request from the peer for our address */
static uint16_t arp_request_frame(uint8_t *f) {
  return peer_arp_frame(f, broadcast_mac, 1, peer_mac, PEER_IP, zero_mac,
                        t.net.ipv4_addr);
}

/* ── Ethernet ── */

/* REQ-ETH-001, 002, 003: a frame for our MAC or for the broadcast address
 * is taken; one for another station, or for a group we have not joined, is
 * not */
TEST(itest_eth_001_frames_for_us_taken) {
  static const uint8_t unjoined_mac[6] = {0x01, 0x00, 0x5E, 0x01, 0x02, 0x03};
  uint8_t f[128];
  up();
  itest_receive(&t, f, datagram_frame(f, t.net.mac, t.net.ipv4_addr));
  ASSERT_EQ(delivered, 1);
  itest_receive(&t, f, datagram_frame(f, broadcast_mac, 0xFFFFFFFFu));
  ASSERT_EQ(delivered, 2);
  itest_receive(&t, f, datagram_frame(f, other_mac, t.net.ipv4_addr));
  itest_receive(&t, f, datagram_frame(f, unjoined_mac, t.net.ipv4_addr));
  ASSERT_EQ(delivered, 2);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-ETH-004, 005, 006, 008, 009, REQ-ETH-017 (deviation): the type field,
 * big-endian at offset 12, chooses the protocol — 0x0800 IPv4, 0x0806 ARP;
 * any other EtherType, an IEEE 802.3 length and a runt are dropped without
 * a word */
TEST(itest_eth_005_dispatch_by_ethertype) {
  static const uint16_t not_ours[] = {
      0x8100, /* a VLAN tag */
      0x88B5, /* an experimental EtherType */
      0x0008, /* IPv4's, the bytes swapped */
      0x05DC, /* an IEEE 802.3 length: 1500 */
      0x001D, /* an IEEE 802.3 length: this frame's payload */
  };
  uint8_t f[128];
  uint16_t n, i;
  up();
  n = datagram_frame(f, t.net.mac, t.net.ipv4_addr);
  itest_receive(&t, f, n);
  ASSERT_EQ(delivered, 1); /* 0x0800: to IPv4 and on to UDP */
  for (i = 0; i < sizeof(not_ours) / sizeof(not_ours[0]); i++) {
    peer_put16(f + 12, not_ours[i]);
    itest_receive(&t, f, n);
  }
  itest_receive(&t, f, 13); /* less than a header */
  itest_receive(&t, f, 1);
  ASSERT_EQ(delivered, 1);
  ASSERT_EQ(t.wire.tx_count, 0);

  n = arp_request_frame(f);
  itest_receive(&t, f, n);
  ASSERT_EQ(t.wire.tx_count, 1); /* 0x0806: to ARP, which answers */
  peer_put16(f + 12, 0x0608);
  itest_receive(&t, f, n);
  ASSERT_EQ(t.wire.tx_count, 1);
}

/* REQ-ETH-011, 012, 013, 014: a frame sent goes to the MAC the sender
 * names, from our MAC, with EtherType 0x0800 for IPv4 and 0x0806 for ARP */
TEST(itest_eth_011_header_sent) {
  const wire_frame_t *f;
  up();
  ASSERT_EQ(udp_send(&t.net, PEER_IP, other_mac, 7, 7, (const uint8_t *)"y", 1),
            NET_OK);
  f = wire_sent(&t, 0);
  ASSERT_MEM_EQ(f->data, other_mac, 6);
  ASSERT_MEM_EQ(f->data + 6, t.net.mac, 6);
  ASSERT_EQ(peer_get16(f->data + 12), 0x0800);
  ASSERT_EQ(arp_request(&t.net, PEER2_IP), NET_OK);
  f = wire_sent(&t, 1);
  ASSERT_MEM_EQ(f->data, broadcast_mac, 6);
  ASSERT_MEM_EQ(f->data + 6, t.net.mac, 6);
  ASSERT_EQ(peer_get16(f->data + 12), 0x0806);
}

/* REQ-ETH-018: the payload is the frame less its 14-byte header: an ARP
 * request one byte short is no ARP packet; padded to the 60-byte minimum
 * frame it is one */
TEST(itest_eth_018_payload_is_the_rest_of_the_frame) {
  uint8_t f[128];
  uint16_t n;
  up();
  memset(f, 0xA5, sizeof(f));
  n = arp_request_frame(f);
  itest_receive(&t, f, (uint16_t)(n - 1));
  ASSERT_EQ(t.wire.tx_count, 0);
  itest_receive(&t, f, n);
  ASSERT_EQ(t.wire.tx_count, 1);
  itest_receive(&t, f, 60);
  ASSERT_EQ(t.wire.tx_count, 2);
}

/* REQ-ETH-019, REQ-IPv4-056: a received frame is parsed where it lies: what
 * a handler is given points into the application's RX buffer */
TEST(itest_eth_019_parsed_in_the_rx_buffer) {
  uint8_t f[128];
  up();
  itest_receive(&t, f, datagram_frame(f, t.net.mac, t.net.ipv4_addr));
  ASSERT_EQ(delivered, 1);
  ASSERT_TRUE(seen_mac == t.rx_buf + 6);
  ASSERT_TRUE(seen_data == t.rx_buf + 14 + 20 + 8);
}

/* REQ-ETH-020, REQ-IPv4-057: a frame is built in the application's TX
 * buffer — the Ethernet header first, the IPv4 header at offset 14 — and
 * sent from there */
TEST(itest_eth_020_built_in_the_tx_buffer) {
  const wire_frame_t *f;
  peer_ip_t ip;
  up();
  ASSERT_EQ(udp_send(&t.net, PEER_IP, peer_mac, 7, 7, (const uint8_t *)"y", 1),
            NET_OK);
  f = wire_sent(&t, 0);
  ASSERT_EQ(f->len, 14 + 20 + 8 + 1);
  ASSERT_MEM_EQ(t.tx_buf, f->data, f->len);
  ASSERT_TRUE(peer_parse_ipv4(f, &ip));
  ASSERT_EQ(t.tx_buf[14] >> 4, 4);
}

/* REQ-ETH-024: an address ARP has not resolved is no error: requests that
 * nobody answers report nothing to the application, and a send with a MAC
 * goes out */
TEST(itest_eth_024_unresolved_address_is_no_error) {
  uint16_t i;
  up();
  t.net.gateway_mac_valid = 0;
  for (i = 0; i < 5; i++) {
    arp_request(&t.net, PEER2_IP);
    itest_advance(&t, 1000, 100);
  }
  ASSERT_EQ(t.wire.tx_count, 5);
  for (i = 0; i < 5; i++)
    ASSERT_EQ(peer_get16(wire_sent(&t, i)->data + 12), 0x0806);
  ASSERT_EQ(errors, 0);
  ASSERT_EQ(
      udp_send(&t.net, PEER2_IP, other_mac, 7, 7, (const uint8_t *)"y", 1),
      NET_OK);
}

#if NET_USE_IPV6
/* ── The peer over IPv6 ── */

static int delivered6;

static void on_datagram6(net_t *net, const uint8_t *src_ip, uint16_t src_port,
                         const uint8_t *src_mac, const uint8_t *data,
                         uint16_t len) {
  (void)net;
  (void)src_ip;
  (void)src_port;
  (void)src_mac;
  (void)data;
  (void)len;
  delivered6++;
}

static const udp6_port_entry_t ports6[] = {{OPEN_PORT, on_datagram6}};
static const uint8_t peer_ll[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                    0,    0,    0, 0, 0, 0, 0, 0x99};
static uint8_t our_ll[16];

/* IPv6 started, the link-local address past Duplicate Address Detection */
static void up6(void) {
  up();
  udp6_set_ports(&t.net, ports6, 1);
  ipv6_start(&t.net);
  itest_advance(&t, 15000, 100);
  ipv6_link_local_from_mac(t.net.mac, our_ll);
  delivered6 = 0;
  wire_clear(&t);
}

/* The checksum of the UDP datagram at @p udp over the IPv6 pseudo-header
 * (RFC 8200 §8.1): source, destination, the upper-layer length in 32 bits,
 * three zero octets and the next header */
static uint16_t peer_udp6_cksum(const uint8_t *src, const uint8_t *dst,
                                const uint8_t *udp, uint16_t ulen) {
  static uint8_t pseudo[40 + 1500];
  memcpy(pseudo, src, 16);
  memcpy(pseudo + 16, dst, 16);
  peer_put32(pseudo + 32, ulen);
  peer_put32(pseudo + 36, 17);
  memcpy(pseudo + 40, udp, ulen);
  return peer_cksum(pseudo, (uint16_t)(40u + ulen));
}

/* An IPv6 UDP frame from the peer's link-local address to ours, port
 * OPEN_PORT, @p len bytes of data, the checksum field left 0.
 * @return the frame's length */
static uint16_t peer_udp6_frame(uint8_t *f, const void *data, uint16_t len) {
  uint8_t *ip = f + 14, *udp = ip + 40;
  uint16_t ulen = (uint16_t)(8u + len);
  memcpy(f, t.net.mac, 6);
  memcpy(f + 6, peer_mac, 6);
  peer_put16(f + 12, 0x86DD);
  memset(ip, 0, 40);
  ip[0] = 0x60;
  peer_put16(ip + 4, ulen);
  ip[6] = 17;
  ip[7] = 64;
  memcpy(ip + 8, peer_ll, 16);
  memcpy(ip + 24, our_ll, 16);
  peer_put16(udp, 5000);
  peer_put16(udp + 2, OPEN_PORT);
  peer_put16(udp + 4, ulen);
  peer_put16(udp + 6, 0);
  memcpy(udp + 8, data, len);
  return (uint16_t)(14u + 40u + ulen);
}

/* REQ-ETH-007, 015: EtherType 0x86DD is IPv6's, received and sent */
TEST(itest_eth_007_ipv6_ethertype) {
  uint8_t f[128];
  const wire_frame_t *s;
  uint16_t n;
  up6();
  n = peer_udp6_frame(f, "x", 1);
  peer_put16(f + 14 + 40 + 6, peer_udp6_cksum(peer_ll, our_ll, f + 54, 9));
  itest_receive(&t, f, n);
  ASSERT_EQ(delivered6, 1);
  peer_put16(f + 12, 0x0800); /* the same bytes are no IPv4 datagram */
  itest_receive(&t, f, n);
  ASSERT_EQ(delivered6, 1);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(udp6_send(&t.net, peer_ll, peer_mac, 7, 7, (const uint8_t *)"y", 1),
            NET_OK);
  s = wire_sent(&t, 0);
  ASSERT_MEM_EQ(s->data, peer_mac, 6);
  ASSERT_MEM_EQ(s->data + 6, t.net.mac, 6);
  ASSERT_EQ(peer_get16(s->data + 12), 0x86DD);
  ASSERT_EQ(s->data[14] >> 4, 6);
}
#endif

/* REQ-ETH-021: every frame sent is Ethernet II: an EtherType, not an 802.3
 * length, and never a trailer encapsulation */
TEST(itest_eth_021_ethernet_ii_only) {
  uint8_t f[128];
  static const uint8_t zero[6] = {0};
  uint16_t i;
  up();
  itest_receive(&t, f,
                peer_arp_frame(f, broadcast_mac, 1, peer_mac, PEER_IP, zero,
                               t.net.ipv4_addr));
  itest_receive(&t, f,
                peer_udp_frame(f, &t.net, PEER_IP, t.net.ipv4_addr, 5000,
                               CLOSED_PORT, "x", 1));
  udp_send(&t.net, PEER_IP, peer_mac, 7, 7, (const uint8_t *)"y", 1);
  ASSERT_EQ(t.wire.tx_count, 3);
  for (i = 0; i < t.wire.tx_count; i++) {
    uint16_t type = peer_get16(wire_sent(&t, i)->data + 12);
    ASSERT_TRUE(type == 0x0800 || type == 0x0806);
  }
}

/* REQ-ETH-022, REQ-ICMPv4-035: a datagram to our address in a link-layer
 * broadcast frame draws no ICMP error */
TEST(itest_eth_022_link_broadcast_draws_no_error) {
  uint8_t f[128], seg[64];
  peer_ip_t ip;
  uint16_t n;
  up();
  ip = peer_ip(PEER_IP, t.net.ipv4_addr, 17);
  n = peer_udp(seg, &ip, 5000, CLOSED_PORT, "x", 1);
  itest_receive(&t, f,
                peer_ipv4_frame(f, broadcast_mac, peer_mac, &ip, seg, n));
  ASSERT_EQ(t.wire.tx_count, 0);
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, seg, n));
  ASSERT_EQ(t.wire.tx_count, 1); /* the same datagram, unicast: answered */
}

/* REQ-ETH-025 (RFC 1112 §7.3): a broadcast or multicast frame the host
 * sent itself, looped back by the medium, is not delivered */
TEST(itest_eth_025_own_frames_not_delivered) {
  uint8_t f[128], seg[64];
  peer_ip_t ip;
  uint16_t n;
  up();
  ip = peer_ip(PEER_IP, 0xFFFFFFFFu, 17);
  n = peer_udp(seg, &ip, 5000, OPEN_PORT, "x", 1);
  itest_receive(&t, f,
                peer_ipv4_frame(f, broadcast_mac, t.net.mac, &ip, seg, n));
  ASSERT_EQ(delivered, 0);
  itest_receive(&t, f,
                peer_ipv4_frame(f, broadcast_mac, peer_mac, &ip, seg, n));
  ASSERT_EQ(delivered, 1);
}

/* ── ARP ── */

/* REQ-ARP-001, 002, 003, 040: a request for our address is answered,
 * unicast, with our MAC and address */
TEST(itest_arp_001_request_for_our_address_answered) {
  uint8_t f[64];
  static const uint8_t zero[6] = {0};
  peer_arp_t a;
  itest_up(&t, 1514, 1514);
  itest_receive(&t, f,
                peer_arp_frame(f, broadcast_mac, 1, peer_mac, PEER_IP, zero,
                               t.net.ipv4_addr));
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, peer_mac, 6);
  ASSERT_TRUE(peer_parse_arp(wire_sent(&t, 0), &a));
  ASSERT_EQ(a.op, 2);
  ASSERT_MEM_EQ(a.sha, t.net.mac, 6);
  ASSERT_EQ(a.spa, t.net.ipv4_addr);
  ASSERT_EQ(a.tpa, PEER_IP);
}

/* REQ-ARP-001, 004: without an address (DHCP has not bound) a request for
 * 0.0.0.0 is no request for ours */
TEST(itest_arp_004_unconfigured_answers_nothing) {
  uint8_t f[64];
  static const uint8_t zero[6] = {0};
  itest_up(&t, 1514, 1514);
  t.net.ipv4_addr = 0;
  itest_receive(
      &t, f, peer_arp_frame(f, broadcast_mac, 1, peer_mac, PEER_IP, zero, 0));
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-ARP-011, 012, REQ-DHCPv4-049: the gateway's reply is learned; with
 * no gateway, a reply from 0.0.0.0 is no gateway's */
TEST(itest_arp_011_gateway_learned_only_from_the_gateway) {
  uint8_t f[64];
  static const uint8_t gw[6] = {0x02, 0x47, 0x57, 0x00, 0x00, 0x01};
  itest_up(&t, 1514, 1514);
  t.net.gateway_ipv4 = 0;
  t.net.gateway_mac_valid = 0;
  itest_receive(
      &t, f,
      peer_arp_frame(f, t.net.mac, 2, gw, 0, t.net.mac, t.net.ipv4_addr));
  ASSERT_FALSE(t.net.gateway_mac_valid);
  t.net.gateway_ipv4 = 0x0A0000FEu;
  itest_receive(&t, f,
                peer_arp_frame(f, t.net.mac, 2, gw, 0x0A0000FEu, t.net.mac,
                               t.net.ipv4_addr));
  ASSERT_TRUE(t.net.gateway_mac_valid);
  ASSERT_MEM_EQ(t.net.gateway_mac, gw, 6);
}

/* The gateway's ARP reply, received */
static void gateway_replies(const uint8_t mac[6]) {
  uint8_t f[64];
  itest_receive(&t, f,
                peer_arp_frame(f, t.net.mac, 2, mac, t.net.gateway_ipv4,
                               t.net.mac, t.net.ipv4_addr));
}

/* REQ-ARP-038: the gateway's MAC is flushed once it is out of date, and a
 * reply from the gateway refreshes it */
TEST(itest_arp_038_gateway_mac_expires) {
  static const uint8_t gw[6] = {0x02, 0x47, 0x57, 0x00, 0x00, 0x01};
  up();
  t.net.gateway_ipv4 = 0x0A0000FEu;
  gateway_replies(gw);
  ASSERT_TRUE(t.net.gateway_mac_valid);
  itest_advance(&t, NET_ARP_GATEWAY_TIMEOUT_MS - 1000u, 1000);
  gateway_replies(gw); /* refreshed: the timeout starts again */
  itest_advance(&t, NET_ARP_GATEWAY_TIMEOUT_MS - 1000u, 1000);
  ASSERT_TRUE(t.net.gateway_mac_valid);
  itest_advance(&t, 2000, 1000);
  ASSERT_FALSE(t.net.gateway_mac_valid);
}

/* REQ-ARP-039: no more than one request a second for the same address */
TEST(itest_arp_039_no_flooding) {
  up();
  arp_request(&t.net, PEER_IP);
  arp_request(&t.net, PEER_IP);
  arp_request(&t.net, PEER_IP);
  ASSERT_EQ(t.wire.tx_count, 1);
  itest_advance(&t, 999, 100);
  arp_request(&t.net, PEER_IP);
  ASSERT_EQ(t.wire.tx_count, 1);
  itest_advance(&t, 1, 1);
  arp_request(&t.net, PEER_IP);
  ASSERT_EQ(t.wire.tx_count, 2);
}

/* REQ-ARP-025, 026, 041: on-link destinations are their own next hop,
 * off-link ones the gateway's — but the limited broadcast and multicast
 * groups always go straight to the link */
TEST(itest_arp_041_broadcast_and_multicast_next_hop) {
  up();
  t.net.gateway_ipv4 = 0x0A0000FEu;
  ASSERT_EQ(arp_next_hop(&t.net, PEER2_IP), PEER2_IP);
  ASSERT_EQ(arp_next_hop(&t.net, REMOTE_IP), 0x0A0000FEu);
  ASSERT_EQ(arp_next_hop(&t.net, 0xFFFFFFFFu), 0xFFFFFFFFu);
  ASSERT_EQ(arp_next_hop(&t.net, 0xE00000FBu), 0xE00000FBu);
}

/* ── UDP sending ── */

/* REQ-UDP-032, 033: never more than one Ethernet frame, whatever the
 * frame buffer: 1472 bytes of payload at most; DF is set (REQ-IPv4-023) */
TEST(itest_udp_032_one_ethernet_frame_at_most) {
  static uint8_t data[1473];
  peer_ip_t ip;
  peer_udp_t udp;
  itest_up(&t, 2048, 2048);
  ASSERT_EQ(udp_send(&t.net, PEER_IP, peer_mac, 7, 7, data, 1473),
            NET_ERR_BUF_TOO_SMALL);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(udp_send(&t.net, PEER_IP, peer_mac, 7, 7, data, 1472), NET_OK);
  ASSERT_EQ(wire_sent(&t, 0)->len, 1514);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip));
  ASSERT_TRUE(ip.df);
  ASSERT_TRUE(ip.header_cksum_ok);
  ASSERT_TRUE(peer_parse_udp(&ip, &udp));
  ASSERT_TRUE(udp.cksum_ok); /* REQ-UDP-009, 014 */
  ASSERT_EQ(udp.data_len, 1472);
}

/* REQ-UDP-032: the frame buffer is the other limit */
TEST(itest_udp_032_frame_buffer_limit) {
  static uint8_t data[300];
  itest_up(&t, 300, 300);
  ASSERT_EQ(udp_send(&t.net, PEER_IP, peer_mac, 7, 7, data, 259),
            NET_ERR_BUF_TOO_SMALL);
  ASSERT_EQ(udp_send(&t.net, PEER_IP, peer_mac, 7, 7, data, 258), NET_OK);
}

/* REQ-IPv4-058 (RFC 1122 §3.2.1.7): no datagram is sent with TTL 0 */
TEST(itest_ipv4_058_never_ttl_zero) {
  itest_up(&t, 1514, 1514);
  memcpy(t.net.tx.buf + UDP_PAYLOAD_OFFSET, "x", 1);
  ASSERT_EQ(udp_send_inplace(&t.net, PEER_IP, peer_mac, 7, 7, 1, 0),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* ── The checksum API ── */

/* REQ-CKSUM-006: pieces of any length add up to the one-shot checksum */
TEST(itest_cksum_006_pieces_of_any_length) {
  uint8_t data[23];
  uint16_t cut, oneshot;
  net_cksum_t c;
  for (cut = 0; cut < sizeof(data); cut++)
    data[cut] = (uint8_t)(0x31 * cut + 7);
  oneshot = net_cksum(data, sizeof(data));
  ASSERT_EQ(oneshot, peer_cksum(data, sizeof(data)));
  for (cut = 0; cut <= sizeof(data); cut++) {
    net_cksum_init(&c);
    net_cksum_add(&c, data, cut);
    net_cksum_add(&c, data + cut, (uint16_t)(sizeof(data) - cut));
    ASSERT_EQ(net_cksum_finalize(&c), oneshot);
  }
  net_cksum_init(&c); /* a word straddling two pieces */
  net_cksum_add(&c, data, 3);
  net_cksum_add_u16(&c, (uint16_t)(data[3] << 8 | data[4]));
  net_cksum_add(&c, data + 5, 18);
  ASSERT_EQ(net_cksum_finalize(&c), oneshot);
}

int main(void) {
  fprintf(stderr, "=== itest_link ===\n");
  RUN_TEST(itest_eth_001_frames_for_us_taken);
  RUN_TEST(itest_eth_005_dispatch_by_ethertype);
  RUN_TEST(itest_eth_011_header_sent);
  RUN_TEST(itest_eth_018_payload_is_the_rest_of_the_frame);
  RUN_TEST(itest_eth_019_parsed_in_the_rx_buffer);
  RUN_TEST(itest_eth_020_built_in_the_tx_buffer);
  RUN_TEST(itest_eth_024_unresolved_address_is_no_error);
#if NET_USE_IPV6
  RUN_TEST(itest_eth_007_ipv6_ethertype);
#endif
  RUN_TEST(itest_eth_021_ethernet_ii_only);
  RUN_TEST(itest_eth_022_link_broadcast_draws_no_error);
  RUN_TEST(itest_eth_025_own_frames_not_delivered);
  RUN_TEST(itest_arp_001_request_for_our_address_answered);
  RUN_TEST(itest_arp_004_unconfigured_answers_nothing);
  RUN_TEST(itest_arp_011_gateway_learned_only_from_the_gateway);
  RUN_TEST(itest_arp_038_gateway_mac_expires);
  RUN_TEST(itest_arp_039_no_flooding);
  RUN_TEST(itest_arp_041_broadcast_and_multicast_next_hop);
  RUN_TEST(itest_udp_032_one_ethernet_frame_at_most);
  RUN_TEST(itest_udp_032_frame_buffer_limit);
  RUN_TEST(itest_ipv4_058_never_ttl_zero);
  RUN_TEST(itest_cksum_006_pieces_of_any_length);
  ITEST_REPORT();
  return test_failures;
}
