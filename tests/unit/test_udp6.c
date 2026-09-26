/**
 * @file test_udp6.c
 * @brief Unit tests for UDP over IPv6 (RFC 768, RFC 8200 §8.1).
 *
 * Built with NET_USE_IPV6=1.  IPv4 UDP is covered by test_udp.
 */

#include "eth.h"
#include "icmpv6.h"
#include "ipv6.h"
#include "net.h"
#include "net_endian.h"
#include "test_main.h"
#include "udp.h"
#include <string.h>

#if !NET_USE_IPV6
#error "test_udp6 needs NET_USE_IPV6=1"
#endif

/* ── Stub MAC driver: records sent frames, peeks the injected frame ── */

#define MAX_SENT 4
static uint8_t sent[MAX_SENT][1514];
static uint16_t sent_len[MAX_SENT];
static int send_count;
static uint8_t rx_frame[1514];
static uint16_t rx_len;

static int stub_init(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_send(void *ctx, const uint8_t *f, uint16_t l) {
  (void)ctx;
  if (send_count < MAX_SENT) {
    memcpy(sent[send_count], f, l);
    sent_len[send_count] = l;
  }
  send_count++;
  return (int)l;
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

static const net_mac_t stub_drv = {
    .init = stub_init,
    .send = stub_send,
    .poll = stub_poll,
    .peek = stub_peek,
    .discard = stub_discard,
    .close = stub_close,
};

/* ── Addresses ────────────────────────────────────────────────────── */

static const uint8_t our_mac[6] = NET_DEFAULT_MAC;
static const uint8_t peer_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
static const uint8_t our_ll[16] = {0xFE, 0x80, 0, 0,    0,    0,    0,    0,
                                   0,    0,    0, 0xFF, 0xFE, 0xDE, 0xAD, 0x01};
static const uint8_t peer_ll[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                    0,    0,    0, 0, 0, 0, 0, 1};
static const uint8_t all_nodes[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                      0,    0,    0, 0, 0, 0, 0, 1};
static const uint8_t mac_all_nodes[6] = {0x33, 0x33, 0, 0, 0, 1};

/* ── Port table and handler spies ─────────────────────────────────── */

static int v6_calls, v4_calls;
static uint8_t got_src[16], got_mac[6];
static uint16_t got_sport, got_off, got_len;
static uint8_t got_data[64];

static void on_v4(net_t *n, uint32_t src_ip, uint16_t sport,
                  const uint8_t *src_mac, uint16_t off, uint16_t len) {
  (void)n;
  (void)src_ip;
  (void)sport;
  (void)src_mac;
  (void)off;
  (void)len;
  v4_calls++;
}

static void on_v6(net_t *n, const uint8_t *src_ip, uint16_t sport,
                  const uint8_t *src_mac, uint16_t off, uint16_t len) {
  v6_calls++;
  memcpy(got_src, src_ip, 16);
  memcpy(got_mac, src_mac, 6);
  got_sport = sport;
  got_off = off;
  got_len = len;
  n->mac_driver->peek(n->mac_ctx, off, got_data, len < 64 ? len : 64);
}

static const udp_port_entry_t ports[] = {{7, on_v4}, {9, on_v4}};
static const udp6_port_entry_t ports6[] = {{7, on_v6}}; /* 9: IPv4 only */

/* ── Fixture ──────────────────────────────────────────────────────── */

static uint8_t rx_buf[1514], tx_buf[1514];
static net_t net;

static void setup(void) {
  int ctx = 0;
  memset(sent, 0, sizeof(sent));
  send_count = v6_calls = v4_calls = 0;
  memset(got_src, 0, sizeof(got_src));
  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf), NULL,
           &stub_drv, &ctx);
  udp_ports.entries = ports;
  udp_ports.count = 2;
  udp6_ports.entries = ports6;
  udp6_ports.count = 1;
  ipv6_start(&net);
  ipv6_tick(&net, 1000);
  ipv6_tick(&net, 1000);
  send_count = 0;
}

/** Ethernet + IPv6 (+ optional 8-byte Hop-by-Hop) + UDP; checksum filled
 *  unless cksum_override >= 0.  Also installs the frame for peek(). */
static uint16_t build_udp6(uint8_t *f, const uint8_t *dst_mac,
                           const uint8_t *src, const uint8_t *dst,
                           uint16_t dport, const char *data, int hbh,
                           long cksum_override) {
  uint16_t dlen = (uint16_t)strlen(data);
  uint16_t ulen = (uint16_t)(8 + dlen);
  uint16_t ext = hbh ? 8 : 0;
  memcpy(f, dst_mac, 6);
  memcpy(f + 6, peer_mac, 6);
  net_write16be(f + 12, NET_ETHERTYPE_IPV6);
  uint8_t *ip = f + 14;
  ipv6_build(ip, (uint16_t)(ext + ulen), hbh ? IPV6_NH_HOPOPT : IPV6_NH_UDP,
             src, dst, 64);
  if (hbh) {
    memset(ip + 40, 0, 8);
    ip[40] = IPV6_NH_UDP;
    ip[42] = 1;
    ip[43] = 4;
  }
  uint8_t *u = ip + 40 + ext;
  net_write16be(u, 40000);
  net_write16be(u + 2, dport);
  net_write16be(u + 4, ulen);
  net_write16be(u + 6, 0);
  memcpy(u + 8, data, dlen);
  uint16_t c = ipv6_cksum(src, dst, IPV6_NH_UDP, u, ulen);
  net_write16be(u + 6, cksum_override >= 0 ? (uint16_t)cksum_override : c);
  uint16_t len = (uint16_t)(14 + 40 + ext + ulen);
  memcpy(rx_frame, f, len);
  rx_len = len;
  return len;
}

static void input(uint8_t *f, uint16_t len) { eth_input(&net, f, len); }

/* ══ Receive ══════════════════════════════════════════════════════ */

TEST(test_udp6_dispatch_to_handler6) {
  uint8_t f[256];
  setup();
  input(f, build_udp6(f, our_mac, peer_ll, our_ll, 7, "hello6", 0, -1));
  ASSERT_EQ(v6_calls, 1);
  ASSERT_EQ(v4_calls, 0);
  ASSERT_MEM_EQ(got_src, peer_ll, 16);
  ASSERT_MEM_EQ(got_mac, peer_mac, 6);
  ASSERT_EQ(got_sport, 40000);
  ASSERT_EQ(got_off, UDP6_PAYLOAD_OFFSET);
  ASSERT_EQ(got_len, 6);
  ASSERT_MEM_EQ(got_data, "hello6", 6);
  ASSERT_EQ(send_count, 0);
}

TEST(test_udp6_payload_offset_after_extension_header) {
  uint8_t f[256];
  setup();
  input(f, build_udp6(f, our_mac, peer_ll, our_ll, 7, "ext", 1, -1));
  ASSERT_EQ(v6_calls, 1);
  ASSERT_EQ(got_off, UDP6_PAYLOAD_OFFSET + 8);
  ASSERT_MEM_EQ(got_data, "ext", 3);
}

TEST(test_udp6_to_all_nodes_dispatched) {
  uint8_t f[256];
  setup();
  input(f, build_udp6(f, mac_all_nodes, peer_ll, all_nodes, 7, "mc", 0, -1));
  ASSERT_EQ(v6_calls, 1);
}

TEST(test_udp6_zero_checksum_dropped) {
  /* REQ-IPv6-045: the UDP checksum is mandatory over IPv6 */
  uint8_t f[256];
  setup();
  input(f, build_udp6(f, our_mac, peer_ll, our_ll, 7, "nock", 0, 0));
  ASSERT_EQ(v6_calls, 0);
  ASSERT_EQ(send_count, 0);
}

TEST(test_udp6_bad_checksum_dropped) {
  uint8_t f[256];
  setup();
  input(f, build_udp6(f, our_mac, peer_ll, our_ll, 7, "bad", 0, 0x1234));
  ASSERT_EQ(v6_calls, 0);
  ASSERT_EQ(send_count, 0);
}

TEST(test_udp6_bad_length_dropped) {
  uint8_t f[256];
  setup();
  uint16_t len = build_udp6(f, our_mac, peer_ll, our_ll, 7, "len", 0, -1);
  net_write16be(f + 54 + 4, 20); /* longer than the IPv6 payload */
  input(f, len);
  net_write16be(f + 54 + 4, 7); /* shorter than a UDP header */
  input(f, len);
  ASSERT_EQ(v6_calls, 0);
}

TEST(test_udp6_closed_port_unreachable) {
  uint8_t f[256];
  setup();
  uint16_t len = build_udp6(f, our_mac, peer_ll, our_ll, 1234, "x", 0, -1);
  input(f, len);
  ASSERT_EQ(send_count, 1);
  const uint8_t *ip = sent[0] + 14;
  const uint8_t *m = ip + 40;
  ASSERT_EQ(ip[6], IPV6_NH_ICMPV6);
  ASSERT_EQ(m[0], ICMPV6_DEST_UNREACH);
  ASSERT_EQ(m[1], ICMPV6_CODE_PORT_UNREACH);
  ASSERT_MEM_EQ(ip + 8, our_ll, 16);
  ASSERT_MEM_EQ(ip + 24, peer_ll, 16);
  ASSERT_MEM_EQ(m + 8, f + 14, (uint16_t)(len - 14)); /* whole datagram */
  ASSERT_EQ(ipv6_cksum(ip + 8, ip + 24, IPV6_NH_ICMPV6, m,
                       net_read16be(ip + 4)),
            0);
}

TEST(test_udp6_ipv4_only_port_is_closed_over_ipv6) {
  uint8_t f[256];
  setup();
  input(f, build_udp6(f, our_mac, peer_ll, our_ll, 9, "v4only", 0, -1));
  ASSERT_EQ(v4_calls, 0);
  ASSERT_EQ(send_count, 1);
  ASSERT_EQ(sent[0][54], ICMPV6_DEST_UNREACH);
}

TEST(test_udp6_closed_port_multicast_no_error) {
  uint8_t f[256];
  setup();
  input(f, build_udp6(f, mac_all_nodes, peer_ll, all_nodes, 1234, "x", 0, -1));
  ASSERT_EQ(send_count, 0);
}

/* ══ Send ═════════════════════════════════════════════════════════ */

TEST(test_udp6_send_frame) {
  setup();
  ASSERT_EQ(udp6_send(&net, peer_ll, peer_mac, 7, 40000,
                      (const uint8_t *)"reply", 5),
            NET_OK);
  ASSERT_EQ(send_count, 1);
  ASSERT_EQ(sent_len[0], UDP6_PAYLOAD_OFFSET + 5);
  const uint8_t *ip = sent[0] + 14;
  const uint8_t *u = ip + 40;
  ASSERT_MEM_EQ(sent[0], peer_mac, 6);
  ASSERT_MEM_EQ(sent[0] + 6, our_mac, 6);
  ASSERT_EQ(net_read16be(sent[0] + 12), NET_ETHERTYPE_IPV6);
  ASSERT_EQ(ip[0], 0x60);
  ASSERT_EQ(net_read16be(ip + 4), 13);
  ASSERT_EQ(ip[6], IPV6_NH_UDP);
  ASSERT_EQ(ip[7], NET_IPV6_DEFAULT_HOP_LIMIT);
  ASSERT_MEM_EQ(ip + 8, our_ll, 16);
  ASSERT_MEM_EQ(ip + 24, peer_ll, 16);
  ASSERT_EQ(net_read16be(u), 7);
  ASSERT_EQ(net_read16be(u + 2), 40000);
  ASSERT_EQ(net_read16be(u + 4), 13);
  ASSERT_NE(net_read16be(u + 6), 0);
  ASSERT_EQ(ipv6_cksum(ip + 8, ip + 24, IPV6_NH_UDP, u, 13), 0);
  ASSERT_MEM_EQ(u + 8, "reply", 5);
}

TEST(test_udp6_send_inplace_with_hop_limit) {
  setup();
  memcpy(net.tx.buf + UDP6_PAYLOAD_OFFSET, "zc", 2);
  ASSERT_EQ(udp6_send_inplace(&net, all_nodes, mac_all_nodes, 5353, 5353, 2,
                              255),
            NET_OK);
  ASSERT_EQ(send_count, 1);
  ASSERT_EQ(sent[0][14 + 7], 255);
  ASSERT_MEM_EQ(sent[0] + 14 + 8, our_ll, 16); /* link-scope group */
  ASSERT_MEM_EQ(sent[0] + UDP6_PAYLOAD_OFFSET, "zc", 2);
}

TEST(test_udp6_send_zero_checksum_sent_as_ffff) {
  uint8_t d[2] = {0, 0};
  setup();
  udp6_send(&net, peer_ll, peer_mac, 7, 40000, d, 2);
  /* A data word equal to that checksum makes the sum 0xFFFF, i.e. a
   * computed checksum of 0, which must go out as 0xFFFF */
  uint16_t c0 = net_read16be(sent[0] + 54 + 6);
  net_write16be(d, c0);
  send_count = 0;
  udp6_send(&net, peer_ll, peer_mac, 7, 40000, d, 2);
  ASSERT_EQ(net_read16be(sent[0] + 54 + 6), 0xFFFF);
}

TEST(test_udp6_send_without_source_address_fails) {
  int ctx = 0;
  send_count = 0;
  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf), NULL,
           &stub_drv, &ctx);
  ASSERT_NE(udp6_send(&net, peer_ll, peer_mac, 7, 7, (const uint8_t *)"x", 1),
            NET_OK);
  ASSERT_EQ(send_count, 0);
}

TEST(test_udp6_send_too_big_for_tx_buffer) {
  static uint8_t d[1500];
  setup();
  ASSERT_EQ(udp6_send(&net, peer_ll, peer_mac, 7, 7, d, sizeof(d)),
            NET_ERR_BUF_TOO_SMALL);
  ASSERT_EQ(send_count, 0);
}

int main(void) {
  fprintf(stderr, "=== UDP over IPv6 tests ===\n");
  RUN_TEST(test_udp6_dispatch_to_handler6);
  RUN_TEST(test_udp6_payload_offset_after_extension_header);
  RUN_TEST(test_udp6_to_all_nodes_dispatched);
  RUN_TEST(test_udp6_zero_checksum_dropped);
  RUN_TEST(test_udp6_bad_checksum_dropped);
  RUN_TEST(test_udp6_bad_length_dropped);
  RUN_TEST(test_udp6_closed_port_unreachable);
  RUN_TEST(test_udp6_ipv4_only_port_is_closed_over_ipv6);
  RUN_TEST(test_udp6_closed_port_multicast_no_error);
  RUN_TEST(test_udp6_send_frame);
  RUN_TEST(test_udp6_send_inplace_with_hop_limit);
  RUN_TEST(test_udp6_send_zero_checksum_sent_as_ffff);
  RUN_TEST(test_udp6_send_without_source_address_fails);
  RUN_TEST(test_udp6_send_too_big_for_tx_buffer);
  TEST_REPORT();
  return test_failures;
}
