/**
 * @file test_ipv6.c
 * @brief Unit tests for IPv6 (RFC 8200/4291), ICMPv6 (RFC 4443), the
 *        Neighbor Discovery responder (RFC 4861) and DAD (RFC 4862).
 *
 * Frames go in through eth_input(), so the Ethernet multicast filter and
 * the dispatch are exercised too.  Built with NET_USE_IPV6=1.
 */

#include "eth.h"
#include "icmpv6.h"
#include "ipv6.h"
#include "ndp.h"
#include "net.h"
#include "net_cksum.h"
#include "net_endian.h"
#include "test_main.h"
#include <string.h>

#if !NET_USE_IPV6
#error "test_ipv6 needs NET_USE_IPV6=1"
#endif

/* ── Stub MAC driver: records every sent frame ────────────────────── */

#define MAX_SENT 8
static uint8_t sent[MAX_SENT][1514];
static uint16_t sent_len[MAX_SENT];
static int send_count;

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
static int stub_peek(void *ctx, uint16_t o, uint8_t *b, uint16_t l) {
  (void)ctx;
  (void)o;
  (void)b;
  (void)l;
  return 0;
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

static const uint8_t our_mac[6] = NET_DEFAULT_MAC; /* 02:00:00:de:ad:01 */
static const uint8_t peer_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
/* fe80::ff:fede:ad01 — Modified EUI-64 of our_mac */
static const uint8_t our_ll[16] = {0xFE, 0x80, 0, 0,    0,    0,    0,    0,
                                   0,    0,    0, 0xFF, 0xFE, 0xDE, 0xAD, 0x01};
static const uint8_t peer_ll[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                    0,    0,    0, 0, 0, 0, 0, 1};
static const uint8_t other_ll[16] = {0xFE, 0x80, 0, 0, 0, 0, 0,    0,
                                     0,    0,    0, 0, 0, 0, 0x12, 0x34};
static const uint8_t all_nodes[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                      0,    0,    0, 0, 0, 0, 0, 1};
/* ff02::1:ffde:ad01 — our solicited-node group */
static const uint8_t our_snm[16] = {0xFF, 0x02, 0, 0, 0,    0,    0,    0,
                                    0,    0,    0, 1, 0xFF, 0xDE, 0xAD, 0x01};
static const uint8_t unspec[16] = {0};
static const uint8_t mac_all_nodes[6] = {0x33, 0x33, 0, 0, 0, 1};
static const uint8_t mac_our_snm[6] = {0x33, 0x33, 0xFF, 0xDE, 0xAD, 0x01};

/* ── Fixture ──────────────────────────────────────────────────────── */

static uint8_t rx_buf[1514], tx_buf[1514];
static net_t net;

static void reset_sent(void) {
  memset(sent, 0, sizeof(sent));
  memset(sent_len, 0, sizeof(sent_len));
  send_count = 0;
}

static void setup_cap(uint16_t tx_cap) {
  int ctx = 0;
  reset_sent();
  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, tx_cap, NULL, &stub_drv,
           &ctx);
}

/** Started, DAD finished: the link-local address is PREFERRED. */
static void setup_up(void) {
  setup_cap(sizeof(tx_buf));
  ipv6_start(&net);
  ipv6_tick(&net, 1000); /* random delay <= 1 s: DAD probe sent */
  ipv6_tick(&net, 1000); /* RetransTimer: DAD done */
  reset_sent();
}

/* ── Frame building ───────────────────────────────────────────────── */

/** Ethernet + IPv6 header + payload bytes (copied). */
static uint16_t build_ip6(uint8_t *f, const uint8_t *dst_mac,
                          const uint8_t *src, const uint8_t *dst, uint8_t nh,
                          uint8_t hlim, const uint8_t *payload,
                          uint16_t plen) {
  memcpy(f, dst_mac, 6);
  memcpy(f + 6, peer_mac, 6);
  net_write16be(f + 12, NET_ETHERTYPE_IPV6);
  uint8_t *ip = f + 14;
  memset(ip, 0, 40);
  ip[0] = 0x60;
  net_write16be(ip + 4, plen);
  ip[6] = nh;
  ip[7] = hlim;
  memcpy(ip + 8, src, 16);
  memcpy(ip + 24, dst, 16);
  memcpy(ip + 40, payload, plen);
  return (uint16_t)(14 + 40 + plen);
}

/** As build_ip6 for ICMPv6, filling the checksum. */
static uint16_t build_icmp6(uint8_t *f, const uint8_t *dst_mac,
                            const uint8_t *src, const uint8_t *dst,
                            uint8_t hlim, uint8_t *icmp, uint16_t ilen) {
  icmp[2] = icmp[3] = 0;
  uint16_t c = ipv6_cksum(src, dst, IPV6_NH_ICMPV6, icmp, ilen);
  net_write16be(icmp + 2, c);
  return build_ip6(f, dst_mac, src, dst, IPV6_NH_ICMPV6, hlim, icmp, ilen);
}

static uint16_t echo_req(uint8_t *icmp, const char *data) {
  uint16_t n = (uint16_t)strlen(data);
  icmp[0] = ICMPV6_ECHO_REQUEST;
  icmp[1] = 0;
  net_write16be(icmp + 4, 0x1234);
  net_write16be(icmp + 6, 0x0001);
  memcpy(icmp + 8, data, n);
  return (uint16_t)(8 + n);
}

/** Neighbor Solicitation for target, with an SLLA option if slla. */
static uint16_t ns_msg(uint8_t *icmp, const uint8_t *target,
                       const uint8_t *slla) {
  memset(icmp, 0, 32);
  icmp[0] = ICMPV6_NS;
  memcpy(icmp + 8, target, 16);
  if (!slla)
    return 24;
  icmp[24] = NDP_OPT_SLLA;
  icmp[25] = 1;
  memcpy(icmp + 26, slla, 6);
  return 32;
}

/** Neighbor Advertisement for target with a TLLA option. */
static uint16_t na_msg(uint8_t *icmp, const uint8_t *target, uint8_t flags) {
  memset(icmp, 0, 32);
  icmp[0] = ICMPV6_NA;
  icmp[4] = flags;
  memcpy(icmp + 8, target, 16);
  icmp[24] = NDP_OPT_TLLA;
  icmp[25] = 1;
  memcpy(icmp + 26, peer_mac, 6);
  return 32;
}

static void input(uint8_t *f, uint16_t len) { eth_input(&net, f, len); }

/* ── Checking sent frames ─────────────────────────────────────────── */

static const uint8_t *s_ip(int i) { return sent[i] + 14; }
static const uint8_t *s_icmp(int i) { return sent[i] + 54; }
static uint16_t s_plen(int i) { return net_read16be(sent[i] + 14 + 4); }

/** The sent frame is IPv6/ICMPv6 with a valid checksum. */
static int s_icmp_ok(int i) {
  const uint8_t *ip = s_ip(i);
  return net_read16be(sent[i] + 12) == NET_ETHERTYPE_IPV6 &&
         (ip[0] >> 4) == 6 && ip[6] == IPV6_NH_ICMPV6 &&
         sent_len[i] == 54 + s_plen(i) &&
         ipv6_cksum(ip + 8, ip + 24, IPV6_NH_ICMPV6, ip + 40, s_plen(i)) == 0;
}

/* ══ Addressing ═══════════════════════════════════════════════════ */

TEST(test_ll_from_mac_rfc4291_example) {
  static const uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  static const uint8_t want[16] = {0xFE, 0x80, 0,    0,    0,    0,
                                   0,    0,    0x02, 0x11, 0x22, 0xFF,
                                   0xFE, 0x33, 0x44, 0x55};
  uint8_t a[16];
  ipv6_link_local_from_mac(mac, a);
  ASSERT_MEM_EQ(a, want, 16);
}

TEST(test_ll_from_mac_local_bit_flipped) {
  uint8_t a[16];
  ipv6_link_local_from_mac(our_mac, a);
  ASSERT_MEM_EQ(a, our_ll, 16);
}

TEST(test_solicited_node_group) {
  uint8_t g[16];
  ipv6_solicited_node(our_ll, g);
  ASSERT_MEM_EQ(g, our_snm, 16);
}

TEST(test_multicast_mac_mapping) {
  uint8_t mac[6];
  ipv6_mcast_mac(our_snm, mac);
  ASSERT_MEM_EQ(mac, mac_our_snm, 6);
  ipv6_mcast_mac(all_nodes, mac);
  ASSERT_MEM_EQ(mac, mac_all_nodes, 6);
}

TEST(test_address_classes) {
  static const uint8_t febf[16] = {0xFE, 0xBF, 0, 0, 0, 0, 0, 0,
                                   0,    0,    0, 0, 0, 0, 0, 1};
  static const uint8_t fec0[16] = {0xFE, 0xC0, 0, 0, 0, 0, 0, 0,
                                   0,    0,    0, 0, 0, 0, 0, 1};
  ASSERT_TRUE(ipv6_is_multicast(all_nodes));
  ASSERT_FALSE(ipv6_is_multicast(our_ll));
  ASSERT_TRUE(ipv6_is_link_local(our_ll));
  ASSERT_TRUE(ipv6_is_link_local(febf));
  ASSERT_FALSE(ipv6_is_link_local(fec0));
  ASSERT_TRUE(ipv6_is_unspecified(unspec));
  ASSERT_FALSE(ipv6_is_unspecified(peer_ll));
}

/* ══ Checksum ═════════════════════════════════════════════════════ */

TEST(test_cksum_known_answer) {
  /* Scapy: IPv6(src=fe80::1, dst=fe80::ff:fede:ad01)/
   *        ICMPv6EchoRequest(id=0x1234, seq=1, data=b"abcd") -> 0xfeda */
  uint8_t icmp[12] = {0x80, 0, 0, 0, 0x12, 0x34, 0, 1, 'a', 'b', 'c', 'd'};
  ASSERT_EQ(ipv6_cksum(peer_ll, our_ll, IPV6_NH_ICMPV6, icmp, 12), 0xFEDA);
  net_write16be(icmp + 2, 0xFEDA);
  ASSERT_EQ(ipv6_cksum(peer_ll, our_ll, IPV6_NH_ICMPV6, icmp, 12), 0);
}

/* ══ Parsing ══════════════════════════════════════════════════════ */

TEST(test_parse_basic) {
  uint8_t f[128], p[4] = {1, 2, 3, 4};
  build_ip6(f, our_mac, peer_ll, our_ll, 253, 64, p, 4);
  ipv6_hdr_t h;
  ASSERT_EQ(ipv6_parse(f + 14, 44, &h), NET_OK);
  ASSERT_MEM_EQ(h.src, peer_ll, 16);
  ASSERT_MEM_EQ(h.dst, our_ll, 16);
  ASSERT_EQ(h.next_header, 253);
  ASSERT_EQ(h.hop_limit, 64);
  ASSERT_EQ(h.header_len, 40);
  ASSERT_TRUE(h.payload == f + 14 + 40);
  ASSERT_EQ(h.payload_len, 4);
  ASSERT_EQ(h.nh_offset, IPV6_OFF_NH);
}

TEST(test_parse_rejects_version) {
  uint8_t f[128], p[4] = {0};
  build_ip6(f, our_mac, peer_ll, our_ll, 253, 64, p, 4);
  f[14] = 0x40;
  ipv6_hdr_t h;
  ASSERT_NE(ipv6_parse(f + 14, 44, &h), NET_OK);
}

TEST(test_parse_rejects_truncated) {
  uint8_t f[128], p[8] = {0};
  build_ip6(f, our_mac, peer_ll, our_ll, 253, 64, p, 8);
  ipv6_hdr_t h;
  ASSERT_NE(ipv6_parse(f + 14, 47, &h), NET_OK); /* 40 + 8 > 47 */
  ASSERT_NE(ipv6_parse(f + 14, 39, &h), NET_OK);
}

TEST(test_parse_ignores_link_padding) {
  uint8_t f[128], p[4] = {0};
  build_ip6(f, our_mac, peer_ll, our_ll, 253, 64, p, 4);
  ipv6_hdr_t h;
  ASSERT_EQ(ipv6_parse(f + 14, 64, &h), NET_OK); /* 20 bytes of padding */
  ASSERT_EQ(h.payload_len, 4);
}

TEST(test_parse_skips_hop_by_hop) {
  /* HBH: next 58, length 0 (8 bytes), PadN 4 */
  uint8_t f[128], p[12] = {58, 0, 1, 4, 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD};
  build_ip6(f, our_mac, peer_ll, our_ll, IPV6_NH_HOPOPT, 64, p, 12);
  ipv6_hdr_t h;
  ASSERT_EQ(ipv6_parse(f + 14, 52, &h), NET_OK);
  ASSERT_EQ(h.next_header, 58);
  ASSERT_EQ(h.header_len, 48);
  ASSERT_TRUE(h.payload == f + 14 + 48);
  ASSERT_EQ(h.payload_len, 4);
  ASSERT_EQ(h.nh_offset, 40);
}

TEST(test_parse_skips_chain) {
  /* HBH (8) -> Destination Options (16, length 1) -> 17 */
  uint8_t f[128], p[28];
  memset(p, 0, sizeof(p));
  p[0] = IPV6_NH_DSTOPTS;
  p[2] = 1; /* PadN */
  p[3] = 4;
  p[8] = IPV6_NH_UDP;
  p[9] = 1;
  p[10] = 1;
  p[11] = 12;
  build_ip6(f, our_mac, peer_ll, our_ll, IPV6_NH_HOPOPT, 64, p, 28);
  ipv6_hdr_t h;
  ASSERT_EQ(ipv6_parse(f + 14, 68, &h), NET_OK);
  ASSERT_EQ(h.next_header, IPV6_NH_UDP);
  ASSERT_EQ(h.header_len, 64);
  ASSERT_EQ(h.payload_len, 4);
  ASSERT_EQ(h.nh_offset, 48);
}

TEST(test_parse_drops_fragment) {
  uint8_t f[128], p[16] = {58, 0, 0, 1, 0, 0, 0, 7};
  build_ip6(f, our_mac, peer_ll, our_ll, IPV6_NH_FRAGMENT, 64, p, 16);
  ipv6_hdr_t h;
  ASSERT_NE(ipv6_parse(f + 14, 56, &h), NET_OK);
}

TEST(test_parse_rejects_extension_overrun) {
  /* HBH claims 16 bytes, only 8 present */
  uint8_t f[128], p[8] = {58, 1, 1, 4, 0, 0, 0, 0};
  build_ip6(f, our_mac, peer_ll, our_ll, IPV6_NH_HOPOPT, 64, p, 8);
  ipv6_hdr_t h;
  ASSERT_NE(ipv6_parse(f + 14, 48, &h), NET_OK);
}

TEST(test_parse_no_next_header) {
  uint8_t f[128], p[4] = {0};
  build_ip6(f, our_mac, peer_ll, our_ll, IPV6_NH_NONE, 64, p, 4);
  ipv6_hdr_t h;
  ASSERT_NE(ipv6_parse(f + 14, 44, &h), NET_OK);
}

TEST(test_parse_hop_by_hop_not_first_is_unrecognized) {
  /* DestOpts -> HBH: HBH is only valid first (RFC 8200 §4.1), so the
   * walk stops there and reports it as the (unknown) upper layer. */
  uint8_t f[128], p[16] = {IPV6_NH_HOPOPT, 0, 1, 4, 0, 0, 0, 0,
                           58,             0, 1, 4, 0, 0, 0, 0};
  build_ip6(f, our_mac, peer_ll, our_ll, IPV6_NH_DSTOPTS, 64, p, 16);
  ipv6_hdr_t h;
  ASSERT_EQ(ipv6_parse(f + 14, 56, &h), NET_OK);
  ASSERT_EQ(h.next_header, IPV6_NH_HOPOPT);
  ASSERT_EQ(h.nh_offset, 40);
}

/* ══ Building ═════════════════════════════════════════════════════ */

TEST(test_build_fields) {
  uint8_t b[40];
  memset(b, 0xEE, sizeof(b));
  ipv6_build(b, 300, IPV6_NH_UDP, our_ll, peer_ll, 64);
  ASSERT_EQ(b[0], 0x60);
  ASSERT_EQ(b[1], 0);
  ASSERT_EQ(b[2], 0);
  ASSERT_EQ(b[3], 0);
  ASSERT_EQ(net_read16be(b + 4), 300);
  ASSERT_EQ(b[6], IPV6_NH_UDP);
  ASSERT_EQ(b[7], 64);
  ASSERT_MEM_EQ(b + 8, our_ll, 16);
  ASSERT_MEM_EQ(b + 24, peer_ll, 16);
}

/* ══ Start and Duplicate Address Detection ════════════════════════ */

TEST(test_start_forms_tentative_link_local) {
  setup_cap(sizeof(tx_buf));
  ASSERT_EQ(ipv6_addr_state(&net, 0), NET_IP6_NONE);
  ipv6_start(&net);
  ASSERT_EQ(ipv6_addr_state(&net, 0), NET_IP6_TENTATIVE);
  ASSERT_MEM_EQ(net.ip6[0].addr, our_ll, 16);
  ASSERT_EQ(net.ip6_hop_limit, NET_IPV6_DEFAULT_HOP_LIMIT);
  ASSERT_EQ(send_count, 0); /* the probe waits for a tick */
}

TEST(test_dad_probe_format) {
  setup_cap(sizeof(tx_buf));
  ipv6_start(&net);
  ipv6_tick(&net, 1000);
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_icmp_ok(0));
  ASSERT_MEM_EQ(sent[0], mac_our_snm, 6);
  ASSERT_MEM_EQ(sent[0] + 6, our_mac, 6);
  ASSERT_MEM_EQ(s_ip(0) + 8, unspec, 16);
  ASSERT_MEM_EQ(s_ip(0) + 24, our_snm, 16);
  ASSERT_EQ(s_ip(0)[7], 255);
  ASSERT_EQ(s_plen(0), 24); /* no Source Link-Layer Address option */
  ASSERT_EQ(s_icmp(0)[0], ICMPV6_NS);
  ASSERT_EQ(s_icmp(0)[1], 0);
  ASSERT_MEM_EQ(s_icmp(0) + 8, our_ll, 16);
}

TEST(test_dad_success_after_retrans_timer) {
  setup_cap(sizeof(tx_buf));
  ipv6_start(&net);
  ipv6_tick(&net, 1000);
  ASSERT_EQ(ipv6_addr_state(&net, 0), NET_IP6_TENTATIVE);
  ipv6_tick(&net, 999);
  ASSERT_EQ(ipv6_addr_state(&net, 0), NET_IP6_TENTATIVE);
  ipv6_tick(&net, 1);
  ASSERT_EQ(ipv6_addr_state(&net, 0), NET_IP6_PREFERRED);
  ASSERT_EQ(send_count, 1); /* one probe (DupAddrDetectTransmits = 1) */
  ipv6_tick(&net, 5000);
  ASSERT_EQ(send_count, 1);
}

TEST(test_dad_conflict_on_na) {
  uint8_t f[128], m[32];
  setup_cap(sizeof(tx_buf));
  ipv6_start(&net);
  ipv6_tick(&net, 1000);
  uint16_t n = na_msg(m, our_ll, NDP_NA_FLAG_O);
  input(f, build_icmp6(f, mac_all_nodes, peer_ll, all_nodes, 255, m, n));
  ASSERT_EQ(ipv6_addr_state(&net, 0), NET_IP6_DUPLICATE);
  ipv6_tick(&net, 5000);
  ASSERT_EQ(ipv6_addr_state(&net, 0), NET_IP6_DUPLICATE);
}

TEST(test_dad_conflict_on_ns_from_unspecified) {
  /* Another node is running DAD for the same address. */
  uint8_t f[128], m[32];
  setup_cap(sizeof(tx_buf));
  ipv6_start(&net);
  ipv6_tick(&net, 1000);
  reset_sent();
  uint16_t n = ns_msg(m, our_ll, NULL);
  input(f, build_icmp6(f, mac_our_snm, unspec, our_snm, 255, m, n));
  ASSERT_EQ(ipv6_addr_state(&net, 0), NET_IP6_DUPLICATE);
  ASSERT_EQ(send_count, 0);
}

TEST(test_dad_invalid_na_is_not_a_conflict) {
  uint8_t f[128], m[32];
  setup_cap(sizeof(tx_buf));
  ipv6_start(&net);
  ipv6_tick(&net, 1000);
  uint16_t n = na_msg(m, our_ll, NDP_NA_FLAG_O);
  input(f, build_icmp6(f, mac_all_nodes, peer_ll, all_nodes, 254, m, n));
  ipv6_tick(&net, 1000);
  ASSERT_EQ(ipv6_addr_state(&net, 0), NET_IP6_PREFERRED);
}

TEST(test_tentative_ignores_resolution_ns) {
  uint8_t f[128], m[32];
  setup_cap(sizeof(tx_buf));
  ipv6_start(&net);
  ipv6_tick(&net, 1000);
  reset_sent();
  uint16_t n = ns_msg(m, our_ll, peer_mac);
  input(f, build_icmp6(f, mac_our_snm, peer_ll, our_snm, 255, m, n));
  ASSERT_EQ(send_count, 0);
  ASSERT_EQ(ipv6_addr_state(&net, 0), NET_IP6_TENTATIVE);
}

TEST(test_tentative_address_not_ours) {
  uint8_t f[128], m[32];
  setup_cap(sizeof(tx_buf));
  ipv6_start(&net);
  ipv6_tick(&net, 1000);
  reset_sent();
  uint16_t n = echo_req(m, "abcd");
  input(f, build_icmp6(f, our_mac, peer_ll, our_ll, 64, m, n));
  ASSERT_EQ(send_count, 0);
  ASSERT_FALSE(ipv6_is_ours(&net, our_ll));
}

TEST(test_silent_before_start) {
  uint8_t f[128], m[32];
  setup_cap(sizeof(tx_buf));
  uint16_t n = echo_req(m, "abcd");
  input(f, build_icmp6(f, our_mac, peer_ll, our_ll, 64, m, n));
  n = ns_msg(m, our_ll, peer_mac);
  input(f, build_icmp6(f, mac_our_snm, peer_ll, our_snm, 255, m, n));
  ASSERT_EQ(send_count, 0);
}

/* ══ Ethernet multicast filter ════════════════════════════════════ */

TEST(test_eth_filter_ipv6_multicast) {
  setup_up();
  ASSERT_TRUE(ipv6_mac_accepted(&net, mac_all_nodes));
  ASSERT_TRUE(ipv6_mac_accepted(&net, mac_our_snm));
  static const uint8_t other_snm_mac[6] = {0x33, 0x33, 0xFF, 0, 0, 0x99};
  static const uint8_t mdns_mac[6] = {0x33, 0x33, 0, 0, 0, 0xFB};
  ASSERT_FALSE(ipv6_mac_accepted(&net, other_snm_mac));
  ASSERT_FALSE(ipv6_mac_accepted(&net, mdns_mac));

  /* An echo to our address in a frame for another group never gets in */
  uint8_t f[128], m[32];
  uint16_t n = echo_req(m, "abcd");
  input(f, build_icmp6(f, other_snm_mac, peer_ll, our_ll, 64, m, n));
  ASSERT_EQ(send_count, 0);
}

/* ══ Echo ═════════════════════════════════════════════════════════ */

TEST(test_echo_reply) {
  uint8_t f[128], m[32];
  setup_up();
  uint16_t n = echo_req(m, "abcd");
  input(f, build_icmp6(f, our_mac, peer_ll, our_ll, 64, m, n));
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_icmp_ok(0));
  ASSERT_MEM_EQ(sent[0], peer_mac, 6);
  ASSERT_MEM_EQ(sent[0] + 6, our_mac, 6);
  ASSERT_MEM_EQ(s_ip(0) + 8, our_ll, 16);
  ASSERT_MEM_EQ(s_ip(0) + 24, peer_ll, 16);
  ASSERT_EQ(s_ip(0)[7], NET_IPV6_DEFAULT_HOP_LIMIT);
  ASSERT_EQ(s_plen(0), n);
  ASSERT_EQ(s_icmp(0)[0], ICMPV6_ECHO_REPLY);
  ASSERT_EQ(s_icmp(0)[1], 0);
  ASSERT_MEM_EQ(s_icmp(0) + 4, m + 4, n - 4); /* id, seq, data */
}

TEST(test_echo_to_all_nodes_answered_from_unicast) {
  uint8_t f[128], m[32];
  setup_up();
  uint16_t n = echo_req(m, "multi");
  input(f, build_icmp6(f, mac_all_nodes, peer_ll, all_nodes, 64, m, n));
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_icmp_ok(0));
  ASSERT_MEM_EQ(s_ip(0) + 8, our_ll, 16);
  ASSERT_MEM_EQ(s_ip(0) + 24, peer_ll, 16);
  ASSERT_EQ(s_icmp(0)[0], ICMPV6_ECHO_REPLY);
}

TEST(test_echo_bad_checksum_dropped) {
  uint8_t f[128], m[32];
  setup_up();
  uint16_t n = echo_req(m, "abcd");
  uint16_t len = build_icmp6(f, our_mac, peer_ll, our_ll, 64, m, n);
  f[54 + 8] ^= 0x01;
  input(f, len);
  ASSERT_EQ(send_count, 0);
}

TEST(test_echo_to_other_address_dropped) {
  uint8_t f[128], m[32];
  setup_up();
  uint16_t n = echo_req(m, "abcd");
  input(f, build_icmp6(f, our_mac, peer_ll, other_ll, 64, m, n));
  ASSERT_EQ(send_count, 0);
}

TEST(test_multicast_source_dropped) {
  uint8_t f[128], m[32];
  setup_up();
  uint16_t n = echo_req(m, "abcd");
  input(f, build_icmp6(f, our_mac, all_nodes, our_ll, 64, m, n));
  ASSERT_EQ(send_count, 0);
}

TEST(test_own_source_dropped) {
  uint8_t f[128], m[32];
  setup_up();
  uint16_t n = echo_req(m, "abcd");
  input(f, build_icmp6(f, our_mac, our_ll, our_ll, 64, m, n));
  ASSERT_EQ(send_count, 0);
}

TEST(test_echo_behind_hop_by_hop) {
  uint8_t f[160], m[32], p[64];
  setup_up();
  uint16_t n = echo_req(m, "hbh!");
  m[2] = m[3] = 0;
  net_write16be(m + 2, ipv6_cksum(peer_ll, our_ll, 58, m, n));
  memset(p, 0, 8);
  p[0] = IPV6_NH_ICMPV6;
  p[2] = 1;
  p[3] = 4;
  memcpy(p + 8, m, n);
  input(f, build_ip6(f, our_mac, peer_ll, our_ll, IPV6_NH_HOPOPT, 64, p,
                     (uint16_t)(8 + n)));
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_icmp_ok(0));
  ASSERT_EQ(s_icmp(0)[0], ICMPV6_ECHO_REPLY);
  ASSERT_MEM_EQ(s_icmp(0) + 4, m + 4, n - 4);
}

TEST(test_echo_larger_than_tx_buffer_dropped) {
  static uint8_t f[1514], m[1400];
  static char data[1300];
  setup_cap(512);
  ipv6_start(&net);
  ipv6_tick(&net, 2000);
  ipv6_tick(&net, 1000);
  reset_sent();
  memset(data, 'x', sizeof(data) - 1);
  uint16_t n = echo_req(m, data);
  input(f, build_icmp6(f, our_mac, peer_ll, our_ll, 64, m, n));
  ASSERT_EQ(send_count, 0);
}

/* ══ ICMPv6 errors ════════════════════════════════════════════════ */

TEST(test_unknown_next_header_parameter_problem) {
  uint8_t f[128], p[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  setup_up();
  uint16_t len = build_ip6(f, our_mac, peer_ll, our_ll, 253, 64, p, 8);
  input(f, len);
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_icmp_ok(0));
  ASSERT_MEM_EQ(sent[0], peer_mac, 6);
  ASSERT_MEM_EQ(s_ip(0) + 8, our_ll, 16);
  ASSERT_MEM_EQ(s_ip(0) + 24, peer_ll, 16);
  ASSERT_EQ(s_icmp(0)[0], ICMPV6_PARAM_PROBLEM);
  ASSERT_EQ(s_icmp(0)[1], ICMPV6_CODE_UNRECOGNIZED_NH);
  ASSERT_EQ(net_read32be(s_icmp(0) + 4), (uint32_t)IPV6_OFF_NH);
  ASSERT_EQ(s_plen(0), 8 + 48); /* quotes the whole invoking packet */
  ASSERT_MEM_EQ(s_icmp(0) + 8, f + 14, 48);
}

TEST(test_unknown_next_header_after_extension_pointer) {
  uint8_t f[128], p[16] = {253, 0, 1, 4, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8};
  setup_up();
  input(f, build_ip6(f, our_mac, peer_ll, our_ll, IPV6_NH_HOPOPT, 64, p, 16));
  ASSERT_EQ(send_count, 1);
  ASSERT_EQ(s_icmp(0)[0], ICMPV6_PARAM_PROBLEM);
  ASSERT_EQ(net_read32be(s_icmp(0) + 4), 40u);
}

TEST(test_no_error_for_multicast_destination) {
  uint8_t f[128], p[8] = {0};
  setup_up();
  input(f, build_ip6(f, mac_all_nodes, peer_ll, all_nodes, 253, 64, p, 8));
  ASSERT_EQ(send_count, 0);
}

TEST(test_no_error_for_unspecified_source) {
  uint8_t f[128], p[8] = {0};
  setup_up();
  input(f, build_ip6(f, our_mac, unspec, our_ll, 253, 64, p, 8));
  ASSERT_EQ(send_count, 0);
}

TEST(test_no_reply_to_icmpv6_error) {
  uint8_t f[160], m[64];
  setup_up();
  memset(m, 0, sizeof(m));
  m[0] = ICMPV6_DEST_UNREACH;
  m[1] = ICMPV6_CODE_PORT_UNREACH;
  input(f, build_icmp6(f, our_mac, peer_ll, our_ll, 64, m, 56));
  ASSERT_EQ(send_count, 0);
}

TEST(test_unknown_informational_type_dropped) {
  uint8_t f[128], m[16] = {200, 0, 0, 0, 1, 2, 3, 4};
  setup_up();
  input(f, build_icmp6(f, our_mac, peer_ll, our_ll, 64, m, 8));
  ASSERT_EQ(send_count, 0);
}

TEST(test_error_quote_fits_tx_buffer) {
  static uint8_t f[1514], p[1000];
  setup_cap(300);
  ipv6_start(&net);
  ipv6_tick(&net, 2000);
  ipv6_tick(&net, 1000);
  reset_sent();
  memset(p, 0x5A, sizeof(p));
  input(f, build_ip6(f, our_mac, peer_ll, our_ll, 253, 64, p, sizeof(p)));
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_icmp_ok(0));
  ASSERT_EQ(sent_len[0], 300);
  ASSERT_MEM_EQ(s_icmp(0) + 8, f + 14, 300 - 54 - 8);
}

/* ══ Neighbor Solicitation / Advertisement ════════════════════════ */

/** The sent frame is our NA for our_ll with the given flags. */
static int s_is_na(int i, uint8_t flags) {
  return s_icmp_ok(i) && s_ip(i)[7] == 255 && s_plen(i) == 32 &&
         s_icmp(i)[0] == ICMPV6_NA && s_icmp(i)[1] == 0 &&
         s_icmp(i)[4] == flags && memcmp(s_icmp(i) + 8, our_ll, 16) == 0 &&
         s_icmp(i)[24] == NDP_OPT_TLLA && s_icmp(i)[25] == 1 &&
         memcmp(s_icmp(i) + 26, our_mac, 6) == 0 &&
         memcmp(s_ip(i) + 8, our_ll, 16) == 0;
}

TEST(test_ns_answered_with_solicited_na) {
  uint8_t f[128], m[32];
  static const uint8_t slla[6] = {0xAA, 0xBB, 0xCC, 0, 0, 0x77};
  setup_up();
  uint16_t n = ns_msg(m, our_ll, slla);
  input(f, build_icmp6(f, mac_our_snm, peer_ll, our_snm, 255, m, n));
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_is_na(0, NDP_NA_FLAG_S | NDP_NA_FLAG_O));
  ASSERT_MEM_EQ(sent[0], slla, 6); /* to the SLLA option's MAC */
  ASSERT_MEM_EQ(s_ip(0) + 24, peer_ll, 16);
}

TEST(test_ns_unicast_without_slla) {
  uint8_t f[128], m[32];
  setup_up();
  uint16_t n = ns_msg(m, our_ll, NULL);
  input(f, build_icmp6(f, our_mac, peer_ll, our_ll, 255, m, n));
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_is_na(0, NDP_NA_FLAG_S | NDP_NA_FLAG_O));
  ASSERT_MEM_EQ(sent[0], peer_mac, 6); /* to the frame's source */
}

TEST(test_ns_hop_limit_not_255_ignored) {
  uint8_t f[128], m[32];
  setup_up();
  uint16_t n = ns_msg(m, our_ll, peer_mac);
  input(f, build_icmp6(f, mac_our_snm, peer_ll, our_snm, 254, m, n));
  ASSERT_EQ(send_count, 0);
}

TEST(test_ns_nonzero_code_ignored) {
  uint8_t f[128], m[32];
  setup_up();
  uint16_t n = ns_msg(m, our_ll, peer_mac);
  m[1] = 1;
  input(f, build_icmp6(f, mac_our_snm, peer_ll, our_snm, 255, m, n));
  ASSERT_EQ(send_count, 0);
}

TEST(test_ns_multicast_target_ignored) {
  uint8_t f[128], m[32];
  setup_up();
  uint16_t n = ns_msg(m, all_nodes, peer_mac);
  input(f, build_icmp6(f, mac_all_nodes, peer_ll, all_nodes, 255, m, n));
  ASSERT_EQ(send_count, 0);
}

TEST(test_ns_zero_length_option_ignored) {
  uint8_t f[128], m[32];
  setup_up();
  uint16_t n = ns_msg(m, our_ll, peer_mac);
  m[25] = 0;
  input(f, build_icmp6(f, mac_our_snm, peer_ll, our_snm, 255, m, n));
  ASSERT_EQ(send_count, 0);
}

TEST(test_ns_too_short_ignored) {
  uint8_t f[128], m[32];
  setup_up();
  ns_msg(m, our_ll, NULL);
  input(f, build_icmp6(f, mac_our_snm, peer_ll, our_snm, 255, m, 20));
  ASSERT_EQ(send_count, 0);
}

TEST(test_ns_for_other_target_ignored) {
  uint8_t f[128], m[32];
  setup_up();
  uint16_t n = ns_msg(m, other_ll, peer_mac);
  input(f, build_icmp6(f, our_mac, peer_ll, our_ll, 255, m, n));
  ASSERT_EQ(send_count, 0);
}

TEST(test_ns_dad_probe_for_our_address_defended) {
  uint8_t f[128], m[32];
  setup_up();
  uint16_t n = ns_msg(m, our_ll, NULL);
  input(f, build_icmp6(f, mac_our_snm, unspec, our_snm, 255, m, n));
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_is_na(0, NDP_NA_FLAG_O)); /* S = 0 */
  ASSERT_MEM_EQ(sent[0], mac_all_nodes, 6);
  ASSERT_MEM_EQ(s_ip(0) + 24, all_nodes, 16);
  ASSERT_EQ(ipv6_addr_state(&net, 0), NET_IP6_PREFERRED);
}

TEST(test_ns_from_unspecified_with_slla_dropped) {
  uint8_t f[128], m[32];
  setup_up();
  uint16_t n = ns_msg(m, our_ll, peer_mac);
  input(f, build_icmp6(f, mac_our_snm, unspec, our_snm, 255, m, n));
  ASSERT_EQ(send_count, 0);
}

TEST(test_ns_from_unspecified_to_unicast_dropped) {
  uint8_t f[128], m[32];
  setup_up();
  uint16_t n = ns_msg(m, our_ll, NULL);
  input(f, build_icmp6(f, our_mac, unspec, our_ll, 255, m, n));
  ASSERT_EQ(send_count, 0);
}

TEST(test_na_for_preferred_address_ignored) {
  uint8_t f[128], m[32];
  setup_up();
  uint16_t n = na_msg(m, our_ll, NDP_NA_FLAG_O);
  input(f, build_icmp6(f, mac_all_nodes, peer_ll, all_nodes, 255, m, n));
  ASSERT_EQ(ipv6_addr_state(&net, 0), NET_IP6_PREFERRED);
  ASSERT_EQ(send_count, 0);
}

/* ══ Source selection ═════════════════════════════════════════════ */

TEST(test_source_selection) {
  static const uint8_t global[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
                                     0,    0,    0,    0,    0, 0, 0, 1};
  setup_cap(sizeof(tx_buf));
  ASSERT_NULL(ipv6_src_for(&net, peer_ll)); /* not started */
  ipv6_start(&net);
  ASSERT_NULL(ipv6_src_for(&net, peer_ll)); /* tentative */
  ipv6_tick(&net, 2000);
  ipv6_tick(&net, 1000);
  ASSERT_NOT_NULL(ipv6_src_for(&net, peer_ll));
  ASSERT_MEM_EQ(ipv6_src_for(&net, peer_ll), our_ll, 16);
  ASSERT_NOT_NULL(ipv6_src_for(&net, all_nodes));
  ASSERT_MEM_EQ(ipv6_src_for(&net, all_nodes), our_ll, 16);
  ASSERT_NULL(ipv6_src_for(&net, global)); /* no global address yet */
  ASSERT_EQ(ipv6_addr_slot(&net, our_ll), 0);
  ASSERT_EQ(ipv6_addr_slot(&net, peer_ll), -1);
}

int main(void) {
  fprintf(stderr, "=== IPv6 / ICMPv6 / NDP tests ===\n");
  RUN_TEST(test_ll_from_mac_rfc4291_example);
  RUN_TEST(test_ll_from_mac_local_bit_flipped);
  RUN_TEST(test_solicited_node_group);
  RUN_TEST(test_multicast_mac_mapping);
  RUN_TEST(test_address_classes);
  RUN_TEST(test_cksum_known_answer);
  RUN_TEST(test_parse_basic);
  RUN_TEST(test_parse_rejects_version);
  RUN_TEST(test_parse_rejects_truncated);
  RUN_TEST(test_parse_ignores_link_padding);
  RUN_TEST(test_parse_skips_hop_by_hop);
  RUN_TEST(test_parse_skips_chain);
  RUN_TEST(test_parse_drops_fragment);
  RUN_TEST(test_parse_rejects_extension_overrun);
  RUN_TEST(test_parse_no_next_header);
  RUN_TEST(test_parse_hop_by_hop_not_first_is_unrecognized);
  RUN_TEST(test_build_fields);
  RUN_TEST(test_start_forms_tentative_link_local);
  RUN_TEST(test_dad_probe_format);
  RUN_TEST(test_dad_success_after_retrans_timer);
  RUN_TEST(test_dad_conflict_on_na);
  RUN_TEST(test_dad_conflict_on_ns_from_unspecified);
  RUN_TEST(test_dad_invalid_na_is_not_a_conflict);
  RUN_TEST(test_tentative_ignores_resolution_ns);
  RUN_TEST(test_tentative_address_not_ours);
  RUN_TEST(test_silent_before_start);
  RUN_TEST(test_eth_filter_ipv6_multicast);
  RUN_TEST(test_echo_reply);
  RUN_TEST(test_echo_to_all_nodes_answered_from_unicast);
  RUN_TEST(test_echo_bad_checksum_dropped);
  RUN_TEST(test_echo_to_other_address_dropped);
  RUN_TEST(test_multicast_source_dropped);
  RUN_TEST(test_own_source_dropped);
  RUN_TEST(test_echo_behind_hop_by_hop);
  RUN_TEST(test_echo_larger_than_tx_buffer_dropped);
  RUN_TEST(test_unknown_next_header_parameter_problem);
  RUN_TEST(test_unknown_next_header_after_extension_pointer);
  RUN_TEST(test_no_error_for_multicast_destination);
  RUN_TEST(test_no_error_for_unspecified_source);
  RUN_TEST(test_no_reply_to_icmpv6_error);
  RUN_TEST(test_unknown_informational_type_dropped);
  RUN_TEST(test_error_quote_fits_tx_buffer);
  RUN_TEST(test_ns_answered_with_solicited_na);
  RUN_TEST(test_ns_unicast_without_slla);
  RUN_TEST(test_ns_hop_limit_not_255_ignored);
  RUN_TEST(test_ns_nonzero_code_ignored);
  RUN_TEST(test_ns_multicast_target_ignored);
  RUN_TEST(test_ns_zero_length_option_ignored);
  RUN_TEST(test_ns_too_short_ignored);
  RUN_TEST(test_ns_for_other_target_ignored);
  RUN_TEST(test_ns_dad_probe_for_our_address_defended);
  RUN_TEST(test_ns_from_unspecified_with_slla_dropped);
  RUN_TEST(test_ns_from_unspecified_to_unicast_dropped);
  RUN_TEST(test_na_for_preferred_address_ignored);
  RUN_TEST(test_source_selection);
  TEST_REPORT();
  return test_failures;
}
