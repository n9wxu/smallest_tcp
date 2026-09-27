/**
 * @file test_slaac.c
 * @brief Unit tests for router discovery (RFC 4861 §6.3) and stateless
 *        address autoconfiguration (RFC 4862 §5.5).
 *
 * Built with NET_USE_IPV6=1.
 */

#include "eth.h"
#include "icmpv6.h"
#include "ipv6.h"
#include "ndp.h"
#include "net.h"
#include "net_endian.h"
#include "test_main.h"
#include <string.h>

#if !NET_USE_IPV6
#error "test_slaac needs NET_USE_IPV6=1"
#endif

/* ── Stub MAC driver ──────────────────────────────────────────────── */

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
  /* MLD reports (Hop-by-Hop + ICMPv6 131/132/143) belong to test_mld */
  if (l > 62 && f[12] == 0x86 && f[13] == 0xDD && f[20] == 0 && f[54] == 58 &&
      (f[62] == 143 || f[62] == 131 || f[62] == 132))
    return (int)l;
  int i = send_count < MAX_SENT ? send_count : MAX_SENT - 1;
  memcpy(sent[i], f, l);
  sent_len[i] = l;
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

static const uint8_t our_mac[6] = NET_DEFAULT_MAC;
static const uint8_t rtr_mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
static const uint8_t other_mac[6] = {0x52, 0x54, 0x00, 0x65, 0x43, 0x21};
static const uint8_t our_ll[16] = {0xFE, 0x80, 0, 0,    0,    0,    0,    0,
                                   0,    0,    0, 0xFF, 0xFE, 0xDE, 0xAD, 0x01};
static const uint8_t rtr_ll[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                   0,    0,    0, 0, 0, 0, 0, 0x01};
static const uint8_t all_nodes[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                      0,    0,    0, 0, 0, 0, 0, 1};
static const uint8_t all_routers[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                        0,    0,    0, 0, 0, 0, 0, 2};
static const uint8_t mac_all_nodes[6] = {0x33, 0x33, 0, 0, 0, 1};
static const uint8_t mac_all_routers[6] = {0x33, 0x33, 0, 0, 0, 2};
/* 2001:db8:1::/64 and our SLAAC address in it */
static const uint8_t prefix[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 1, 0, 0,
                                   0,    0,    0,    0,    0, 0, 0, 0};
static const uint8_t our_global[16] = {
    0x20, 0x01, 0x0D, 0xB8, 0, 1, 0, 0, 0, 0, 0, 0xFF, 0xFE, 0xDE, 0xAD, 0x01};
static const uint8_t remote_global[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 2, 0, 0,
                                          0,    0,    0,    0,    0, 0, 0, 7};
static const uint8_t onlink_global[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 1, 0, 0,
                                          0,    0,    0,    0,    0, 0, 0, 9};

#define INFINITE 0xFFFFFFFFu
#define TWO_HOURS 7200u

/* ── Fixture ──────────────────────────────────────────────────────── */

static uint8_t rx_buf[1514], tx_buf[1514];
static net_t net;

static void reset_sent(void) {
  memset(sent, 0, sizeof(sent));
  send_count = 0;
}

/** Up to the point where the link-local address is preferred. */
static void setup(void) {
  int ctx = 0;
  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf), NULL,
           &stub_drv, &ctx);
  ipv6_start(&net);
  ipv6_tick(&net, 1000); /* DAD probe */
  ipv6_tick(&net, 1000); /* link-local preferred */
  reset_sent();
}

/** setup() plus all three Router Solicitations sent (no RA yet). */
static void setup_quiet(void) {
  setup();
  for (int i = 0; i < 4; i++)
    ipv6_tick(&net, NDP_RTR_SOLICITATION_INTERVAL_MS);
  reset_sent();
}

/** Router Advertisement: hop limit, M/O flags, router lifetime, then
 *  options: SLLA if slla, a Prefix Information option if pfx. */
static uint16_t ra_msg(uint8_t *m, uint8_t cur_hop, uint8_t flags,
                       uint16_t router_life, const uint8_t *slla,
                       const uint8_t *pfx, uint8_t pfx_len, uint8_t pfx_flags,
                       uint32_t valid, uint32_t preferred) {
  uint16_t len = 16;
  memset(m, 0, 64);
  m[0] = ICMPV6_RA;
  m[4] = cur_hop;
  m[5] = flags;
  net_write16be(m + 6, router_life);
  if (slla) {
    m[len] = NDP_OPT_SLLA;
    m[len + 1] = 1;
    memcpy(m + len + 2, slla, 6);
    len += 8;
  }
  if (pfx) {
    uint8_t *o = m + len;
    o[0] = NDP_OPT_PREFIX;
    o[1] = 4;
    o[2] = pfx_len;
    o[3] = pfx_flags;
    net_write32be(o + 4, valid);
    net_write32be(o + 8, preferred);
    memcpy(o + 16, pfx, 16);
    len += 32;
  }
  return len;
}

/** Deliver an ICMPv6 message src → dst (hop limit 255) from rtr_mac. */
static void deliver(const uint8_t *src, const uint8_t *dst,
                    const uint8_t *dst_mac, uint8_t *m, uint16_t mlen,
                    uint8_t hlim) {
  uint8_t f[256];
  memcpy(f, dst_mac, 6);
  memcpy(f + 6, rtr_mac, 6);
  net_write16be(f + 12, NET_ETHERTYPE_IPV6);
  m[2] = m[3] = 0;
  net_write16be(m + 2, ipv6_cksum(src, dst, IPV6_NH_ICMPV6, m, mlen));
  ipv6_build(f + 14, mlen, IPV6_NH_ICMPV6, src, dst, hlim);
  memcpy(f + 54, m, mlen);
  eth_input(&net, f, (uint16_t)(54 + mlen));
}

/** A typical RA: hop 64, lifetime 1800 s, SLLA, 2001:db8:1::/64 (L+A). */
static void send_ra(uint32_t valid, uint32_t preferred) {
  uint8_t m[64];
  uint16_t n =
      ra_msg(m, 64, 0, 1800, rtr_mac, prefix, 64, 0xC0, valid, preferred);
  deliver(rtr_ll, all_nodes, mac_all_nodes, m, n, 255);
}

/** Complete DAD on whatever is tentative. */
static void finish_dad(void) {
  ipv6_tick(&net, 1000);
  ipv6_tick(&net, 1000);
}

static int is_rs(int i) {
  const uint8_t *ip = sent[i] + 14;
  const uint8_t *m = sent[i] + 54;
  return net_read16be(sent[i] + 12) == NET_ETHERTYPE_IPV6 &&
         ip[6] == IPV6_NH_ICMPV6 && m[0] == ICMPV6_RS;
}

/* ══ Router Solicitation ══════════════════════════════════════════ */

TEST(test_rs_after_link_local_preferred) {
  setup();
  ipv6_tick(&net, 1000); /* random delay <= 1 s */
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(is_rs(0));
  const uint8_t *ip = sent[0] + 14;
  const uint8_t *m = sent[0] + 54;
  ASSERT_MEM_EQ(sent[0], mac_all_routers, 6);
  ASSERT_MEM_EQ(ip + 8, our_ll, 16);
  ASSERT_MEM_EQ(ip + 24, all_routers, 16);
  ASSERT_EQ(ip[7], 255);
  ASSERT_EQ(m[1], 0);
  ASSERT_EQ(net_read16be(ip + 4), 16); /* 8 + SLLA option */
  ASSERT_EQ(m[8], NDP_OPT_SLLA);
  ASSERT_MEM_EQ(m + 10, our_mac, 6);
  ASSERT_EQ(ipv6_cksum(ip + 8, ip + 24, IPV6_NH_ICMPV6, m, 16), 0);
}

TEST(test_rs_retransmitted_three_times) {
  setup();
  ipv6_tick(&net, 1000);
  ipv6_tick(&net, 3999);
  ASSERT_EQ(send_count, 1);
  ipv6_tick(&net, 1);
  ASSERT_EQ(send_count, 2); /* RTR_SOLICITATION_INTERVAL = 4 s */
  ipv6_tick(&net, 4000);
  ASSERT_EQ(send_count, 3);
  ipv6_tick(&net, 4000);
  ipv6_tick(&net, 4000);
  ASSERT_EQ(send_count, 3); /* MAX_RTR_SOLICITATIONS = 3 */
}

TEST(test_ra_stops_solicitations) {
  setup();
  ipv6_tick(&net, 1000);
  send_ra(86400, 14400);
  reset_sent();
  ipv6_tick(&net, 4000);
  ipv6_tick(&net, 4000);
  for (int i = 0; i < send_count && i < MAX_SENT; i++)
    ASSERT_FALSE(is_rs(i));
}

/* ══ Router Advertisement ═════════════════════════════════════════ */

TEST(test_ra_sets_router_and_hop_limit) {
  uint8_t m[64];
  setup_quiet();
  uint16_t n = ra_msg(m, 42, 0, 1800, rtr_mac, NULL, 0, 0, 0, 0);
  deliver(rtr_ll, all_nodes, mac_all_nodes, m, n, 255);
  ASSERT_EQ(net.ip6.hop_limit, 42);
  ASSERT_NOT_NULL(ipv6_router_mac(&net));
  ASSERT_MEM_EQ(ipv6_router_mac(&net), rtr_mac, 6);
  ASSERT_MEM_EQ(net.ip6.router.addr, rtr_ll, 16);
}

TEST(test_ra_zero_hop_limit_keeps_ours) {
  uint8_t m[64];
  setup_quiet();
  uint16_t n = ra_msg(m, 0, 0, 1800, rtr_mac, NULL, 0, 0, 0, 0);
  deliver(rtr_ll, all_nodes, mac_all_nodes, m, n, 255);
  ASSERT_EQ(net.ip6.hop_limit, NET_IPV6_DEFAULT_HOP_LIMIT);
}

TEST(test_ra_without_slla_uses_frame_source) {
  uint8_t m[64];
  setup_quiet();
  uint16_t n = ra_msg(m, 64, 0, 1800, NULL, NULL, 0, 0, 0, 0);
  deliver(rtr_ll, all_nodes, mac_all_nodes, m, n, 255);
  ASSERT_NOT_NULL(ipv6_router_mac(&net));
  ASSERT_MEM_EQ(ipv6_router_mac(&net), rtr_mac, 6);
}

TEST(test_ra_router_lifetime_zero_removes_router) {
  uint8_t m[64];
  setup_quiet();
  uint16_t n = ra_msg(m, 64, 0, 1800, rtr_mac, NULL, 0, 0, 0, 0);
  deliver(rtr_ll, all_nodes, mac_all_nodes, m, n, 255);
  n = ra_msg(m, 64, 0, 0, rtr_mac, NULL, 0, 0, 0, 0);
  deliver(rtr_ll, all_nodes, mac_all_nodes, m, n, 255);
  ASSERT_NULL(ipv6_router_mac(&net));
}

TEST(test_router_expires) {
  uint8_t m[64];
  setup_quiet();
  uint16_t n = ra_msg(m, 64, 0, 3, rtr_mac, NULL, 0, 0, 0, 0);
  deliver(rtr_ll, all_nodes, mac_all_nodes, m, n, 255);
  ipv6_tick(&net, 2000);
  ASSERT_NOT_NULL(ipv6_router_mac(&net));
  ipv6_tick(&net, 1000);
  ASSERT_NULL(ipv6_router_mac(&net));
}

TEST(test_ra_flags_recorded) {
  uint8_t m[64];
  setup_quiet();
  uint16_t n = ra_msg(m, 64, 0xC0, 1800, rtr_mac, NULL, 0, 0, 0, 0);
  deliver(rtr_ll, all_nodes, mac_all_nodes, m, n, 255);
  ASSERT_EQ(net.ip6.ra_flags & 0xC0, 0xC0); /* M and O */
}

TEST(test_ra_invalid_ignored) {
  uint8_t m[64];
  static const uint8_t global_src[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
                                         0,    0,    0,    0,    0, 0, 0, 1};
  setup_quiet();
  uint16_t n =
      ra_msg(m, 42, 0, 1800, rtr_mac, prefix, 64, 0xC0, INFINITE, INFINITE);
  deliver(rtr_ll, all_nodes, mac_all_nodes, m, n, 254);     /* hop limit */
  deliver(global_src, all_nodes, mac_all_nodes, m, n, 255); /* not LL src */
  m[1] = 1;
  deliver(rtr_ll, all_nodes, mac_all_nodes, m, n, 255); /* code */
  ASSERT_NULL(ipv6_router_mac(&net));
  ASSERT_EQ(net.ip6.hop_limit, NET_IPV6_DEFAULT_HOP_LIMIT);
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_NONE);
}

/* ══ SLAAC ════════════════════════════════════════════════════════ */

TEST(test_prefix_forms_global_address) {
  setup_quiet();
  send_ra(86400, 14400);
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_TENTATIVE);
  ASSERT_MEM_EQ(net.ip6.addr[1].addr, our_global, 16);
  ASSERT_NULL(ipv6_src_for(&net, remote_global)); /* not yet */
  finish_dad();
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_PREFERRED);
  ASSERT_NOT_NULL(ipv6_src_for(&net, remote_global));
  ASSERT_MEM_EQ(ipv6_src_for(&net, remote_global), our_global, 16);
  ASSERT_TRUE(ipv6_is_ours(&net, our_global));
}

TEST(test_slaac_dad_probe) {
  setup_quiet();
  send_ra(86400, 14400);
  ipv6_tick(&net, 1000);
  ASSERT_EQ(send_count, 1);
  const uint8_t *m = sent[0] + 54;
  ASSERT_EQ(m[0], ICMPV6_NS);
  ASSERT_MEM_EQ(m + 8, our_global, 16);
  static const uint8_t unspec[16] = {0};
  ASSERT_MEM_EQ(sent[0] + 14 + 8, unspec, 16);
}

TEST(test_prefix_not_autonomous_ignored) {
  uint8_t m[64];
  setup_quiet();
  uint16_t n = ra_msg(m, 64, 0, 1800, rtr_mac, prefix, 64, 0x80, INFINITE,
                      INFINITE); /* L only */
  deliver(rtr_ll, all_nodes, mac_all_nodes, m, n, 255);
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_NONE);
}

TEST(test_prefix_length_not_64_ignored) {
  uint8_t m[64];
  setup_quiet();
  uint16_t n =
      ra_msg(m, 64, 0, 1800, rtr_mac, prefix, 48, 0xC0, INFINITE, INFINITE);
  deliver(rtr_ll, all_nodes, mac_all_nodes, m, n, 255);
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_NONE);
}

TEST(test_prefix_preferred_above_valid_ignored) {
  setup_quiet();
  send_ra(100, 200); /* REQ-SLAAC-021 */
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_NONE);
}

TEST(test_link_local_prefix_ignored) {
  uint8_t m[64];
  setup_quiet();
  uint16_t n =
      ra_msg(m, 64, 0, 1800, rtr_mac, our_ll, 64, 0xC0, INFINITE, INFINITE);
  deliver(rtr_ll, all_nodes, mac_all_nodes, m, n, 255);
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_NONE);
}

TEST(test_same_prefix_twice_one_address) {
  setup_quiet();
  send_ra(86400, 14400);
  finish_dad();
  send_ra(86400, 14400);
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_PREFERRED);
}

TEST(test_slaac_dad_conflict) {
  uint8_t m[32];
  setup_quiet();
  send_ra(86400, 14400);
  ipv6_tick(&net, 1000);
  memset(m, 0, sizeof(m));
  m[0] = ICMPV6_NA;
  m[4] = NDP_NA_FLAG_O;
  memcpy(m + 8, our_global, 16);
  m[24] = NDP_OPT_TLLA;
  m[25] = 1;
  memcpy(m + 26, other_mac, 6);
  deliver(rtr_ll, all_nodes, mac_all_nodes, m, 32, 255);
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_DUPLICATE);
  finish_dad();
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_DUPLICATE);
  ASSERT_NULL(ipv6_src_for(&net, remote_global));
}

/* ══ Lifetimes ════════════════════════════════════════════════════ */

TEST(test_preferred_lifetime_deprecates) {
  setup_quiet();
  send_ra(100, 10);
  finish_dad(); /* 2 s of the lifetimes gone */
  ipv6_tick(&net, 7000);
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_PREFERRED);
  ipv6_tick(&net, 1000);
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_DEPRECATED);
  ASSERT_TRUE(ipv6_is_ours(&net, our_global)); /* still valid */
}

TEST(test_valid_lifetime_removes_address) {
  setup_quiet();
  send_ra(20, 10);
  finish_dad();
  ipv6_tick(&net, 17000);
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_DEPRECATED);
  ipv6_tick(&net, 1000);
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_NONE);
  ASSERT_FALSE(ipv6_is_ours(&net, our_global));
}

TEST(test_infinite_lifetime_never_expires) {
  setup_quiet();
  send_ra(INFINITE, INFINITE);
  finish_dad();
  for (int i = 0; i < 100; i++)
    ipv6_tick(&net, 60000);
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_PREFERRED);
}

TEST(test_valid_lifetime_two_hour_rule) {
  /* RFC 4862 §5.5.3(e): a short lifetime cannot cut a longer one below
   * two hours; a longer one, or one above two hours, is taken. */
  setup_quiet();
  send_ra(86400, 14400);
  finish_dad();
  send_ra(60, 30);
  ASSERT_EQ(net.ip6.addr[1].valid_s, TWO_HOURS);
  ASSERT_EQ(net.ip6.addr[1].preferred_s, 30u);
  send_ra(3 * 3600, 3600);
  ASSERT_EQ(net.ip6.addr[1].valid_s, 3u * 3600u);
  send_ra(60, 30); /* remaining 3 h > 2 h → 2 h */
  ASSERT_EQ(net.ip6.addr[1].valid_s, TWO_HOURS);
  send_ra(60, 30); /* remaining <= 2 h and 60 < remaining → unchanged */
  ASSERT_EQ(net.ip6.addr[1].valid_s, TWO_HOURS);
}

TEST(test_deprecated_address_preferred_again) {
  setup_quiet();
  send_ra(100, 5);
  finish_dad();
  ipv6_tick(&net, 5000);
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_DEPRECATED);
  send_ra(100, 50);
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_PREFERRED);
}

/* ══ Static addresses and next hop ════════════════════════════════ */

TEST(test_addr_add_runs_dad) {
  setup_quiet();
  ASSERT_EQ(ipv6_addr_add(&net, remote_global, INFINITE, INFINITE), NET_OK);
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_TENTATIVE);
  finish_dad();
  ASSERT_EQ(ipv6_addr_state(&net, 1), NET_IP6_PREFERRED);
  ASSERT_EQ(ipv6_addr_add(&net, remote_global, INFINITE, INFINITE),
            NET_OK); /* already there */
  ASSERT_EQ(ipv6_addr_add(&net, onlink_global, INFINITE, INFINITE),
            NET_ERR_BUF_TOO_SMALL); /* NET_IPV6_ADDRS = 2 */
  ASSERT_EQ(ipv6_addr_add(&net, all_nodes, INFINITE, INFINITE),
            NET_ERR_INVALID_PARAM);
}

TEST(test_on_link) {
  setup_quiet();
  send_ra(INFINITE, INFINITE);
  finish_dad();
  ASSERT_TRUE(ipv6_on_link(&net, rtr_ll));        /* link-local */
  ASSERT_TRUE(ipv6_on_link(&net, onlink_global)); /* our /64 */
  ASSERT_FALSE(ipv6_on_link(&net, remote_global));
}

TEST(test_echo_to_global_answered_from_global) {
  uint8_t m[16] = {
      ICMPV6_ECHO_REQUEST, 0, 0, 0, 0, 1, 0, 1, 'g', 'l', 'o', 'b'};
  static const uint8_t our_mac_arr[6] = NET_DEFAULT_MAC;
  setup_quiet();
  send_ra(INFINITE, INFINITE);
  finish_dad();
  reset_sent();
  deliver(remote_global, our_global, our_mac_arr, m, 12, 60);
  ASSERT_EQ(send_count, 1);
  ASSERT_MEM_EQ(sent[0], rtr_mac, 6); /* back via the router */
  ASSERT_MEM_EQ(sent[0] + 14 + 8, our_global, 16);
  ASSERT_MEM_EQ(sent[0] + 14 + 24, remote_global, 16);
  ASSERT_EQ(sent[0][54], ICMPV6_ECHO_REPLY);
}

int main(void) {
  fprintf(stderr, "=== Router discovery + SLAAC tests ===\n");
  RUN_TEST(test_rs_after_link_local_preferred);
  RUN_TEST(test_rs_retransmitted_three_times);
  RUN_TEST(test_ra_stops_solicitations);
  RUN_TEST(test_ra_sets_router_and_hop_limit);
  RUN_TEST(test_ra_zero_hop_limit_keeps_ours);
  RUN_TEST(test_ra_without_slla_uses_frame_source);
  RUN_TEST(test_ra_router_lifetime_zero_removes_router);
  RUN_TEST(test_router_expires);
  RUN_TEST(test_ra_flags_recorded);
  RUN_TEST(test_ra_invalid_ignored);
  RUN_TEST(test_prefix_forms_global_address);
  RUN_TEST(test_slaac_dad_probe);
  RUN_TEST(test_prefix_not_autonomous_ignored);
  RUN_TEST(test_prefix_length_not_64_ignored);
  RUN_TEST(test_prefix_preferred_above_valid_ignored);
  RUN_TEST(test_link_local_prefix_ignored);
  RUN_TEST(test_same_prefix_twice_one_address);
  RUN_TEST(test_slaac_dad_conflict);
  RUN_TEST(test_preferred_lifetime_deprecates);
  RUN_TEST(test_valid_lifetime_removes_address);
  RUN_TEST(test_infinite_lifetime_never_expires);
  RUN_TEST(test_valid_lifetime_two_hour_rule);
  RUN_TEST(test_deprecated_address_preferred_again);
  RUN_TEST(test_addr_add_runs_dad);
  RUN_TEST(test_on_link);
  RUN_TEST(test_echo_to_global_answered_from_global);
  TEST_REPORT();
  return test_failures;
}
