/**
 * @file itest_ndp.c
 * @brief Neighbor Discovery, Duplicate Address Detection, router
 *        discovery and SLAAC, black box: ND messages on the wire, time,
 *        and the addresses the interface comes to use.
 */

#include "icmpv6.h"
#include "ipv6.h"
#include "itest.h"
#include "ndp.h"
#include "tcp.h"
#include "tcp_buf.h"
#include "udp.h"
#include <string.h>

#define T_ECHO_REQUEST 128
#define T_ECHO_REPLY 129
#define T_RS 133
#define T_RA 134
#define T_NS 135
#define T_NA 136
#define T_REDIRECT 137
#define T_MLD_V2_REPORT 143

#define NA_R 0x80
#define NA_S 0x40
#define NA_O 0x20
#define RA_M 0x80
#define RA_O 0x40
#define PI_L 0x80
#define PI_A 0x40

#define TWO_HOURS 7200u
#define FOREVER 0xFFFFFFFFu

static itest_t t;
static const uint8_t unspec[16] = {0};
static const uint8_t all_nodes_mac[6] = {0x33, 0x33, 0, 0, 0, 1};
/* Our link-local address, its solicited-node group and that group's MAC,
 * and the address SLAAC forms in the router's prefix */
static uint8_t ll[16], sn[16], sn_mac[6], global[16];

/* net_init() done and IPv6 started: the link-local address is tentative
 * and waits its random delay before the first probe */
static void starting(void) {
  itest_up(&t, 1514, 1514);
  peer_link_local(t.net.mac, ll);
  peer_solicited_node(ll, sn);
  peer_mcast6_mac(sn, sn_mac);
  memcpy(global, prefix6, 8);
  memcpy(global + 8, ll + 8, 8);
  ipv6_start(&t.net);
}

/* The link-local address past DAD, the Router Solicitations over */
static void up(void) {
  starting();
  itest_advance(&t, 15000, 100);
  wire_clear(&t);
}

/* Time passes in steps of @p step ms until a frame has been sent, at most
 * @p max_ms; @return the time passed, or -1 */
static long advance_until_sent(uint32_t max_ms, uint32_t step) {
  uint32_t ms;
  for (ms = 0; ms < max_ms && t.wire.tx_count == 0; ms += step)
    itest_advance(&t, step, step);
  return t.wire.tx_count ? (long)ms : -1;
}

static int sent(uint8_t type, peer_ip6_t *ip, peer_icmp_t *icmp) {
  return wire_find_icmp6(&t, 0, type, ip, icmp) >= 0;
}

/* Time passes in steps of 1 ms until a Router Solicitation has been
 * sent, at most @p max_ms; @return the time passed, or -1 */
static long advance_until_rs(uint32_t max_ms) {
  uint32_t ms;
  for (ms = 0; ms < max_ms && !wire_count_icmp6(&t, T_RS); ms++)
    itest_advance(&t, 1, 1);
  return wire_count_icmp6(&t, T_RS) ? (long)ms : -1;
}

/* ── The peer's Neighbor Discovery messages ── */

/* What a test may get wrong on purpose in an ND message */
typedef struct {
  uint8_t hop_limit, code;
  int bad_cksum;
  uint16_t cut;           /* bytes left off the end */
  const uint8_t *src_mac; /* the frame's source; NULL: peer_mac */
} nd_fault_t;

static const nd_fault_t nd_ok = {255, 0, 0, 0, NULL};

static void nd_deliver(const uint8_t *src, const uint8_t *dst,
                       const uint8_t *dst_mac, uint8_t type,
                       const uint8_t rest[4], const uint8_t *body, uint16_t len,
                       const nd_fault_t *fault) {
  static uint8_t msg[512], f[600];
  uint8_t mac[6];
  peer_ip6_t ip = peer_ip6(src, dst, 58);
  uint16_t n;
  ip.hop_limit = fault->hop_limit;
  n = peer_icmp6(msg, &ip, type, fault->code, rest, body,
                 (uint16_t)(len - fault->cut));
  if (fault->bad_cksum)
    msg[2] ^= 0x40;
  if (!dst_mac) {
    if (dst[0] == 0xFF)
      peer_mcast6_mac(dst, mac);
    else
      memcpy(mac, t.net.mac, 6);
    dst_mac = mac;
  }
  itest_receive(&t, f,
                peer_ipv6_frame(f, dst_mac,
                                fault->src_mac ? fault->src_mac : peer_mac, &ip,
                                msg, n));
}

/* A Neighbor Solicitation for @p target with @p opts_len bytes of options */
static void ns_opts(const uint8_t *src, const uint8_t *dst,
                    const uint8_t *target, const uint8_t *opts,
                    uint16_t opts_len, const nd_fault_t *fault) {
  uint8_t body[128];
  memcpy(body, target, 16);
  if (opts_len)
    memcpy(body + 16, opts, opts_len);
  nd_deliver(src, dst, NULL, T_NS, NULL, body, (uint16_t)(16 + opts_len),
             fault);
}

/* ... with the peer's Source Link-Layer Address option if @p slla */
static void ns(const uint8_t *src, const uint8_t *dst, const uint8_t *target,
               int slla, const nd_fault_t *fault) {
  uint8_t opt[8];
  peer_nd_lla(opt, 1, peer_mac);
  ns_opts(src, dst, target, opt, slla ? 8 : 0, fault);
}

/* Another node's DAD probe for @p target */
static void dad_probe(const uint8_t *target) {
  uint8_t group[16];
  peer_solicited_node(target, group);
  ns(unspec, group, target, 0, &nd_ok);
}

/* A Neighbor Advertisement for @p target with a Target Link-Layer Address
 * option */
static void na(const uint8_t *src, const uint8_t *dst, const uint8_t *target,
               uint8_t flags, const nd_fault_t *fault) {
  uint8_t body[24], rest[4] = {0, 0, 0, 0};
  rest[0] = flags;
  memcpy(body, target, 16);
  peer_nd_lla(body + 16, 2, peer_mac);
  nd_deliver(src, dst, NULL, T_NA, rest, body, 24, fault);
}

/* A Router Advertisement from the router to all-nodes */
typedef struct {
  uint8_t cur_hop_limit, flags;
  uint16_t lifetime;
  int no_slla;
  int prefix; /* a Prefix Information option */
  uint8_t prefix_len, prefix_flags;
  uint32_t valid, preferred;
  const uint8_t *prefix_addr; /* NULL: prefix6 */
  const uint8_t *src;         /* NULL: router6_ll */
} ra_t;

/* Router lifetime 1800 s, the prefix /64 on-link and autonomous, valid a
 * day and preferred four hours — but not included unless .prefix is set */
static ra_t ra_default(void) {
  ra_t r;
  memset(&r, 0, sizeof(r));
  r.lifetime = 1800;
  r.prefix_len = 64;
  r.prefix_flags = PI_L | PI_A;
  r.valid = 86400;
  r.preferred = 14400;
  return r;
}

static void ra_send(const ra_t *r, const nd_fault_t *fault) {
  uint8_t body[64], rest[4];
  nd_fault_t f = *fault;
  uint16_t n = 8;
  rest[0] = r->cur_hop_limit;
  rest[1] = r->flags;
  peer_put16(rest + 2, r->lifetime);
  memset(body, 0, 8); /* Reachable Time, Retrans Timer: unspecified */
  if (!r->no_slla)
    n = (uint16_t)(n + peer_nd_lla(body + n, 1, router6_mac));
  if (r->prefix)
    n = (uint16_t)(n + peer_nd_prefix(body + n,
                                      r->prefix_addr ? r->prefix_addr : prefix6,
                                      r->prefix_len, r->prefix_flags, r->valid,
                                      r->preferred));
  if (!f.src_mac)
    f.src_mac = router6_mac;
  nd_deliver(r->src ? r->src : router6_ll, all_nodes6, NULL, T_RA, rest, body,
             n, &f);
}

/* A Router Advertisement with the prefix, lifetimes @p valid and
 * @p preferred */
static void ra_prefix(uint32_t valid, uint32_t preferred) {
  ra_t r = ra_default();
  r.prefix = 1;
  r.valid = valid;
  r.preferred = preferred;
  ra_send(&r, &nd_ok);
}

/* up(), then the global address formed from a Router Advertisement
 * (lifetimes @p valid and @p preferred), past DAD */
static void up_slaac(uint32_t valid, uint32_t preferred) {
  up();
  ra_prefix(valid, preferred);
  itest_advance(&t, 2000, 100);
  wire_clear(&t);
}

/* An Echo Request from @p src to @p dst: 1 if an Echo Reply from @p dst
 * came back */
static int answers_echo(const uint8_t *src, const uint8_t *dst) {
  static uint8_t f[128];
  static const uint8_t id_seq[4] = {0, 1, 0, 1};
  peer_ip6_t ip = peer_ip6(src, dst, 58), rip;
  peer_icmp_t icmp;
  wire_clear(&t);
  itest_receive(&t, f,
                peer_icmp6_frame(f, t.net.mac, &ip, T_ECHO_REQUEST, 0, id_seq,
                                 "ping", 4));
  return sent(T_ECHO_REPLY, &rip, &icmp) && memcmp(rip.src, dst, 16) == 0;
}

/* Seconds pass */
static void seconds(uint32_t s) {
  while (s--)
    itest_advance(&t, 1000, 1000);
}

/* ── Validation common to all ND messages ── */

/* REQ-NDP-001, 029, 041: a Neighbor Solicitation, a Neighbor
 * Advertisement or a Router Advertisement whose Hop Limit is not 255 did
 * not come from the link: ignored */
TEST(itest_ndp_001_hop_limit_255_required) {
  nd_fault_t far = nd_ok;
  ra_t r = ra_default();
  far.hop_limit = 254;
  up();
  ns(peer6_ll, sn, ll, 1, &far);
  ASSERT_EQ(t.wire.tx_count, 0);
  ra_send(&r, &far);
  ASSERT_NULL(ipv6_router_mac(&t.net));
  starting(); /* tentative: an NA for the address would be a conflict */
  na(peer6_ll, all_nodes6, ll, NA_O, &far);
  itest_advance(&t, 3000, 100);
  ASSERT_EQ(ipv6_addr_state(&t.net, 0), NET_IP6_PREFERRED);
  ns(peer6_ll, sn, ll, 1, &nd_ok); /* the same, from the link: answered */
  ASSERT_TRUE(wire_count_icmp6(&t, T_NA) == 1);
}

/* REQ-NDP-002: a code other than 0 is ignored */
TEST(itest_ndp_002_code_zero_required) {
  nd_fault_t coded = nd_ok;
  ra_t r = ra_default();
  coded.code = 1;
  up();
  ns(peer6_ll, sn, ll, 1, &coded);
  ASSERT_EQ(t.wire.tx_count, 0);
  ra_send(&r, &coded);
  ASSERT_NULL(ipv6_router_mac(&t.net));
  starting();
  na(peer6_ll, all_nodes6, ll, NA_O, &coded);
  ASSERT_EQ(ipv6_addr_state(&t.net, 0), NET_IP6_TENTATIVE);
}

/* REQ-NDP-003, REQ-ICMPv6-002: a bad ICMPv6 checksum is ignored */
TEST(itest_ndp_003_checksum_required) {
  nd_fault_t bad = nd_ok;
  ra_t r = ra_default();
  bad.bad_cksum = 1;
  up();
  ns(peer6_ll, sn, ll, 1, &bad);
  ASSERT_EQ(t.wire.tx_count, 0);
  ra_send(&r, &bad);
  ASSERT_NULL(ipv6_router_mac(&t.net));
}

/* REQ-NDP-004, 005, 007: options are type, length in units of 8 octets,
 * value: an unknown option is skipped by its length, and the Source
 * Link-Layer Address after it is found — the advertisement goes to it */
TEST(itest_ndp_004_options_walked) {
  static const uint8_t other_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
  uint8_t opts[32];
  peer_ip6_t ip;
  peer_icmp_t icmp;
  up();
  memset(opts, 0x5A, sizeof(opts));
  opts[0] = 200; /* unknown, 16 bytes */
  opts[1] = 2;
  peer_nd_lla(opts + 16, 1, other_mac);
  ns_opts(peer6_ll, sn, ll, opts, 24, &nd_ok);
  ASSERT_TRUE(sent(T_NA, &ip, &icmp));
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, other_mac, 6);
}

/* REQ-NDP-006: a message with an option of length 0, or one that runs
 * past its end, is ignored */
TEST(itest_ndp_006_zero_length_option_discards) {
  uint8_t opts[16];
  ra_t r = ra_default();
  uint8_t body[24], rest[4] = {0, 0, 0x07, 0x08};
  up();
  peer_nd_lla(opts, 1, peer_mac);
  opts[8] = 200;
  opts[9] = 0;
  memset(opts + 10, 0, 6);
  ns_opts(peer6_ll, sn, ll, opts, 16, &nd_ok);
  opts[9] = 3; /* 24 bytes, of which 8 are there */
  ns_opts(peer6_ll, sn, ll, opts, 16, &nd_ok);
  ASSERT_EQ(t.wire.tx_count, 0);
  memset(body, 0, sizeof(body)); /* a Router Advertisement likewise */
  peer_nd_lla(body + 8, 1, router6_mac);
  body[16] = 200;
  nd_deliver(router6_ll, all_nodes6, NULL, T_RA, rest, body, 24, &nd_ok);
  ASSERT_NULL(ipv6_router_mac(&t.net));
  ra_send(&r, &nd_ok);
  ASSERT_NOT_NULL(ipv6_router_mac(&t.net));
}

/* ── Neighbor Solicitations received ── */

/* REQ-NDP-011, 012, 013, 017, REQ-ICMPv6-036: a solicitation for our
 * address draws a Neighbor Advertisement: Hop Limit 255, from the target
 * address to the solicitor, Router 0, Solicited 1, Override 1, the target,
 * our MAC in a Target Link-Layer Address option */
TEST(itest_ndp_011_solicitation_answered) {
  peer_ip6_t ip;
  peer_icmp_t icmp;
  const uint8_t *tlla;
  up();
  ns(peer6_ll, sn, ll, 1, &nd_ok);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(sent(T_NA, &ip, &icmp));
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, peer_mac, 6);
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data + 6, t.net.mac, 6);
  ASSERT_EQ(ip.hop_limit, 255);
  ASSERT_MEM_EQ(ip.src, ll, 16);
  ASSERT_MEM_EQ(ip.dst, peer6_ll, 16);
  ASSERT_EQ(icmp.code, 0);
  ASSERT_TRUE(icmp.cksum_ok);
  ASSERT_EQ(icmp.rest[0], NA_S | NA_O);
  ASSERT_EQ(icmp.rest[1] | icmp.rest[2] | icmp.rest[3], 0);
  ASSERT_EQ(icmp.data_len, 16 + 8);
  ASSERT_MEM_EQ(icmp.data, ll, 16);
  ASSERT_NOT_NULL(tlla = peer_nd_option(icmp.data + 16, 8, 2));
  ASSERT_EQ(tlla[1], 1);
  ASSERT_MEM_EQ(tlla + 2, t.net.mac, 6);
}

/* REQ-NDP-011: a solicitation for a global address of ours is answered
 * from that address; one for another node's address is not answered */
TEST(itest_ndp_011_each_address_of_ours_and_no_other) {
  uint8_t other[16], gsn[16];
  peer_ip6_t ip;
  peer_icmp_t icmp;
  up_slaac(86400, 14400);
  peer_solicited_node(global, gsn);
  ns(peer6_ll, gsn, global, 1, &nd_ok);
  ASSERT_TRUE(sent(T_NA, &ip, &icmp));
  ASSERT_MEM_EQ(ip.src, global, 16);
  ASSERT_MEM_EQ(icmp.data, global, 16);
  wire_clear(&t);
  memcpy(other, ll, 16);
  other[9] ^= 0x10; /* another address in our solicited-node group */
  ns(peer6_ll, sn, other, 1, &nd_ok);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-NDP-019: without a Source Link-Layer Address option — a unicast
 * solicitation may omit it — the advertisement goes to the MAC the frame
 * came from */
TEST(itest_ndp_019_answer_to_the_frame_source_without_slla) {
  peer_ip6_t ip;
  peer_icmp_t icmp;
  up();
  ns(peer6_ll, ll, ll, 0, &nd_ok);
  ASSERT_TRUE(sent(T_NA, &ip, &icmp));
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, peer_mac, 6);
  ASSERT_MEM_EQ(ip.dst, peer6_ll, 16);
  ASSERT_EQ(icmp.rest[0], NA_S | NA_O);
}

/* REQ-NDP-014, 015: a solicitation shorter than 24 octets, or whose
 * target is a multicast address, is ignored */
TEST(itest_ndp_014_solicitation_validated) {
  nd_fault_t cut = nd_ok;
  up();
  cut.cut = 4; /* 20 octets */
  ns(peer6_ll, sn, ll, 0, &cut);
  ns(peer6_ll, sn, sn, 1, &nd_ok);
  ns(peer6_ll, all_nodes6, all_nodes6, 1, &nd_ok);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-NDP-072: a solicitation from the unspecified address must go to a
 * solicited-node group and carry no Source Link-Layer Address option */
TEST(itest_ndp_072_solicitation_from_unspecified_validated) {
  up();
  ns(unspec, ll, ll, 0, &nd_ok);
  ns(unspec, all_nodes6, ll, 0, &nd_ok);
  ns(unspec, sn, ll, 1, &nd_ok);
  ASSERT_EQ(t.wire.tx_count, 0);
  starting(); /* nor is it a conflict for a tentative address */
  ns(unspec, sn, ll, 1, &nd_ok);
  ns(unspec, all_nodes6, ll, 0, &nd_ok);
  ASSERT_EQ(ipv6_addr_state(&t.net, 0), NET_IP6_TENTATIVE);
}

/* REQ-NDP-016, 018: another node's DAD probe for an address of ours is
 * answered to all-nodes, Solicited 0 */
TEST(itest_ndp_016_dad_probe_of_our_address_defended) {
  peer_ip6_t ip;
  peer_icmp_t icmp;
  up();
  dad_probe(ll);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(sent(T_NA, &ip, &icmp));
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, all_nodes_mac, 6);
  ASSERT_MEM_EQ(ip.dst, all_nodes6, 16);
  ASSERT_MEM_EQ(ip.src, ll, 16);
  ASSERT_EQ(ip.hop_limit, 255);
  ASSERT_EQ(icmp.rest[0], NA_O);
  ASSERT_MEM_EQ(icmp.data, ll, 16);
  ASSERT_NOT_NULL(peer_nd_option(icmp.data + 16, 8, 2));
}

/* ── Neighbor Solicitations sent ── */

/* REQ-NDP-020..026: ndp_send_ns() solicits a neighbour: to the target's
 * solicited-node group and its Ethernet address, Hop Limit 255, from our
 * address of the target's scope, the target, our MAC in a Source
 * Link-Layer Address option */
TEST(itest_ndp_020_solicitation_sent) {
  static const uint8_t neighbour[16] = {0xFE, 0x80, 0,    0,    0,    0,
                                        0,    0,    0x12, 0x34, 0x56, 0x78,
                                        0x9A, 0xBC, 0xDE, 0xF0};
  static const uint8_t group[16] = {0xFF, 0x02, 0, 0, 0,    0,    0,    0,
                                    0,    0,    0, 1, 0xFF, 0xBC, 0xDE, 0xF0};
  static const uint8_t group_mac[6] = {0x33, 0x33, 0xFF, 0xBC, 0xDE, 0xF0};
  uint8_t on_link_global[16];
  peer_ip6_t ip;
  peer_icmp_t icmp;
  const uint8_t *slla;
  up_slaac(86400, 14400);
  ASSERT_EQ(ndp_send_ns(&t.net, neighbour, 0), NET_OK);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(sent(T_NS, &ip, &icmp));
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, group_mac, 6);
  ASSERT_MEM_EQ(ip.dst, group, 16);
  ASSERT_MEM_EQ(ip.src, ll, 16);
  ASSERT_EQ(ip.hop_limit, 255);
  ASSERT_EQ(icmp.code, 0);
  ASSERT_TRUE(icmp.cksum_ok);
  ASSERT_EQ(peer_get32(icmp.rest), 0);
  ASSERT_EQ(icmp.data_len, 16 + 8);
  ASSERT_MEM_EQ(icmp.data, neighbour, 16);
  ASSERT_NOT_NULL(slla = peer_nd_option(icmp.data + 16, 8, 1));
  ASSERT_MEM_EQ(slla + 2, t.net.mac, 6);
  wire_clear(&t);
  memcpy(on_link_global, prefix6, 16);
  on_link_global[15] = 0x77;
  ASSERT_EQ(ndp_send_ns(&t.net, on_link_global, 0), NET_OK);
  ASSERT_TRUE(sent(T_NS, &ip, &icmp));
  ASSERT_MEM_EQ(ip.src, global, 16);
}

/* REQ-NDP-020, 027, 028, 031, 032, 068 (deviations): no neighbour
 * cache — the advertisement answering our solicitation is not recorded,
 * and the stack does not solicit again by itself: the application does */
TEST(itest_ndp_027_advertisements_not_recorded) {
  up();
  ASSERT_EQ(ndp_send_ns(&t.net, peer6_ll, 0), NET_OK);
  wire_clear(&t);
  na(peer6_ll, ll, peer6_ll, NA_S | NA_O, &nd_ok);
  itest_advance(&t, 5000, 100);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_NULL(ipv6_router_mac(&t.net));
  ASSERT_EQ(ndp_send_ns(&t.net, peer6_ll, 0), NET_OK); /* asked again */
  ASSERT_EQ(wire_count_icmp6(&t, T_NS), 1);
}

/* ── Neighbor Advertisements received ── */

/* REQ-NDP-071, REQ-ICMPv6-037: an advertisement that is too short,
 * has the Solicited flag though sent to a multicast address, or carries a
 * zero-length option, is ignored — it does not make a tentative address a
 * duplicate; a valid one does */
TEST(itest_ndp_071_advertisement_validated) {
  nd_fault_t cut = nd_ok;
  uint8_t body[24], rest[4] = {NA_O, 0, 0, 0};
  starting();
  cut.cut = 12; /* 20 octets */
  na(peer6_ll, all_nodes6, ll, NA_O, &cut);
  na(peer6_ll, all_nodes6, ll, NA_S | NA_O, &nd_ok);
  memcpy(body, ll, 16);
  memset(body + 16, 0, 8);
  body[16] = 2; /* a Target Link-Layer Address option of length 0 */
  nd_deliver(peer6_ll, all_nodes6, NULL, T_NA, rest, body, 24, &nd_ok);
  ASSERT_EQ(ipv6_addr_state(&t.net, 0), NET_IP6_TENTATIVE);
  na(peer6_ll, all_nodes6, ll, NA_O, &nd_ok);
  ASSERT_EQ(ipv6_addr_state(&t.net, 0), NET_IP6_DUPLICATE);
}

/* REQ-NDP-033, 008: an advertisement that answers nothing of ours — even
 * one claiming an address we already use — changes nothing and draws
 * nothing */
TEST(itest_ndp_033_unsolicited_advertisement_ignored) {
  up();
  na(peer6_ll, all_nodes6, peer6_ll, NA_O, &nd_ok);
  na(peer6_ll, all_nodes6, ll, NA_O, &nd_ok);
  na(peer6_ll, ll, ll, NA_S | NA_O, &nd_ok);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(ipv6_addr_state(&t.net, 0), NET_IP6_PREFERRED);
  ASSERT_TRUE(answers_echo(peer6_ll, ll));
}

/* ── Router Solicitations ── */

/* REQ-NDP-034..038, 064..066, REQ-SLAAC-028, REQ-ICMPv6-001: once the
 * link-local address is usable, within MAX_RTR_SOLICITATION_DELAY (1 s),
 * a Router Solicitation goes to all-routers — Hop Limit 255, from the
 * link-local address, our MAC in a Source Link-Layer Address option —
 * and MAX_RTR_SOLICITATIONS (3) in all, RTR_SOLICITATION_INTERVAL (4 s)
 * apart */
TEST(itest_ndp_034_router_solicitations) {
  static const uint8_t all_routers_mac[6] = {0x33, 0x33, 0, 0, 0, 2};
  peer_ip6_t ip;
  peer_icmp_t icmp;
  const uint8_t *slla;
  uint8_t k;
  for (k = 0; k < 8; k++) { /* several devices: the delays are random */
    long ms;
    int at;
    itest_up(&t, 1514, 1514);
    t.net.mac[5] = (uint8_t)(k * 37);
    net_random_seed(&t.net, &k, 1);
    peer_link_local(t.net.mac, ll);
    ipv6_start(&t.net);
    while (ipv6_addr_state(&t.net, 0) != NET_IP6_PREFERRED)
      itest_advance(&t, 1, 1);
    ASSERT_EQ(wire_count_icmp6(&t, T_RS), 0); /* none from a tentative one */
    wire_clear(&t);
    ms = advance_until_rs(2000);
    ASSERT_TRUE(ms >= 0 && ms <= 1001);
    at = wire_find_icmp6(&t, 0, T_RS, &ip, &icmp);
    ASSERT_MEM_EQ(wire_sent(&t, (uint16_t)at)->data, all_routers_mac, 6);
    ASSERT_MEM_EQ(ip.dst, all_routers6, 16);
    ASSERT_MEM_EQ(ip.src, ll, 16);
    ASSERT_EQ(ip.hop_limit, 255);
    ASSERT_EQ(icmp.code, 0);
    ASSERT_TRUE(icmp.cksum_ok);
    ASSERT_EQ(peer_get32(icmp.rest), 0);
    ASSERT_EQ(icmp.data_len, 8);
    ASSERT_NOT_NULL(slla = peer_nd_option(icmp.data, 8, 1));
    ASSERT_MEM_EQ(slla + 2, t.net.mac, 6);
    wire_clear(&t);
    ASSERT_EQ(advance_until_rs(10000), 4000);
    ASSERT_EQ(wire_count_icmp6(&t, T_RS), 1);
    wire_clear(&t);
    ASSERT_EQ(advance_until_rs(10000), 4000);
    ASSERT_EQ(wire_count_icmp6(&t, T_RS), 1);
    wire_clear(&t);
    itest_advance(&t, 30000, 100);
    ASSERT_EQ(wire_count_icmp6(&t, T_RS), 0);
  }
}

/* REQ-NDP-073: a valid Router Advertisement with a non-zero Router
 * Lifetime ends the solicitations */
TEST(itest_ndp_073_advertisement_ends_solicitations) {
  ra_t r = ra_default();
  starting();
  while (wire_count_icmp6(&t, T_RS) == 0)
    itest_advance(&t, 10, 10);
  wire_clear(&t);
  ra_send(&r, &nd_ok);
  itest_advance(&t, 30000, 100);
  ASSERT_EQ(wire_count_icmp6(&t, T_RS), 0);
}

/* REQ-ICMPv6-034: a host ignores Router Solicitations */
TEST(itest_ndp_034_router_solicitation_received_ignored) {
  uint8_t opt[8];
  up();
  peer_nd_lla(opt, 1, peer_mac);
  nd_deliver(peer6_ll, ll, NULL, T_RS, NULL, opt, 8, &nd_ok);
  nd_deliver(peer6_ll, all_nodes6, NULL, T_RS, NULL, opt, 8, &nd_ok);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* ── Router Advertisements ── */

/* REQ-NDP-039, 043, 044, 062, REQ-SLAAC-029, 031, REQ-ICMPv6-035: a
 * Router Advertisement with a Router Lifetime makes its sender the default
 * router, at the MAC of its Source Link-Layer Address option;
 * ipv6_router_mac() gives it */
TEST(itest_ndp_039_default_router_learned) {
  static const uint8_t forwarder[6] = {0x02, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4};
  ra_t r = ra_default();
  nd_fault_t via = nd_ok;
  up();
  ASSERT_NULL(ipv6_router_mac(&t.net));
  via.src_mac = forwarder; /* the option, not the frame, names the router */
  ra_send(&r, &via);
  ASSERT_NOT_NULL(ipv6_router_mac(&t.net));
  ASSERT_MEM_EQ(ipv6_router_mac(&t.net), router6_mac, 6);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-NDP-044: without the option, the router's MAC is the frame's
 * source */
TEST(itest_ndp_044_router_mac_from_the_frame_without_slla) {
  ra_t r = ra_default();
  up();
  r.no_slla = 1;
  ra_send(&r, &nd_ok);
  ASSERT_NOT_NULL(ipv6_router_mac(&t.net));
  ASSERT_MEM_EQ(ipv6_router_mac(&t.net), router6_mac, 6);
}

/* REQ-NDP-040: a Router Advertisement from an address that is not
 * link-local, or shorter than 16 octets, is ignored */
TEST(itest_ndp_040_advertisement_validated) {
  ra_t r = ra_default();
  nd_fault_t cut = nd_ok;
  up();
  r.src = offlink6;
  r.prefix = 1;
  ra_send(&r, &nd_ok);
  r.src = NULL;
  r.prefix = 0;
  r.no_slla = 1;
  cut.cut = 4; /* 12 octets */
  ra_send(&r, &cut);
  ASSERT_NULL(ipv6_router_mac(&t.net));
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_NONE);
}

/* REQ-NDP-042: a non-zero Cur Hop Limit becomes the Hop Limit of what we
 * send; zero leaves it as it is */
TEST(itest_ndp_042_cur_hop_limit) {
  static uint8_t f[128];
  ra_t r = ra_default();
  peer_ip6_t ip = peer_ip6(peer6_ll, NULL, 58), rip;
  peer_icmp_t icmp;
  up();
  ip.dst = ll;
  r.cur_hop_limit = 42;
  ra_send(&r, &nd_ok);
  itest_receive(
      &t, f,
      peer_icmp6_frame(f, t.net.mac, &ip, T_ECHO_REQUEST, 0, NULL, "x", 1));
  ASSERT_TRUE(sent(T_ECHO_REPLY, &rip, &icmp));
  ASSERT_EQ(rip.hop_limit, 42);
  wire_clear(&t);
  r.cur_hop_limit = 0;
  ra_send(&r, &nd_ok);
  itest_receive(
      &t, f,
      peer_icmp6_frame(f, t.net.mac, &ip, T_ECHO_REQUEST, 0, NULL, "x", 1));
  ASSERT_TRUE(sent(T_ECHO_REPLY, &rip, &icmp));
  ASSERT_EQ(rip.hop_limit, 42);
  ASSERT_EQ(
      udp6_send(&t.net, peer6_ll, peer_mac, 1, 2, (const uint8_t *)"x", 1),
      NET_OK);
  ASSERT_TRUE(peer_parse_ipv6(wire_sent(&t, 1), &rip));
  ASSERT_EQ(rip.hop_limit, 42);
}

/* REQ-NDP-043: the router is the default router for its Router Lifetime:
 * it is gone when the lifetime runs out, or at once when it advertises a
 * lifetime of 0; an advertisement renews it */
TEST(itest_ndp_043_router_lifetime) {
  static const uint8_t other_router[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                           0,    0,    0, 0, 0, 0, 0, 2};
  ra_t r = ra_default();
  up();
  r.lifetime = 30;
  ra_send(&r, &nd_ok);
  seconds(29);
  ASSERT_NOT_NULL(ipv6_router_mac(&t.net));
  ra_send(&r, &nd_ok); /* renewed */
  seconds(29);
  ASSERT_NOT_NULL(ipv6_router_mac(&t.net));
  seconds(1);
  ASSERT_NULL(ipv6_router_mac(&t.net));
  ra_send(&r, &nd_ok);
  ASSERT_NOT_NULL(ipv6_router_mac(&t.net));
  r.lifetime = 0;
  r.src = other_router; /* another router's goodbye is not ours */
  ra_send(&r, &nd_ok);
  ASSERT_NOT_NULL(ipv6_router_mac(&t.net));
  r.src = NULL;
  ra_send(&r, &nd_ok);
  ASSERT_NULL(ipv6_router_mac(&t.net));
}

/* REQ-NDP-074 (deviation): one default router is kept — the last to
 * advertise a Router Lifetime */
TEST(itest_ndp_074_one_default_router) {
  static const uint8_t other_router[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                           0,    0,    0, 0, 0, 0, 0, 2};
  static const uint8_t other_mac[6] = {0x02, 0x52, 0x4F, 0x55, 0x54, 0x02};
  ra_t r = ra_default();
  nd_fault_t from_other = nd_ok;
  up();
  ra_send(&r, &nd_ok);
  r.src = other_router;
  r.no_slla = 1;
  from_other.src_mac = other_mac;
  ra_send(&r, &from_other);
  ASSERT_MEM_EQ(ipv6_router_mac(&t.net), other_mac, 6);
  r.lifetime = 0;
  ra_send(&r, &from_other);
  ASSERT_NULL(ipv6_router_mac(&t.net)); /* the first is not remembered */
}

/* REQ-NDP-047, 048, REQ-SLAAC-035, 036: the Managed and Other flags of
 * the last Router Advertisement are given to the application, which
 * starts DHCPv6 */
TEST(itest_ndp_047_managed_and_other_flags) {
  ra_t r = ra_default();
  up();
  ASSERT_EQ(t.net.ip6.ra_flags, 0);
  r.flags = RA_M | 0x3F; /* and every bit that is not M or O */
  ra_send(&r, &nd_ok);
  ASSERT_EQ(t.net.ip6.ra_flags, NDP_RA_MANAGED);
  r.flags = RA_O;
  ra_send(&r, &nd_ok);
  ASSERT_EQ(t.net.ip6.ra_flags, NDP_RA_OTHER);
  r.flags = RA_M | RA_O;
  ra_send(&r, &nd_ok);
  ASSERT_EQ(t.net.ip6.ra_flags, NDP_RA_MANAGED | NDP_RA_OTHER);
  r.flags = 0;
  ra_send(&r, &nd_ok);
  ASSERT_EQ(t.net.ip6.ra_flags, 0);
}

/* REQ-NDP-010, 046 (deviations): an MTU option is ignored — packets of
 * the Ethernet MTU are still sent */
TEST(itest_ndp_046_mtu_option_ignored) {
  static uint8_t data[1452];
  uint8_t body[16], rest[4] = {0, 0, 0x07, 0x08};
  up();
  memset(body, 0, sizeof(body));
  body[8] = 5; /* MTU option: 1280 */
  body[9] = 1;
  peer_put32(body + 12, 1280);
  nd_deliver(router6_ll, all_nodes6, NULL, T_RA, rest, body, 16, &nd_ok);
  ASSERT_NOT_NULL(ipv6_router_mac(&t.net));
  ASSERT_EQ(udp6_send(&t.net, peer6_ll, peer_mac, 1, 2, data, sizeof(data)),
            NET_OK);
  ASSERT_EQ(wire_sent(&t, 0)->len, 14 + 1500);
}

/* ── Redirect, Neighbor Unreachability Detection, the cache ── */

/* REQ-NDP-049..053, REQ-ICMPv6-038: Redirects are ignored: the next hop
 * for an off-link destination stays the default router */
TEST(itest_ndp_049_redirect_ignored) {
  static const uint8_t better[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                     0,    0,    0, 0, 0, 0, 0, 3};
  static const uint8_t better_mac[6] = {0x02, 0x52, 0x4F, 0x55, 0x54, 0x03};
  ra_t r = ra_default();
  nd_fault_t from_router = nd_ok;
  uint8_t body[40];
  up();
  ra_send(&r, &nd_ok);
  memcpy(body, better, 16);        /* target: the better first hop */
  memcpy(body + 16, offlink6, 16); /* destination */
  peer_nd_lla(body + 32, 2, better_mac);
  from_router.src_mac = router6_mac;
  nd_deliver(router6_ll, ll, NULL, T_REDIRECT, NULL, body, 40, &from_router);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_MEM_EQ(ipv6_router_mac(&t.net), router6_mac, 6);
  ASSERT_FALSE(ipv6_on_link(&t.net, offlink6));
}

/* REQ-NDP-054..059, 069, 070 (deviations): there is no Neighbor
 * Unreachability Detection: a neighbour we exchange packets with is never
 * probed, however long it stays silent */
TEST(itest_ndp_054_no_unreachability_detection) {
  up();
  ASSERT_TRUE(answers_echo(peer6_ll, ll));
  ASSERT_EQ(
      udp6_send(&t.net, peer6_ll, peer_mac, 1, 2, (const uint8_t *)"x", 1),
      NET_OK);
  wire_clear(&t);
  seconds(120);
  ASSERT_EQ(
      udp6_send(&t.net, peer6_ll, peer_mac, 1, 2, (const uint8_t *)"x", 1),
      NET_OK);
  seconds(60);
  ASSERT_EQ(wire_count_icmp6(&t, T_NS), 0);
  ASSERT_EQ(t.wire.tx_count, 1);
}

/* REQ-NDP-060: no neighbour cache: each reply goes to the MAC its request
 * came from, whatever MAC that address used before */
TEST(itest_ndp_060_no_neighbour_cache) {
  static const uint8_t moved[6] = {0x02, 0x4D, 0x4F, 0x56, 0x45, 0x44};
  static uint8_t f[128];
  peer_ip6_t ip = peer_ip6(peer6_ll, NULL, 58);
  nd_fault_t from_moved = nd_ok;
  uint16_t n;
  up();
  ip.dst = ll;
  ns(peer6_ll, sn, ll, 1, &nd_ok); /* peer6_ll is at peer_mac */
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, peer_mac, 6);
  wire_clear(&t);
  n = peer_icmp6_frame(f, t.net.mac, &ip, T_ECHO_REQUEST, 0, NULL, "x", 1);
  memcpy(f + 6, moved, 6);
  itest_receive(&t, f, n);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, moved, 6);
  wire_clear(&t);
  from_moved.src_mac = moved;
  ns(peer6_ll, ll, ll, 0, &from_moved);
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, moved, 6);
}

/* REQ-NDP-061: a TCP connection keeps its peer's MAC: every segment of a
 * connection opened by a SYN goes to the MAC that SYN came from */
TEST(itest_ndp_061_connection_keeps_the_peer_mac) {
  static tcp_conn_t conn;
  static tcp_conn_t *table[1] = {&conn};
  static tcp_saw_tx_ctx_t tx_ctx;
  static tcp_saw_rx_ctx_t rx_ctx;
  static uint8_t tx_mem[256], rx_mem[256], seg[64], f[128];
  peer_tcp_seg_t s;
  peer_ip6_t ip = peer_ip6(peer6_ll, NULL, 6);
  int i;
  up();
  ip.dst = ll;
  tcp_saw_tx_init(&tx_ctx, tx_mem, sizeof(tx_mem));
  tcp_saw_rx_init(&rx_ctx, rx_mem, sizeof(rx_mem));
  tcp_conn_init(&conn, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops, &rx_ctx,
                NULL);
  tcp_set_connections(&t.net, table, 1);
  tcp_listen(&conn, 80);
  memset(&s, 0, sizeof(s));
  s.sport = 40000;
  s.dport = 80;
  s.seq = 1000;
  s.flags = TCPF_SYN;
  s.window = 4096;
  itest_receive(&t, f,
                peer_ipv6_frame(f, t.net.mac, peer_mac, &ip, seg,
                                peer_tcp6(seg, &ip, &s)));
  ASSERT_EQ(t.wire.tx_count, 1);
  itest_advance(&t, 8000, 100); /* the SYN,ACK again, and again */
  ASSERT_TRUE(t.wire.tx_count >= 3);
  for (i = 0; i < (int)t.wire.tx_count; i++)
    ASSERT_MEM_EQ(wire_sent(&t, (uint16_t)i)->data, peer_mac, 6);
}

/* ── Duplicate Address Detection ── */

/* REQ-SLAAC-004, 005, 006, 011, 013, 039, REQ-NDP-067: the link-local address
 * is probed before it is used: after a delay of at most 1 s, the
 * solicited-node group is reported (MLD), then one Neighbor Solicitation
 * goes from :: to that group — the target the address, no Source
 * Link-Layer Address option, Hop Limit 255 — and no second one */
TEST(itest_slaac_004_link_local_probed) {
  peer_ip6_t ip;
  peer_icmp_t icmp;
  long ms;
  int ns_at, report_at;
  starting();
  ASSERT_EQ(ipv6_addr_state(&t.net, 0), NET_IP6_TENTATIVE);
  ms = advance_until_sent(2000, 1);
  ASSERT_TRUE(ms >= 0 && ms <= 1001);
  ASSERT_EQ(t.wire.tx_count, 2);
  report_at = wire_find_icmp6(&t, 0, T_MLD_V2_REPORT, &ip, &icmp);
  ASSERT_MEM_EQ(ip.src, unspec, 16); /* no usable address yet */
  ASSERT_MEM_EQ(icmp.data + 4, sn, 16);
  ns_at = wire_find_icmp6(&t, 0, T_NS, &ip, &icmp);
  ASSERT_TRUE(report_at == 0 && ns_at == 1);
  ASSERT_MEM_EQ(wire_sent(&t, 1)->data, sn_mac, 6);
  ASSERT_MEM_EQ(ip.src, unspec, 16);
  ASSERT_MEM_EQ(ip.dst, sn, 16);
  ASSERT_EQ(ip.hop_limit, 255);
  ASSERT_EQ(icmp.code, 0);
  ASSERT_TRUE(icmp.cksum_ok);
  ASSERT_EQ(icmp.data_len, 16); /* no option */
  ASSERT_MEM_EQ(icmp.data, ll, 16);
  itest_advance(&t, 20000, 100);
  ASSERT_EQ(wire_count_icmp6(&t, T_NS), 1);
}

/* REQ-SLAAC-007, 010, REQ-NDP-067: RetransTimer (1 s) after the probe,
 * with nothing heard, the address is assigned — not a millisecond
 * before */
TEST(itest_slaac_007_assigned_after_retrans_timer) {
  starting();
  ASSERT_TRUE(advance_until_sent(2000, 1) >= 0);
  itest_advance(&t, 999, 1);
  ASSERT_EQ(ipv6_addr_state(&t.net, 0), NET_IP6_TENTATIVE);
  ASSERT_FALSE(ipv6_is_ours(&t.net, ll));
  itest_advance(&t, 1, 1);
  ASSERT_EQ(ipv6_addr_state(&t.net, 0), NET_IP6_PREFERRED);
  ASSERT_TRUE(ipv6_is_ours(&t.net, ll));
  ASSERT_TRUE(answers_echo(peer6_ll, ll));
}

/* REQ-SLAAC-012, REQ-IPv6-010: a tentative address is not used: nothing
 * is sent from it, packets to it are dropped, solicitations for it from a
 * unicast address are not answered */
TEST(itest_slaac_012_tentative_address_not_used) {
  starting();
  ASSERT_EQ(
      udp6_send(&t.net, peer6_ll, peer_mac, 1, 2, (const uint8_t *)"x", 1),
      NET_ERR_INVALID_PARAM);
  ASSERT_EQ(ndp_send_ns(&t.net, peer6_ll, 0), NET_ERR_INVALID_PARAM);
  ASSERT_FALSE(answers_echo(peer6_ll, ll));
  ns(peer6_ll, sn, ll, 1, &nd_ok);
  ns(peer6_ll, ll, ll, 1, &nd_ok);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(ipv6_addr_state(&t.net, 0), NET_IP6_TENTATIVE);
}

/* REQ-SLAAC-008: a Neighbor Advertisement for the tentative address: it
 * is a duplicate, and never used — no probe, no Router Solicitation, no
 * answer to solicitations or echo requests, nothing sent from it */
TEST(itest_slaac_008_advertisement_means_duplicate) {
  starting();
  ASSERT_TRUE(advance_until_sent(2000, 1) >= 0);
  na(peer6_ll, all_nodes6, ll, NA_O, &nd_ok);
  ASSERT_EQ(ipv6_addr_state(&t.net, 0), NET_IP6_DUPLICATE);
  wire_clear(&t);
  itest_advance(&t, 20000, 100);
  ns(peer6_ll, sn, ll, 1, &nd_ok);
  dad_probe(ll);
  ASSERT_FALSE(answers_echo(peer6_ll, ll));
  ASSERT_EQ(
      udp6_send(&t.net, peer6_ll, peer_mac, 1, 2, (const uint8_t *)"x", 1),
      NET_ERR_INVALID_PARAM);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(ipv6_addr_state(&t.net, 0), NET_IP6_DUPLICATE);
}

/* REQ-SLAAC-009, 013: another node's probe for the tentative address —
 * also one that arrives during the delay before ours — makes it a
 * duplicate: its solicited-node group is listened to from the start */
TEST(itest_slaac_009_probe_from_another_means_duplicate) {
  starting();
  dad_probe(ll); /* before ours */
  ASSERT_EQ(ipv6_addr_state(&t.net, 0), NET_IP6_DUPLICATE);
  starting();
  ASSERT_TRUE(advance_until_sent(2000, 1) >= 0);
  itest_advance(&t, 500, 100);
  dad_probe(ll); /* after ours */
  ASSERT_EQ(ipv6_addr_state(&t.net, 0), NET_IP6_DUPLICATE);
}

/* ── Global addresses from Router Advertisements ── */

/* REQ-SLAAC-014, 017, 018, REQ-NDP-009, 045: an autonomous /64 prefix
 * gives the address prefix + interface identifier; it is probed (without
 * the start-up delay), then used: it answers, from itself */
TEST(itest_slaac_014_global_address_formed) {
  uint8_t gsn[16];
  peer_ip6_t ip;
  peer_icmp_t icmp;
  up();
  ra_prefix(86400, 14400);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_TENTATIVE);
  ASSERT_FALSE(answers_echo(offlink6, global));
  itest_advance(&t, 1, 1);
  ASSERT_TRUE(sent(T_NS, &ip, &icmp));
  peer_solicited_node(global, gsn);
  ASSERT_MEM_EQ(ip.src, unspec, 16);
  ASSERT_MEM_EQ(ip.dst, gsn, 16);
  ASSERT_MEM_EQ(icmp.data, global, 16);
  ASSERT_EQ(icmp.data_len, 16);
  itest_advance(&t, 1000, 100);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_PREFERRED);
  ASSERT_TRUE(answers_echo(offlink6, global));
  ra_prefix(86400, 14400); /* the same prefix again: no second address */
  itest_advance(&t, 3000, 100);
  ASSERT_EQ(wire_count_icmp6(&t, T_NS), 0);
}

/* REQ-SLAAC-015, 016, 021: a prefix without the Autonomous flag, of a
 * length other than 64, with a preferred lifetime above the valid one, of
 * valid lifetime 0, or the link-local prefix, forms no address */
TEST(itest_slaac_015_prefixes_not_used) {
  static const uint8_t link_local_prefix[16] = {0xFE, 0x80};
  static const uint8_t link_local_subnet[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 1};
  uint8_t body[48], rest[4] = {0, 0, 0x07, 0x08};
  ra_t r;
  up();
  r = ra_default();
  r.prefix = 1;
  r.prefix_flags = PI_L;
  ra_send(&r, &nd_ok);
  r = ra_default();
  r.prefix = 1;
  r.prefix_len = 63;
  ra_send(&r, &nd_ok);
  r.prefix_len = 65;
  ra_send(&r, &nd_ok);
  r = ra_default();
  r.prefix = 1;
  r.valid = 100;
  r.preferred = 101;
  ra_send(&r, &nd_ok);
  r = ra_default();
  r.prefix = 1;
  r.valid = 0;
  r.preferred = 0;
  ra_send(&r, &nd_ok);
  r = ra_default();
  r.prefix = 1;
  r.prefix_addr = link_local_prefix;
  r.preferred = 0; /* nor does it touch the link-local address */
  ra_send(&r, &nd_ok);
  ASSERT_EQ(ipv6_addr_state(&t.net, 0), NET_IP6_PREFERRED);
  r.prefix_addr = link_local_subnet;
  r.preferred = 14400;
  ra_send(&r, &nd_ok);
  /* an option of another type, though laid out like a prefix */
  memset(body, 0, sizeof(body));
  peer_nd_lla(body + 8, 1, router6_mac);
  peer_nd_prefix(body + 16, prefix6, 64, PI_L | PI_A, 86400, 14400);
  body[16] = 200;
  nd_deliver(router6_ll, all_nodes6, NULL, T_RA, rest, body, 48, &nd_ok);
  itest_advance(&t, 3000, 100);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_NONE);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-SLAAC-008, 018: a global address found to be a duplicate is not
 * used, and later advertisements of the prefix neither revive it nor
 * keep it: when its valid lifetime has run out, the next advertisement
 * forms the address anew, and it is probed again */
TEST(itest_slaac_018_duplicate_global_address) {
  up();
  ra_prefix(100, 100);
  itest_advance(&t, 100, 100);
  na(peer6_ll, all_nodes6, global, NA_O, &nd_ok);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_DUPLICATE);
  seconds(50);
  ra_prefix(100, 100);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_DUPLICATE);
  ASSERT_FALSE(answers_echo(offlink6, global));
  ASSERT_TRUE(answers_echo(peer6_ll, ll)); /* the link-local one works on */
  seconds(51);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_NONE);
  wire_clear(&t);
  ra_prefix(100, 100);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_TENTATIVE);
  itest_advance(&t, 1100, 100);
  ASSERT_EQ(wire_count_icmp6(&t, T_NS), 1);
  ASSERT_TRUE(answers_echo(offlink6, global));
}

/* REQ-SLAAC-019, 020, 022, 023: the address is preferred for the
 * Preferred Lifetime, then deprecated — still ours, still answering —
 * until the Valid Lifetime ends: then it is neither a source nor a
 * destination */
TEST(itest_slaac_019_lifetimes) {
  peer_ip6_t ip;
  up_slaac(100, 50);
  seconds(47); /* 2 s went by in up_slaac() */
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_PREFERRED);
  seconds(1);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_DEPRECATED);
  ASSERT_TRUE(answers_echo(offlink6, global));
  wire_clear(&t);
  ASSERT_EQ(
      udp6_send(&t.net, offlink6, router6_mac, 1, 2, (const uint8_t *)"x", 1),
      NET_OK); /* no preferred address fits: the deprecated one */
  ASSERT_TRUE(peer_parse_ipv6(wire_sent(&t, 0), &ip));
  ASSERT_MEM_EQ(ip.src, global, 16);
  seconds(49);
  ASSERT_TRUE(answers_echo(offlink6, global));
  seconds(1);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_NONE);
  ASSERT_FALSE(answers_echo(offlink6, global));
  ASSERT_EQ(
      udp6_send(&t.net, offlink6, router6_mac, 1, 2, (const uint8_t *)"x", 1),
      NET_ERR_INVALID_PARAM);
  ASSERT_TRUE(answers_echo(peer6_ll, ll)); /* the link-local never expires */
}

/* REQ-SLAAC-019: a lifetime of 0xFFFFFFFF is infinite */
TEST(itest_slaac_019_infinite_lifetime) {
  up_slaac(FOREVER, FOREVER);
  itest_advance(&t, 400000000u, 4000000u); /* more than four days */
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_PREFERRED);
}

/* REQ-SLAAC-024: every advertisement of the prefix resets the preferred
 * lifetime: 0 deprecates the address at once, more makes it preferred
 * again */
TEST(itest_slaac_024_preferred_lifetime_reset) {
  up_slaac(86400, 14400);
  ra_prefix(86400, 0);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_DEPRECATED);
  ra_prefix(86400, 10);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_PREFERRED);
  seconds(10);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_DEPRECATED);
  ra_prefix(86400, 14400);
  seconds(20);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_PREFERRED);
}

/* REQ-SLAAC-025: a valid lifetime longer than the time remaining is
 * taken */
TEST(itest_slaac_025_longer_valid_lifetime_taken) {
  up_slaac(100, 100);
  seconds(50);
  ra_prefix(200, 200);
  seconds(199);
  ASSERT_TRUE(answers_echo(offlink6, global));
  seconds(1);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_NONE);
}

/* REQ-SLAAC-026: a valid lifetime above two hours is taken even though
 * it shortens the time remaining */
TEST(itest_slaac_026_valid_lifetime_above_two_hours_taken) {
  up_slaac(86400, 14400);
  ra_prefix(TWO_HOURS + 100, 100);
  seconds(TWO_HOURS + 99);
  ASSERT_TRUE(answers_echo(offlink6, global));
  seconds(1);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_NONE);
}

/* REQ-SLAAC-027: a valid lifetime of two hours or less cannot expire the
 * address early: with more than two hours remaining they become two
 * hours; with two hours or less remaining they stay as they are */
TEST(itest_slaac_027_two_hour_rule) {
  up_slaac(86400, 14400);
  ra_prefix(60, 60);
  seconds(TWO_HOURS - 1);
  ASSERT_TRUE(answers_echo(offlink6, global));
  seconds(1);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_NONE);

  up_slaac(3600, 3600);
  ra_prefix(60, 60);
  seconds(3597); /* 2 s went by in up_slaac() */
  ASSERT_TRUE(answers_echo(offlink6, global));
  seconds(1);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_NONE);

  up_slaac(86400, 14400);
  ra_prefix(0, 0); /* "expire now" is no exception */
  seconds(TWO_HOURS - 1);
  ASSERT_TRUE(answers_echo(offlink6, global));
  seconds(1);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_NONE);
}

/* REQ-SLAAC-030, REQ-NDP-075: the next hop: link-local destinations and
 * those in the /64 of a global address of ours are on the link; any other
 * goes to the default router's MAC, and without a router there is none */
TEST(itest_slaac_030_next_hop) {
  uint8_t neighbour[16];
  ra_t r = ra_default();
  up();
  ASSERT_TRUE(ipv6_on_link(&t.net, peer6_ll));
  ASSERT_FALSE(ipv6_on_link(&t.net, offlink6));
  ASSERT_NULL(ipv6_router_mac(&t.net));
  r.prefix = 1;
  ra_send(&r, &nd_ok);
  itest_advance(&t, 2000, 100);
  memcpy(neighbour, prefix6, 16);
  neighbour[15] = 0x77;
  ASSERT_TRUE(ipv6_on_link(&t.net, neighbour));
  neighbour[7] ^= 0x01; /* the next /64 */
  ASSERT_FALSE(ipv6_on_link(&t.net, neighbour));
  ASSERT_FALSE(ipv6_on_link(&t.net, offlink6));
  ASSERT_MEM_EQ(ipv6_router_mac(&t.net), router6_mac, 6);
}

/* REQ-SLAAC-037: with one global slot (NET_IPV6_ADDRS 2) the first global
 * address keeps it: a second prefix, or an address added by hand or by
 * DHCPv6, finds no room */
TEST(itest_slaac_037_one_global_slot) {
  static const uint8_t prefix2[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 2};
  static const uint8_t manual[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 3, 0, 0,
                                     0,    0,    0,    0,    0, 0, 0, 5};
  ra_t r = ra_default();
  up_slaac(86400, 14400);
  r.prefix = 1;
  r.prefix_addr = prefix2;
  ra_send(&r, &nd_ok);
  itest_advance(&t, 3000, 100);
  ASSERT_EQ(wire_count_icmp6(&t, T_NS), 0);
  ASSERT_TRUE(ipv6_is_ours(&t.net, global));
  if (NET_IPV6_ADDRS == 2)
    ASSERT_EQ(ipv6_addr_add(&t.net, manual, FOREVER, FOREVER),
              NET_ERR_BUF_TOO_SMALL);
}

int main(void) {
  fprintf(stderr, "=== itest_ndp ===\n");
  RUN_TEST(itest_ndp_001_hop_limit_255_required);
  RUN_TEST(itest_ndp_002_code_zero_required);
  RUN_TEST(itest_ndp_003_checksum_required);
  RUN_TEST(itest_ndp_004_options_walked);
  RUN_TEST(itest_ndp_006_zero_length_option_discards);
  RUN_TEST(itest_ndp_011_solicitation_answered);
  RUN_TEST(itest_ndp_011_each_address_of_ours_and_no_other);
  RUN_TEST(itest_ndp_019_answer_to_the_frame_source_without_slla);
  RUN_TEST(itest_ndp_014_solicitation_validated);
  RUN_TEST(itest_ndp_072_solicitation_from_unspecified_validated);
  RUN_TEST(itest_ndp_016_dad_probe_of_our_address_defended);
  RUN_TEST(itest_ndp_020_solicitation_sent);
  RUN_TEST(itest_ndp_027_advertisements_not_recorded);
  RUN_TEST(itest_ndp_071_advertisement_validated);
  RUN_TEST(itest_ndp_033_unsolicited_advertisement_ignored);
  RUN_TEST(itest_ndp_034_router_solicitations);
  RUN_TEST(itest_ndp_073_advertisement_ends_solicitations);
  RUN_TEST(itest_ndp_034_router_solicitation_received_ignored);
  RUN_TEST(itest_ndp_039_default_router_learned);
  RUN_TEST(itest_ndp_044_router_mac_from_the_frame_without_slla);
  RUN_TEST(itest_ndp_040_advertisement_validated);
  RUN_TEST(itest_ndp_042_cur_hop_limit);
  RUN_TEST(itest_ndp_043_router_lifetime);
  RUN_TEST(itest_ndp_074_one_default_router);
  RUN_TEST(itest_ndp_047_managed_and_other_flags);
  RUN_TEST(itest_ndp_046_mtu_option_ignored);
  RUN_TEST(itest_ndp_049_redirect_ignored);
  RUN_TEST(itest_ndp_054_no_unreachability_detection);
  RUN_TEST(itest_ndp_060_no_neighbour_cache);
  RUN_TEST(itest_ndp_061_connection_keeps_the_peer_mac);
  RUN_TEST(itest_slaac_004_link_local_probed);
  RUN_TEST(itest_slaac_007_assigned_after_retrans_timer);
  RUN_TEST(itest_slaac_012_tentative_address_not_used);
  RUN_TEST(itest_slaac_008_advertisement_means_duplicate);
  RUN_TEST(itest_slaac_009_probe_from_another_means_duplicate);
  RUN_TEST(itest_slaac_014_global_address_formed);
  RUN_TEST(itest_slaac_015_prefixes_not_used);
  RUN_TEST(itest_slaac_018_duplicate_global_address);
  RUN_TEST(itest_slaac_019_lifetimes);
  RUN_TEST(itest_slaac_019_infinite_lifetime);
  RUN_TEST(itest_slaac_024_preferred_lifetime_reset);
  RUN_TEST(itest_slaac_025_longer_valid_lifetime_taken);
  RUN_TEST(itest_slaac_026_valid_lifetime_above_two_hours_taken);
  RUN_TEST(itest_slaac_027_two_hour_rule);
  RUN_TEST(itest_slaac_030_next_hop);
  RUN_TEST(itest_slaac_037_one_global_slot);
  ITEST_REPORT();
  return test_failures;
}
