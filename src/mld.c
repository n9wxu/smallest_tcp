/**
 * @file mld.c
 * @brief Multicast Listener Discovery for hosts: MLDv2 (RFC 3810) with
 *        MLDv1 (RFC 2710) compatibility.
 *
 * REQ-IPv6-049..054.  Reports go out with a Hop-by-Hop Router Alert, Hop
 * Limit 1, from the link-local address (from :: before it is usable,
 * RFC 3810 §5.2.13).
 * Simplifications: a group-specific query is answered with a report of
 * all our groups; a leave is sent once (joins are repeated once).
 */

#include "mld.h"
#include "icmpv6.h"
#include "net_endian.h"
#include <string.h>

#define HOP_BY_HOP_LEN 8
#define MLD_MSG_OFFSET (ETH_HDR_SIZE + IPV6_HDR_SIZE + HOP_BY_HOP_LEN)
#define MLD_RECORD_LEN 20
#define MLD_MAX_GROUPS (NET_IPV6_ADDRS + NET_MAX_MCAST6_GROUPS)
#define MLD_QUERY_OFF_MAX_RESP 4
#define MLD_OFF_GROUP 8

static const uint8_t all_mldv2_routers[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                              0,    0,    0, 0, 0, 0, 0, 0x16};

typedef uint8_t group_list_t[MLD_MAX_GROUPS][16];

static int listening(const net_t *net) {
  return net->ip6.addr[0].state != NET_IP6_NONE;
}

/* Our groups: the solicited-node group of every configured address (once
 * each), then the joined groups.  All-nodes is never reported (§6). */
static uint8_t our_groups(const net_t *net, group_list_t out) {
  uint8_t n = 0, i, k, group[16];
  for (i = 0; i < NET_IPV6_ADDRS; i++) {
    uint8_t state = net->ip6.addr[i].state;
    if (state == NET_IP6_NONE || state == NET_IP6_DUPLICATE)
      continue;
    ipv6_solicited_node(net->ip6.addr[i].addr, group);
    for (k = 0; k < n && !ipv6_addr_equal(out[k], group); k++) {
    }
    if (k == n)
      memcpy(out[n++], group, 16);
  }
#if NET_MAX_MCAST6_GROUPS > 0
  for (i = 0; i < NET_MAX_MCAST6_GROUPS; i++) {
    if (!ipv6_is_unspecified(net->mcast6_groups[i]))
      memcpy(out[n++], net->mcast6_groups[i], 16);
  }
#endif
  return n;
}

static int is_our_group(const net_t *net, const uint8_t *group) {
  group_list_t list;
  uint8_t n = our_groups(net, list), k;
  for (k = 0; k < n; k++) {
    if (ipv6_addr_equal(list[k], group))
      return 1;
  }
  return 0;
}

/* The MLD message of @p len bytes at MLD_MSG_OFFSET, to @p dst */
static void mld_send(net_t *net, const uint8_t *dst, uint16_t len) {
  static const uint8_t router_alert_mld[HOP_BY_HOP_LEN] = {
      IPV6_NH_ICMPV6, 0, 5, 2, 0, 0, 1, 0};
  uint8_t *msg = net->tx.buf + MLD_MSG_OFFSET;
  uint8_t mac[6];
  const uint8_t *src = ipv6_is_ours(net, net->ip6.addr[0].addr)
                           ? net->ip6.addr[0].addr
                           : ipv6_unspecified;

  memcpy(net->tx.buf + ETH_HDR_SIZE + IPV6_HDR_SIZE, router_alert_mld,
         HOP_BY_HOP_LEN);
  net_write16be(msg + ICMPV6_OFF_CKSUM, 0);
  net_write16be(msg + ICMPV6_OFF_CKSUM,
                ipv6_cksum(src, dst, IPV6_NH_ICMPV6, msg, len));
  ipv6_mcast_mac(dst, mac);
  eth_build(net->tx.buf, net->tx.capacity, mac, net->mac, NET_ETHERTYPE_IPV6);
  ipv6_build(net->tx.buf + ETH_HDR_SIZE, (uint16_t)(HOP_BY_HOP_LEN + len),
             IPV6_NH_HOPOPT, src, dst, MLD_HOP_LIMIT);
  net_transmit(net, (uint16_t)(MLD_MSG_OFFSET + len));
}

/* MLDv2 report: a record of @p type for each group in @p list */
static void send_v2(net_t *net, uint8_t type, group_list_t list, uint8_t n) {
  uint8_t *msg = net->tx.buf + MLD_MSG_OFFSET;
  uint16_t len = (uint16_t)(8 + MLD_RECORD_LEN * n);
  uint8_t k;

  if (n == 0 || net->tx.capacity < MLD_MSG_OFFSET + len)
    return;
  memset(msg, 0, 8);
  msg[ICMPV6_OFF_TYPE] = MLD_V2_REPORT;
  net_write16be(msg + 6, n);
  for (k = 0; k < n; k++) {
    uint8_t *record = msg + 8 + MLD_RECORD_LEN * k;
    memset(record, 0, 4); /* no auxiliary data, no sources */
    record[0] = type;
    memcpy(record + 4, list[k], 16);
  }
  mld_send(net, all_mldv2_routers, len);
}

/* MLDv1 Report (to the group) or Done (to all-routers) */
static void send_v1(net_t *net, uint8_t type, const uint8_t *group) {
  uint8_t *msg = net->tx.buf + MLD_MSG_OFFSET;
  if (net->tx.capacity < MLD_MSG_OFFSET + MLD_V1_QUERY_LEN)
    return;
  memset(msg, 0, MLD_V1_QUERY_LEN);
  msg[ICMPV6_OFF_TYPE] = type;
  memcpy(msg + MLD_OFF_GROUP, group, 16);
  mld_send(net, type == MLD_V1_DONE ? ipv6_all_routers : group,
           MLD_V1_QUERY_LEN);
}

static int v1_mode(const net_t *net) {
  return net->ip6.mld.v1_querier_left_s != 0;
}

/* Every group: MLDv2 records of @p v2_type, or one MLDv1 report each */
static void report_all(net_t *net, uint8_t v2_type) {
  group_list_t list;
  uint8_t n = our_groups(net, list), k;
  if (!v1_mode(net)) {
    send_v2(net, v2_type, list, n);
    return;
  }
  for (k = 0; k < n; k++)
    send_v1(net, MLD_V1_REPORT, list[k]);
}

void mld_report_change(net_t *net, const uint8_t *leaving) {
  group_list_t list;
  if (!listening(net))
    return; /* the report sent before DAD's first probe covers all */
  if (leaving && v1_mode(net)) {
    send_v1(net, MLD_V1_DONE, leaving);
  } else if (leaving) {
    memcpy(list[0], leaving, 16);
    send_v2(net, MLD_CHANGE_TO_INCLUDE, list, 1);
  } else {
    report_all(net, MLD_CHANGE_TO_EXCLUDE);
    net->ip6.mld.report_repeat_ms = MLD_UNSOLICITED_INTERVAL_MS;
  }
}

/* Maximum Response Delay in ms: MLDv1 gives it directly, MLDv2 as a
 * floating-point code (RFC 3810 §5.1.3) */
static uint32_t max_response_ms(const uint8_t *msg, uint16_t len) {
  uint16_t code = net_read16be(msg + MLD_QUERY_OFF_MAX_RESP);
  if (len == MLD_V1_QUERY_LEN || code < 32768u)
    return code;
  return (uint32_t)((code & 0x0FFFu) | 0x1000u) << (((code >> 12) & 7u) + 3u);
}

/* RFC 3810 §5.1.14, §6.2, §8.2.1: a query from a link-local router, Hop
 * Limit 1.  Reports and Dones of other listeners need nothing from us. */
void mld_input(net_t *net, const ipv6_hdr_t *ip) {
  const uint8_t *msg = ip->payload;
  uint16_t len = ip->payload_len;
  uint32_t max_ms, delay;

  if (msg[ICMPV6_OFF_TYPE] != MLD_QUERY || ip->hop_limit != MLD_HOP_LIMIT ||
      !ipv6_is_link_local(ip->src))
    return;
  if (len != MLD_V1_QUERY_LEN && len < MLD_V2_QUERY_MIN_LEN)
    return;
  if (len == MLD_V1_QUERY_LEN)
    net->ip6.mld.v1_querier_left_s = MLD_OLDER_QUERIER_S;
  if (!ipv6_is_unspecified(msg + MLD_OFF_GROUP) &&
      !is_our_group(net, msg + MLD_OFF_GROUP))
    return;

  /* Answer after a random delay up to the maximum; an earlier pending
   * answer stands */
  max_ms = max_response_ms(msg, len);
  delay = net_random_below(net, (max_ms > 65535u ? 65535u : max_ms) + 1u);
  if (delay == 0)
    delay = 1;
  if (net->ip6.mld.query_reply_ms == 0 || delay < net->ip6.mld.query_reply_ms)
    net->ip6.mld.query_reply_ms = (uint16_t)delay;
}

void mld_tick(net_t *net, uint32_t elapsed_ms) {
  net_mld_t *mld = &net->ip6.mld;
  if (mld->query_reply_ms && net_countdown16(&mld->query_reply_ms, elapsed_ms))
    report_all(net, MLD_MODE_IS_EXCLUDE);
  if (mld->report_repeat_ms &&
      net_countdown16(&mld->report_repeat_ms, elapsed_ms))
    report_all(net, MLD_CHANGE_TO_EXCLUDE);
}

void mld_seconds_elapse(net_t *net, uint32_t secs) {
  net_mld_t *mld = &net->ip6.mld;
  mld->v1_querier_left_s = mld->v1_querier_left_s > secs
                               ? (uint16_t)(mld->v1_querier_left_s - secs)
                               : 0;
}
