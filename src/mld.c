/**
 * @file mld.c
 * @brief Multicast Listener Discovery for hosts: MLDv2 (RFC 3810) with
 *        MLDv1 (RFC 2710) compatibility.
 *
 * Reports go out with a Hop-by-Hop Router Alert, Hop Limit 1, from the
 * link-local address (from :: before it is usable, RFC 3810 §5.2.13).
 * Simplifications: a group-specific query is answered with a report of
 * all our groups; a leave is sent once (joins are repeated once).
 */

#include "mld.h"
#include "icmpv6.h"
#include "net_endian.h"
#include <string.h>

#define MLD_MSG_OFFSET (ETH_HDR_SIZE + IPV6_HDR_SIZE + 8) /* after the HBH */
#define MLD_RECORD_LEN 20
#define MLD_MAX_GROUPS (NET_IPV6_ADDRS + NET_MAX_MCAST6_GROUPS)

static const uint8_t all_mldv2[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                      0,    0,    0, 0, 0, 0, 0, 0x16};
static const uint8_t all_routers[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                        0,    0,    0, 0, 0, 0, 0, 2};
static const uint8_t unspecified[16] = {0};

/** Our listening groups: the solicited-node group of every configured
 *  address (once each), then the joined groups. */
static uint8_t groups(const net_t *net, uint8_t out[][16]) {
  uint8_t n = 0, i, k, g[16];
  for (i = 0; i < NET_IPV6_ADDRS; i++) {
    uint8_t st = net->ip6[i].state;
    if (st == NET_IP6_NONE || st == NET_IP6_DUPLICATE)
      continue;
    ipv6_solicited_node(net->ip6[i].addr, g);
    for (k = 0; k < n && !ipv6_addr_equal(out[k], g); k++) {
    }
    if (k == n)
      memcpy(out[n++], g, 16);
  }
#if NET_MAX_MCAST6_GROUPS > 0
  for (i = 0; i < NET_MAX_MCAST6_GROUPS; i++) {
    if (!ipv6_is_unspecified(net->mcast6_groups[i]))
      memcpy(out[n++], net->mcast6_groups[i], 16);
  }
#endif
  return n;
}

/** Send the MLD message of @p len bytes at MLD_MSG_OFFSET to @p dst. */
static void mld_send(net_t *net, const uint8_t *dst, uint16_t len) {
  static const uint8_t hbh[8] = {IPV6_NH_ICMPV6, 0, 5, 2, 0, 0, 1, 0};
  uint8_t *buf = net->tx.buf;
  uint8_t *msg = buf + MLD_MSG_OFFSET;
  uint8_t mac[6];
  const uint8_t *src = (net->ip6[0].state == NET_IP6_PREFERRED ||
                        net->ip6[0].state == NET_IP6_DEPRECATED)
                           ? net->ip6[0].addr
                           : unspecified;

  memcpy(buf + ETH_HDR_SIZE + IPV6_HDR_SIZE, hbh, 8); /* Router Alert: MLD */
  net_write16be(msg + ICMPV6_OFF_CKSUM, 0);
  net_write16be(msg + ICMPV6_OFF_CKSUM,
                ipv6_cksum(src, dst, IPV6_NH_ICMPV6, msg, len));
  ipv6_mcast_mac(dst, mac);
  eth_build(buf, net->tx.capacity, mac, net->mac, NET_ETHERTYPE_IPV6);
  ipv6_build(buf + ETH_HDR_SIZE, (uint16_t)(8 + len), IPV6_NH_HOPOPT, src,
             dst, MLD_HOP_LIMIT);
  net->mac_driver->send(net->mac_ctx, buf, (uint16_t)(MLD_MSG_OFFSET + len));
}

/** MLDv2 report: one record of @p type per current group, or for @p only. */
static void send_v2(net_t *net, uint8_t type, const uint8_t *only) {
  uint8_t list[MLD_MAX_GROUPS][16];
  uint8_t n, k;
  uint8_t *msg = net->tx.buf + MLD_MSG_OFFSET;

  if (only) {
    memcpy(list[0], only, 16);
    n = 1;
  } else {
    n = groups(net, list);
  }
  uint16_t len = (uint16_t)(8 + MLD_RECORD_LEN * n);
  if (n == 0 || net->tx.capacity < MLD_MSG_OFFSET + len)
    return;
  memset(msg, 0, 8);
  msg[ICMPV6_OFF_TYPE] = MLD_V2_REPORT;
  net_write16be(msg + 6, n);
  for (k = 0; k < n; k++) {
    uint8_t *r = msg + 8 + MLD_RECORD_LEN * k;
    r[0] = type; /* no auxiliary data, no sources */
    r[1] = 0;
    net_write16be(r + 2, 0);
    memcpy(r + 4, list[k], 16);
  }
  mld_send(net, all_mldv2, len);
}

/** MLDv1 Report (to the group) or Done (to all-routers). */
static void send_v1(net_t *net, uint8_t type, const uint8_t *group) {
  uint8_t *msg = net->tx.buf + MLD_MSG_OFFSET;
  if (net->tx.capacity < MLD_MSG_OFFSET + MLD_V1_QUERY_LEN)
    return;
  memset(msg, 0, MLD_V1_QUERY_LEN);
  msg[ICMPV6_OFF_TYPE] = type;
  memcpy(msg + 8, group, 16);
  mld_send(net, type == MLD_V1_DONE ? all_routers : group, MLD_V1_QUERY_LEN);
}

/** Report every group: MLDv2 records of @p v2_type, or MLDv1 reports. */
static void report_all(net_t *net, uint8_t v2_type) {
  if (net->mld_v1_s) {
    uint8_t list[MLD_MAX_GROUPS][16];
    uint8_t n = groups(net, list), k;
    for (k = 0; k < n; k++)
      send_v1(net, MLD_V1_REPORT, list[k]);
  } else {
    send_v2(net, v2_type, NULL);
  }
}

void mld_report_change(net_t *net, const uint8_t *leaving) {
  if (net->ip6[0].state == NET_IP6_NONE)
    return; /* IPv6 not started: DAD's report will include every group */
  if (leaving) {
    if (net->mld_v1_s)
      send_v1(net, MLD_V1_DONE, leaving);
    else
      send_v2(net, MLD_CHANGE_TO_INCLUDE, leaving);
    return;
  }
  report_all(net, MLD_CHANGE_TO_EXCLUDE);
  net->mld_unsol_ms = MLD_UNSOLICITED_INTERVAL_MS; /* Robustness 2 */
}

void mld_input(net_t *net, const ipv6_hdr_t *ip) {
  const uint8_t *msg = ip->payload;
  uint16_t len = ip->payload_len;
  uint32_t max_ms;

  /* Reports and Dones of other listeners need nothing from us (MLDv2
   * has no report suppression) */
  if (msg[ICMPV6_OFF_TYPE] != MLD_QUERY)
    return;
  /* RFC 3810 §5.1.14: from a link-local router, Hop Limit 1 */
  if (ip->hop_limit != MLD_HOP_LIMIT || !ipv6_is_link_local(ip->src))
    return;
  if (len == MLD_V1_QUERY_LEN) {
    net->mld_v1_s = MLD_OLDER_QUERIER_S; /* §8.2.1: MLDv1 compatibility */
    max_ms = net_read16be(msg + 4);
  } else if (len >= MLD_V2_QUERY_MIN_LEN) {
    uint16_t code = net_read16be(msg + 4); /* Maximum Response Code */
    max_ms = code < 32768u ? code
                           : (uint32_t)((code & 0x0FFFu) | 0x1000u)
                                 << (((code >> 12) & 7u) + 3u);
  } else {
    return;
  }

  /* A group-specific query only concerns us if it is one of our groups */
  if (!ipv6_is_unspecified(msg + 8)) {
    uint8_t list[MLD_MAX_GROUPS][16];
    uint8_t n = groups(net, list), k;
    for (k = 0; k < n && !ipv6_addr_equal(list[k], msg + 8); k++) {
    }
    if (k == n)
      return;
  }

  /* Answer after a random delay up to Maximum Response Delay; an earlier
   * pending answer stands */
  if (max_ms > 65535u)
    max_ms = 65535u;
  uint32_t delay = ((ipv6_random(net) & 0xFFFFu) * (max_ms + 1u)) >> 16;
  if (delay == 0)
    delay = 1;
  if (net->mld_query_ms == 0 || delay < net->mld_query_ms)
    net->mld_query_ms = (uint16_t)delay;
}

void mld_tick(net_t *net, uint32_t elapsed_ms) {
  if (net->mld_query_ms) {
    if (net->mld_query_ms > elapsed_ms) {
      net->mld_query_ms = (uint16_t)(net->mld_query_ms - elapsed_ms);
    } else {
      net->mld_query_ms = 0;
      report_all(net, MLD_MODE_IS_EXCLUDE);
    }
  }
  if (net->mld_unsol_ms) {
    if (net->mld_unsol_ms > elapsed_ms) {
      net->mld_unsol_ms = (uint16_t)(net->mld_unsol_ms - elapsed_ms);
    } else {
      net->mld_unsol_ms = 0;
      report_all(net, MLD_CHANGE_TO_EXCLUDE);
    }
  }
}
