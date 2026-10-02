/**
 * @file igmp.c
 * @brief IGMPv2 host (RFC 2236): reports on joining, Leave Group, queries
 *        answered after a random delay, another host's report suppressing
 *        ours, IGMPv1 routers.  REQ-IGMP-001..014, REQ-MDNS-002.
 *        Linked into the IP layer by igmp_join() (net->igmp_ops).
 */

#include "igmp.h"
#include "eth.h"
#include "ipv4.h"
#include "net_cksum.h"
#include "net_endian.h"

#define IGMP_MSG_SIZE 8
#define IGMP_V1_ROUTER_TIMEOUT_MS 400000u /* RFC 2236 §8.11 */
#define IGMP_V1_MAX_RESP 100u             /* 10 s, in tenths (§4) */

static net_err_t igmp_send(net_t *net, uint8_t type, uint32_t dst_ip,
                           uint32_t group) {
  uint8_t dst_mac[6];
  uint8_t *ip = net->tx.buf + ETH_HDR_SIZE;
  uint8_t *msg = ip + IPV4_ROUTER_ALERT_HDR_SIZE;

  if (net->tx.capacity < IGMP_FRAME_SIZE)
    return NET_ERR_BUF_TOO_SMALL;
  ipv4_mcast_mac(dst_ip, dst_mac);
  eth_build(net->tx.buf, net->tx.capacity, dst_mac, net->mac,
            NET_ETHERTYPE_IPV4);
  ipv4_build_router_alert(ip, IGMP_MSG_SIZE, IPV4_PROTO_IGMP, net->ipv4_addr,
                          dst_ip);
  msg[0] = type;
  msg[1] = 0; /* Max Resp Time: queries only */
  net_write16be(msg + 2, 0);
  net_write32be(msg + 4, group);
  net_write16be(msg + 2, net_cksum(msg, IGMP_MSG_SIZE));
  return net_transmit(net, IGMP_FRAME_SIZE);
}

/* REQ-IGMP-013: an IGMPv1 querier was heard in the last 400 s */
static int v1_querier(const net_t *net) { return net->igmp_v1_ms != 0; }

/* REQ-IGMP-008, 014: never for all-hosts; version 1 while a v1 querier is
 * present */
net_err_t igmp_report(net_t *net, uint32_t group) {
  if (!ipv4_is_multicast(group))
    return NET_ERR_INVALID_PARAM;
  if (group == IPV4_ALL_HOSTS)
    return NET_OK;
  return igmp_send(net,
                   v1_querier(net) ? IGMP_TYPE_V1_REPORT : IGMP_TYPE_V2_REPORT,
                   group, group);
}

/* The slot of a joined group, or -1 */
static int group_slot(const net_t *net, uint32_t group) {
  uint8_t i;
  for (i = 0; group != 0 && i < NET_MAX_MCAST_GROUPS; i++) {
    if (net->mcast_groups[i] == group)
      return i;
  }
  return -1;
}

/* REQ-IGMP-009, 010: a report due within (0, @p max_ms] — unless one is
 * due sooner already */
static void schedule(net_t *net, uint8_t slot, uint32_t max_ms) {
  uint16_t *delay = &net->igmp_delay_ms[slot];
  if (*delay == 0 || max_ms < *delay)
    *delay = (uint16_t)(1u + net_random_below(net, max_ms));
}

/* REQ-IGMP-002, 004, 005, 009..013: queries start timers, another host's
 * report stops ours; the rest is ignored.  Bytes past the first 8 count
 * only in the checksum. */
static void igmp_input(net_t *net, const ipv4_hdr_t *ip) {
  const uint8_t *msg = ip->payload;
  uint32_t group, max_ms;
  int slot;
  uint8_t i;

  if (ip->payload_len < IGMP_MSG_SIZE ||
      !net_cksum_verify(msg, ip->payload_len))
    return;
  group = net_read32be(msg + 4);
  switch (msg[0]) {
  case IGMP_TYPE_QUERY:
    max_ms = msg[1] ? msg[1] * 100u : IGMP_V1_MAX_RESP * 100u;
    if (msg[1] == 0)
      net->igmp_v1_ms = IGMP_V1_ROUTER_TIMEOUT_MS;
    if (group == 0) { /* General */
      for (i = 0; i < NET_MAX_MCAST_GROUPS; i++)
        if (net->mcast_groups[i])
          schedule(net, i, max_ms);
    } else if ((slot = group_slot(net, group)) >= 0) { /* Group-Specific */
      schedule(net, (uint8_t)slot, max_ms);
    }
    break;
  case IGMP_TYPE_V1_REPORT:
  case IGMP_TYPE_V2_REPORT:
    if ((slot = group_slot(net, group)) >= 0)
      net->igmp_delay_ms[slot] = 0; /* REQ-IGMP-011 */
    break;
  default:
    break;
  }
}

/* Reports due go out; the v1 querier state times out */
static void igmp_tick(net_t *net, uint32_t elapsed_ms) {
  uint8_t i;
  net->igmp_v1_ms =
      net->igmp_v1_ms > elapsed_ms ? net->igmp_v1_ms - elapsed_ms : 0;
  for (i = 0; i < NET_MAX_MCAST_GROUPS; i++) {
    uint16_t *delay = &net->igmp_delay_ms[i];
    if (*delay == 0)
      continue;
    if (net->mcast_groups[i] == 0) { /* left meanwhile */
      *delay = 0;
    } else if (elapsed_ms >= *delay) {
      *delay = 0;
      igmp_report(net, net->mcast_groups[i]);
    } else {
      *delay = (uint16_t)(*delay - elapsed_ms);
    }
  }
}

static const struct net_igmp_ops_s igmp_ops = {igmp_input, igmp_tick};

net_err_t igmp_join(net_t *net, uint32_t group) {
  net_err_t err = ipv4_mcast_join(net, group);
  if (err != NET_OK)
    return err;
  net->igmp_ops = &igmp_ops;
  return igmp_report(net, group);
}

/* REQ-IGMP-007, 014: Leave Group to all-routers — none while a v1 querier
 * is present */
net_err_t igmp_leave(net_t *net, uint32_t group) {
  int slot;
  if (!ipv4_is_multicast(group))
    return NET_ERR_INVALID_PARAM;
  if ((slot = group_slot(net, group)) >= 0)
    net->igmp_delay_ms[slot] = 0;
  ipv4_mcast_leave(net, group);
  if (v1_querier(net) || group == IPV4_ALL_HOSTS)
    return NET_OK;
  return igmp_send(net, IGMP_TYPE_LEAVE, IGMP_ALL_ROUTERS, group);
}
