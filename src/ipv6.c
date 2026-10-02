/**
 * @file ipv6.c
 * @brief IPv6 (RFC 8200, RFC 4291, RFC 6724): packets, and the addresses
 *        of the interface.  REQ-IPv6-001..048, 055.
 */

#include "ipv6.h"
#include "icmpv6.h"
#include "mld.h"
#include "ndp.h"
#include "net_endian.h"
#include <string.h>

#if NET_USE_UDP
#include "udp.h"
#endif

#if NET_USE_TCP
#include "tcp.h"
#endif

const uint8_t ipv6_unspecified[16] = {0};
const uint8_t ipv6_all_nodes[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                    0,    0,    0, 0, 0, 0, 0, 1};
const uint8_t ipv6_all_routers[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                      0,    0,    0, 0, 0, 0, 0, 2};

/* Hop-by-Hop, Routing and Destination Options are skipped; Hop-by-Hop
 * only straight after the IPv6 header (RFC 8200 §4.1). */
static int is_skippable_extension(uint8_t nh, int first) {
  return (nh == IPV6_NH_HOPOPT && first) || nh == IPV6_NH_ROUTING ||
         nh == IPV6_NH_DSTOPTS;
}

/* REQ-IPv6-001..003, 018..022, 048 */
net_err_t ipv6_parse(uint8_t *data, uint16_t data_len, ipv6_hdr_t *out) {
  uint32_t end, off = IPV6_HDR_SIZE;
  uint16_t nh_off = IPV6_OFF_NH;
  uint8_t nh;

  if (data_len < IPV6_HDR_SIZE || (data[IPV6_OFF_VTF] >> 4) != 6)
    return NET_ERR_INVALID_PARAM;
  end = (uint32_t)IPV6_HDR_SIZE + net_read16be(data + IPV6_OFF_PLEN);
  if (end > data_len) /* bytes past `end` are link padding */
    return NET_ERR_INVALID_PARAM;

  nh = data[IPV6_OFF_NH];
  while (is_skippable_extension(nh, nh_off == IPV6_OFF_NH)) {
    uint32_t ext_len;
    if (off + 2 > end)
      return NET_ERR_INVALID_PARAM;
    ext_len = ((uint32_t)data[off + 1] + 1u) * 8u;
    if (off + ext_len > end)
      return NET_ERR_INVALID_PARAM;
    /* A Routing header with segments left would have us forward: hosts
     * don't.  The walk ends at it, and ipv6_input() answers (RFC 8200
     * §4.4) */
    if (nh == IPV6_NH_ROUTING && data[off + IPV6_ROUTING_OFF_SEGMENTS] != 0)
      break;
    nh_off = (uint16_t)off;
    nh = data[off];
    off += ext_len;
  }
  if (nh == IPV6_NH_FRAGMENT || nh == IPV6_NH_NONE)
    return NET_ERR_INVALID_PARAM;

  out->src = data + IPV6_OFF_SRC;
  out->dst = data + IPV6_OFF_DST;
  out->next_header = nh;
  out->hop_limit = data[IPV6_OFF_HLIM];
  out->header = data;
  out->header_len = (uint16_t)off;
  out->payload = data + off;
  out->payload_len = (uint16_t)(end - off);
  out->nh_offset = nh_off;
  return NET_OK;
}

/* REQ-IPv6-024..031 */
void ipv6_build(uint8_t *buf, uint16_t payload_len, uint8_t next_header,
                const uint8_t *src, const uint8_t *dst, uint8_t hop_limit) {
  buf[0] = 0x60; /* version 6, traffic class 0, flow label 0 */
  buf[1] = 0;
  buf[2] = 0;
  buf[3] = 0;
  net_write16be(buf + IPV6_OFF_PLEN, payload_len);
  buf[IPV6_OFF_NH] = next_header;
  buf[IPV6_OFF_HLIM] = hop_limit;
  memcpy(buf + IPV6_OFF_SRC, src, 16);
  memcpy(buf + IPV6_OFF_DST, dst, 16);
}

/* REQ-IPv6-044 */
uint16_t ipv6_cksum(const uint8_t *src, const uint8_t *dst, uint8_t next_header,
                    const uint8_t *data, uint16_t len) {
  net_cksum_t c;
  net_cksum_init(&c);
  net_cksum_add(&c, src, 16);
  net_cksum_add(&c, dst, 16);
  net_cksum_add_u32(&c, len);
  net_cksum_add_u32(&c, next_header);
  net_cksum_add(&c, data, len);
  return net_cksum_finalize(&c);
}

static int is_usable(const net_ip6_addr_t *a) {
  return a->state == NET_IP6_PREFERRED || a->state == NET_IP6_DEPRECATED;
}

/* REQ-IPv6-035, 036, REQ-SLAAC-001..003 */
void ipv6_start(net_t *net) {
  net_ip6_t *ip6 = &net->ip6;
  memset(ip6, 0, sizeof(*ip6));
  ip6->hop_limit = NET_IPV6_DEFAULT_HOP_LIMIT;
  ip6->error_tokens = ICMPV6_ERROR_BURST;
  ipv6_link_local_from_mac(net->mac, ip6->addr[0].addr);
  ip6->addr[0].valid_s = NET_IP6_INFINITE;
  ip6->addr[0].preferred_s = NET_IP6_INFINITE;
  /* RFC 4862 §5.4.2: the first message waits a random delay */
  ndp_dad_start(
      net, 0,
      (uint16_t)net_random_below(net, NDP_MAX_RTR_SOLICITATION_DELAY_MS + 1u));
}

/* RFC 4862 §5.5.4, REQ-SLAAC-022, 023, REQ-NDP-043 */
static void lifetimes_elapse(net_t *net, uint32_t secs) {
  net_ip6_t *ip6 = &net->ip6;
  uint8_t i;
  for (i = 1; i < NET_IPV6_ADDRS; i++) {
    net_ip6_addr_t *a = &ip6->addr[i];
    uint32_t valid = a->valid_s, preferred = a->preferred_s;
    if (a->state == NET_IP6_NONE)
      continue;
    if (valid != NET_IP6_INFINITE)
      valid = valid > secs ? valid - secs : 0;
    if (preferred != NET_IP6_INFINITE)
      preferred = preferred > secs ? preferred - secs : 0;
    if (valid == 0)
      memset(a, 0, sizeof(*a));
    else
      ipv6_addr_set_lifetimes(net, i, valid, preferred);
  }
  ip6->router.lifetime_s = ip6->router.lifetime_s > secs
                               ? (uint16_t)(ip6->router.lifetime_s - secs)
                               : 0;
  mld_seconds_elapse(net, secs);
}

void ipv6_tick(net_t *net, uint32_t elapsed_ms) {
  uint32_t secs = net_whole_seconds(&net->ip6.lifetime_carry_ms, elapsed_ms);
  if (secs)
    lifetimes_elapse(net, secs);
  icmpv6_tick(net, elapsed_ms);
  /* MLD first: a report that ND sends now is then repeated a full
   * interval later, not in this same tick */
  mld_tick(net, elapsed_ms);
  ndp_tick(net, elapsed_ms);
}

net_err_t ipv6_addr_add(net_t *net, const uint8_t *addr, uint32_t valid_s,
                        uint32_t preferred_s) {
  uint8_t i;
  if (ipv6_is_multicast(addr) || ipv6_is_unspecified(addr))
    return NET_ERR_INVALID_PARAM;
  if (ipv6_addr_slot(net, addr) >= 0)
    return NET_OK;
  for (i = 1; i < NET_IPV6_ADDRS; i++) {
    net_ip6_addr_t *a = &net->ip6.addr[i];
    if (a->state != NET_IP6_NONE)
      continue;
    memcpy(a->addr, addr, 16);
    a->valid_s = valid_s;
    a->preferred_s = preferred_s;
    ndp_dad_start(net, i, 0); /* REQ-SLAAC-018 */
    return NET_OK;
  }
  return NET_ERR_BUF_TOO_SMALL;
}

void ipv6_addr_set_lifetimes(net_t *net, uint8_t slot, uint32_t valid_s,
                             uint32_t preferred_s) {
  net_ip6_addr_t *a = &net->ip6.addr[slot];
  a->valid_s = valid_s;
  a->preferred_s = preferred_s;
  if (is_usable(a))
    a->state = preferred_s ? NET_IP6_PREFERRED : NET_IP6_DEPRECATED;
}

void ipv6_addr_remove(net_t *net, const uint8_t *addr) {
  int slot = ipv6_addr_slot(net, addr);
  if (slot > 0) /* never the link-local address */
    memset(&net->ip6.addr[slot], 0, sizeof(net->ip6.addr[slot]));
}

uint8_t ipv6_addr_state(const net_t *net, uint8_t slot) {
  return slot < NET_IPV6_ADDRS ? net->ip6.addr[slot].state : NET_IP6_NONE;
}

int ipv6_addr_slot(const net_t *net, const uint8_t *addr) {
  uint8_t i;
  for (i = 0; i < NET_IPV6_ADDRS; i++) {
    if (net->ip6.addr[i].state != NET_IP6_NONE &&
        ipv6_addr_equal(net->ip6.addr[i].addr, addr))
      return i;
  }
  return -1;
}

int ipv6_is_ours(const net_t *net, const uint8_t *addr) {
  int slot = ipv6_addr_slot(net, addr);
  return slot >= 0 && is_usable(&net->ip6.addr[slot]);
}

static int is_link_scope(const uint8_t *dst) {
  return ipv6_is_link_local(dst) ||
         (ipv6_is_multicast(dst) && (dst[1] & 0x0F) <= 2);
}

/* RFC 6724 rules 2 and 3, for a single interface; REQ-IPv6-013: nothing
 * is sent to the unspecified address */
const uint8_t *ipv6_src_for(const net_t *net, const uint8_t *dst) {
  const net_ip6_addr_t *link_local = &net->ip6.addr[0];
  uint8_t i;
  if (ipv6_is_unspecified(dst))
    return NULL;
  if (is_link_scope(dst))
    return is_usable(link_local) ? link_local->addr : NULL;
  for (i = 1; i < NET_IPV6_ADDRS; i++) {
    if (net->ip6.addr[i].state == NET_IP6_PREFERRED)
      return net->ip6.addr[i].addr;
  }
  for (i = 1; i < NET_IPV6_ADDRS; i++) {
    if (net->ip6.addr[i].state == NET_IP6_DEPRECATED)
      return net->ip6.addr[i].addr;
  }
  /* a wider-scope group can still be reached from the link */
  if (ipv6_is_multicast(dst) && is_usable(link_local))
    return link_local->addr;
  return NULL;
}

const uint8_t *ipv6_router_mac(const net_t *net) {
  return net->ip6.router.lifetime_s ? net->ip6.router.mac : NULL;
}

int ipv6_on_link(const net_t *net, const uint8_t *dst) {
  uint8_t i;
  if (ipv6_is_link_local(dst))
    return 1;
  for (i = 1; i < NET_IPV6_ADDRS; i++) {
    if (net->ip6.addr[i].state != NET_IP6_NONE &&
        memcmp(net->ip6.addr[i].addr, dst, 8) == 0)
      return 1;
  }
  return 0;
}

net_err_t ipv6_mcast_join(net_t *net, const uint8_t *group) {
  if (!ipv6_is_multicast(group))
    return NET_ERR_INVALID_PARAM;
  if (ipv6_mcast_is_member(net, group))
    return NET_OK;
#if NET_MAX_MCAST6_GROUPS > 0
  uint8_t i;
  for (i = 0; i < NET_MAX_MCAST6_GROUPS; i++) {
    if (ipv6_is_unspecified(net->mcast6_groups[i])) {
      memcpy(net->mcast6_groups[i], group, 16);
      mld_report_change(net, NULL);
      return NET_OK;
    }
  }
#endif
  return NET_ERR_BUF_TOO_SMALL;
}

void ipv6_mcast_leave(net_t *net, const uint8_t *group) {
#if NET_MAX_MCAST6_GROUPS > 0
  uint8_t i;
  for (i = 0; i < NET_MAX_MCAST6_GROUPS; i++) {
    if (ipv6_addr_equal(net->mcast6_groups[i], group)) {
      memset(net->mcast6_groups[i], 0, 16);
      mld_report_change(net, group);
    }
  }
#else
  (void)net;
  (void)group;
#endif
}

int ipv6_mcast_is_member(const net_t *net, const uint8_t *group) {
#if NET_MAX_MCAST6_GROUPS > 0
  uint8_t i;
  if (ipv6_is_unspecified(group))
    return 0;
  for (i = 0; i < NET_MAX_MCAST6_GROUPS; i++) {
    if (ipv6_addr_equal(net->mcast6_groups[i], group))
      return 1;
  }
#else
  (void)net;
  (void)group;
#endif
  return 0;
}

static int started(const net_t *net) {
  return net->ip6.addr[0].state != NET_IP6_NONE;
}

int ipv6_mac_accepted(const net_t *net, const uint8_t *mac) {
  uint8_t i, group_mac[6], solicited[16];
  if (mac[0] != 0x33 || mac[1] != 0x33 || !started(net))
    return 0;
  ipv6_mcast_mac(ipv6_all_nodes, group_mac);
  if (net_mac_equal(mac, group_mac))
    return 1;
  for (i = 0; i < NET_IPV6_ADDRS; i++) {
    if (net->ip6.addr[i].state == NET_IP6_NONE)
      continue;
    ipv6_solicited_node(net->ip6.addr[i].addr, solicited);
    ipv6_mcast_mac(solicited, group_mac);
    if (net_mac_equal(mac, group_mac))
      return 1;
  }
#if NET_MAX_MCAST6_GROUPS > 0
  for (i = 0; i < NET_MAX_MCAST6_GROUPS; i++) {
    if (ipv6_is_unspecified(net->mcast6_groups[i]))
      continue;
    ipv6_mcast_mac(net->mcast6_groups[i], group_mac);
    if (net_mac_equal(mac, group_mac))
      return 1;
  }
#endif
  return 0;
}

/* REQ-IPv6-006..010: a usable address of ours, all-nodes, a joined group,
 * or the solicited-node group of a configured address (DAD runs over it
 * while the address is tentative) */
static int destination_is_us(const net_t *net, const uint8_t *dst) {
  uint8_t i, solicited[16];
  if (!ipv6_is_multicast(dst))
    return ipv6_is_ours(net, dst);
  if (ipv6_addr_equal(dst, ipv6_all_nodes) || ipv6_mcast_is_member(net, dst))
    return 1;
  for (i = 0; i < NET_IPV6_ADDRS; i++) {
    if (net->ip6.addr[i].state == NET_IP6_NONE)
      continue;
    ipv6_solicited_node(net->ip6.addr[i].addr, solicited);
    if (ipv6_addr_equal(dst, solicited))
      return 1;
  }
  return 0;
}

/* REQ-IPv6-011..017, 048 */
void ipv6_input(net_t *net, const eth_frame_t *eth) {
  ipv6_hdr_t ip;

  if (!started(net) ||
      ipv6_parse(eth->payload, eth->payload_len, &ip) != NET_OK ||
      ipv6_is_multicast(ip.src) || ipv6_is_ours(net, ip.src) ||
      !destination_is_us(net, ip.dst))
    return;

  switch (ip.next_header) {
  case IPV6_NH_ICMPV6:
    icmpv6_input(net, &ip, eth);
    break;
#if NET_USE_UDP
  case IPV6_NH_UDP:
    udp6_input(net, &ip, eth);
    break;
#endif
#if NET_USE_TCP
  case IPV6_NH_TCP:
    tcp6_input(net, &ip, eth);
    break;
#endif
  case IPV6_NH_ROUTING: /* with segments left: its Routing Type is at fault */
    icmpv6_send_error(net, ICMPV6_PARAM_PROBLEM, ICMPV6_CODE_ERRONEOUS_HEADER,
                      (uint32_t)ip.header_len + IPV6_ROUTING_OFF_TYPE, &ip,
                      eth);
    break;
  default:
    icmpv6_send_error(net, ICMPV6_PARAM_PROBLEM, ICMPV6_CODE_UNRECOGNIZED_NH,
                      ip.nh_offset, &ip, eth);
    break;
  }
}
