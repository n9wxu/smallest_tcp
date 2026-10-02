/**
 * @file ndp.c
 * @brief Neighbor Discovery (RFC 4861): answering Neighbor Solicitations,
 *        router discovery, Duplicate Address Detection and SLAAC
 *        (RFC 4862).  REQ-NDP-001..076, REQ-SLAAC-004..039.
 */

#include "ndp.h"
#include "icmpv6.h"
#include "mld.h"
#include "net_endian.h"
#include <string.h>

static uint16_t option_len(const uint8_t *opt) {
  return (uint16_t)(opt[1] * 8u);
}

/* REQ-NDP-004..008: every option has a length, and fits (RFC 4861 §4.6) */
static int options_valid(const uint8_t *opt, uint16_t len) {
  while (len > 0) {
    if (len < 2 || option_len(opt) == 0 || option_len(opt) > len)
      return 0;
    len = (uint16_t)(len - option_len(opt));
    opt += option_len(opt);
  }
  return 1;
}

/* The first option of @p type in validated options, or NULL */
static const uint8_t *option_find(const uint8_t *opt, uint16_t len,
                                  uint8_t type) {
  while (len > 0) {
    if (opt[0] == type)
      return opt;
    len = (uint16_t)(len - option_len(opt));
    opt += option_len(opt);
  }
  return NULL;
}

/* A link-layer address option carrying our MAC */
static void write_lla_option(uint8_t *opt, uint8_t type, const net_t *net) {
  opt[0] = type;
  opt[1] = NDP_OPT_LLA_LEN / 8;
  memcpy(opt + 2, net->mac, 6);
}

/* REQ-NDP-013: an NA for our address @p target, from it, with our MAC */
static void send_na(net_t *net, const uint8_t *target, const uint8_t *dst,
                    const uint8_t *dst_mac, uint8_t flags) {
  uint8_t *msg = net->tx.buf + ICMPV6_OFFSET;
  if (net->tx.capacity < ICMPV6_OFFSET + NDP_NS_NA_LEN + NDP_OPT_LLA_LEN)
    return;
  memset(msg, 0, NDP_NS_NA_LEN);
  msg[ICMPV6_OFF_TYPE] = ICMPV6_NA;
  msg[NDP_OFF_FLAGS] = flags;
  memcpy(msg + NDP_OFF_TARGET, target, 16);
  write_lla_option(msg + NDP_NS_NA_LEN, NDP_OPT_TLLA, net);
  icmpv6_send(net, target, dst, dst_mac, NDP_NS_NA_LEN + NDP_OPT_LLA_LEN,
              NDP_HOP_LIMIT);
}

static void send_na_to_all_nodes(net_t *net, const uint8_t *target,
                                 uint8_t flags) {
  uint8_t mac[6];
  ipv6_mcast_mac(ipv6_all_nodes, mac);
  send_na(net, target, ipv6_all_nodes, mac, flags);
}

/* REQ-NDP-021..025, REQ-SLAAC-005, 006: to the target's solicited-node
 * group; a DAD probe comes from :: without our MAC */
net_err_t ndp_send_ns(net_t *net, const uint8_t *target, int dad) {
  uint8_t group[16], group_mac[6];
  uint8_t *msg = net->tx.buf + ICMPV6_OFFSET;
  uint16_t len = dad ? NDP_NS_NA_LEN : NDP_NS_NA_LEN + NDP_OPT_LLA_LEN;
  const uint8_t *src = dad ? ipv6_unspecified : ipv6_src_for(net, target);

  if (!src)
    return NET_ERR_INVALID_PARAM;
  if (net->tx.capacity < ICMPV6_OFFSET + NDP_NS_NA_LEN + NDP_OPT_LLA_LEN)
    return NET_ERR_BUF_TOO_SMALL;
  ipv6_solicited_node(target, group);
  ipv6_mcast_mac(group, group_mac);
  memset(msg, 0, NDP_NS_NA_LEN);
  msg[ICMPV6_OFF_TYPE] = ICMPV6_NS;
  memcpy(msg + NDP_OFF_TARGET, target, 16);
  if (!dad)
    write_lla_option(msg + NDP_NS_NA_LEN, NDP_OPT_SLLA, net);
  return icmpv6_send(net, src, group, group_mac, len, NDP_HOP_LIMIT);
}

/* REQ-NDP-034..037 */
static void send_rs(net_t *net) {
  uint8_t *msg = net->tx.buf + ICMPV6_OFFSET;
  uint8_t mac[6];
  if (net->tx.capacity < ICMPV6_OFFSET + NDP_RS_LEN + NDP_OPT_LLA_LEN)
    return;
  memset(msg, 0, NDP_RS_LEN);
  msg[ICMPV6_OFF_TYPE] = ICMPV6_RS;
  write_lla_option(msg + NDP_RS_LEN, NDP_OPT_SLLA, net);
  ipv6_mcast_mac(ipv6_all_routers, mac);
  icmpv6_send(net, net->ip6.addr[0].addr, ipv6_all_routers, mac,
              NDP_RS_LEN + NDP_OPT_LLA_LEN, NDP_HOP_LIMIT);
}

/* REQ-NDP-012, 014..019, REQ-SLAAC-009 */
static void ns_input(net_t *net, const ipv6_hdr_t *ip, const eth_frame_t *eth) {
  const uint8_t *msg = ip->payload;
  const uint8_t *target = msg + NDP_OFF_TARGET;
  const uint8_t *opts = msg + NDP_NS_NA_LEN;
  uint16_t opts_len = (uint16_t)(ip->payload_len - NDP_NS_NA_LEN);
  int from_dad_probe = ipv6_is_unspecified(ip->src);
  const uint8_t *slla;
  net_ip6_addr_t *a;
  int slot;

  if (ip->payload_len < NDP_NS_NA_LEN || ipv6_is_multicast(target) ||
      !options_valid(opts, opts_len))
    return;
  slla = option_find(opts, opts_len, NDP_OPT_SLLA);
  if (from_dad_probe) { /* RFC 4861 §7.1.1 */
    uint8_t group[16];
    ipv6_solicited_node(target, group);
    if (!ipv6_addr_equal(ip->dst, group) || slla)
      return;
  }
  if ((slot = ipv6_addr_slot(net, target)) < 0)
    return;
  a = &net->ip6.addr[slot];

  switch (a->state) {
  case NET_IP6_TENTATIVE:
    /* Someone else probing the same address; a unicast-sourced NS for a
     * tentative address is ignored (RFC 4862 §5.4.3) */
    if (from_dad_probe)
      a->state = NET_IP6_DUPLICATE;
    break;
  case NET_IP6_DUPLICATE:
    break;
  default:
    if (from_dad_probe) /* defend the address */
      send_na_to_all_nodes(net, a->addr, NDP_NA_FLAG_O);
    else
      send_na(net, a->addr, ip->src, slla ? slla + 2 : eth->src_mac,
              NDP_NA_FLAG_S | NDP_NA_FLAG_O);
    break;
  }
}

/* REQ-NDP-029..033, REQ-SLAAC-008; with no neighbour cache, an NA only
 * matters when it claims one of our tentative addresses */
static void na_input(net_t *net, const ipv6_hdr_t *ip) {
  const uint8_t *msg = ip->payload;
  int slot;

  if (ip->payload_len < NDP_NS_NA_LEN ||
      ipv6_is_multicast(msg + NDP_OFF_TARGET) ||
      !options_valid(msg + NDP_NS_NA_LEN,
                     (uint16_t)(ip->payload_len - NDP_NS_NA_LEN)))
    return;
  if (ipv6_is_multicast(ip->dst) && (msg[NDP_OFF_FLAGS] & NDP_NA_FLAG_S))
    return; /* §7.1.2 */
  slot = ipv6_addr_slot(net, msg + NDP_OFF_TARGET);
  if (slot >= 0 && net->ip6.addr[slot].state == NET_IP6_TENTATIVE)
    net->ip6.addr[slot].state = NET_IP6_DUPLICATE;
}

/* RFC 4862 §5.5.3(e): an advertised valid lifetime below two hours can
 * only shorten ours to two hours */
static uint32_t slaac_valid_lifetime(uint32_t advertised, uint32_t current) {
  if (advertised > SLAAC_TWO_HOURS_S || advertised > current)
    return advertised;
  return current > SLAAC_TWO_HOURS_S ? SLAAC_TWO_HOURS_S : current;
}

/* REQ-SLAAC-014..027: a /64 prefix + our interface identifier */
static void slaac_prefix(net_t *net, const uint8_t *opt) {
  uint8_t prefix_len = opt[2], flags = opt[3];
  uint32_t valid = net_read32be(opt + 4);
  uint32_t preferred = net_read32be(opt + 8);
  const uint8_t *prefix = opt + 16;
  uint8_t addr[16];
  int slot;

  if (!(flags & NDP_PREFIX_FLAG_A) || ipv6_is_link_local(prefix) ||
      preferred > valid || prefix_len != 64)
    return;
  memcpy(addr, prefix, 8);
  memcpy(addr + 8, net->ip6.addr[0].addr + 8, 8);

  slot = ipv6_addr_slot(net, addr);
  if (slot < 0) {
    if (valid > 0)
      ipv6_addr_add(net, addr, valid, preferred);
  } else if (net->ip6.addr[slot].state != NET_IP6_DUPLICATE) {
    ipv6_addr_set_lifetimes(
        net, (uint8_t)slot,
        slaac_valid_lifetime(valid, net->ip6.addr[slot].valid_s), preferred);
  }
}

/* REQ-NDP-039..048 */
static void ra_input(net_t *net, const ipv6_hdr_t *ip, const eth_frame_t *eth) {
  const uint8_t *msg = ip->payload;
  const uint8_t *opt = msg + NDP_RA_LEN;
  uint16_t opts_len = (uint16_t)(ip->payload_len - NDP_RA_LEN);
  net_ip6_router_t *router = &net->ip6.router;
  uint16_t lifetime;
  const uint8_t *slla;

  if (ip->payload_len < NDP_RA_LEN || !ipv6_is_link_local(ip->src) ||
      !options_valid(opt, opts_len))
    return;

  net->ip6.router_solicits_left = 0; /* a router answered */
  if (msg[NDP_RA_OFF_HOPLIMIT])
    net->ip6.hop_limit = msg[NDP_RA_OFF_HOPLIMIT];
  net->ip6.ra_flags = msg[NDP_RA_OFF_FLAGS] & (NDP_RA_MANAGED | NDP_RA_OTHER);

  lifetime = net_read16be(msg + NDP_RA_OFF_LIFETIME);
  slla = option_find(opt, opts_len, NDP_OPT_SLLA);
  if (lifetime) {
    memcpy(router->addr, ip->src, 16);
    memcpy(router->mac, slla ? slla + 2 : eth->src_mac, 6);
    router->lifetime_s = lifetime;
  } else if (ipv6_addr_equal(router->addr, ip->src)) {
    router->lifetime_s = 0;
  }

  for (; opts_len > 0; opts_len = (uint16_t)(opts_len - option_len(opt)),
                       opt += option_len(opt)) {
    if (opt[0] == NDP_OPT_PREFIX && option_len(opt) == NDP_OPT_PREFIX_LEN)
      slaac_prefix(net, opt);
  }
}

/* REQ-NDP-001, 002, 053: only from the link itself; RS (we are not a
 * router) and Redirect are ignored */
void ndp_input(net_t *net, const ipv6_hdr_t *ip, const eth_frame_t *eth) {
  const uint8_t *msg = ip->payload;
  if (ip->hop_limit != NDP_HOP_LIMIT || msg[ICMPV6_OFF_CODE] != 0)
    return;
  switch (msg[ICMPV6_OFF_TYPE]) {
  case ICMPV6_NS:
    ns_input(net, ip, eth);
    break;
  case ICMPV6_NA:
    na_input(net, ip);
    break;
  case ICMPV6_RA:
    ra_input(net, ip, eth);
    break;
  default:
    break;
  }
}

/* REQ-SLAAC-011..013: tentative; its solicited-node group is accepted
 * (ipv6_mac_accepted()) from now on */
void ndp_dad_start(net_t *net, uint8_t slot, uint16_t delay_ms) {
  net_ip6_addr_t *a = &net->ip6.addr[slot];
  a->state = NET_IP6_TENTATIVE;
  a->dad_probes_left = NET_IPV6_DAD_TRANSMITS;
  a->dad_timer_ms = delay_ms;
}

/* REQ-SLAAC-028: routers are solicited once the link-local address is
 * usable, after a random delay */
static void start_router_discovery(net_t *net) {
  if (NDP_MAX_RTR_SOLICITATIONS == 0)
    return;
  net->ip6.router_solicits_left = NDP_MAX_RTR_SOLICITATIONS;
  net->ip6.router_solicit_ms =
      (uint16_t)net_random_below(net, NDP_MAX_RTR_SOLICITATION_DELAY_MS + 1u);
}

/* REQ-SLAAC-005..007, 010, 013 */
static void dad_step(net_t *net, uint8_t slot) {
  net_ip6_addr_t *a = &net->ip6.addr[slot];
  if (a->dad_probes_left > 0) {
    /* Report the solicited-node group before the first probe (RFC 4862
     * §5.4.2), so a snooping switch delivers any answer */
    if (a->dad_probes_left == NET_IPV6_DAD_TRANSMITS)
      mld_report_change(net, NULL);
    ndp_send_ns(net, a->addr, 1);
    a->dad_probes_left--;
    a->dad_timer_ms = NDP_RETRANS_TIMER_MS;
    return;
  }
  /* No one answered: the address is ours */
  a->state = a->preferred_s ? NET_IP6_PREFERRED : NET_IP6_DEPRECATED;
  if (slot == 0) {
    /* REQ-IPv6-054: the groups again, from an address routers accept
     * (RFC 3810 §5.2.13) */
    mld_report_change(net, NULL);
    start_router_discovery(net);
  }
}

/* REQ-NDP-034..038; solicitations go before DAD so one scheduled by DAD
 * waits for the next tick */
void ndp_tick(net_t *net, uint32_t elapsed_ms) {
  net_ip6_t *ip6 = &net->ip6;
  uint8_t i;

  if (ip6->router_solicits_left &&
      net_countdown16(&ip6->router_solicit_ms, elapsed_ms)) {
    send_rs(net);
    ip6->router_solicits_left--;
    ip6->router_solicit_ms = NDP_RTR_SOLICITATION_INTERVAL_MS;
  }
  for (i = 0; i < NET_IPV6_ADDRS; i++) {
    if (ip6->addr[i].state == NET_IP6_TENTATIVE &&
        net_countdown16(&ip6->addr[i].dad_timer_ms, elapsed_ms))
      dad_step(net, i);
  }
}
