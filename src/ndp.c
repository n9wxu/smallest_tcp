/**
 * @file ndp.c
 * @brief Neighbor Discovery (RFC 4861): the Neighbor Solicitation /
 *        Advertisement responder, and Duplicate Address Detection
 *        (RFC 4862 §5.4).
 *
 * Implements REQ-NDP-001..019, 027..033 and REQ-SLAAC-004..013.
 */

#include "ndp.h"
#include "icmpv6.h"
#include "net_endian.h"
#include <string.h>

static const uint8_t all_nodes[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                      0,    0,    0, 0, 0, 0, 0, 1};
static const uint8_t all_nodes_mac[6] = {0x33, 0x33, 0, 0, 0, 1};
static const uint8_t all_routers[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                        0,    0,    0, 0, 0, 0, 0, 2};
static const uint8_t all_routers_mac[6] = {0x33, 0x33, 0, 0, 0, 2};
static const uint8_t unspecified[16] = {0};

/* ── Options (REQ-NDP-004..008) ───────────────────────────────────── */

/** Every option has a non-zero length and fits (RFC 4861 §4.6). */
static int options_valid(const uint8_t *opt, uint16_t len) {
  while (len > 0) {
    if (len < 2)
      return 0;
    uint16_t olen = (uint16_t)(opt[1] * 8u);
    if (olen == 0 || olen > len)
      return 0;
    opt += olen;
    len = (uint16_t)(len - olen);
  }
  return 1;
}

/** The first option of @p type (in validated options), or NULL. */
static const uint8_t *option_find(const uint8_t *opt, uint16_t len,
                                  uint8_t type) {
  while (len > 0) {
    uint16_t olen = (uint16_t)(opt[1] * 8u);
    if (opt[0] == type)
      return opt;
    opt += olen;
    len = (uint16_t)(len - olen);
  }
  return NULL;
}

/* ── Send ─────────────────────────────────────────────────────────── */

/** NA for our address @p target, with our MAC as Target Link-Layer
 *  Address.  The source is the target address itself. */
static void send_na(net_t *net, const uint8_t *target, const uint8_t *dst,
                    const uint8_t *dst_mac, uint8_t flags) {
  uint8_t *msg = net->tx.buf + ICMPV6_OFFSET;

  if (net->tx.capacity < ICMPV6_OFFSET + NDP_NS_NA_LEN + NDP_OPT_LLA_LEN)
    return;
  memset(msg, 0, NDP_NS_NA_LEN + NDP_OPT_LLA_LEN);
  msg[ICMPV6_OFF_TYPE] = ICMPV6_NA;
  msg[NDP_OFF_FLAGS] = flags;
  memcpy(msg + NDP_OFF_TARGET, target, 16);
  msg[NDP_NS_NA_LEN] = NDP_OPT_TLLA; /* REQ-NDP-013 */
  msg[NDP_NS_NA_LEN + 1] = 1;
  memcpy(msg + NDP_NS_NA_LEN + 2, net->mac, 6);
  icmpv6_send(net, target, dst, dst_mac, NDP_NS_NA_LEN + NDP_OPT_LLA_LEN,
              NDP_HOP_LIMIT);
}

net_err_t ndp_send_ns(net_t *net, const uint8_t *target, int dad) {
  uint8_t group[16], group_mac[6];
  uint8_t *msg = net->tx.buf + ICMPV6_OFFSET;
  uint16_t len = NDP_NS_NA_LEN;

  /* REQ-SLAAC-005, REQ-NDP-025: DAD probes come from :: */
  const uint8_t *src = dad ? unspecified : ipv6_src_for(net, target);
  if (!src)
    return NET_ERR_INVALID_PARAM;
  if (net->tx.capacity < ICMPV6_OFFSET + NDP_NS_NA_LEN + NDP_OPT_LLA_LEN)
    return NET_ERR_BUF_TOO_SMALL;

  /* REQ-NDP-022,023, REQ-SLAAC-006: to the target's solicited-node group */
  ipv6_solicited_node(target, group);
  ipv6_mcast_mac(group, group_mac);

  memset(msg, 0, NDP_NS_NA_LEN + NDP_OPT_LLA_LEN);
  msg[ICMPV6_OFF_TYPE] = ICMPV6_NS;
  memcpy(msg + NDP_OFF_TARGET, target, 16); /* REQ-NDP-021 */
  if (!dad) {
    msg[NDP_NS_NA_LEN] = NDP_OPT_SLLA; /* REQ-NDP-024 */
    msg[NDP_NS_NA_LEN + 1] = 1;
    memcpy(msg + NDP_NS_NA_LEN + 2, net->mac, 6);
    len = NDP_NS_NA_LEN + NDP_OPT_LLA_LEN;
  }
  return icmpv6_send(net, src, group, group_mac, len, NDP_HOP_LIMIT);
}

/** Router Solicitation (REQ-NDP-034..037): from the link-local address
 *  with our MAC in an SLLA option. */
static void send_rs(net_t *net) {
  uint8_t *msg = net->tx.buf + ICMPV6_OFFSET;
  if (net->tx.capacity < ICMPV6_OFFSET + NDP_RS_LEN + NDP_OPT_LLA_LEN)
    return;
  memset(msg, 0, NDP_RS_LEN + NDP_OPT_LLA_LEN);
  msg[ICMPV6_OFF_TYPE] = ICMPV6_RS;
  msg[NDP_RS_LEN] = NDP_OPT_SLLA;
  msg[NDP_RS_LEN + 1] = 1;
  memcpy(msg + NDP_RS_LEN + 2, net->mac, 6);
  icmpv6_send(net, net->ip6[0].addr, all_routers, all_routers_mac,
              NDP_RS_LEN + NDP_OPT_LLA_LEN, NDP_HOP_LIMIT);
}

/* ── Receive ──────────────────────────────────────────────────────── */

static void ns_input(net_t *net, const ipv6_hdr_t *ip, const eth_frame_t *eth) {
  const uint8_t *msg = ip->payload;
  uint16_t len = ip->payload_len;

  /* REQ-NDP-014,015 */
  if (len < NDP_NS_NA_LEN || ipv6_is_multicast(msg + NDP_OFF_TARGET))
    return;
  const uint8_t *opts = msg + NDP_NS_NA_LEN;
  uint16_t opts_len = (uint16_t)(len - NDP_NS_NA_LEN);
  if (!options_valid(opts, opts_len)) /* REQ-NDP-006 */
    return;
  const uint8_t *slla = option_find(opts, opts_len, NDP_OPT_SLLA);

  /* From ::, it is someone's DAD probe: it must go to the target's
   * solicited-node group and carry no link-layer address (§7.1.1) */
  int dad = ipv6_is_unspecified(ip->src);
  if (dad) {
    uint8_t group[16];
    ipv6_solicited_node(msg + NDP_OFF_TARGET, group);
    if (!ipv6_addr_equal(ip->dst, group) || slla)
      return;
  }

  int slot = ipv6_addr_slot(net, msg + NDP_OFF_TARGET);
  if (slot < 0)
    return;
  net_ip6_addr_t *a = &net->ip6[slot];

  if (a->state == NET_IP6_TENTATIVE) {
    /* REQ-SLAAC-009: another node probing the same address.  NS from a
     * unicast source for a tentative address is ignored (§5.4.3). */
    if (dad) {
      a->state = NET_IP6_DUPLICATE;
      NET_LOG("ndp: DAD conflict (NS) on slot %d", slot);
    }
    return;
  }
  if (a->state == NET_IP6_DUPLICATE)
    return;

  if (dad) {
    /* REQ-NDP-016,018: defend our address — unsolicited NA to all-nodes */
    send_na(net, a->addr, all_nodes, all_nodes_mac, NDP_NA_FLAG_O);
  } else {
    /* REQ-NDP-012,017,019: answer the solicitor at its link-layer
     * address (from the option, else the frame) */
    send_na(net, a->addr, ip->src, slla ? slla + 2 : eth->src_mac,
            NDP_NA_FLAG_S | NDP_NA_FLAG_O);
  }
}

static void na_input(net_t *net, const ipv6_hdr_t *ip) {
  const uint8_t *msg = ip->payload;
  uint16_t len = ip->payload_len;

  /* REQ-NDP-029,030 (hop limit checked by ndp_input) */
  if (len < NDP_NS_NA_LEN || ipv6_is_multicast(msg + NDP_OFF_TARGET))
    return;
  if (!options_valid(msg + NDP_NS_NA_LEN, (uint16_t)(len - NDP_NS_NA_LEN)))
    return;
  /* §7.1.2: a multicast NA cannot be Solicited */
  if (ipv6_is_multicast(ip->dst) && (msg[NDP_OFF_FLAGS] & NDP_NA_FLAG_S))
    return;

  int slot = ipv6_addr_slot(net, msg + NDP_OFF_TARGET);
  if (slot < 0)
    return; /* REQ-NDP-033: no neighbour cache to update */
  if (net->ip6[slot].state == NET_IP6_TENTATIVE) {
    /* REQ-SLAAC-008 */
    net->ip6[slot].state = NET_IP6_DUPLICATE;
    NET_LOG("ndp: DAD conflict (NA) on slot %d", slot);
  } else {
    /* RFC 4862 §5.4.4: after DAD, just note it */
    NET_LOG("ndp: another node advertises our address (slot %d)", slot);
  }
}

/**
 * Stateless address autoconfiguration from one Prefix Information option
 * (RFC 4862 §5.5.3, REQ-SLAAC-014..027).
 */
static void slaac_prefix(net_t *net, const uint8_t *opt) {
  uint8_t flags = opt[3];
  uint32_t valid = net_read32be(opt + 4);
  uint32_t preferred = net_read32be(opt + 8);
  const uint8_t *prefix = opt + 16;
  uint8_t addr[16];

  if (!(flags & NDP_PREFIX_FLAG_A) || ipv6_is_link_local(prefix) ||
      preferred > valid || opt[2] != 64)
    return; /* (a) not autonomous, (b) link-local, (c), /64 IID only */

  /* Prefix + the interface identifier of our link-local address */
  memcpy(addr, prefix, 8);
  memcpy(addr + 8, net->ip6[0].addr + 8, 8);

  int slot = ipv6_addr_slot(net, addr);
  if (slot < 0) {
    if (valid > 0) /* (d) */
      ipv6_addr_add(net, addr, valid, preferred);
    return;
  }
  net_ip6_addr_t *a = &net->ip6[slot];
  if (a->state == NET_IP6_DUPLICATE)
    return;
  /* (e): a short valid lifetime cannot cut ours below two hours */
  if (valid > SLAAC_TWO_HOURS_S || valid > a->valid_s)
    a->valid_s = valid;
  else if (a->valid_s > SLAAC_TWO_HOURS_S)
    a->valid_s = SLAAC_TWO_HOURS_S;
  a->preferred_s = preferred;
  if (a->state == NET_IP6_DEPRECATED && preferred > 0)
    a->state = NET_IP6_PREFERRED;
  else if (a->state == NET_IP6_PREFERRED && preferred == 0)
    a->state = NET_IP6_DEPRECATED;
}

/** Router Advertisement (RFC 4861 §6.3.4, REQ-NDP-039..048). */
static void ra_input(net_t *net, const ipv6_hdr_t *ip, const eth_frame_t *eth) {
  const uint8_t *msg = ip->payload;
  uint16_t len = ip->payload_len;

  /* REQ-NDP-040: only from a router's link-local address */
  if (len < NDP_RA_LEN || !ipv6_is_link_local(ip->src))
    return;
  const uint8_t *opt = msg + NDP_RA_LEN;
  uint16_t opts_len = (uint16_t)(len - NDP_RA_LEN);
  if (!options_valid(opt, opts_len))
    return;

  net->ip6_rs_left = 0; /* a router answered: stop soliciting */
  if (msg[NDP_RA_OFF_HOPLIMIT]) /* REQ-NDP-042 */
    net->ip6_hop_limit = msg[NDP_RA_OFF_HOPLIMIT];
  net->ip6_ra_flags = msg[NDP_RA_OFF_FLAGS] & 0xC0; /* REQ-NDP-047,048 */

  /* REQ-NDP-043,044: the default router and its MAC */
  uint16_t life = net_read16be(msg + NDP_RA_OFF_LIFETIME);
  const uint8_t *slla = option_find(opt, opts_len, NDP_OPT_SLLA);
  if (life) {
    memcpy(net->ip6_router, ip->src, 16);
    memcpy(net->ip6_router_mac, slla ? slla + 2 : eth->src_mac, 6);
    net->ip6_router_life_s = life;
  } else if (ipv6_addr_equal(net->ip6_router, ip->src)) {
    net->ip6_router_life_s = 0;
  }

  /* REQ-NDP-045: every Prefix Information option */
  while (opts_len > 0) {
    uint16_t olen = (uint16_t)(opt[1] * 8u);
    if (opt[0] == NDP_OPT_PREFIX && olen == NDP_OPT_PREFIX_LEN)
      slaac_prefix(net, opt);
    opt += olen;
    opts_len = (uint16_t)(opts_len - olen);
  }
}

void ndp_input(net_t *net, const ipv6_hdr_t *ip, const eth_frame_t *eth) {
  const uint8_t *msg = ip->payload;

  /* REQ-NDP-001,002: only messages from the link itself */
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
    /* RS: we are not a router.  Redirect: ignored (REQ-NDP-053). */
    break;
  }
}

/* ── Duplicate Address Detection ──────────────────────────────────── */

void ndp_dad_start(net_t *net, uint8_t slot, uint16_t delay_ms) {
  net_ip6_addr_t *a = &net->ip6[slot];
  /* REQ-SLAAC-011..013: tentative, and its solicited-node group (accepted
   * by ipv6_mac_accepted()) is joined from now on */
  a->state = NET_IP6_TENTATIVE;
  a->dad_left = NET_IPV6_DAD_TRANSMITS;
  a->timer_ms = delay_ms;
}

void ndp_tick(net_t *net, uint32_t elapsed_ms) {
  uint8_t i;

  /* REQ-NDP-034..038: Router Solicitations, 4 s apart (before DAD, so a
   * solicitation scheduled below waits for the next tick) */
  if (net->ip6_rs_left) {
    if (net->ip6_rs_timer_ms > elapsed_ms) {
      net->ip6_rs_timer_ms = (uint16_t)(net->ip6_rs_timer_ms - elapsed_ms);
    } else {
      send_rs(net);
      net->ip6_rs_left--;
      net->ip6_rs_timer_ms = NDP_RTR_SOLICITATION_INTERVAL_MS;
    }
  }

  for (i = 0; i < NET_IPV6_ADDRS; i++) {
    net_ip6_addr_t *a = &net->ip6[i];
    if (a->state != NET_IP6_TENTATIVE)
      continue;
    if (a->timer_ms > elapsed_ms) {
      a->timer_ms = (uint16_t)(a->timer_ms - elapsed_ms);
      continue;
    }
    if (a->dad_left > 0) {
      /* REQ-SLAAC-005..007 */
      ndp_send_ns(net, a->addr, 1);
      a->dad_left--;
      a->timer_ms = NDP_RETRANS_TIMER_MS;
    } else {
      /* REQ-SLAAC-010: no one answered — the address is ours (deprecated
       * if its preferred lifetime ran out meanwhile) */
      a->state = a->preferred_s ? NET_IP6_PREFERRED : NET_IP6_DEPRECATED;
      NET_LOG("ndp: address slot %u usable", i);
      if (i == 0 && NDP_MAX_RTR_SOLICITATIONS > 0) {
        /* REQ-SLAAC-028: now look for routers, after a random delay */
        net->ip6_rs_left = NDP_MAX_RTR_SOLICITATIONS;
        net->ip6_rs_timer_ms =
            (uint16_t)(((ipv6_random(net) & 0xFFFFu) *
                        (NDP_MAX_RTR_SOLICITATION_DELAY_MS + 1u)) >>
                       16);
      }
    }
  }
}
