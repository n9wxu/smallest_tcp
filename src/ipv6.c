/**
 * @file ipv6.c
 * @brief IPv6 — Internet Protocol version 6 (RFC 8200, RFC 4291, RFC 6724).
 *
 * Implements REQ-IPv6-001 through REQ-IPv6-047 (see docs/design/ipv6.md).
 * No fragmentation or reassembly.
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

static const uint8_t all_nodes[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                      0,    0,    0, 0, 0, 0, 0, 1};

/* ── Parse ────────────────────────────────────────────────────────── */

net_err_t ipv6_parse(uint8_t *data, uint16_t data_len, ipv6_hdr_t *out) {
  if (data_len < IPV6_HDR_SIZE)
    return NET_ERR_INVALID_PARAM;
  /* REQ-IPv6-001 */
  if ((data[IPV6_OFF_VTF] >> 4) != 6)
    return NET_ERR_INVALID_PARAM;
  /* REQ-IPv6-002,003: the Payload Length bounds the packet; anything
   * after it in the frame is link padding */
  uint32_t end = (uint32_t)IPV6_HDR_SIZE + net_read16be(data + IPV6_OFF_PLEN);
  if (end > data_len)
    return NET_ERR_INVALID_PARAM;

  /* REQ-IPv6-018..020: walk the extension headers */
  uint32_t off = IPV6_HDR_SIZE;
  uint16_t nh_off = IPV6_OFF_NH;
  uint8_t nh = data[IPV6_OFF_NH];
  for (;;) {
    /* Hop-by-Hop is only valid straight after the IPv6 header
     * (RFC 8200 §4.1); anywhere else it is an unrecognized header. */
    if (nh == IPV6_NH_HOPOPT && nh_off != IPV6_OFF_NH)
      break;
    if (nh != IPV6_NH_HOPOPT && nh != IPV6_NH_ROUTING &&
        nh != IPV6_NH_DSTOPTS)
      break;
    if (off + 2 > end)
      return NET_ERR_INVALID_PARAM;
    uint32_t ext_len = ((uint32_t)data[off + 1] + 1u) * 8u;
    if (off + ext_len > end)
      return NET_ERR_INVALID_PARAM;
    /* A Routing header still naming hops would have us forward: hosts
     * don't (RFC 8200 §4.4). */
    if (nh == IPV6_NH_ROUTING && data[off + 3] != 0)
      return NET_ERR_INVALID_PARAM;
    nh_off = (uint16_t)off;
    nh = data[off];
    off += ext_len;
  }
  /* REQ-IPv6-022: no reassembly; No Next Header carries nothing */
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

/* ── Build ────────────────────────────────────────────────────────── */

void ipv6_build(uint8_t *buf, uint16_t payload_len, uint8_t next_header,
                const uint8_t *src, const uint8_t *dst, uint8_t hop_limit) {
  /* REQ-IPv6-024..026: version 6, traffic class 0, flow label 0 */
  buf[0] = 0x60;
  buf[1] = 0;
  buf[2] = 0;
  buf[3] = 0;
  net_write16be(buf + IPV6_OFF_PLEN, payload_len); /* REQ-IPv6-027 */
  buf[IPV6_OFF_NH] = next_header;                   /* REQ-IPv6-028 */
  buf[IPV6_OFF_HLIM] = hop_limit;                   /* REQ-IPv6-029 */
  memcpy(buf + IPV6_OFF_SRC, src, 16);              /* REQ-IPv6-030 */
  memcpy(buf + IPV6_OFF_DST, dst, 16);              /* REQ-IPv6-031 */
}

/* ── Checksum (REQ-IPv6-044) ──────────────────────────────────────── */

void ipv6_pseudo_sum(net_cksum_t *c, const uint8_t *src, const uint8_t *dst,
                     uint16_t upper_len, uint8_t next_header) {
  net_cksum_add(c, src, 16);
  net_cksum_add(c, dst, 16);
  net_cksum_add_u32(c, upper_len);
  net_cksum_add_u32(c, next_header); /* three zero bytes + Next Header */
}

uint16_t ipv6_cksum(const uint8_t *src, const uint8_t *dst,
                    uint8_t next_header, const uint8_t *data, uint16_t len) {
  net_cksum_t c;
  net_cksum_init(&c);
  ipv6_pseudo_sum(&c, src, dst, len, next_header);
  net_cksum_add(&c, data, len);
  return net_cksum_finalize(&c);
}

/* ── The interface's addresses ────────────────────────────────────── */

uint32_t ipv6_random(net_t *net) {
  uint32_t x = net->ip6_rng;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  net->ip6_rng = x;
  return x;
}

void ipv6_start(net_t *net) {
  memset(net->ip6, 0, sizeof(net->ip6));
  net->ip6_hop_limit = NET_IPV6_DEFAULT_HOP_LIMIT;
  net->ip6_router_life_s = 0;
  net->ip6_ra_flags = 0;
  net->ip6_rs_left = 0;
  net->ip6_sec_ms = 0;
  net->mld_query_ms = 0;
  net->mld_unsol_ms = 0;
  net->mld_v1_s = 0;
  if (net->ip6_rng == 0) {
    net->ip6_rng = ((uint32_t)net->mac[2] << 24 | (uint32_t)net->mac[3] << 16 |
                    (uint32_t)net->mac[4] << 8 | net->mac[5]) |
                   1u;
  }
  /* REQ-IPv6-035,036, REQ-SLAAC-001..003 */
  ipv6_link_local_from_mac(net->mac, net->ip6[0].addr);
  net->ip6[0].valid_s = NET_IP6_INFINITE;
  net->ip6[0].preferred_s = NET_IP6_INFINITE;
  /* RFC 4862 §5.4.2: first message after start-up waits a random
   * 0..MAX_RTR_SOLICITATION_DELAY (scaled, no division) */
  uint32_t delay =
      ((ipv6_random(net) & 0xFFFFu) * (NDP_MAX_RTR_SOLICITATION_DELAY_MS + 1u)) >>
      16;
  ndp_dad_start(net, 0, (uint16_t)delay);
}

/** Count @p secs whole seconds off the address and router lifetimes
 *  (RFC 4862 §5.5.4). */
static void lifetimes_elapse(net_t *net, uint32_t secs) {
  uint8_t i;
  for (i = 1; i < NET_IPV6_ADDRS; i++) {
    net_ip6_addr_t *a = &net->ip6[i];
    if (a->state == NET_IP6_NONE)
      continue;
    if (a->preferred_s != NET_IP6_INFINITE) {
      a->preferred_s = a->preferred_s > secs ? a->preferred_s - secs : 0;
      /* REQ-SLAAC-023: still usable, but not for new connections */
      if (a->preferred_s == 0 && a->state == NET_IP6_PREFERRED)
        a->state = NET_IP6_DEPRECATED;
    }
    if (a->valid_s != NET_IP6_INFINITE) {
      a->valid_s = a->valid_s > secs ? a->valid_s - secs : 0;
      if (a->valid_s == 0) /* REQ-SLAAC-022 */
        memset(a, 0, sizeof(*a));
    }
  }
  if (net->ip6_router_life_s) /* REQ-NDP-043 */
    net->ip6_router_life_s = net->ip6_router_life_s > secs
                                 ? (uint16_t)(net->ip6_router_life_s - secs)
                                 : 0;
  if (net->mld_v1_s) /* Older Version Querier Present timeout */
    net->mld_v1_s =
        net->mld_v1_s > secs ? (uint16_t)(net->mld_v1_s - secs) : 0;
}

void ipv6_tick(net_t *net, uint32_t elapsed_ms) {
  /* Whole seconds for the lifetimes (a loop, not a division: Cortex-M0) */
  uint32_t acc = net->ip6_sec_ms + elapsed_ms;
  uint32_t secs = 0;
  while (acc >= 1000u) {
    acc -= 1000u;
    secs++;
  }
  net->ip6_sec_ms = (uint16_t)acc;
  if (secs)
    lifetimes_elapse(net, secs);
  /* MLD before ND: a report ND sends now is repeated a full interval
   * later, not in this same tick */
  mld_tick(net, elapsed_ms);
  ndp_tick(net, elapsed_ms);
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

net_err_t ipv6_addr_add(net_t *net, const uint8_t *addr, uint32_t valid_s,
                        uint32_t preferred_s) {
  uint8_t i;
  if (ipv6_is_multicast(addr) || ipv6_is_unspecified(addr))
    return NET_ERR_INVALID_PARAM;
  if (ipv6_addr_slot(net, addr) >= 0)
    return NET_OK;
  for (i = 1; i < NET_IPV6_ADDRS; i++) {
    net_ip6_addr_t *a = &net->ip6[i];
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

void ipv6_addr_remove(net_t *net, const uint8_t *addr) {
  int slot = ipv6_addr_slot(net, addr);
  if (slot > 0) /* never the link-local address */
    memset(&net->ip6[slot], 0, sizeof(net->ip6[slot]));
}

const uint8_t *ipv6_router_mac(const net_t *net) {
  return net->ip6_router_life_s ? net->ip6_router_mac : NULL;
}

int ipv6_on_link(const net_t *net, const uint8_t *dst) {
  uint8_t i;
  if (ipv6_is_link_local(dst))
    return 1;
  for (i = 1; i < NET_IPV6_ADDRS; i++) {
    if (net->ip6[i].state != NET_IP6_NONE &&
        memcmp(net->ip6[i].addr, dst, 8) == 0)
      return 1;
  }
  return 0;
}

uint8_t ipv6_addr_state(const net_t *net, uint8_t slot) {
  return slot < NET_IPV6_ADDRS ? net->ip6[slot].state : NET_IP6_NONE;
}

int ipv6_addr_slot(const net_t *net, const uint8_t *addr) {
  uint8_t i;
  for (i = 0; i < NET_IPV6_ADDRS; i++) {
    if (net->ip6[i].state != NET_IP6_NONE &&
        ipv6_addr_equal(net->ip6[i].addr, addr))
      return i;
  }
  return -1;
}

static int usable(const net_ip6_addr_t *a) {
  return a->state == NET_IP6_PREFERRED || a->state == NET_IP6_DEPRECATED;
}

int ipv6_is_ours(const net_t *net, const uint8_t *addr) {
  int slot = ipv6_addr_slot(net, addr);
  return slot >= 0 && usable(&net->ip6[slot]);
}

const uint8_t *ipv6_src_for(const net_t *net, const uint8_t *dst) {
  const net_ip6_addr_t *ll = &net->ip6[0];
  uint8_t i;
  /* RFC 6724 rule 2: the link-local address for link-scope destinations */
  if (ipv6_is_link_local(dst) ||
      (ipv6_is_multicast(dst) && (dst[1] & 0x0F) <= 2))
    return usable(ll) ? ll->addr : NULL;
  /* rule 3: preferred before deprecated */
  for (i = 1; i < NET_IPV6_ADDRS; i++) {
    if (net->ip6[i].state == NET_IP6_PREFERRED)
      return net->ip6[i].addr;
  }
  for (i = 1; i < NET_IPV6_ADDRS; i++) {
    if (net->ip6[i].state == NET_IP6_DEPRECATED)
      return net->ip6[i].addr;
  }
  /* a wider-scope group can still be reached from the link */
  if (ipv6_is_multicast(dst) && usable(ll))
    return ll->addr;
  return NULL;
}

int ipv6_mac_accepted(const net_t *net, const uint8_t *mac) {
  uint8_t i;
  if (mac[0] != 0x33 || mac[1] != 0x33)
    return 0;
  if (net->ip6[0].state == NET_IP6_NONE)
    return 0; /* IPv6 not started */
  if (mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 1)
    return 1; /* all-nodes */
  for (i = 0; i < NET_IPV6_ADDRS; i++) {
    /* solicited-node group: 33:33:ff + low 24 bits of the address */
    if (net->ip6[i].state != NET_IP6_NONE && mac[2] == 0xFF &&
        memcmp(mac + 3, net->ip6[i].addr + 13, 3) == 0)
      return 1;
  }
#if NET_MAX_MCAST6_GROUPS > 0
  for (i = 0; i < NET_MAX_MCAST6_GROUPS; i++) {
    if (!ipv6_is_unspecified(net->mcast6_groups[i]) &&
        memcmp(mac + 2, net->mcast6_groups[i] + 12, 4) == 0)
      return 1;
  }
#endif
  return 0;
}

/** Destination is ours: a usable address, all-nodes, or the solicited-node
 *  group of a configured address (DAD runs over it while tentative). */
static int for_us(const net_t *net, const uint8_t *dst) {
  uint8_t i, snm[16];
  if (!ipv6_is_multicast(dst))
    return ipv6_is_ours(net, dst);
  if (ipv6_addr_equal(dst, all_nodes) || ipv6_mcast_is_member(net, dst))
    return 1;
  for (i = 0; i < NET_IPV6_ADDRS; i++) {
    if (net->ip6[i].state == NET_IP6_NONE)
      continue;
    ipv6_solicited_node(net->ip6[i].addr, snm);
    if (ipv6_addr_equal(dst, snm))
      return 1;
  }
  return 0;
}

/* ── Input processing ─────────────────────────────────────────────── */

void ipv6_input(net_t *net, const eth_frame_t *eth) {
  ipv6_hdr_t ip;

  if (net->ip6[0].state == NET_IP6_NONE)
    return; /* IPv6 not started */
  if (ipv6_parse(eth->payload, eth->payload_len, &ip) != NET_OK) {
    NET_LOG("ipv6_input: parse failed");
    return;
  }
  /* REQ-IPv6-011,012: multicast or own source */
  if (ipv6_is_multicast(ip.src) || ipv6_is_ours(net, ip.src))
    return;
  /* REQ-IPv6-006..010 */
  if (!for_us(net, ip.dst))
    return;

  switch (ip.next_header) {
  case IPV6_NH_ICMPV6: /* REQ-IPv6-014 */
    icmpv6_input(net, &ip, eth);
    break;
#if NET_USE_UDP
  case IPV6_NH_UDP: /* REQ-IPv6-016 */
    udp6_input(net, &ip, eth);
    break;
#endif
#if NET_USE_TCP
  case IPV6_NH_TCP: /* REQ-IPv6-015 */
    tcp6_input(net, &ip, eth);
    break;
#endif
  default:
    /* REQ-IPv6-017: unrecognized Next Header → Parameter Problem code 1,
     * pointing at the field that named it */
    NET_LOG("ipv6_input: unknown next header %u", ip.next_header);
    icmpv6_send_error(net, ICMPV6_PARAM_PROBLEM, ICMPV6_CODE_UNRECOGNIZED_NH,
                      ip.nh_offset, &ip, eth);
    break;
  }
}
