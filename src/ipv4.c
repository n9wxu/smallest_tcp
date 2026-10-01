/**
 * @file ipv4.c
 * @brief IPv4 (RFC 791, RFC 1112).  REQ-IPv4-001..057.
 */

#include "ipv4.h"
#include "icmp.h"
#include "net_cksum.h"
#include "net_endian.h"
#include <string.h>

#if NET_USE_UDP
#include "udp.h"
#endif

#if NET_USE_TCP
#include "tcp.h"
#endif

#define IPV4_OPT_ROUTER_ALERT 0x94 /* copied flag + option 20 */
#define IPV4_OPT_EOL 0
#define IPV4_OPT_NOP 1
#define IPV4_OPT_LSRR 131
#define IPV4_OPT_SSRR 137

/* The options carry a Loose or Strict Source Route.  The walk stops at End
 * of List or at a malformed length: what follows is ignored, as every
 * other option is (REQ-IPv4-026, 068). */
static int source_routed(const uint8_t *opt, uint16_t len) {
  uint16_t i = 0;
  while (i < len && opt[i] != IPV4_OPT_EOL) {
    if (opt[i] == IPV4_OPT_NOP) {
      i++;
      continue;
    }
    if (i + 1 >= len || opt[i + 1] < 2 || opt[i + 1] > len - i)
      return 0;
    if (opt[i] == IPV4_OPT_LSRR || opt[i] == IPV4_OPT_SSRR)
      return 1;
    i = (uint16_t)(i + opt[i + 1]);
  }
  return 0;
}

/* REQ-IPv4-001..007, 024, 027, 067 */
net_err_t ipv4_parse(uint8_t *data, uint16_t data_len, ipv4_hdr_t *out) {
  if (data_len < IPV4_HDR_SIZE || (data[IPV4_OFF_VER_IHL] >> 4) != 4)
    return NET_ERR_INVALID_PARAM;

  uint16_t header_len = (uint16_t)((data[IPV4_OFF_VER_IHL] & 0x0F) * 4);
  uint16_t total_len = net_read16be(data + IPV4_OFF_TOTLEN);
  uint16_t flags_frag = net_read16be(data + IPV4_OFF_FLAGS_FRAG);
  int is_fragment = (flags_frag & (IPV4_FLAG_MF | IPV4_FRAG_MASK)) != 0;

  if (header_len < IPV4_HDR_SIZE || total_len < header_len ||
      total_len > data_len || !net_cksum_verify(data, header_len) ||
      is_fragment ||
      source_routed(data + IPV4_HDR_SIZE, header_len - IPV4_HDR_SIZE))
    return NET_ERR_INVALID_PARAM;

  out->protocol = data[IPV4_OFF_PROTO];
  out->ttl = data[IPV4_OFF_TTL];
  out->total_len = total_len;
  out->src_ip = net_read32be(data + IPV4_OFF_SRC);
  out->dst_ip = net_read32be(data + IPV4_OFF_DST);
  out->header = data;
  out->header_len = header_len;
  out->payload = data + header_len;
  out->payload_len = total_len - header_len;
  return NET_OK;
}

/* REQ-IPv4-030..041, 045 */
static void build_header(uint8_t *buf, uint8_t header_len, uint16_t payload_len,
                         uint8_t protocol, uint32_t src_ip, uint32_t dst_ip,
                         uint8_t ttl, uint8_t tos) {
  buf[IPV4_OFF_VER_IHL] = (uint8_t)(0x40 | (header_len >> 2));
  buf[IPV4_OFF_TOS] = tos;
  net_write16be(buf + IPV4_OFF_TOTLEN, (uint16_t)(header_len + payload_len));
  net_write16be(buf + IPV4_OFF_ID, 0);
  net_write16be(buf + IPV4_OFF_FLAGS_FRAG, IPV4_FLAG_DF);
  buf[IPV4_OFF_TTL] = ttl;
  buf[IPV4_OFF_PROTO] = protocol;
  net_write16be(buf + IPV4_OFF_CKSUM, 0);
  net_write32be(buf + IPV4_OFF_SRC, src_ip);
  net_write32be(buf + IPV4_OFF_DST, dst_ip);
  net_write16be(buf + IPV4_OFF_CKSUM, net_cksum(buf, header_len));
}

void ipv4_build_tos(uint8_t *buf, uint16_t payload_len, uint8_t protocol,
                    uint32_t src_ip, uint32_t dst_ip, uint8_t ttl,
                    uint8_t tos) {
  build_header(buf, IPV4_HDR_SIZE, payload_len, protocol, src_ip, dst_ip, ttl,
               tos);
}

void ipv4_build_router_alert(uint8_t *buf, uint16_t payload_len,
                             uint8_t protocol, uint32_t src_ip,
                             uint32_t dst_ip) {
  static const uint8_t router_alert[4] = {IPV4_OPT_ROUTER_ALERT, 4, 0, 0};
  memcpy(buf + IPV4_HDR_SIZE, router_alert, sizeof(router_alert));
  build_header(buf, IPV4_ROUTER_ALERT_HDR_SIZE, payload_len, protocol, src_ip,
               dst_ip, 1, 0);
}

uint16_t ipv4_cksum(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol,
                    const uint8_t *data, uint16_t len) {
  net_cksum_t c;
  net_cksum_init(&c);
  net_cksum_add_u32(&c, src_ip);
  net_cksum_add_u32(&c, dst_ip);
  net_cksum_add_u16(&c, protocol);
  net_cksum_add_u16(&c, len);
  net_cksum_add(&c, data, len);
  return net_cksum_finalize(&c);
}

net_err_t ipv4_mcast_join(net_t *net, uint32_t group) {
  if (!ipv4_is_multicast(group))
    return NET_ERR_INVALID_PARAM;
#if NET_MAX_MCAST_GROUPS > 0
  uint8_t i;
  int free_slot = -1;
  if (group == IPV4_ALL_HOSTS)
    return NET_OK;
  for (i = 0; i < NET_MAX_MCAST_GROUPS; i++) {
    if (net->mcast_groups[i] == group)
      return NET_OK;
    if (net->mcast_groups[i] == 0 && free_slot < 0)
      free_slot = i;
  }
  if (free_slot >= 0) {
    net->mcast_groups[free_slot] = group;
    return NET_OK;
  }
#else
  (void)net;
#endif
  return NET_ERR_BUF_TOO_SMALL;
}

void ipv4_mcast_leave(net_t *net, uint32_t group) {
#if NET_MAX_MCAST_GROUPS > 0
  uint8_t i;
  for (i = 0; i < NET_MAX_MCAST_GROUPS; i++) {
    if (net->mcast_groups[i] == group)
      net->mcast_groups[i] = 0;
  }
#else
  (void)net;
  (void)group;
#endif
}

int ipv4_mcast_is_member(const net_t *net, uint32_t group) {
#if NET_MAX_MCAST_GROUPS > 0
  uint8_t i;
  if (group == IPV4_ALL_HOSTS) /* REQ-IPv4-050 */
    return 1;
  for (i = 0; group != 0 && i < NET_MAX_MCAST_GROUPS; i++) {
    if (net->mcast_groups[i] == group)
      return 1;
  }
#else
  (void)net;
  (void)group;
#endif
  return 0;
}

int ipv4_mcast_mac_accepted(const net_t *net, const uint8_t *mac) {
#if NET_MAX_MCAST_GROUPS > 0
  uint8_t i, group_mac[6];
  ipv4_mcast_mac(IPV4_ALL_HOSTS, group_mac);
  if (net_mac_equal(mac, group_mac))
    return 1;
  for (i = 0; i < NET_MAX_MCAST_GROUPS; i++) {
    if (net->mcast_groups[i] == 0)
      continue;
    ipv4_mcast_mac(net->mcast_groups[i], group_mac);
    if (net_mac_equal(mac, group_mac))
      return 1;
  }
#else
  (void)net;
  (void)mac;
#endif
  return 0;
}

/* The mask of our address's class (A, B or C), 0 for none */
static uint32_t classful_mask(uint32_t ip) {
  if ((ip >> 31) == 0)
    return 0xFF000000u;
  if ((ip >> 30) == 2)
    return 0xFFFF0000u;
  if ((ip >> 29) == 6)
    return 0xFFFFFF00u;
  return 0;
}

int ipv4_is_broadcast(const net_t *net, uint32_t ip) {
  uint32_t host = ~net->subnet_mask;
  uint32_t net_mask = classful_mask(net->ipv4_addr);
  if (ip == IPV4_BROADCAST)
    return 1;
  if (host > 1u && (ip & host) == host && ipv4_is_local(net, ip))
    return 1;
  /* {network, -1} and {network, -1, -1} of our classful network, when the
   * subnet lies inside it (RFC 1122 §3.3.6) */
  return net->ipv4_addr != 0 && net_mask != 0 &&
         (net->subnet_mask & net_mask) == net_mask &&
         (ip & net_mask) == (net->ipv4_addr & net_mask) &&
         (ip | net_mask) == IPV4_BROADCAST;
}

int ipv4_is_host(const net_t *net, uint32_t ip) {
  return ip != 0 && (ip >> 24) != 127 && (ip >> 28) < 0xE &&
         !ipv4_is_broadcast(net, ip);
}

net_err_t ipv4_set_reassembly(net_t *net, uint8_t *buf, uint16_t size) {
  (void)net;
  (void)buf;
  (void)size;
  return NET_ERR_INVALID_PARAM; /* not implemented yet */
}

/* The transport message a frame of @p capacity carries */
static uint16_t frame_mms(const net_t *net, uint16_t capacity) {
  uint16_t room = eth_frame_room(net, capacity);
  return room > ETH_HDR_SIZE + IPV4_HDR_SIZE
             ? (uint16_t)(room - ETH_HDR_SIZE - IPV4_HDR_SIZE)
             : 0u;
}

/* REQ-IPv4-062 */
uint16_t ipv4_mms_r(const net_t *net) {
  return frame_mms(net, net->rx.capacity);
}

/* REQ-IPv4-063, 064 */
uint16_t ipv4_mms_s(const net_t *net) {
  return frame_mms(net, net->tx.capacity);
}

/* REQ-IPv4-013..015: a single host other than us, or 0.0.0.0 — a DHCP
 * client's (REQ-IPv4-016) */
static int source_is_valid(const net_t *net, uint32_t src_ip) {
  return (src_ip == 0 || ipv4_is_host(net, src_ip)) &&
         (src_ip != net->ipv4_addr || net->ipv4_addr == 0);
}

/* REQ-IPv4-008..012, 043: we do not forward */
static int destination_is_us(const net_t *net, uint32_t dst_ip) {
  int bootstrapping = net->ipv4_addr == 0 && dst_ip == 0; /* DHCP */
  return dst_ip == net->ipv4_addr || ipv4_is_broadcast(net, dst_ip) ||
         bootstrapping ||
         (ipv4_is_multicast(dst_ip) && ipv4_mcast_is_member(net, dst_ip));
}

/* REQ-IPv4-017..021 */
void ipv4_input(net_t *net, const eth_frame_t *eth) {
  ipv4_hdr_t ip;

  if (ipv4_parse(eth->payload, eth->payload_len, &ip) != NET_OK ||
      !source_is_valid(net, ip.src_ip) || !destination_is_us(net, ip.dst_ip))
    return;

  switch (ip.protocol) {
  case IPV4_PROTO_ICMP:
    icmp_input(net, &ip, eth);
    break;
#if NET_USE_UDP
  case IPV4_PROTO_UDP:
    udp_input(net, &ip, eth);
    break;
#endif
#if NET_USE_TCP
  case IPV4_PROTO_TCP:
    tcp_input(net, &ip, eth);
    break;
#endif
  default:
    icmp_send_dest_unreach(net, ICMP_CODE_PROTO_UNREACH, &ip, eth);
    break;
  }
}
