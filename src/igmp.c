/**
 * @file igmp.c
 * @brief Minimal IGMPv2 host (RFC 2236) — join/leave signalling only.
 *
 * Implements REQ-MDNS-002 (join 224.0.0.251).  See igmp.h for scope.
 */

#include "igmp.h"
#include "eth.h"
#include "ipv4.h"
#include "net_cksum.h"
#include "net_endian.h"

#define IGMP_IP_HDR_SIZE 24 /* 20-byte header + 4-byte Router Alert */
#define IGMP_MSG_SIZE 8
#define IGMP_PROTO 2

static net_err_t igmp_send(net_t *net, uint8_t type, uint32_t dst_ip,
                           uint32_t group) {
  uint8_t dst_mac[6];
  if (net->tx.capacity < IGMP_FRAME_SIZE)
    return NET_ERR_BUF_TOO_SMALL;

  ipv4_mcast_mac(dst_ip, dst_mac);
  uint8_t *ip = eth_build(net->tx.buf, net->tx.capacity, dst_mac, net->mac,
                          NET_ETHERTYPE_IPV4);
  if (!ip)
    return NET_ERR_BUF_TOO_SMALL;

  /* IPv4 header with Router Alert (RFC 2113), TTL 1 (RFC 2236 §2) */
  ip[IPV4_OFF_VER_IHL] = 0x46;
  ip[IPV4_OFF_TOS] = 0x00;
  net_write16be(ip + IPV4_OFF_TOTLEN, IGMP_IP_HDR_SIZE + IGMP_MSG_SIZE);
  net_write16be(ip + IPV4_OFF_ID, 0);
  net_write16be(ip + IPV4_OFF_FLAGS_FRAG, IPV4_FLAG_DF);
  ip[IPV4_OFF_TTL] = 1;
  ip[IPV4_OFF_PROTO] = IGMP_PROTO;
  net_write16be(ip + IPV4_OFF_CKSUM, 0);
  net_write32be(ip + IPV4_OFF_SRC, net->ipv4_addr);
  net_write32be(ip + IPV4_OFF_DST, dst_ip);
  ip[20] = 0x94; /* Router Alert: copied flag + option 20 */
  ip[21] = 0x04;
  ip[22] = 0x00;
  ip[23] = 0x00;
  net_write16be(ip + IPV4_OFF_CKSUM, net_cksum(ip, IGMP_IP_HDR_SIZE));

  uint8_t *msg = ip + IGMP_IP_HDR_SIZE;
  msg[0] = type;
  msg[1] = 0; /* Max Resp Time: unused in reports/leaves */
  net_write16be(msg + 2, 0);
  net_write32be(msg + 4, group);
  net_write16be(msg + 2, net_cksum(msg, IGMP_MSG_SIZE));

  int r = net->mac_driver->send(net->mac_ctx, net->tx.buf, IGMP_FRAME_SIZE);
  return (r >= 0) ? NET_OK : NET_ERR_NO_FRAME;
}

net_err_t igmp_report(net_t *net, uint32_t group) {
  if (!ipv4_is_multicast(group))
    return NET_ERR_INVALID_PARAM;
  return igmp_send(net, IGMP_TYPE_V2_REPORT, group, group);
}

net_err_t igmp_join(net_t *net, uint32_t group) {
  net_err_t err = ipv4_mcast_join(net, group);
  if (err != NET_OK)
    return err;
  return igmp_report(net, group);
}

net_err_t igmp_leave(net_t *net, uint32_t group) {
  if (!ipv4_is_multicast(group))
    return NET_ERR_INVALID_PARAM;
  ipv4_mcast_leave(net, group);
  return igmp_send(net, IGMP_TYPE_LEAVE, IGMP_ALL_ROUTERS, group);
}
