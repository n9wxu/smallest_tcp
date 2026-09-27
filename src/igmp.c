/**
 * @file igmp.c
 * @brief Minimal IGMPv2 host (RFC 2236): join and leave reports only.
 *        REQ-MDNS-002.
 */

#include "igmp.h"
#include "eth.h"
#include "ipv4.h"
#include "net_cksum.h"
#include "net_endian.h"

#define IGMP_MSG_SIZE 8

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
