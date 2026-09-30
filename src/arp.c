/**
 * @file arp.c
 * @brief ARP (RFC 826).  REQ-ARP-001..037.
 *
 * No ARP cache: the gateway's MAC is kept in net_t, other peers' MACs in
 * the connections that use them.
 */

#include "arp.h"
#include "ipv4.h"
#include "net_endian.h"
#include <string.h>

static const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* REQ-ARP-005, 006 */
static int arp_is_ethernet_ipv4(const uint8_t *pkt, uint16_t len) {
  return len >= ARP_PKT_SIZE &&
         net_read16be(pkt + ARP_OFF_HTYPE) == ARP_HTYPE_ETHERNET &&
         net_read16be(pkt + ARP_OFF_PTYPE) == ARP_PTYPE_IPV4 &&
         pkt[ARP_OFF_HLEN] == ARP_HLEN_ETH &&
         pkt[ARP_OFF_PLEN] == ARP_PLEN_IPV4;
}

/* REQ-ARP-002, 003, 015..020 */
static net_err_t arp_send(net_t *net, uint16_t oper, const uint8_t *frame_dst,
                          const uint8_t *target_mac, uint32_t target_ip) {
  uint8_t *pkt;
  if (net->tx.capacity < ETH_HDR_SIZE + ARP_PKT_SIZE)
    return NET_ERR_BUF_TOO_SMALL;
  pkt = eth_build(net->tx.buf, net->tx.capacity, frame_dst, net->mac,
                  NET_ETHERTYPE_ARP);
  net_write16be(pkt + ARP_OFF_HTYPE, ARP_HTYPE_ETHERNET);
  net_write16be(pkt + ARP_OFF_PTYPE, ARP_PTYPE_IPV4);
  pkt[ARP_OFF_HLEN] = ARP_HLEN_ETH;
  pkt[ARP_OFF_PLEN] = ARP_PLEN_IPV4;
  net_write16be(pkt + ARP_OFF_OPER, oper);
  memcpy(pkt + ARP_OFF_SHA, net->mac, 6);
  net_write32be(pkt + ARP_OFF_SPA, net->ipv4_addr);
  memcpy(pkt + ARP_OFF_THA, target_mac, 6);
  net_write32be(pkt + ARP_OFF_TPA, target_ip);
  return net_transmit(net, ETH_HDR_SIZE + ARP_PKT_SIZE);
}

/* REQ-ARP-001..013 */
void arp_input(net_t *net, const eth_frame_t *eth) {
  const uint8_t *pkt = eth->payload;
  if (!arp_is_ethernet_ipv4(pkt, eth->payload_len))
    return;

  uint16_t oper = net_read16be(pkt + ARP_OFF_OPER);
  uint32_t sender_ip = net_read32be(pkt + ARP_OFF_SPA);
  const uint8_t *sender_mac = pkt + ARP_OFF_SHA;

  /* 0.0.0.0 is no one's address: not ours before DHCP configures one, nor
   * the gateway's while there is none */
  if (oper == ARP_OPER_REQUEST && net->ipv4_addr != 0 &&
      net_read32be(pkt + ARP_OFF_TPA) == net->ipv4_addr) {
    arp_send(net, ARP_OPER_REPLY, sender_mac, sender_mac, sender_ip);
  } else if (oper == ARP_OPER_REPLY && net->gateway_ipv4 != 0 &&
             sender_ip == net->gateway_ipv4) {
    memcpy(net->gateway_mac, sender_mac, 6);
    net->gateway_mac_valid = 1;
  }
}

net_err_t arp_request(net_t *net, uint32_t target_ip) {
  static const uint8_t unknown_mac[6] = {0};
  return arp_send(net, ARP_OPER_REQUEST, broadcast_mac, unknown_mac, target_ip);
}

/* REQ-ARP-025, 026 */
uint32_t arp_next_hop(const net_t *net, uint32_t dst_ip) {
  return ipv4_is_local(net, dst_ip) ? dst_ip : net->gateway_ipv4;
}
