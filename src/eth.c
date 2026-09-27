/**
 * @file eth.c
 * @brief Ethernet II framing (RFC 894).  REQ-ETH-001..020.
 */

#include "eth.h"
#include "net_endian.h"
#include <string.h>

#if NET_USE_IPV4
#include "arp.h"
#include "ipv4.h"
#endif

#if NET_USE_IPV6
#include "ipv6.h"
#endif

/* REQ-ETH-004, 009, 017..019 */
net_err_t eth_parse(uint8_t *frame, uint16_t frame_len, eth_frame_t *out) {
  if (frame_len < ETH_HDR_SIZE)
    return NET_ERR_INVALID_PARAM;
  uint16_t ethertype = net_read16be(frame + ETH_OFF_TYPE);
  if (ethertype <= ETH_MAX_8023_LENGTH)
    return NET_ERR_INVALID_PARAM;

  out->dst_mac = frame + ETH_OFF_DST;
  out->src_mac = frame + ETH_OFF_SRC;
  out->ethertype = ethertype;
  out->payload = frame + ETH_HDR_SIZE;
  out->payload_len = frame_len - ETH_HDR_SIZE;
  return NET_OK;
}

/* REQ-ETH-011..015, 020 */
uint8_t *eth_build(uint8_t *buf, uint16_t buf_capacity, const uint8_t *dst_mac,
                   const uint8_t *src_mac, uint16_t ethertype) {
  if (buf_capacity < ETH_HDR_SIZE)
    return NULL;
  memcpy(buf + ETH_OFF_DST, dst_mac, 6);
  memcpy(buf + ETH_OFF_SRC, src_mac, 6);
  net_write16be(buf + ETH_OFF_TYPE, ethertype);
  return buf + ETH_HDR_SIZE;
}

/* REQ-ETH-001..003 */
static int addressed_to_us(const net_t *net, const uint8_t *dst_mac) {
  if (net_mac_equal(dst_mac, net->mac) || net_mac_is_broadcast(dst_mac))
    return 1;
#if NET_USE_IPV4 && NET_MAX_MCAST_GROUPS > 0
  if (ipv4_mcast_mac_accepted(net, dst_mac))
    return 1;
#endif
#if NET_USE_IPV6
  if (ipv6_mac_accepted(net, dst_mac))
    return 1;
#endif
  return 0;
}

/* REQ-ETH-005..008 */
void eth_input(net_t *net, uint8_t *frame, uint16_t len) {
  eth_frame_t eth;

  if (eth_parse(frame, len, &eth) != NET_OK ||
      !addressed_to_us(net, eth.dst_mac))
    return;

  switch (eth.ethertype) {
#if NET_USE_IPV4
  case NET_ETHERTYPE_ARP:
    arp_input(net, &eth);
    break;
  case NET_ETHERTYPE_IPV4:
    ipv4_input(net, &eth);
    break;
#endif
#if NET_USE_IPV6
  case NET_ETHERTYPE_IPV6:
    ipv6_input(net, &eth);
    break;
#endif
  default:
    NET_LOG("eth_input: unknown EtherType 0x%04x", eth.ethertype);
    break;
  }
}
