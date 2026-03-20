/**
 * @file arp.c
 * @brief ARP — Address Resolution Protocol (RFC 826).
 *
 * Implements REQ-ARP-001 through REQ-ARP-037.
 * Distributed cache: gateway MAC stored in net_t, no global table.
 */

#include "arp.h"
#include "net_endian.h"
#include <string.h>

/* ── Validation ───────────────────────────────────────────────────── */

static int arp_validate(const uint8_t *pkt, uint16_t len) {
  if (len < ARP_PKT_SIZE)
    return 0;
  /* REQ-ARP-005: HW type = Ethernet */
  if (net_read16be(pkt + ARP_OFF_HTYPE) != ARP_HTYPE_ETHERNET)
    return 0;
  /* REQ-ARP-005: Protocol type = IPv4 */
  if (net_read16be(pkt + ARP_OFF_PTYPE) != ARP_PTYPE_IPV4)
    return 0;
  /* REQ-ARP-006: HLEN=6, PLEN=4 */
  if (pkt[ARP_OFF_HLEN] != ARP_HLEN_ETH)
    return 0;
  if (pkt[ARP_OFF_PLEN] != ARP_PLEN_IPV4)
    return 0;
  return 1;
}

/* ── Send ARP reply ───────────────────────────────────────────────── */

static net_err_t arp_send_reply(net_t *net, const uint8_t *target_mac,
                                uint32_t target_ip) {
  uint8_t *buf = net->tx.buf;
  uint16_t cap = net->tx.capacity;
  if (cap < ETH_HDR_SIZE + ARP_PKT_SIZE)
    return NET_ERR_BUF_TOO_SMALL;

  /* Build Ethernet header: unicast reply to requester (REQ-ARP-003) */
  uint8_t *payload =
      eth_build(buf, cap, target_mac, net->mac, NET_ETHERTYPE_ARP);
  if (!payload)
    return NET_ERR_BUF_TOO_SMALL;

  /* Build ARP reply (REQ-ARP-002) */
  net_write16be(payload + ARP_OFF_HTYPE, ARP_HTYPE_ETHERNET);
  net_write16be(payload + ARP_OFF_PTYPE, ARP_PTYPE_IPV4);
  payload[ARP_OFF_HLEN] = ARP_HLEN_ETH;
  payload[ARP_OFF_PLEN] = ARP_PLEN_IPV4;
  net_write16be(payload + ARP_OFF_OPER, ARP_OPER_REPLY);
  memcpy(payload + ARP_OFF_SHA, net->mac, 6);
  net_write32be(payload + ARP_OFF_SPA, net->ipv4_addr);
  memcpy(payload + ARP_OFF_THA, target_mac, 6);
  net_write32be(payload + ARP_OFF_TPA, target_ip);

  uint16_t frame_len = ETH_HDR_SIZE + ARP_PKT_SIZE;
  return (net->mac_driver->send(net->mac_ctx, buf, frame_len) >= 0)
             ? NET_OK
             : NET_ERR_NO_FRAME;
}

/* ── Input processing ─────────────────────────────────────────────── */

void arp_input(net_t *net, const eth_frame_t *eth) {
  uint8_t *pkt = eth->payload;
  uint16_t len = eth->payload_len;

  /* REQ-ARP-005..007: validate fields */
  if (!arp_validate(pkt, len)) {
    NET_LOG("arp_input: invalid ARP packet");
    return;
  }

  uint16_t oper = net_read16be(pkt + ARP_OFF_OPER);
  uint32_t sender_ip = net_read32be(pkt + ARP_OFF_SPA);
  uint32_t target_ip = net_read32be(pkt + ARP_OFF_TPA);
  const uint8_t *sender_mac = pkt + ARP_OFF_SHA;

  if (oper == ARP_OPER_REQUEST) {
    /* REQ-ARP-004: discard if target IP is not ours */
    if (target_ip != net->ipv4_addr)
      return;
    /* REQ-ARP-001: respond with our MAC */
    NET_LOG("arp_input: request for our IP from %u.%u.%u.%u",
            (sender_ip >> 24) & 0xFF, (sender_ip >> 16) & 0xFF,
            (sender_ip >> 8) & 0xFF, sender_ip & 0xFF);
    arp_send_reply(net, sender_mac, sender_ip);
  } else if (oper == ARP_OPER_REPLY) {
    /* REQ-ARP-010..012: check if reply matches gateway IP */
    if (sender_ip == net->gateway_ipv4) {
      memcpy(net->gateway_mac, sender_mac, 6);
      net->gateway_mac_valid = 1;
      NET_LOG("arp_input: learned gateway MAC %02x:%02x:%02x:%02x:%02x:%02x",
              sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3],
              sender_mac[4], sender_mac[5]);
    }
    /* REQ-ARP-013: otherwise silently discard */
  }
  /* REQ-ARP-007: unknown operation — silently discard */
}

/* ── Send ARP request ─────────────────────────────────────────────── */

net_err_t arp_request(net_t *net, uint32_t target_ip) {
  uint8_t *buf = net->tx.buf;
  uint16_t cap = net->tx.capacity;
  if (cap < ETH_HDR_SIZE + ARP_PKT_SIZE)
    return NET_ERR_BUF_TOO_SMALL;

  /* REQ-ARP-016: broadcast MAC */
  static const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t *payload = eth_build(buf, cap, bcast, net->mac, NET_ETHERTYPE_ARP);
  if (!payload)
    return NET_ERR_BUF_TOO_SMALL;

  /* REQ-ARP-019, REQ-ARP-020: our MAC and IP as sender */
  net_write16be(payload + ARP_OFF_HTYPE, ARP_HTYPE_ETHERNET);
  net_write16be(payload + ARP_OFF_PTYPE, ARP_PTYPE_IPV4);
  payload[ARP_OFF_HLEN] = ARP_HLEN_ETH;
  payload[ARP_OFF_PLEN] = ARP_PLEN_IPV4;
  net_write16be(payload + ARP_OFF_OPER, ARP_OPER_REQUEST);
  memcpy(payload + ARP_OFF_SHA, net->mac, 6);
  net_write32be(payload + ARP_OFF_SPA, net->ipv4_addr);
  memset(payload + ARP_OFF_THA, 0x00, 6);
  net_write32be(payload + ARP_OFF_TPA, target_ip);

  uint16_t frame_len = ETH_HDR_SIZE + ARP_PKT_SIZE;
  NET_LOG("arp_request: who has %u.%u.%u.%u?", (target_ip >> 24) & 0xFF,
          (target_ip >> 16) & 0xFF, (target_ip >> 8) & 0xFF, target_ip & 0xFF);
  return (net->mac_driver->send(net->mac_ctx, buf, frame_len) >= 0)
             ? NET_OK
             : NET_ERR_NO_FRAME;
}

/* ── Next-hop determination ───────────────────────────────────────── */

uint32_t arp_next_hop(const net_t *net, uint32_t dst_ip) {
  /* REQ-ARP-025: local subnet → direct */
  if ((dst_ip & net->subnet_mask) == (net->ipv4_addr & net->subnet_mask)) {
    return dst_ip;
  }
  /* REQ-ARP-026: off-subnet → gateway */
  return net->gateway_ipv4;
}
