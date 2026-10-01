/**
 * @file icmp.c
 * @brief ICMPv4 (RFC 792).  REQ-ICMPv4-001..041.
 */

#include "icmp.h"
#include "ipv4.h"
#include "net_cksum.h"
#include "net_endian.h"
#include <string.h>

#define ICMP_OFFSET (ETH_HDR_SIZE + IPV4_HDR_SIZE)

/* REQ-ICMPv4-009 */
static int sent_to_many(const net_t *net, const ipv4_hdr_t *ip) {
  return ipv4_is_broadcast(net, ip->dst_ip) || ipv4_rx_is_multicast(ip->dst_ip);
}

/* The ICMP message of @p icmp_len bytes at ICMP_OFFSET, to @p ip / @p mac */
static net_err_t icmp_send(net_t *net, uint16_t icmp_len, uint32_t dst_ip,
                           const uint8_t *dst_mac) {
  uint8_t *icmp = net->tx.buf + ICMP_OFFSET;
  if (net->ipv4_addr == 0) /* REQ-IPv4-070: not from 0.0.0.0 */
    return NET_ERR_INVALID_PARAM;
  net_write16be(icmp + ICMP_OFF_CKSUM, 0);
  net_write16be(icmp + ICMP_OFF_CKSUM, net_cksum(icmp, icmp_len));
  eth_build(net->tx.buf, net->tx.capacity, dst_mac, net->mac,
            NET_ETHERTYPE_IPV4);
  ipv4_build(net->tx.buf + ETH_HDR_SIZE, icmp_len, IPV4_PROTO_ICMP,
             net->ipv4_addr, dst_ip);
  return net_transmit(net, (uint16_t)(ICMP_OFFSET + icmp_len));
}

/* REQ-ICMPv4-001..009: the request's identifier, sequence and data back;
 * REQ-IPv4-070: none to a source of 0.0.0.0 */
static void echo_reply(net_t *net, const ipv4_hdr_t *ip,
                       const eth_frame_t *eth) {
  uint8_t *reply = net->tx.buf + ICMP_OFFSET;
  if (sent_to_many(net, ip) || ip->src_ip == 0 ||
      (uint32_t)ICMP_OFFSET + ip->payload_len > net->tx.capacity)
    return;
  memcpy(reply, ip->payload, ip->payload_len);
  reply[ICMP_OFF_TYPE] = ICMP_TYPE_ECHO_REPLY;
  reply[ICMP_OFF_CODE] = 0;
  icmp_send(net, ip->payload_len, ip->src_ip, eth->src_mac);
}

/* REQ-ICMPv4-028, 031, 040: only Echo Request is answered.  Received
 * errors — Destination Unreachable, Redirect, Time Exceeded, Parameter
 * Problem (REQ-ICMPv4-011..016, 019..021, 024, 029) — are dropped too:
 * no upper layer hears of them. */
void icmp_input(net_t *net, const ipv4_hdr_t *ip, const eth_frame_t *eth) {
  if (ip->payload_len < ICMP_HDR_SIZE ||
      !net_cksum_verify(ip->payload, ip->payload_len))
    return;
  if (ip->payload[ICMP_OFF_TYPE] == ICMP_TYPE_ECHO_REQUEST)
    echo_reply(net, ip, eth);
}

/* REQ-ICMPv4-038 */
net_err_t icmp_send_dest_unreach(net_t *net, uint8_t code,
                                 const ipv4_hdr_t *invoking,
                                 const eth_frame_t *eth) {
  uint16_t payload = invoking->payload_len < ICMP_QUOTED_PAYLOAD
                         ? invoking->payload_len
                         : ICMP_QUOTED_PAYLOAD;
  uint16_t quote = (uint16_t)(invoking->header_len + payload);
  uint16_t icmp_len = (uint16_t)(ICMP_HDR_SIZE + quote);
  uint8_t *icmp = net->tx.buf + ICMP_OFFSET;

  /* REQ-ICMPv4-035, 036 (RFC 1122 §3.2.2): never about a broadcast or
   * multicast, nor a datagram from 0.0.0.0 or any source no single host */
  if (sent_to_many(net, invoking) || net_mac_is_multicast(eth->dst_mac) ||
      !ipv4_is_host(net, invoking->src_ip))
    return NET_ERR_INVALID_PARAM;
  if ((uint32_t)ICMP_OFFSET + icmp_len > net->tx.capacity)
    return NET_ERR_BUF_TOO_SMALL;

  icmp[ICMP_OFF_TYPE] = ICMP_TYPE_DEST_UNREACH;
  icmp[ICMP_OFF_CODE] = code;
  net_write32be(icmp + 4, 0); /* unused / next-hop MTU */
  memcpy(icmp + ICMP_HDR_SIZE, invoking->header, quote);
  return icmp_send(net, icmp_len, invoking->src_ip, eth->src_mac);
}
