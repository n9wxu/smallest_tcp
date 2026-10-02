/**
 * @file icmp.c
 * @brief ICMPv4 (RFC 792).  REQ-ICMPv4-001..048.
 */

#include "icmp.h"
#include "ipv4.h"
#include "net_cksum.h"
#include "net_endian.h"
#include <string.h>

#if NET_USE_UDP
#include "udp.h"
#endif
#if NET_USE_TCP
#include "tcp.h"
#endif

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

/* REQ-ICMPv4-001..009: the request's identifier, sequence and data back,
 * truncated to what one datagram carries (MMS_S); REQ-IPv4-070: none to a
 * source of 0.0.0.0 */
static void echo_reply(net_t *net, const ipv4_hdr_t *ip,
                       const eth_frame_t *eth) {
  uint8_t *reply = net->tx.buf + ICMP_OFFSET;
  uint16_t len = ip->payload_len;
  uint16_t room = ipv4_mms_s(net);
  if (sent_to_many(net, ip) || ip->src_ip == 0 || room < ICMP_HDR_SIZE)
    return;
  if (len > room)
    len = room;
  memcpy(reply, ip->payload, len);
  reply[ICMP_OFF_TYPE] = ICMP_TYPE_ECHO_REPLY;
  reply[ICMP_OFF_CODE] = 0;
  icmp_send(net, len, ip->src_ip, eth->src_mac);
}

/* REQ-ICMPv4-011..016, 024, 029, 042: an error quoting a datagram we sent
 * goes to the transport the quoted header names, with the whole quote.
 * The quote must begin with a whole IPv4 header: the transports find
 * their own header after it. */
static void error_input(net_t *net, const ipv4_hdr_t *ip) {
  const uint8_t *icmp = ip->payload;
  const uint8_t *quote = icmp + ICMP_HDR_SIZE;
  uint16_t quote_len = (uint16_t)(ip->payload_len - ICMP_HDR_SIZE);
  uint16_t quoted_ihl, mtu = 0;
  if (quote_len < IPV4_HDR_SIZE || (quote[IPV4_OFF_VER_IHL] >> 4) != 4)
    return;
  quoted_ihl = (uint16_t)((quote[IPV4_OFF_VER_IHL] & 0x0F) * 4);
  if (quoted_ihl < IPV4_HDR_SIZE || quoted_ihl > quote_len ||
      net_read32be(quote + IPV4_OFF_SRC) != net->ipv4_addr)
    return;
  if (icmp[ICMP_OFF_TYPE] == ICMP_TYPE_DEST_UNREACH &&
      icmp[ICMP_OFF_CODE] == ICMP_CODE_FRAG_NEEDED)
    mtu = net_read16be(icmp + 6); /* RFC 1191 §4 */
  switch (quote[IPV4_OFF_PROTO]) {
#if NET_USE_UDP
  case IPV4_PROTO_UDP:
    udp_icmp_error(net, icmp[ICMP_OFF_TYPE], icmp[ICMP_OFF_CODE], mtu, quote,
                   quote_len);
    break;
#endif
#if NET_USE_TCP
  case IPV4_PROTO_TCP:
    tcp_icmp_error(net, icmp[ICMP_OFF_TYPE], icmp[ICMP_OFF_CODE], mtu, quote,
                   quote_len);
    break;
#endif
  default:
    (void)mtu;
    break;
  }
}

/* REQ-ICMPv4-028, 031, 040: only Echo Request is answered.  Errors go up
 * (error_input()); Source Quench (RFC 6633), Redirect (REQ-ICMPv4-019) and
 * the rest are dropped. */
void icmp_input(net_t *net, const ipv4_hdr_t *ip, const eth_frame_t *eth) {
  if (ip->payload_len < ICMP_HDR_SIZE ||
      !net_cksum_verify(ip->payload, ip->payload_len))
    return;
  switch (ip->payload[ICMP_OFF_TYPE]) {
  case ICMP_TYPE_ECHO_REQUEST:
    echo_reply(net, ip, eth);
    break;
  case ICMP_TYPE_DEST_UNREACH:
  case ICMP_TYPE_TIME_EXCEEDED:
  case ICMP_TYPE_PARAM_PROBLEM:
    error_input(net, ip);
    break;
  default:
    break;
  }
}

/* An ICMP error message, whose type is neither a query nor a reply */
static int is_icmp_error(const ipv4_hdr_t *ip) {
  uint8_t type;
  if (ip->protocol != IPV4_PROTO_ICMP || ip->payload_len == 0)
    return 0;
  type = ip->payload[ICMP_OFF_TYPE];
  return type == ICMP_TYPE_DEST_UNREACH || type == ICMP_TYPE_SOURCE_QUENCH ||
         type == ICMP_TYPE_REDIRECT || type == ICMP_TYPE_TIME_EXCEEDED ||
         type == ICMP_TYPE_PARAM_PROBLEM;
}

/* REQ-ICMPv4-038 */
static net_err_t send_error(net_t *net, uint8_t type, uint8_t code,
                            const ipv4_hdr_t *invoking,
                            const eth_frame_t *eth) {
  uint16_t payload = invoking->payload_len < ICMP_QUOTED_PAYLOAD
                         ? invoking->payload_len
                         : ICMP_QUOTED_PAYLOAD;
  uint16_t quote = (uint16_t)(invoking->header_len + payload);
  uint16_t icmp_len = (uint16_t)(ICMP_HDR_SIZE + quote);
  uint8_t *icmp = net->tx.buf + ICMP_OFFSET;

  /* REQ-ICMPv4-034..036 (RFC 1122 §3.2.2): never about an ICMP error, a
   * broadcast or multicast, nor a datagram from 0.0.0.0 or any source no
   * single host */
  if (sent_to_many(net, invoking) || net_mac_is_multicast(eth->dst_mac) ||
      !ipv4_is_host(net, invoking->src_ip) || is_icmp_error(invoking))
    return NET_ERR_INVALID_PARAM;
  if (icmp_len > ipv4_mms_s(net))
    return NET_ERR_BUF_TOO_SMALL;

  icmp[ICMP_OFF_TYPE] = type;
  icmp[ICMP_OFF_CODE] = code;
  net_write32be(icmp + 4, 0); /* unused / next-hop MTU */
  memcpy(icmp + ICMP_HDR_SIZE, invoking->header, quote);
  return icmp_send(net, icmp_len, invoking->src_ip, eth->src_mac);
}

net_err_t icmp_send_dest_unreach(net_t *net, uint8_t code,
                                 const ipv4_hdr_t *invoking,
                                 const eth_frame_t *eth) {
  return send_error(net, ICMP_TYPE_DEST_UNREACH, code, invoking, eth);
}

/* REQ-ICMPv4-025 */
net_err_t icmp_send_time_exceeded(net_t *net, uint8_t code,
                                  const ipv4_hdr_t *invoking,
                                  const eth_frame_t *eth) {
  return send_error(net, ICMP_TYPE_TIME_EXCEEDED, code, invoking, eth);
}
