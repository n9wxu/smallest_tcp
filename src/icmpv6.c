/**
 * @file icmpv6.c
 * @brief ICMPv6 (RFC 4443).  REQ-ICMPv6-001..041.
 */

#include "icmpv6.h"
#include "mld.h"
#include "ndp.h"
#include "net_endian.h"
#include <string.h>

#if NET_USE_TCP
#include "tcp.h"
#endif

net_err_t icmpv6_send(net_t *net, const uint8_t *src, const uint8_t *dst,
                      const uint8_t *dst_mac, uint16_t icmp_len,
                      uint8_t hop_limit) {
  uint8_t *msg = net->tx.buf + ICMPV6_OFFSET;
  if ((uint32_t)ICMPV6_OFFSET + icmp_len > net->tx.capacity)
    return NET_ERR_BUF_TOO_SMALL;

  /* REQ-ICMPv6-001, 003 */
  net_write16be(msg + ICMPV6_OFF_CKSUM, 0);
  net_write16be(msg + ICMPV6_OFF_CKSUM,
                ipv6_cksum(src, dst, IPV6_NH_ICMPV6, msg, icmp_len));
  eth_build(net->tx.buf, net->tx.capacity, dst_mac, net->mac,
            NET_ETHERTYPE_IPV6);
  ipv6_build(net->tx.buf + ETH_HDR_SIZE, icmp_len, IPV6_NH_ICMPV6, src, dst,
             hop_limit);
  return net_transmit(net, (uint16_t)(ICMPV6_OFFSET + icmp_len));
}

/* An error message itself, or one of unknown type (REQ-ICMPv6-031) */
static int is_icmpv6_error(const ipv6_hdr_t *ip) {
  return ip->next_header == IPV6_NH_ICMPV6 &&
         (ip->payload_len == 0 || ip->payload[ICMPV6_OFF_TYPE] < 128);
}

/* RFC 4443 §2.4(e), REQ-ICMPv6-028..031 */
static int error_allowed(uint8_t type, uint8_t code, const ipv6_hdr_t *ip,
                         const eth_frame_t *eth) {
  int to_group =
      ipv6_is_multicast(ip->dst) || net_mac_is_multicast(eth->dst_mac);
  int reportable_to_group =
      type == ICMPV6_PKT_TOO_BIG ||
      (type == ICMPV6_PARAM_PROBLEM && code == ICMPV6_CODE_UNRECOGNIZED_OPTION);
  return (!to_group || reportable_to_group) && !ipv6_is_multicast(ip->src) &&
         !ipv6_is_unspecified(ip->src) && !is_icmpv6_error(ip);
}

/* REQ-ICMPv6-017, 032: as much as fits in the minimum MTU and in tx */
static uint16_t quote_len(const net_t *net, const ipv6_hdr_t *ip) {
  uint32_t quote = (uint32_t)ip->header_len + ip->payload_len;
  uint32_t room = IPV6_MIN_MTU - IPV6_HDR_SIZE - ICMPV6_HDR_SIZE;
  uint32_t tx_room =
      (uint32_t)net->tx.capacity - ICMPV6_OFFSET - ICMPV6_HDR_SIZE;
  if (room > tx_room)
    room = tx_room;
  return (uint16_t)(quote < room ? quote : room);
}

net_err_t icmpv6_send_error(net_t *net, uint8_t type, uint8_t code,
                            uint32_t param, const ipv6_hdr_t *invoking,
                            const eth_frame_t *eth) {
  const uint8_t *src;
  uint16_t quote;

  if (!error_allowed(type, code, invoking, eth))
    return NET_ERR_INVALID_PARAM;
  if (net->tx.capacity < ICMPV6_OFFSET + ICMPV6_HDR_SIZE)
    return NET_ERR_BUF_TOO_SMALL;
  /* From the address the packet was sent to, if it is one of ours */
  src = ipv6_is_ours(net, invoking->dst) ? invoking->dst
                                         : ipv6_src_for(net, invoking->src);
  if (!src)
    return NET_ERR_INVALID_PARAM;
  if (net->ip6.error_tokens == 0) /* REQ-ICMPv6-033 */
    return NET_ERR_BUSY;
  net->ip6.error_tokens--;
  quote = quote_len(net, invoking);

  uint8_t *msg = net->tx.buf + ICMPV6_OFFSET;
  msg[ICMPV6_OFF_TYPE] = type;
  msg[ICMPV6_OFF_CODE] = code;
  net_write32be(msg + ICMPV6_OFF_BODY, param); /* REQ-ICMPv6-027 */
  memcpy(msg + ICMPV6_HDR_SIZE, invoking->header, quote);

  return icmpv6_send(net, src, invoking->src, eth->src_mac,
                     (uint16_t)(ICMPV6_HDR_SIZE + quote), net->ip6.hop_limit);
}

/* REQ-ICMPv6-033: a token for every ICMPV6_ERROR_INTERVAL_MS, up to
 * ICMPV6_ERROR_BURST (RFC 4443 §2.4(f)) */
void icmpv6_tick(net_t *net, uint32_t elapsed_ms) {
  net_ip6_t *ip6 = &net->ip6;
  uint32_t ms =
      (elapsed_ms > 0xFFFFu ? 0xFFFFu : elapsed_ms) + ip6->error_refill_ms;
  while (ip6->error_tokens < ICMPV6_ERROR_BURST &&
         ms >= ICMPV6_ERROR_INTERVAL_MS) {
    ms -= ICMPV6_ERROR_INTERVAL_MS;
    ip6->error_tokens++;
  }
  ip6->error_refill_ms =
      ip6->error_tokens < ICMPV6_ERROR_BURST ? (uint16_t)ms : 0;
}

/* REQ-ICMPv6-004..009 */
static void echo_reply(net_t *net, const ipv6_hdr_t *ip,
                       const eth_frame_t *eth) {
  uint16_t len = ip->payload_len;

  if (len < ICMPV6_HDR_SIZE || ipv6_is_unspecified(ip->src))
    return;
  if ((uint32_t)ICMPV6_OFFSET + len > net->tx.capacity)
    return;
  /* A request to a group is answered from a unicast address */
  const uint8_t *src =
      ipv6_is_multicast(ip->dst) ? ipv6_src_for(net, ip->src) : ip->dst;
  if (!src)
    return;

  uint8_t *msg = net->tx.buf + ICMPV6_OFFSET;
  memcpy(msg, ip->payload, len); /* identifier, sequence, data */
  msg[ICMPV6_OFF_TYPE] = ICMPV6_ECHO_REPLY;
  msg[ICMPV6_OFF_CODE] = 0;
  icmpv6_send(net, src, ip->src, eth->src_mac, len, net->ip6.hop_limit);
}

#if NET_USE_TCP
/* REQ-ICMPv6-011, 018..020, 022, 025: an error quoting a TCP segment goes
 * to TCP, with the packet quoted and the message's 4-byte field (a Packet
 * Too Big's MTU); TCP finds the connection, or none.  An error about any
 * other protocol is dropped */
static void error_input(net_t *net, const ipv6_hdr_t *ip) {
  const uint8_t *msg = ip->payload;
  const uint8_t *quote = msg + ICMPV6_HDR_SIZE;
  if (ip->payload_len < ICMPV6_HDR_SIZE + IPV6_HDR_SIZE ||
      (quote[IPV6_OFF_VTF] >> 4) != 6 || quote[IPV6_OFF_NH] != IPV6_NH_TCP)
    return;
  tcp6_icmp_error(net, msg[ICMPV6_OFF_TYPE], msg[ICMPV6_OFF_CODE],
                  net_read32be(msg + ICMPV6_OFF_BODY), quote,
                  (uint16_t)(ip->payload_len - ICMPV6_HDR_SIZE));
}
#endif

/* REQ-ICMPv6-002, 011, 018, 022, 025, 034..039 */
void icmpv6_input(net_t *net, const ipv6_hdr_t *ip, const eth_frame_t *eth) {
  const uint8_t *msg = ip->payload;

  if (ip->payload_len < 4)
    return;
  if (ipv6_cksum(ip->src, ip->dst, IPV6_NH_ICMPV6, msg, ip->payload_len) != 0) {
    NET_LOG("icmpv6_input: bad checksum");
    return;
  }

  switch (msg[ICMPV6_OFF_TYPE]) {
  case ICMPV6_ECHO_REQUEST:
    echo_reply(net, ip, eth);
    break;
  case ICMPV6_RS:
  case ICMPV6_RA:
  case ICMPV6_NS:
  case ICMPV6_NA:
  case ICMPV6_REDIRECT:
    ndp_input(net, ip, eth);
    break;
  case MLD_QUERY:
  case MLD_V1_REPORT:
  case MLD_V1_DONE:
  case MLD_V2_REPORT:
    mld_input(net, ip);
    break;
#if NET_USE_TCP
  case ICMPV6_DEST_UNREACH:
  case ICMPV6_PKT_TOO_BIG:
  case ICMPV6_TIME_EXCEEDED:
  case ICMPV6_PARAM_PROBLEM:
    error_input(net, ip);
    break;
#endif
  default: /* other errors and unknown informational messages are dropped */
    break;
  }
}
