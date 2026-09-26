/**
 * @file icmpv6.c
 * @brief ICMPv6 — Internet Control Message Protocol for IPv6 (RFC 4443).
 *
 * Implements REQ-ICMPv6-001 through REQ-ICMPv6-041.
 */

#include "icmpv6.h"
#include "ndp.h"
#include "net_endian.h"
#include <string.h>

/* ── Send ─────────────────────────────────────────────────────────── */

net_err_t icmpv6_send(net_t *net, const uint8_t *src, const uint8_t *dst,
                      const uint8_t *dst_mac, uint16_t icmp_len,
                      uint8_t hop_limit) {
  uint32_t total = (uint32_t)ICMPV6_OFFSET + icmp_len;
  if (total > net->tx.capacity)
    return NET_ERR_BUF_TOO_SMALL;

  uint8_t *buf = net->tx.buf;
  uint8_t *msg = buf + ICMPV6_OFFSET;

  /* REQ-ICMPv6-001,003: checksum over the pseudo-header */
  net_write16be(msg + ICMPV6_OFF_CKSUM, 0);
  net_write16be(msg + ICMPV6_OFF_CKSUM,
                ipv6_cksum(src, dst, IPV6_NH_ICMPV6, msg, icmp_len));

  eth_build(buf, net->tx.capacity, dst_mac, net->mac, NET_ETHERTYPE_IPV6);
  ipv6_build(buf + ETH_HDR_SIZE, icmp_len, IPV6_NH_ICMPV6, src, dst,
             hop_limit);

  int r = net->mac_driver->send(net->mac_ctx, buf, (uint16_t)total);
  return (r >= 0) ? NET_OK : NET_ERR_NO_FRAME;
}

net_err_t icmpv6_send_error(net_t *net, uint8_t type, uint8_t code,
                            uint32_t param, const ipv6_hdr_t *invoking,
                            const eth_frame_t *eth) {
  /* REQ-ICMPv6-028..031 (RFC 4443 §2.4(e)) */
  if ((ipv6_is_multicast(invoking->dst) || net_mac_is_multicast(eth->dst_mac)) &&
      type != ICMPV6_PKT_TOO_BIG && !(type == ICMPV6_PARAM_PROBLEM && code == 2))
    return NET_ERR_INVALID_PARAM;
  if (ipv6_is_multicast(invoking->src) || ipv6_is_unspecified(invoking->src))
    return NET_ERR_INVALID_PARAM;
  if (invoking->next_header == IPV6_NH_ICMPV6 &&
      (invoking->payload_len == 0 || invoking->payload[ICMPV6_OFF_TYPE] < 128))
    return NET_ERR_INVALID_PARAM;
  if (net->tx.capacity < ICMPV6_OFFSET + ICMPV6_HDR_SIZE)
    return NET_ERR_BUF_TOO_SMALL;

  /* From the address the packet was sent to (it is ours: multicast was
   * refused above) */
  const uint8_t *src = ipv6_is_ours(net, invoking->dst)
                           ? invoking->dst
                           : ipv6_src_for(net, invoking->src);
  if (!src)
    return NET_ERR_INVALID_PARAM;

  /* REQ-ICMPv6-017,032: as much of the invoking packet as fits in the
   * minimum MTU — and in our TX buffer */
  uint32_t quote = (uint32_t)invoking->header_len + invoking->payload_len;
  uint32_t room = IPV6_MIN_MTU - IPV6_HDR_SIZE - ICMPV6_HDR_SIZE;
  uint32_t tx_room =
      (uint32_t)net->tx.capacity - ICMPV6_OFFSET - ICMPV6_HDR_SIZE;
  if (room > tx_room)
    room = tx_room;
  if (quote > room)
    quote = room;

  uint8_t *msg = net->tx.buf + ICMPV6_OFFSET;
  msg[ICMPV6_OFF_TYPE] = type;
  msg[ICMPV6_OFF_CODE] = code;
  net_write32be(msg + ICMPV6_OFF_BODY, param); /* REQ-ICMPv6-027 */
  memcpy(msg + ICMPV6_HDR_SIZE, invoking->header, quote);

  return icmpv6_send(net, src, invoking->src, eth->src_mac,
                     (uint16_t)(ICMPV6_HDR_SIZE + quote), net->ip6_hop_limit);
}

/* ── Echo (REQ-ICMPv6-004..009) ───────────────────────────────────── */

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
  icmpv6_send(net, src, ip->src, eth->src_mac, len, net->ip6_hop_limit);
}

/* ── Input ────────────────────────────────────────────────────────── */

void icmpv6_input(net_t *net, const ipv6_hdr_t *ip, const eth_frame_t *eth) {
  const uint8_t *msg = ip->payload;

  if (ip->payload_len < 4)
    return;
  /* REQ-ICMPv6-002 */
  if (ipv6_cksum(ip->src, ip->dst, IPV6_NH_ICMPV6, msg, ip->payload_len) !=
      0) {
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
    /* REQ-ICMPv6-034..038 */
    ndp_input(net, ip, eth);
    break;
  case ICMPV6_DEST_UNREACH:
  case ICMPV6_PKT_TOO_BIG:
  case ICMPV6_TIME_EXCEEDED:
  case ICMPV6_PARAM_PROBLEM:
    /* REQ-ICMPv6-011,018,022,025: errors — logged, as for ICMPv4 */
    NET_LOG("icmpv6_input: error type=%u code=%u", msg[ICMPV6_OFF_TYPE],
            msg[ICMPV6_OFF_CODE]);
    break;
  default:
    /* REQ-ICMPv6-039: unknown informational messages are dropped */
    break;
  }
}
