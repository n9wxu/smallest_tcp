/**
 * @file icmp.c
 * @brief ICMPv4 — Internet Control Message Protocol (RFC 792).
 *
 * Implements REQ-ICMPv4-001 through REQ-ICMPv4-041.
 * Echo reply is done in-place for zero-copy efficiency.
 */

#include "icmp.h"
#include "ipv4.h"
#include "net_cksum.h"
#include "net_endian.h"
#include <string.h>

/* ── Echo Reply (in-place) ────────────────────────────────────────── */

static void icmp_echo_reply(net_t *net, const ipv4_hdr_t *ip,
                            const eth_frame_t *eth) {
  uint8_t *icmp = ip->payload;
  uint16_t icmp_len = ip->payload_len;

  /* REQ-ICMPv4-009: don't reply to broadcast/multicast pings */
  if (ipv4_is_broadcast(net, ip->dst_ip))
    return;
  if (net_mac_is_broadcast(eth->dst_mac) && ip->dst_ip != net->ipv4_addr)
    return;

  /* REQ-ICMPv4-008: if too large for TX buffer, discard */
  uint16_t total_frame = ETH_HDR_SIZE + IPV4_HDR_SIZE + icmp_len;
  if (total_frame > net->tx.capacity)
    return;

  /* Build reply in tx buffer */
  uint8_t *buf = net->tx.buf;

  /* Ethernet header: reply to sender */
  uint8_t *ip_hdr = eth_build(buf, net->tx.capacity, eth->src_mac, net->mac,
                              NET_ETHERTYPE_IPV4);
  if (!ip_hdr)
    return;

  /* Copy ICMP data (identifier, sequence, payload) */
  uint8_t *icmp_out = ip_hdr + IPV4_HDR_SIZE;
  memcpy(icmp_out, icmp, icmp_len);

  /* REQ-ICMPv4-001: change Type 8 → 0 */
  icmp_out[ICMP_OFF_TYPE] = ICMP_TYPE_ECHO_REPLY;
  /* REQ-ICMPv4-002: identifier and sequence number unchanged (already copied)
   */

  /* REQ-ICMPv4-006: recompute ICMP checksum */
  net_write16be(icmp_out + ICMP_OFF_CKSUM, 0x0000);
  uint16_t cksum = net_cksum(icmp_out, icmp_len);
  net_write16be(icmp_out + ICMP_OFF_CKSUM, cksum);

  /* REQ-ICMPv4-004,005: build IPv4 header (src=us, dst=original sender) */
  ipv4_build(ip_hdr, icmp_len, IPV4_PROTO_ICMP, net->ipv4_addr, ip->src_ip);

  /* Send */
  net->mac_driver->send(net->mac_ctx, buf, total_frame);
}

/* ── Input processing ─────────────────────────────────────────────── */

void icmp_input(net_t *net, const ipv4_hdr_t *ip, const eth_frame_t *eth) {
  uint8_t *icmp = ip->payload;
  uint16_t icmp_len = ip->payload_len;

  /* Need at least ICMP header */
  if (icmp_len < ICMP_HDR_SIZE)
    return;

  /* REQ-ICMPv4-031: verify ICMP checksum */
  if (!net_cksum_verify(icmp, icmp_len)) {
    NET_LOG("icmp_input: bad checksum");
    return;
  }

  uint8_t type = icmp[ICMP_OFF_TYPE];

  switch (type) {
  case ICMP_TYPE_ECHO_REQUEST:
    NET_LOG("icmp_input: echo request (len=%u)", icmp_len);
    icmp_echo_reply(net, ip, eth);
    break;
  case ICMP_TYPE_SOURCE_QUENCH:
    /* REQ-ICMPv4-028: silently discard */
    break;
  case ICMP_TYPE_DEST_UNREACH:
  case ICMP_TYPE_TIME_EXCEEDED:
  case ICMP_TYPE_REDIRECT:
  case ICMP_TYPE_PARAM_PROBLEM:
    /* REQ-ICMPv4-011,024,019,029: error messages - log only for now */
    NET_LOG("icmp_input: error type=%u code=%u", type, icmp[ICMP_OFF_CODE]);
    break;
  default:
    /* REQ-ICMPv4-040: silently discard unknown types */
    break;
  }
}

/* ── Send Destination Unreachable ─────────────────────────────────── */

net_err_t icmp_send_dest_unreach(net_t *net, uint8_t code,
                                 const uint8_t *orig_ip_hdr,
                                 uint16_t orig_ip_len,
                                 const uint8_t *orig_payload, uint32_t dst_ip,
                                 const uint8_t *dst_mac) {
  /* REQ-ICMPv4-038: include original IP header + first 8 bytes of payload */
  uint16_t copy_len = orig_ip_len + 8;
  uint16_t icmp_len = ICMP_HDR_SIZE + copy_len;
  uint16_t total = ETH_HDR_SIZE + IPV4_HDR_SIZE + icmp_len;

  if (total > net->tx.capacity)
    return NET_ERR_BUF_TOO_SMALL;

  uint8_t *buf = net->tx.buf;
  uint8_t *ip_hdr =
      eth_build(buf, net->tx.capacity, dst_mac, net->mac, NET_ETHERTYPE_IPV4);
  if (!ip_hdr)
    return NET_ERR_BUF_TOO_SMALL;

  uint8_t *icmp_out = ip_hdr + IPV4_HDR_SIZE;

  /* Build ICMP Destination Unreachable */
  icmp_out[ICMP_OFF_TYPE] = ICMP_TYPE_DEST_UNREACH;
  icmp_out[ICMP_OFF_CODE] = code;
  net_write16be(icmp_out + ICMP_OFF_CKSUM, 0x0000);
  /* Unused/Next-Hop MTU field (bytes 4-7) = 0 */
  net_write32be(icmp_out + 4, 0);

  /* Copy original IP header + 8 bytes of original payload */
  memcpy(icmp_out + ICMP_HDR_SIZE, orig_ip_hdr, orig_ip_len);
  if (orig_payload) {
    memcpy(icmp_out + ICMP_HDR_SIZE + orig_ip_len, orig_payload, 8);
  }

  /* Compute ICMP checksum */
  uint16_t cksum = net_cksum(icmp_out, icmp_len);
  net_write16be(icmp_out + ICMP_OFF_CKSUM, cksum);

  /* Build IPv4 header */
  ipv4_build(ip_hdr, icmp_len, IPV4_PROTO_ICMP, net->ipv4_addr, dst_ip);

  int r = net->mac_driver->send(net->mac_ctx, buf, total);
  return (r >= 0) ? NET_OK : NET_ERR_NO_FRAME;
}
