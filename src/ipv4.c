/**
 * @file ipv4.c
 * @brief IPv4 — Internet Protocol version 4 (RFC 791).
 *
 * Implements REQ-IPv4-001 through REQ-IPv4-057.
 * No fragmentation/reassembly. Always sets DF.
 */

#include "ipv4.h"
#include "net_cksum.h"
#include "net_endian.h"
#include <string.h>

#if NET_USE_IPV4
#include "icmp.h"
#endif

#if NET_USE_UDP
#include "udp.h"
#endif

#if NET_USE_TCP
#include "tcp.h"
#endif

/* ── Parse ────────────────────────────────────────────────────────── */

net_err_t ipv4_parse(uint8_t *data, uint16_t data_len, ipv4_hdr_t *out) {
  /* Need at least 20 bytes for minimum header */
  if (data_len < IPV4_HDR_SIZE)
    return NET_ERR_INVALID_PARAM;

  uint8_t ver_ihl = data[IPV4_OFF_VER_IHL];
  uint8_t version = (ver_ihl >> 4) & 0x0F;
  uint8_t ihl = ver_ihl & 0x0F;

  /* REQ-IPv4-001: version must be 4 */
  if (version != 4)
    return NET_ERR_INVALID_PARAM;

  /* REQ-IPv4-002: IHL >= 5 */
  if (ihl < 5)
    return NET_ERR_INVALID_PARAM;

  uint16_t header_len = (uint16_t)ihl * 4;
  uint16_t total_len = net_read16be(data + IPV4_OFF_TOTLEN);

  /* REQ-IPv4-003: total length >= header length */
  if (total_len < header_len)
    return NET_ERR_INVALID_PARAM;

  /* REQ-IPv4-004: total length <= available data */
  if (total_len > data_len)
    return NET_ERR_INVALID_PARAM;

  /* REQ-IPv4-005: verify header checksum */
  if (!net_cksum_verify(data, header_len))
    return NET_ERR_INVALID_PARAM;

  /* REQ-IPv4-024: reject fragments */
  uint16_t flags_frag = net_read16be(data + IPV4_OFF_FLAGS_FRAG);
  if ((flags_frag & IPV4_FLAG_MF) || (flags_frag & IPV4_FRAG_MASK)) {
    return NET_ERR_INVALID_PARAM;
  }

  out->ihl = ihl;
  out->header_len = header_len;
  out->total_len = total_len;
  out->flags_frag = flags_frag;
  out->ttl = data[IPV4_OFF_TTL];
  out->protocol = data[IPV4_OFF_PROTO];
  out->src_ip = net_read32be(data + IPV4_OFF_SRC);
  out->dst_ip = net_read32be(data + IPV4_OFF_DST);
  out->header = data;
  /* REQ-IPv4-027: payload starts at IHL*4, not fixed offset 20 */
  out->payload = data + header_len;
  /* REQ-IPv4-007: use total_len to determine payload length */
  out->payload_len = total_len - header_len;

  return NET_OK;
}

/* ── Build ────────────────────────────────────────────────────────── */

static uint16_t ipv4_id_counter = 0;

void ipv4_build(uint8_t *buf, uint16_t payload_len, uint8_t protocol,
                uint32_t src_ip, uint32_t dst_ip) {
  /* REQ-IPv4-030: Version=4, REQ-IPv4-031: IHL=5 */
  buf[IPV4_OFF_VER_IHL] = 0x45;
  /* REQ-IPv4-040: TOS=0 */
  buf[IPV4_OFF_TOS] = 0x00;
  /* REQ-IPv4-032: Total Length = 20 + payload */
  net_write16be(buf + IPV4_OFF_TOTLEN, (uint16_t)(IPV4_HDR_SIZE + payload_len));
  /* REQ-IPv4-033: ID (any value ok with DF=1 per RFC 6864) */
  net_write16be(buf + IPV4_OFF_ID, ipv4_id_counter++);
  /* REQ-IPv4-034: DF=1, MF=0, Fragment Offset=0 */
  net_write16be(buf + IPV4_OFF_FLAGS_FRAG, IPV4_FLAG_DF);
  /* REQ-IPv4-035,045: TTL=64 */
  buf[IPV4_OFF_TTL] = NET_DEFAULT_TTL;
  /* REQ-IPv4-036: Protocol */
  buf[IPV4_OFF_PROTO] = protocol;
  /* Checksum placeholder — compute after all fields set */
  net_write16be(buf + IPV4_OFF_CKSUM, 0x0000);
  /* REQ-IPv4-038,039: Source and Destination */
  net_write32be(buf + IPV4_OFF_SRC, src_ip);
  net_write32be(buf + IPV4_OFF_DST, dst_ip);
  /* REQ-IPv4-037: compute header checksum */
  uint16_t cksum = net_cksum(buf, IPV4_HDR_SIZE);
  net_write16be(buf + IPV4_OFF_CKSUM, cksum);
}

/* ── Send ─────────────────────────────────────────────────────────── */

net_err_t ipv4_send(net_t *net, uint32_t dst_ip, const uint8_t *dst_mac,
                    uint8_t protocol, const uint8_t *payload,
                    uint16_t payload_len) {
  uint16_t total = ETH_HDR_SIZE + IPV4_HDR_SIZE + payload_len;
  if (total > net->tx.capacity)
    return NET_ERR_BUF_TOO_SMALL;

  uint8_t *buf = net->tx.buf;

  /* Build Ethernet header */
  uint8_t *ip_hdr =
      eth_build(buf, net->tx.capacity, dst_mac, net->mac, NET_ETHERTYPE_IPV4);
  if (!ip_hdr)
    return NET_ERR_BUF_TOO_SMALL;

  /* Copy payload if provided (may already be in place) */
  if (payload) {
    memcpy(ip_hdr + IPV4_HDR_SIZE, payload, payload_len);
  }

  /* Build IPv4 header */
  ipv4_build(ip_hdr, payload_len, protocol, net->ipv4_addr, dst_ip);

  /* Send */
  int r = net->mac_driver->send(net->mac_ctx, buf, total);
  return (r >= 0) ? NET_OK : NET_ERR_NO_FRAME;
}

/* ── Input processing ─────────────────────────────────────────────── */

void ipv4_input(net_t *net, const eth_frame_t *eth) {
  ipv4_hdr_t ip;

  if (ipv4_parse(eth->payload, eth->payload_len, &ip) != NET_OK) {
    NET_LOG("ipv4_input: parse failed");
    return;
  }

  /* REQ-IPv4-013: discard broadcast source */
  if (ip.src_ip == 0xFFFFFFFFu)
    return;
  /* REQ-IPv4-014: discard our own source */
  if (ip.src_ip == net->ipv4_addr && net->ipv4_addr != 0)
    return;
  /* REQ-IPv4-015: discard loopback source */
  if ((ip.src_ip >> 24) == 127)
    return;

  /* REQ-IPv4-008..012: destination address validation */
  int for_us = 0;
  if (ip.dst_ip == net->ipv4_addr)
    for_us = 1; /* unicast */
  if (ip.dst_ip == 0xFFFFFFFFu)
    for_us = 1; /* limited bcast */
  if (ipv4_is_broadcast(net, ip.dst_ip))
    for_us = 1; /* subnet bcast */
  if (ip.dst_ip == 0 && net->ipv4_addr == 0)
    for_us = 1; /* DHCP bootstrap */

  if (!for_us) {
    /* REQ-IPv4-011,043: not for us and we don't forward */
    return;
  }

  /* Dispatch by protocol */
  switch (ip.protocol) {
#if NET_USE_IPV4
  case IPV4_PROTO_ICMP:
    /* REQ-IPv4-017 */
    icmp_input(net, &ip, eth);
    break;
#endif
#if NET_USE_UDP
  case IPV4_PROTO_UDP:
    /* REQ-IPv4-019 */
    udp_input(net, &ip, eth);
    break;
#endif
#if NET_USE_TCP
  case IPV4_PROTO_TCP:
    /* REQ-IPv4-018 */
    tcp_input(net, &ip, eth);
    break;
#endif
  default:
    /* REQ-IPv4-020,021: unrecognized protocol */
    NET_LOG("ipv4_input: unknown proto %u", ip.protocol);
    break;
  }
}
