/**
 * @file udp.c
 * @brief UDP — User Datagram Protocol (RFC 768).
 *
 * Implements REQ-UDP-001 through REQ-UDP-039.
 * Static port→callback dispatch. Zero-copy payload delivery.
 */

#include "udp.h"
#include "icmp.h"
#include "ipv4.h"
#include "net_cksum.h"
#include "net_endian.h"
#include <string.h>

/* ── Default empty port table ─────────────────────────────────────── */

udp_port_table_t udp_ports = {(void *)0, 0};

/* ── Checksum ─────────────────────────────────────────────────────── */

uint16_t udp_checksum(uint32_t src_ip, uint32_t dst_ip, const uint8_t *udp_hdr,
                      uint16_t udp_len) {
  net_cksum_t c;
  net_cksum_init(&c);

  /* REQ-UDP-014: IPv4 pseudo-header */
  net_cksum_add_u32(&c, src_ip);
  net_cksum_add_u32(&c, dst_ip);
  net_cksum_add_u16(&c, 0x0011); /* zero + protocol 17 */
  net_cksum_add_u16(&c, udp_len);

  /* UDP header + data */
  net_cksum_add(&c, udp_hdr, udp_len);

  uint16_t result = net_cksum_finalize(&c);
  /* REQ-UDP-009: if computed checksum is 0, transmit as 0xFFFF */
  if (result == 0x0000)
    result = 0xFFFF;
  return result;
}

/* ── Input processing ─────────────────────────────────────────────── */

void udp_input(net_t *net, const ipv4_hdr_t *ip, const eth_frame_t *eth) {
  uint8_t *udp = ip->payload;
  uint16_t avail = ip->payload_len;

  /* REQ-UDP-001: parse at IP payload offset */
  if (avail < UDP_HDR_SIZE)
    return;

  /* REQ-UDP-002: length >= 8 */
  uint16_t udp_len = net_read16be(udp + UDP_OFF_LEN);
  if (udp_len < UDP_HDR_SIZE)
    return;

  /* REQ-UDP-003: length <= IP payload length */
  if (udp_len > avail)
    return;

  /* REQ-UDP-006,007,008: verify checksum if non-zero */
  uint16_t rx_cksum = net_read16be(udp + UDP_OFF_CKSUM);
  if (rx_cksum != 0) {
    /* Verify over pseudo-header + UDP */
    net_cksum_t c;
    net_cksum_init(&c);
    net_cksum_add_u32(&c, ip->src_ip);
    net_cksum_add_u32(&c, ip->dst_ip);
    net_cksum_add_u16(&c, 0x0011);
    net_cksum_add_u16(&c, udp_len);
    net_cksum_add(&c, udp, udp_len);
    uint16_t check = net_cksum_finalize(&c);
    if (check != 0x0000 && check != 0xFFFF) {
      NET_LOG("udp_input: bad checksum");
      return;
    }
  }

  uint16_t src_port = net_read16be(udp + UDP_OFF_SPORT);
  uint16_t dst_port = net_read16be(udp + UDP_OFF_DPORT);
  /* REQ-UDP-004: data length from UDP Length, not IP */
  uint16_t data_len = udp_len - UDP_HDR_SIZE;
  uint8_t *data = udp + UDP_HDR_SIZE;

  NET_LOG("udp_input: %u.%u.%u.%u:%u -> port %u (%u bytes)",
          (unsigned)((ip->src_ip >> 24) & 0xFF),
          (unsigned)((ip->src_ip >> 16) & 0xFF),
          (unsigned)((ip->src_ip >> 8) & 0xFF), (unsigned)(ip->src_ip & 0xFF),
          src_port, dst_port, data_len);

  /* REQ-UDP-016: dispatch by destination port */
  uint8_t i;
  for (i = 0; i < udp_ports.count; i++) {
    if (udp_ports.entries[i].port == dst_port) {
      /* REQ-UDP-020,037: handler gets src info + zero-copy payload */
      udp_ports.entries[i].handler(net, ip->src_ip, src_port, eth->src_mac,
                                   data, data_len);
      return;
    }
  }

  /* REQ-UDP-017,031: ICMP Port Unreachable — but not for broadcast/multicast */
  if (!ipv4_is_broadcast(net, ip->dst_ip) &&
      !net_mac_is_broadcast(eth->dst_mac)) {
    NET_LOG("udp_input: no handler for port %u, sending ICMP", dst_port);
    icmp_send_dest_unreach(net, ICMP_CODE_PORT_UNREACH, ip->header,
                           ip->header_len, ip->payload, ip->src_ip,
                           eth->src_mac);
  }
}

/* ── Send ─────────────────────────────────────────────────────────── */

net_err_t udp_send(net_t *net, uint32_t dst_ip, const uint8_t *dst_mac,
                   uint16_t src_port, uint16_t dst_port, const uint8_t *data,
                   uint16_t data_len) {
  /* REQ-UDP-032,033: check size limits */
  uint16_t udp_len = UDP_HDR_SIZE + data_len;
  uint16_t total = ETH_HDR_SIZE + IPV4_HDR_SIZE + udp_len;
  if (total > net->tx.capacity)
    return NET_ERR_BUF_TOO_SMALL;

  uint8_t *buf = net->tx.buf;

  /* Build Ethernet header */
  uint8_t *ip_hdr =
      eth_build(buf, net->tx.capacity, dst_mac, net->mac, NET_ETHERTYPE_IPV4);
  if (!ip_hdr)
    return NET_ERR_BUF_TOO_SMALL;

  uint8_t *udp_hdr = ip_hdr + IPV4_HDR_SIZE;

  /* REQ-UDP-021,022: build UDP header */
  net_write16be(udp_hdr + UDP_OFF_SPORT, src_port);
  net_write16be(udp_hdr + UDP_OFF_DPORT, dst_port);
  net_write16be(udp_hdr + UDP_OFF_LEN, udp_len);
  net_write16be(udp_hdr + UDP_OFF_CKSUM, 0x0000);

  /* Copy payload */
  if (data && data_len > 0) {
    memcpy(udp_hdr + UDP_HDR_SIZE, data, data_len);
  }

  /* REQ-UDP-009: compute UDP checksum with pseudo-header */
  uint16_t cksum = udp_checksum(net->ipv4_addr, dst_ip, udp_hdr, udp_len);
  net_write16be(udp_hdr + UDP_OFF_CKSUM, cksum);

  /* REQ-UDP-023: pass to IP layer */
  ipv4_build(ip_hdr, udp_len, IPV4_PROTO_UDP, net->ipv4_addr, dst_ip);

  /* Send */
  int r = net->mac_driver->send(net->mac_ctx, buf, total);
  return (r >= 0) ? NET_OK : NET_ERR_NO_FRAME;
}
