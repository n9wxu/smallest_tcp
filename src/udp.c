/**
 * @file udp.c
 * @brief UDP (RFC 768).  REQ-UDP-001..039, REQ-IPv6-045.
 */

#include "udp.h"
#include "net_endian.h"
#include <string.h>

#if NET_USE_IPV4
#include "icmp.h"
#include "ipv4.h"
#endif
#if NET_USE_IPV6
#include "icmpv6.h"
#endif

/* A computed checksum of 0 is sent as 0xFFFF: 0 means "none" (REQ-UDP-009) */
static uint16_t udp_wire_cksum(uint16_t cksum) {
  return cksum ? cksum : 0xFFFFu;
}

/* REQ-UDP-001..004: the datagram's length, or 0 if it is malformed */
static uint16_t udp_length(const uint8_t *udp, uint16_t ip_payload_len) {
  uint16_t len;
  if (ip_payload_len < UDP_HDR_SIZE)
    return 0;
  len = net_read16be(udp + UDP_OFF_LEN);
  return (len >= UDP_HDR_SIZE && len <= ip_payload_len) ? len : 0;
}

static void write_header(uint8_t *udp, uint16_t src_port, uint16_t dst_port,
                         uint16_t udp_len) {
  net_write16be(udp + UDP_OFF_SPORT, src_port);
  net_write16be(udp + UDP_OFF_DPORT, dst_port);
  net_write16be(udp + UDP_OFF_LEN, udp_len);
  net_write16be(udp + UDP_OFF_CKSUM, 0);
}

/* A payload of @p data_len at @p offset fits the TX frame buffer and one
 * Ethernet frame: never fragmented, DF being set */
static int fits_frame(const net_t *net, uint16_t offset, uint16_t data_len) {
  uint32_t frame = (uint32_t)offset + data_len;
  return frame <= net->tx.capacity && frame <= ETH_HDR_SIZE + ETH_MTU;
}

#if NET_USE_IPV4

/* REQ-UDP-006..008, 016, 017, 020, 031, 037 */
void udp_input(net_t *net, const ipv4_hdr_t *ip, const eth_frame_t *eth) {
  const uint8_t *udp = ip->payload;
  uint16_t udp_len = udp_length(udp, ip->payload_len);
  uint16_t dst_port;
  uint8_t i;

  if (udp_len == 0)
    return;
  if (net_read16be(udp + UDP_OFF_CKSUM) != 0 &&
      ipv4_cksum(ip->src_ip, ip->dst_ip, IPV4_PROTO_UDP, udp, udp_len) != 0)
    return;

  dst_port = net_read16be(udp + UDP_OFF_DPORT);
  for (i = 0; i < net->udp_port_count; i++) {
    if (net->udp_ports[i].port == dst_port) {
      net->udp_ports[i].handler(
          net, ip->src_ip, net_read16be(udp + UDP_OFF_SPORT), eth->src_mac,
          udp + UDP_HDR_SIZE, (uint16_t)(udp_len - UDP_HDR_SIZE));
      return;
    }
  }
  icmp_send_dest_unreach(net, ICMP_CODE_PORT_UNREACH, ip, eth);
}

/* REQ-UDP-032, 033 */
net_err_t udp_send(net_t *net, uint32_t dst_ip, const uint8_t *dst_mac,
                   uint16_t src_port, uint16_t dst_port, const uint8_t *data,
                   uint16_t data_len) {
  if (!fits_frame(net, UDP_PAYLOAD_OFFSET, data_len))
    return NET_ERR_BUF_TOO_SMALL;
  if (data_len > 0)
    memcpy(net->tx.buf + UDP_PAYLOAD_OFFSET, data, data_len);
  return udp_send_inplace(net, dst_ip, dst_mac, src_port, dst_port, data_len,
                          NET_DEFAULT_TTL);
}

net_err_t udp_send_inplace(net_t *net, uint32_t dst_ip, const uint8_t *dst_mac,
                           uint16_t src_port, uint16_t dst_port,
                           uint16_t data_len, uint8_t ttl) {
  return udp_send_inplace_from(net, net->ipv4_addr, dst_ip, dst_mac, src_port,
                               dst_port, data_len, ttl);
}

uint32_t udp_rx_dst_ip(const net_t *net) {
  (void)net;
  return 0; /* not implemented yet */
}

void udp_set_error_handler(net_t *net, udp_error_handler_t handler) {
  (void)net;
  (void)handler; /* not implemented yet */
}

/* REQ-IPv4-070..072: never to 0.0.0.0, never to or from 127/8, and the
 * link-layer broadcast only for an IP broadcast or multicast */
static int addresses_valid(const net_t *net, uint32_t src_ip, uint32_t dst_ip,
                           const uint8_t *dst_mac) {
  return dst_ip != 0 && (src_ip >> 24) != 127 && (dst_ip >> 24) != 127 &&
         (!net_mac_is_broadcast(dst_mac) || ipv4_is_broadcast(net, dst_ip) ||
          ipv4_is_multicast(dst_ip));
}

/* REQ-UDP-009, 021..023, 044 */
net_err_t udp_send_inplace_opts(net_t *net, uint32_t dst_ip,
                                const uint8_t *dst_mac, uint16_t src_port,
                                uint16_t dst_port, uint16_t data_len,
                                const udp_tx_opts_t *opts) {
  uint32_t src_ip = opts->src_ip;
  uint8_t ttl = opts->ttl;
  uint8_t *ip = net->tx.buf + ETH_HDR_SIZE;
  uint8_t *udp = ip + IPV4_HDR_SIZE;
  uint16_t udp_len = (uint16_t)(UDP_HDR_SIZE + data_len);

  if (!fits_frame(net, UDP_PAYLOAD_OFFSET, data_len))
    return NET_ERR_BUF_TOO_SMALL;
  if (ttl == 0 || /* RFC 1122 §3.2.1.7 */
      !addresses_valid(net, src_ip, dst_ip, dst_mac))
    return NET_ERR_INVALID_PARAM;
  write_header(udp, src_port, dst_port, udp_len);
  net_write16be(
      udp + UDP_OFF_CKSUM,
      udp_wire_cksum(ipv4_cksum(src_ip, dst_ip, IPV4_PROTO_UDP, udp, udp_len)));
  eth_build(net->tx.buf, net->tx.capacity, dst_mac, net->mac,
            NET_ETHERTYPE_IPV4);
  ipv4_build_tos(ip, udp_len, IPV4_PROTO_UDP, src_ip, dst_ip, ttl, opts->tos);
  return net_transmit(net, (uint16_t)(UDP_PAYLOAD_OFFSET + data_len));
}

net_err_t udp_send_inplace_from(net_t *net, uint32_t src_ip, uint32_t dst_ip,
                                const uint8_t *dst_mac, uint16_t src_port,
                                uint16_t dst_port, uint16_t data_len,
                                uint8_t ttl) {
  udp_tx_opts_t opts;
  opts.src_ip = src_ip;
  opts.ttl = ttl;
  opts.tos = 0;
  return udp_send_inplace_opts(net, dst_ip, dst_mac, src_port, dst_port,
                               data_len, &opts);
}

#endif

#if NET_USE_IPV6

/* REQ-IPv6-045, REQ-ICMPv6-016 */
void udp6_input(net_t *net, const ipv6_hdr_t *ip, const eth_frame_t *eth) {
  const uint8_t *udp = ip->payload;
  uint16_t udp_len = udp_length(udp, ip->payload_len);
  uint16_t dst_port;
  uint8_t i;

  if (udp_len == 0 || net_read16be(udp + UDP_OFF_CKSUM) == 0 ||
      ipv6_cksum(ip->src, ip->dst, IPV6_NH_UDP, udp, udp_len) != 0)
    return;

  dst_port = net_read16be(udp + UDP_OFF_DPORT);
  for (i = 0; i < net->udp6_port_count; i++) {
    if (net->udp6_ports[i].port == dst_port) {
      net->udp6_ports[i].handler(
          net, ip->src, net_read16be(udp + UDP_OFF_SPORT), eth->src_mac,
          udp + UDP_HDR_SIZE, (uint16_t)(udp_len - UDP_HDR_SIZE));
      return;
    }
  }
  icmpv6_send_error(net, ICMPV6_DEST_UNREACH, ICMPV6_CODE_PORT_UNREACH, 0, ip,
                    eth);
}

net_err_t udp6_send(net_t *net, const uint8_t *dst_ip, const uint8_t *dst_mac,
                    uint16_t src_port, uint16_t dst_port, const uint8_t *data,
                    uint16_t data_len) {
  if (!fits_frame(net, UDP6_PAYLOAD_OFFSET, data_len))
    return NET_ERR_BUF_TOO_SMALL;
  if (data_len > 0)
    memcpy(net->tx.buf + UDP6_PAYLOAD_OFFSET, data, data_len);
  return udp6_send_inplace(net, dst_ip, dst_mac, src_port, dst_port, data_len,
                           net->ip6.hop_limit);
}

net_err_t udp6_send_inplace(net_t *net, const uint8_t *dst_ip,
                            const uint8_t *dst_mac, uint16_t src_port,
                            uint16_t dst_port, uint16_t data_len,
                            uint8_t hop_limit) {
  uint8_t *udp = net->tx.buf + ETH_HDR_SIZE + IPV6_HDR_SIZE;
  uint16_t udp_len = (uint16_t)(UDP_HDR_SIZE + data_len);
  const uint8_t *src = ipv6_src_for(net, dst_ip);

  if (!fits_frame(net, UDP6_PAYLOAD_OFFSET, data_len))
    return NET_ERR_BUF_TOO_SMALL;
  if (!src)
    return NET_ERR_INVALID_PARAM;
  write_header(udp, src_port, dst_port, udp_len);
  net_write16be(
      udp + UDP_OFF_CKSUM,
      udp_wire_cksum(ipv6_cksum(src, dst_ip, IPV6_NH_UDP, udp, udp_len)));
  eth_build(net->tx.buf, net->tx.capacity, dst_mac, net->mac,
            NET_ETHERTYPE_IPV6);
  ipv6_build(net->tx.buf + ETH_HDR_SIZE, udp_len, IPV6_NH_UDP, src, dst_ip,
             hop_limit);
  return net_transmit(net, (uint16_t)(UDP6_PAYLOAD_OFFSET + data_len));
}
#endif
