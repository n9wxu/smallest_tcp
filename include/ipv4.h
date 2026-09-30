/**
 * @file ipv4.h
 * @brief IPv4 (RFC 791): headers parsed and built in place, dispatch by
 *        protocol, multicast membership (RFC 1112).  No fragmentation:
 *        every datagram is sent with DF set and fragments are dropped.
 */

#ifndef IPV4_H
#define IPV4_H

#include "eth.h"
#include "net.h"
#include "net_cksum.h"
#include <stdint.h>

#if !NET_USE_IPV4
#error "IPv4 is not compiled in (NET_USE_IPV4 is 0)"
#endif

#define IPV4_OFF_VER_IHL 0
#define IPV4_OFF_TOS 1
#define IPV4_OFF_TOTLEN 2
#define IPV4_OFF_ID 4
#define IPV4_OFF_FLAGS_FRAG 6
#define IPV4_OFF_TTL 8
#define IPV4_OFF_PROTO 9
#define IPV4_OFF_CKSUM 10
#define IPV4_OFF_SRC 12
#define IPV4_OFF_DST 16
#define IPV4_HDR_SIZE 20 /**< Without options */

#define IPV4_PROTO_ICMP 1
#define IPV4_PROTO_IGMP 2
#define IPV4_PROTO_TCP 6
#define IPV4_PROTO_UDP 17

#define IPV4_FLAG_DF 0x4000
#define IPV4_FLAG_MF 0x2000
#define IPV4_FRAG_MASK 0x1FFF

#define IPV4_BROADCAST 0xFFFFFFFFu

#ifndef NET_DEFAULT_TTL
#define NET_DEFAULT_TTL 64
#endif

/** A received datagram; the pointers point into the frame. */
typedef struct {
  uint8_t protocol;
  uint8_t ttl;
  uint16_t total_len;
  uint32_t src_ip; /**< Host byte order */
  uint32_t dst_ip; /**< Host byte order */
  uint8_t *header;
  uint16_t header_len;
  uint8_t *payload;
  uint16_t payload_len;
} ipv4_hdr_t;

/**
 * Parse and check an IPv4 header: version, length, header checksum.
 * @return NET_OK, or NET_ERR_INVALID_PARAM (fragments included).
 */
net_err_t ipv4_parse(uint8_t *data, uint16_t data_len, ipv4_hdr_t *out);

/** Deliver a datagram addressed to us to ICMP, UDP or TCP. */
void ipv4_input(net_t *net, const eth_frame_t *eth);

/** Write a 20-byte header (DF set, ID 0: every datagram is atomic,
 *  RFC 6864 §4.1) with the header checksum. */
void ipv4_build_ttl(uint8_t *buf, uint16_t payload_len, uint8_t protocol,
                    uint32_t src_ip, uint32_t dst_ip, uint8_t ttl);

static inline void ipv4_build(uint8_t *buf, uint16_t payload_len,
                              uint8_t protocol, uint32_t src_ip,
                              uint32_t dst_ip) {
  ipv4_build_ttl(buf, payload_len, protocol, src_ip, dst_ip, NET_DEFAULT_TTL);
}

#define IPV4_ROUTER_ALERT_HDR_SIZE 24

/** Write a 24-byte header carrying the Router Alert option (RFC 2113),
 *  TTL 1 — for link-local signalling such as IGMP. */
void ipv4_build_router_alert(uint8_t *buf, uint16_t payload_len,
                             uint8_t protocol, uint32_t src_ip,
                             uint32_t dst_ip);

/**
 * Upper-layer checksum (TCP, UDP) of @p data over the pseudo-header.
 * With the checksum field zero it is the value to store; over a received
 * segment it is 0 when the checksum is valid.
 */
uint16_t ipv4_cksum(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol,
                    const uint8_t *data, uint16_t len);

static inline int ipv4_is_local(const net_t *net, uint32_t ip) {
  return (ip & net->subnet_mask) == (net->ipv4_addr & net->subnet_mask);
}

/** Limited (255.255.255.255) or our own subnet's directed broadcast.  A
 *  /31 or /32 has none (RFC 3021). */
static inline int ipv4_is_broadcast(const net_t *net, uint32_t ip) {
  uint32_t host = ~net->subnet_mask;
  return ip == IPV4_BROADCAST ||
         (host > 1u && (ip & host) == host && ipv4_is_local(net, ip));
}

/* Multicast (RFC 1112) */

/** 224.0.0.0/4 */
static inline int ipv4_is_multicast(uint32_t ip) { return (ip >> 28) == 0xE; }

/**
 * A received datagram's destination is multicast.  Only joined groups get
 * past ipv4_input(), so without multicast support this is constant 0 and
 * the checks using it compile away.
 */
static inline int ipv4_rx_is_multicast(uint32_t dst_ip) {
#if NET_MAX_MCAST_GROUPS > 0
  return ipv4_is_multicast(dst_ip);
#else
  (void)dst_ip;
  return 0;
#endif
}

/** Ethernet MAC of a group: 01:00:5E + the low 23 bits. */
static inline void ipv4_mcast_mac(uint32_t group, uint8_t mac[6]) {
  mac[0] = 0x01;
  mac[1] = 0x00;
  mac[2] = 0x5E;
  mac[3] = (uint8_t)((group >> 16) & 0x7F);
  mac[4] = (uint8_t)((group >> 8) & 0xFF);
  mac[5] = (uint8_t)(group & 0xFF);
}

/**
 * Accept frames and datagrams for @p group.  Sends nothing (igmp_join()
 * does); a MAC with a hardware multicast filter must also pass
 * ipv4_mcast_mac(group).
 * @return NET_OK (also if already joined), NET_ERR_INVALID_PARAM if not
 *         multicast, NET_ERR_BUF_TOO_SMALL if every slot is in use.
 */
net_err_t ipv4_mcast_join(net_t *net, uint32_t group);

void ipv4_mcast_leave(net_t *net, uint32_t group);

int ipv4_mcast_is_member(const net_t *net, uint32_t group);

/** @p mac is the Ethernet address of a joined group. */
int ipv4_mcast_mac_accepted(const net_t *net, const uint8_t *mac);

#endif /* IPV4_H */
