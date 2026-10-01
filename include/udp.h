/**
 * @file udp.h
 * @brief UDP (RFC 768) over IPv4 and IPv6: datagrams dispatched to the
 *        application's port handlers; sending, copied or in place.
 */

#ifndef UDP_H
#define UDP_H

#include "eth.h"
#include "net.h"
#include <stdint.h>

#if NET_USE_IPV4
#include "ipv4.h"
#endif
#if NET_USE_IPV6
#include "ipv6.h"
#endif

#define UDP_OFF_SPORT 0
#define UDP_OFF_DPORT 2
#define UDP_OFF_LEN 4
#define UDP_OFF_CKSUM 6
#define UDP_HDR_SIZE 8

#if NET_USE_IPV4
/* UDP over IPv4 */

/**
 * A datagram for a bound port.  @p payload points into the received frame
 * and is valid during the call.  Addresses and ports are host byte order.
 */
typedef void (*udp_handler_t)(net_t *net, uint32_t src_ip, uint16_t src_port,
                              const uint8_t *src_mac, const uint8_t *payload,
                              uint16_t payload_len);

typedef struct udp_port_entry_s {
  uint16_t port;
  udp_handler_t handler;
} udp_port_entry_t;

/** Bind the application's port table; a port absent from it is closed
 *  (ICMP Port Unreachable). */
static inline void udp_set_ports(net_t *net, const udp_port_entry_t *ports,
                                 uint8_t count) {
  net->udp_ports = ports;
  net->udp_port_count = count;
}

/** Check a datagram (length, checksum) and hand it to its port's handler. */
void udp_input(net_t *net, const ipv4_hdr_t *ip, const eth_frame_t *eth);

/** Where the payload goes in a frame built by udp_send_inplace(). */
#define UDP_PAYLOAD_OFFSET (ETH_HDR_SIZE + IPV4_HDR_SIZE + UDP_HDR_SIZE)

/** What a send may set besides addresses and ports */
typedef struct {
  uint32_t src_ip; /**< 0.0.0.0 only while DHCP acquires an address */
  uint8_t ttl;     /**< Not 0 */
  uint8_t tos;     /**< The IP TOS / DSCP byte (RFC 1122 §3.2.1.6) */
} udp_tx_opts_t;

/** As udp_send_inplace_from(), with @p opts. */
net_err_t udp_send_inplace_opts(net_t *net, uint32_t dst_ip,
                                const uint8_t *dst_mac, uint16_t src_port,
                                uint16_t dst_port, uint16_t data_len,
                                const udp_tx_opts_t *opts);

/** In a handler: the destination address of the datagram being handled —
 *  ours, a broadcast or a group (RFC 1122 §4.1.3.5). */
uint32_t udp_rx_dst_ip(const net_t *net);

/**
 * Told of an ICMP error about a datagram sent from @p local_port to
 * @p dst_ip : @p dst_port (RFC 1122 §4.1.3.3): its type and code, and for
 * Fragmentation Needed the next-hop MTU (else 0).
 */
typedef void (*udp_error_handler_t)(net_t *net, uint16_t local_port,
                                    uint32_t dst_ip, uint16_t dst_port,
                                    uint8_t icmp_type, uint8_t icmp_code,
                                    uint16_t mtu);

/** Where ICMP errors about UDP datagrams go; NULL: nowhere. */
void udp_set_error_handler(net_t *net, udp_error_handler_t handler);

/** Send @p data_len bytes copied from @p data, from net->ipv4_addr.
 *  @return NET_ERR_BUF_TOO_SMALL if the datagram does not fit the TX frame
 *          buffer or one Ethernet frame (1472 bytes of payload). */
net_err_t udp_send(net_t *net, uint32_t dst_ip, const uint8_t *dst_mac,
                   uint16_t src_port, uint16_t dst_port, const uint8_t *data,
                   uint16_t data_len);

/** Send the @p data_len bytes the caller wrote at UDP_PAYLOAD_OFFSET in
 *  net->tx.buf, from net->ipv4_addr, with IP TTL @p ttl.
 *  @return NET_ERR_INVALID_PARAM for a TTL of 0, a destination of 0.0.0.0,
 *          an address in 127/8, or the broadcast MAC with a destination
 *          that is no IP broadcast or multicast (RFC 1122 §3.2.1.3,
 *          §3.3.6). */
net_err_t udp_send_inplace(net_t *net, uint32_t dst_ip, const uint8_t *dst_mac,
                           uint16_t src_port, uint16_t dst_port,
                           uint16_t data_len, uint8_t ttl);

/** As udp_send_inplace(), from @p src_ip — e.g. 0.0.0.0 while DHCP has no
 *  address yet, or a DHCP server's own address. */
net_err_t udp_send_inplace_from(net_t *net, uint32_t src_ip, uint32_t dst_ip,
                                const uint8_t *dst_mac, uint16_t src_port,
                                uint16_t dst_port, uint16_t data_len,
                                uint8_t ttl);
#endif

#if NET_USE_IPV6
/* UDP over IPv6 */

/** As udp_handler_t; @p src_ip is the sender's 16-byte address. */
typedef void (*udp6_handler_t)(net_t *net, const uint8_t *src_ip,
                               uint16_t src_port, const uint8_t *src_mac,
                               const uint8_t *payload, uint16_t payload_len);

typedef struct udp6_port_entry_s {
  uint16_t port;
  udp6_handler_t handler;
} udp6_port_entry_t;

/** Bind the IPv6 port table, separate from the IPv4 one (if any). */
static inline void udp6_set_ports(net_t *net, const udp6_port_entry_t *ports,
                                  uint8_t count) {
  net->udp6_ports = ports;
  net->udp6_port_count = count;
}

/** As udp_input(); a zero checksum is invalid over IPv6 (RFC 8200 §8.1). */
void udp6_input(net_t *net, const ipv6_hdr_t *ip, const eth_frame_t *eth);

#define UDP6_PAYLOAD_OFFSET (ETH_HDR_SIZE + IPV6_HDR_SIZE + UDP_HDR_SIZE)

/**
 * Send from the source address ipv6_src_for() picks.
 * @return NET_OK; NET_ERR_INVALID_PARAM if no address of ours can reach
 *         @p dst_ip; NET_ERR_BUF_TOO_SMALL.
 */
net_err_t udp6_send(net_t *net, const uint8_t *dst_ip, const uint8_t *dst_mac,
                    uint16_t src_port, uint16_t dst_port, const uint8_t *data,
                    uint16_t data_len);

/** As udp6_send(), for a payload written at UDP6_PAYLOAD_OFFSET. */
net_err_t udp6_send_inplace(net_t *net, const uint8_t *dst_ip,
                            const uint8_t *dst_mac, uint16_t src_port,
                            uint16_t dst_port, uint16_t data_len,
                            uint8_t hop_limit);
#endif

#endif /* UDP_H */
