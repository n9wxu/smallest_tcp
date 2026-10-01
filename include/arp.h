/**
 * @file arp.h
 * @brief ARP (RFC 826): replies for our address, requests, next hop.
 */

#ifndef ARP_H
#define ARP_H

#include "eth.h"
#include "ipv4.h" /* an IPv4 protocol: needs NET_USE_IPV4 */
#include "net.h"
#include <stdint.h>

#define ARP_OFF_HTYPE 0 /* Hardware type (2) */
#define ARP_OFF_PTYPE 2 /* Protocol type (2) */
#define ARP_OFF_HLEN 4  /* Hardware addr len (1) */
#define ARP_OFF_PLEN 5  /* Protocol addr len (1) */
#define ARP_OFF_OPER 6  /* Operation (2) */
#define ARP_OFF_SHA 8   /* Sender hardware addr (6) */
#define ARP_OFF_SPA 14  /* Sender protocol addr (4) */
#define ARP_OFF_THA 18  /* Target hardware addr (6) */
#define ARP_OFF_TPA 24  /* Target protocol addr (4) */
#define ARP_PKT_SIZE 28 /* Total ARP packet size */

#define ARP_HTYPE_ETHERNET 1
#define ARP_PTYPE_IPV4 0x0800
#define ARP_HLEN_ETH 6
#define ARP_PLEN_IPV4 4
#define ARP_OPER_REQUEST 1
#define ARP_OPER_REPLY 2

/**
 * Answer requests for our address; learn the gateway's MAC from its
 * replies; while net->arp_probe_ip is set, set net->arp_probe_conflict on
 * a packet that shows another host using it (RFC 5227 §2.1.1).
 * Everything else is ignored.
 */
void arp_input(net_t *net, const eth_frame_t *eth);

/** Broadcast a request for @p target_ip (host byte order).
 *  @return NET_ERR_BUSY, sending nothing, if that target was requested in
 *  the last second (or NET_ARP_RATE_SLOTS others were). */
net_err_t arp_request(net_t *net, uint32_t target_ip);

/** Age the gateway's MAC and the request rate limit; net_tick() calls it. */
void arp_tick(net_t *net, uint32_t elapsed_ms);

/** The next hop for @p dst_ip: itself if on-link, the limited broadcast
 *  or a multicast group (sent straight to the link), else the gateway
 *  (host byte order). */
uint32_t arp_next_hop(const net_t *net, uint32_t dst_ip);

#endif /* ARP_H */
