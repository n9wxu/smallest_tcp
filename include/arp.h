/**
 * @file arp.h
 * @brief ARP — Address Resolution Protocol (RFC 826).
 *
 * Distributed cache model: no global ARP table. Resolved MACs are
 * stored in the application's connection structures or gateway_mac.
 */

#ifndef ARP_H
#define ARP_H

#include "eth.h"
#include "net.h"
#include <stdint.h>

/* ── ARP packet field offsets (within Ethernet payload) ───────────── */

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

/* ── ARP constants ────────────────────────────────────────────────── */

#define ARP_HTYPE_ETHERNET 1
#define ARP_PTYPE_IPV4 0x0800
#define ARP_HLEN_ETH 6
#define ARP_PLEN_IPV4 4
#define ARP_OPER_REQUEST 1
#define ARP_OPER_REPLY 2

/* ── Functions ────────────────────────────────────────────────────── */

/**
 * Process a received ARP packet (after Ethernet layer dispatch).
 *
 * - Validates HW type, proto type, HLEN, PLEN (REQ-ARP-005..007)
 * - For requests targeting our IP: sends reply (REQ-ARP-001..003)
 * - For replies: updates gateway_mac if sender IP matches gateway
 * (REQ-ARP-010..012)
 * - Discards everything else (REQ-ARP-004, REQ-ARP-013)
 *
 * @param net   Network context.
 * @param eth   Parsed Ethernet frame (payload points to ARP data).
 */
void arp_input(net_t *net, const eth_frame_t *eth);

/**
 * Send an ARP request for the given IPv4 address.
 *
 * Sends a broadcast ARP request (REQ-ARP-015..020).
 *
 * @param net       Network context (uses tx buffer).
 * @param target_ip IPv4 address to resolve (host byte order).
 * @return NET_OK on success, or error code.
 */
net_err_t arp_request(net_t *net, uint32_t target_ip);

/**
 * Determine the next-hop IP for a destination.
 *
 * On-subnet → destination IP. Off-subnet → gateway IP. (REQ-ARP-025..026)
 *
 * @param net     Network context.
 * @param dst_ip  Destination IP (host byte order).
 * @return Next-hop IP (host byte order).
 */
uint32_t arp_next_hop(const net_t *net, uint32_t dst_ip);

#endif /* ARP_H */
