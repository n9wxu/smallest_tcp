/**
 * @file icmp.h
 * @brief ICMPv4 — Internet Control Message Protocol (RFC 792).
 *
 * Handles Echo Request → Echo Reply (ping) in-place.
 */

#ifndef ICMP_H
#define ICMP_H

#include "eth.h"
#include "ipv4.h"
#include "net.h"
#include <stdint.h>

/* ── ICMP header offsets ──────────────────────────────────────────── */

#define ICMP_OFF_TYPE 0
#define ICMP_OFF_CODE 1
#define ICMP_OFF_CKSUM 2
#define ICMP_OFF_ID 4   /* Echo only */
#define ICMP_OFF_SEQ 6  /* Echo only */
#define ICMP_HDR_SIZE 8 /* Minimum ICMP header */

/* ── ICMP types ───────────────────────────────────────────────────── */

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DEST_UNREACH 3
#define ICMP_TYPE_SOURCE_QUENCH 4
#define ICMP_TYPE_REDIRECT 5
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_TYPE_PARAM_PROBLEM 12

/* ── ICMP Destination Unreachable codes ───────────────────────────── */

#define ICMP_CODE_NET_UNREACH 0
#define ICMP_CODE_HOST_UNREACH 1
#define ICMP_CODE_PROTO_UNREACH 2
#define ICMP_CODE_PORT_UNREACH 3
#define ICMP_CODE_FRAG_NEEDED 4

/* ── Functions ────────────────────────────────────────────────────── */

/**
 * Process a received ICMP packet.
 *
 * - Echo Request → Echo Reply in-place (REQ-ICMPv4-001..009)
 * - Validates ICMP checksum (REQ-ICMPv4-031)
 * - Silently discards unknown types (REQ-ICMPv4-040)
 *
 * @param net   Network context.
 * @param ip    Parsed IPv4 header.
 * @param eth   Parsed Ethernet frame (for src MAC on reply).
 */
void icmp_input(net_t *net, const ipv4_hdr_t *ip, const eth_frame_t *eth);

/**
 * Send an ICMP Destination Unreachable message.
 *
 * Includes original IP header + first 8 bytes of original payload.
 *
 * @param net          Network context.
 * @param code         Unreachable code (0-15).
 * @param orig_ip_hdr  Pointer to original IP header.
 * @param orig_ip_len  Length of original IP header.
 * @param orig_payload First 8 bytes of original IP payload.
 * @param dst_ip       Where to send the error (original source IP).
 * @param dst_mac      MAC of destination.
 * @return NET_OK or error.
 */
net_err_t icmp_send_dest_unreach(net_t *net, uint8_t code,
                                 const uint8_t *orig_ip_hdr,
                                 uint16_t orig_ip_len,
                                 const uint8_t *orig_payload, uint32_t dst_ip,
                                 const uint8_t *dst_mac);

#endif /* ICMP_H */
