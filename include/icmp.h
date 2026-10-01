/**
 * @file icmp.h
 * @brief ICMPv4 (RFC 792): echo replies and Destination Unreachable.
 */

#ifndef ICMP_H
#define ICMP_H

#include "eth.h"
#include "ipv4.h"
#include "net.h"
#include <stdint.h>

#define ICMP_OFF_TYPE 0
#define ICMP_OFF_CODE 1
#define ICMP_OFF_CKSUM 2
#define ICMP_OFF_ID 4  /* Echo only */
#define ICMP_OFF_SEQ 6 /* Echo only */
#define ICMP_HDR_SIZE 8

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DEST_UNREACH 3
#define ICMP_TYPE_SOURCE_QUENCH 4
#define ICMP_TYPE_REDIRECT 5
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_TYPE_PARAM_PROBLEM 12

/* Destination Unreachable codes */
#define ICMP_CODE_NET_UNREACH 0
#define ICMP_CODE_HOST_UNREACH 1
#define ICMP_CODE_PROTO_UNREACH 2
#define ICMP_CODE_PORT_UNREACH 3
#define ICMP_CODE_FRAG_NEEDED 4

/** Bytes of the invoking datagram's payload an error quotes (RFC 792). */
#define ICMP_QUOTED_PAYLOAD 8

/** Answer echo requests; errors and unknown types are dropped. */
void icmp_input(net_t *net, const ipv4_hdr_t *ip, const eth_frame_t *eth);

/**
 * Report @p invoking undeliverable to its sender, quoting its header and
 * the start of its payload.  Nothing is sent about a datagram sent to a
 * broadcast or multicast address (RFC 1122 §3.2.2).
 */
net_err_t icmp_send_dest_unreach(net_t *net, uint8_t code,
                                 const ipv4_hdr_t *invoking,
                                 const eth_frame_t *eth);

/** As icmp_send_dest_unreach(), Time Exceeded (type 11) — code 1 when
 *  reassembly gives up on a datagram (RFC 1122 §3.3.2). */
net_err_t icmp_send_time_exceeded(net_t *net, uint8_t code,
                                  const ipv4_hdr_t *invoking,
                                  const eth_frame_t *eth);

#endif /* ICMP_H */
