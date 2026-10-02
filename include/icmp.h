/**
 * @file icmp.h
 * @brief ICMPv4 (RFC 792): echo replies, the errors a host sends
 *        (Destination Unreachable, Time Exceeded in reassembly), and the
 *        errors received, passed to UDP and TCP.
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

/** Answer Echo Requests (none sent to a broadcast or multicast address);
 *  pass Destination Unreachable, Time Exceeded and Parameter Problem about
 *  a datagram of ours to the transport the quoted header names
 *  (udp_icmp_error(), tcp_icmp_error()).  A message with a wrong checksum
 *  and every other type — Source Quench, Redirect, Echo Reply — is
 *  dropped. */
void icmp_input(net_t *net, const ipv4_hdr_t *ip, const eth_frame_t *eth);

/**
 * Report @p invoking undeliverable to its sender, quoting its header and
 * the first ICMP_QUOTED_PAYLOAD bytes of its payload.
 * @return NET_ERR_INVALID_PARAM, sending nothing, about a datagram sent to
 *         a broadcast or multicast address (IP or link layer), one whose
 *         source is no single host, an ICMP error message, or while we
 *         have no address (RFC 1122 §3.2.2); NET_ERR_BUF_TOO_SMALL if the
 *         message does not fit one frame; else net_transmit()'s result.
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
