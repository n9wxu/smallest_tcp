/**
 * @file icmpv6.h
 * @brief ICMPv6 — Internet Control Message Protocol for IPv6 (RFC 4443).
 *
 * Echo, error reporting, and the transport for Neighbor Discovery.
 */

#ifndef ICMPV6_H
#define ICMPV6_H

#include "eth.h"
#include "ipv6.h"
#include "net.h"
#include <stdint.h>

#define ICMPV6_OFF_TYPE 0
#define ICMPV6_OFF_CODE 1
#define ICMPV6_OFF_CKSUM 2
#define ICMPV6_OFF_BODY 4 /* type-specific 4 bytes, then the message */
#define ICMPV6_HDR_SIZE 8

/** Offset of the ICMPv6 message in a frame built by icmpv6_send(). */
#define ICMPV6_OFFSET (ETH_HDR_SIZE + IPV6_HDR_SIZE)

#define ICMPV6_DEST_UNREACH 1
#define ICMPV6_PKT_TOO_BIG 2
#define ICMPV6_TIME_EXCEEDED 3
#define ICMPV6_PARAM_PROBLEM 4
#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129
#define ICMPV6_RS 133
#define ICMPV6_RA 134
#define ICMPV6_NS 135
#define ICMPV6_NA 136
#define ICMPV6_REDIRECT 137

#define ICMPV6_CODE_PORT_UNREACH 4        /* Destination Unreachable */
#define ICMPV6_CODE_ERRONEOUS_HEADER 0    /* Parameter Problem */
#define ICMPV6_CODE_UNRECOGNIZED_NH 1     /* Parameter Problem */
#define ICMPV6_CODE_UNRECOGNIZED_OPTION 2 /* Parameter Problem */

/* Rate limit of the errors sent (RFC 4443 §2.4(f)): a token bucket of
 * ICMPV6_ERROR_BURST errors, refilled by one each ICMPV6_ERROR_INTERVAL_MS
 * (at most 65535) */
#ifndef ICMPV6_ERROR_BURST
#define ICMPV6_ERROR_BURST 10
#endif
#ifndef ICMPV6_ERROR_INTERVAL_MS
#define ICMPV6_ERROR_INTERVAL_MS 100
#endif

/** Answer echo requests; hand Neighbor Discovery to ndp_input() and MLD
 *  to mld_input(). */
void icmpv6_input(net_t *net, const ipv6_hdr_t *ip, const eth_frame_t *eth);

/**
 * Send an ICMPv6 message already written at ICMPV6_OFFSET in net->tx.buf:
 * fills the checksum and the IPv6 and Ethernet headers.
 *
 * @param src        Source address (may be :: for DAD).
 * @param icmp_len   Message length (header + body).
 * @param hop_limit  255 for Neighbor Discovery, else net->ip6.hop_limit.
 */
net_err_t icmpv6_send(net_t *net, const uint8_t *src, const uint8_t *dst,
                      const uint8_t *dst_mac, uint16_t icmp_len,
                      uint8_t hop_limit);

/**
 * Send an ICMPv6 error about a received packet, quoting as much of it as
 * fits in 1280 bytes and the TX buffer.  Nothing is sent if RFC 4443
 * §2.4(e) forbids it: the invoking packet is an ICMPv6 error, went to a
 * multicast group or a link-layer multicast/broadcast address, or came
 * from a multicast or unspecified address.
 *
 * @param param  The 4-byte field after the checksum (pointer, MTU or 0).
 * @param eth    The invoking frame (its source MAC gets the error).
 * @return NET_OK; NET_ERR_INVALID_PARAM if no error may be sent about the
 *         packet; NET_ERR_BUSY if the rate limit holds it back;
 *         NET_ERR_BUF_TOO_SMALL.
 */
net_err_t icmpv6_send_error(net_t *net, uint8_t type, uint8_t code,
                            uint32_t param, const ipv6_hdr_t *invoking,
                            const eth_frame_t *eth);

/** Refill the bucket of the error rate limit (called by ipv6_tick()). */
void icmpv6_tick(net_t *net, uint32_t elapsed_ms);

#endif /* ICMPV6_H */
