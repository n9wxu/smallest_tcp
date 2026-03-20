/**
 * @file ipv4.h
 * @brief IPv4 — Internet Protocol version 4 (RFC 791).
 *
 * Parse/build IPv4 headers in-place. Dispatch by protocol field.
 * Always sets DF (no fragmentation support).
 */

#ifndef IPV4_H
#define IPV4_H

#include "eth.h"
#include "net.h"
#include <stdint.h>

/* ── IPv4 header field offsets ────────────────────────────────────── */

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
#define IPV4_HDR_SIZE 20 /* Minimum (no options) */

/* ── IPv4 protocol numbers ────────────────────────────────────────── */

#define IPV4_PROTO_ICMP 1
#define IPV4_PROTO_TCP 6
#define IPV4_PROTO_UDP 17

/* ── IPv4 flags ───────────────────────────────────────────────────── */

#define IPV4_FLAG_DF 0x4000   /* Don't Fragment */
#define IPV4_FLAG_MF 0x2000   /* More Fragments */
#define IPV4_FRAG_MASK 0x1FFF /* Fragment offset mask */

/* ── Default TTL ──────────────────────────────────────────────────── */

#ifndef NET_DEFAULT_TTL
#define NET_DEFAULT_TTL 64
#endif

/* ── Parsed IPv4 header info ──────────────────────────────────────── */

typedef struct {
  uint8_t ihl;          /**< Header length in 32-bit words (5-15) */
  uint8_t protocol;     /**< Protocol (1=ICMP, 6=TCP, 17=UDP) */
  uint8_t ttl;          /**< Time to live */
  uint16_t total_len;   /**< Total length (header + payload) */
  uint16_t flags_frag;  /**< Flags + fragment offset (raw) */
  uint32_t src_ip;      /**< Source IP in host byte order */
  uint32_t dst_ip;      /**< Destination IP in host byte order */
  uint8_t *payload;     /**< Pointer to IP payload (after header) */
  uint16_t payload_len; /**< Payload length in bytes */
  uint8_t *header;      /**< Pointer to start of IPv4 header */
  uint16_t header_len;  /**< Header length in bytes (ihl*4) */
} ipv4_hdr_t;

/* ── Functions ────────────────────────────────────────────────────── */

/**
 * Parse an IPv4 header in-place.
 *
 * Validates version, IHL, total length, checksum (REQ-IPv4-001..007).
 * Rejects fragments (REQ-IPv4-024).
 *
 * @param data     Pointer to IPv4 header (Ethernet payload).
 * @param data_len Length of data available.
 * @param out      Parsed header info (pointers into original buffer).
 * @return NET_OK on success, or error code.
 */
net_err_t ipv4_parse(uint8_t *data, uint16_t data_len, ipv4_hdr_t *out);

/**
 * Process a received IPv4 packet (after Ethernet dispatch).
 *
 * Validates header, checks destination address, dispatches by protocol.
 *
 * @param net   Network context.
 * @param eth   Parsed Ethernet frame.
 */
void ipv4_input(net_t *net, const eth_frame_t *eth);

/**
 * Build an IPv4 header in-place at the given offset.
 *
 * Always: Version=4, IHL=5, DF=1, TTL=64. No options.
 *
 * @param buf          Pointer to start of IP header area.
 * @param payload_len  Length of IP payload (after IP header).
 * @param protocol     Protocol number (1, 6, 17).
 * @param src_ip       Source IP in host byte order.
 * @param dst_ip       Destination IP in host byte order.
 */
void ipv4_build(uint8_t *buf, uint16_t payload_len, uint8_t protocol,
                uint32_t src_ip, uint32_t dst_ip);

/**
 * Send an IPv4 packet. Builds Ethernet + IPv4 headers in the tx buffer
 * and sends via the MAC driver.
 *
 * @param net          Network context.
 * @param dst_ip       Destination IP (host byte order).
 * @param dst_mac      Destination MAC (6 bytes). Use broadcast if needed.
 * @param protocol     IP protocol number.
 * @param payload      Pointer to payload data (or NULL if already in tx buf).
 * @param payload_len  Payload length.
 * @return NET_OK on success, or error code.
 */
net_err_t ipv4_send(net_t *net, uint32_t dst_ip, const uint8_t *dst_mac,
                    uint8_t protocol, const uint8_t *payload,
                    uint16_t payload_len);

/**
 * Check if an IP address is on the local subnet.
 */
static inline int ipv4_is_local(const net_t *net, uint32_t ip) {
  return (ip & net->subnet_mask) == (net->ipv4_addr & net->subnet_mask);
}

/**
 * Check if an IP address is broadcast (limited or subnet-directed).
 */
static inline int ipv4_is_broadcast(const net_t *net, uint32_t ip) {
  if (ip == 0xFFFFFFFFu)
    return 1; /* Limited broadcast */
  /* Subnet-directed broadcast: host part all ones */
  uint32_t host_part = ip & ~net->subnet_mask;
  uint32_t host_max = ~net->subnet_mask;
  return host_part == host_max;
}

#endif /* IPV4_H */
