/**
 * @file udp.h
 * @brief UDP — User Datagram Protocol (RFC 768).
 *
 * Connectionless datagram service with port-based dispatch.
 * Static port→callback table provided by the application.
 */

#ifndef UDP_H
#define UDP_H

#include "eth.h"
#include "ipv4.h"
#include "net.h"
#include <stdint.h>

#if NET_USE_IPV6
#include "ipv6.h"
#endif

/* ── UDP header offsets ───────────────────────────────────────────── */

#define UDP_OFF_SPORT 0
#define UDP_OFF_DPORT 2
#define UDP_OFF_LEN 4
#define UDP_OFF_CKSUM 6
#define UDP_HDR_SIZE 8

/* ── UDP port handler callback ────────────────────────────────────── */

/**
 * @brief Callback invoked when a UDP datagram arrives for a registered port.
 *
 * The handler receives source information and the byte offset within the
 * current MAC frame where the UDP payload begins.  To read payload bytes,
 * call net->mac_driver->peek(net->mac_ctx, payload_offset, buf, n).
 *
 * The handler MUST NOT call discard() — eth_input() does so after dispatch.
 *
 * @param net             Network context.
 * @param src_ip          Sender's IPv4 address (host byte order).
 * @param src_port        Sender's port (host byte order).
 * @param src_mac         Sender's MAC address (6 bytes).
 * @param payload_offset  Byte offset into the MAC frame where payload starts.
 * @param payload_len     Length of UDP payload in bytes.
 */
typedef void (*udp_handler_t)(net_t *net, uint32_t src_ip, uint16_t src_port,
                              const uint8_t *src_mac, uint16_t payload_offset,
                              uint16_t payload_len);

/**
 * @brief Port-to-handler binding.
 */
typedef struct {
  uint16_t port;         /**< Local port number (host byte order) */
  udp_handler_t handler; /**< Callback function */
} udp_port_entry_t;

/**
 * @brief UDP port handler table (provided by the application).
 */
typedef struct {
  const udp_port_entry_t *entries; /**< Array of port bindings */
  uint8_t count;                   /**< Number of entries */
} udp_port_table_t;

/* ── Global port table (application sets this) ────────────────────── */

extern udp_port_table_t udp_ports;

/* ── Functions ────────────────────────────────────────────────────── */

/**
 * Process a received UDP datagram (after IPv4 dispatch).
 *
 * Validates length and checksum, dispatches by destination port.
 *
 * @param net   Network context.
 * @param ip    Parsed IPv4 header.
 * @param eth   Parsed Ethernet frame.
 */
void udp_input(net_t *net, const ipv4_hdr_t *ip, const eth_frame_t *eth);

/**
 * Send a UDP datagram.
 *
 * Builds UDP + IPv4 + Ethernet headers in the tx buffer and sends.
 *
 * @param net        Network context.
 * @param dst_ip     Destination IPv4 (host byte order).
 * @param dst_mac    Destination MAC (6 bytes).
 * @param src_port   Source port (host byte order).
 * @param dst_port   Destination port (host byte order).
 * @param data       Pointer to payload data.
 * @param data_len   Payload length.
 * @return NET_OK on success, or error code.
 */
net_err_t udp_send(net_t *net, uint32_t dst_ip, const uint8_t *dst_mac,
                   uint16_t src_port, uint16_t dst_port, const uint8_t *data,
                   uint16_t data_len);

/** Offset of the UDP payload in a frame built by udp_send_inplace(). */
#define UDP_PAYLOAD_OFFSET (ETH_HDR_SIZE + IPV4_HDR_SIZE + UDP_HDR_SIZE)

/**
 * Send a UDP datagram whose payload the caller has already written into
 * net->tx.buf at UDP_PAYLOAD_OFFSET (zero copy), with an explicit IP TTL.
 *
 * @param data_len   Payload length already in place.
 * @param ttl        IP TTL (e.g. 255 for mDNS, RFC 6762 §11).
 * @return NET_OK on success, or error code.
 */
net_err_t udp_send_inplace(net_t *net, uint32_t dst_ip, const uint8_t *dst_mac,
                           uint16_t src_port, uint16_t dst_port,
                           uint16_t data_len, uint8_t ttl);

/**
 * Compute UDP checksum over pseudo-header + UDP header + data.
 *
 * @param src_ip     Source IP (host byte order).
 * @param dst_ip     Destination IP (host byte order).
 * @param udp_hdr    Pointer to UDP header (checksum field should be 0).
 * @param udp_len    Total UDP length (header + data).
 * @return Checksum value (network byte order). 0xFFFF if computed as 0.
 */
uint16_t udp_checksum(uint32_t src_ip, uint32_t dst_ip, const uint8_t *udp_hdr,
                      uint16_t udp_len);

#if NET_USE_IPV6
/* ── UDP over IPv6 ────────────────────────────────────────────────── */

/**
 * @brief As udp_handler_t, for a datagram that arrived over IPv6.
 *
 * @param src_ip  Sender's address (16 bytes, network order, in the frame —
 *                valid during the call).
 */
typedef void (*udp6_handler_t)(net_t *net, const uint8_t *src_ip,
                               uint16_t src_port, const uint8_t *src_mac,
                               uint16_t payload_offset, uint16_t payload_len);

/** @brief Port-to-handler binding for IPv6. */
typedef struct {
  uint16_t port;          /**< Local port number (host byte order) */
  udp6_handler_t handler; /**< Callback function */
} udp6_port_entry_t;

/**
 * @brief IPv6 port table, separate from udp_ports so IPv4 tables stay as
 * they are.  A port absent here is closed over IPv6.
 */
typedef struct {
  const udp6_port_entry_t *entries;
  uint8_t count;
} udp6_port_table_t;

extern udp6_port_table_t udp6_ports;

/**
 * Process a received UDP datagram (after IPv6 dispatch).  The checksum is
 * mandatory over IPv6: a zero checksum is dropped (RFC 8200 §8.1).
 */
void udp6_input(net_t *net, const ipv6_hdr_t *ip, const eth_frame_t *eth);

/** Offset of the UDP payload in a frame built by udp6_send_inplace(). */
#define UDP6_PAYLOAD_OFFSET (ETH_HDR_SIZE + IPV6_HDR_SIZE + UDP_HDR_SIZE)

/**
 * Send a UDP datagram over IPv6, from the source ipv6_src_for() picks.
 * @return NET_OK; NET_ERR_INVALID_PARAM if we have no usable source
 *         address for @p dst_ip; NET_ERR_BUF_TOO_SMALL.
 */
net_err_t udp6_send(net_t *net, const uint8_t *dst_ip, const uint8_t *dst_mac,
                    uint16_t src_port, uint16_t dst_port, const uint8_t *data,
                    uint16_t data_len);

/**
 * As udp6_send(), for a payload already written at UDP6_PAYLOAD_OFFSET in
 * net->tx.buf, with an explicit Hop Limit (e.g. 255 for mDNS).
 */
net_err_t udp6_send_inplace(net_t *net, const uint8_t *dst_ip,
                            const uint8_t *dst_mac, uint16_t src_port,
                            uint16_t dst_port, uint16_t data_len,
                            uint8_t hop_limit);
#endif

#endif /* UDP_H */
