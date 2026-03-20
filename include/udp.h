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
 * @param net       Network context.
 * @param src_ip    Sender's IPv4 address (host byte order).
 * @param src_port  Sender's port (host byte order).
 * @param src_mac   Sender's MAC address (6 bytes).
 * @param data      Pointer to UDP payload data (in rx buffer, zero-copy).
 * @param data_len  Length of UDP payload data.
 */
typedef void (*udp_handler_t)(net_t *net, uint32_t src_ip, uint16_t src_port,
                              const uint8_t *src_mac, const uint8_t *data,
                              uint16_t data_len);

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

#endif /* UDP_H */
