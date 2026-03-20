/**
 * @file eth.h
 * @brief Ethernet II frame parsing and building — zero-copy, in-place.
 *
 * All operations work directly on the application's net_buf_t.
 * No data is copied — headers are parsed/built in-place.
 *
 * Frame format (RFC 894):
 *   Offset 0:  Destination MAC (6 bytes)
 *   Offset 6:  Source MAC (6 bytes)
 *   Offset 12: EtherType (2 bytes, big-endian)
 *   Offset 14: Payload (46–1500 bytes)
 */

#ifndef ETH_H
#define ETH_H

#include "net.h"
#include <stdint.h>

/* ── Ethernet header field offsets ────────────────────────────────── */

#define ETH_OFF_DST 0
#define ETH_OFF_SRC 6
#define ETH_OFF_TYPE 12
#define ETH_HDR_SIZE 14

/* ── Parsed Ethernet frame info ───────────────────────────────────── */

/**
 * @brief Result of parsing an Ethernet frame.
 *
 * Points into the original buffer — zero-copy.
 */
typedef struct {
  const uint8_t *dst_mac; /**< Pointer to destination MAC in frame */
  const uint8_t *src_mac; /**< Pointer to source MAC in frame */
  uint16_t ethertype;     /**< EtherType in host byte order */
  uint8_t *payload;       /**< Pointer to payload (frame + 14) */
  uint16_t payload_len;   /**< Payload length (frame_len - 14) */
} eth_frame_t;

/* ── Functions ────────────────────────────────────────────────────── */

/**
 * Parse an Ethernet II frame in-place.
 *
 * Validates:
 *   - Frame length >= 14 bytes (REQ-ETH-009)
 *   - EtherType > 0x05DC (rejects 802.3 length-encoded frames, REQ-ETH-017)
 *
 * @param frame     Pointer to raw frame data.
 * @param frame_len Frame length in bytes.
 * @param out       Parsed frame info (pointers into original buffer).
 * @return NET_OK on success, or error code.
 */
net_err_t eth_parse(uint8_t *frame, uint16_t frame_len, eth_frame_t *out);

/**
 * Build an Ethernet II header in-place at the start of a buffer.
 *
 * After calling, the caller writes payload starting at the returned pointer.
 *
 * @param buf       Buffer to write header into (must have >= 14 bytes
 * capacity).
 * @param dst_mac   Destination MAC address (6 bytes).
 * @param src_mac   Source MAC address (6 bytes).
 * @param ethertype EtherType in host byte order (e.g., NET_ETHERTYPE_IPV4).
 * @return Pointer to payload area (buf + 14), or NULL on error.
 */
uint8_t *eth_build(uint8_t *buf, uint16_t buf_capacity, const uint8_t *dst_mac,
                   const uint8_t *src_mac, uint16_t ethertype);

/**
 * Process a received Ethernet frame: validate, filter by MAC, dispatch.
 *
 * Checks destination MAC against our MAC and broadcast (REQ-ETH-001,
 * REQ-ETH-002). Discards frames not addressed to us (REQ-ETH-003). Dispatches
 * by EtherType (REQ-ETH-005, REQ-ETH-006, REQ-ETH-007).
 *
 * @param net   Network context.
 * @param frame Raw frame data.
 * @param len   Frame length.
 */
void eth_input(net_t *net, uint8_t *frame, uint16_t len);

#endif /* ETH_H */
