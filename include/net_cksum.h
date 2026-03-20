/**
 * @file net_cksum.h
 * @brief Internet checksum API (RFC 1071, RFC 1624).
 *
 * Provides an incremental checksum API that supports streaming
 * computation, pseudo-header inclusion, and a convenience one-shot
 * function. Uses a uint32 accumulator to defer carry folding.
 */

#ifndef NET_CKSUM_H
#define NET_CKSUM_H

#include <stdint.h>

/**
 * @brief Checksum accumulator (uint32 defers carry folding).
 */
typedef struct {
  uint32_t sum;
} net_cksum_t;

/**
 * Initialize checksum accumulator to zero.
 */
void net_cksum_init(net_cksum_t *c);

/**
 * Add a block of data to the checksum accumulator.
 * Handles odd-length data by logically padding a zero byte.
 * @param data  Pointer to data (may be unaligned).
 * @param len   Length in bytes.
 */
void net_cksum_add(net_cksum_t *c, const uint8_t *data, uint16_t len);

/**
 * Add a single uint16 value to the checksum accumulator.
 * Useful for pseudo-header fields without constructing a temporary buffer.
 * @param val  Value in host byte order — caller must pass net_htons() if
 * needed.
 */
void net_cksum_add_u16(net_cksum_t *c, uint16_t val);

/**
 * Add a single uint32 value to the checksum accumulator.
 * Added as two uint16 values (high word, then low word).
 * @param val  Value in host byte order — caller must pass net_htonl() if
 * needed.
 */
void net_cksum_add_u32(net_cksum_t *c, uint32_t val);

/**
 * Finalize: fold carries and complement.
 * @return The Internet checksum (16-bit, in network byte order).
 */
uint16_t net_cksum_finalize(net_cksum_t *c);

/**
 * Convenience: compute checksum over a contiguous block in one call.
 * @return The Internet checksum.
 */
uint16_t net_cksum(const uint8_t *data, uint16_t len);

/**
 * Verify a checksum: compute over data (including checksum field).
 * @return 1 if checksum verifies (result is 0x0000 or 0xFFFF), 0 otherwise.
 */
int net_cksum_verify(const uint8_t *data, uint16_t len);

/**
 * Incremental update (RFC 1624): update checksum when a single 16-bit
 * field changes, without recomputing over the entire header.
 * @param old_cksum  Previous checksum value (as stored in header).
 * @param old_val    Old value of the changed field.
 * @param new_val    New value of the changed field.
 * @return Updated checksum.
 */
uint16_t net_cksum_update(uint16_t old_cksum, uint16_t old_val,
                          uint16_t new_val);

#endif /* NET_CKSUM_H */
