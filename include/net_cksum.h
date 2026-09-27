/**
 * @file net_cksum.h
 * @brief The Internet checksum (RFC 1071): computed incrementally, so
 *        pseudo-headers and discontiguous data add up without copying.
 *        See docs/design/checksum.md.
 */

#ifndef NET_CKSUM_H
#define NET_CKSUM_H

#include <stdint.h>

/** A running one's complement sum; carries are folded at the end. */
typedef struct {
  uint32_t sum;
} net_cksum_t;

void net_cksum_init(net_cksum_t *c);

/** Add bytes (any alignment; an odd length is padded with a zero byte). */
void net_cksum_add(net_cksum_t *c, const uint8_t *data, uint16_t len);

/** Add one 16-bit word, host byte order. */
void net_cksum_add_u16(net_cksum_t *c, uint16_t val);

/** Add a 32-bit value as two words, host byte order. */
void net_cksum_add_u32(net_cksum_t *c, uint32_t val);

/** Fold and complement: the checksum to store, or 0 over data whose
 *  stored checksum is valid. */
uint16_t net_cksum_finalize(net_cksum_t *c);

/** The checksum of one contiguous block. */
uint16_t net_cksum(const uint8_t *data, uint16_t len);

/** 1 if @p data, its checksum field included, verifies. */
int net_cksum_verify(const uint8_t *data, uint16_t len);

/** The checksum after one 16-bit field changes from @p old_val to
 *  @p new_val, without recomputing (RFC 1624 eqn. 3). */
uint16_t net_cksum_update(uint16_t old_cksum, uint16_t old_val,
                          uint16_t new_val);

#endif /* NET_CKSUM_H */
