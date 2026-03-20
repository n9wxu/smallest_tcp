/**
 * @file net_cksum.c
 * @brief Internet checksum implementation (RFC 1071, RFC 1624).
 *
 * Uses a uint32 accumulator to defer carry folding until finalize().
 * Processes data as 16-bit words for speed, handles odd trailing byte.
 * All data access is byte-based for unaligned-safety.
 */

#include "net_cksum.h"

void net_cksum_init(net_cksum_t *c) { c->sum = 0; }

void net_cksum_add(net_cksum_t *c, const uint8_t *data, uint16_t len) {
  uint32_t sum = c->sum;
  uint16_t i;

  /* Process 16-bit words (byte-based for alignment safety) */
  for (i = 0; i + 1 < len; i += 2) {
    sum += ((uint16_t)data[i] << 8) | data[i + 1];
  }

  /* Handle odd trailing byte: pad with zero */
  if (len & 1) {
    sum += (uint16_t)data[len - 1] << 8;
  }

  c->sum = sum;
}

void net_cksum_add_u16(net_cksum_t *c, uint16_t val) { c->sum += val; }

void net_cksum_add_u32(net_cksum_t *c, uint32_t val) {
  c->sum += (val >> 16) & 0xFFFF;
  c->sum += val & 0xFFFF;
}

uint16_t net_cksum_finalize(net_cksum_t *c) {
  uint32_t sum = c->sum;

  /* Fold 32-bit sum to 16 bits */
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  /* One's complement */
  return (uint16_t)(~sum & 0xFFFF);
}

uint16_t net_cksum(const uint8_t *data, uint16_t len) {
  net_cksum_t c;
  net_cksum_init(&c);
  net_cksum_add(&c, data, len);
  return net_cksum_finalize(&c);
}

int net_cksum_verify(const uint8_t *data, uint16_t len) {
  uint16_t result = net_cksum(data, len);
  /* When including the checksum field in the computation,
   * a correct checksum yields 0x0000 (after complement, 0xFFFF before).
   * We check for 0x0000 (the complemented result). */
  return result == 0x0000;
}

uint16_t net_cksum_update(uint16_t old_cksum, uint16_t old_val,
                          uint16_t new_val) {
  /* RFC 1624, Equation 3:
   * HC' = ~(~HC + ~m + m')
   * Where HC = old checksum, m = old value, m' = new value
   * All in one's complement arithmetic. */
  uint32_t sum;

  sum = (uint16_t)~old_cksum;
  sum += (uint16_t)~old_val;
  sum += new_val;

  /* Fold carries */
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return (uint16_t)(~sum & 0xFFFF);
}
