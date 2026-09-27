/**
 * @file net_cksum.c
 * @brief The Internet checksum (RFC 1071, RFC 1624).
 */

#include "net_cksum.h"

static uint16_t fold(uint32_t sum) {
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
  return (uint16_t)sum;
}

void net_cksum_init(net_cksum_t *c) { c->sum = 0; }

void net_cksum_add(net_cksum_t *c, const uint8_t *data, uint16_t len) {
  uint32_t sum = c->sum;
  uint16_t i;
  for (i = 0; i + 1 < len; i += 2)
    sum += (uint16_t)((uint16_t)data[i] << 8 | data[i + 1]);
  if (len & 1)
    sum += (uint16_t)((uint16_t)data[len - 1] << 8);
  c->sum = sum;
}

void net_cksum_add_u16(net_cksum_t *c, uint16_t val) { c->sum += val; }

void net_cksum_add_u32(net_cksum_t *c, uint32_t val) {
  c->sum += (val >> 16) & 0xFFFF;
  c->sum += val & 0xFFFF;
}

uint16_t net_cksum_finalize(net_cksum_t *c) { return (uint16_t)~fold(c->sum); }

uint16_t net_cksum(const uint8_t *data, uint16_t len) {
  net_cksum_t c;
  net_cksum_init(&c);
  net_cksum_add(&c, data, len);
  return net_cksum_finalize(&c);
}

int net_cksum_verify(const uint8_t *data, uint16_t len) {
  return net_cksum(data, len) == 0;
}

/* HC' = ~(~HC + ~m + m') */
uint16_t net_cksum_update(uint16_t old_cksum, uint16_t old_val,
                          uint16_t new_val) {
  uint32_t sum = (uint16_t)~old_cksum;
  sum += (uint16_t)~old_val;
  sum += new_val;
  return (uint16_t)~fold(sum);
}
