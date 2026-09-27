/**
 * @file net_text.c
 * @brief ASCII helpers for text protocols.
 */

#include "net_text.h"

uint8_t net_u32_to_dec(char out[NET_U32_DEC_MAX], uint32_t v) {
  static const uint32_t powers_of_ten[10] = {
      1000000000u, 100000000u, 10000000u, 1000000u, 100000u,
      10000u,      1000u,      100u,      10u,      1u};
  uint8_t n = 0, i;
  for (i = 0; i < 10; i++) {
    char digit = '0';
    while (v >= powers_of_ten[i]) {
      v -= powers_of_ten[i];
      digit++;
    }
    if (digit != '0' || n > 0 || i == 9)
      out[n++] = digit;
  }
  out[n] = '\0';
  return n;
}
