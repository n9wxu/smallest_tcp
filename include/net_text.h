/**
 * @file net_text.h
 * @brief ASCII helpers for text protocols (HTTP, TFTP, DNS names).
 */

#ifndef NET_TEXT_H
#define NET_TEXT_H

#include <stdint.h>

static inline char net_tolower(char c) {
  return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

/** @p a equals the lower-case string @p lower, ignoring the case of @p a. */
static inline int net_equal_nocase(const char *a, const char *lower) {
  while (*lower && net_tolower(*a) == *lower) {
    a++;
    lower++;
  }
  return *a == '\0' && *lower == '\0';
}

#define NET_U32_DEC_MAX 11 /**< "4294967295" and its NUL */

/**
 * Write @p v in decimal, NUL-terminated, without division (Cortex-M0 has
 * no divide instruction).
 * @return The number of digits.
 */
uint8_t net_u32_to_dec(char out[NET_U32_DEC_MAX], uint32_t v);

#endif /* NET_TEXT_H */
