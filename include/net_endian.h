/**
 * @file net_endian.h
 * @brief Byte order conversion and wire read/write helpers.
 *
 * Wire helpers (net_read16be, net_write16be, etc.) are always needed and
 * operate on byte pointers — safe on all architectures regardless of
 * alignment requirements.
 *
 * Host/network order helpers (net_htons, net_ntohl, etc.) perform byte
 * swapping on little-endian targets and are no-ops on big-endian targets
 * (including 8-bit MCUs where we store everything in network order).
 */

#ifndef NET_ENDIAN_H
#define NET_ENDIAN_H

#include <stdint.h>

/* ── Byte order detection ─────────────────────────────────────────── */

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define NET_BIG_ENDIAN 1
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define NET_LITTLE_ENDIAN 1
#elif defined(NET_8BIT_TARGET) && NET_8BIT_TARGET
/* 8-bit MCUs: use big-endian (network order) natively */
#define NET_BIG_ENDIAN 1
#else
#error                                                                         \
    "Cannot determine byte order. Define NET_BIG_ENDIAN or NET_LITTLE_ENDIAN."
#endif

/* ── Wire read/write helpers (always big-endian, unaligned-safe) ──── */

static inline uint16_t net_read16be(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static inline void net_write16be(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v);
}

static inline uint32_t net_read32be(const uint8_t *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
         (uint32_t)p[3];
}

static inline void net_write32be(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)(v);
}

/* ── Host ↔ Network byte order ────────────────────────────────────── */

#if defined(NET_BIG_ENDIAN)

static inline uint16_t net_htons(uint16_t h) { return h; }
static inline uint16_t net_ntohs(uint16_t n) { return n; }
static inline uint32_t net_htonl(uint32_t h) { return h; }
static inline uint32_t net_ntohl(uint32_t n) { return n; }

#elif defined(NET_LITTLE_ENDIAN)

static inline uint16_t net_htons(uint16_t h) {
  return (uint16_t)((h >> 8) | (h << 8));
}
static inline uint16_t net_ntohs(uint16_t n) {
  return (uint16_t)((n >> 8) | (n << 8));
}
static inline uint32_t net_htonl(uint32_t h) {
  return ((h >> 24) & 0x000000FFu) | ((h >> 8) & 0x0000FF00u) |
         ((h << 8) & 0x00FF0000u) | ((h << 24) & 0xFF000000u);
}
static inline uint32_t net_ntohl(uint32_t n) {
  return net_htonl(n); /* symmetric */
}

#endif

#endif /* NET_ENDIAN_H */
