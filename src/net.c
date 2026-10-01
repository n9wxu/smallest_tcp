/**
 * @file net.c
 * @brief Network context: initialisation, frame reception, timers,
 *        randomness.
 */

#include "net.h"
#include "eth.h"
#if NET_USE_IPV4
#include "arp.h"
#endif
#include <string.h>

#if NET_USE_TCP
#include "tcp.h"
#endif

#if NET_USE_IPV6
#include "ipv6.h"
#endif

/* The smallest frame buffers the protocols compiled in can work with */
#if NET_USE_TCP
#define NET_MIN_FRAME TCP_MIN_FRAME
#else
#define NET_MIN_FRAME ETH_HDR_SIZE
#endif

/* Replies are built in tx while the request is still read from rx, so the
 * two must not share a byte.  Addresses are compared as integers: '<' is
 * defined only between pointers into the same object. */
static int buffers_overlap(const uint8_t *a, uint16_t a_size, const uint8_t *b,
                           uint16_t b_size) {
  uintptr_t pa = (uintptr_t)a, pb = (uintptr_t)b;
  return pa < pb + b_size && pb < pa + a_size;
}

net_err_t net_init(net_t *net, uint8_t *rx_buf, uint16_t rx_size,
                   uint8_t *tx_buf, uint16_t tx_size, const uint8_t mac[6],
                   const net_mac_t *driver, void *driver_ctx) {
  static const uint8_t default_mac[6] = NET_DEFAULT_MAC;

  if (!net || !rx_buf || !tx_buf || !driver ||
      buffers_overlap(rx_buf, rx_size, tx_buf, tx_size))
    return NET_ERR_INVALID_PARAM;
  if (rx_size < NET_MIN_FRAME || tx_size < NET_MIN_FRAME)
    return NET_ERR_BUF_TOO_SMALL;

  memset(net, 0, sizeof(*net));
  net->rx.buf = rx_buf;
  net->rx.capacity = rx_size;
  net->tx.buf = tx_buf;
  net->tx.capacity = tx_size;
  memcpy(net->mac, mac ? mac : default_mac, 6);
  net->mac_driver = driver;
  net->mac_ctx = driver_ctx;
  net->mtu = NET_DEFAULT_MTU;
#if NET_USE_IPV4
  net->ipv4_addr = NET_DEFAULT_IPV4_ADDR;
  net->subnet_mask = NET_DEFAULT_SUBNET_MASK;
  net->gateway_ipv4 = NET_DEFAULT_GATEWAY;
#endif
  net_random_seed(net, net->mac, 6);

  NET_LOG("net_init: rx=%u tx=%u mac=%02x:%02x:%02x:%02x:%02x:%02x", rx_size,
          tx_size, net->mac[0], net->mac[1], net->mac[2], net->mac[3],
          net->mac[4], net->mac[5]);
  return NET_OK;
}

int net_poll(net_t *net) {
  int len = net->mac_driver->poll(net->mac_ctx);
  if (len <= 0)
    return len;
  if (len > net->rx.capacity)
    len = net->rx.capacity;
  len = net->mac_driver->peek(net->mac_ctx, 0, net->rx.buf, (uint16_t)len);
  if (len > 0)
    eth_input(net, net->rx.buf, (uint16_t)len);
  net->mac_driver->discard(net->mac_ctx);
  return len;
}

void net_tick(net_t *net, uint32_t elapsed_ms) {
#if NET_USE_IPV4
  arp_tick(net, elapsed_ms);
#endif
#if NET_USE_TCP
  tcp_tick(net, elapsed_ms);
#endif
#if NET_USE_IPV6
  ipv6_tick(net, elapsed_ms);
#endif
  (void)net;
  (void)elapsed_ms;
}

net_err_t net_transmit(net_t *net, uint16_t frame_len) {
  int sent = net->mac_driver->send(net->mac_ctx, net->tx.buf, frame_len);
  if (sent > 0)
    return NET_OK;
  return sent == 0 ? NET_ERR_BUSY : NET_ERR_NO_FRAME;
}

/* ── HalfSipHash-2-4, 32-bit output (Aumasson, Bernstein) ── */

static uint32_t rotl(uint32_t x, unsigned bits) {
  return x << bits | x >> (32u - bits);
}

static void sip_rounds(uint32_t v[4], unsigned rounds) {
  while (rounds--) {
    v[0] += v[1];
    v[1] = rotl(v[1], 5) ^ v[0];
    v[0] = rotl(v[0], 16);
    v[2] += v[3];
    v[3] = rotl(v[3], 8) ^ v[2];
    v[0] += v[3];
    v[3] = rotl(v[3], 7) ^ v[0];
    v[2] += v[1];
    v[1] = rotl(v[1], 13) ^ v[2];
    v[2] = rotl(v[2], 16);
  }
}

static void sip_absorb(uint32_t v[4], uint32_t word) {
  v[3] ^= word;
  sip_rounds(v, 2);
  v[0] ^= word;
}

uint32_t net_hash(const net_t *net, const uint8_t *data, uint16_t len) {
  uint32_t v[4];
  uint32_t word = 0;
  uint16_t i;
  v[0] = net->secret[0];
  v[1] = net->secret[1];
  v[2] = 0x6c796765u ^ net->secret[0];
  v[3] = 0x74656462u ^ net->secret[1];
  for (i = 0; i < len; i++) { /* little-endian words */
    word |= (uint32_t)data[i] << (8u * (i & 3u));
    if ((i & 3u) == 3u) {
      sip_absorb(v, word);
      word = 0;
    }
  }
  sip_absorb(v, word | (uint32_t)len << 24);
  v[2] ^= 0xFFu;
  sip_rounds(v, 4);
  return v[1] ^ v[3];
}

#define SEED_CHUNK 16u

/* The new secret is two hashes under the old one of 16 bytes of entropy,
 * zero-padded, and a byte of how many were entropy and which word — so each
 * seed adds to what the key already holds, 16 bytes at a time.  17 bytes is
 * no length net_random() or TCP hashes. */
void net_random_seed(net_t *net, const uint8_t *entropy, uint16_t len) {
  uint8_t in[SEED_CHUNK + 1];
  uint16_t n;
  uint32_t first;
  do {
    n = len < SEED_CHUNK ? len : (uint16_t)SEED_CHUNK;
    memset(in, 0, sizeof(in));
    if (n)
      memcpy(in, entropy, n);
    in[SEED_CHUNK] = (uint8_t)(n << 1);
    first = net_hash(net, in, sizeof(in));
    in[SEED_CHUNK] |= 1u;
    net->secret[1] = net_hash(net, in, sizeof(in));
    net->secret[0] = first;
    entropy += n;
    len = (uint16_t)(len - n);
  } while (len > 0);
}

uint32_t net_random(net_t *net) {
  uint8_t count[4];
  net_write32be(count, net->random_count++);
  return net_hash(net, count, sizeof(count));
}

uint32_t net_random_below(net_t *net, uint32_t n) {
  return ((net_random(net) & 0xFFFFu) * n) >> 16;
}

uint32_t net_whole_seconds(uint16_t *carry_ms, uint32_t elapsed_ms) {
  uint32_t ms = *carry_ms + elapsed_ms;
  uint32_t seconds = 0;
  while (ms >= 1000u) { /* no division on Cortex-M0 */
    ms -= 1000u;
    seconds++;
  }
  *carry_ms = (uint16_t)ms;
  return seconds;
}
