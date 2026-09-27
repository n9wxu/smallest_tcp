/**
 * @file net.c
 * @brief Network context: initialisation, frame reception, timers,
 *        randomness.
 */

#include "net.h"
#include "eth.h"
#include <string.h>

#if NET_USE_TCP
#include "tcp.h"
#endif

#if NET_USE_IPV6
#include "ipv6.h"
#endif

net_err_t net_init(net_t *net, uint8_t *rx_buf, uint16_t rx_size,
                   uint8_t *tx_buf, uint16_t tx_size, const uint8_t mac[6],
                   const net_mac_t *driver, void *driver_ctx) {
  static const uint8_t default_mac[6] = NET_DEFAULT_MAC;

  if (!net || !rx_buf || !tx_buf || !driver)
    return NET_ERR_INVALID_PARAM;
  if (rx_size < ETH_HDR_SIZE || tx_size < ETH_HDR_SIZE)
    return NET_ERR_BUF_TOO_SMALL;

  memset(net, 0, sizeof(*net));
  net->rx.buf = rx_buf;
  net->rx.capacity = rx_size;
  net->tx.buf = tx_buf;
  net->tx.capacity = tx_size;
  memcpy(net->mac, mac ? mac : default_mac, 6);
  net->mac_driver = driver;
  net->mac_ctx = driver_ctx;
  net->ipv4_addr = NET_DEFAULT_IPV4_ADDR;
  net->subnet_mask = NET_DEFAULT_SUBNET_MASK;
  net->gateway_ipv4 = NET_DEFAULT_GATEWAY;
  net->rng = 1;
  net_random_seed(net, (uint32_t)net->mac[2] << 24 |
                           (uint32_t)net->mac[3] << 16 |
                           (uint32_t)net->mac[4] << 8 | net->mac[5]);

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
  return net->mac_driver->send(net->mac_ctx, net->tx.buf, frame_len) >= 0
             ? NET_OK
             : NET_ERR_NO_FRAME;
}

void net_random_seed(net_t *net, uint32_t entropy) {
  net->rng ^= entropy;
  if (net->rng == 0)
    net->rng = 1; /* the one state xorshift never leaves */
  net_random(net);
}

uint32_t net_random(net_t *net) {
  uint32_t x = net->rng;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  net->rng = x;
  return x;
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
