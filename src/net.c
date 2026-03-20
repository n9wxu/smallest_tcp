/**
 * @file net.c
 * @brief Core network context factory method.
 */

#include "net.h"
#include <string.h>

net_err_t net_init(net_t *net, uint8_t *rx_buf, uint16_t rx_size,
                   uint8_t *tx_buf, uint16_t tx_size, const uint8_t mac[6],
                   const net_mac_t *driver, void *driver_ctx) {
  /* Validate parameters */
  if (!net || !rx_buf || !tx_buf || !driver) {
    return NET_ERR_INVALID_PARAM;
  }

  /* Minimum buffer size: must hold at least an Ethernet header */
  if (rx_size < NET_MIN_BUF_ETH || tx_size < NET_MIN_BUF_ETH) {
    return NET_ERR_BUF_TOO_SMALL;
  }

  /* Zero the entire structure */
  memset(net, 0, sizeof(*net));

  /* Set up buffers */
  net->rx.buf = rx_buf;
  net->rx.capacity = rx_size;
  net->rx.frame_len = 0;

  net->tx.buf = tx_buf;
  net->tx.capacity = tx_size;
  net->tx.frame_len = 0;

  /* Set MAC address */
  if (mac) {
    memcpy(net->mac, mac, 6);
  } else {
    static const uint8_t default_mac[] = NET_DEFAULT_MAC;
    memcpy(net->mac, default_mac, 6);
  }

  /* Connect MAC driver */
  net->mac_driver = driver;
  net->mac_ctx = driver_ctx;

  /* Apply compile-time defaults for runtime-tunable fields */
#ifdef NET_DEFAULT_IPV4_ADDR
  net->ipv4_addr = NET_DEFAULT_IPV4_ADDR;
#endif
#ifdef NET_DEFAULT_SUBNET_MASK
  net->subnet_mask = NET_DEFAULT_SUBNET_MASK;
#endif
#ifdef NET_DEFAULT_GATEWAY
  net->gateway_ipv4 = NET_DEFAULT_GATEWAY;
#endif

  net->gateway_mac_valid = 0;

  net->arp_retry_ms = NET_DEFAULT_ARP_RETRY_MS;
  net->arp_max_retries = NET_DEFAULT_ARP_MAX_RETRIES;

  NET_LOG("net_init: rx=%u tx=%u mac=%02x:%02x:%02x:%02x:%02x:%02x", rx_size,
          tx_size, net->mac[0], net->mac[1], net->mac[2], net->mac[3],
          net->mac[4], net->mac[5]);

  return NET_OK;
}
