/**
 * @file driver/tap.h
 * @brief Linux TAP network driver for the MAC HAL.
 *
 * Uses /dev/net/tun with IFF_TAP | IFF_NO_PI to send/receive
 * raw Ethernet frames in userspace.
 */

#ifndef DRIVER_TAP_H
#define DRIVER_TAP_H

#include "net_mac.h"
#include <stdint.h>

/**
 * @brief TAP driver context. Application allocates this.
 */
typedef struct {
  int fd;                 /**< TAP file descriptor */
  char ifname[16];        /**< Interface name (e.g., "tap0") */
  uint8_t rx_frame[1514]; /**< Internal read buffer for peek support */
  uint16_t rx_len;        /**< Bytes currently in rx_frame */
} tap_ctx_t;

/**
 * @brief MAC driver vtable for Linux TAP.
 *
 * Usage:
 *   tap_ctx_t tap;
 *   snprintf(tap.ifname, sizeof(tap.ifname), "tap0");
 *   tap_mac_ops.init(&tap);
 */
extern const net_mac_t tap_mac_ops;

/**
 * Initialize TAP context with default values.
 * @param ctx     TAP context to initialize.
 * @param ifname  Interface name (e.g., "tap0"). NULL for default "tap0".
 */
void tap_ctx_init(tap_ctx_t *ctx, const char *ifname);

#endif /* DRIVER_TAP_H */
