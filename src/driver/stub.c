/**
 * @file src/driver/stub.c
 * @brief Stub MAC driver for bare-metal size measurement.
 *
 * This driver has no OS dependencies. All functions are minimal stubs
 * that satisfy the net_mac_t vtable interface. Used for cross-compilation
 * to measure code size on targets like ARM Cortex-M0.
 */

#include "net_mac.h"
#include <stddef.h>

static int stub_init(void *ctx) {
  (void)ctx;
  return 0;
}

static int stub_send(void *ctx, const uint8_t *frame, uint16_t len) {
  (void)ctx;
  (void)frame;
  (void)len;
  return (int)len;
}

static int stub_recv(void *ctx, uint8_t *frame, uint16_t maxlen) {
  (void)ctx;
  (void)frame;
  (void)maxlen;
  return 0; /* no frame available */
}

static int stub_peek(void *ctx, uint16_t offset, uint8_t *buf, uint16_t len) {
  (void)ctx;
  (void)offset;
  (void)buf;
  (void)len;
  return 0;
}

static void stub_discard(void *ctx) { (void)ctx; }

static void stub_close(void *ctx) { (void)ctx; }

const net_mac_t stub_mac_ops = {
    .init = stub_init,
    .send = stub_send,
    .recv = stub_recv,
    .peek = stub_peek,
    .discard = stub_discard,
    .close = stub_close,
};
