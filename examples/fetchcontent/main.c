/**
 * @file main.c
 * @brief Minimal example demonstrating smallest_tcp used via FetchContent.
 *
 * This simply initializes the stack structures to prove the headers
 * and library link correctly from an external project.
 */

#include "eth.h"
#include "net.h"
#include "net_cksum.h"
#include <stdio.h>

/* Minimal stub driver for demonstration */
static int stub_init(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_send(void *ctx, const uint8_t *f, uint16_t l) {
  (void)ctx;
  (void)f;
  (void)l;
  return (int)l;
}
static int stub_recv(void *ctx, uint8_t *f, uint16_t m) {
  (void)ctx;
  (void)f;
  (void)m;
  return 0;
}
static int stub_peek(void *ctx, uint16_t o, uint8_t *b, uint16_t l) {
  (void)ctx;
  (void)o;
  (void)b;
  (void)l;
  return 0;
}
static void stub_discard(void *ctx) { (void)ctx; }
static void stub_close(void *ctx) { (void)ctx; }

static const net_mac_t stub_mac = {
    .init = stub_init,
    .send = stub_send,
    .recv = stub_recv,
    .peek = stub_peek,
    .discard = stub_discard,
    .close = stub_close,
};

int main(void) {
  static uint8_t rx[256], tx[256];
  static net_t net;
  int ctx = 0;

  net_err_t err =
      net_init(&net, rx, sizeof(rx), tx, sizeof(tx), NULL, &stub_mac, &ctx);
  if (err != NET_OK) {
    fprintf(stderr, "net_init failed: %d\n", err);
    return 1;
  }

  printf("smallest_tcp FetchContent integration works!\n");
  printf("  MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", net.mac[0], net.mac[1],
         net.mac[2], net.mac[3], net.mac[4], net.mac[5]);
  printf("  Checksum of empty data: 0x%04X\n", net_cksum(NULL, 0));

  return 0;
}
