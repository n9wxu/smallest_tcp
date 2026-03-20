/**
 * @file test_net.c
 * @brief Unit tests for net_init() factory method and utility functions.
 */

#include "net.h"
#include "test_main.h"
#include <string.h>

/* ── Stub MAC driver for testing ──────────────────────────────────── */

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

/* ── Factory method tests ─────────────────────────────────────────── */

TEST(test_net_init_success) {
  uint8_t rx[200], tx[200];
  net_t net;
  uint8_t mac[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
  int dummy_ctx = 0;

  net_err_t err = net_init(&net, rx, sizeof(rx), tx, sizeof(tx), mac, &stub_mac,
                           &dummy_ctx);
  ASSERT_EQ(err, NET_OK);
  ASSERT_EQ(net.rx.buf, rx);
  ASSERT_EQ(net.rx.capacity, 200);
  ASSERT_EQ(net.tx.buf, tx);
  ASSERT_EQ(net.tx.capacity, 200);
  ASSERT_MEM_EQ(net.mac, mac, 6);
  ASSERT_EQ(net.mac_driver, &stub_mac);
  ASSERT_EQ(net.mac_ctx, &dummy_ctx);
}

TEST(test_net_init_null_mac_uses_default) {
  uint8_t rx[200], tx[200];
  net_t net;
  int dummy = 0;

  net_err_t err =
      net_init(&net, rx, sizeof(rx), tx, sizeof(tx), NULL, &stub_mac, &dummy);
  ASSERT_EQ(err, NET_OK);

  /* Should have default MAC */
  uint8_t expected[] = NET_DEFAULT_MAC;
  ASSERT_MEM_EQ(net.mac, expected, 6);
}

TEST(test_net_init_defaults_applied) {
  uint8_t rx[200], tx[200];
  net_t net;
  int dummy = 0;

  net_init(&net, rx, sizeof(rx), tx, sizeof(tx), NULL, &stub_mac, &dummy);

  ASSERT_EQ(net.ipv4_addr, NET_DEFAULT_IPV4_ADDR);
  ASSERT_EQ(net.subnet_mask, NET_DEFAULT_SUBNET_MASK);
  ASSERT_EQ(net.gateway_ipv4, NET_DEFAULT_GATEWAY);
  ASSERT_EQ(net.gateway_mac_valid, 0);
  ASSERT_EQ(net.arp_retry_ms, NET_DEFAULT_ARP_RETRY_MS);
  ASSERT_EQ(net.arp_max_retries, NET_DEFAULT_ARP_MAX_RETRIES);
}

TEST(test_net_init_buf_too_small) {
  uint8_t rx[10], tx[200]; /* rx too small */
  net_t net;
  int dummy = 0;

  net_err_t err =
      net_init(&net, rx, sizeof(rx), tx, sizeof(tx), NULL, &stub_mac, &dummy);
  ASSERT_EQ(err, NET_ERR_BUF_TOO_SMALL);
}

TEST(test_net_init_null_params) {
  uint8_t rx[200], tx[200];
  net_t net;
  int dummy = 0;

  ASSERT_EQ(net_init(NULL, rx, 200, tx, 200, NULL, &stub_mac, &dummy),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(net_init(&net, NULL, 200, tx, 200, NULL, &stub_mac, &dummy),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(net_init(&net, rx, 200, NULL, 200, NULL, &stub_mac, &dummy),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(net_init(&net, rx, 200, tx, 200, NULL, NULL, &dummy),
            NET_ERR_INVALID_PARAM);
}

/* ── MAC utility tests ────────────────────────────────────────────── */

TEST(test_mac_equal) {
  uint8_t a[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
  uint8_t b[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
  uint8_t c[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};

  ASSERT_TRUE(net_mac_equal(a, b));
  ASSERT_FALSE(net_mac_equal(a, c));
}

TEST(test_mac_is_broadcast) {
  uint8_t bcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t unicast[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

  ASSERT_TRUE(net_mac_is_broadcast(bcast));
  ASSERT_FALSE(net_mac_is_broadcast(unicast));
}

TEST(test_mac_is_multicast) {
  uint8_t mcast[] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01};
  uint8_t unicast[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

  ASSERT_TRUE(net_mac_is_multicast(mcast));
  ASSERT_FALSE(net_mac_is_multicast(unicast));
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void) {
  fprintf(stderr, "=== test_net ===\n");

  RUN_TEST(test_net_init_success);
  RUN_TEST(test_net_init_null_mac_uses_default);
  RUN_TEST(test_net_init_defaults_applied);
  RUN_TEST(test_net_init_buf_too_small);
  RUN_TEST(test_net_init_null_params);
  RUN_TEST(test_mac_equal);
  RUN_TEST(test_mac_is_broadcast);
  RUN_TEST(test_mac_is_multicast);

  TEST_REPORT();
  return test_failures;
}
