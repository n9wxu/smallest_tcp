/**
 * @file test_net.c
 * @brief Unit tests for net_init() factory method and utility functions.
 */

#include "net.h"
#include "tcp.h"
#include "test_main.h"
#include <string.h>

/* ── Stub MAC driver for testing ──────────────────────────────────── */

static int stub_init(void *ctx) {
  (void)ctx;
  return 0;
}
static int driver_busy;

static int stub_send(void *ctx, const uint8_t *f, uint16_t l) {
  (void)ctx;
  (void)f;
  return driver_busy ? 0 : (int)l;
}
static int stub_poll(void *ctx) {
  (void)ctx;
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
    .poll = stub_poll,
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

#if NET_USE_IPV4
TEST(test_net_init_defaults_applied) {
  uint8_t rx[200], tx[200];
  net_t net;
  int dummy = 0;

  net_init(&net, rx, sizeof(rx), tx, sizeof(tx), NULL, &stub_mac, &dummy);

  ASSERT_EQ(net.ipv4_addr, NET_DEFAULT_IPV4_ADDR);
  ASSERT_EQ(net.subnet_mask, NET_DEFAULT_SUBNET_MASK);
  ASSERT_EQ(net.gateway_ipv4, NET_DEFAULT_GATEWAY);
  ASSERT_EQ(net.gateway_mac_valid, 0);
}
#endif

TEST(test_net_init_buf_too_small) {
  uint8_t rx[10], tx[200]; /* rx too small */
  net_t net;
  int dummy = 0;

  net_err_t err =
      net_init(&net, rx, sizeof(rx), tx, sizeof(tx), NULL, &stub_mac, &dummy);
  ASSERT_EQ(err, NET_ERR_BUF_TOO_SMALL);
}

/* TCP needs room for a SYN with every option a peer may send.  A buffer
 * that would leave it an MSS of 0 — 54 bytes, 74 with IPv6 — is refused
 * at once. */
TEST(test_net_init_refuses_buffers_too_small_for_tcp) {
  uint8_t rx[TCP_MIN_FRAME], tx[TCP_MIN_FRAME];
  uint16_t no_mss = NET_USE_IPV6 ? 74 : 54;
  net_t net;
  int dummy = 0;

  ASSERT_EQ(TCP_MIN_FRAME, NET_USE_IPV6 ? 114 : 94);
  ASSERT_EQ(net_init(&net, rx, no_mss, tx, sizeof(tx), NULL, &stub_mac, &dummy),
            NET_ERR_BUF_TOO_SMALL);
  ASSERT_EQ(net_init(&net, rx, sizeof(rx), tx, no_mss, NULL, &stub_mac, &dummy),
            NET_ERR_BUF_TOO_SMALL);
  ASSERT_EQ(net_init(&net, rx, TCP_MIN_FRAME - 1, tx, sizeof(tx), NULL,
                     &stub_mac, &dummy),
            NET_ERR_BUF_TOO_SMALL);
  ASSERT_EQ(net_init(&net, rx, sizeof(rx), tx, TCP_MIN_FRAME - 1, NULL,
                     &stub_mac, &dummy),
            NET_ERR_BUF_TOO_SMALL);
  ASSERT_EQ(
      net_init(&net, rx, sizeof(rx), tx, sizeof(tx), NULL, &stub_mac, &dummy),
      NET_OK);
}

/* Replies are built in tx while the request is still read from rx: the
 * two may touch but not share a byte */
TEST(test_net_init_refuses_overlapping_buffers) {
  static uint8_t mem[3 * TCP_MIN_FRAME];
  net_t net;
  int dummy = 0;

  ASSERT_EQ(net_init(&net, mem, TCP_MIN_FRAME, mem, TCP_MIN_FRAME, NULL,
                     &stub_mac, &dummy),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(net_init(&net, mem, 2 * TCP_MIN_FRAME, mem + TCP_MIN_FRAME,
                     TCP_MIN_FRAME, NULL, &stub_mac, &dummy),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(net_init(&net, mem + TCP_MIN_FRAME, TCP_MIN_FRAME, mem,
                     TCP_MIN_FRAME + 1, NULL, &stub_mac, &dummy),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(net_init(&net, mem + TCP_MIN_FRAME, TCP_MIN_FRAME, mem,
                     TCP_MIN_FRAME, NULL, &stub_mac, &dummy),
            NET_OK);
  ASSERT_EQ(net_init(&net, mem, TCP_MIN_FRAME, mem + TCP_MIN_FRAME,
                     2 * TCP_MIN_FRAME, NULL, &stub_mac, &dummy),
            NET_OK);
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

/* ── Transmit ─────────────────────────────────────────────────────── */

TEST(test_net_transmit_reports_busy_driver) {
  uint8_t rx[200], tx[200];
  net_t net;
  int ctx = 0;
  net_init(&net, rx, sizeof(rx), tx, sizeof(tx), NULL, &stub_mac, &ctx);
  ASSERT_EQ(net_transmit(&net, 60), NET_OK);
  driver_busy = 1;
  ASSERT_EQ(net_transmit(&net, 60), NET_ERR_BUSY);
  driver_busy = 0;
}

/* ── Random numbers ───────────────────────────────────────────────── */

static uint32_t xorshift32(uint32_t x) {
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  return x;
}

/* HalfSipHash-2-4, 32-bit output: the reference vectors (key 00..07,
 * message 00..len-1) for every tail length */
TEST(test_net_hash_matches_reference_vectors) {
  static const uint32_t expected[16] = {
      0x5b9f35a9u, 0xb85a4727u, 0x03a662fau, 0x04e7fe8au,
      0x89466e2au, 0x69b6fac5u, 0x23fc6358u, 0xc563cf8bu,
      0x8f84b8d0u, 0x79e706f8u, 0x3479b094u, 0x50300808u,
      0x2f87f057u, 0xff63e677u, 0x7cf8ffd6u, 0x972bfe74u,
  };
  net_t net;
  uint8_t msg[16];
  uint16_t len;
  memset(&net, 0, sizeof(net));
  net.secret[0] = 0x03020100u;
  net.secret[1] = 0x07060504u;
  for (len = 0; len < 16; len++)
    msg[len] = (uint8_t)len;
  for (len = 0; len < 16; len++)
    ASSERT_EQ(net_hash(&net, msg, len), expected[len]);
}

/* An output must not give away the generator's state */
TEST(test_net_random_output_does_not_predict_the_next) {
  uint8_t rx[200], tx[200];
  net_t net;
  int ctx = 0;
  uint32_t a, b;
  net_init(&net, rx, sizeof(rx), tx, sizeof(tx), NULL, &stub_mac, &ctx);
  a = net_random(&net);
  b = net_random(&net);
  ASSERT_TRUE(b != xorshift32(a));
}

int main(void) {
  fprintf(stderr, "=== test_net ===\n");

  RUN_TEST(test_net_init_success);
  RUN_TEST(test_net_init_null_mac_uses_default);
#if NET_USE_IPV4
  RUN_TEST(test_net_init_defaults_applied);
#endif
  RUN_TEST(test_net_init_buf_too_small);
  RUN_TEST(test_net_init_refuses_buffers_too_small_for_tcp);
  RUN_TEST(test_net_init_refuses_overlapping_buffers);
  RUN_TEST(test_net_init_null_params);
  RUN_TEST(test_mac_equal);
  RUN_TEST(test_mac_is_broadcast);
  RUN_TEST(test_mac_is_multicast);
  RUN_TEST(test_net_transmit_reports_busy_driver);
  RUN_TEST(test_net_hash_matches_reference_vectors);
  RUN_TEST(test_net_random_output_does_not_predict_the_next);

  TEST_REPORT();
  return test_failures;
}
