/**
 * @file test_eth.c
 * @brief Unit tests for Ethernet II frame parsing and building (eth.h/eth.c).
 */

#include "eth.h"
#include "test_main.h"
#include <string.h>

/* ── Helper: build a valid Ethernet frame ─────────────────────────── */

static void make_frame(uint8_t *buf, uint16_t *len, const uint8_t *dst,
                       const uint8_t *src, uint16_t ethertype,
                       uint16_t payload_len) {
  memcpy(buf + 0, dst, 6);
  memcpy(buf + 6, src, 6);
  buf[12] = (uint8_t)(ethertype >> 8);
  buf[13] = (uint8_t)(ethertype);
  /* Fill payload with incrementing bytes */
  for (uint16_t i = 0; i < payload_len; i++) {
    buf[14 + i] = (uint8_t)(i & 0xFF);
  }
  *len = 14 + payload_len;
}

static const uint8_t our_mac[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t other_mac[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
static const uint8_t bcast_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* ── Parse tests ──────────────────────────────────────────────────── */

TEST(test_eth_parse_valid_ipv4) {
  uint8_t frame[100];
  uint16_t len;
  make_frame(frame, &len, our_mac, other_mac, 0x0800, 46);

  eth_frame_t out;
  ASSERT_EQ(eth_parse(frame, len, &out), NET_OK);
  ASSERT_MEM_EQ(out.dst_mac, our_mac, 6);
  ASSERT_MEM_EQ(out.src_mac, other_mac, 6);
  ASSERT_EQ(out.ethertype, 0x0800);
  ASSERT_EQ(out.payload, frame + 14);
  ASSERT_EQ(out.payload_len, 46);
}

TEST(test_eth_parse_valid_arp) {
  uint8_t frame[100];
  uint16_t len;
  make_frame(frame, &len, bcast_mac, other_mac, 0x0806, 28);

  eth_frame_t out;
  ASSERT_EQ(eth_parse(frame, len, &out), NET_OK);
  ASSERT_EQ(out.ethertype, 0x0806);
  ASSERT_EQ(out.payload_len, 28);
}

TEST(test_eth_parse_too_short) {
  /* REQ-ETH-009: frames < 14 bytes must be rejected */
  uint8_t frame[13] = {0};
  eth_frame_t out;
  ASSERT_NE(eth_parse(frame, 13, &out), NET_OK);
  ASSERT_NE(eth_parse(frame, 0, &out), NET_OK);
}

TEST(test_eth_parse_reject_802_3) {
  /* REQ-ETH-017: EtherType <= 0x05DC is 802.3 length, must reject */
  uint8_t frame[64];
  uint16_t len;
  make_frame(frame, &len, our_mac, other_mac, 0x0040,
             46); /* 64 = length field */

  eth_frame_t out;
  ASSERT_NE(eth_parse(frame, len, &out), NET_OK);
}

TEST(test_eth_parse_exact_14_bytes) {
  /* Minimum valid: 14-byte frame, 0 payload */
  uint8_t frame[14];
  uint16_t len;
  make_frame(frame, &len, our_mac, other_mac, 0x0800, 0);

  eth_frame_t out;
  ASSERT_EQ(eth_parse(frame, len, &out), NET_OK);
  ASSERT_EQ(out.payload_len, 0);
}

TEST(test_eth_parse_ipv6) {
  uint8_t frame[100];
  uint16_t len;
  make_frame(frame, &len, our_mac, other_mac, 0x86DD, 40);

  eth_frame_t out;
  ASSERT_EQ(eth_parse(frame, len, &out), NET_OK);
  ASSERT_EQ(out.ethertype, 0x86DD);
}

/* ── Build tests ──────────────────────────────────────────────────── */

TEST(test_eth_build_ipv4) {
  uint8_t buf[100];
  uint8_t *payload = eth_build(buf, sizeof(buf), other_mac, our_mac, 0x0800);

  ASSERT_NOT_NULL(payload);
  ASSERT_EQ(payload, buf + 14);

  /* Verify header contents */
  ASSERT_MEM_EQ(buf + 0, other_mac, 6); /* dst */
  ASSERT_MEM_EQ(buf + 6, our_mac, 6);   /* src */
  ASSERT_EQ(buf[12], 0x08);             /* EtherType high */
  ASSERT_EQ(buf[13], 0x00);             /* EtherType low */
}

TEST(test_eth_build_arp) {
  uint8_t buf[100];
  uint8_t *payload = eth_build(buf, sizeof(buf), bcast_mac, our_mac, 0x0806);

  ASSERT_NOT_NULL(payload);
  ASSERT_MEM_EQ(buf + 0, bcast_mac, 6);
  ASSERT_EQ(buf[12], 0x08);
  ASSERT_EQ(buf[13], 0x06);
}

TEST(test_eth_build_too_small) {
  uint8_t buf[10]; /* Too small for header */
  uint8_t *payload = eth_build(buf, sizeof(buf), other_mac, our_mac, 0x0800);
  ASSERT_NULL(payload);
}

/* ── Roundtrip test ───────────────────────────────────────────────── */

TEST(test_eth_build_parse_roundtrip) {
  uint8_t buf[100];

  /* Build */
  uint8_t *payload = eth_build(buf, sizeof(buf), other_mac, our_mac, 0x0800);
  ASSERT_NOT_NULL(payload);

  /* Write some payload */
  payload[0] = 0xDE;
  payload[1] = 0xAD;
  uint16_t total_len = 14 + 2;

  /* Parse */
  eth_frame_t out;
  ASSERT_EQ(eth_parse(buf, total_len, &out), NET_OK);

  ASSERT_MEM_EQ(out.dst_mac, other_mac, 6);
  ASSERT_MEM_EQ(out.src_mac, our_mac, 6);
  ASSERT_EQ(out.ethertype, 0x0800);
  ASSERT_EQ(out.payload_len, 2);
  ASSERT_EQ(out.payload[0], 0xDE);
  ASSERT_EQ(out.payload[1], 0xAD);
}

/* ── Zero-copy verification ───────────────────────────────────────── */

TEST(test_eth_parse_zero_copy) {
  /* REQ-ETH-019: pointers must point into original buffer */
  uint8_t frame[100];
  uint16_t len;
  make_frame(frame, &len, our_mac, other_mac, 0x0800, 20);

  eth_frame_t out;
  ASSERT_EQ(eth_parse(frame, len, &out), NET_OK);

  /* dst_mac should point to frame[0] */
  ASSERT_EQ(out.dst_mac, frame + 0);
  /* src_mac should point to frame[6] */
  ASSERT_EQ(out.src_mac, frame + 6);
  /* payload should point to frame[14] */
  ASSERT_EQ(out.payload, frame + 14);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void) {
  fprintf(stderr, "=== test_eth ===\n");

  RUN_TEST(test_eth_parse_valid_ipv4);
  RUN_TEST(test_eth_parse_valid_arp);
  RUN_TEST(test_eth_parse_too_short);
  RUN_TEST(test_eth_parse_reject_802_3);
  RUN_TEST(test_eth_parse_exact_14_bytes);
  RUN_TEST(test_eth_parse_ipv6);
  RUN_TEST(test_eth_build_ipv4);
  RUN_TEST(test_eth_build_arp);
  RUN_TEST(test_eth_build_too_small);
  RUN_TEST(test_eth_build_parse_roundtrip);
  RUN_TEST(test_eth_parse_zero_copy);

  TEST_REPORT();
  return test_failures;
}
