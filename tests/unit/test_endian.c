/**
 * @file test_endian.c
 * @brief Unit tests for byte order helpers (net_endian.h).
 */

#include "net_endian.h"
#include "test_main.h"

/* ── Wire read/write tests ────────────────────────────────────────── */

TEST(test_read16be) {
  uint8_t data[] = {0x08, 0x00};
  ASSERT_EQ(net_read16be(data), 0x0800);
}

TEST(test_read16be_ff) {
  uint8_t data[] = {0xFF, 0xFF};
  ASSERT_EQ(net_read16be(data), 0xFFFF);
}

TEST(test_write16be) {
  uint8_t data[2] = {0, 0};
  net_write16be(data, 0x0806);
  ASSERT_EQ(data[0], 0x08);
  ASSERT_EQ(data[1], 0x06);
}

TEST(test_read32be) {
  uint8_t data[] = {0x0A, 0x00, 0x00, 0x02};
  ASSERT_EQ(net_read32be(data), 0x0A000002u);
}

TEST(test_write32be) {
  uint8_t data[4] = {0, 0, 0, 0};
  net_write32be(data, 0xC0A80101u); /* 192.168.1.1 */
  ASSERT_EQ(data[0], 0xC0);
  ASSERT_EQ(data[1], 0xA8);
  ASSERT_EQ(data[2], 0x01);
  ASSERT_EQ(data[3], 0x01);
}

TEST(test_roundtrip_16) {
  uint8_t data[2];
  net_write16be(data, 0x1234);
  ASSERT_EQ(net_read16be(data), 0x1234);
}

TEST(test_roundtrip_32) {
  uint8_t data[4];
  net_write32be(data, 0xDEADBEEFu);
  ASSERT_EQ(net_read32be(data), 0xDEADBEEFu);
}

/* ── Host/network order tests ─────────────────────────────────────── */

TEST(test_htons_ntohs_roundtrip) {
  uint16_t orig = 0x1234;
  ASSERT_EQ(net_ntohs(net_htons(orig)), orig);
}

TEST(test_htonl_ntohl_roundtrip) {
  uint32_t orig = 0x12345678u;
  ASSERT_EQ(net_ntohl(net_htonl(orig)), orig);
}

TEST(test_htons_known_value) {
  /* 80 = 0x0050. After net_htons, writing to wire should be 00 50. */
  uint16_t net_val = net_htons(80);
  uint8_t bytes[2];
  net_write16be(bytes, net_ntohs(net_val));
  ASSERT_EQ(bytes[0], 0x00);
  ASSERT_EQ(bytes[1], 0x50);
  /* Also verify roundtrip */
  ASSERT_EQ(net_ntohs(net_val), 80);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void) {
  fprintf(stderr, "=== test_endian ===\n");

  RUN_TEST(test_read16be);
  RUN_TEST(test_read16be_ff);
  RUN_TEST(test_write16be);
  RUN_TEST(test_read32be);
  RUN_TEST(test_write32be);
  RUN_TEST(test_roundtrip_16);
  RUN_TEST(test_roundtrip_32);
  RUN_TEST(test_htons_ntohs_roundtrip);
  RUN_TEST(test_htonl_ntohl_roundtrip);
  RUN_TEST(test_htons_known_value);

  TEST_REPORT();
  return test_failures;
}
