/**
 * @file test_checksum.c
 * @brief Unit tests for Internet checksum (RFC 1071, RFC 1624).
 */

#include "net_cksum.h"
#include "test_main.h"
#include <string.h>

/* ── Basic checksum tests ─────────────────────────────────────────── */

TEST(test_cksum_init) {
  /* REQ-CKSUM-008: init must zero accumulator */
  net_cksum_t c;
  net_cksum_init(&c);
  ASSERT_EQ(c.sum, 0u);
}

TEST(test_cksum_zero_length) {
  /* Checksum of empty data should be 0xFFFF (complement of 0) */
  uint16_t result = net_cksum(NULL, 0);
  ASSERT_EQ(result, 0xFFFF);
}

TEST(test_cksum_two_bytes) {
  /* Data: 0x0001 → sum = 0x0001, complement = 0xFFFE */
  uint8_t data[] = {0x00, 0x01};
  uint16_t result = net_cksum(data, 2);
  ASSERT_EQ(result, 0xFFFE);
}

TEST(test_cksum_odd_byte) {
  /* REQ-CKSUM-002: odd-length data, pad with zero */
  /* Data: 0x01 → padded to 0x0100, sum = 0x0100, complement = 0xFEFF */
  uint8_t data[] = {0x01};
  uint16_t result = net_cksum(data, 1);
  ASSERT_EQ(result, 0xFEFF);
}

TEST(test_cksum_known_ipv4_header) {
  /* A known valid IPv4 header (from RFC 1071 example concept):
   * Version=4, IHL=5, TOS=0, TotalLen=44, ID=1, Flags=0, TTL=64,
   * Protocol=6(TCP), Checksum=0 (to be computed), Src=10.0.0.2, Dst=10.0.0.1
   */
  uint8_t hdr[] = {
      0x45, 0x00, 0x00, 0x2C, /* ver/ihl, tos, total len */
      0x00, 0x01, 0x00, 0x00, /* id, flags/frag */
      0x40, 0x06, 0x00, 0x00, /* ttl, proto, checksum (zeroed) */
      0x0A, 0x00, 0x00, 0x02, /* src: 10.0.0.2 */
      0x0A, 0x00, 0x00, 0x01, /* dst: 10.0.0.1 */
  };

  /* Compute checksum */
  uint16_t cksum = net_cksum(hdr, 20);

  /* Write checksum into header */
  hdr[10] = (uint8_t)(cksum >> 8);
  hdr[11] = (uint8_t)(cksum);

  /* REQ-CKSUM-010: verify — computing over data with checksum should yield 0 */
  ASSERT_TRUE(net_cksum_verify(hdr, 20));
}

/* ── Incremental API tests ────────────────────────────────────────── */

TEST(test_cksum_incremental_equals_oneshot) {
  /* REQ-CKSUM-006: incremental must equal one-shot */
  uint8_t data[] = {0x45, 0x00, 0x00, 0x2C, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06,
                    0x00, 0x00, 0x0A, 0x00, 0x00, 0x02, 0x0A, 0x00, 0x00, 0x01};

  uint16_t oneshot = net_cksum(data, 20);

  net_cksum_t c;
  net_cksum_init(&c);
  net_cksum_add(&c, data, 10);      /* First half */
  net_cksum_add(&c, data + 10, 10); /* Second half */
  uint16_t incremental = net_cksum_finalize(&c);

  ASSERT_EQ(oneshot, incremental);
}

TEST(test_cksum_add_u16) {
  /* REQ-CKSUM-007: add individual uint16 values */
  net_cksum_t c;
  net_cksum_init(&c);
  net_cksum_add_u16(&c, 0x4500);
  net_cksum_add_u16(&c, 0x002C);
  uint16_t result = net_cksum_finalize(&c);

  /* Manual: sum = 0x4500 + 0x002C = 0x452C, complement = 0xBAD3 */
  ASSERT_EQ(result, 0xBAD3);
}

TEST(test_cksum_add_u32) {
  /* Add 0x0A000002 (10.0.0.2) as two u16: 0x0A00 + 0x0002 */
  net_cksum_t c1, c2;
  net_cksum_init(&c1);
  net_cksum_init(&c2);

  net_cksum_add_u32(&c1, 0x0A000002u);

  net_cksum_add_u16(&c2, 0x0A00);
  net_cksum_add_u16(&c2, 0x0002);

  ASSERT_EQ(net_cksum_finalize(&c1), net_cksum_finalize(&c2));
}

/* ── Verification tests ───────────────────────────────────────────── */

TEST(test_cksum_verify_valid) {
  /* Build a header with valid checksum, then verify */
  uint8_t hdr[] = {
      0x45, 0x00, 0x00, 0x2C, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06,
      0x00, 0x00, 0x0A, 0x00, 0x00, 0x02, 0x0A, 0x00, 0x00, 0x01,
  };
  uint16_t cksum = net_cksum(hdr, 20);
  hdr[10] = (uint8_t)(cksum >> 8);
  hdr[11] = (uint8_t)(cksum);

  ASSERT_TRUE(net_cksum_verify(hdr, 20));
}

TEST(test_cksum_verify_invalid) {
  uint8_t hdr[] = {
      0x45, 0x00, 0x00, 0x2C, 0x00, 0x01, 0x00, 0x00,
      0x40, 0x06, 0xDE, 0xAD, /* bogus checksum */
      0x0A, 0x00, 0x00, 0x02, 0x0A, 0x00, 0x00, 0x01,
  };
  ASSERT_FALSE(net_cksum_verify(hdr, 20));
}

/* ── Incremental update (RFC 1624) ────────────────────────────────── */

TEST(test_cksum_update_ttl_decrement) {
  /* REQ-CKSUM-012/013: incremental update when TTL changes */
  uint8_t hdr[] = {
      0x45, 0x00, 0x00, 0x2C, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06,
      0x00, 0x00, 0x0A, 0x00, 0x00, 0x02, 0x0A, 0x00, 0x00, 0x01,
  };

  /* Compute original checksum */
  uint16_t cksum = net_cksum(hdr, 20);
  hdr[10] = (uint8_t)(cksum >> 8);
  hdr[11] = (uint8_t)(cksum);

  /* Decrement TTL: 0x40 → 0x3F */
  /* The 16-bit word at offset 8 is {TTL, Protocol} = {0x40, 0x06} → {0x3F,
   * 0x06} */
  uint16_t old_word = 0x4006;
  uint16_t new_word = 0x3F06;

  uint16_t new_cksum = net_cksum_update(cksum, old_word, new_word);

  /* Apply changes */
  hdr[8] = 0x3F;
  hdr[10] = (uint8_t)(new_cksum >> 8);
  hdr[11] = (uint8_t)(new_cksum);

  /* Verify the updated header */
  ASSERT_TRUE(net_cksum_verify(hdr, 20));
}

/* ── Carry folding test ───────────────────────────────────────────── */

TEST(test_cksum_carry_folding) {
  /* REQ-CKSUM-003: data that produces carries during folding */
  uint8_t data[] = {0xFF, 0xFF, 0xFF, 0xFF};
  /* sum = 0xFFFF + 0xFFFF = 0x1FFFE → fold → 0xFFFF + 1 = 0x10000 → fold → 1 */
  /* complement = 0xFFFE ... let me compute more carefully */
  /* Actually: 0xFFFF + 0xFFFF = 0x1FFFE, fold: 0xFFFE + 1 = 0xFFFF, complement
   * = 0x0000 */
  uint16_t result = net_cksum(data, 4);
  ASSERT_EQ(result, 0x0000);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void) {
  fprintf(stderr, "=== test_checksum ===\n");

  RUN_TEST(test_cksum_init);
  RUN_TEST(test_cksum_zero_length);
  RUN_TEST(test_cksum_two_bytes);
  RUN_TEST(test_cksum_odd_byte);
  RUN_TEST(test_cksum_known_ipv4_header);
  RUN_TEST(test_cksum_incremental_equals_oneshot);
  RUN_TEST(test_cksum_add_u16);
  RUN_TEST(test_cksum_add_u32);
  RUN_TEST(test_cksum_verify_valid);
  RUN_TEST(test_cksum_verify_invalid);
  RUN_TEST(test_cksum_update_ttl_decrement);
  RUN_TEST(test_cksum_carry_folding);

  TEST_REPORT();
  return test_failures;
}
