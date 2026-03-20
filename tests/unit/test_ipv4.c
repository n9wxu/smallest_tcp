/**
 * @file test_ipv4.c
 * @brief Unit tests for IPv4 (RFC 791).
 */

#include "ipv4.h"
#include "net.h"
#include "net_cksum.h"
#include "net_endian.h"
#include "test_main.h"
#include <string.h>

/* ── Helper: build a valid IPv4 header in buf ─────────────────────── */

static void make_valid_ipv4(uint8_t *buf, uint16_t payload_len,
                            uint8_t protocol, uint32_t src, uint32_t dst) {
  ipv4_build(buf, payload_len, protocol, src, dst);
}

/* ── Tests ────────────────────────────────────────────────────────── */

TEST(test_ipv4_parse_valid) {
  uint8_t pkt[60];
  memset(pkt, 0, sizeof(pkt));
  make_valid_ipv4(pkt, 10, IPV4_PROTO_UDP, NET_IPV4(10, 0, 0, 1),
                  NET_IPV4(10, 0, 0, 2));

  ipv4_hdr_t hdr;
  ASSERT_EQ(ipv4_parse(pkt, 30, &hdr), NET_OK);
  ASSERT_EQ(hdr.ihl, 5);
  ASSERT_EQ(hdr.protocol, IPV4_PROTO_UDP);
  ASSERT_EQ(hdr.total_len, 30);
  ASSERT_EQ(hdr.src_ip, NET_IPV4(10, 0, 0, 1));
  ASSERT_EQ(hdr.dst_ip, NET_IPV4(10, 0, 0, 2));
  ASSERT_EQ(hdr.payload_len, 10);
  ASSERT_EQ(hdr.header_len, 20);
}

TEST(test_ipv4_parse_too_short) {
  uint8_t pkt[10];
  memset(pkt, 0, sizeof(pkt));
  ipv4_hdr_t hdr;
  ASSERT_NE(ipv4_parse(pkt, 10, &hdr), NET_OK);
}

TEST(test_ipv4_parse_bad_version) {
  uint8_t pkt[40];
  memset(pkt, 0, sizeof(pkt));
  make_valid_ipv4(pkt, 10, IPV4_PROTO_ICMP, NET_IPV4(10, 0, 0, 1),
                  NET_IPV4(10, 0, 0, 2));
  pkt[0] = 0x65; /* version=6, IHL=5 */
  /* Recompute checksum */
  net_write16be(pkt + IPV4_OFF_CKSUM, 0);
  net_write16be(pkt + IPV4_OFF_CKSUM, net_cksum(pkt, 20));
  ipv4_hdr_t hdr;
  ASSERT_NE(ipv4_parse(pkt, 30, &hdr), NET_OK);
}

TEST(test_ipv4_parse_bad_ihl) {
  uint8_t pkt[40];
  memset(pkt, 0, sizeof(pkt));
  make_valid_ipv4(pkt, 10, IPV4_PROTO_ICMP, NET_IPV4(10, 0, 0, 1),
                  NET_IPV4(10, 0, 0, 2));
  pkt[0] = 0x43; /* version=4, IHL=3 (invalid) */
  net_write16be(pkt + IPV4_OFF_CKSUM, 0);
  net_write16be(pkt + IPV4_OFF_CKSUM, net_cksum(pkt, 20));
  ipv4_hdr_t hdr;
  ASSERT_NE(ipv4_parse(pkt, 30, &hdr), NET_OK);
}

TEST(test_ipv4_parse_bad_checksum) {
  uint8_t pkt[40];
  memset(pkt, 0, sizeof(pkt));
  make_valid_ipv4(pkt, 10, IPV4_PROTO_UDP, NET_IPV4(10, 0, 0, 1),
                  NET_IPV4(10, 0, 0, 2));
  /* Corrupt checksum */
  pkt[IPV4_OFF_CKSUM] ^= 0xFF;
  ipv4_hdr_t hdr;
  ASSERT_NE(ipv4_parse(pkt, 30, &hdr), NET_OK);
}

TEST(test_ipv4_parse_rejects_fragments) {
  uint8_t pkt[40];
  memset(pkt, 0, sizeof(pkt));
  make_valid_ipv4(pkt, 10, IPV4_PROTO_UDP, NET_IPV4(10, 0, 0, 1),
                  NET_IPV4(10, 0, 0, 2));
  /* Set MF flag */
  net_write16be(pkt + IPV4_OFF_FLAGS_FRAG, IPV4_FLAG_MF);
  net_write16be(pkt + IPV4_OFF_CKSUM, 0);
  net_write16be(pkt + IPV4_OFF_CKSUM, net_cksum(pkt, 20));
  ipv4_hdr_t hdr;
  ASSERT_NE(ipv4_parse(pkt, 30, &hdr), NET_OK);
}

TEST(test_ipv4_build_valid) {
  uint8_t buf[40];
  memset(buf, 0, sizeof(buf));
  ipv4_build(buf, 8, IPV4_PROTO_ICMP, NET_IPV4(10, 0, 0, 2),
             NET_IPV4(10, 0, 0, 1));

  ASSERT_EQ(buf[0], 0x45); /* Version=4, IHL=5 */
  ASSERT_EQ(buf[IPV4_OFF_TOS], 0);
  ASSERT_EQ(net_read16be(buf + IPV4_OFF_TOTLEN), 28);
  ASSERT_EQ(net_read16be(buf + IPV4_OFF_FLAGS_FRAG), IPV4_FLAG_DF);
  ASSERT_EQ(buf[IPV4_OFF_TTL], 64);
  ASSERT_EQ(buf[IPV4_OFF_PROTO], IPV4_PROTO_ICMP);
  ASSERT_EQ(net_read32be(buf + IPV4_OFF_SRC), NET_IPV4(10, 0, 0, 2));
  ASSERT_EQ(net_read32be(buf + IPV4_OFF_DST), NET_IPV4(10, 0, 0, 1));
  /* Verify checksum */
  ASSERT_TRUE(net_cksum_verify(buf, 20));
}

TEST(test_ipv4_build_parse_roundtrip) {
  uint8_t buf[60];
  memset(buf, 0xAA, sizeof(buf));
  ipv4_build(buf, 20, IPV4_PROTO_TCP, NET_IPV4(192, 168, 1, 100),
             NET_IPV4(8, 8, 8, 8));

  ipv4_hdr_t hdr;
  ASSERT_EQ(ipv4_parse(buf, 40, &hdr), NET_OK);
  ASSERT_EQ(hdr.protocol, IPV4_PROTO_TCP);
  ASSERT_EQ(hdr.src_ip, NET_IPV4(192, 168, 1, 100));
  ASSERT_EQ(hdr.dst_ip, NET_IPV4(8, 8, 8, 8));
  ASSERT_EQ(hdr.payload_len, 20);
}

TEST(test_ipv4_is_broadcast) {
  net_t n;
  memset(&n, 0, sizeof(n));
  n.ipv4_addr = NET_IPV4(10, 0, 0, 2);
  n.subnet_mask = NET_IPV4(255, 255, 255, 0);

  ASSERT_TRUE(ipv4_is_broadcast(&n, 0xFFFFFFFFu));
  ASSERT_TRUE(ipv4_is_broadcast(&n, NET_IPV4(10, 0, 0, 255)));
  ASSERT_FALSE(ipv4_is_broadcast(&n, NET_IPV4(10, 0, 0, 1)));
}

TEST(test_ipv4_is_local) {
  net_t n;
  memset(&n, 0, sizeof(n));
  n.ipv4_addr = NET_IPV4(10, 0, 0, 2);
  n.subnet_mask = NET_IPV4(255, 255, 255, 0);

  ASSERT_TRUE(ipv4_is_local(&n, NET_IPV4(10, 0, 0, 100)));
  ASSERT_FALSE(ipv4_is_local(&n, NET_IPV4(192, 168, 1, 1)));
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void) {
  fprintf(stderr, "=== test_ipv4 ===\n");
  RUN_TEST(test_ipv4_parse_valid);
  RUN_TEST(test_ipv4_parse_too_short);
  RUN_TEST(test_ipv4_parse_bad_version);
  RUN_TEST(test_ipv4_parse_bad_ihl);
  RUN_TEST(test_ipv4_parse_bad_checksum);
  RUN_TEST(test_ipv4_parse_rejects_fragments);
  RUN_TEST(test_ipv4_build_valid);
  RUN_TEST(test_ipv4_build_parse_roundtrip);
  RUN_TEST(test_ipv4_is_broadcast);
  RUN_TEST(test_ipv4_is_local);
  TEST_REPORT();
  return test_failures;
}
