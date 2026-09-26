/**
 * @file test_dns_wire.c
 * @brief Unit tests for DNS wire-format helpers (RFC 1035 §3-4).
 *
 * Tests REQ-MDNS-003 (DNS wire format), REQ-MDNS-043 (name compression),
 * REQ-DNSSD-031 (label / name length limits).
 */

#include "dns_wire.h"
#include "test_main.h"
#include <string.h>

static uint8_t buf[512];
static dns_writer_t w;

static void fresh(void) {
  memset(buf, 0xAA, sizeof(buf));
  dns_writer_init(&w, buf, sizeof(buf));
}

/* ── Name encoding ────────────────────────────────────────────────── */

/* REQ-MDNS-003: length-prefixed labels terminated by a zero byte */
TEST(test_name_encode_uncompressed) {
  static const uint8_t expect[] = {11,  'p', 'y', 'r', 'o', '-', 'd', 'e', 'a',
                                   'd', '0', '1', 5,   'l', 'o', 'c', 'a', 'l',
                                   0};
  fresh();
  ASSERT_EQ(dns_write_name(&w, "pyro-dead01.local"), 0);
  ASSERT_EQ(w.len, sizeof(expect));
  ASSERT_MEM_EQ(buf, expect, sizeof(expect));
}

TEST(test_name_trailing_dot_equivalent) {
  uint8_t a[64];
  fresh();
  ASSERT_EQ(dns_write_name(&w, "pyro-dead01.local"), 0);
  memcpy(a, buf, w.len);
  uint16_t alen = w.len;
  fresh();
  ASSERT_EQ(dns_write_name(&w, "pyro-dead01.local."), 0);
  ASSERT_EQ(w.len, alen);
  ASSERT_MEM_EQ(buf, a, alen);
}

TEST(test_name_root) {
  fresh();
  ASSERT_EQ(dns_write_name(&w, "."), 0);
  ASSERT_EQ(w.len, 1);
  ASSERT_EQ(buf[0], 0);
  fresh();
  ASSERT_EQ(dns_write_name(&w, ""), 0);
  ASSERT_EQ(w.len, 1);
}

/* DNS-SD instance labels may contain spaces */
TEST(test_name_label_with_spaces) {
  fresh();
  ASSERT_EQ(dns_write_name(&w, "Pyro Unit 1._pyro._tcp.local"), 0);
  ASSERT_EQ(buf[0], 11);
  ASSERT_MEM_EQ(buf + 1, "Pyro Unit 1", 11);
  ASSERT_EQ(buf[12], 5);
  ASSERT_MEM_EQ(buf + 13, "_pyro", 5);
}

/* REQ-DNSSD-031: labels over 63 bytes are rejected */
TEST(test_name_label_too_long) {
  char name[80];
  memset(name, 'a', 64);
  strcpy(name + 64, ".local");
  fresh();
  ASSERT_EQ(dns_write_name(&w, name), -2);
  ASSERT_EQ(w.len, 0);

  /* 63 is the maximum and is accepted */
  memset(name, 'a', 63);
  strcpy(name + 63, ".local");
  fresh();
  ASSERT_EQ(dns_write_name(&w, name), 0);
}

/* REQ-DNSSD-031: wire names over 255 bytes are rejected */
TEST(test_name_too_long) {
  char name[300];
  int i;
  /* 5 labels of 50 chars = 5*51 + 1 = 256 wire bytes */
  for (i = 0; i < 5; i++) {
    memset(name + i * 51, 'b', 50);
    name[i * 51 + 50] = '.';
  }
  name[5 * 51 - 1] = '\0';
  fresh();
  ASSERT_EQ(dns_write_name(&w, name), -2);
  ASSERT_EQ(w.len, 0);
}

TEST(test_name_empty_label_rejected) {
  fresh();
  ASSERT_EQ(dns_write_name(&w, "a..local"), -2);
  ASSERT_EQ(dns_write_name(&w, ".local"), -2);
  ASSERT_EQ(w.len, 0);
}

/* ── Compression (REQ-MDNS-043) ───────────────────────────────────── */

TEST(test_compress_shared_suffix) {
  fresh();
  ASSERT_EQ(dns_write_name(&w, "pyro-dead01.local"), 0); /* offset 0 */
  uint16_t second = w.len;
  ASSERT_EQ(dns_write_name(&w, "other.local"), 0);
  /* "other" label, then pointer to "local" at offset 12 */
  ASSERT_EQ(w.len, second + 1 + 5 + 2);
  ASSERT_EQ(buf[second], 5);
  ASSERT_EQ(buf[second + 6], 0xC0);
  ASSERT_EQ(buf[second + 7], 12);
}

TEST(test_compress_whole_name) {
  fresh();
  ASSERT_EQ(dns_write_name(&w, "_pyro._tcp.local"), 0);
  uint16_t second = w.len;
  ASSERT_EQ(dns_write_name(&w, "_PYRO._tcp.LOCAL."), 0); /* case differs */
  ASSERT_EQ(w.len, second + 2);
  ASSERT_EQ(buf[second], 0xC0);
  ASSERT_EQ(buf[second + 1], 0);
}

/* A name that extends an earlier one points at the earlier name */
TEST(test_compress_prefix_label) {
  fresh();
  ASSERT_EQ(dns_write_name(&w, "_pyro._tcp.local"), 0);
  uint16_t second = w.len;
  ASSERT_EQ(dns_write_name(&w, "Pyro Unit 1._pyro._tcp.local"), 0);
  ASSERT_EQ(w.len, second + 1 + 11 + 2);
  ASSERT_EQ(buf[second + 12], 0xC0);
  ASSERT_EQ(buf[second + 13], 0);
}

/* Compression targets recorded after the header use message offsets */
TEST(test_compress_after_header) {
  fresh();
  ASSERT_EQ(dns_write_header(&w, 0, DNS_FLAG_QR | DNS_FLAG_AA, 0, 2, 0, 0), 0);
  ASSERT_EQ(dns_write_name(&w, "a.local"), 0);
  uint16_t second = w.len;
  ASSERT_EQ(dns_write_name(&w, "b.local"), 0);
  ASSERT_EQ(buf[second + 2], 0xC0);
  ASSERT_EQ(buf[second + 3], DNS_HDR_SIZE + 2); /* "local" label */
}

/* ── Writer bounds + rollback ─────────────────────────────────────── */

TEST(test_writer_overflow_is_sticky) {
  uint8_t small[8];
  dns_writer_init(&w, small, sizeof(small));
  ASSERT_EQ(dns_write_u32(&w, 0x01020304u), 0);
  ASSERT_EQ(dns_write_u32(&w, 0x05060708u), 0);
  ASSERT_EQ(w.len, 8);
  ASSERT_EQ(dns_write_u16(&w, 1), -1);
  ASSERT_EQ(w.overflow, 1);
  ASSERT_EQ(w.len, 8);
  ASSERT_EQ(small[0], 1);
  ASSERT_EQ(small[7], 8);
}

TEST(test_writer_name_overflow_writes_nothing) {
  uint8_t small[10];
  dns_writer_init(&w, small, sizeof(small));
  ASSERT_EQ(dns_write_name(&w, "pyro-dead01.local"), -1);
  ASSERT_EQ(w.len, 0);
  ASSERT_EQ(w.overflow, 1);
}

TEST(test_writer_rollback_forgets_offsets) {
  fresh();
  ASSERT_EQ(dns_write_name(&w, "a.local"), 0);
  dns_writer_mark_t m = dns_writer_mark(&w);
  ASSERT_EQ(dns_write_name(&w, "zzz.example"), 0);
  dns_writer_rollback(&w, m);
  ASSERT_EQ(w.len, m.len);
  /* "example" must not be a compression target any more */
  ASSERT_EQ(dns_write_name(&w, "q.example"), 0);
  ASSERT_EQ(w.len, m.len + 1 + 1 + 1 + 7 + 1);
}

TEST(test_header_and_counts) {
  fresh();
  ASSERT_EQ(dns_write_header(&w, 0x1234, DNS_FLAG_QR, 1, 2, 3, 4), 0);
  ASSERT_EQ(w.len, DNS_HDR_SIZE);
  static const uint8_t expect[] = {0x12, 0x34, 0x80, 0x00, 0, 1,
                                   0,    2,    0,    3,    0, 4};
  ASSERT_MEM_EQ(buf, expect, sizeof(expect));
  dns_set_counts(buf, 0, 9, 0, 7);
  ASSERT_EQ(buf[5], 0);
  ASSERT_EQ(buf[7], 9);
  ASSERT_EQ(buf[11], 7);
}

/* ── Reading names ────────────────────────────────────────────────── */

TEST(test_decode_roundtrip_compressed) {
  char out[64];
  fresh();
  ASSERT_EQ(dns_write_name(&w, "_pyro._tcp.local"), 0);
  uint16_t second = w.len;
  ASSERT_EQ(dns_write_name(&w, "Pyro Unit 1._pyro._tcp.local."), 0);
  ASSERT_EQ(dns_name_decode(buf, w.len, second, out, sizeof(out)), 28);
  ASSERT_TRUE(strcmp(out, "Pyro Unit 1._pyro._tcp.local") == 0);
  ASSERT_EQ(dns_name_skip(buf, w.len, second), w.len);
}

TEST(test_decode_root_and_small_out) {
  char out[8];
  fresh();
  ASSERT_EQ(dns_write_name(&w, "."), 0);
  ASSERT_EQ(dns_name_decode(buf, w.len, 0, out, sizeof(out)), 0);
  ASSERT_EQ(out[0], '\0');
  fresh();
  ASSERT_EQ(dns_write_name(&w, "pyro-dead01.local"), 0);
  ASSERT_EQ(dns_name_decode(buf, w.len, 0, out, sizeof(out)), -1);
}

TEST(test_name_equals) {
  fresh();
  ASSERT_EQ(dns_write_name(&w, "_pyro._tcp.local"), 0);
  uint16_t second = w.len;
  ASSERT_EQ(dns_write_name(&w, "Pyro Unit 1._pyro._tcp.local"), 0);
  ASSERT_EQ(dns_name_equals(buf, w.len, second, "pyro unit 1._PYRO._tcp.local."),
            1);
  ASSERT_EQ(dns_name_equals(buf, w.len, second, "Pyro Unit 1._pyro._tcp"), 0);
  ASSERT_EQ(dns_name_equals(buf, w.len, second,
                            "Pyro Unit 1._pyro._tcp.local.extra"),
            0);
  ASSERT_EQ(dns_name_equals(buf, w.len, second, "Pyro Unit 2._pyro._tcp.local"),
            0);
  ASSERT_EQ(dns_name_equals(buf, w.len, 0, "_pyro._tcp.local"), 1);
}

/* Robustness: a pointer loop must be rejected, not followed forever */
TEST(test_pointer_loop_rejected) {
  char out[64];
  uint8_t msg[] = {1, 'a', 0xC0, 0x00}; /* "a" then pointer back to 0 */
  ASSERT_EQ(dns_name_decode(msg, sizeof(msg), 0, out, sizeof(out)), -1);
  ASSERT_EQ(dns_name_equals(msg, sizeof(msg), 0, "a.a.a"), 0);
  /* skip does not follow pointers, so it can still step over this name */
  ASSERT_EQ(dns_name_skip(msg, sizeof(msg), 0), 4);
}

TEST(test_truncated_and_bad_names_rejected) {
  char out[64];
  uint8_t trunc[] = {5, 'l', 'o', 'c'};              /* label runs off end */
  uint8_t noterm[] = {1, 'a'};                       /* no terminator */
  uint8_t badptr[] = {0xC0, 0x40};                   /* pointer past end */
  uint8_t badtype[] = {0x40, 'a', 0};                /* 01 label type */
  uint8_t cutptr[] = {1, 'a', 0xC0};                 /* half a pointer */
  ASSERT_EQ(dns_name_skip(trunc, sizeof(trunc), 0), -1);
  ASSERT_EQ(dns_name_skip(noterm, sizeof(noterm), 0), -1);
  ASSERT_EQ(dns_name_decode(badptr, sizeof(badptr), 0, out, sizeof(out)), -1);
  ASSERT_EQ(dns_name_skip(badtype, sizeof(badtype), 0), -1);
  ASSERT_EQ(dns_name_skip(cutptr, sizeof(cutptr), 0), -1);
  ASSERT_EQ(dns_name_skip(noterm, sizeof(noterm), 5), -1); /* off past end */
}

/* ── Reading questions and records ────────────────────────────────── */

TEST(test_read_question) {
  dns_question_t q;
  fresh();
  ASSERT_EQ(dns_write_header(&w, 0, 0, 1, 0, 0, 0), 0);
  ASSERT_EQ(dns_write_name(&w, "pyro-dead01.local"), 0);
  ASSERT_EQ(dns_write_u16(&w, DNS_TYPE_A), 0);
  ASSERT_EQ(dns_write_u16(&w, DNS_CLASS_IN | DNS_CLASS_TOPBIT), 0);
  ASSERT_EQ(dns_read_question(buf, w.len, DNS_HDR_SIZE, &q), w.len);
  ASSERT_EQ(q.name_off, DNS_HDR_SIZE);
  ASSERT_EQ(q.type, DNS_TYPE_A);
  ASSERT_EQ(q.class_, DNS_CLASS_IN | DNS_CLASS_TOPBIT);
  /* truncated: no room for type/class */
  ASSERT_EQ(dns_read_question(buf, w.len - 1, DNS_HDR_SIZE, &q), -1);
}

TEST(test_read_rr) {
  dns_rr_t rr;
  static const uint8_t addr[4] = {10, 0, 0, 2};
  fresh();
  ASSERT_EQ(dns_write_name(&w, "pyro-dead01.local"), 0);
  ASSERT_EQ(dns_write_u16(&w, DNS_TYPE_A), 0);
  ASSERT_EQ(dns_write_u16(&w, DNS_CLASS_IN | DNS_CLASS_TOPBIT), 0);
  ASSERT_EQ(dns_write_u32(&w, 120), 0);
  ASSERT_EQ(dns_write_u16(&w, 4), 0);
  ASSERT_EQ(dns_write_bytes(&w, addr, 4), 0);
  ASSERT_EQ(dns_read_rr(buf, w.len, 0, &rr), w.len);
  ASSERT_EQ(rr.type, DNS_TYPE_A);
  ASSERT_EQ(rr.class_, DNS_CLASS_IN | DNS_CLASS_TOPBIT);
  ASSERT_EQ(rr.ttl, 120u);
  ASSERT_EQ(rr.rdlen, 4);
  ASSERT_MEM_EQ(buf + rr.rdata_off, addr, 4);
  /* rdata running past the end of the message is rejected */
  ASSERT_EQ(dns_read_rr(buf, w.len - 1, 0, &rr), -1);
}

int main(void) {
  RUN_TEST(test_name_encode_uncompressed);
  RUN_TEST(test_name_trailing_dot_equivalent);
  RUN_TEST(test_name_root);
  RUN_TEST(test_name_label_with_spaces);
  RUN_TEST(test_name_label_too_long);
  RUN_TEST(test_name_too_long);
  RUN_TEST(test_name_empty_label_rejected);
  RUN_TEST(test_compress_shared_suffix);
  RUN_TEST(test_compress_whole_name);
  RUN_TEST(test_compress_prefix_label);
  RUN_TEST(test_compress_after_header);
  RUN_TEST(test_writer_overflow_is_sticky);
  RUN_TEST(test_writer_name_overflow_writes_nothing);
  RUN_TEST(test_writer_rollback_forgets_offsets);
  RUN_TEST(test_header_and_counts);
  RUN_TEST(test_decode_roundtrip_compressed);
  RUN_TEST(test_decode_root_and_small_out);
  RUN_TEST(test_name_equals);
  RUN_TEST(test_pointer_loop_rejected);
  RUN_TEST(test_truncated_and_bad_names_rejected);
  RUN_TEST(test_read_question);
  RUN_TEST(test_read_rr);
  TEST_REPORT();
  return test_failures;
}
