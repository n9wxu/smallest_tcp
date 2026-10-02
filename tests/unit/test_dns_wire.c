/**
 * @file test_dns_wire.c
 * @brief The DNS wire-format functions of dns_wire.h (RFC 1035 §3-4):
 *        names written, compressed, compared and decoded, questions and
 *        records read, the writer's bounds.
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

/* REQ-MDNS-003 */
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

/* REQ-MDNS-003 */
TEST(test_name_root) {
  fresh();
  ASSERT_EQ(dns_write_name(&w, "."), 0);
  ASSERT_EQ(w.len, 1);
  ASSERT_EQ(buf[0], 0);
  fresh();
  ASSERT_EQ(dns_write_name(&w, ""), 0);
  ASSERT_EQ(w.len, 1);
}

/* REQ-MDNS-003, REQ-DNSSD-034: DNS-SD instance labels may contain spaces */
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

/* REQ-MDNS-051, REQ-DNSSD-031 */
TEST(test_name_wire_len) {
  ASSERT_EQ(dns_name_wire_len("pyro-dead01.local"), 19);
  ASSERT_EQ(dns_name_wire_len("pyro-dead01.local."), 19);
  ASSERT_EQ(dns_name_wire_len("."), 1);
  ASSERT_EQ(dns_name_wire_len("a..local"), -2);
}

/* REQ-DNSSD-031 */
TEST(test_name_empty_label_rejected) {
  fresh();
  ASSERT_EQ(dns_write_name(&w, "a..local"), -2);
  ASSERT_EQ(dns_write_name(&w, ".local"), -2);
  ASSERT_EQ(w.len, 0);
}

/* ── Compression (REQ-MDNS-043) ───────────────────────────────────── */

/* REQ-MDNS-043 */
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

/* REQ-MDNS-043 */
TEST(test_compress_whole_name) {
  fresh();
  ASSERT_EQ(dns_write_name(&w, "_pyro._tcp.local"), 0);
  uint16_t second = w.len;
  ASSERT_EQ(dns_write_name(&w, "_PYRO._tcp.LOCAL."), 0); /* case differs */
  ASSERT_EQ(w.len, second + 2);
  ASSERT_EQ(buf[second], 0xC0);
  ASSERT_EQ(buf[second + 1], 0);
}

/* REQ-MDNS-043: a name that extends an earlier one points at the earlier name
 */
TEST(test_compress_prefix_label) {
  fresh();
  ASSERT_EQ(dns_write_name(&w, "_pyro._tcp.local"), 0);
  uint16_t second = w.len;
  ASSERT_EQ(dns_write_name(&w, "Pyro Unit 1._pyro._tcp.local"), 0);
  ASSERT_EQ(w.len, second + 1 + 11 + 2);
  ASSERT_EQ(buf[second + 12], 0xC0);
  ASSERT_EQ(buf[second + 13], 0);
}

/* REQ-MDNS-043: compression targets recorded after the header use message
 * offsets */
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

/* REQ-MDNS-042 */
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

/* REQ-MDNS-042 */
TEST(test_writer_name_overflow_writes_nothing) {
  uint8_t small[10];
  dns_writer_init(&w, small, sizeof(small));
  ASSERT_EQ(dns_write_name(&w, "pyro-dead01.local"), -1);
  ASSERT_EQ(w.len, 0);
  ASSERT_EQ(w.overflow, 1);
}

/* REQ-MDNS-042, 043 */
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

/* REQ-MDNS-003 */
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

/* REQ-MDNS-048 */
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

/* REQ-MDNS-048 */
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

/* REQ-MDNS-048 */
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

/* REQ-MDNS-041: robustness: a pointer loop must be rejected, not followed
 * forever */
TEST(test_pointer_loop_rejected) {
  char out[64];
  uint8_t msg[] = {1, 'a', 0xC0, 0x00}; /* "a" then pointer back to 0 */
  ASSERT_EQ(dns_name_decode(msg, sizeof(msg), 0, out, sizeof(out)), -1);
  ASSERT_EQ(dns_name_equals(msg, sizeof(msg), 0, "a.a.a"), 0);
  /* skip does not follow pointers, so it can still step over this name */
  ASSERT_EQ(dns_name_skip(msg, sizeof(msg), 0), 4);
}

/* REQ-MDNS-041 */
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

/* REQ-MDNS-003 */
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

/* REQ-MDNS-003 */
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

/* ── Dotted names, flat names, the order of rdata ─────────────────── */

/* REQ-MDNS-003: two dotted names compare label by label, without case,
 * the trailing dot optional */
TEST(test_dotted_equal) {
  ASSERT_TRUE(dns_dotted_equal("Pyro-Dead01.local.", "pyro-dead01.LOCAL"));
  ASSERT_TRUE(dns_dotted_equal(".", ""));
  ASSERT_FALSE(dns_dotted_equal("pyro.local", "pyro.locals"));
  ASSERT_FALSE(dns_dotted_equal("pyro.local", "pyro"));
  ASSERT_FALSE(dns_dotted_equal("a..local", "a..local")); /* not a name */
}

/* REQ-MDNS-043: a name written flat is spelled out in full, though an
 * earlier name could be pointed to; later names may point into it */
TEST(test_name_flat_is_not_compressed) {
  static const uint8_t flat[] = {4,   'h', 'o', 's', 't', 5,
                                 'l', 'o', 'c', 'a', 'l', 0};
  fresh();
  ASSERT_EQ(dns_write_name(&w, "other.local"), 0);
  uint16_t at = w.len;
  ASSERT_EQ(dns_write_name_flat(&w, "host.local"), 0);
  ASSERT_EQ(w.len - at, (int)sizeof(flat));
  ASSERT_MEM_EQ(buf + at, flat, sizeof(flat));
  uint16_t next = w.len;
  ASSERT_EQ(dns_write_name(&w, "host.local"), 0);
  ASSERT_EQ(w.len - next, 2);
  ASSERT_EQ(dns_write_name_flat(&w, "a..b"), -2);
}

/* A record of @p type written at the end of the message: its rdata is
 * @p head bytes of @p fixed, then @p name (compressed if it can be) */
static dns_rr_t rr_with_name(uint16_t type, const uint8_t *fixed, uint16_t head,
                             const char *name) {
  dns_rr_t rr;
  rr.name_off = 0;
  rr.type = type;
  rr.class_ = DNS_CLASS_IN;
  rr.ttl = 120;
  rr.rdata_off = w.len;
  dns_write_bytes(&w, fixed, head);
  dns_write_name(&w, name);
  rr.rdlen = (uint16_t)(w.len - rr.rdata_off);
  return rr;
}

/* REQ-MDNS-055: rdata is ordered byte by byte with its names uncompressed
 * (RFC 6762 §8.2) — in the types whose rdata holds a name, wherever it
 * starts; the rdata that ends first is the earlier */
TEST(test_rdata_compare_uncompresses_names) {
  static const uint8_t pref[6] = {0, 10, 0, 0, 0, 80};
  static uint8_t other[128];
  dns_writer_t o;
  dns_rr_t a, b;
  fresh();
  ASSERT_EQ(dns_write_name(&w, "zeta.local"), 0);
  /* PTR: a pointer (0xC0...) against the same name spelled out */
  a = rr_with_name(DNS_TYPE_PTR, pref, 0, "zeta.local");
  ASSERT_EQ(a.rdlen, 2);
  dns_writer_init(&o, other, sizeof(other));
  b.type = DNS_TYPE_PTR;
  b.rdata_off = 0;
  dns_write_name(&o, "zeta.local");
  b.rdlen = o.len;
  ASSERT_EQ(dns_rdata_compare(buf, w.len, &a, other, o.len, &b), 0);
  /* its pointer's 0xC0 would sort it after any name spelled out;
   * uncompressed, "zeta" is earlier than "zulu" and later than "alfa" */
  dns_writer_init(&o, other, sizeof(other));
  dns_write_name(&o, "zulu.local");
  b.rdlen = o.len;
  ASSERT_TRUE(dns_rdata_compare(buf, w.len, &a, other, o.len, &b) < 0);
  ASSERT_TRUE(dns_rdata_compare(other, o.len, &b, buf, w.len, &a) > 0);
  dns_writer_init(&o, other, sizeof(other));
  dns_write_name(&o, "alfa.local");
  b.rdlen = o.len;
  ASSERT_TRUE(dns_rdata_compare(buf, w.len, &a, other, o.len, &b) > 0);
  /* SRV: the name after six bytes; MX: after two */
  a = rr_with_name(DNS_TYPE_SRV, pref, 6, "zeta.local");
  dns_writer_init(&o, other, sizeof(other));
  dns_write_bytes(&o, pref, 6);
  dns_write_name(&o, "zeta.local");
  b.type = DNS_TYPE_SRV;
  b.rdlen = o.len;
  ASSERT_EQ(dns_rdata_compare(buf, w.len, &a, other, o.len, &b), 0);
  a = rr_with_name(15 /* MX */, pref, 2, "zeta.local");
  dns_writer_init(&o, other, sizeof(other));
  dns_write_bytes(&o, pref, 2);
  dns_write_name(&o, "zeta.local");
  b.type = 15;
  b.rdlen = o.len;
  ASSERT_EQ(dns_rdata_compare(buf, w.len, &a, other, o.len, &b), 0);
  a = rr_with_name(5 /* CNAME */, pref, 0, "zeta.local");
  dns_writer_init(&o, other, sizeof(other));
  dns_write_name(&o, "zeta.local");
  b.type = 5;
  b.rdlen = o.len;
  ASSERT_EQ(dns_rdata_compare(buf, w.len, &a, other, o.len, &b), 0);
  /* TXT: no name in it — bytes as they are; the shorter is the earlier */
  a = rr_with_name(DNS_TYPE_TXT, (const uint8_t *)"\x03x=1", 4, "");
  a.rdlen = 4;
  b.type = DNS_TYPE_TXT;
  b.rdata_off = 0;
  b.rdlen = 5;
  ASSERT_TRUE(dns_rdata_compare(buf, w.len, &a, (const uint8_t *)"\x03x=1z", 5,
                                &b) < 0);
}

int main(void) {
  RUN_TEST(test_name_encode_uncompressed);
  RUN_TEST(test_name_trailing_dot_equivalent);
  RUN_TEST(test_name_root);
  RUN_TEST(test_name_label_with_spaces);
  RUN_TEST(test_name_label_too_long);
  RUN_TEST(test_name_wire_len);
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
  RUN_TEST(test_dotted_equal);
  RUN_TEST(test_name_flat_is_not_compressed);
  RUN_TEST(test_rdata_compare_uncompresses_names);
  TEST_REPORT();
  return test_failures;
}
