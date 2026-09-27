/**
 * @file test_dtls.c
 * @brief DTLS 1.3 (RFC 9147): records — the unified header, record number
 *        encryption, sequence number reconstruction, the replay window —
 *        with the Mbed TLS backend.
 */

#include "dtls.h"
#include "test_main.h"
#include "tls_crypto_mbedtls.h"
#include "tls_dtls13.h"
#include "tls_rfc8448.h"
#include <string.h>

static tls_mbedtls_t be;
static tls_crypto_t c;

/* The keys of one epoch, as each side derives them from its secret */
static void keys(dtls_keys_t *k) { dtls_keys_derive(&c, r3_s_hs_traffic, k); }

/* A record as the RFC describes it, built from the backend's primitives:
 * the header's sequence bits (@p seq_len 1 or 2, with or without the
 * length) are the plaintext ones in the AEAD's additional data and masked
 * on the wire.  Returns the record length. */
static size_t build_record(const dtls_keys_t *k, uint8_t epoch_bits,
                           uint64_t seq, int seq_len, int with_len,
                           uint8_t type, const uint8_t *content, size_t n,
                           size_t padding, uint8_t *out) {
  uint8_t nonce[12], mask[16];
  size_t h = 0, i, inner = n + 1 + padding;
  uint64_t s = seq;
  out[h++] = (uint8_t)(0x20 | (seq_len == 2 ? 0x08 : 0) |
                       (with_len ? 0x04 : 0) | (epoch_bits & 3));
  if (seq_len == 2)
    out[h++] = (uint8_t)(seq >> 8);
  out[h++] = (uint8_t)seq;
  if (with_len) {
    out[h++] = (uint8_t)((inner + 16) >> 8);
    out[h++] = (uint8_t)(inner + 16);
  }
  memcpy(out + h, content, n);
  out[h + n] = type;
  memset(out + h + n + 1, 0, padding);
  memcpy(nonce, k->k.iv, 12);
  for (i = 11; i >= 4; i--) {
    nonce[i] ^= (uint8_t)s;
    s >>= 8;
  }
  c.aead_seal(k->k.key, nonce, out, h, out + h, inner, out + h,
              out + h + inner);
  c.aes_block(k->sn, out + h, mask);
  out[1] ^= mask[0];
  if (seq_len == 2)
    out[2] ^= mask[1];
  return h + inner + 16;
}

/* Open @p rec with @p k; the content length, or -1 */
static int open_record(dtls_keys_t *k, const uint8_t *rec, size_t len,
                       uint8_t *out, uint8_t *type, uint64_t *seq) {
  dtls_rec_t r;
  if (dtls_record_parse(rec, len, &r) != 0)
    return -2;
  return dtls_record_open(&c, k, rec, &r, out, type, seq);
}

/* ══ Keys ═════════════════════════════════════════════════════════ */

TEST(test_keys_from_secret) {
  dtls_keys_t k;
  keys(&k);
  ASSERT_MEM_EQ(k.k.key, d13_key, 16);
  ASSERT_MEM_EQ(k.k.iv, d13_iv, 12);
  ASSERT_MEM_EQ(k.sn, d13_sn, 16);
  ASSERT_TRUE(k.k.seq == 0 && k.window == 0);
}

/* ══ Sealing ══════════════════════════════════════════════════════ */

/* 0x2C | epoch bits: fixed bits 001, no CID, 16-bit sequence number,
 * length present; the rest exactly as the RFC builds it */
TEST(test_seal_as_rfc_describes) {
  static const uint8_t hello[5] = {'h', 'e', 'l', 'l', 'o'};
  dtls_keys_t w, ref;
  uint8_t rec[64], want[64];
  size_t n, wn;
  keys(&w);
  keys(&ref);
  w.k.seq = 0x1234;
  memcpy(rec + DTLS_RECORD_HDR, hello, 5);
  n = dtls_record_seal(&c, &w, 7, TLS_CT_APPLICATION_DATA, rec, 5);
  wn = build_record(&ref, 7, 0x1234, 2, 1, TLS_CT_APPLICATION_DATA, hello, 5, 0,
                    want);
  ASSERT_EQ(n, 5 + DTLS_RECORD_OVERHEAD);
  ASSERT_EQ(n, wn);
  ASSERT_EQ(rec[0], 0x2F);
  ASSERT_MEM_EQ(rec, want, n);
  ASSERT_TRUE(w.k.seq == 0x1235);
}

/* The record number on the wire is masked: two records with consecutive
 * numbers do not show them */
TEST(test_seal_masks_the_record_number) {
  dtls_keys_t w;
  uint8_t a[64], b[64];
  keys(&w);
  memset(a + DTLS_RECORD_HDR, 'x', 4);
  memset(b + DTLS_RECORD_HDR, 'x', 4);
  dtls_record_seal(&c, &w, 3, TLS_CT_APPLICATION_DATA, a, 4);
  dtls_record_seal(&c, &w, 3, TLS_CT_APPLICATION_DATA, b, 4);
  ASSERT_FALSE(a[1] == 0 && a[2] == 0 && b[1] == 0 && b[2] == 1);
}

/* ══ Opening ══════════════════════════════════════════════════════ */

TEST(test_open_what_was_sealed) {
  dtls_keys_t w, r;
  uint8_t rec[64], out[64], type = 0;
  uint64_t seq = 99;
  int n;
  keys(&w);
  keys(&r);
  memcpy(rec + DTLS_RECORD_HDR, "ping", 4);
  dtls_record_seal(&c, &w, 2, TLS_CT_HANDSHAKE, rec, 4);
  n = open_record(&r, rec, 4 + DTLS_RECORD_OVERHEAD, out, &type, &seq);
  ASSERT_EQ(n, 4);
  ASSERT_MEM_EQ(out, "ping", 4);
  ASSERT_EQ(type, TLS_CT_HANDSHAKE);
  ASSERT_TRUE(seq == 0 && r.k.seq == 1 && r.window == 1);
}

/* REQ-DTLS-012: an 8-bit sequence number, and no length — the record
 * takes the rest of the datagram */
TEST(test_open_short_header) {
  dtls_keys_t k, r;
  uint8_t rec[64], out[64], type;
  uint64_t seq;
  dtls_rec_t h;
  size_t n;
  keys(&k);
  keys(&r);
  n = build_record(&k, 2, 0, 1, 0, TLS_CT_HANDSHAKE, (const uint8_t *)"abc", 3,
                   0, rec);
  ASSERT_EQ(dtls_record_parse(rec, n, &h), 0);
  ASSERT_EQ(h.hlen, 2);
  ASSERT_EQ(h.len, n - 2);
  ASSERT_EQ(h.epoch, 2);
  ASSERT_EQ(dtls_record_open(&c, &r, rec, &h, out, &type, &seq), 3);
  ASSERT_MEM_EQ(out, "abc", 3);
}

/* With a length, the record ends there: what follows is the next one */
TEST(test_parse_uses_the_length) {
  dtls_keys_t k;
  uint8_t rec[128];
  dtls_rec_t h;
  size_t n;
  keys(&k);
  n = build_record(&k, 3, 5, 1, 1, TLS_CT_APPLICATION_DATA,
                   (const uint8_t *)"abc", 3, 0, rec);
  memset(rec + n, 0xAA, 20); /* another record's bytes */
  ASSERT_EQ(dtls_record_parse(rec, n + 20, &h), 0);
  ASSERT_EQ(h.hlen, 4);
  ASSERT_EQ(h.len, n - 4);
}

/* REQ-DTLS-013, -014: a CID we never negotiated, a first byte that is no
 * DTLSCiphertext, a header or length running past the datagram */
TEST(test_parse_refuses) {
  uint8_t rec[40];
  dtls_rec_t h;
  memset(rec, 0, sizeof(rec));
  rec[0] = 0x3C; /* C set */
  ASSERT_EQ(dtls_record_parse(rec, sizeof(rec), &h), -1);
  rec[0] = 0x4C; /* 010: not DTLS 1.3 ciphertext */
  ASSERT_EQ(dtls_record_parse(rec, sizeof(rec), &h), -1);
  rec[0] = 0x2C; /* header of 5 bytes, only 4 there */
  ASSERT_EQ(dtls_record_parse(rec, 4, &h), -1);
  rec[3] = 0;
  rec[4] = 36; /* 36 bytes claimed, 35 there */
  ASSERT_EQ(dtls_record_parse(rec, 40, &h), -1);
  rec[4] = 35;
  ASSERT_EQ(dtls_record_parse(rec, 40, &h), 0);
}

/* REQ-DTLS-016: less than 16 bytes of ciphertext cannot be unmasked */
TEST(test_open_refuses_short_ciphertext) {
  dtls_keys_t r;
  uint8_t rec[40], out[40], type;
  uint64_t seq;
  memset(rec, 0x55, sizeof(rec));
  rec[0] = 0x2E;
  rec[3] = 0;
  rec[4] = 15;
  keys(&r);
  ASSERT_EQ(open_record(&r, rec, 20, out, &type, &seq), -1);
}

/* REQ-DTLS-022: a forged or damaged record is refused, and the window
 * does not move (§4.5.1) */
TEST(test_open_refuses_tampering) {
  dtls_keys_t w, r;
  uint8_t rec[64], out[64], type;
  uint64_t seq;
  keys(&w);
  keys(&r);
  w.k.seq = 100;
  memcpy(rec + DTLS_RECORD_HDR, "data", 4);
  dtls_record_seal(&c, &w, 3, TLS_CT_APPLICATION_DATA, rec, 4);
  rec[DTLS_RECORD_HDR + 2] ^= 1;
  ASSERT_EQ(open_record(&r, rec, 4 + DTLS_RECORD_OVERHEAD, out, &type, &seq),
            -1);
  ASSERT_TRUE(r.k.seq == 0 && r.window == 0);
  rec[DTLS_RECORD_HDR + 2] ^= 1;
  rec[0] ^= 0x01; /* the header is authenticated */
  ASSERT_EQ(open_record(&r, rec, 4 + DTLS_RECORD_OVERHEAD, out, &type, &seq),
            -1);
}

/* Padding is stripped; a record of nothing but zeros has no type */
TEST(test_open_strips_padding) {
  dtls_keys_t k, r;
  uint8_t rec[64], out[64], type;
  uint64_t seq;
  size_t n;
  keys(&k);
  keys(&r);
  n = build_record(&k, 3, 0, 2, 1, TLS_CT_ALERT, (const uint8_t *)"\x01\x00", 2,
                   7, rec);
  ASSERT_EQ(open_record(&r, rec, n, out, &type, &seq), 2);
  ASSERT_EQ(type, TLS_CT_ALERT);
  n = build_record(&k, 3, 1, 2, 1, 0, NULL, 0, 4, rec);
  ASSERT_EQ(open_record(&r, rec, n, out, &type, &seq), -1);
}

/* ══ Record numbers ═══════════════════════════════════════════════ */

/* REQ-DTLS-017: the number closest to the next one expected */
TEST(test_seq_expand) {
  ASSERT_TRUE(dtls_seq_expand(0, 0x05, 8) == 0x05);
  ASSERT_TRUE(dtls_seq_expand(0x1FE, 0x01, 8) == 0x201); /* wrapped */
  ASSERT_TRUE(dtls_seq_expand(0x1FE, 0xFD, 8) == 0x1FD);
  ASSERT_TRUE(dtls_seq_expand(0x201, 0xFF, 8) == 0x1FF); /* late */
  ASSERT_TRUE(dtls_seq_expand(0x10000, 0xFFFF, 16) == 0xFFFF);
  ASSERT_TRUE(dtls_seq_expand(0x1FFF0, 0x0005, 16) == 0x20005);
  ASSERT_TRUE(dtls_seq_expand(0x10, 0xF0, 8) == 0xF0); /* none below 0 */
  /* half a window either way: forward, as in RFC 9000 §A.3 */
  ASSERT_TRUE(dtls_seq_expand(0x180, 0x00, 8) == 0x200);
}

/* The full number is recovered from its low byte and opens the record */
TEST(test_open_reconstructs_the_number) {
  dtls_keys_t k, r;
  uint8_t rec[64], out[64], type;
  uint64_t seq = 0;
  size_t n;
  keys(&k);
  keys(&r);
  r.k.seq = 0x1FE;
  n = build_record(&k, 3, 0x201, 1, 1, TLS_CT_APPLICATION_DATA,
                   (const uint8_t *)"z", 1, 0, rec);
  ASSERT_EQ(open_record(&r, rec, n, out, &type, &seq), 1);
  ASSERT_TRUE(seq == 0x201 && r.k.seq == 0x202);
}

/* REQ-DTLS-021: duplicates refused, reordering within the window taken,
 * anything older than the window refused */
TEST(test_replay_window) {
  dtls_keys_t k, r;
  uint8_t rec[64], out[64], type;
  uint64_t seq;
  size_t n;
  keys(&k);
  keys(&r);
#define REC(s)                                                                 \
  (n = build_record(&k, 3, (s), 2, 1, TLS_CT_APPLICATION_DATA,                 \
                    (const uint8_t *)"q", 1, 0, rec),                          \
   open_record(&r, rec, n, out, &type, &seq))
  ASSERT_EQ(REC(10), 1);
  ASSERT_EQ(REC(10), -1); /* again */
  ASSERT_EQ(REC(9), 1);   /* late, new */
  ASSERT_EQ(REC(9), -1);
  ASSERT_EQ(REC(50), 1);  /* the window moves */
  ASSERT_EQ(REC(18), -1); /* 32 behind: out of the window */
  ASSERT_EQ(REC(19), 1);  /* 31 behind: in it */
  ASSERT_EQ(REC(49), 1);
  ASSERT_EQ(REC(49), -1);
  ASSERT_EQ(REC(1000), 1); /* a jump past the window clears it */
  ASSERT_EQ(REC(999), 1);
#undef REC
}

int main(void) {
  fprintf(stderr, "=== DTLS 1.3 tests ===\n");
  if (tls_mbedtls_init(&be, &c) != 0) {
    fprintf(stderr, "backend init failed\n");
    return 1;
  }

  RUN_TEST(test_keys_from_secret);
  RUN_TEST(test_seal_as_rfc_describes);
  RUN_TEST(test_seal_masks_the_record_number);
  RUN_TEST(test_open_what_was_sealed);
  RUN_TEST(test_open_short_header);
  RUN_TEST(test_parse_uses_the_length);
  RUN_TEST(test_parse_refuses);
  RUN_TEST(test_open_refuses_short_ciphertext);
  RUN_TEST(test_open_refuses_tampering);
  RUN_TEST(test_open_strips_padding);
  RUN_TEST(test_seq_expand);
  RUN_TEST(test_open_reconstructs_the_number);
  RUN_TEST(test_replay_window);

  tls_mbedtls_free(&be);
  TEST_REPORT();
  return test_failures;
}
