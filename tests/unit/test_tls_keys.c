/**
 * @file test_tls_keys.c
 * @brief TLS 1.3 key schedule (RFC 8446 §7) and record protection (§5.2)
 *        against the RFC 8448 §3 trace, with the Mbed TLS backend; DTLS
 *        1.3's label prefix (RFC 9147 §5.9).
 */

#include "test_main.h"
#include "tls.h"
#include "tls_crypto_mbedtls.h"
#include "tls_dtls13.h"
#include "tls_rfc8448.h"
#include <string.h>

static tls_mbedtls_t be;
static tls_crypto_t c;

static void hash2(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen,
                  uint8_t out[32]) {
  tls_hash_t h;
  c.hash_init(&h);
  c.hash_update(&h, a, alen);
  c.hash_update(&h, b, blen);
  c.hash_peek(&h, out);
}

/* Transcript hash of the §3 handshake messages, first @p n of them:
 * CH, SH, EE, Certificate, CertificateVerify, server Finished, client
 * Finished. */
static void transcript(int n, uint8_t out[32]) {
  const uint8_t *m[7] = {r3_client_hello,      r3_server_hello,
                         r3_encrypted_extensions, r3_certificate,
                         r3_certificate_verify, r3_s_finished,
                         r3_c_finished};
  const size_t len[7] = {sizeof(r3_client_hello),
                         sizeof(r3_server_hello),
                         sizeof(r3_encrypted_extensions),
                         sizeof(r3_certificate),
                         sizeof(r3_certificate_verify),
                         sizeof(r3_s_finished),
                         sizeof(r3_c_finished)};
  tls_hash_t h;
  int i;
  c.hash_init(&h);
  for (i = 0; i < n; i++)
    c.hash_update(&h, m[i], len[i]);
  c.hash_peek(&h, out);
}

/* ══ Key schedule (REQ-TLS-032, 033; the transcript hashes of RFC 8448's
 * messages, REQ-TLS-034) ═════════════════════════════════════════ */

TEST(test_early_secret_no_psk) {
  uint8_t s[32];
  tls_early_secret(&c, NULL, 0, s);
  ASSERT_MEM_EQ(s, r3_early_secret, 32);
}

TEST(test_derive_secret_empty_hash) {
  /* Derive-Secret(early, "derived", "") — the salt of the Handshake
   * Secret; exercises HkdfLabel encoding and the hash of no messages */
  uint8_t d[32];
  tls_derive_secret(&c, 0, r3_early_secret, "derived", NULL, d);
  ASSERT_MEM_EQ(d, r3_derived_hs, 32);
}

TEST(test_ecdhe_shared_secret) {
  uint8_t z[32];
  ASSERT_EQ(c.kx_shared(c.ctx, TLS_GROUP_X25519, r3_s_x25519_priv,
                        r3_c_x25519_pub, 32, z),
            0);
  ASSERT_MEM_EQ(z, r3_ecdhe_shared, 32);
  ASSERT_EQ(c.kx_shared(c.ctx, TLS_GROUP_X25519, r3_c_x25519_priv,
                        r3_s_x25519_pub, 32, z),
            0);
  ASSERT_MEM_EQ(z, r3_ecdhe_shared, 32);
}

TEST(test_handshake_secret) {
  uint8_t s[32];
  memcpy(s, r3_early_secret, 32);
  tls_next_secret(&c, 0, s, r3_ecdhe_shared, 32);
  ASSERT_MEM_EQ(s, r3_handshake_secret, 32);
}

TEST(test_master_secret) {
  uint8_t s[32], d[32];
  tls_derive_secret(&c, 0, r3_handshake_secret, "derived", NULL, d);
  ASSERT_MEM_EQ(d, r3_derived_ms, 32);
  memcpy(s, r3_handshake_secret, 32);
  tls_next_secret(&c, 0, s, NULL, 0);
  ASSERT_MEM_EQ(s, r3_master_secret, 32);
}

TEST(test_handshake_traffic_secrets) {
  uint8_t th[32], s[32];
  hash2(r3_client_hello, sizeof(r3_client_hello), r3_server_hello,
        sizeof(r3_server_hello), th);
  ASSERT_MEM_EQ(th, r3_hash_ch_sh, 32);
  tls_derive_secret(&c, 0, r3_handshake_secret, "c hs traffic", th, s);
  ASSERT_MEM_EQ(s, r3_c_hs_traffic, 32);
  tls_derive_secret(&c, 0, r3_handshake_secret, "s hs traffic", th, s);
  ASSERT_MEM_EQ(s, r3_s_hs_traffic, 32);
}

TEST(test_application_traffic_secrets) {
  uint8_t th[32], s[32];
  transcript(6, th); /* ClientHello .. server Finished */
  ASSERT_MEM_EQ(th, r3_hash_ch_sfin, 32);
  tls_derive_secret(&c, 0, r3_master_secret, "c ap traffic", th, s);
  ASSERT_MEM_EQ(s, r3_c_ap_traffic, 32);
  tls_derive_secret(&c, 0, r3_master_secret, "s ap traffic", th, s);
  ASSERT_MEM_EQ(s, r3_s_ap_traffic, 32);
  tls_derive_secret(&c, 0, r3_master_secret, "exp master", th, s);
  ASSERT_MEM_EQ(s, r3_exp_master, 32);
}

TEST(test_resumption_secrets) {
  uint8_t th[32], s[32];
  transcript(7, th); /* .. client Finished */
  ASSERT_MEM_EQ(th, r3_hash_ch_cfin, 32);
  tls_derive_secret(&c, 0, r3_master_secret, "res master", th, s);
  ASSERT_MEM_EQ(s, r3_res_master, 32);
  /* the ticket's PSK: HKDF-Expand-Label(res master, "resumption", nonce) */
  tls_expand_label(&c, 0, r3_res_master, "resumption", r3_ticket_nonce,
                   sizeof(r3_ticket_nonce), s, 32);
  ASSERT_MEM_EQ(s, r3_resumption_psk, 32);
}

TEST(test_traffic_keys) {
  tls_keys_t k;
  memset(&k, 0xAA, sizeof(k));
  tls_traffic_keys(&c, 0, r3_s_hs_traffic, &k);
  ASSERT_MEM_EQ(k.key, r3_s_hs_key, 16);
  ASSERT_MEM_EQ(k.iv, r3_s_hs_iv, 12);
  ASSERT_TRUE(k.seq == 0);
  tls_traffic_keys(&c, 0, r3_c_hs_traffic, &k);
  ASSERT_MEM_EQ(k.key, r3_c_hs_key, 16);
  ASSERT_MEM_EQ(k.iv, r3_c_hs_iv, 12);
  tls_traffic_keys(&c, 0, r3_s_ap_traffic, &k);
  ASSERT_MEM_EQ(k.key, r3_s_ap_key, 16);
  ASSERT_MEM_EQ(k.iv, r3_s_ap_iv, 12);
  tls_traffic_keys(&c, 0, r3_c_ap_traffic, &k);
  ASSERT_MEM_EQ(k.key, r3_c_ap_key, 16);
  ASSERT_MEM_EQ(k.iv, r3_c_ap_iv, 12);
}

TEST(test_server_finished) {
  uint8_t fk[32], th[32], mac[32];
  tls_expand_label(&c, 0, r3_s_hs_traffic, "finished", NULL, 0, fk, 32);
  ASSERT_MEM_EQ(fk, r3_s_finished_key, 32);
  transcript(5, th); /* .. CertificateVerify */
  tls_finished_mac(&c, 0, r3_s_hs_traffic, th, mac);
  ASSERT_MEM_EQ(mac, r3_s_finished + 4, 32);
}

TEST(test_client_finished) {
  uint8_t fk[32], th[32], mac[32];
  tls_expand_label(&c, 0, r3_c_hs_traffic, "finished", NULL, 0, fk, 32);
  ASSERT_MEM_EQ(fk, r3_c_finished_key, 32);
  transcript(6, th); /* .. server Finished */
  tls_finished_mac(&c, 0, r3_c_hs_traffic, th, mac);
  ASSERT_MEM_EQ(mac, r3_c_finished + 4, 32);
}

TEST(test_key_update) {
  /* RFC 8446 §7.2: HKDF-Expand-Label(secret, "traffic upd", "", 32);
   * expected values computed independently (Python hmac/hashlib) */
  static const uint8_t upd[32] = {
      0x51, 0x92, 0x1b, 0x8a, 0xa3, 0x00, 0x19, 0x76, 0xeb, 0x40, 0x1d,
      0x0a, 0x43, 0x19, 0xa8, 0x51, 0x64, 0x16, 0xa6, 0xc5, 0x60, 0x01,
      0xa3, 0x57, 0xe5, 0xd1, 0x62, 0x03, 0x1e, 0x84, 0xf9, 0x16};
  static const uint8_t key[16] = {0x2e, 0x63, 0xbe, 0x99, 0xd6, 0x7b,
                                  0x39, 0x09, 0x7f, 0xeb, 0x97, 0x86,
                                  0xcf, 0x7a, 0x15, 0xa0};
  static const uint8_t iv[12] = {0x62, 0x8a, 0x0a, 0x82, 0x98, 0xac,
                                 0x95, 0x3b, 0xae, 0xf4, 0x25, 0x5a};
  uint8_t s[32];
  tls_keys_t k;
  memcpy(s, r3_s_ap_traffic, 32);
  tls_update_secret(&c, 0, s);
  ASSERT_MEM_EQ(s, upd, 32);
  tls_traffic_keys(&c, 0, s, &k);
  ASSERT_MEM_EQ(k.key, key, 16);
  ASSERT_MEM_EQ(k.iv, iv, 12);
}

/* ══ RFC 8448 §4: a resumption PSK ═══════════════════════════════ */

TEST(test_psk_early_secret) {
  /* The PSK is §3's ticket's */
  uint8_t s[32];
  ASSERT_MEM_EQ(r4_psk, r3_resumption_psk, 32);
  tls_early_secret(&c, r4_psk, sizeof(r4_psk), s);
  ASSERT_MEM_EQ(s, r4_early_secret, 32);
}

TEST(test_psk_binder) {
  /* Over the ClientHello up to its binders: the RFC's binder, which then
   * completes the ClientHello */
  uint8_t bk[32], h[32], b[32];
  tls_hash_t th;
  tls_derive_secret(&c, 0, r4_early_secret, "res binder", NULL, bk);
  ASSERT_MEM_EQ(bk, r4_binder_key, 32);
  c.hash_init(&th);
  c.hash_update(&th, r4_ch_prefix, sizeof(r4_ch_prefix));
  c.hash_peek(&th, h);
  ASSERT_MEM_EQ(h, r4_binder_hash, 32);
  tls_psk_binder(&c, 0, r4_early_secret, 1, h, b);
  ASSERT_MEM_EQ(b, r4_binder, 32);
  ASSERT_MEM_EQ(r4_client_hello, r4_ch_prefix, sizeof(r4_ch_prefix));
  ASSERT_MEM_EQ(r4_client_hello + sizeof(r4_ch_prefix), "\x00\x21\x20", 3);
  ASSERT_MEM_EQ(r4_client_hello + sizeof(r4_ch_prefix) + 3, r4_binder, 32);
  /* an external PSK's binder uses another label */
  tls_psk_binder(&c, 0, r4_early_secret, 0, h, b);
  ASSERT_TRUE(memcmp(b, r4_binder, 32) != 0);
}

TEST(test_psk_dhe_handshake_secrets) {
  uint8_t s[32], th[32], t2[32];
  memcpy(s, r4_early_secret, 32);
  tls_next_secret(&c, 0, s, r4_ecdhe_shared, 32);
  ASSERT_MEM_EQ(s, r4_handshake_secret, 32);
  hash2(r4_client_hello, sizeof(r4_client_hello), r4_server_hello,
        sizeof(r4_server_hello), th);
  tls_derive_secret(&c, 0, s, "c hs traffic", th, t2);
  ASSERT_MEM_EQ(t2, r4_c_hs_traffic, 32);
  tls_derive_secret(&c, 0, s, "s hs traffic", th, t2);
  ASSERT_MEM_EQ(t2, r4_s_hs_traffic, 32);
  tls_next_secret(&c, 0, s, NULL, 0);
  ASSERT_MEM_EQ(s, r4_master_secret, 32);
}

/* ══ RFC 8448 §5: a HelloRetryRequest ════════════════════════════ */

TEST(test_p256_shared_secret) {
  uint8_t z[32];
  ASSERT_EQ(c.kx_shared(c.ctx, TLS_GROUP_SECP256R1, r5_s_p256_priv,
                        r5_c_p256_pub, 65, z),
            0);
  ASSERT_MEM_EQ(z, r5_ecdhe_shared, 32);
  ASSERT_EQ(c.kx_shared(c.ctx, TLS_GROUP_SECP256R1, r5_c_p256_priv,
                        r5_s_p256_pub, 65, z),
            0);
  ASSERT_MEM_EQ(z, r5_ecdhe_shared, 32);
}

TEST(test_hrr_transcript) {
  /* ClientHello1 becomes message_hash (RFC 8446 §4.4.1); then the
   * HelloRetryRequest, ClientHello2 and ServerHello */
  tls_hash_t th;
  uint8_t h[32], s[32];
  c.hash_init(&th);
  c.hash_update(&th, r5_client_hello1, sizeof(r5_client_hello1));
  tls_transcript_hrr(&c, &th);
  c.hash_update(&th, r5_hrr, sizeof(r5_hrr));
  c.hash_update(&th, r5_client_hello2, sizeof(r5_client_hello2));
  c.hash_update(&th, r5_server_hello, sizeof(r5_server_hello));
  c.hash_peek(&th, h);
  ASSERT_MEM_EQ(h, r5_hash_hs, 32);
  tls_early_secret(&c, NULL, 0, s);
  tls_next_secret(&c, 0, s, r5_ecdhe_shared, 32);
  ASSERT_MEM_EQ(s, r5_handshake_secret, 32);
  tls_derive_secret(&c, 0, s, "c hs traffic", h, h);
  ASSERT_MEM_EQ(h, r5_c_hs_traffic, 32);
}

TEST(test_equal) {
  static const uint8_t a[4] = {1, 2, 3, 4}, b[4] = {1, 2, 3, 5},
                       d[4] = {0, 2, 3, 4};
  ASSERT_EQ(tls_equal(a, a, 4), 1);
  ASSERT_EQ(tls_equal(a, b, 4), 0);
  ASSERT_EQ(tls_equal(a, d, 4), 0); /* a difference early is not lost */
  ASSERT_EQ(tls_equal(a, b, 3), 1);
  ASSERT_EQ(tls_equal(a, b, 0), 1);
}

/* ══ DTLS 1.3: the "dtls13" label prefix (RFC 9147 §5.9, REQ-DTLS-006)
 * Expected values from tests/tls/gen_dtls13.py, an independent HKDF, on
 * RFC 8448 §3's secrets. */

TEST(test_dtls13_labels) {
  uint8_t out[32], secret[32];
  tls_keys_t k;
  tls_derive_secret(&c, 1, r3_handshake_secret, "s hs traffic", r3_hash_ch_sh,
                    out);
  ASSERT_MEM_EQ(out, d13_s_hs_traffic, 32);
  tls_derive_secret(&c, 1, r3_handshake_secret, "derived", NULL, out);
  ASSERT_MEM_EQ(out, d13_derived, 32);
  tls_traffic_keys(&c, 1, r3_s_hs_traffic, &k);
  ASSERT_MEM_EQ(k.key, d13_key, 16);
  ASSERT_MEM_EQ(k.iv, d13_iv, 12);
  tls_expand_label(&c, 1, r3_s_hs_traffic, "sn", NULL, 0, out, 16);
  ASSERT_MEM_EQ(out, d13_sn, 16);
  tls_finished_mac(&c, 1, r3_s_hs_traffic, d13_finished_hash, out);
  ASSERT_MEM_EQ(out, d13_finished, 32);
  memcpy(secret, r3_s_hs_traffic, 32);
  tls_update_secret(&c, 1, secret);
  ASSERT_MEM_EQ(secret, d13_traffic_upd, 32);
}

/* The same derivations under TLS's prefix are RFC 8448's */
TEST(test_dtls13_labels_differ_from_tls) {
  tls_keys_t k;
  tls_traffic_keys(&c, 0, r3_s_hs_traffic, &k);
  ASSERT_MEM_EQ(k.key, r3_s_hs_key, 16);
  ASSERT_TRUE(memcmp(k.key, d13_key, 16) != 0);
}

/* ══ Record protection (REQ-TLS-026, 027: RFC 8448's records byte for
 * byte) ══════════════════════════════════════════════════════════ */

static uint8_t rec[TLS_RECORD_HDR + TLS_MAX_CIPHERTEXT + 64];

/* Seal @p payload as @p type with the keys of @p secret at @p seq; the
 * result must be @p want. */
static int seal_eq(const uint8_t *secret, uint64_t seq, uint8_t type,
                   const uint8_t *payload, size_t len, const uint8_t *want,
                   size_t want_len) {
  tls_keys_t k;
  size_t n;
  tls_traffic_keys(&c, 0, secret, &k);
  k.seq = seq;
  memset(rec, 0xEE, sizeof(rec));
  memcpy(rec + TLS_RECORD_HDR, payload, len);
  n = tls_record_seal(&c, &k, type, rec, len);
  return n == want_len && memcmp(rec, want, n) == 0 && k.seq == seq + 1;
}

TEST(test_seal_server_handshake_flight) {
  /* EncryptedExtensions .. Finished in one record */
  ASSERT_EQ(sizeof(r3_s_hs_payload),
            sizeof(r3_encrypted_extensions) + sizeof(r3_certificate) +
                sizeof(r3_certificate_verify) + sizeof(r3_s_finished));
  ASSERT_TRUE(seal_eq(r3_s_hs_traffic, 0, TLS_CT_HANDSHAKE, r3_s_hs_payload,
                      sizeof(r3_s_hs_payload), r3_s_hs_record,
                      sizeof(r3_s_hs_record)));
}

TEST(test_seal_client_finished) {
  ASSERT_TRUE(seal_eq(r3_c_hs_traffic, 0, TLS_CT_HANDSHAKE, r3_c_finished,
                      sizeof(r3_c_finished), r3_c_fin_record,
                      sizeof(r3_c_fin_record)));
}

TEST(test_seal_server_application_records) {
  /* NewSessionTicket is the server's first application-key record, then
   * data (seq 1), then close_notify (seq 2) */
  ASSERT_TRUE(seal_eq(r3_s_ap_traffic, 0, TLS_CT_HANDSHAKE,
                      r3_new_session_ticket, sizeof(r3_new_session_ticket),
                      r3_nst_record, sizeof(r3_nst_record)));
  ASSERT_TRUE(seal_eq(r3_s_ap_traffic, 1, TLS_CT_APPLICATION_DATA,
                      r3_s_app_payload, sizeof(r3_s_app_payload),
                      r3_s_app_record, sizeof(r3_s_app_record)));
  ASSERT_TRUE(seal_eq(r3_s_ap_traffic, 2, TLS_CT_ALERT, r3_s_alert_payload,
                      sizeof(r3_s_alert_payload), r3_s_alert_record,
                      sizeof(r3_s_alert_record)));
}

TEST(test_seal_client_application_records) {
  ASSERT_TRUE(seal_eq(r3_c_ap_traffic, 0, TLS_CT_APPLICATION_DATA,
                      r3_c_app_payload, sizeof(r3_c_app_payload),
                      r3_c_app_record, sizeof(r3_c_app_record)));
  ASSERT_TRUE(seal_eq(r3_c_ap_traffic, 1, TLS_CT_ALERT, r3_c_alert_payload,
                      sizeof(r3_c_alert_payload), r3_c_alert_record,
                      sizeof(r3_c_alert_record)));
}

TEST(test_open_sequence) {
  /* The server's application-key records in order, one key state */
  tls_keys_t k;
  uint8_t type = 0;
  int n;
  tls_traffic_keys(&c, 0, r3_s_ap_traffic, &k);

  memcpy(rec, r3_nst_record, sizeof(r3_nst_record));
  n = tls_record_open(&c, &k, rec, sizeof(r3_nst_record), &type);
  ASSERT_EQ(n, (int)sizeof(r3_new_session_ticket));
  ASSERT_EQ(type, TLS_CT_HANDSHAKE);
  ASSERT_MEM_EQ(rec + TLS_RECORD_HDR, r3_new_session_ticket, (size_t)n);
  ASSERT_TRUE(k.seq == 1);

  memcpy(rec, r3_s_app_record, sizeof(r3_s_app_record));
  n = tls_record_open(&c, &k, rec, sizeof(r3_s_app_record), &type);
  ASSERT_EQ(n, (int)sizeof(r3_s_app_payload));
  ASSERT_EQ(type, TLS_CT_APPLICATION_DATA);
  ASSERT_MEM_EQ(rec + TLS_RECORD_HDR, r3_s_app_payload, (size_t)n);

  memcpy(rec, r3_s_alert_record, sizeof(r3_s_alert_record));
  n = tls_record_open(&c, &k, rec, sizeof(r3_s_alert_record), &type);
  ASSERT_EQ(n, 2);
  ASSERT_EQ(type, TLS_CT_ALERT);
  ASSERT_MEM_EQ(rec + TLS_RECORD_HDR, r3_s_alert_payload, 2);
  ASSERT_TRUE(k.seq == 3);
}

TEST(test_open_server_handshake_flight) {
  tls_keys_t k;
  uint8_t type = 0;
  int n;
  tls_traffic_keys(&c, 0, r3_s_hs_traffic, &k);
  memcpy(rec, r3_s_hs_record, sizeof(r3_s_hs_record));
  n = tls_record_open(&c, &k, rec, sizeof(r3_s_hs_record), &type);
  ASSERT_EQ(n, (int)sizeof(r3_s_hs_payload));
  ASSERT_EQ(type, TLS_CT_HANDSHAKE);
  ASSERT_MEM_EQ(rec + TLS_RECORD_HDR, r3_s_hs_payload, (size_t)n);
}

TEST(test_open_tampered) {
  /* REQ-TLS-030: any change to header, ciphertext or tag fails */
  static const size_t at[4] = {2, 5, 40, sizeof(r3_c_app_record) - 1};
  int i;
  for (i = 0; i < 4; i++) {
    tls_keys_t k;
    uint8_t type;
    tls_traffic_keys(&c, 0, r3_c_ap_traffic, &k);
    memcpy(rec, r3_c_app_record, sizeof(r3_c_app_record));
    rec[at[i]] ^= 0x01;
    ASSERT_EQ(tls_record_open(&c, &k, rec, sizeof(r3_c_app_record), &type),
              -TLS_ALERT_BAD_RECORD_MAC);
  }
}

TEST(test_open_wrong_sequence) {
  /* REQ-TLS-028/029: the nonce carries the sequence number */
  tls_keys_t k;
  uint8_t type;
  tls_traffic_keys(&c, 0, r3_s_ap_traffic, &k);
  memcpy(rec, r3_s_app_record, sizeof(r3_s_app_record)); /* seq 1 */
  ASSERT_EQ(tls_record_open(&c, &k, rec, sizeof(r3_s_app_record), &type),
            -TLS_ALERT_BAD_RECORD_MAC);
}

TEST(test_open_length_mismatch) {
  tls_keys_t k;
  uint8_t type;
  tls_traffic_keys(&c, 0, r3_c_ap_traffic, &k);
  memcpy(rec, r3_c_app_record, sizeof(r3_c_app_record));
  ASSERT_EQ(tls_record_open(&c, &k, rec, sizeof(r3_c_app_record) - 1, &type),
            -TLS_ALERT_DECODE_ERROR);
}

TEST(test_open_too_short) {
  /* Shorter than a content type plus a tag */
  tls_keys_t k;
  uint8_t type;
  tls_traffic_keys(&c, 0, r3_c_ap_traffic, &k);
  memcpy(rec, "\x17\x03\x03\x00\x10", 5);
  memset(rec + 5, 0, 16);
  ASSERT_EQ(tls_record_open(&c, &k, rec, 21, &type),
            -TLS_ALERT_BAD_RECORD_MAC);
  rec[4] = 15; /* shorter than the tag alone */
  ASSERT_EQ(tls_record_open(&c, &k, rec, 20, &type),
            -TLS_ALERT_BAD_RECORD_MAC);
  ASSERT_EQ(tls_record_open(&c, &k, rec, 4, &type), -TLS_ALERT_DECODE_ERROR);
  ASSERT_TRUE(k.seq == 0);
}

TEST(test_open_not_application_data) {
  /* A protected record always has opaque_type application_data */
  tls_keys_t k;
  uint8_t type;
  tls_traffic_keys(&c, 0, r3_c_ap_traffic, &k);
  memcpy(rec, r3_c_app_record, sizeof(r3_c_app_record));
  rec[0] = TLS_CT_HANDSHAKE;
  ASSERT_EQ(tls_record_open(&c, &k, rec, sizeof(r3_c_app_record), &type),
            -TLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(test_padding_stripped) {
  /* content "hello" | type 0x17 | 00 00 00: seal it as content of type 0
   * so the inner plaintext is hello 17 00 00 00 00 */
  tls_keys_t k;
  uint8_t type = 0;
  size_t n;
  tls_traffic_keys(&c, 0, r3_c_ap_traffic, &k);
  memcpy(rec + 5, "hello\x17\x00\x00\x00", 9);
  n = tls_record_seal(&c, &k, 0, rec, 9);
  ASSERT_EQ(n, (size_t)(9 + TLS_RECORD_OVERHEAD));
  tls_traffic_keys(&c, 0, r3_c_ap_traffic, &k);
  ASSERT_EQ(tls_record_open(&c, &k, rec, n, &type), 5);
  ASSERT_EQ(type, TLS_CT_APPLICATION_DATA);
  ASSERT_MEM_EQ(rec + 5, "hello", 5);
}

TEST(test_all_zero_plaintext) {
  /* No non-zero byte: no content type (RFC 8446 §5.4) */
  tls_keys_t k;
  uint8_t type;
  size_t n;
  tls_traffic_keys(&c, 0, r3_c_ap_traffic, &k);
  memset(rec + 5, 0, 8);
  n = tls_record_seal(&c, &k, 0, rec, 8);
  tls_traffic_keys(&c, 0, r3_c_ap_traffic, &k);
  ASSERT_EQ(tls_record_open(&c, &k, rec, n, &type),
            -TLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(test_open_ciphertext_overflow) {
  /* TLSCiphertext.length > 2^14 + 256 */
  tls_keys_t k;
  uint8_t type;
  size_t len = TLS_MAX_CIPHERTEXT + 1;
  tls_traffic_keys(&c, 0, r3_c_ap_traffic, &k);
  rec[0] = 23;
  rec[1] = 3;
  rec[2] = 3;
  rec[3] = (uint8_t)(len >> 8);
  rec[4] = (uint8_t)len;
  ASSERT_EQ(tls_record_open(&c, &k, rec, len + 5, &type),
            -TLS_ALERT_RECORD_OVERFLOW);
}

TEST(test_open_plaintext_overflow) {
  /* An authentic record whose content exceeds 2^14 bytes */
  tls_keys_t k;
  uint8_t type;
  size_t n;
  tls_traffic_keys(&c, 0, r3_c_ap_traffic, &k);
  memset(rec + 5, 'x', TLS_MAX_PLAINTEXT + 1);
  n = tls_record_seal(&c, &k, TLS_CT_APPLICATION_DATA, rec,
                      TLS_MAX_PLAINTEXT + 1);
  tls_traffic_keys(&c, 0, r3_c_ap_traffic, &k);
  ASSERT_EQ(tls_record_open(&c, &k, rec, n, &type),
            -TLS_ALERT_RECORD_OVERFLOW);
  /* exactly 2^14 is fine */
  tls_traffic_keys(&c, 0, r3_c_ap_traffic, &k);
  memset(rec + 5, 'x', TLS_MAX_PLAINTEXT);
  n = tls_record_seal(&c, &k, TLS_CT_APPLICATION_DATA, rec,
                      TLS_MAX_PLAINTEXT);
  tls_traffic_keys(&c, 0, r3_c_ap_traffic, &k);
  ASSERT_EQ(tls_record_open(&c, &k, rec, n, &type), (int)TLS_MAX_PLAINTEXT);
}

TEST(test_nonce_uses_all_sequence_bytes) {
  /* nonce = iv XOR seq (64-bit, big-endian, right-aligned) — checked
   * against a direct AEAD call */
  tls_keys_t k;
  uint8_t nonce[12], tag[16], want[3 + 16], hdr[5];
  size_t n;
  int i;
  tls_traffic_keys(&c, 0, r3_c_ap_traffic, &k);
  k.seq = 0x0102030405060708ull;
  memcpy(nonce, k.iv, 12);
  for (i = 0; i < 8; i++)
    nonce[4 + i] ^= (uint8_t)(k.seq >> (56 - 8 * i));
  memcpy(want, "ab\x17", 3);
  hdr[0] = 23;
  hdr[1] = 3;
  hdr[2] = 3;
  hdr[3] = 0;
  hdr[4] = 3 + 16;
  c.aead_seal(k.key, nonce, hdr, 5, want, 3, want, tag);
  memcpy(want + 3, tag, 16);

  memcpy(rec + 5, "ab", 2);
  n = tls_record_seal(&c, &k, TLS_CT_APPLICATION_DATA, rec, 2);
  ASSERT_EQ(n, (size_t)(5 + 3 + 16));
  ASSERT_MEM_EQ(rec, hdr, 5);
  ASSERT_MEM_EQ(rec + 5, want, 3 + 16);
  ASSERT_TRUE(k.seq == 0x0102030405060709ull);
}

int main(void) {
  fprintf(stderr, "=== TLS key schedule and record tests (RFC 8448) ===\n");
  if (tls_mbedtls_init(&be, &c) != 0) {
    fprintf(stderr, "backend init failed\n");
    return 1;
  }

  RUN_TEST(test_early_secret_no_psk);
  RUN_TEST(test_derive_secret_empty_hash);
  RUN_TEST(test_ecdhe_shared_secret);
  RUN_TEST(test_handshake_secret);
  RUN_TEST(test_master_secret);
  RUN_TEST(test_handshake_traffic_secrets);
  RUN_TEST(test_application_traffic_secrets);
  RUN_TEST(test_resumption_secrets);
  RUN_TEST(test_traffic_keys);
  RUN_TEST(test_server_finished);
  RUN_TEST(test_client_finished);
  RUN_TEST(test_key_update);
  RUN_TEST(test_psk_early_secret);
  RUN_TEST(test_psk_binder);
  RUN_TEST(test_psk_dhe_handshake_secrets);
  RUN_TEST(test_p256_shared_secret);
  RUN_TEST(test_hrr_transcript);
  RUN_TEST(test_equal);
  RUN_TEST(test_dtls13_labels);
  RUN_TEST(test_dtls13_labels_differ_from_tls);

  RUN_TEST(test_seal_server_handshake_flight);
  RUN_TEST(test_seal_client_finished);
  RUN_TEST(test_seal_server_application_records);
  RUN_TEST(test_seal_client_application_records);
  RUN_TEST(test_open_sequence);
  RUN_TEST(test_open_server_handshake_flight);
  RUN_TEST(test_open_tampered);
  RUN_TEST(test_open_wrong_sequence);
  RUN_TEST(test_open_length_mismatch);
  RUN_TEST(test_open_too_short);
  RUN_TEST(test_open_not_application_data);
  RUN_TEST(test_padding_stripped);
  RUN_TEST(test_all_zero_plaintext);
  RUN_TEST(test_open_ciphertext_overflow);
  RUN_TEST(test_open_plaintext_overflow);
  RUN_TEST(test_nonce_uses_all_sequence_bytes);

  tls_mbedtls_free(&be);
  TEST_REPORT();
  return test_failures;
}
