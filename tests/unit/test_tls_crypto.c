/**
 * @file test_tls_crypto.c
 * @brief Known-answer tests for the Mbed TLS crypto backend of the TLS
 *        layer: SHA-256, HMAC (RFC 4231), HKDF (RFC 5869), AES-128-GCM (GCM
 *        spec test cases 3-4), the AES-128 block (FIPS-197), X25519 (RFC 7748),
 * P-256 ECDH, ECDSA and RSA-PSS signatures, certificate chains, randomness.
 */

#include "test_main.h"
#include "tls.h" /* alert numbers */
#include "tls_crypto.h"
#include "tls_crypto_mbedtls.h"
#include "tls_test_data.h"
#include <stdlib.h>
#include <string.h>

static tls_mbedtls_t be;
static tls_crypto_t c;

/* hex string → bytes; returns length */
static size_t hex(const char *s, uint8_t *out) {
  size_t n = 0;
  while (s[0] && s[1]) {
    unsigned v;
    char b[3] = {s[0], s[1], 0};
    if (b[0] == ' ') {
      s++;
      continue;
    }
    v = (unsigned)strtoul(b, NULL, 16);
    out[n++] = (uint8_t)v;
    s += 2;
  }
  return n;
}

static int eq_hex(const uint8_t *got, size_t n, const char *want) {
  uint8_t w[256];
  return hex(want, w) == n && memcmp(got, w, n) == 0;
}

/* ══ SHA-256 ══════════════════════════════════════════════════════ */

TEST(test_sha256_abc) {
  tls_hash_t h;
  uint8_t d[32];
  c.hash_init(&h);
  c.hash_update(&h, (const uint8_t *)"abc", 3);
  c.hash_peek(&h, d);
  ASSERT_TRUE(eq_hex(d, 32, "ba7816bf8f01cfea414140de5dae2223"
                            "b00361a396177a9cb410ff61f20015ad"));
}

TEST(test_sha256_empty) {
  tls_hash_t h;
  uint8_t d[32];
  c.hash_init(&h);
  c.hash_peek(&h, d);
  ASSERT_TRUE(eq_hex(d, 32, "e3b0c44298fc1c149afbf4c8996fb924"
                            "27ae41e4649b934ca495991b7852b855"));
}

TEST(test_sha256_peek_keeps_running) {
  /* A transcript is hashed at several points without restarting */
  tls_hash_t h;
  uint8_t mid[32], end[32];
  c.hash_init(&h);
  c.hash_update(&h, (const uint8_t *)"ab", 2);
  c.hash_peek(&h, mid);
  c.hash_update(&h, (const uint8_t *)"c", 1);
  c.hash_peek(&h, end);
  ASSERT_TRUE(eq_hex(end, 32, "ba7816bf8f01cfea414140de5dae2223"
                              "b00361a396177a9cb410ff61f20015ad"));
  ASSERT_TRUE(memcmp(mid, end, 32) != 0);
}

/* ══ HMAC-SHA-256 (RFC 4231 test case 1) ══════════════════════════ */

TEST(test_hmac_rfc4231) {
  uint8_t key[20], out[32];
  memset(key, 0x0B, sizeof(key));
  c.hmac(key, 20, (const uint8_t *)"Hi There", 8, out);
  ASSERT_TRUE(eq_hex(out, 32, "b0344c61d8db38535ca8afceaf0bf12b"
                              "881dc200c9833da726e9376c2e32cff7"));
}

/* ══ HKDF (RFC 5869 test case 1) ══════════════════════════════════ */

TEST(test_hkdf_rfc5869) {
  uint8_t ikm[22], salt[13], info[10], prk[32], okm[42];
  memset(ikm, 0x0B, sizeof(ikm));
  hex("000102030405060708090a0b0c", salt);
  hex("f0f1f2f3f4f5f6f7f8f9", info);
  c.hkdf_extract(salt, 13, ikm, 22, prk);
  ASSERT_TRUE(eq_hex(prk, 32, "077709362c2e32df0ddc3f0dc47bba63"
                              "90b6c73bb50f9c3122ec844ad7c2b3e5"));
  c.hkdf_expand(prk, info, 10, okm, 42);
  ASSERT_TRUE(eq_hex(okm, 42, "3cb25f25faacd57a90434f64d0362f2a"
                              "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                              "34007208d5b887185865"));
}

/* ══ AES-128-GCM (McGrew/Viega test cases 3 and 4) ════════════════ */

static const char *GCM_KEY = "feffe9928665731c6d6a8f9467308308";
static const char *GCM_IV = "cafebabefacedbaddecaf888";
static const char *GCM_P =
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
static const char *GCM_C =
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
    "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";

TEST(test_gcm_seal_no_aad) {
  uint8_t key[16], iv[12], p[64], out[64], tag[16];
  hex(GCM_KEY, key);
  hex(GCM_IV, iv);
  hex(GCM_P, p);
  c.aead_seal(key, iv, NULL, 0, p, 64, out, tag);
  ASSERT_TRUE(eq_hex(out, 64, GCM_C));
  ASSERT_TRUE(eq_hex(tag, 16, "4d5c2af327cd64a62cf35abd2ba6fab4"));
}

TEST(test_gcm_seal_with_aad_in_place) {
  uint8_t key[16], iv[12], buf[64], aad[20], tag[16];
  hex(GCM_KEY, key);
  hex(GCM_IV, iv);
  hex(GCM_P, buf);
  hex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad);
  c.aead_seal(key, iv, aad, 20, buf, 60, buf, tag);
  uint8_t want[64];
  hex(GCM_C, want);
  ASSERT_MEM_EQ(buf, want, 60);
  ASSERT_TRUE(eq_hex(tag, 16, "5bc94fbc3221a5db94fae95ae7121a47"));
  /* and back */
  ASSERT_EQ(c.aead_open(key, iv, aad, 20, buf, 60, tag, buf), 0);
  uint8_t p[64];
  hex(GCM_P, p);
  ASSERT_MEM_EQ(buf, p, 60);
}

TEST(test_gcm_open_rejects_tampering) {
  uint8_t key[16], iv[12], p[64], ct[64], tag[16], out[64];
  hex(GCM_KEY, key);
  hex(GCM_IV, iv);
  hex(GCM_P, p);
  c.aead_seal(key, iv, NULL, 0, p, 64, ct, tag);
  tag[0] ^= 1;
  ASSERT_NE(c.aead_open(key, iv, NULL, 0, ct, 64, tag, out), 0);
  tag[0] ^= 1;
  ct[5] ^= 0x80;
  ASSERT_NE(c.aead_open(key, iv, NULL, 0, ct, 64, tag, out), 0);
}

/* ══ AES-128 block (FIPS-197 Appendices B and C.1) — DTLS record
 *    number encryption, RFC 9147 §4.2.3 ════════════════════════════ */

TEST(test_aes_block_fips197) {
  uint8_t key[16], in[16], out[16];
  hex("000102030405060708090a0b0c0d0e0f", key);
  hex("00112233445566778899aabbccddeeff", in);
  c.aes_block(key, in, out);
  ASSERT_TRUE(eq_hex(out, 16, "69c4e0d86a7b0430d8cdb78070b4c55a"));
  hex("2b7e151628aed2a6abf7158809cf4f3c", key);
  hex("3243f6a8885a308d313198a2e0370734", in);
  c.aes_block(key, in, out);
  ASSERT_TRUE(eq_hex(out, 16, "3925841d02dc09fbdc118597196a0b32"));
}

/* ══ X25519 (RFC 7748 §6.1) ═══════════════════════════════════════ */

static const char *A_PRIV =
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
static const char *A_PUB =
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
static const char *B_PRIV =
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
static const char *B_PUB =
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
static const char *AB_SHARED =
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

TEST(test_x25519_rfc7748) {
  uint8_t a[32], b[32], ap[32], bp[32], s[32];
  hex(A_PRIV, a);
  hex(B_PRIV, b);
  hex(A_PUB, ap);
  hex(B_PUB, bp);
  ASSERT_EQ(c.kx_shared(c.ctx, TLS_GROUP_X25519, a, bp, 32, s), 0);
  ASSERT_TRUE(eq_hex(s, 32, AB_SHARED));
  ASSERT_EQ(c.kx_shared(c.ctx, TLS_GROUP_X25519, b, ap, 32, s), 0);
  ASSERT_TRUE(eq_hex(s, 32, AB_SHARED));
}

TEST(test_x25519_public_key_is_scalar_times_base) {
  uint8_t a[32], base[32] = {9}, pub[32];
  hex(A_PRIV, a);
  ASSERT_EQ(c.kx_shared(c.ctx, TLS_GROUP_X25519, a, base, 32, pub), 0);
  ASSERT_TRUE(eq_hex(pub, 32, A_PUB));
}

TEST(test_x25519_keygen_agrees) {
  uint8_t a[32], b[32], ap[65], bp[65], s1[32], s2[32];
  size_t al = 0, bl = 0;
  ASSERT_EQ(c.kx_keygen(c.ctx, TLS_GROUP_X25519, a, ap, &al), 0);
  ASSERT_EQ(c.kx_keygen(c.ctx, TLS_GROUP_X25519, b, bp, &bl), 0);
  ASSERT_EQ(al, 32u);
  ASSERT_EQ(bl, 32u);
  ASSERT_EQ(c.kx_shared(c.ctx, TLS_GROUP_X25519, a, bp, bl, s1), 0);
  ASSERT_EQ(c.kx_shared(c.ctx, TLS_GROUP_X25519, b, ap, al, s2), 0);
  ASSERT_MEM_EQ(s1, s2, 32);
}

TEST(test_x25519_rejects_bad_length) {
  uint8_t a[32], p[32], s[32];
  hex(A_PRIV, a);
  hex(B_PUB, p);
  ASSERT_NE(c.kx_shared(c.ctx, TLS_GROUP_X25519, a, p, 31, s), 0);
}

/* ══ secp256r1 ECDH ═══════════════════════════════════════════════ */

TEST(test_p256_keygen_agrees) {
  uint8_t a[32], b[32], ap[65], bp[65], s1[32], s2[32];
  size_t al = 0, bl = 0;
  ASSERT_EQ(c.kx_keygen(c.ctx, TLS_GROUP_SECP256R1, a, ap, &al), 0);
  ASSERT_EQ(c.kx_keygen(c.ctx, TLS_GROUP_SECP256R1, b, bp, &bl), 0);
  ASSERT_EQ(al, 65u);
  ASSERT_EQ(ap[0], 0x04); /* uncompressed point (RFC 8446 §4.2.8.2) */
  ASSERT_EQ(c.kx_shared(c.ctx, TLS_GROUP_SECP256R1, a, bp, bl, s1), 0);
  ASSERT_EQ(c.kx_shared(c.ctx, TLS_GROUP_SECP256R1, b, ap, al, s2), 0);
  ASSERT_MEM_EQ(s1, s2, 32);
}

/* REQ-TLS-054 */
TEST(test_p256_rejects_point_off_curve) {
  uint8_t a[32], ap[65], s[32];
  size_t al = 0;
  ASSERT_EQ(c.kx_keygen(c.ctx, TLS_GROUP_SECP256R1, a, ap, &al), 0);
  ap[40] ^= 0x01;
  ASSERT_NE(c.kx_shared(c.ctx, TLS_GROUP_SECP256R1, a, ap, al, s), 0);
}

TEST(test_unknown_group_rejected) {
  uint8_t a[32], p[65];
  size_t l;
  ASSERT_NE(c.kx_keygen(c.ctx, 0x0018 /* secp384r1 */, a, p, &l), 0);
}

/* ══ Signatures and certificates ══════════════════════════════════ */

TEST(test_ecdsa_sign_verify) {
  mbedtls_pk_context key;
  uint8_t sig[128];
  size_t sig_len = 0;
  static const uint8_t msg[] = "CertificateVerify content";
  ASSERT_EQ(tls_mbedtls_parse_key(&be, &key, (const uint8_t *)server_key_pem,
                                  sizeof(server_key_pem)),
            0);
  ASSERT_EQ(c.sign(c.ctx, &key, TLS_SIG_ECDSA_SECP256R1_SHA256, msg,
                   sizeof(msg), sig, &sig_len, sizeof(sig)),
            0);
  ASSERT_TRUE(sig_len > 8 && sig[0] == 0x30); /* DER SEQUENCE */
  ASSERT_EQ(c.verify(c.ctx, server_der, sizeof(server_der),
                     TLS_SIG_ECDSA_SECP256R1_SHA256, msg, sizeof(msg), sig,
                     sig_len),
            0);
  sig[sig_len - 1] ^= 1;
  ASSERT_NE(c.verify(c.ctx, server_der, sizeof(server_der),
                     TLS_SIG_ECDSA_SECP256R1_SHA256, msg, sizeof(msg), sig,
                     sig_len),
            0);
  mbedtls_pk_free(&key);
}

TEST(test_rsa_pss_verify_openssl_signature) {
  ASSERT_EQ(c.verify(c.ctx, rsa_der, sizeof(rsa_der),
                     TLS_SIG_RSA_PSS_RSAE_SHA256, rsa_pss_msg,
                     sizeof(rsa_pss_msg), rsa_pss_sig, sizeof(rsa_pss_sig)),
            0);
  ASSERT_NE(c.verify(c.ctx, rsa_der, sizeof(rsa_der),
                     TLS_SIG_RSA_PSS_RSAE_SHA256, rsa_pss_msg,
                     sizeof(rsa_pss_msg) - 1, rsa_pss_sig, sizeof(rsa_pss_sig)),
            0);
}

TEST(test_scheme_must_match_key) {
  /* An ECDSA scheme with an RSA certificate is refused */
  ASSERT_NE(c.verify(c.ctx, rsa_der, sizeof(rsa_der),
                     TLS_SIG_ECDSA_SECP256R1_SHA256, rsa_pss_msg,
                     sizeof(rsa_pss_msg), rsa_pss_sig, sizeof(rsa_pss_sig)),
            0);
}

TEST(test_chain_verification) {
  /* verify_chain returns 0 or the alert to send */
  const uint8_t *chain[1] = {server_der};
  uint16_t lens[1] = {sizeof(server_der)};
  /* no trust anchors yet */
  ASSERT_EQ(c.verify_chain(c.ctx, chain, lens, 1, "pyro-dead01.local"),
            TLS_ALERT_UNKNOWN_CA);
  ASSERT_EQ(tls_mbedtls_set_ca(&be, (const uint8_t *)ca_pem, sizeof(ca_pem)),
            0);
  ASSERT_EQ(c.verify_chain(c.ctx, chain, lens, 1, "pyro-dead01.local"), 0);
  ASSERT_EQ(c.verify_chain(c.ctx, chain, lens, 1, NULL), 0);
  ASSERT_EQ(c.verify_chain(c.ctx, chain, lens, 1, "evil.example"),
            TLS_ALERT_BAD_CERTIFICATE);
  /* a CA certificate is not a server certificate for the name */
  const uint8_t *wrong[1] = {ca_der};
  uint16_t wlens[1] = {sizeof(ca_der)};
  ASSERT_EQ(c.verify_chain(c.ctx, wrong, wlens, 1, "pyro-dead01.local"),
            TLS_ALERT_BAD_CERTIFICATE);
  /* not a certificate at all */
  const uint8_t junk[3] = {0x30, 0x01, 0x00};
  const uint8_t *bad[1] = {junk};
  uint16_t blens[1] = {sizeof(junk)};
  ASSERT_EQ(c.verify_chain(c.ctx, bad, blens, 1, NULL),
            TLS_ALERT_BAD_CERTIFICATE);
}

TEST(test_chain_ip_address) {
  /* The subjectAltName iPAddress, when the name is an address literal */
  const uint8_t *chain[1] = {server_der};
  uint16_t lens[1] = {sizeof(server_der)};
  ASSERT_EQ(c.verify_chain(c.ctx, chain, lens, 1, "10.0.0.2"), 0);
  ASSERT_EQ(c.verify_chain(c.ctx, chain, lens, 1, "10.0.0.3"),
            TLS_ALERT_BAD_CERTIFICATE);
}

TEST(test_chain_other_anchor) {
  /* Trusting only another certificate: the chain leads nowhere */
  static tls_mbedtls_t be2;
  tls_crypto_t c2;
  const uint8_t *chain[1] = {server_der};
  uint16_t lens[1] = {sizeof(server_der)};
  ASSERT_EQ(tls_mbedtls_init(&be2, &c2), 0);
  ASSERT_EQ(tls_mbedtls_set_ca(&be2, rsa_der, sizeof(rsa_der)), 0);
  ASSERT_EQ(c2.verify_chain(c2.ctx, chain, lens, 1, "pyro-dead01.local"),
            TLS_ALERT_UNKNOWN_CA);
  tls_mbedtls_free(&be2);
}

/* ══ Random ═══════════════════════════════════════════════════════ */

TEST(test_random) {
  uint8_t a[32], b[32], zero[32] = {0};
  ASSERT_EQ(c.random(c.ctx, a, 32), 0);
  ASSERT_EQ(c.random(c.ctx, b, 32), 0);
  ASSERT_TRUE(memcmp(a, b, 32) != 0);
  ASSERT_TRUE(memcmp(a, zero, 32) != 0);
}

int main(void) {
  fprintf(stderr, "=== TLS crypto backend (Mbed TLS) tests ===\n");
  if (tls_mbedtls_init(&be, &c) != 0) {
    fprintf(stderr, "backend init failed\n");
    return 1;
  }
  RUN_TEST(test_sha256_abc);
  RUN_TEST(test_sha256_empty);
  RUN_TEST(test_sha256_peek_keeps_running);
  RUN_TEST(test_hmac_rfc4231);
  RUN_TEST(test_hkdf_rfc5869);
  RUN_TEST(test_gcm_seal_no_aad);
  RUN_TEST(test_gcm_seal_with_aad_in_place);
  RUN_TEST(test_gcm_open_rejects_tampering);
  RUN_TEST(test_aes_block_fips197);
  RUN_TEST(test_x25519_rfc7748);
  RUN_TEST(test_x25519_public_key_is_scalar_times_base);
  RUN_TEST(test_x25519_keygen_agrees);
  RUN_TEST(test_x25519_rejects_bad_length);
  RUN_TEST(test_p256_keygen_agrees);
  RUN_TEST(test_p256_rejects_point_off_curve);
  RUN_TEST(test_unknown_group_rejected);
  RUN_TEST(test_ecdsa_sign_verify);
  RUN_TEST(test_rsa_pss_verify_openssl_signature);
  RUN_TEST(test_scheme_must_match_key);
  RUN_TEST(test_chain_verification);
  RUN_TEST(test_chain_ip_address);
  RUN_TEST(test_chain_other_anchor);
  RUN_TEST(test_random);
  TEST_REPORT();
  tls_mbedtls_free(&be);
  return test_failures;
}
