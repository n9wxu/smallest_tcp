/**
 * @file tls_keys.c
 * @brief TLS 1.3 key schedule (RFC 8446 §7) and record protection (§5.2).
 *
 * No cryptography here (REQ-TLS-006): HKDF, HMAC and AES-GCM come from
 * the tls_crypto_t backend.
 */

#include "tls_keys.h"
#include "net_endian.h"

#include <string.h>

/* SHA-256("") — Transcript-Hash of no messages, for Derive-Secret(.., "") */
static const uint8_t empty_hash[TLS_HASH_LEN] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
    0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
    0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

static const uint8_t zeros[TLS_HASH_LEN];

#define LABEL_MAX 12 /* "e exp master" */

void tls_wipe(void *p, size_t n) {
  volatile uint8_t *v = (volatile uint8_t *)p;
  while (n--)
    *v++ = 0;
}

int tls_equal(const uint8_t *a, const uint8_t *b, size_t len) {
  uint8_t d = 0;
  size_t i;
  for (i = 0; i < len; i++)
    d |= (uint8_t)(a[i] ^ b[i]);
  return d == 0;
}

void tls_expand_label(const tls_crypto_t *c, int dtls, const uint8_t *secret,
                      const char *label, const uint8_t *context,
                      size_t context_len, uint8_t *out, size_t out_len) {
  /* struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
   * HkdfLabel, with label = "tls13 " + Label — or "dtls13" + Label (RFC
   * 9147 §5.9), the same length */
  uint8_t info[2 + 1 + 6 + LABEL_MAX + 1 + TLS_HASH_LEN];
  size_t ll = strlen(label), n;
  if (ll > LABEL_MAX)
    ll = LABEL_MAX;
  if (context_len > TLS_HASH_LEN)
    context_len = TLS_HASH_LEN;
  net_write16be(info, out_len);
  info[2] = (uint8_t)(6 + ll);
  memcpy(info + 3, dtls ? "dtls13" : "tls13 ", 6);
  memcpy(info + 9, label, ll);
  n = 9 + ll;
  info[n++] = (uint8_t)context_len;
  if (context_len) {
    memcpy(info + n, context, context_len);
    n += context_len;
  }
  c->hkdf_expand(secret, info, n, out, out_len);
}

void tls_derive_secret(const tls_crypto_t *c, int dtls, const uint8_t *secret,
                       const char *label, const uint8_t *hash,
                       uint8_t out[TLS_HASH_LEN]) {
  tls_expand_label(c, dtls, secret, label, hash ? hash : empty_hash,
                   TLS_HASH_LEN, out, TLS_HASH_LEN);
}

void tls_early_secret(const tls_crypto_t *c, const uint8_t *psk, size_t psk_len,
                      uint8_t out[TLS_HASH_LEN]) {
  if (!psk) {
    psk = zeros;
    psk_len = TLS_HASH_LEN;
  }
  c->hkdf_extract(zeros, TLS_HASH_LEN, psk, psk_len, out);
}

void tls_next_secret(const tls_crypto_t *c, int dtls,
                     uint8_t secret[TLS_HASH_LEN], const uint8_t *ikm,
                     size_t ikm_len) {
  uint8_t salt[TLS_HASH_LEN];
  if (!ikm) {
    ikm = zeros;
    ikm_len = TLS_HASH_LEN;
  }
  tls_derive_secret(c, dtls, secret, "derived", NULL, salt);
  c->hkdf_extract(salt, TLS_HASH_LEN, ikm, ikm_len, secret);
  tls_wipe(salt, sizeof(salt));
}

void tls_traffic_keys(const tls_crypto_t *c, int dtls, const uint8_t *secret,
                      tls_keys_t *k) {
  tls_expand_label(c, dtls, secret, "key", NULL, 0, k->key, TLS_AEAD_KEY_LEN);
  tls_expand_label(c, dtls, secret, "iv", NULL, 0, k->iv, TLS_AEAD_IV_LEN);
  k->seq = 0;
}

void tls_finished_mac(const tls_crypto_t *c, int dtls, const uint8_t *base,
                      const uint8_t hash[TLS_HASH_LEN],
                      uint8_t out[TLS_HASH_LEN]) {
  uint8_t fk[TLS_HASH_LEN];
  tls_expand_label(c, dtls, base, "finished", NULL, 0, fk, TLS_HASH_LEN);
  c->hmac(fk, TLS_HASH_LEN, hash, TLS_HASH_LEN, out);
  tls_wipe(fk, sizeof(fk));
}

void tls_psk_binder(const tls_crypto_t *c, int dtls, const uint8_t *early,
                    int resumption, const uint8_t hash[TLS_HASH_LEN],
                    uint8_t out[TLS_HASH_LEN]) {
  uint8_t bk[TLS_HASH_LEN];
  tls_derive_secret(c, dtls, early, resumption ? "res binder" : "ext binder",
                    NULL, bk);
  tls_finished_mac(c, dtls, bk, hash, out);
  tls_wipe(bk, sizeof(bk));
}

void tls_transcript_hrr(const tls_crypto_t *c, tls_hash_t *transcript) {
  uint8_t mh[4 + TLS_HASH_LEN] = {254, 0, 0, TLS_HASH_LEN}; /* message_hash */
  c->hash_peek(transcript, mh + 4);
  c->hash_init(transcript);
  c->hash_update(transcript, mh, sizeof(mh));
}

void tls_update_secret(const tls_crypto_t *c, int dtls,
                       uint8_t secret[TLS_HASH_LEN]) {
  uint8_t next[TLS_HASH_LEN];
  tls_expand_label(c, dtls, secret, "traffic upd", NULL, 0, next, TLS_HASH_LEN);
  memcpy(secret, next, TLS_HASH_LEN);
  tls_wipe(next, sizeof(next));
}

/* The per-record nonce: the IV XOR the 64-bit sequence number, big-endian
 * and right-aligned (RFC 8446 §5.3). */
static void record_nonce(const tls_keys_t *k, uint8_t nonce[TLS_AEAD_IV_LEN]) {
  uint64_t s = k->seq;
  int i;
  memcpy(nonce, k->iv, TLS_AEAD_IV_LEN);
  for (i = TLS_AEAD_IV_LEN - 1; i >= TLS_AEAD_IV_LEN - 8; i--) {
    nonce[i] ^= (uint8_t)s;
    s >>= 8;
  }
}

size_t tls_record_seal(const tls_crypto_t *c, tls_keys_t *k, uint8_t type,
                       uint8_t *rec, size_t len) {
  uint8_t nonce[TLS_AEAD_IV_LEN];
  uint8_t *inner = rec + TLS_RECORD_HDR;
  size_t clen = len + 1 + TLS_AEAD_TAG_LEN;

  inner[len] = type; /* TLSInnerPlaintext: content, type, no padding */
  rec[0] = TLS_CT_APPLICATION_DATA;
  net_write16be(rec + 1, TLS_LEGACY_VERSION);
  net_write16be(rec + 3, (uint16_t)clen);
  record_nonce(k, nonce);
  c->aead_seal(k->key, nonce, rec, TLS_RECORD_HDR, inner, len + 1, inner,
               inner + len + 1);
  k->seq++;
  return TLS_RECORD_HDR + clen;
}

int tls_record_open(const tls_crypto_t *c, tls_keys_t *k, uint8_t *rec,
                    size_t rec_len, uint8_t *type) {
  uint8_t nonce[TLS_AEAD_IV_LEN];
  uint8_t *inner = rec + TLS_RECORD_HDR;
  size_t clen, n;

  if (rec_len < TLS_RECORD_HDR)
    return -TLS_ALERT_DECODE_ERROR;
  if (rec[0] != TLS_CT_APPLICATION_DATA)
    return -TLS_ALERT_UNEXPECTED_MESSAGE;
  clen = ((size_t)rec[3] << 8) | rec[4];
  if (clen != rec_len - TLS_RECORD_HDR)
    return -TLS_ALERT_DECODE_ERROR;
  if (clen < 1 + TLS_AEAD_TAG_LEN)
    return -TLS_ALERT_BAD_RECORD_MAC;
  n = clen - TLS_AEAD_TAG_LEN;
  /* TLSInnerPlaintext may not exceed 2^14 + 1 (§5.4), which also bounds
   * TLSCiphertext.length by 2^14 + 256 (§5.2) */
  if (n > TLS_MAX_PLAINTEXT + 1)
    return -TLS_ALERT_RECORD_OVERFLOW;

  record_nonce(k, nonce);
  if (c->aead_open(k->key, nonce, rec, TLS_RECORD_HDR, inner, n, inner + n,
                   inner) != 0)
    return -TLS_ALERT_BAD_RECORD_MAC;
  k->seq++;

  while (n > 0 && inner[n - 1] == 0) /* strip the padding */
    n--;
  if (n == 0)
    return -TLS_ALERT_UNEXPECTED_MESSAGE;
  n--;
  *type = inner[n];
  return (int)n;
}
