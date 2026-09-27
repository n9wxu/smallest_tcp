/**
 * @file dtls.c
 * @brief DTLS 1.3 (RFC 9147): the datagram record layer.
 *
 * No cryptography here (REQ-DTLS-070): AES-GCM, the AES block for record
 * numbers and HKDF come from the tls_crypto_t backend.
 *
 * No division: this builds for Cortex-M0.
 */

#include "dtls.h"
#include "net_endian.h"

#include <string.h>

/* The first byte of a DTLSCiphertext header (RFC 9147 §4, Figure 3) */
#define HDR_FIXED 0x20u /* 001 */
#define HDR_FIXED_MASK 0xE0u
#define HDR_CID 0x10u
#define HDR_SEQ16 0x08u
#define HDR_LEN 0x04u
#define HDR_EPOCH 0x03u

#define REPLAY_WINDOW 32u

/* ── Records (§4) ── */

void dtls_keys_derive(const tls_crypto_t *c, const uint8_t secret[TLS_HASH_LEN],
                      dtls_keys_t *k) {
  tls_traffic_keys(c, 1, secret, &k->k);
  tls_expand_label(c, 1, secret, "sn", NULL, 0, k->sn, TLS_AEAD_KEY_LEN);
  k->window = 0;
}

/* The per-record nonce: the IV XOR the 64-bit record number (§4: the
 * epoch is not in it — each epoch has its own keys) */
static void record_nonce(const dtls_keys_t *k, uint64_t seq,
                         uint8_t nonce[TLS_AEAD_IV_LEN]) {
  int i;
  memcpy(nonce, k->k.iv, TLS_AEAD_IV_LEN);
  for (i = TLS_AEAD_IV_LEN - 1; i >= TLS_AEAD_IV_LEN - 8; i--) {
    nonce[i] ^= (uint8_t)seq;
    seq >>= 8;
  }
}

size_t dtls_record_seal(const tls_crypto_t *c, dtls_keys_t *k, uint16_t epoch,
                        uint8_t type, uint8_t *rec, size_t len) {
  uint8_t nonce[TLS_AEAD_IV_LEN], mask[16];
  uint8_t *inner = rec + DTLS_RECORD_HDR;
  size_t clen = len + 1 + TLS_AEAD_TAG_LEN;

  inner[len] = type; /* DTLSInnerPlaintext: content, type, no padding */
  rec[0] = (uint8_t)(HDR_FIXED | HDR_SEQ16 | HDR_LEN | (epoch & HDR_EPOCH));
  net_write16be(rec + 1, (uint16_t)k->k.seq);
  net_write16be(rec + 3, (uint16_t)clen);
  record_nonce(k, k->k.seq, nonce);
  /* the header goes into the AAD before its record number is masked */
  c->aead_seal(k->k.key, nonce, rec, DTLS_RECORD_HDR, inner, len + 1, inner,
               inner + len + 1);
  c->aes_block(k->sn, inner, mask); /* at least 17 bytes of ciphertext */
  rec[1] ^= mask[0];
  rec[2] ^= mask[1];
  k->k.seq++;
  return DTLS_RECORD_HDR + clen;
}

int dtls_record_parse(const uint8_t *in, size_t avail, dtls_rec_t *r) {
  size_t h;
  if (avail < 2 || (in[0] & HDR_FIXED_MASK) != HDR_FIXED ||
      (in[0] & HDR_CID)) /* no CID was negotiated (§9.1) */
    return -1;
  h = (in[0] & HDR_SEQ16) ? 3u : 2u;
  if (in[0] & HDR_LEN) {
    if (avail < h + 2)
      return -1;
    r->len = net_read16be(in + h);
    h += 2;
    if (r->len > avail - h)
      return -1;
  } else { /* the rest of the datagram */
    if (avail < h || avail - h > 0xFFFFu)
      return -1;
    r->len = (uint16_t)(avail - h);
  }
  r->hlen = (uint8_t)h;
  r->epoch = (uint8_t)(in[0] & HDR_EPOCH);
  return 0;
}

uint64_t dtls_seq_expand(uint64_t next, uint32_t bits, unsigned nbits) {
  uint64_t win = nbits == 8 ? 0x100u : 0x10000u, hwin = win >> 1;
  uint64_t cand = (next & ~(win - 1)) | bits;
  if (cand + hwin <= next) /* too far behind: it is in the next window */
    return cand + win;
  if (cand > next + hwin && cand >= win) /* too far ahead: the one before */
    return cand - win;
  return cand;
}

/* §4.5.1: a record number already taken, or below the window */
static int replayed(const dtls_keys_t *k, uint64_t seq) {
  uint64_t behind;
  if (seq >= k->k.seq)
    return 0;
  behind = k->k.seq - 1 - seq;
  return behind >= REPLAY_WINDOW || ((k->window >> behind) & 1u);
}

static void mark_taken(dtls_keys_t *k, uint64_t seq) {
  if (seq >= k->k.seq) {
    uint64_t shift = seq + 1 - k->k.seq;
    k->window = shift >= REPLAY_WINDOW ? 0 : k->window << shift;
    k->window |= 1u;
    k->k.seq = seq + 1;
  } else {
    k->window |= 1ul << (k->k.seq - 1 - seq);
  }
}

int dtls_record_open(const tls_crypto_t *c, dtls_keys_t *k, const uint8_t *in,
                     const dtls_rec_t *r, uint8_t *out, uint8_t *type,
                     uint64_t *seq) {
  uint8_t mask[16], aad[DTLS_RECORD_HDR], nonce[TLS_AEAD_IV_LEN];
  size_t n, h = r->hlen;
  uint64_t s;

  /* §4.2.3: the mask needs 16 bytes of ciphertext; TLS's bound on
   * DTLSInnerPlaintext applies too */
  if (r->len < 16 || r->len - TLS_AEAD_TAG_LEN > TLS_MAX_PLAINTEXT + 1)
    return -1;
  c->aes_block(k->sn, in + h, mask);
  memcpy(aad, in, h);
  aad[1] ^= mask[0];
  if (in[0] & HDR_SEQ16) {
    aad[2] ^= mask[1];
    s = dtls_seq_expand(k->k.seq, ((uint32_t)aad[1] << 8) | aad[2], 16);
  } else {
    s = dtls_seq_expand(k->k.seq, aad[1], 8);
  }
  n = r->len - TLS_AEAD_TAG_LEN;
  record_nonce(k, s, nonce);
  if (c->aead_open(k->k.key, nonce, aad, h, in + h, n, in + h + n, out) != 0)
    return -1;
  /* after deprotection, so that a discard is no timing channel (§4.5.1) */
  if (replayed(k, s))
    return -1;
  mark_taken(k, s);
  while (n > 0 && out[n - 1] == 0) /* strip the padding */
    n--;
  if (n == 0)
    return -1;
  *type = out[--n];
  *seq = s;
  return (int)n;
}
