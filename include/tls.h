/**
 * @file tls.h
 * @brief TLS 1.3 (RFC 8446) — record protection and key schedule.
 *
 * The protocol is smallest_tcp's own; every cryptographic primitive comes
 * from the application's tls_crypto_t backend (REQ-TLS-006).  One cipher
 * suite, TLS_AES_128_GCM_SHA256, so every secret and hash is 32 bytes.
 *
 * This part of the API is the building blocks the handshake uses: the key
 * schedule of RFC 8446 §7 and the protected records of §5.2.  Both are pure
 * functions of their arguments and are tested against the RFC 8448 traces.
 */

#ifndef TLS_H
#define TLS_H

#include "tls_crypto.h"

#include <stddef.h>
#include <stdint.h>

/* ── Record layer (RFC 8446 §5) ──────────────────────────────────────── */

/* ContentType */
#define TLS_CT_CHANGE_CIPHER_SPEC 20
#define TLS_CT_ALERT 21
#define TLS_CT_HANDSHAKE 22
#define TLS_CT_APPLICATION_DATA 23

#define TLS_RECORD_HDR 5 /**< type, legacy_record_version, length */
/** Bytes a protected record adds to its content: header, type, tag. */
#define TLS_RECORD_OVERHEAD (TLS_RECORD_HDR + 1 + TLS_AEAD_TAG_LEN)
#define TLS_MAX_PLAINTEXT 16384u /**< 2^14 */
#define TLS_MAX_CIPHERTEXT (TLS_MAX_PLAINTEXT + 256u)

/* AlertDescription (RFC 8446 §6) */
#define TLS_ALERT_CLOSE_NOTIFY 0
#define TLS_ALERT_UNEXPECTED_MESSAGE 10
#define TLS_ALERT_BAD_RECORD_MAC 20
#define TLS_ALERT_RECORD_OVERFLOW 22
#define TLS_ALERT_HANDSHAKE_FAILURE 40
#define TLS_ALERT_BAD_CERTIFICATE 42
#define TLS_ALERT_UNSUPPORTED_CERTIFICATE 43
#define TLS_ALERT_CERTIFICATE_UNKNOWN 46
#define TLS_ALERT_ILLEGAL_PARAMETER 47
#define TLS_ALERT_UNKNOWN_CA 48
#define TLS_ALERT_DECODE_ERROR 50
#define TLS_ALERT_DECRYPT_ERROR 51
#define TLS_ALERT_PROTOCOL_VERSION 70
#define TLS_ALERT_INSUFFICIENT_SECURITY 71
#define TLS_ALERT_INTERNAL_ERROR 80
#define TLS_ALERT_MISSING_EXTENSION 109
#define TLS_ALERT_UNSUPPORTED_EXTENSION 110
#define TLS_ALERT_UNKNOWN_PSK_IDENTITY 115

/** @brief The keys protecting one direction of records (RFC 8446 §7.3). */
typedef struct {
  uint8_t key[TLS_AEAD_KEY_LEN];
  uint8_t iv[TLS_AEAD_IV_LEN];
  uint64_t seq; /**< Records protected so far; XORed into the nonce */
} tls_keys_t;

/**
 * Protect one record in place (RFC 8446 §5.2).
 *
 * @p rec[TLS_RECORD_HDR ..] holds @p len bytes of content of type @p type;
 * the record needs @p len + TLS_RECORD_OVERHEAD bytes.  Writes the header
 * (opaque_type application_data), the inner content type and the tag, and
 * advances @p k->seq.
 * @return The length of the whole record.
 */
size_t tls_record_seal(const tls_crypto_t *c, tls_keys_t *k, uint8_t type,
                       uint8_t *rec, size_t len);

/**
 * Remove the protection of one record in place.  @p rec is the whole record
 * (header included, @p rec_len bytes).  On success the content is at
 * @p rec + TLS_RECORD_HDR, @p type receives its content type (the padding is
 * stripped) and @p k->seq advances.
 * @return The content length, or the negated alert to send:
 *         -TLS_ALERT_BAD_RECORD_MAC, -TLS_ALERT_RECORD_OVERFLOW,
 *         -TLS_ALERT_DECODE_ERROR or -TLS_ALERT_UNEXPECTED_MESSAGE.
 */
int tls_record_open(const tls_crypto_t *c, tls_keys_t *k, uint8_t *rec,
                    size_t rec_len, uint8_t *type);

/* ── Key schedule (RFC 8446 §7.1) ────────────────────────────────────── */

/**
 * HKDF-Expand-Label(@p secret, "tls13 " + @p label, @p context, @p out_len).
 * @p label is at most 12 characters and @p context at most 32 bytes (the
 * longest TLS 1.3 uses).
 */
void tls_expand_label(const tls_crypto_t *c, const uint8_t *secret,
                      const char *label, const uint8_t *context,
                      size_t context_len, uint8_t *out, size_t out_len);

/**
 * Derive-Secret(@p secret, @p label, Messages) where @p hash is
 * Transcript-Hash(Messages), or NULL for the hash of no messages.
 */
void tls_derive_secret(const tls_crypto_t *c, const uint8_t *secret,
                       const char *label, const uint8_t *hash,
                       uint8_t out[TLS_HASH_LEN]);

/**
 * The Early Secret: HKDF-Extract(0, @p psk), or of 32 zero bytes when
 * @p psk is NULL (no PSK).
 */
void tls_early_secret(const tls_crypto_t *c, const uint8_t *psk,
                      size_t psk_len, uint8_t out[TLS_HASH_LEN]);

/**
 * Step the schedule to its next secret in place:
 * HKDF-Extract(Derive-Secret(@p secret, "derived", ""), @p ikm) — Early to
 * Handshake Secret with the (EC)DHE shared secret, Handshake to Master
 * Secret with @p ikm NULL (32 zero bytes).
 */
void tls_next_secret(const tls_crypto_t *c, uint8_t secret[TLS_HASH_LEN],
                     const uint8_t *ikm, size_t ikm_len);

/** The write key and IV of traffic secret @p secret; the sequence is 0. */
void tls_traffic_keys(const tls_crypto_t *c, const uint8_t *secret,
                      tls_keys_t *k);

/**
 * Finished verify_data (RFC 8446 §4.4.4): HMAC(finished_key, @p hash) with
 * finished_key = HKDF-Expand-Label(@p base, "finished", "", 32).
 */
void tls_finished_mac(const tls_crypto_t *c, const uint8_t *base,
                      const uint8_t hash[TLS_HASH_LEN],
                      uint8_t out[TLS_HASH_LEN]);

/** KeyUpdate (RFC 8446 §7.2): the next generation of a traffic secret. */
void tls_update_secret(const tls_crypto_t *c, uint8_t secret[TLS_HASH_LEN]);

/** Constant-time comparison: 1 if equal. */
int tls_equal(const uint8_t *a, const uint8_t *b, size_t len);

#endif /* TLS_H */
