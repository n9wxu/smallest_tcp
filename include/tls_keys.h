/**
 * @file tls_keys.h
 * @brief TLS 1.3 key schedule (RFC 8446 §7) and record protection (§5.2):
 *        pure functions over the tls_crypto_t backend, verified against
 *        the RFC 8448 traces.  tls.c builds the connection on them.
 */

#ifndef TLS_KEYS_H
#define TLS_KEYS_H

#include "tls_crypto.h"

#include <stddef.h>
#include <stdint.h>

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

#define TLS_LEGACY_VERSION 0x0303 /**< In record headers and hellos */
#define TLS_VERSION_13 0x0304

/* AlertDescription (RFC 8446 §6) */
#define TLS_ALERT_CLOSE_NOTIFY 0
#define TLS_ALERT_UNEXPECTED_MESSAGE 10
#define TLS_ALERT_BAD_RECORD_MAC 20
#define TLS_ALERT_RECORD_OVERFLOW 22
#define TLS_ALERT_HANDSHAKE_FAILURE 40
#define TLS_ALERT_BAD_CERTIFICATE 42
#define TLS_ALERT_UNSUPPORTED_CERTIFICATE 43
#define TLS_ALERT_CERTIFICATE_REVOKED 44
#define TLS_ALERT_CERTIFICATE_EXPIRED 45
#define TLS_ALERT_CERTIFICATE_UNKNOWN 46
#define TLS_ALERT_ILLEGAL_PARAMETER 47
#define TLS_ALERT_UNKNOWN_CA 48
#define TLS_ALERT_DECODE_ERROR 50
#define TLS_ALERT_DECRYPT_ERROR 51
#define TLS_ALERT_PROTOCOL_VERSION 70
#define TLS_ALERT_INSUFFICIENT_SECURITY 71
#define TLS_ALERT_INTERNAL_ERROR 80
#define TLS_ALERT_USER_CANCELED 90
#define TLS_ALERT_MISSING_EXTENSION 109
#define TLS_ALERT_UNSUPPORTED_EXTENSION 110
#define TLS_ALERT_UNKNOWN_PSK_IDENTITY 115

/** The keys protecting one direction of records (RFC 8446 §7.3). */
typedef struct {
  uint8_t key[TLS_AEAD_KEY_LEN];
  uint8_t iv[TLS_AEAD_IV_LEN];
  uint64_t seq; /**< Records protected so far; XORed into the nonce */
} tls_keys_t;

/**
 * Protect one record in place.  @p rec[TLS_RECORD_HDR ..] holds @p len
 * bytes of content of type @p type; the record needs @p len +
 * TLS_RECORD_OVERHEAD bytes.  Writes the header (opaque_type
 * application_data), the inner content type and the tag; advances
 * @p k->seq.
 * @return The length of the whole record.
 */
size_t tls_record_seal(const tls_crypto_t *c, tls_keys_t *k, uint8_t type,
                       uint8_t *rec, size_t len);

/**
 * Remove the protection of the record @p rec (header included) in place.
 * On success the content is at @p rec + TLS_RECORD_HDR, its type in
 * @p type (padding stripped), and @p k->seq advances.
 * @return The content length, or the negated alert to send.
 */
int tls_record_open(const tls_crypto_t *c, tls_keys_t *k, uint8_t *rec,
                    size_t rec_len, uint8_t *type);

/**
 * HKDF-Expand-Label(@p secret, "tls13 " + @p label, @p context,
 * @p out_len); @p label at most 12 characters, @p context at most 32 bytes.
 */
void tls_expand_label(const tls_crypto_t *c, const uint8_t *secret,
                      const char *label, const uint8_t *context,
                      size_t context_len, uint8_t *out, size_t out_len);

/** Derive-Secret(@p secret, @p label, Messages), @p hash being
 *  Transcript-Hash(Messages), or NULL for no messages. */
void tls_derive_secret(const tls_crypto_t *c, const uint8_t *secret,
                       const char *label, const uint8_t *hash,
                       uint8_t out[TLS_HASH_LEN]);

/** The Early Secret: HKDF-Extract(0, @p psk), 32 zero bytes without one. */
void tls_early_secret(const tls_crypto_t *c, const uint8_t *psk, size_t psk_len,
                      uint8_t out[TLS_HASH_LEN]);

/**
 * The next secret of the schedule, in place:
 * HKDF-Extract(Derive-Secret(@p secret, "derived", ""), @p ikm) — Early
 * to Handshake Secret with the (EC)DHE secret, Handshake to Master Secret
 * with @p ikm NULL.
 */
void tls_next_secret(const tls_crypto_t *c, uint8_t secret[TLS_HASH_LEN],
                     const uint8_t *ikm, size_t ikm_len);

/** The write key and IV of traffic secret @p secret; sequence 0. */
void tls_traffic_keys(const tls_crypto_t *c, const uint8_t *secret,
                      tls_keys_t *k);

/** Finished verify_data (§4.4.4): HMAC(finished_key(@p base), @p hash). */
void tls_finished_mac(const tls_crypto_t *c, const uint8_t *base,
                      const uint8_t hash[TLS_HASH_LEN],
                      uint8_t out[TLS_HASH_LEN]);

/**
 * PSK binder (§4.2.11.2) under the Early Secret @p early — "res binder"
 * for a @p resumption PSK, "ext binder" for an external one — over
 * @p hash, the transcript hash up to the binders.
 */
void tls_psk_binder(const tls_crypto_t *c, const uint8_t *early, int resumption,
                    const uint8_t hash[TLS_HASH_LEN],
                    uint8_t out[TLS_HASH_LEN]);

/** After a HelloRetryRequest (§4.4.1): the transcript of ClientHello1
 *  restarts as the hash of the message_hash message standing for it. */
void tls_transcript_hrr(const tls_crypto_t *c, tls_hash_t *transcript);

/** KeyUpdate (§7.2): the next generation of a traffic secret. */
void tls_update_secret(const tls_crypto_t *c, uint8_t secret[TLS_HASH_LEN]);

/** Constant-time comparison: 1 if equal. */
int tls_equal(const uint8_t *a, const uint8_t *b, size_t len);

/** Zero memory in a way the compiler cannot drop. */
void tls_wipe(void *p, size_t n);

#endif /* TLS_KEYS_H */
