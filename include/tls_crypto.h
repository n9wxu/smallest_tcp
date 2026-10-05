/**
 * @file tls_crypto.h
 * @brief Crypto backend interface for the TLS 1.3 layer (tls.c).
 *
 * tls.c implements the protocol — records, handshake, key schedule — and
 * no cryptography.  Every primitive it needs comes through
 * this vtable, which the application fills from a backend such as
 * tls_crypto_mbedtls.c, the same pattern as net_mac_t for MAC drivers.
 *
 * One cipher suite, TLS_AES_128_GCM_SHA256: SHA-256 for the
 * transcript, HMAC and HKDF; AES-128-GCM for records (and, for DTLS, the
 * AES block cipher alone to encrypt record numbers).  Key exchange over
 * x25519 or secp256r1.
 */

#ifndef TLS_CRYPTO_H
#define TLS_CRYPTO_H

#include "net_config.h"
#include <stddef.h>
#include <stdint.h>

#define TLS_HASH_LEN 32
#define TLS_AEAD_KEY_LEN 16
#define TLS_AEAD_IV_LEN 12
#define TLS_AEAD_TAG_LEN 16

/* Named groups (RFC 8446 §4.2.7) */
#define TLS_GROUP_SECP256R1 0x0017
#define TLS_GROUP_X25519 0x001D

/* Signature schemes (RFC 8446 §4.2.3) */
#define TLS_SIG_ECDSA_SECP256R1_SHA256 0x0403
#define TLS_SIG_RSA_PSS_RSAE_SHA256 0x0804

/* Key-exchange sizes: x25519 32/32, secp256r1 32 / 65 (uncompressed) */
#define TLS_KX_PRIV_MAX 32
#define TLS_KX_PUB_MAX 65

/** Room for the backend's SHA-256 state (checked by the backend). */
#define TLS_HASH_STATE_SIZE 128

/** Running SHA-256, opaque to tls.c (the transcript hash). */
typedef union {
  uint8_t bytes[TLS_HASH_STATE_SIZE];
  uint64_t align_u64;
  void *align_ptr;
} tls_hash_t;

/**
 * @brief The primitives tls.c uses.  Functions returning int return 0 on
 * success.  @p ctx is passed to those that need backend state (random
 * numbers, trust anchors).
 */
typedef struct tls_crypto_s {
  /* SHA-256 */
  void (*hash_init)(tls_hash_t *h);
  void (*hash_update)(tls_hash_t *h, const uint8_t *data, size_t len);
  /** The digest of everything so far; @p h keeps going. */
  void (*hash_peek)(const tls_hash_t *h, uint8_t out[TLS_HASH_LEN]);

  /* HMAC-SHA-256 and HKDF (RFC 2104, RFC 5869) */
  void (*hmac)(const uint8_t *key, size_t key_len, const uint8_t *data,
               size_t len, uint8_t out[TLS_HASH_LEN]);
  void (*hkdf_extract)(const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                       size_t ikm_len, uint8_t prk[TLS_HASH_LEN]);
  void (*hkdf_expand)(const uint8_t prk[TLS_HASH_LEN], const uint8_t *info,
                      size_t info_len, uint8_t *out, size_t out_len);

  /* AES-128-GCM; @p out may equal @p in */
  void (*aead_seal)(const uint8_t key[TLS_AEAD_KEY_LEN],
                    const uint8_t nonce[TLS_AEAD_IV_LEN], const uint8_t *aad,
                    size_t aad_len, const uint8_t *in, size_t len, uint8_t *out,
                    uint8_t tag[TLS_AEAD_TAG_LEN]);
  /** @return 0 if authentic (and @p out holds the plaintext), else -1. */
  int (*aead_open)(const uint8_t key[TLS_AEAD_KEY_LEN],
                   const uint8_t nonce[TLS_AEAD_IV_LEN], const uint8_t *aad,
                   size_t aad_len, const uint8_t *in, size_t len,
                   const uint8_t tag[TLS_AEAD_TAG_LEN], uint8_t *out);

  /* (EC)DHE */
  /** New key pair for @p group; @p pub_len receives the share's size. */
  int (*kx_keygen)(void *ctx, uint16_t group, uint8_t *priv, uint8_t *pub,
                   size_t *pub_len);
  /** Shared secret (32 bytes for both groups); rejects invalid shares. */
  int (*kx_shared)(void *ctx, uint16_t group, const uint8_t *priv,
                   const uint8_t *peer, size_t peer_len,
                   uint8_t shared[TLS_HASH_LEN]);

  /* Signatures and certificates (certificate mode only) */
  /** Sign @p msg (the backend hashes it) with the private key @p key. */
  int (*sign)(void *ctx, const void *key, uint16_t scheme, const uint8_t *msg,
              size_t len, uint8_t *sig, size_t *sig_len, size_t sig_cap);
  /** Verify @p sig over @p msg with the public key of DER @p cert. */
  int (*verify)(void *ctx, const uint8_t *cert, size_t cert_len,
                uint16_t scheme, const uint8_t *msg, size_t len,
                const uint8_t *sig, size_t sig_len);
  /** Verify a chain (leaf first, DER) against the backend's trust anchors
   *  and, if @p hostname is not NULL, the leaf's names (an address literal
   *  matches an iPAddress name).  Returns 0, or the TLS alert to send
   *  (RFC 8446 §6: unknown_ca, certificate_expired, bad_certificate ..). */
  int (*verify_chain)(void *ctx, const uint8_t *const *certs,
                      const uint16_t *lens, uint8_t count,
                      const char *hostname);

  /* Randomness */
  int (*random)(void *ctx, uint8_t *out, size_t len);

  void *ctx;

  /** AES-128 of one block: DTLS 1.3 record number encryption (RFC 9147
   *  §4.2.3).  TLS does not use it; a TLS-only backend may leave it NULL. */
  void (*aes_block)(const uint8_t key[TLS_AEAD_KEY_LEN], const uint8_t in[16],
                    uint8_t out[16]);
} tls_crypto_t;

#endif /* TLS_CRYPTO_H */
