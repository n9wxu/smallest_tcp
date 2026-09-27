/**
 * @file tls_crypto_mbedtls.h
 * @brief tls_crypto_t backend on Mbed TLS 3.6 (crypto and X.509 only —
 *        the TLS protocol is smallest_tcp's own, tls.c).
 *
 *   static tls_mbedtls_t be;
 *   static tls_crypto_t crypto;
 *   tls_mbedtls_init(&be, &crypto);          // seeds a CTR-DRBG
 *   tls_mbedtls_set_ca(&be, ca_pem, sizeof(ca_pem));   // client: trust
 *   tls_mbedtls_parse_key(&be, &key, key_pem, sizeof(key_pem)); // server
 *
 * Mbed TLS allocates bignums with mbedtls_calloc().  With the bundled
 * configuration (MBEDTLS_MEMORY_BUFFER_ALLOC_C) the application can hand it
 * a static arena instead of a heap: tls_mbedtls_use_arena().
 */

#ifndef TLS_CRYPTO_MBEDTLS_H
#define TLS_CRYPTO_MBEDTLS_H

#include "tls_crypto.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>

/** @brief Backend state (application owned). */
typedef struct {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context drbg;
  mbedtls_x509_crt ca; /**< Trust anchors for verify_chain */
  int ca_count;        /**< Certificates loaded into @ref ca */
} tls_mbedtls_t;

/**
 * Seed the random generator from the platform entropy source and fill
 * @p crypto with this backend's functions (crypto->ctx = be).
 * @return 0, or an Mbed TLS error code.
 */
int tls_mbedtls_init(tls_mbedtls_t *be, tls_crypto_t *crypto);

/** Add trust anchors (PEM with the terminating NUL counted, or DER). */
int tls_mbedtls_set_ca(tls_mbedtls_t *be, const uint8_t *cert, size_t len);

/**
 * Parse a private key (PEM with NUL, or DER) for signing — the value to
 * put in tls_config_t.key.  Free it with mbedtls_pk_free().
 */
int tls_mbedtls_parse_key(tls_mbedtls_t *be, mbedtls_pk_context *key,
                          const uint8_t *pem_or_der, size_t len);

/**
 * Serve every Mbed TLS allocation from @p arena instead of the heap
 * (MBEDTLS_MEMORY_BUFFER_ALLOC_C).  Call before tls_mbedtls_init().
 * @return 0, or -1 if this build of Mbed TLS lacks the allocator.
 */
int tls_mbedtls_use_arena(uint8_t *arena, size_t len);

void tls_mbedtls_free(tls_mbedtls_t *be);

#endif /* TLS_CRYPTO_MBEDTLS_H */
