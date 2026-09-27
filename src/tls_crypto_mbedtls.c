/**
 * @file tls_crypto_mbedtls.c
 * @brief tls_crypto_t on Mbed TLS 3.6: SHA-256, HMAC, HKDF, AES-128-GCM,
 *        X25519 / P-256 ECDH, ECDSA and RSA-PSS, X.509 chains.
 *
 * Only Mbed TLS's crypto and X.509 modules are used; the TLS protocol is
 * tls.c.  Stateless primitives ignore the ctx argument; random numbers,
 * key generation, signing and chain checks use the tls_mbedtls_t.
 */

#include "tls_crypto_mbedtls.h"
#include "tls.h" /* alert numbers */

#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <string.h>

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include <mbedtls/memory_buffer_alloc.h>
#endif

/* The transcript state lives in tls_hash_t */
typedef char tls_hash_state_fits
    [(sizeof(mbedtls_sha256_context) <= TLS_HASH_STATE_SIZE) ? 1 : -1];

static void hash_init(tls_hash_t *h) {
  mbedtls_sha256_context *s = (mbedtls_sha256_context *)(void *)h->bytes;
  mbedtls_sha256_init(s);
  mbedtls_sha256_starts(s, 0);
}

static void hash_update(tls_hash_t *h, const uint8_t *data, size_t len) {
  mbedtls_sha256_update((mbedtls_sha256_context *)(void *)h->bytes, data, len);
}

static void hash_peek(const tls_hash_t *h, uint8_t out[TLS_HASH_LEN]) {
  mbedtls_sha256_context tmp;
  mbedtls_sha256_init(&tmp);
  mbedtls_sha256_clone(&tmp,
                       (const mbedtls_sha256_context *)(const void *)h->bytes);
  mbedtls_sha256_finish(&tmp, out);
  mbedtls_sha256_free(&tmp);
}

static const mbedtls_md_info_t *sha256_md(void) {
  return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
}

static void hmac(const uint8_t *key, size_t key_len, const uint8_t *data,
                 size_t len, uint8_t out[TLS_HASH_LEN]) {
  mbedtls_md_hmac(sha256_md(), key, key_len, data, len, out);
}

static void hkdf_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t prk[TLS_HASH_LEN]) {
  mbedtls_hkdf_extract(sha256_md(), salt, salt_len, ikm, ikm_len, prk);
}

static void hkdf_expand(const uint8_t prk[TLS_HASH_LEN], const uint8_t *info,
                        size_t info_len, uint8_t *out, size_t out_len) {
  mbedtls_hkdf_expand(sha256_md(), prk, TLS_HASH_LEN, info, info_len, out,
                      out_len);
}

static void aead_seal(const uint8_t key[TLS_AEAD_KEY_LEN],
                      const uint8_t nonce[TLS_AEAD_IV_LEN], const uint8_t *aad,
                      size_t aad_len, const uint8_t *in, size_t len,
                      uint8_t *out, uint8_t tag[TLS_AEAD_TAG_LEN]) {
  mbedtls_gcm_context g;
  mbedtls_gcm_init(&g);
  mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 128);
  mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, len, nonce,
                            TLS_AEAD_IV_LEN, aad, aad_len, in, out,
                            TLS_AEAD_TAG_LEN, tag);
  mbedtls_gcm_free(&g);
}

static int aead_open(const uint8_t key[TLS_AEAD_KEY_LEN],
                     const uint8_t nonce[TLS_AEAD_IV_LEN], const uint8_t *aad,
                     size_t aad_len, const uint8_t *in, size_t len,
                     const uint8_t tag[TLS_AEAD_TAG_LEN], uint8_t *out) {
  mbedtls_gcm_context g;
  int r;
  mbedtls_gcm_init(&g);
  mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 128);
  r = mbedtls_gcm_auth_decrypt(&g, len, nonce, TLS_AEAD_IV_LEN, aad, aad_len,
                               tag, TLS_AEAD_TAG_LEN, in, out);
  mbedtls_gcm_free(&g);
  return r == 0 ? 0 : -1;
}

static mbedtls_ecp_group_id group_id(uint16_t group) {
  switch (group) {
  case TLS_GROUP_X25519:
    return MBEDTLS_ECP_DP_CURVE25519;
  case TLS_GROUP_SECP256R1:
    return MBEDTLS_ECP_DP_SECP256R1;
  default:
    return MBEDTLS_ECP_DP_NONE;
  }
}

static int kx_keygen(void *ctx, uint16_t group, uint8_t *priv, uint8_t *pub,
                     size_t *pub_len) {
  tls_mbedtls_t *be = (tls_mbedtls_t *)ctx;
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point q;
  mbedtls_ecp_group_id id = group_id(group);
  int r = -1;

  if (id == MBEDTLS_ECP_DP_NONE)
    return -1;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&q);
  if (mbedtls_ecp_group_load(&grp, id) == 0 &&
      mbedtls_ecp_gen_keypair(&grp, &d, &q, mbedtls_ctr_drbg_random,
                              &be->drbg) == 0 &&
      mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                     pub_len, pub, TLS_KX_PUB_MAX) == 0) {
    /* RFC 7748 scalars are little-endian; P-256 private keys big-endian */
    r = (id == MBEDTLS_ECP_DP_CURVE25519)
            ? mbedtls_mpi_write_binary_le(&d, priv, 32)
            : mbedtls_mpi_write_binary(&d, priv, 32);
  }
  mbedtls_ecp_point_free(&q);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return r == 0 ? 0 : -1;
}

static int kx_shared(void *ctx, uint16_t group, const uint8_t *priv,
                     const uint8_t *peer, size_t peer_len,
                     uint8_t shared[TLS_HASH_LEN]) {
  tls_mbedtls_t *be = (tls_mbedtls_t *)ctx;
  mbedtls_ecp_group grp;
  mbedtls_mpi d, z;
  mbedtls_ecp_point q;
  mbedtls_ecp_group_id id = group_id(group);
  uint8_t k[32];
  int r = -1;

  if (id == MBEDTLS_ECP_DP_NONE ||
      peer_len != (id == MBEDTLS_ECP_DP_CURVE25519 ? 32u : 65u))
    return -1;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&z);
  mbedtls_ecp_point_init(&q);
  if (mbedtls_ecp_group_load(&grp, id) != 0)
    goto done;
  if (id == MBEDTLS_ECP_DP_CURVE25519) {
    /* X25519 clamps the scalar (RFC 7748 §5) */
    memcpy(k, priv, 32);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    if (mbedtls_mpi_read_binary_le(&d, k, 32) != 0)
      goto done;
  } else if (mbedtls_mpi_read_binary(&d, priv, 32) != 0) {
    goto done;
  }
  /* RFC 8446 §4.2.8.2: reject shares that are not points of the group */
  if (mbedtls_ecp_point_read_binary(&grp, &q, peer, peer_len) != 0 ||
      mbedtls_ecp_check_pubkey(&grp, &q) != 0)
    goto done;
  if (mbedtls_ecdh_compute_shared(&grp, &z, &q, &d, mbedtls_ctr_drbg_random,
                                  &be->drbg) != 0)
    goto done;
  r = (id == MBEDTLS_ECP_DP_CURVE25519)
          ? mbedtls_mpi_write_binary_le(&z, shared, 32)
          : mbedtls_mpi_write_binary(&z, shared, 32);
  if (r == 0) {
    /* RFC 7748 §6.1: an all-zero X25519 result means a bad share */
    uint8_t acc = 0;
    int i;
    for (i = 0; i < 32; i++)
      acc |= shared[i];
    if (acc == 0)
      r = -1;
  }
done:
  memset(k, 0, sizeof(k));
  mbedtls_ecp_point_free(&q);
  mbedtls_mpi_free(&z);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return r == 0 ? 0 : -1;
}

static int sign(void *ctx, const void *key, uint16_t scheme, const uint8_t *msg,
                size_t len, uint8_t *sig, size_t *sig_len, size_t sig_cap) {
  tls_mbedtls_t *be = (tls_mbedtls_t *)ctx;
  mbedtls_pk_context *pk = (mbedtls_pk_context *)(uintptr_t)key;
  uint8_t hash[32];
  int r;

  mbedtls_sha256(msg, len, hash, 0);
  if (scheme == TLS_SIG_ECDSA_SECP256R1_SHA256 &&
      mbedtls_pk_can_do(pk, MBEDTLS_PK_ECDSA))
    r = mbedtls_pk_sign(pk, MBEDTLS_MD_SHA256, hash, 32, sig, sig_cap, sig_len,
                        mbedtls_ctr_drbg_random, &be->drbg);
  else if (scheme == TLS_SIG_RSA_PSS_RSAE_SHA256 &&
           mbedtls_pk_can_do(pk, MBEDTLS_PK_RSA))
    r = mbedtls_pk_sign_ext(MBEDTLS_PK_RSASSA_PSS, pk, MBEDTLS_MD_SHA256, hash,
                            32, sig, sig_cap, sig_len, mbedtls_ctr_drbg_random,
                            &be->drbg);
  else
    r = -1;
  return r == 0 ? 0 : -1;
}

/* Verify with an already parsed public key */
static int verify_pk(mbedtls_pk_context *pk, uint16_t scheme,
                     const uint8_t *msg, size_t len, const uint8_t *sig,
                     size_t sig_len) {
  uint8_t hash[32];
  mbedtls_sha256(msg, len, hash, 0);
  if (scheme == TLS_SIG_ECDSA_SECP256R1_SHA256) {
    /* the scheme names the curve too (RFC 8446 §4.2.3) */
    if (!mbedtls_pk_can_do(pk, MBEDTLS_PK_ECDSA) ||
        mbedtls_ecp_keypair_get_group_id(mbedtls_pk_ec(*pk)) !=
            MBEDTLS_ECP_DP_SECP256R1)
      return -1;
    return mbedtls_pk_verify(pk, MBEDTLS_MD_SHA256, hash, 32, sig, sig_len) == 0
               ? 0
               : -1;
  }
  if (scheme == TLS_SIG_RSA_PSS_RSAE_SHA256) {
    mbedtls_pk_rsassa_pss_options opt;
    if (mbedtls_pk_get_type(pk) != MBEDTLS_PK_RSA)
      return -1;
    opt.mgf1_hash_id = MBEDTLS_MD_SHA256;
    opt.expected_salt_len = 32; /* salt = hash length (RFC 8446 §4.2.3) */
    return mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS, &opt, pk,
                                 MBEDTLS_MD_SHA256, hash, 32, sig, sig_len) == 0
               ? 0
               : -1;
  }
  return -1;
}

static int verify(void *ctx, const uint8_t *cert, size_t cert_len,
                  uint16_t scheme, const uint8_t *msg, size_t len,
                  const uint8_t *sig, size_t sig_len) {
  mbedtls_x509_crt crt;
  int r = -1;
  (void)ctx;
  mbedtls_x509_crt_init(&crt);
  if (mbedtls_x509_crt_parse_der(&crt, cert, cert_len) == 0)
    r = verify_pk(&crt.pk, scheme, msg, len, sig, sig_len);
  mbedtls_x509_crt_free(&crt);
  return r;
}

/* Returns 0, or the alert that says why the chain is refused */
static int verify_chain(void *ctx, const uint8_t *const *certs,
                        const uint16_t *lens, uint8_t count,
                        const char *hostname) {
  tls_mbedtls_t *be = (tls_mbedtls_t *)ctx;
  mbedtls_x509_crt chain;
  uint32_t flags = 0;
  uint8_t i;
  int r = TLS_ALERT_BAD_CERTIFICATE;

  if (be->ca_count == 0 || count == 0)
    return TLS_ALERT_UNKNOWN_CA;
  mbedtls_x509_crt_init(&chain);
  for (i = 0; i < count; i++) {
    if (mbedtls_x509_crt_parse_der(&chain, certs[i], lens[i]) != 0)
      goto done;
  }
  if (mbedtls_x509_crt_verify(&chain, &be->ca, NULL, hostname, &flags, NULL,
                              NULL) == 0 &&
      flags == 0)
    r = 0;
  else if (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
    r = TLS_ALERT_UNKNOWN_CA;
  else if (flags & (MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE))
    r = TLS_ALERT_CERTIFICATE_EXPIRED;
  else if (flags & MBEDTLS_X509_BADCERT_REVOKED)
    r = TLS_ALERT_CERTIFICATE_REVOKED;
done:
  mbedtls_x509_crt_free(&chain);
  return r;
}

static int random_bytes(void *ctx, uint8_t *out, size_t len) {
  tls_mbedtls_t *be = (tls_mbedtls_t *)ctx;
  return mbedtls_ctr_drbg_random(&be->drbg, out, len) == 0 ? 0 : -1;
}

int tls_mbedtls_init(tls_mbedtls_t *be, tls_crypto_t *c) {
  static const char pers[] = "smallest_tcp tls";
  int r;

  mbedtls_entropy_init(&be->entropy);
  mbedtls_ctr_drbg_init(&be->drbg);
  mbedtls_x509_crt_init(&be->ca);
  be->ca_count = 0;
  r = mbedtls_ctr_drbg_seed(&be->drbg, mbedtls_entropy_func, &be->entropy,
                            (const unsigned char *)pers, sizeof(pers) - 1);
  if (r != 0)
    return r;

  c->hash_init = hash_init;
  c->hash_update = hash_update;
  c->hash_peek = hash_peek;
  c->hmac = hmac;
  c->hkdf_extract = hkdf_extract;
  c->hkdf_expand = hkdf_expand;
  c->aead_seal = aead_seal;
  c->aead_open = aead_open;
  c->kx_keygen = kx_keygen;
  c->kx_shared = kx_shared;
  c->sign = sign;
  c->verify = verify;
  c->verify_chain = verify_chain;
  c->random = random_bytes;
  c->ctx = be;
  return 0;
}

int tls_mbedtls_set_ca(tls_mbedtls_t *be, const uint8_t *cert, size_t len) {
  int r = mbedtls_x509_crt_parse(&be->ca, cert, len);
  if (r == 0)
    be->ca_count++;
  return r;
}

int tls_mbedtls_parse_key(tls_mbedtls_t *be, mbedtls_pk_context *key,
                          const uint8_t *pem_or_der, size_t len) {
  mbedtls_pk_init(key);
  return mbedtls_pk_parse_key(key, pem_or_der, len, NULL, 0,
                              mbedtls_ctr_drbg_random, &be->drbg);
}

int tls_mbedtls_use_arena(uint8_t *arena, size_t len) {
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
  mbedtls_memory_buffer_alloc_init(arena, len);
  return 0;
#else
  (void)arena;
  (void)len;
  return -1;
#endif
}

void tls_mbedtls_free(tls_mbedtls_t *be) {
  mbedtls_x509_crt_free(&be->ca);
  mbedtls_ctr_drbg_free(&be->drbg);
  mbedtls_entropy_free(&be->entropy);
}
