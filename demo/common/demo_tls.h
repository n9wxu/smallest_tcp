/**
 * @file demo/common/demo_tls.h
 * @brief Shared by the TLS demos: the Mbed TLS backend, a server's
 *        credentials, and a pre-shared key from the environment.
 *
 *   TLS_CERT, TLS_KEY  a server's chain (PEM, leaf first) and key; the
 *                      defaults are the test credentials in tests/tls
 *   TLS_PSK            a pre-shared key, hex
 *   TLS_PSK_ID         its identity                   (default "device-1")
 *   TLS_PSK_MODES      "dhe" (psk_dhe_ke, the default), "ke" or "both"
 */

#ifndef DEMO_TLS_H
#define DEMO_TLS_H

#include "tls.h"
#include "tls_crypto_mbedtls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEMO_TLS_MAX_CHAIN 4
/** Room for the largest record a peer may send, and a partial message */
#define DEMO_TLS_RX_SIZE (TLS_RECORD_HDR + TLS_MAX_CIPHERTEXT + 512u)
#define DEMO_TLS_TX_SIZE 4096u

typedef struct {
  tls_mbedtls_t backend;
  tls_crypto_t crypto;
  mbedtls_x509_crt chain;
  mbedtls_pk_context key;
  const uint8_t *chain_der[DEMO_TLS_MAX_CHAIN];
  uint16_t chain_len[DEMO_TLS_MAX_CHAIN];
  uint8_t psk[64];
} demo_tls_t;

static inline const char *demo_env(const char *name, const char *dflt) {
  const char *v = getenv(name);
  return v && *v ? v : dflt;
}

/* A PEM file, NUL-terminated as Mbed TLS wants it counted; its length or 0 */
static inline size_t demo_read_pem(const char *path, uint8_t *buf, size_t cap) {
  FILE *f = fopen(path, "rb");
  size_t n;
  if (!f)
    return 0;
  n = fread(buf, 1, cap - 1, f);
  fclose(f);
  buf[n++] = 0;
  return n;
}

/* The PSK fields of @p cfg from the environment: 0 if none is set, 1 if
 * one is, -1 if TLS_PSK is not valid hex */
static inline int demo_tls_psk(tls_config_t *cfg, uint8_t *buf, size_t cap) {
  const char *hex = getenv("TLS_PSK");
  const char *id = demo_env("TLS_PSK_ID", "device-1");
  const char *modes = getenv("TLS_PSK_MODES");
  size_t n = 0;
  if (!hex || !*hex)
    return 0;
  while (hex[0] && hex[1] && n < cap) {
    unsigned v;
    if (sscanf(hex, "%2x", &v) != 1)
      return -1;
    buf[n++] = (uint8_t)v;
    hex += 2;
  }
  if (*hex || n == 0)
    return -1;
  cfg->psk = buf;
  cfg->psk_len = (uint16_t)n;
  cfg->psk_id = (const uint8_t *)id;
  cfg->psk_id_len = (uint16_t)strlen(id);
  cfg->psk_modes = TLS_PSK_DHE_KE;
  if (modes && strcmp(modes, "ke") == 0)
    cfg->psk_modes = TLS_PSK_KE;
  else if (modes && strcmp(modes, "both") == 0)
    cfg->psk_modes = TLS_PSK_KE | TLS_PSK_DHE_KE;
  return 1;
}

/** The backend in @p cfg, for a client or a server. */
static inline int demo_tls_backend(demo_tls_t *d, tls_config_t *cfg,
                                   const char *tag) {
  mbedtls_x509_crt_init(&d->chain);
  mbedtls_pk_init(&d->key);
  if (tls_mbedtls_init(&d->backend, &d->crypto) != 0) {
    fprintf(stderr, "[%s] Mbed TLS initialisation failed\n", tag);
    return -1;
  }
  cfg->crypto = &d->crypto;
  if (demo_tls_psk(cfg, d->psk, sizeof(d->psk)) < 0) {
    fprintf(stderr, "[%s] TLS_PSK is not hex\n", tag);
    return -1;
  }
  return 0;
}

/**
 * A server's configuration: the backend, the chain and key named by
 * TLS_CERT / TLS_KEY (else @p default_cert / @p default_key) — an ECDSA
 * P-256 key signs with ecdsa_secp256r1_sha256, an RSA key with
 * rsa_pss_rsae_sha256 — and an optional PSK.
 */
static inline int demo_tls_server(demo_tls_t *d, tls_config_t *cfg,
                                  const char *default_cert,
                                  const char *default_key, const char *tag) {
  const char *cert_path = demo_env("TLS_CERT", default_cert);
  const char *key_path = demo_env("TLS_KEY", default_key);
  static uint8_t pem[16384];
  mbedtls_x509_crt *crt;
  size_t n;

  if (demo_tls_backend(d, cfg, tag) != 0)
    return -1;
  if (mbedtls_x509_crt_parse_file(&d->chain, cert_path) != 0) {
    fprintf(stderr, "[%s] cannot read certificate %s\n", tag, cert_path);
    return -1;
  }
  for (crt = &d->chain;
       crt && crt->raw.len && cfg->cert_count < DEMO_TLS_MAX_CHAIN;
       crt = crt->next) {
    d->chain_der[cfg->cert_count] = crt->raw.p;
    d->chain_len[cfg->cert_count] = (uint16_t)crt->raw.len;
    cfg->cert_count++;
  }
  if (!(n = demo_read_pem(key_path, pem, sizeof(pem))) ||
      tls_mbedtls_parse_key(&d->backend, &d->key, pem, n) != 0) {
    fprintf(stderr, "[%s] cannot read key %s\n", tag, key_path);
    return -1;
  }
  cfg->cert = d->chain_der;
  cfg->cert_len = d->chain_len;
  cfg->key = &d->key;
  cfg->sig_scheme = mbedtls_pk_get_type(&d->key) == MBEDTLS_PK_ECKEY
                        ? TLS_SIG_ECDSA_SECP256R1_SHA256
                        : TLS_SIG_RSA_PSS_RSAE_SHA256;
  return 0;
}

static inline void demo_tls_free(demo_tls_t *d) {
  mbedtls_pk_free(&d->key);
  mbedtls_x509_crt_free(&d->chain);
  tls_mbedtls_free(&d->backend);
}

static inline const char *demo_tls_group_name(const tls_conn_t *tls) {
  return tls->group == TLS_GROUP_X25519      ? "x25519"
         : tls->group == TLS_GROUP_SECP256R1 ? "secp256r1"
                                             : "no (EC)DHE";
}

#endif /* DEMO_TLS_H */
