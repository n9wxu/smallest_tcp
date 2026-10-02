/**
 * @file tls_peer.c
 * @brief The integration tests' TLS 1.3 / DTLS 1.3 peer (tls_peer.h):
 *        written from RFC 8446 and RFC 9147 on Mbed TLS's primitives,
 *        with none of the stack's TLS code.
 */

#include "tls_peer.h"

#include <mbedtls/aes.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <string.h>

static const uint8_t zeros[32];

/* SHA-256("HelloRetryRequest") */
const uint8_t tp_hrr_random[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
    0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB,
    0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

uint32_t tp_get(const uint8_t *p, int n) {
  uint32_t v = 0;
  while (n--)
    v = (v << 8) | *p++;
  return v;
}

void tp_put(uint8_t *p, int n, uint32_t v) {
  while (n--) {
    p[n] = (uint8_t)v;
    v >>= 8;
  }
}

/* ── Primitives ── */

void tp_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
  mbedtls_sha256(data, len, out, 0);
}

void tp_hmac(const uint8_t *key, size_t key_len, const uint8_t *data,
             size_t len, uint8_t out[32]) {
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, key_len,
                  data, len, out);
}

/* HKDF-Expand (RFC 5869 §2.3) of at most one hash length is its first
 * block: T(1) = HMAC(PRK, info | 0x01) */
void tp_expand_label(int dtls, const uint8_t secret[32], const char *label,
                     const uint8_t *context, size_t context_len, uint8_t *out,
                     size_t out_len) {
  uint8_t info[2 + 1 + 6 + 32 + 1 + 32 + 1], t[32];
  size_t ll = strlen(label), n = 2;
  tp_put(info, 2, (uint32_t)out_len);
  info[n++] = (uint8_t)(6 + ll);
  memcpy(info + n, dtls ? "dtls13" : "tls13 ", 6);
  n += 6;
  memcpy(info + n, label, ll);
  n += ll;
  info[n++] = (uint8_t)context_len;
  if (context_len)
    memcpy(info + n, context, context_len);
  n += context_len;
  info[n++] = 1;
  tp_hmac(secret, 32, info, n, t);
  memcpy(out, t, out_len);
}

/* Derive-Secret (RFC 8446 §7.1), @p hash being Transcript-Hash(Messages) */
static void derive_secret(int dtls, const uint8_t secret[32], const char *label,
                          const uint8_t hash[32], uint8_t out[32]) {
  tp_expand_label(dtls, secret, label, hash, 32, out, 32);
}

/* Test randomness: a hash chain */
static int tp_rng(void *ctx, unsigned char *out, size_t len) {
  static uint8_t state[32];
  (void)ctx;
  while (len) {
    size_t k = len < 32 ? len : 32;
    state[0]++;
    tp_sha256(state, 32, state);
    memcpy(out, state, k);
    out += k;
    len -= k;
  }
  return 0;
}

void tp_x25519_keygen(uint8_t priv[32], uint8_t pub[32]) {
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point q;
  size_t n;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&q);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
  mbedtls_ecp_gen_keypair(&grp, &d, &q, tp_rng, NULL);
  mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED, &n, pub,
                                 32);
  mbedtls_mpi_write_binary_le(&d, priv, 32);
  mbedtls_ecp_point_free(&q);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
}

int tp_x25519(const uint8_t priv[32], const uint8_t peer[32],
              uint8_t shared[32]) {
  mbedtls_ecp_group grp;
  mbedtls_mpi d, z;
  mbedtls_ecp_point q;
  int r;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&z);
  mbedtls_ecp_point_init(&q);
  r = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) ||
      mbedtls_mpi_read_binary_le(&d, priv, 32) ||
      mbedtls_ecp_point_read_binary(&grp, &q, peer, 32) ||
      mbedtls_ecdh_compute_shared(&grp, &z, &q, &d, tp_rng, NULL) ||
      mbedtls_mpi_write_binary_le(&z, shared, 32);
  mbedtls_ecp_point_free(&q);
  mbedtls_mpi_free(&z);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return r ? -1 : 0;
}

static void gcm_seal(const tp_keys_t *k, const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len, const uint8_t *in,
                     size_t len, uint8_t *out, uint8_t tag[16]) {
  mbedtls_gcm_context g;
  mbedtls_gcm_init(&g);
  mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, k->key, 128);
  mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, len, nonce, 12, aad,
                            aad_len, in, out, 16, tag);
  mbedtls_gcm_free(&g);
}

static int gcm_open(const tp_keys_t *k, const uint8_t nonce[12],
                    const uint8_t *aad, size_t aad_len, const uint8_t *in,
                    size_t len, const uint8_t tag[16], uint8_t *out) {
  mbedtls_gcm_context g;
  int r;
  mbedtls_gcm_init(&g);
  mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, k->key, 128);
  r = mbedtls_gcm_auth_decrypt(&g, len, nonce, 12, aad, aad_len, tag, 16, in,
                               out);
  mbedtls_gcm_free(&g);
  return r;
}

/* The per-record nonce: the IV XOR the 64-bit sequence number, right
 * aligned (RFC 8446 §5.3) */
static void nonce_of(const tp_keys_t *k, uint64_t seq, uint8_t nonce[12]) {
  int i;
  memcpy(nonce, k->iv, 12);
  for (i = 11; i >= 4; i--) {
    nonce[i] ^= (uint8_t)seq;
    seq >>= 8;
  }
}

/* ── Records ── */

void tp_traffic_keys(int dtls, const uint8_t secret[32], tp_keys_t *k) {
  tp_expand_label(dtls, secret, "key", NULL, 0, k->key, 16);
  tp_expand_label(dtls, secret, "iv", NULL, 0, k->iv, 12);
  tp_expand_label(dtls, secret, "sn", NULL, 0, k->sn, 16);
  k->seq = 0;
}

size_t tp_record(uint8_t type, const uint8_t *content, size_t n, uint8_t *rec) {
  rec[0] = type;
  tp_put(rec + 1, 2, 0x0303);
  tp_put(rec + 3, 2, (uint32_t)n);
  memcpy(rec + 5, content, n);
  return 5 + n;
}

size_t tp_seal(tp_keys_t *k, uint8_t type, const uint8_t *content, size_t n,
               size_t pad, uint8_t *rec) {
  static uint8_t inner[17000];
  uint8_t nonce[12];
  size_t len = n + 1 + pad;
  memcpy(inner, content, n);
  inner[n] = type;
  memset(inner + n + 1, 0, pad);
  rec[0] = TP_APPDATA;
  tp_put(rec + 1, 2, 0x0303);
  tp_put(rec + 3, 2, (uint32_t)(len + 16));
  nonce_of(k, k->seq++, nonce);
  gcm_seal(k, nonce, rec, 5, inner, len, rec + 5, rec + 5 + len);
  return 5 + len + 16;
}

/* TLSInnerPlaintext: content, type, zeros */
static int strip_inner(const uint8_t *inner, size_t len, uint8_t *type) {
  while (len && inner[len - 1] == 0)
    len--;
  if (!len)
    return -1;
  *type = inner[len - 1];
  return (int)(len - 1);
}

int tp_open(tp_keys_t *k, const uint8_t *rec, size_t rec_len, uint8_t *content,
            uint8_t *type) {
  uint8_t nonce[12];
  size_t len;
  if (rec_len < 5 + 17 || rec[0] != TP_APPDATA ||
      tp_get(rec + 3, 2) != rec_len - 5)
    return -1;
  len = rec_len - 5 - 16;
  nonce_of(k, k->seq, nonce);
  if (gcm_open(k, nonce, rec, 5, rec + 5, len, rec + 5 + len, content) != 0)
    return -1;
  k->seq++;
  return strip_inner(content, len, type);
}

size_t tp_drecord(uint8_t type, uint64_t seq, const uint8_t *content, size_t n,
                  uint8_t *rec) {
  rec[0] = type;
  tp_put(rec + 1, 2, 0xFEFD);
  tp_put(rec + 3, 2, 0); /* epoch */
  tp_put(rec + 5, 2, (uint32_t)(seq >> 32));
  tp_put(rec + 7, 4, (uint32_t)seq);
  tp_put(rec + 11, 2, (uint32_t)n);
  memcpy(rec + 13, content, n);
  return 13 + n;
}

static void aes_block(const uint8_t key[16], const uint8_t in[16],
                      uint8_t out[16]) {
  mbedtls_aes_context a;
  mbedtls_aes_init(&a);
  mbedtls_aes_setkey_enc(&a, key, 128);
  mbedtls_aes_crypt_ecb(&a, MBEDTLS_AES_ENCRYPT, in, out);
  mbedtls_aes_free(&a);
}

size_t tp_dseal(tp_keys_t *k, unsigned epoch, uint8_t type,
                const uint8_t *content, size_t n, int short_hdr, uint8_t *rec) {
  static uint8_t inner[17000];
  uint8_t nonce[12], mask[16];
  size_t h = 0, len = n + 1;
  memcpy(inner, content, n);
  inner[n] = type;
  /* 0 0 1 C S L E E */
  rec[h++] = (uint8_t)(0x20 | (short_hdr ? 0 : 0x0C) | (epoch & 3));
  if (!short_hdr)
    rec[h++] = (uint8_t)(k->seq >> 8);
  rec[h++] = (uint8_t)k->seq;
  if (!short_hdr) {
    tp_put(rec + h, 2, (uint32_t)(len + 16));
    h += 2;
  }
  nonce_of(k, k->seq++, nonce);
  gcm_seal(k, nonce, rec, h, inner, len, rec + h, rec + h + len);
  aes_block(k->sn, rec + h, mask); /* RFC 9147 §4.2.3 */
  rec[1] ^= mask[0];
  if (!short_hdr)
    rec[2] ^= mask[1];
  return h + len + 16;
}

int tp_dopen(const tp_keys_t *k, const uint8_t *rec, size_t avail,
             uint8_t *content, uint8_t *type, tp_drec_t *info) {
  uint8_t hdr[5], mask[16], nonce[12];
  size_t len;
  if (avail < 5 || (rec[0] & 0xFC) != 0x2C)
    return -1;
  len = tp_get(rec + 3, 2);
  if (len < 17 || len > avail - 5)
    return -1;
  aes_block(k->sn, rec + 5, mask);
  memcpy(hdr, rec, 5);
  hdr[1] ^= mask[0];
  hdr[2] ^= mask[1];
  info->epoch_bits = rec[0] & 3u;
  info->seq = (uint16_t)tp_get(hdr + 1, 2);
  info->rec_len = 5 + len;
  nonce_of(k, info->seq, nonce);
  if (gcm_open(k, nonce, hdr, 5, rec + 5, len - 16, rec + 5 + len - 16,
               content) != 0)
    return -1;
  return strip_inner(content, len - 16, type);
}

/* ── The handshake ── */

void tp_init(tp_t *p, int dtls, const uint8_t *psk, size_t psk_len,
             const char *psk_id) {
  memset(p, 0, sizeof(*p));
  p->dtls = dtls;
  p->psk = psk;
  p->psk_len = psk_len;
  p->psk_id = psk_id;
  tp_rng(NULL, p->random, 32);
  tp_x25519_keygen(p->x_priv, p->x_pub);
}

void tp_add(tp_t *p, const uint8_t *msg, size_t len) {
  memcpy(p->transcript + p->transcript_len, msg, len);
  p->transcript_len += len;
}

void tp_transcript_hash(const tp_t *p, uint8_t out[32]) {
  tp_sha256(p->transcript, p->transcript_len, out);
}

void tp_message_hash(tp_t *p) {
  uint8_t h[32];
  tp_transcript_hash(p, h);
  p->transcript[0] = 254;
  tp_put(p->transcript + 1, 3, 32);
  memcpy(p->transcript + 4, h, 32);
  p->transcript_len = 36;
}

void tp_early_secret(tp_t *p, int with_psk) {
  if (with_psk)
    tp_hmac(zeros, 32, p->psk, p->psk_len, p->early);
  else
    tp_hmac(zeros, 32, zeros, 32, p->early);
}

void tp_verify_data(const tp_t *p, const uint8_t base[32], uint8_t out[32]) {
  uint8_t fk[32], h[32];
  tp_expand_label(p->dtls, base, "finished", NULL, 0, fk, 32);
  tp_transcript_hash(p, h);
  tp_hmac(fk, 32, h, 32, out);
}

/* The binder of a ClientHello whose bytes before the binders list are
 * @p msg[0 .. @p truncated) (RFC 8446 §4.2.11.2) */
static void binder_of(tp_t *p, const uint8_t *msg, size_t truncated,
                      uint8_t out[32]) {
  static uint8_t buf[TP_TRANSCRIPT_MAX];
  uint8_t empty[32], key[32], fk[32], h[32];
  tp_early_secret(p, 1);
  tp_sha256(NULL, 0, empty);
  derive_secret(p->dtls, p->early, "ext binder", empty, key);
  tp_expand_label(p->dtls, key, "finished", NULL, 0, fk, 32);
  memcpy(buf, p->transcript, p->transcript_len);
  memcpy(buf + p->transcript_len, msg, truncated);
  tp_sha256(buf, p->transcript_len + truncated, h);
  tp_hmac(fk, 32, h, 32, out);
}

static uint8_t *ext_begin(uint8_t *q, uint16_t type) {
  tp_put(q, 2, type);
  return q + 4;
}

static uint8_t *ext_end(uint8_t *start, uint8_t *q) {
  tp_put(start + 2, 2, (uint32_t)(q - start - 4));
  return q;
}

static uint16_t version_13(const tp_t *p) { return p->dtls ? 0xFEFC : 0x0304; }

static uint16_t legacy_version(const tp_t *p) {
  return p->dtls ? 0xFEFD : 0x0303;
}

size_t tp_client_hello(tp_t *p, const tp_ch_t *o, uint8_t *msg) {
  uint8_t *q = msg + 4, *exts, *e, *binders = NULL;
  size_t idl = p->psk_id ? strlen(p->psk_id) : 0;
  int i;
  msg[0] = TP_CLIENT_HELLO;
  tp_put(q, 2, legacy_version(p));
  memcpy(q + 2, p->random, 32);
  q += 34;
  *q++ = (uint8_t)o->session_id_len;
  if (o->session_id_len)
    memcpy(q, o->session_id, o->session_id_len);
  q += o->session_id_len;
  if (p->dtls) {
    *q++ = (uint8_t)o->legacy_cookie_len;
    if (o->legacy_cookie_len)
      memcpy(q, o->legacy_cookie, o->legacy_cookie_len);
    q += o->legacy_cookie_len;
  }
  tp_put(q, 2, 4); /* a suite the stack does not have, then ours */
  tp_put(q + 2, 2, 0x1302);
  tp_put(q + 4, 2, o->no_suite ? 0x1303 : TP_SUITE);
  q[6] = 1;
  q[7] = o->compression;
  exts = q + 8;
  q = exts + 2;
  for (i = 0; i < (o->no_versions ? 0 : o->twice ? 2 : 1); i++) {
    e = q;
    q = ext_begin(q, TP_EXT_SUPPORTED_VERSIONS);
    *q++ = 2;
    tp_put(q, 2, o->version ? o->version : version_13(p));
    q = ext_end(e, q + 2);
  }
  if (o->share || o->groups_no_share || o->groups_only) {
    e = q;
    q = ext_begin(q, TP_EXT_SUPPORTED_GROUPS);
    tp_put(q, 2, 4);
    tp_put(q + 2, 2, TP_P256);
    tp_put(q + 4, 2, TP_X25519);
    q = ext_end(e, q + 6);
  }
  if (o->share || o->groups_no_share) {
    e = q;
    q = ext_begin(q, TP_EXT_KEY_SHARE);
    if (o->share) {
      tp_put(q, 2, 36);
      tp_put(q + 2, 2, TP_X25519);
      tp_put(q + 4, 2, 32);
      memcpy(q + 6, p->x_pub, 32);
      if (o->zero_share)
        memset(q + 6, 0, 32);
      q += 38;
    } else {
      tp_put(q, 2, 0);
      q += 2;
    }
    q = ext_end(e, q);
  }
  if (o->sig_algs) {
    e = q;
    q = ext_begin(q, TP_EXT_SIGNATURE_ALGORITHMS);
    tp_put(q, 2, 4);
    tp_put(q + 2, 2, 0x0403);
    tp_put(q + 4, 2, 0x0804);
    q = ext_end(e, q + 6);
  }
  if (o->mfl) {
    e = q;
    q = ext_begin(q, TP_EXT_MAX_FRAGMENT_LENGTH);
    *q++ = o->mfl;
    q = ext_end(e, q);
  }
  if (o->cookie_len) {
    e = q;
    q = ext_begin(q, TP_EXT_COOKIE);
    tp_put(q, 2, (uint32_t)o->cookie_len);
    memcpy(q + 2, o->cookie, o->cookie_len);
    q = ext_end(e, q + 2 + o->cookie_len);
  }
  if (!o->no_psk) {
    if (!o->no_modes) {
      e = q;
      q = ext_begin(q, TP_EXT_PSK_MODES);
      *q++ = (uint8_t)((o->psk_dhe ? 1 : 0) + (o->psk_ke ? 1 : 0));
      if (o->psk_dhe)
        *q++ = 1;
      if (o->psk_ke)
        *q++ = 0;
      q = ext_end(e, q);
    }
    e = q; /* pre_shared_key: the last extension */
    q = ext_begin(q, TP_EXT_PRE_SHARED_KEY);
    tp_put(q, 2, (uint32_t)(2 + idl + 4));
    tp_put(q + 2, 2, (uint32_t)idl);
    memcpy(q + 4, p->psk_id, idl);
    tp_put(q + 4 + idl, 4, 0); /* obfuscated_ticket_age */
    q += 8 + idl;
    binders = q;
    tp_put(q, 2, 33);
    q[2] = 32;
    q = ext_end(e, q + 35);
    if (o->psk_not_last) {
      e = q;
      q = ext_end(e, ext_begin(q, 0x0A0A));
    }
  }
  tp_put(exts, 2, (uint32_t)(q - exts - 2));
  if (o->truncated)
    q -= 3;
  tp_put(msg + 1, 3, (uint32_t)(q - msg - 4));
  if (binders) {
    binder_of(p, msg, (size_t)(binders - msg), binders + 3);
    if (o->bad_binder)
      binders[3] ^= 1;
  }
  tp_add(p, msg, (size_t)(q - msg));
  return (size_t)(q - msg);
}

int tp_parse_hello(const uint8_t *msg, size_t len, int dtls, tp_hello_t *h) {
  const uint8_t *q = msg + 4, *end = msg + len, *x;
  int client = len > 0 && msg[0] == TP_CLIENT_HELLO;
  memset(h, 0, sizeof(*h));
  if (len < 4 + 35 ||
      (msg[0] != TP_CLIENT_HELLO && msg[0] != TP_SERVER_HELLO) ||
      tp_get(msg + 1, 3) != len - 4)
    return 0;
  h->legacy_version = (uint16_t)tp_get(q, 2);
  h->random = q + 2;
  q += 34;
  h->session_id_len = *q++;
  h->session_id = q;
  q += h->session_id_len;
  if (q + 4 > end)
    return 0;
  if (client && dtls) {
    h->legacy_cookie_len = *q++;
    h->legacy_cookie = q;
    q += h->legacy_cookie_len;
    if (q + 4 > end)
      return 0;
  }
  if (client) {
    h->suites_len = tp_get(q, 2);
    h->suites = q + 2;
    q += 2 + h->suites_len;
    if (q + 1 > end)
      return 0;
    h->compression_len = *q++;
    h->compression = q;
    q += h->compression_len;
  } else {
    h->suite = (uint16_t)tp_get(q, 2);
    h->compression_len = 1;
    h->compression = q + 2;
    q += 3;
  }
  if (q + 2 > end)
    return 0;
  h->exts_len = tp_get(q, 2);
  h->exts = q + 2;
  if (h->exts + h->exts_len != end)
    return 0;
  for (x = h->exts; x < end; x += 4 + tp_get(x + 2, 2))
    if (x + 4 > end || x + 4 + tp_get(x + 2, 2) > end)
      return 0;
  return 1;
}

const uint8_t *tp_ext(const tp_hello_t *h, uint16_t type, size_t *len) {
  const uint8_t *x, *end = h->exts + h->exts_len;
  for (x = h->exts; x < end; x += 4 + tp_get(x + 2, 2))
    if (tp_get(x, 2) == type) {
      *len = tp_get(x + 2, 2);
      return x + 4;
    }
  return NULL;
}

int tp_ext_count(const tp_hello_t *h, uint16_t *last) {
  const uint8_t *x, *end = h->exts + h->exts_len;
  int n = 0;
  for (x = h->exts; x < end; x += 4 + tp_get(x + 2, 2)) {
    *last = (uint16_t)tp_get(x, 2);
    n++;
  }
  return n;
}

int tp_binder_ok(tp_t *p, const uint8_t *msg, size_t len) {
  tp_hello_t h;
  const uint8_t *d, *binders;
  uint8_t want[32];
  size_t dl, idl;
  if (!tp_parse_hello(msg, len, p->dtls, &h) ||
      !(d = tp_ext(&h, TP_EXT_PRE_SHARED_KEY, &dl)) || dl < 2)
    return 0;
  idl = tp_get(d, 2);
  if (2 + idl + 2 + 33 != dl)
    return 0;
  binders = d + 2 + idl;
  if (tp_get(binders, 2) != 33 || binders[2] != 32)
    return 0;
  binder_of(p, msg, (size_t)(binders - msg), want);
  return memcmp(want, binders + 3, 32) == 0;
}

size_t tp_server_hello(tp_t *p, const tp_sh_t *o, uint8_t *msg) {
  uint8_t *q = msg + 4, *exts, *e;
  msg[0] = TP_SERVER_HELLO;
  tp_put(q, 2, legacy_version(p));
  memcpy(q + 2, o->hrr ? tp_hrr_random : p->random, 32);
  q += 34;
  *q++ = (uint8_t)o->session_id_len;
  if (o->session_id_len)
    memcpy(q, o->session_id, o->session_id_len);
  q += o->session_id_len;
  tp_put(q, 2, o->suite ? o->suite : TP_SUITE);
  q[2] = o->compression;
  exts = q + 3;
  q = exts + 2;
  if (!o->no_versions) {
    e = q;
    q = ext_begin(q, TP_EXT_SUPPORTED_VERSIONS);
    tp_put(q, 2, o->version ? o->version : version_13(p));
    q = ext_end(e, q + 2);
  }
  if (o->hrr && o->hrr_group) {
    e = q;
    q = ext_begin(q, TP_EXT_KEY_SHARE);
    tp_put(q, 2, o->hrr_group);
    q = ext_end(e, q + 2);
  }
  if (o->cookie_len) {
    e = q;
    q = ext_begin(q, TP_EXT_COOKIE);
    tp_put(q, 2, (uint32_t)o->cookie_len);
    memcpy(q + 2, o->cookie, o->cookie_len);
    q = ext_end(e, q + 2 + o->cookie_len);
  }
  if (o->psk) {
    e = q;
    q = ext_begin(q, TP_EXT_PRE_SHARED_KEY);
    tp_put(q, 2, 0);
    q = ext_end(e, q + 2);
  }
  if (o->share) {
    e = q;
    q = ext_begin(q, TP_EXT_KEY_SHARE);
    tp_put(q, 2, o->share_group ? o->share_group : TP_X25519);
    tp_put(q + 2, 2, 32);
    memcpy(q + 4, p->x_pub, 32);
    if (o->zero_share)
      memset(q + 4, 0, 32);
    q = ext_end(e, q + 36);
  }
  if (o->stray) {
    e = q;
    q = ext_end(e, ext_begin(q, (uint16_t)(o->stray - 1)));
  }
  tp_put(exts, 2, (uint32_t)(q - exts - 2));
  if (o->truncated)
    q -= 3;
  tp_put(msg + 1, 3, (uint32_t)(q - msg - 4));
  if (o->hrr)
    tp_message_hash(p);
  tp_add(p, msg, (size_t)(q - msg));
  return (size_t)(q - msg);
}

size_t tp_encrypted_extensions(tp_t *p, int type, const uint8_t *data,
                               size_t len, uint8_t *msg) {
  size_t n = 6;
  msg[0] = TP_ENCRYPTED_EXTENSIONS;
  if (type >= 0) {
    tp_put(msg + 6, 2, (uint32_t)type);
    tp_put(msg + 8, 2, (uint32_t)len);
    memcpy(msg + 10, data, len);
    n = 10 + len;
  }
  tp_put(msg + 4, 2, (uint32_t)(n - 6));
  tp_put(msg + 1, 3, (uint32_t)(n - 4));
  tp_add(p, msg, n);
  return n;
}

size_t tp_certificate_request(tp_t *p, uint8_t *msg) {
  uint8_t *q = msg + 4, *e;
  msg[0] = TP_CERTIFICATE_REQUEST;
  *q++ = 0; /* certificate_request_context */
  e = q;
  q += 2;
  q = ext_begin(q, TP_EXT_SIGNATURE_ALGORITHMS);
  tp_put(q, 2, 2);
  tp_put(q + 2, 2, 0x0403);
  q = ext_end(e + 2, q + 4);
  tp_put(e, 2, (uint32_t)(q - e - 2));
  tp_put(msg + 1, 3, (uint32_t)(q - msg - 4));
  tp_add(p, msg, (size_t)(q - msg));
  return (size_t)(q - msg);
}

size_t tp_certificate(tp_t *p, const uint8_t *const *der, const uint16_t *len,
                      int n, int context, uint8_t *msg) {
  uint8_t *q = msg + 4, *list;
  int i;
  msg[0] = TP_CERTIFICATE;
  *q++ = (uint8_t)context;
  memset(q, 0xC7, (size_t)context);
  q += context;
  list = q;
  q += 3;
  for (i = 0; i < n; i++) {
    tp_put(q, 3, len[i]);
    memcpy(q + 3, der[i], len[i]);
    q += 3 + len[i];
    tp_put(q, 2, 0); /* no extensions */
    q += 2;
  }
  tp_put(list, 3, (uint32_t)(q - list - 3));
  tp_put(msg + 1, 3, (uint32_t)(q - msg - 4));
  tp_add(p, msg, (size_t)(q - msg));
  return (size_t)(q - msg);
}

size_t tp_certificate_verify(tp_t *p, uint16_t scheme, const char *key,
                             size_t key_len, uint8_t *msg) {
  static const char context[] = "TLS 1.3, server CertificateVerify";
  uint8_t content[64 + sizeof(context) + 32], hash[32];
  mbedtls_pk_context pk;
  size_t sig_len = 0;
  int r;
  memset(content, 0x20, 64);
  memcpy(content + 64, context, sizeof(context)); /* with its 0 */
  tp_transcript_hash(p, content + 64 + sizeof(context));
  tp_sha256(content, sizeof(content), hash);
  mbedtls_pk_init(&pk);
  r = mbedtls_pk_parse_key(&pk, (const unsigned char *)key, key_len, NULL, 0,
                           tp_rng, NULL) ||
      mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 32, msg + 8, 80, &sig_len,
                      tp_rng, NULL);
  mbedtls_pk_free(&pk);
  if (r)
    return 0;
  msg[0] = 15; /* certificate_verify */
  tp_put(msg + 1, 3, (uint32_t)(4 + sig_len));
  tp_put(msg + 4, 2, scheme);
  tp_put(msg + 6, 2, (uint32_t)sig_len);
  tp_add(p, msg, 8 + sig_len);
  return 8 + sig_len;
}

size_t tp_finished(tp_t *p, const uint8_t base[32], uint8_t *msg) {
  msg[0] = TP_FINISHED;
  tp_put(msg + 1, 3, 32);
  tp_verify_data(p, base, msg + 4);
  tp_add(p, msg, 36);
  return 36;
}

void tp_handshake_secrets(tp_t *p, const uint8_t *dhe) {
  uint8_t empty[32], salt[32], h[32];
  tp_sha256(NULL, 0, empty);
  derive_secret(p->dtls, p->early, "derived", empty, salt);
  tp_hmac(salt, 32, dhe ? dhe : zeros, 32, p->handshake);
  tp_transcript_hash(p, h);
  derive_secret(p->dtls, p->handshake, "c hs traffic", h, p->c_hs);
  derive_secret(p->dtls, p->handshake, "s hs traffic", h, p->s_hs);
}

void tp_application_secrets(tp_t *p) {
  uint8_t empty[32], salt[32], h[32];
  tp_sha256(NULL, 0, empty);
  derive_secret(p->dtls, p->handshake, "derived", empty, salt);
  tp_hmac(salt, 32, zeros, 32, p->master);
  tp_transcript_hash(p, h);
  derive_secret(p->dtls, p->master, "c ap traffic", h, p->c_ap);
  derive_secret(p->dtls, p->master, "s ap traffic", h, p->s_ap);
}

void tp_update_secret(int dtls, uint8_t secret[32]) {
  uint8_t next[32];
  tp_expand_label(dtls, secret, "traffic upd", NULL, 0, next, 32);
  memcpy(secret, next, 32);
}

/* ── DTLS handshake messages ── */

size_t tp_dfragment(const uint8_t *msg, uint16_t mseq, size_t off, size_t n,
                    uint8_t *out) {
  memcpy(out, msg, 4); /* msg_type, length */
  tp_put(out + 4, 2, mseq);
  tp_put(out + 6, 3, (uint32_t)off);
  tp_put(out + 9, 3, (uint32_t)n);
  memcpy(out + 12, msg + 4 + off, n);
  return 12 + n;
}

size_t tp_reassemble(tp_reasm_t *r, const uint8_t *f, size_t avail,
                     size_t *done) {
  size_t len, off, n;
  uint16_t mseq;
  *done = 0;
  if (avail < 12)
    return 0;
  len = tp_get(f + 1, 3);
  mseq = (uint16_t)tp_get(f + 4, 2);
  off = tp_get(f + 6, 3);
  n = tp_get(f + 9, 3);
  if (12 + n > avail || off + n > len || 4 + len > sizeof(r->msg))
    return 0;
  if (mseq < r->next_seq) /* a retransmission of a message already whole */
    return 12 + n;
  if (r->have == r->len) { /* the message before is done: a new one */
    r->msg[0] = f[0];
    tp_put(r->msg + 1, 3, (uint32_t)len);
    r->len = len;
    r->have = 0;
    if (len == 0 && mseq == r->next_seq) {
      r->next_seq++;
      *done = 4;
      return 12;
    }
  }
  if (mseq != r->next_seq || r->msg[0] != f[0] || r->len != len ||
      off > r->have) {
    r->bad++;
    return 12 + n;
  }
  if (off < r->have)
    r->overlaps++;
  memcpy(r->msg + 4 + off, f + 12, n);
  if (off + n > r->have)
    r->have = off + n;
  if (r->have == r->len) {
    r->next_seq++;
    *done = 4 + len;
  }
  return 12 + n;
}
