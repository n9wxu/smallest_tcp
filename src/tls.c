/**
 * @file tls.c
 * @brief TLS 1.3 (RFC 8446): key schedule and record protection.
 *
 * No cryptography here (REQ-TLS-006) — HKDF, HMAC and AES-GCM come from
 * the tls_crypto_t backend.  No division: this builds for Cortex-M0.
 */

#include "tls.h"

#include <string.h>

/* SHA-256("") — Transcript-Hash of no messages, for Derive-Secret(.., "") */
static const uint8_t empty_hash[TLS_HASH_LEN] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
    0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
    0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

static const uint8_t zeros[TLS_HASH_LEN];

#define LABEL_MAX 12 /* "e exp master" */

static void put16(uint8_t *p, size_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)v;
}

static void wipe(void *p, size_t n) {
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

/* ── Key schedule ─────────────────────────────────────────────────────── */

void tls_expand_label(const tls_crypto_t *c, const uint8_t *secret,
                      const char *label, const uint8_t *context,
                      size_t context_len, uint8_t *out, size_t out_len) {
  /* struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
   * HkdfLabel, with label = "tls13 " + Label */
  uint8_t info[2 + 1 + 6 + LABEL_MAX + 1 + TLS_HASH_LEN];
  size_t ll = strlen(label), n;
  if (ll > LABEL_MAX)
    ll = LABEL_MAX;
  if (context_len > TLS_HASH_LEN)
    context_len = TLS_HASH_LEN;
  put16(info, out_len);
  info[2] = (uint8_t)(6 + ll);
  memcpy(info + 3, "tls13 ", 6);
  memcpy(info + 9, label, ll);
  n = 9 + ll;
  info[n++] = (uint8_t)context_len;
  if (context_len) {
    memcpy(info + n, context, context_len);
    n += context_len;
  }
  c->hkdf_expand(secret, info, n, out, out_len);
}

void tls_derive_secret(const tls_crypto_t *c, const uint8_t *secret,
                       const char *label, const uint8_t *hash,
                       uint8_t out[TLS_HASH_LEN]) {
  tls_expand_label(c, secret, label, hash ? hash : empty_hash, TLS_HASH_LEN,
                   out, TLS_HASH_LEN);
}

void tls_early_secret(const tls_crypto_t *c, const uint8_t *psk,
                      size_t psk_len, uint8_t out[TLS_HASH_LEN]) {
  if (!psk) {
    psk = zeros;
    psk_len = TLS_HASH_LEN;
  }
  c->hkdf_extract(zeros, TLS_HASH_LEN, psk, psk_len, out);
}

void tls_next_secret(const tls_crypto_t *c, uint8_t secret[TLS_HASH_LEN],
                     const uint8_t *ikm, size_t ikm_len) {
  uint8_t salt[TLS_HASH_LEN];
  if (!ikm) {
    ikm = zeros;
    ikm_len = TLS_HASH_LEN;
  }
  tls_derive_secret(c, secret, "derived", NULL, salt);
  c->hkdf_extract(salt, TLS_HASH_LEN, ikm, ikm_len, secret);
  wipe(salt, sizeof(salt));
}

void tls_traffic_keys(const tls_crypto_t *c, const uint8_t *secret,
                      tls_keys_t *k) {
  tls_expand_label(c, secret, "key", NULL, 0, k->key, TLS_AEAD_KEY_LEN);
  tls_expand_label(c, secret, "iv", NULL, 0, k->iv, TLS_AEAD_IV_LEN);
  k->seq = 0;
}

void tls_finished_mac(const tls_crypto_t *c, const uint8_t *base,
                      const uint8_t hash[TLS_HASH_LEN],
                      uint8_t out[TLS_HASH_LEN]) {
  uint8_t fk[TLS_HASH_LEN];
  tls_expand_label(c, base, "finished", NULL, 0, fk, TLS_HASH_LEN);
  c->hmac(fk, TLS_HASH_LEN, hash, TLS_HASH_LEN, out);
  wipe(fk, sizeof(fk));
}

void tls_update_secret(const tls_crypto_t *c, uint8_t secret[TLS_HASH_LEN]) {
  uint8_t next[TLS_HASH_LEN];
  tls_expand_label(c, secret, "traffic upd", NULL, 0, next, TLS_HASH_LEN);
  memcpy(secret, next, TLS_HASH_LEN);
  wipe(next, sizeof(next));
}

/* ── Record protection ────────────────────────────────────────────────── */

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
  rec[1] = 0x03; /* legacy_record_version 0x0303 */
  rec[2] = 0x03;
  put16(rec + 3, clen);
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

/* ══ Connections ═══════════════════════════════════════════════════════ */

/* flags */
#define F_SERVER 0x01u
#define F_RPROT 0x02u    /* records from the peer are protected */
#define F_WPROT 0x04u    /* our records are protected */
#define F_CCS_OK 0x08u   /* a dummy change_cipher_spec may arrive */
#define F_WCLOSED 0x10u  /* we sent close_notify */
#define F_KU_OWED 0x20u  /* the peer asked for a KeyUpdate */
#define F_CERT_REQ 0x40u /* client: the server asked for our certificate */

/* step: where the handshake is */
enum {
  ST_NONE,
  ST_WAIT_CH,  /* server: ClientHello */
  ST_SEND_CCS, /* server: the flight after ServerHello, one message */
  ST_SEND_EE,  /*   per step so a small buffer can send it in parts */
  ST_SEND_CERT,
  ST_SEND_CV,
  ST_SEND_FIN,
  ST_WAIT_FIN, /* server: the client's Finished */
  ST_DONE,
  ST_C_WAIT_SH,   /* client: ServerHello */
  ST_C_WAIT_EE,   /* EncryptedExtensions */
  ST_C_WAIT_CERT, /* CertificateRequest or Certificate */
  ST_C_WAIT_CV,   /* CertificateVerify */
  ST_C_WAIT_FIN,  /* the server's Finished */
  ST_C_SEND_FIN   /* our (empty Certificate and) Finished */
};

/* Steps that have output to send */
#define SENDING(s)                                                            \
  (((s) >= ST_SEND_CCS && (s) <= ST_SEND_FIN) || (s) == ST_C_SEND_FIN)

/* What on_handshake() says about the message it took */
#define HS_KEYS 1    /* keys change after it: it must end its record */
#define HS_KEEP 2    /* keep it (the Certificate, for CertificateVerify) */
#define HS_RELEASE 3 /* done with it and with the kept one */

#define CHAIN_MAX 6 /* certificates passed to verify_chain */

#define NO_REC 0xFFFFu
#define BUF_MIN 256u
#define BUF_MAX 0xFFFEu

/* The most signature bytes CertificateVerify reserves */
#define SIG_MAX_ECDSA 72u /* DER ECDSA-P256 */
#define SIG_MAX_RSA 512u  /* RSA up to 4096 bits */

static const uint8_t cv_server_ctx[] = "TLS 1.3, server CertificateVerify";

/* ServerHello.random of a HelloRetryRequest: SHA-256("HelloRetryRequest") */
static const uint8_t hrr_random[32] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c,
    0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
    0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};

static void put24(uint8_t *p, size_t v) {
  p[0] = (uint8_t)(v >> 16);
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)v;
}

static void event(tls_conn_t *t, uint8_t evt) {
  if (t->on_event)
    t->on_event(t, evt);
}

static void wipe_keys(tls_conn_t *t) {
  wipe(t->secret, sizeof(t->secret));
  wipe(t->rsec, sizeof(t->rsec));
  wipe(t->wsec, sizeof(t->wsec));
  wipe(&t->rkeys, sizeof(t->rkeys));
  wipe(&t->wkeys, sizeof(t->wkeys));
}

/* ── Reading messages ─────────────────────────────────────────────────── */

typedef struct {
  const uint8_t *p;
  size_t n;
  uint8_t bad; /* ran past the end */
} rd_t;

static uint32_t rd_uint(rd_t *r, size_t w) {
  uint32_t v = 0;
  if (r->n < w) {
    r->bad = 1;
    r->n = 0;
    return 0;
  }
  r->n -= w;
  while (w--)
    v = (v << 8) | *r->p++;
  return v;
}

static const uint8_t *rd_take(rd_t *r, size_t len) {
  const uint8_t *p = r->p;
  if (r->n < len) {
    r->bad = 1;
    r->n = 0;
    return NULL;
  }
  r->p += len;
  r->n -= len;
  return p;
}

/* A vector with a @p w byte length prefix, as its own reader */
static rd_t rd_vec(rd_t *r, size_t w) {
  rd_t v;
  size_t len = rd_uint(r, w);
  v.p = rd_take(r, len);
  v.n = v.p ? len : 0;
  v.bad = r->bad;
  return v;
}

/* ── Building records ─────────────────────────────────────────────────── */

/* Drop bytes the transport has taken from the front of tx. */
static void tx_compact(tls_conn_t *t) {
  if (!t->tx_sent)
    return;
  memmove(t->tx, t->tx + t->tx_sent, (size_t)(t->tx_len - t->tx_sent));
  t->tx_len = (uint16_t)(t->tx_len - t->tx_sent);
  t->tx_sent = 0;
}

static void rec_close(tls_conn_t *t) {
  uint8_t *rec;
  size_t len;
  if (t->rec_start == NO_REC)
    return;
  rec = t->tx + t->rec_start;
  len = (size_t)(t->tx_len - t->rec_start - TLS_RECORD_HDR);
  if (t->flags & F_WPROT) {
    len = tls_record_seal(t->cfg->crypto, &t->wkeys, t->rec_type, rec, len);
    t->tx_len = (uint16_t)(t->rec_start + len);
  } else {
    rec[0] = t->rec_type;
    rec[1] = 0x03;
    rec[2] = 0x03;
    put16(rec + 3, len);
  }
  t->rec_start = NO_REC;
}

/* Room for @p need more content bytes of @p type: continues the record
 * being built or starts one.  NULL when tx cannot take them yet. */
static uint8_t *rec_room(tls_conn_t *t, uint8_t type, size_t need) {
  size_t over = (t->flags & F_WPROT) ? 1 + TLS_AEAD_TAG_LEN : 0;
  if (t->rec_start != NO_REC) {
    size_t used = (size_t)(t->tx_len - t->rec_start - TLS_RECORD_HDR);
    if (t->rec_type == type && used + need <= TLS_MAX_PLAINTEXT &&
        t->tx_len + need + over <= t->tx_cap)
      return t->tx + t->tx_len;
    rec_close(t);
  }
  tx_compact(t);
  if (need > TLS_MAX_PLAINTEXT ||
      t->tx_len + TLS_RECORD_HDR + need + over > t->tx_cap)
    return NULL;
  t->rec_start = t->tx_len;
  t->rec_type = type;
  t->tx_len = (uint16_t)(t->tx_len + TLS_RECORD_HDR);
  return t->tx + t->tx_len;
}

/* A handshake message of at most @p max bytes (header included) */
static uint8_t *hs_begin(tls_conn_t *t, size_t max) {
  return rec_room(t, TLS_CT_HANDSHAKE, max);
}

/* Finish the message at @p m: header, transcript, into the record */
static void hs_end(tls_conn_t *t, uint8_t *m, uint8_t type, size_t body) {
  m[0] = type;
  put24(m + 1, body);
  t->cfg->crypto->hash_update(&t->transcript, m, 4 + body);
  t->tx_len = (uint16_t)(t->tx_len + 4 + body);
}

static int send_alert(tls_conn_t *t, uint8_t level, uint8_t desc) {
  uint8_t *p = rec_room(t, TLS_CT_ALERT, 2);
  if (!p)
    return -1;
  p[0] = level;
  p[1] = desc;
  t->tx_len = (uint16_t)(t->tx_len + 2);
  rec_close(t);
  return 0;
}

/* End the connection with a fatal alert (sent if tx has room). */
static int fail(tls_conn_t *t, int alert) {
  if (t->rec_start != NO_REC) { /* drop a half-built record */
    t->tx_len = t->rec_start;
    t->rec_start = NO_REC;
  }
  (void)send_alert(t, 2, (uint8_t)alert);
  t->state = TLS_STATE_ERROR;
  t->alert = (uint8_t)alert;
  wipe_keys(t);
  event(t, TLS_EVT_ERROR);
  return -alert;
}

/* ── Server handshake ─────────────────────────────────────────────────── */

static size_t sig_max(uint16_t scheme) {
  return scheme == TLS_SIG_ECDSA_SECP256R1_SHA256 ? SIG_MAX_ECDSA
                                                   : SIG_MAX_RSA;
}

/* Extension types seen, to refuse duplicates (types below 64) */
static int ext_seen(uint32_t seen[2], uint16_t type) {
  uint32_t bit;
  if (type >= 64)
    return 0;
  bit = 1ul << (type & 31u);
  if (seen[type >> 5] & bit)
    return 1;
  seen[type >> 5] |= bit;
  return 0;
}

/* RFC 8446 §4.1.2-4.1.3: pick the parameters, answer with ServerHello,
 * and enter the handshake keys.  Returns 1 (a key change), or < 0. */
static int on_client_hello(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  const tls_crypto_t *c = t->cfg->crypto;
  rd_t r, v, ext;
  const uint8_t *share = NULL;
  size_t share_len = 0, pub_len = 0;
  uint16_t group = 0;
  uint32_t seen[2] = {0, 0};
  int tls13 = 0, suite = 0, sig = 0, have_ks = 0, have_sa = 0;
  uint8_t priv[TLS_KX_PRIV_MAX], pub[TLS_KX_PUB_MAX], z[TLS_HASH_LEN];
  uint8_t h[TLS_HASH_LEN], *sh, *p;

  r.p = m + 4;
  r.n = mlen - 4;
  r.bad = 0;
  rd_uint(&r, 2);   /* legacy_version: the extension decides */
  rd_take(&r, 32);  /* random */
  v = rd_vec(&r, 1); /* legacy_session_id */
  if (v.n > sizeof(t->sid))
    return fail(t, TLS_ALERT_DECODE_ERROR);
  memcpy(t->sid, v.p, v.n);
  t->sid_len = (uint8_t)v.n;
  v = rd_vec(&r, 2); /* cipher_suites */
  while (v.n >= 2)
    if (rd_uint(&v, 2) == TLS_AES_128_GCM_SHA256)
      suite = 1;
  if (v.n)
    return fail(t, TLS_ALERT_DECODE_ERROR);
  v = rd_vec(&r, 1); /* legacy_compression_methods: exactly null */
  if (!r.bad && (v.n != 1 || v.p[0] != 0))
    return fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  ext = rd_vec(&r, 2);
  if (r.bad || r.n)
    return fail(t, TLS_ALERT_DECODE_ERROR);

  while (ext.n) {
    uint16_t type = (uint16_t)rd_uint(&ext, 2);
    rd_t d = rd_vec(&ext, 2);
    if (ext.bad)
      return fail(t, TLS_ALERT_DECODE_ERROR);
    if (ext_seen(seen, type))
      return fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
    switch (type) {
    case TLS_EXT_SUPPORTED_VERSIONS:
      v = rd_vec(&d, 1);
      while (v.n >= 2)
        if (rd_uint(&v, 2) == 0x0304)
          tls13 = 1;
      break;
    case TLS_EXT_SIGNATURE_ALGORITHMS:
      have_sa = 1;
      v = rd_vec(&d, 2);
      while (v.n >= 2)
        if (rd_uint(&v, 2) == t->cfg->sig_scheme)
          sig = 1;
      break;
    case TLS_EXT_KEY_SHARE:
      have_ks = 1;
      v = rd_vec(&d, 2);
      while (v.n) {
        uint16_t g = (uint16_t)rd_uint(&v, 2);
        rd_t k = rd_vec(&v, 2);
        if (v.bad)
          return fail(t, TLS_ALERT_DECODE_ERROR);
        /* x25519 preferred over secp256r1 */
        if ((g == TLS_GROUP_X25519 ||
             (g == TLS_GROUP_SECP256R1 && group != TLS_GROUP_X25519))) {
          group = g;
          share = k.p;
          share_len = k.n;
        }
      }
      break;
    default: /* not ours: ignored */
      break;
    }
    if (d.bad)
      return fail(t, TLS_ALERT_DECODE_ERROR);
  }

  /* REQ-TLS-001: TLS 1.3 only */
  if (!tls13)
    return fail(t, TLS_ALERT_PROTOCOL_VERSION);
  if (!suite)
    return fail(t, TLS_ALERT_HANDSHAKE_FAILURE);
  if (!have_ks || !have_sa || !(seen[0] & (1ul << TLS_EXT_SUPPORTED_GROUPS)))
    return fail(t, TLS_ALERT_MISSING_EXTENSION);
  if (!sig || !group)
    return fail(t, TLS_ALERT_HANDSHAKE_FAILURE);
  if (share_len != (group == TLS_GROUP_X25519 ? 32u : 65u))
    return fail(t, TLS_ALERT_ILLEGAL_PARAMETER);

  /* Our share, and the shared secret (the peer's share checked) */
  if (c->kx_keygen(c->ctx, group, priv, pub, &pub_len) != 0)
    return fail(t, TLS_ALERT_INTERNAL_ERROR);
  if (c->kx_shared(c->ctx, group, priv, share, share_len, z) != 0) {
    wipe(priv, sizeof(priv));
    return fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  }
  wipe(priv, sizeof(priv));
  t->group = group;
  c->hash_update(&t->transcript, m, mlen);

  /* ServerHello: extensions key_share, supported_versions */
  sh = hs_begin(t, 4 + 2 + 32 + 1 + 32 + 2 + 1 + 2 + 8 + TLS_KX_PUB_MAX + 6);
  if (!sh) {
    wipe(z, sizeof(z));
    return fail(t, TLS_ALERT_INTERNAL_ERROR);
  }
  p = sh + 4;
  *p++ = 0x03;
  *p++ = 0x03;
  if (c->random(c->ctx, p, 32) != 0) {
    wipe(z, sizeof(z));
    return fail(t, TLS_ALERT_INTERNAL_ERROR);
  }
  p += 32;
  *p++ = t->sid_len;
  memcpy(p, t->sid, t->sid_len);
  p += t->sid_len;
  put16(p, TLS_AES_128_GCM_SHA256);
  p[2] = 0; /* legacy_compression_method */
  p += 3;
  put16(p, 8 + pub_len + 6);
  put16(p + 2, TLS_EXT_KEY_SHARE);
  put16(p + 4, 4 + pub_len);
  put16(p + 6, group);
  put16(p + 8, pub_len);
  memcpy(p + 10, pub, pub_len);
  p += 10 + pub_len;
  put16(p, TLS_EXT_SUPPORTED_VERSIONS);
  put16(p + 2, 2);
  put16(p + 4, 0x0304);
  p += 6;
  hs_end(t, sh, TLS_HS_SERVER_HELLO, (size_t)(p - sh - 4));
  rec_close(t);

  /* Handshake Secret and traffic keys (RFC 8446 §7.1) */
  tls_early_secret(c, NULL, 0, t->secret);
  tls_next_secret(c, t->secret, z, sizeof(z));
  wipe(z, sizeof(z));
  c->hash_peek(&t->transcript, h);
  tls_derive_secret(c, t->secret, "c hs traffic", h, t->rsec);
  tls_derive_secret(c, t->secret, "s hs traffic", h, t->wsec);
  tls_traffic_keys(c, t->rsec, &t->rkeys);
  tls_traffic_keys(c, t->wsec, &t->wkeys);
  t->flags |= F_RPROT | F_WPROT | F_CCS_OK;
  /* A client in middlebox compatibility mode (a session id) gets the
   * dummy change_cipher_spec (RFC 8446 D.4) */
  t->step = t->sid_len ? ST_SEND_CCS : ST_SEND_EE;
  return HS_KEYS;
}

/* The server's flight after ServerHello, as far as tx allows. */
static int pump_server(tls_conn_t *t) {
  const tls_config_t *cfg = t->cfg;
  const tls_crypto_t *c = cfg->crypto;
  uint8_t *m, h[TLS_HASH_LEN];
  size_t i, n;

  for (;;) {
    switch (t->step) {
    case ST_SEND_CCS: /* a plaintext record, outside the transcript */
      tx_compact(t);
      if (t->tx_len + 6u > t->tx_cap)
        return 0;
      memcpy(t->tx + t->tx_len, "\x14\x03\x03\x00\x01\x01", 6);
      t->tx_len = (uint16_t)(t->tx_len + 6);
      t->step = ST_SEND_EE;
      break;

    case ST_SEND_EE: /* no extensions to report */
      if (!(m = hs_begin(t, 6)))
        return 0;
      put16(m + 4, 0);
      hs_end(t, m, TLS_HS_ENCRYPTED_EXTENSIONS, 2);
      t->step = ST_SEND_CERT;
      break;

    case ST_SEND_CERT: /* context "", then each DER cert, no extensions */
      n = 4 + 1 + 3;
      for (i = 0; i < cfg->cert_count; i++)
        n += 3 + (size_t)cfg->cert_len[i] + 2;
      if (!(m = hs_begin(t, n)))
        return 0;
      m[4] = 0;
      put24(m + 5, n - 8);
      n = 8;
      for (i = 0; i < cfg->cert_count; i++) {
        put24(m + n, cfg->cert_len[i]);
        memcpy(m + n + 3, cfg->cert[i], cfg->cert_len[i]);
        n += 3 + (size_t)cfg->cert_len[i];
        put16(m + n, 0);
        n += 2;
      }
      hs_end(t, m, TLS_HS_CERTIFICATE, n - 4);
      t->step = ST_SEND_CV;
      break;

    case ST_SEND_CV: { /* RFC 8446 §4.4.3 */
      uint8_t content[64 + sizeof(cv_server_ctx) + TLS_HASH_LEN];
      size_t sig_len = 0, cap = sig_max(cfg->sig_scheme);
      if (!(m = hs_begin(t, 8 + cap)))
        return 0;
      memset(content, 0x20, 64);
      memcpy(content + 64, cv_server_ctx, sizeof(cv_server_ctx)); /* + 0 */
      c->hash_peek(&t->transcript, content + 64 + sizeof(cv_server_ctx));
      if (c->sign(c->ctx, cfg->key, cfg->sig_scheme, content, sizeof(content),
                  m + 8, &sig_len, cap) != 0 ||
          sig_len > cap)
        return fail(t, TLS_ALERT_INTERNAL_ERROR);
      put16(m + 4, cfg->sig_scheme);
      put16(m + 6, sig_len);
      hs_end(t, m, TLS_HS_CERTIFICATE_VERIFY, 4 + sig_len);
      t->step = ST_SEND_FIN;
      break;
    }

    case ST_SEND_FIN: {
      uint8_t ms[TLS_HASH_LEN];
      if (!(m = hs_begin(t, 4 + TLS_HASH_LEN)))
        return 0;
      c->hash_peek(&t->transcript, h);
      tls_finished_mac(c, t->wsec, h, m + 4);
      hs_end(t, m, TLS_HS_FINISHED, TLS_HASH_LEN);
      rec_close(t);
      /* Master Secret; ours to use now, the client's once its Finished
       * checks out */
      c->hash_peek(&t->transcript, h);
      memcpy(ms, t->secret, sizeof(ms));
      tls_next_secret(c, ms, NULL, 0);
      tls_derive_secret(c, ms, "c ap traffic", h, t->secret);
      tls_derive_secret(c, ms, "s ap traffic", h, t->wsec);
      wipe(ms, sizeof(ms));
      tls_traffic_keys(c, t->wsec, &t->wkeys);
      t->step = ST_WAIT_FIN;
      return 0;
    }

    default:
      return 0;
    }
  }
}

/* ── Client handshake ─────────────────────────────────────────────────── */

/* A literal IPv4 or IPv6 address is not sent as server_name (RFC 6066 §3) */
static int ip_literal(const char *h) {
  int dot_digit_only = 1;
  for (; *h; h++) {
    if (*h == ':')
      return 1;
    if (*h != '.' && (*h < '0' || *h > '9'))
      dot_digit_only = 0;
  }
  return dot_digit_only;
}

/* The client's flight after the server's Finished, as tx allows. */
static int pump_client(tls_conn_t *t) {
  const tls_crypto_t *c = t->cfg->crypto;
  uint8_t *m, h[TLS_HASH_LEN];
  int cert = (t->flags & F_CERT_REQ) != 0;

  if (t->step != ST_C_SEND_FIN)
    return 0;
  if (!(m = hs_begin(t, (cert ? 8u : 0u) + 4 + TLS_HASH_LEN)))
    return 0;
  if (cert) { /* no certificate to offer: an empty list (§4.4.2) */
    memset(m + 4, 0, 4);
    hs_end(t, m, TLS_HS_CERTIFICATE, 4);
    m += 8;
  }
  c->hash_peek(&t->transcript, h);
  tls_finished_mac(c, t->wsec, h, m + 4);
  hs_end(t, m, TLS_HS_FINISHED, TLS_HASH_LEN);
  rec_close(t);
  memcpy(t->wsec, t->secret, TLS_HASH_LEN);
  wipe(t->secret, sizeof(t->secret));
  tls_traffic_keys(c, t->wsec, &t->wkeys);
  t->step = ST_DONE;
  t->state = TLS_STATE_CONNECTED;
  event(t, TLS_EVT_CONNECTED);
  return 0;
}

/* RFC 8446 §4.1.3: the server's parameters; enter the handshake keys. */
static int on_server_hello(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  const tls_crypto_t *c = t->cfg->crypto;
  rd_t r, v, ext, share = {NULL, 0, 0};
  const uint8_t *random;
  uint32_t seen[2] = {0, 0};
  int tls13 = 0;
  uint8_t z[TLS_HASH_LEN], h[TLS_HASH_LEN];

  r.p = m + 4;
  r.n = mlen - 4;
  r.bad = 0;
  rd_uint(&r, 2); /* legacy_version */
  random = rd_take(&r, 32);
  v = rd_vec(&r, 1); /* legacy_session_id_echo */
  if (r.bad)
    return fail(t, TLS_ALERT_DECODE_ERROR);
  if (memcmp(random, hrr_random, 32) == 0) /* a HelloRetryRequest */
    return fail(t, TLS_ALERT_HANDSHAKE_FAILURE);
  if (v.n != t->sid_len || memcmp(v.p, t->sid, v.n) != 0)
    return fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  if (rd_uint(&r, 2) != TLS_AES_128_GCM_SHA256 || rd_uint(&r, 1) != 0)
    return fail(t, r.bad ? TLS_ALERT_DECODE_ERROR
                         : TLS_ALERT_ILLEGAL_PARAMETER);
  ext = rd_vec(&r, 2);
  if (r.bad || r.n)
    return fail(t, TLS_ALERT_DECODE_ERROR);

  while (ext.n) {
    uint16_t type = (uint16_t)rd_uint(&ext, 2);
    rd_t d = rd_vec(&ext, 2);
    if (ext.bad)
      return fail(t, TLS_ALERT_DECODE_ERROR);
    if (ext_seen(seen, type))
      return fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
    switch (type) {
    case TLS_EXT_SUPPORTED_VERSIONS:
      if (rd_uint(&d, 2) != 0x0304)
        return fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
      tls13 = 1;
      break;
    case TLS_EXT_KEY_SHARE: /* the group we offered a share for */
      if (rd_uint(&d, 2) != t->group)
        return fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
      share = rd_vec(&d, 2);
      break;
    default: /* nothing else was offered for a ServerHello */
      return fail(t, TLS_ALERT_UNSUPPORTED_EXTENSION);
    }
    if (d.bad || d.n)
      return fail(t, TLS_ALERT_DECODE_ERROR);
  }
  if (!tls13) /* a TLS 1.2 (or older) server */
    return fail(t, TLS_ALERT_PROTOCOL_VERSION);
  if (!share.p)
    return fail(t, TLS_ALERT_MISSING_EXTENSION);
  if (c->kx_shared(c->ctx, t->group, t->kx_priv, share.p, share.n, z) != 0)
    return fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  wipe(t->kx_priv, sizeof(t->kx_priv));

  c->hash_update(&t->transcript, m, mlen);
  tls_early_secret(c, NULL, 0, t->secret);
  tls_next_secret(c, t->secret, z, sizeof(z));
  wipe(z, sizeof(z));
  c->hash_peek(&t->transcript, h);
  tls_derive_secret(c, t->secret, "s hs traffic", h, t->rsec);
  tls_derive_secret(c, t->secret, "c hs traffic", h, t->wsec);
  tls_traffic_keys(c, t->rsec, &t->rkeys);
  tls_traffic_keys(c, t->wsec, &t->wkeys);
  t->flags |= F_RPROT | F_WPROT;
  t->step = ST_C_WAIT_EE;
  return HS_KEYS;
}

/* Extensions we offered that the server may answer here: server_name
 * (empty) and supported_groups (its preference, for later) */
static int on_encrypted_extensions(tls_conn_t *t, const uint8_t *m,
                                   size_t mlen) {
  rd_t r, ext;
  uint32_t seen[2] = {0, 0};
  r.p = m + 4;
  r.n = mlen - 4;
  r.bad = 0;
  ext = rd_vec(&r, 2);
  if (r.bad || r.n)
    return fail(t, TLS_ALERT_DECODE_ERROR);
  while (ext.n) {
    uint16_t type = (uint16_t)rd_uint(&ext, 2);
    rd_t d = rd_vec(&ext, 2);
    if (ext.bad)
      return fail(t, TLS_ALERT_DECODE_ERROR);
    if (ext_seen(seen, type))
      return fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
    if (type == TLS_EXT_SERVER_NAME && d.n == 0)
      continue;
    if (type != TLS_EXT_SUPPORTED_GROUPS)
      return fail(t, TLS_ALERT_UNSUPPORTED_EXTENSION);
  }
  t->cfg->crypto->hash_update(&t->transcript, m, mlen);
  t->step = ST_C_WAIT_CERT;
  return 0;
}

/* The server wants our certificate; we have none and say so (§4.4.2) */
static int on_certificate_request(tls_conn_t *t, const uint8_t *m,
                                  size_t mlen) {
  rd_t r, v;
  r.p = m + 4;
  r.n = mlen - 4;
  r.bad = 0;
  v = rd_vec(&r, 1); /* certificate_request_context: empty in a handshake */
  rd_vec(&r, 2);     /* extensions */
  if (r.bad || r.n)
    return fail(t, TLS_ALERT_DECODE_ERROR);
  if (v.n)
    return fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  t->cfg->crypto->hash_update(&t->transcript, m, mlen);
  t->flags |= F_CERT_REQ;
  return 0;
}

/* The server's chain: verified now, the leaf kept for CertificateVerify */
static int on_certificate(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  const tls_crypto_t *c = t->cfg->crypto;
  const uint8_t *cert[CHAIN_MAX];
  uint16_t len[CHAIN_MAX];
  uint8_t count = 0;
  rd_t r, ctx, list;
  int a;

  r.p = m + 4;
  r.n = mlen - 4;
  r.bad = 0;
  ctx = rd_vec(&r, 1);
  list = rd_vec(&r, 3);
  if (r.bad || r.n)
    return fail(t, TLS_ALERT_DECODE_ERROR);
  if (ctx.n)
    return fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  while (list.n) {
    rd_t data = rd_vec(&list, 3);
    rd_vec(&list, 2); /* CertificateEntry extensions */
    if (list.bad || data.n == 0)
      return fail(t, TLS_ALERT_DECODE_ERROR);
    if (count == CHAIN_MAX || data.n > 0xFFFFu)
      return fail(t, TLS_ALERT_BAD_CERTIFICATE);
    cert[count] = data.p;
    len[count++] = (uint16_t)data.n;
  }
  if (!count) /* §4.4.2.4 */
    return fail(t, TLS_ALERT_DECODE_ERROR);
  if ((a = c->verify_chain(c->ctx, cert, len, count, t->host)) != 0)
    return fail(t, a > 0 ? a : TLS_ALERT_BAD_CERTIFICATE);
  c->hash_update(&t->transcript, m, mlen);
  t->leaf_off = (uint16_t)(cert[0] - t->rx);
  t->leaf_len = len[0];
  t->step = ST_C_WAIT_CV;
  return HS_KEEP;
}

/* RFC 8446 §4.4.3: the server holds the certificate's private key */
static int on_certificate_verify(tls_conn_t *t, const uint8_t *m,
                                 size_t mlen) {
  const tls_crypto_t *c = t->cfg->crypto;
  uint8_t content[64 + sizeof(cv_server_ctx) + TLS_HASH_LEN];
  uint16_t scheme;
  rd_t r, sig;

  r.p = m + 4;
  r.n = mlen - 4;
  r.bad = 0;
  scheme = (uint16_t)rd_uint(&r, 2);
  sig = rd_vec(&r, 2);
  if (r.bad || r.n)
    return fail(t, TLS_ALERT_DECODE_ERROR);
  if (scheme != TLS_SIG_ECDSA_SECP256R1_SHA256 &&
      scheme != TLS_SIG_RSA_PSS_RSAE_SHA256) /* not offered */
    return fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  memset(content, 0x20, 64);
  memcpy(content + 64, cv_server_ctx, sizeof(cv_server_ctx));
  c->hash_peek(&t->transcript, content + 64 + sizeof(cv_server_ctx));
  if (c->verify(c->ctx, t->rx + t->leaf_off, t->leaf_len, scheme, content,
                sizeof(content), sig.p, sig.n) != 0)
    return fail(t, TLS_ALERT_DECRYPT_ERROR);
  c->hash_update(&t->transcript, m, mlen);
  t->step = ST_C_WAIT_FIN;
  return HS_RELEASE;
}

/* The server's Finished: its application keys now, ours after our
 * Finished (pump_client) */
static int on_server_finished(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  const tls_crypto_t *c = t->cfg->crypto;
  uint8_t h[TLS_HASH_LEN], mac[TLS_HASH_LEN], ms[TLS_HASH_LEN];
  if (mlen != 4 + TLS_HASH_LEN)
    return fail(t, TLS_ALERT_DECODE_ERROR);
  c->hash_peek(&t->transcript, h);
  tls_finished_mac(c, t->rsec, h, mac);
  if (!tls_equal(mac, m + 4, TLS_HASH_LEN))
    return fail(t, TLS_ALERT_DECRYPT_ERROR);
  c->hash_update(&t->transcript, m, mlen);
  c->hash_peek(&t->transcript, h);
  memcpy(ms, t->secret, sizeof(ms));
  tls_next_secret(c, ms, NULL, 0);
  tls_derive_secret(c, ms, "s ap traffic", h, t->rsec);
  tls_derive_secret(c, ms, "c ap traffic", h, t->secret);
  wipe(ms, sizeof(ms));
  tls_traffic_keys(c, t->rsec, &t->rkeys);
  t->flags &= (uint8_t)~F_CCS_OK;
  t->step = ST_C_SEND_FIN;
  return HS_KEYS;
}

/* Produce whatever output is due; runs after every input and drain. */
static int pump(tls_conn_t *t) {
  int r = 0;
  if (t->state == TLS_STATE_HANDSHAKE)
    r = (t->flags & F_SERVER) ? pump_server(t) : pump_client(t);
  if (r == 0 && (t->flags & F_KU_OWED) && !(t->flags & F_WCLOSED)) {
    uint8_t *m = hs_begin(t, 5);
    if (m) { /* KeyUpdate(update_not_requested), then our next keys */
      m[4] = 0;
      hs_end(t, m, TLS_HS_KEY_UPDATE, 1);
      rec_close(t);
      tls_update_secret(t->cfg->crypto, t->wsec);
      tls_traffic_keys(t->cfg->crypto, t->wsec, &t->wkeys);
      t->flags &= (uint8_t)~F_KU_OWED;
    }
  }
  rec_close(t);
  if (r == 0 && t->state == TLS_STATE_HANDSHAKE && SENDING(t->step) &&
      t->tx_len == t->tx_sent)
    return fail(t, TLS_ALERT_INTERNAL_ERROR); /* tx too small */
  return r;
}

/* The client's Finished (RFC 8446 §4.4.4): the handshake is done. */
static int on_client_finished(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  const tls_crypto_t *c = t->cfg->crypto;
  uint8_t h[TLS_HASH_LEN], mac[TLS_HASH_LEN];
  if (mlen != 4 + TLS_HASH_LEN)
    return fail(t, TLS_ALERT_DECODE_ERROR);
  c->hash_peek(&t->transcript, h);
  tls_finished_mac(c, t->rsec, h, mac);
  if (!tls_equal(mac, m + 4, TLS_HASH_LEN))
    return fail(t, TLS_ALERT_DECRYPT_ERROR);
  c->hash_update(&t->transcript, m, mlen);
  memcpy(t->rsec, t->secret, TLS_HASH_LEN);
  wipe(t->secret, sizeof(t->secret));
  tls_traffic_keys(c, t->rsec, &t->rkeys);
  t->flags &= (uint8_t)~F_CCS_OK;
  t->step = ST_DONE;
  t->state = TLS_STATE_CONNECTED;
  event(t, TLS_EVT_CONNECTED);
  return HS_KEYS;
}

/* KeyUpdate (RFC 8446 §4.6.3): the peer's next keys; answer if asked. */
static int on_key_update(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  if (mlen != 5)
    return fail(t, TLS_ALERT_DECODE_ERROR);
  if (m[4] > 1)
    return fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  tls_update_secret(t->cfg->crypto, t->rsec);
  tls_traffic_keys(t->cfg->crypto, t->rsec, &t->rkeys);
  if (m[4])
    t->flags |= F_KU_OWED;
  return HS_KEYS;
}

/* One whole handshake message.  Returns 1 after a key change, 0, or < 0. */
static int on_handshake(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  uint8_t type = m[0];
  if (t->state == TLS_STATE_CONNECTED) {
    if (type == TLS_HS_KEY_UPDATE)
      return on_key_update(t, m, mlen);
    /* tickets are for resumption, which a client here does not do */
    if (type == TLS_HS_NEW_SESSION_TICKET && !(t->flags & F_SERVER))
      return 0;
    return fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
  }
  switch (t->step) {
  case ST_WAIT_CH:
    if (type == TLS_HS_CLIENT_HELLO)
      return on_client_hello(t, m, mlen);
    break;
  case ST_WAIT_FIN:
    if (type == TLS_HS_FINISHED)
      return on_client_finished(t, m, mlen);
    break;
  case ST_C_WAIT_SH:
    if (type == TLS_HS_SERVER_HELLO)
      return on_server_hello(t, m, mlen);
    break;
  case ST_C_WAIT_EE:
    if (type == TLS_HS_ENCRYPTED_EXTENSIONS)
      return on_encrypted_extensions(t, m, mlen);
    break;
  case ST_C_WAIT_CERT:
    if (type == TLS_HS_CERTIFICATE_REQUEST && !(t->flags & F_CERT_REQ))
      return on_certificate_request(t, m, mlen);
    if (type == TLS_HS_CERTIFICATE)
      return on_certificate(t, m, mlen);
    break;
  case ST_C_WAIT_CV:
    if (type == TLS_HS_CERTIFICATE_VERIFY)
      return on_certificate_verify(t, m, mlen);
    break;
  case ST_C_WAIT_FIN:
    if (type == TLS_HS_FINISHED)
      return on_server_finished(t, m, mlen);
    break;
  default:
    break;
  }
  return fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
}

/* ── Receiving ────────────────────────────────────────────────────────── */

/* Replace the record at rx + hs_len (@p rlen bytes) by the @p n content
 * bytes at its offset @p off. */
static void rx_keep(tls_conn_t *t, size_t off, size_t n, size_t rlen) {
  uint8_t *rec = t->rx + t->hs_len;
  memmove(rec, rec + off, n);
  memmove(rec + n, rec + rlen, (size_t)(t->rx_len - t->hs_len) - rlen);
  t->hs_len = (uint16_t)(t->hs_len + n);
  t->rx_len = (uint16_t)(t->rx_len - (rlen - n));
}

static int on_alert(tls_conn_t *t, const uint8_t *a, size_t n, size_t rlen) {
  uint8_t desc;
  if (n != 2)
    return fail(t, TLS_ALERT_DECODE_ERROR);
  desc = a[1];
  rx_keep(t, 0, 0, rlen);
  if (desc == 90) /* user_canceled: close_notify follows */
    return 0;
  if (desc == TLS_ALERT_CLOSE_NOTIFY) {
    t->state = TLS_STATE_CLOSED;
    event(t, TLS_EVT_CLOSED);
    return 0;
  }
  t->state = TLS_STATE_ERROR;
  t->alert = desc;
  wipe_keys(t);
  event(t, TLS_EVT_ERROR);
  return -(int)desc;
}

/* One whole record at rx + hs_len. */
static int on_record(tls_conn_t *t, size_t rlen) {
  uint8_t *rec = t->rx + t->hs_len, type = rec[0];
  size_t len = rlen - TLS_RECORD_HDR;
  int n;

  switch (type) { /* one of the four: process() checked */
  case TLS_CT_CHANGE_CIPHER_SPEC: /* RFC 8446 §5: dropped, once allowed */
    if (!(t->flags & F_CCS_OK) || len != 1 || rec[5] != 0x01)
      return fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
    rx_keep(t, 0, 0, rlen);
    return 0;
  case TLS_CT_ALERT: /* plaintext: before our keys reach the peer */
    if ((t->flags & F_RPROT) && t->state != TLS_STATE_HANDSHAKE)
      return fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
    return on_alert(t, rec + TLS_RECORD_HDR, len, rlen);
  case TLS_CT_HANDSHAKE:
    if (t->flags & F_RPROT)
      return fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
    if (len == 0)
      return fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
    rx_keep(t, TLS_RECORD_HDR, len, rlen);
    return 0;
  default: /* TLS_CT_APPLICATION_DATA */
    if (!(t->flags & F_RPROT))
      return fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
    n = tls_record_open(t->cfg->crypto, &t->rkeys, rec, rlen, &type);
    if (n < 0)
      return fail(t, -n);
    if (type == TLS_CT_HANDSHAKE && n > 0) {
      rx_keep(t, TLS_RECORD_HDR, (size_t)n, rlen);
      return 0;
    }
    if (type == TLS_CT_ALERT)
      return on_alert(t, rec + TLS_RECORD_HDR, (size_t)n, rlen);
    /* application data: only between complete handshake messages */
    if (type != TLS_CT_APPLICATION_DATA || t->hs_len ||
        t->state != TLS_STATE_CONNECTED)
      return fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
    if (n == 0) {
      rx_keep(t, 0, 0, rlen);
      return 0;
    }
    t->app_off = TLS_RECORD_HDR;
    t->app_len = (uint16_t)n;
    t->app_rec = (uint16_t)rlen;
    return 0;
  }
}

/* Work through rx: whole handshake messages, then whole records. */
static int process(tls_conn_t *t) {
  for (;;) {
    const uint8_t *hdr;
    size_t avail, rlen;
    int r;
    if (t->state != TLS_STATE_HANDSHAKE && t->state != TLS_STATE_CONNECTED)
      return t->state == TLS_STATE_ERROR ? -(int)t->alert : 0;
    if (t->app_len) /* the reader first */
      return 0;

    while (t->hs_len - t->hs_off >= 4) {
      uint8_t *m = t->rx + t->hs_off;
      size_t from, n, mlen = 4 + (((size_t)m[1] << 16) |
                                  ((size_t)m[2] << 8) | m[3]);
      if (mlen > (size_t)(t->rx_cap - t->hs_off))
        return fail(t, TLS_ALERT_RECORD_OVERFLOW);
      if ((size_t)(t->hs_len - t->hs_off) < mlen)
        break;
      r = on_handshake(t, m, mlen);
      if (r < 0)
        return r;
      if (r == HS_KEEP) {
        t->hs_off = (uint16_t)(t->hs_off + mlen);
        continue;
      }
      /* drop the message (and the kept one before it, when released) */
      from = r == HS_RELEASE ? 0 : t->hs_off;
      n = t->hs_off + mlen - from;
      memmove(t->rx + from, t->rx + from + n, t->rx_len - from - n);
      t->hs_len = (uint16_t)(t->hs_len - n);
      t->rx_len = (uint16_t)(t->rx_len - n);
      if (r == HS_RELEASE)
        t->hs_off = 0;
      /* RFC 8446 §5.1: a key change falls on a record boundary */
      if (r == HS_KEYS && t->hs_len)
        return fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
      if ((r = pump(t)) < 0)
        return r;
    }

    /* A record header is checked before its body is awaited */
    avail = (size_t)(t->rx_len - t->hs_len);
    if (avail < TLS_RECORD_HDR)
      return 0;
    hdr = t->rx + t->hs_len;
    if (hdr[0] < TLS_CT_CHANGE_CIPHER_SPEC || hdr[0] > TLS_CT_APPLICATION_DATA)
      return fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
    rlen = ((size_t)hdr[3] << 8) | hdr[4];
    if (rlen > (hdr[0] == TLS_CT_APPLICATION_DATA ? TLS_MAX_CIPHERTEXT
                                                  : TLS_MAX_PLAINTEXT))
      return fail(t, TLS_ALERT_RECORD_OVERFLOW);
    rlen += TLS_RECORD_HDR;
    if (rlen > (size_t)(t->rx_cap - t->hs_len))
      return fail(t, TLS_ALERT_RECORD_OVERFLOW);
    if (avail < rlen)
      return 0;
    if ((r = on_record(t, rlen)) < 0)
      return r;
  }
}

/* ── API ──────────────────────────────────────────────────────────────── */

int tls_init(tls_conn_t *t, const tls_config_t *cfg, uint8_t *rx,
             size_t rx_cap, uint8_t *tx, size_t tx_cap) {
  if (!t || !cfg || !cfg->crypto || !rx || !tx || rx_cap < BUF_MIN ||
      tx_cap < BUF_MIN)
    return -1;
  memset(t, 0, sizeof(*t));
  t->cfg = cfg;
  t->rx = rx;
  t->rx_cap = (uint16_t)(rx_cap > BUF_MAX ? BUF_MAX : rx_cap);
  t->tx = tx;
  t->tx_cap = (uint16_t)(tx_cap > BUF_MAX ? BUF_MAX : tx_cap);
  t->rec_start = NO_REC;
  return 0;
}

int tls_accept(tls_conn_t *t) {
  const tls_config_t *cfg = t->cfg;
  if (t->state != TLS_STATE_IDLE || !cfg->cert_count || !cfg->cert ||
      !cfg->cert_len || !cfg->key || !cfg->sig_scheme)
    return -1;
  t->flags = F_SERVER;
  t->state = TLS_STATE_HANDSHAKE;
  t->step = ST_WAIT_CH;
  cfg->crypto->hash_init(&t->transcript);
  return 0;
}

int tls_connect(tls_conn_t *t, const char *host) {
  const tls_crypto_t *c = t->cfg->crypto;
  uint8_t pub[TLS_KX_PUB_MAX], *m, *p, *ext;
  size_t pub_len = 0, hl = 0;
  int sni = host && !ip_literal(host);

  if (t->state != TLS_STATE_IDLE)
    return -1;
  if (sni && (hl = strlen(host)) > 255)
    return -1;
  t->host = host;
  t->group = TLS_GROUP_X25519;
  c->hash_init(&t->transcript);
  if (c->kx_keygen(c->ctx, t->group, t->kx_priv, pub, &pub_len) != 0)
    return -1;
  m = hs_begin(t, 4 + 2 + 32 + 1 + 4 + 2 + 2 + (sni ? 9 + hl : 0) + 7 + 10 +
                      10 + 10 + pub_len);
  if (!m)
    return -1;

  p = m + 4;
  put16(p, 0x0303); /* legacy_version */
  if (c->random(c->ctx, p + 2, 32) != 0) {
    t->tx_len = t->rec_start;
    t->rec_start = NO_REC;
    return -1;
  }
  p += 34;
  *p++ = 0; /* legacy_session_id: none (no middlebox compatibility mode) */
  put16(p, 2);
  put16(p + 2, TLS_AES_128_GCM_SHA256);
  p[4] = 1; /* legacy_compression_methods: null */
  p[5] = 0;
  p += 6;
  ext = p;
  p += 2;
  if (sni) { /* server_name: one host_name */
    put16(p, TLS_EXT_SERVER_NAME);
    put16(p + 2, 5 + hl);
    put16(p + 4, 3 + hl);
    p[6] = 0;
    put16(p + 7, hl);
    memcpy(p + 9, host, hl);
    p += 9 + hl;
  }
  memcpy(p, "\x00\x2b\x00\x03\x02\x03\x04", 7); /* supported_versions */
  p += 7;
  put16(p, TLS_EXT_SUPPORTED_GROUPS);
  put16(p + 2, 6);
  put16(p + 4, 4);
  put16(p + 6, TLS_GROUP_X25519);
  put16(p + 8, TLS_GROUP_SECP256R1);
  p += 10;
  put16(p, TLS_EXT_SIGNATURE_ALGORITHMS);
  put16(p + 2, 6);
  put16(p + 4, 4);
  put16(p + 6, TLS_SIG_ECDSA_SECP256R1_SHA256);
  put16(p + 8, TLS_SIG_RSA_PSS_RSAE_SHA256);
  p += 10;
  put16(p, TLS_EXT_KEY_SHARE); /* one share: x25519 */
  put16(p + 2, 6 + pub_len);
  put16(p + 4, 4 + pub_len);
  put16(p + 6, t->group);
  put16(p + 8, pub_len);
  memcpy(p + 10, pub, pub_len);
  p += 10 + pub_len;
  put16(ext, (size_t)(p - ext - 2));
  hs_end(t, m, TLS_HS_CLIENT_HELLO, (size_t)(p - m - 4));
  rec_close(t);

  t->state = TLS_STATE_HANDSHAKE;
  t->step = ST_C_WAIT_SH;
  t->flags = F_CCS_OK; /* a server may send the dummy one anyway */
  return 0;
}

size_t tls_rx_space(tls_conn_t *t, uint8_t **buf) {
  *buf = t->rx + t->rx_len;
  return (size_t)(t->rx_cap - t->rx_len);
}

int tls_rx_commit(tls_conn_t *t, size_t n) {
  int r;
  if (n > (size_t)(t->rx_cap - t->rx_len))
    n = (size_t)(t->rx_cap - t->rx_len);
  t->rx_len = (uint16_t)(t->rx_len + n);
  if (t->state != TLS_STATE_HANDSHAKE && t->state != TLS_STATE_CONNECTED) {
    t->rx_len = t->hs_len; /* after close_notify or an error: discarded */
    return t->state == TLS_STATE_ERROR ? -(int)t->alert : 0;
  }
  r = process(t);
  return r < 0 ? r : pump(t);
}

size_t tls_input(tls_conn_t *t, const uint8_t *data, size_t len) {
  size_t used = 0;
  while (used < len) {
    uint8_t *p;
    size_t n = tls_rx_space(t, &p);
    if (n > len - used)
      n = len - used;
    if (n == 0)
      break;
    memcpy(p, data + used, n);
    used += n;
    if (tls_rx_commit(t, n) < 0)
      break;
  }
  return used;
}

size_t tls_tx_pending(tls_conn_t *t, const uint8_t **buf) {
  *buf = t->tx + t->tx_sent;
  return (size_t)(t->tx_len - t->tx_sent);
}

void tls_tx_done(tls_conn_t *t, size_t n) {
  if (n > (size_t)(t->tx_len - t->tx_sent))
    n = (size_t)(t->tx_len - t->tx_sent);
  t->tx_sent = (uint16_t)(t->tx_sent + n);
  if (t->tx_sent == t->tx_len)
    t->tx_len = t->tx_sent = 0;
  if (t->state == TLS_STATE_HANDSHAKE || t->state == TLS_STATE_CONNECTED)
    (void)pump(t);
}

int tls_write(tls_conn_t *t, const uint8_t *data, size_t len) {
  uint8_t *p;
  size_t room;
  if ((t->state != TLS_STATE_CONNECTED && t->state != TLS_STATE_CLOSED) ||
      (t->flags & F_WCLOSED))
    return -1;
  tx_compact(t);
  room = (size_t)(t->tx_cap - t->tx_len);
  if (room <= TLS_RECORD_OVERHEAD)
    return 0;
  room -= TLS_RECORD_OVERHEAD;
  if (len > room)
    len = room;
  if (len > TLS_MAX_PLAINTEXT)
    len = TLS_MAX_PLAINTEXT;
  p = rec_room(t, TLS_CT_APPLICATION_DATA, len);
  memcpy(p, data, len);
  t->tx_len = (uint16_t)(t->tx_len + len);
  rec_close(t);
  return (int)len;
}

size_t tls_read(tls_conn_t *t, uint8_t *buf, size_t len) {
  if (!t->app_len)
    return 0;
  if (len > t->app_len)
    len = t->app_len;
  memcpy(buf, t->rx + t->app_off, len);
  t->app_off = (uint16_t)(t->app_off + len);
  t->app_len = (uint16_t)(t->app_len - len);
  if (!t->app_len) { /* the record is used up: on to the next */
    rx_keep(t, 0, 0, t->app_rec);
    t->app_rec = 0;
    if (process(t) >= 0)
      (void)pump(t);
  }
  return len;
}

int tls_close(tls_conn_t *t) {
  if (t->flags & F_WCLOSED)
    return 0;
  if (t->state == TLS_STATE_IDLE || t->state == TLS_STATE_ERROR)
    return -1;
  if (send_alert(t, 1, TLS_ALERT_CLOSE_NOTIFY) != 0)
    return -1;
  t->flags |= F_WCLOSED;
  return 0;
}
