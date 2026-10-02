/**
 * @file tls_server.c
 * @brief The TLS 1.3 server handshake (RFC 8446 §4): ClientHello in,
 *        ServerHello and the server's flight out, the client's Finished
 *        in.  REQ-TLS-001..030 (server side).
 */

#include "tls_internal.h"

#define SIG_MAX_ECDSA 72u /* DER ECDSA-P256 */
#define SIG_MAX_RSA 512u  /* RSA up to 4096 bits */
#define X25519_SHARE_LEN 32u
#define SECP256R1_SHARE_LEN 65u /* uncompressed point */

/* Bytes of a hello before its extensions: version, random, session ID,
 * cipher suite, compression method, extensions length */
#define SERVER_HELLO_FIXED (2 + TLS_RANDOM_LEN + 1 + SESSION_ID_MAX + 2 + 1 + 2)
#define SUPPORTED_VERSIONS_EXT (EXT_HDR + 2)
#define SELECTED_GROUP_EXT (EXT_HDR + 2)
#define SELECTED_IDENTITY_EXT (EXT_HDR + 2)
#define DTLS_COOKIE_LEN 16 /* random, kept in t->sid (DTLS echoes no id) */
#define COOKIE_EXT (EXT_HDR + 2 + DTLS_COOKIE_LEN)
#define KEY_SHARE_EXT(pub_len) (EXT_HDR + 4 + (pub_len))

/** What a ClientHello offers */
typedef struct {
  int tls13;     /* supported_versions lists TLS 1.3 */
  int our_suite; /* TLS_AES_128_GCM_SHA256 is offered */
  int our_sig;   /* signature_algorithms lists our scheme */
  int has_sig_algs, has_groups, has_key_share, has_psk, has_psk_modes;
  uint8_t psk_modes; /* TLS_PSK_* */
  uint16_t group;    /* the group of the share we would use; 0: none */
  const uint8_t *share;
  size_t share_len;
  uint16_t retry_group; /* a group we could ask a share of */
  rd_t cookie;          /* DTLS: the one our HelloRetryRequest sent */
  rd_t identities, binders;
  size_t binders_at; /* the binders are outside their own hash */
} client_hello_t;

static size_t sig_max(uint16_t scheme) {
  return scheme == TLS_SIG_ECDSA_SECP256R1_SHA256 ? SIG_MAX_ECDSA : SIG_MAX_RSA;
}

static uint8_t server_psk_modes(const tls_config_t *cfg) {
  return cfg->psk_modes ? cfg->psk_modes : TLS_PSK_DHE_KE;
}

/* x25519 preferred over secp256r1; after a HelloRetryRequest, only the
 * group it asked for */
static void consider_share(const tls_conn_t *t, client_hello_t *ch,
                           uint16_t group, rd_t share) {
  if (!tls_group_allowed(t->cfg, group) ||
      ((t->flags & F_HRR) && group != t->group) ||
      (group != TLS_GROUP_X25519 && ch->group == TLS_GROUP_X25519))
    return;
  ch->group = group;
  ch->share = share.p;
  ch->share_len = share.n;
}

static int client_extension(tls_conn_t *t, client_hello_t *ch, const uint8_t *m,
                            uint16_t type, rd_t *d, size_t exts_left) {
  rd_t v;
  switch (type) {
  case TLS_EXT_SUPPORTED_VERSIONS:
    v = rd_vec(d, 1);
    while (v.n >= 2)
      if (rd_uint(&v, 2) == tls_version(t))
        ch->tls13 = 1;
    break;
  case TLS_EXT_COOKIE: /* DTLS: ours, returned */
    if (tls_is_dtls(t))
      ch->cookie = rd_vec(d, 2);
    break;
  case TLS_EXT_SIGNATURE_ALGORITHMS:
    ch->has_sig_algs = 1;
    v = rd_vec(d, 2);
    while (v.n >= 2)
      if (rd_uint(&v, 2) == t->cfg->sig_scheme)
        ch->our_sig = 1;
    break;
  case TLS_EXT_SUPPORTED_GROUPS: /* what a HelloRetryRequest could ask */
    ch->has_groups = 1;
    v = rd_vec(d, 2);
    while (v.n >= 2) {
      uint16_t g = (uint16_t)rd_uint(&v, 2);
      if (tls_group_allowed(t->cfg, g) &&
          (g == TLS_GROUP_X25519 || !ch->retry_group))
        ch->retry_group = g;
    }
    break;
  case TLS_EXT_KEY_SHARE:
    ch->has_key_share = 1;
    v = rd_vec(d, 2);
    while (v.n) {
      uint16_t g = (uint16_t)rd_uint(&v, 2);
      rd_t share = rd_vec(&v, 2);
      if (v.bad)
        return TLS_ALERT_DECODE_ERROR;
      consider_share(t, ch, g, share);
    }
    break;
  case TLS_EXT_MAX_FRAGMENT_LENGTH: /* granted: records of 2^(8+code) */
    if (d->n != 1)
      return TLS_ALERT_DECODE_ERROR;
    if (d->p[0] < TLS_MFL_512 || d->p[0] > TLS_MFL_4096)
      return TLS_ALERT_ILLEGAL_PARAMETER;
    t->max_frag = (uint16_t)(256u << d->p[0]);
    break;
  case TLS_EXT_PSK_KEY_EXCHANGE_MODES:
    ch->has_psk_modes = 1;
    v = rd_vec(d, 1);
    while (v.n) { /* psk_ke (0) → TLS_PSK_KE, psk_dhe_ke (1) → .._DHE_KE */
      uint32_t k = rd_uint(&v, 1);
      if (k < 2)
        ch->psk_modes |= (uint8_t)(1u << k);
    }
    break;
  case TLS_EXT_PRE_SHARED_KEY: /* the last extension (§4.2.11) */
    if (exts_left)
      return TLS_ALERT_ILLEGAL_PARAMETER;
    ch->has_psk = 1;
    ch->identities = rd_vec(d, 2);
    ch->binders_at = (size_t)(d->p - m);
    ch->binders = rd_vec(d, 2);
    break;
  default: /* not ours: ignored */
    break;
  }
  return d->bad ? TLS_ALERT_DECODE_ERROR : 0;
}

/* RFC 8446 §4.1.2: 0, or the alert for a malformed ClientHello */
static int parse_client_hello(tls_conn_t *t, const uint8_t *m, size_t mlen,
                              client_hello_t *ch) {
  rd_t r = rd_body(m, mlen), v, exts;
  uint32_t seen[2] = {0, 0};

  memset(ch, 0, sizeof(*ch));
  rd_uint(&r, 2); /* legacy_version: the extension decides */
  rd_take(&r, TLS_RANDOM_LEN);
  v = rd_vec(&r, 1); /* legacy_session_id, echoed — but not by DTLS (§5) */
  if (v.n > sizeof(t->sid))
    return TLS_ALERT_DECODE_ERROR;
  if (!tls_is_dtls(t)) {
    memcpy(t->sid, v.p, v.n);
    t->sid_len = (uint8_t)v.n;
  } else if (rd_vec(&r, 1).n) { /* legacy_cookie: empty (RFC 9147 §5.3) */
    return TLS_ALERT_ILLEGAL_PARAMETER;
  }
  v = rd_vec(&r, 2); /* cipher_suites */
  while (v.n >= 2)
    if (rd_uint(&v, 2) == TLS_AES_128_GCM_SHA256)
      ch->our_suite = 1;
  if (v.n)
    return TLS_ALERT_DECODE_ERROR;
  v = rd_vec(&r, 1); /* legacy_compression_methods: exactly null */
  if (!r.bad && (v.n != 1 || v.p[0] != 0))
    return TLS_ALERT_ILLEGAL_PARAMETER;
  exts = rd_vec(&r, 2);
  if (r.bad || r.n)
    return TLS_ALERT_DECODE_ERROR;
  while (exts.n) {
    uint16_t type;
    rd_t d;
    int alert = tls_next_extension(&exts, seen, &type, &d);
    if (!alert)
      alert = client_extension(t, ch, m, type, &d, exts.n);
    if (alert)
      return alert;
  }
  return 0;
}

/* RFC 8446 §4.2.11: the index of the identity that is our PSK; -1 if none
 * is (or none is configured); -2 if the list is malformed */
static int find_our_psk(const tls_config_t *cfg, rd_t ids) {
  int i = 0, pick = -1;
  if (ids.n == 0)
    return -2;
  while (ids.n) {
    rd_t id = rd_vec(&ids, 2);
    rd_uint(&ids, 4); /* obfuscated_ticket_age: none for external PSKs */
    if (ids.bad || id.n == 0)
      return -2;
    if (pick < 0 && cfg->psk && id.n == cfg->psk_id_len &&
        memcmp(id.p, cfg->psk_id, id.n) == 0)
      pick = i;
    i++;
  }
  return pick;
}

/* Our PSK with a mode both sides allow, (EC)DHE preferred; 0: none */
static uint8_t choose_psk_mode(const tls_config_t *cfg,
                               const client_hello_t *ch, int pick) {
  uint8_t both = ch->psk_modes & server_psk_modes(cfg);
  if (pick < 0)
    return 0;
  if ((both & TLS_PSK_DHE_KE) && ch->group)
    return TLS_PSK_DHE_KE;
  return (both & TLS_PSK_KE) ? TLS_PSK_KE : 0;
}

/* RFC 8446 §4.1.4: no share we can use, but a group in common — ask for a
 * share of @p group; and for DTLS, unless configured not to, a cookie the
 * second ClientHello must return (RFC 9147 §5.1), with or without a
 * group.  ClientHello1 gives way to message_hash. */
static int send_hello_retry(tls_conn_t *t, const uint8_t *m, size_t mlen,
                            uint16_t group) {
  const tls_crypto_t *c = t->cfg->crypto;
  int cookie = tls_is_dtls(t) && !t->cfg->dtls_no_cookie;
  size_t exts = (group ? SELECTED_GROUP_EXT : 0u) + SUPPORTED_VERSIONS_EXT +
                (cookie ? COOKIE_EXT : 0u);
  uint8_t *hrr = tls_hs_begin(t, HS_HDR + SERVER_HELLO_FIXED + exts);
  uint8_t *p;
  if (!hrr || (cookie && c->random(c->ctx, t->sid, DTLS_COOKIE_LEN) != 0))
    return tls_fail(t, TLS_ALERT_INTERNAL_ERROR);
  c->hash_update(&t->transcript, m, mlen);
  tls_transcript_hrr(c, &t->transcript);
  p = hrr + HS_HDR;
  net_write16be(p, tls_legacy_version(t));
  memcpy(p + 2, tls_hrr_random, TLS_RANDOM_LEN);
  p += 2 + TLS_RANDOM_LEN;
  *p++ = t->sid_len;
  memcpy(p, t->sid, t->sid_len);
  p += t->sid_len;
  net_write16be(p, TLS_AES_128_GCM_SHA256);
  p[2] = 0; /* legacy_compression_method */
  net_write16be(p + 3, exts);
  p += 5;
  if (group) {
    net_write16be(p, TLS_EXT_KEY_SHARE);
    net_write16be(p + 2, 2);
    net_write16be(p + 4, group);
    p += SELECTED_GROUP_EXT;
  }
  net_write16be(p, TLS_EXT_SUPPORTED_VERSIONS);
  net_write16be(p + 2, 2);
  net_write16be(p + 4, tls_version(t));
  p += SUPPORTED_VERSIONS_EXT;
  if (cookie) {
    net_write16be(p, TLS_EXT_COOKIE);
    net_write16be(p + 2, 2 + DTLS_COOKIE_LEN);
    net_write16be(p + 4, DTLS_COOKIE_LEN);
    memcpy(p + 6, t->sid, DTLS_COOKIE_LEN);
    p += COOKIE_EXT;
  }
  tls_hs_end(t, hrr, TLS_HS_SERVER_HELLO, (size_t)(p - hrr - HS_HDR));
  tls_hs_flush(t);
  if (t->sid_len) /* compatibility mode: the dummy CCS goes here */
    (void)tls_queue_ccs(t);
  t->group = group;
  t->flags |= F_HRR | F_CCS_OK | (cookie ? F_COOKIE : 0u);
  return 0;
}

/* The Early Secret, and the transcript through the ClientHello; with a
 * PSK its binder must check out (RFC 8446 §4.2.11.2) */
static int take_early_secret(tls_conn_t *t, const client_hello_t *ch,
                             const uint8_t *m, size_t mlen, int pick) {
  const tls_config_t *cfg = t->cfg;
  const tls_crypto_t *c = cfg->crypto;
  uint8_t h[TLS_HASH_LEN], expected[TLS_HASH_LEN];
  rd_t binders = ch->binders, binder = {NULL, 0, 0};
  int i;

  if (pick < 0) {
    tls_early_secret(c, NULL, 0, t->secret);
    c->hash_update(&t->transcript, m, mlen);
    return 0;
  }
  for (i = 0; i <= pick; i++)
    binder = rd_vec(&binders, 1);
  if (binder.n != TLS_HASH_LEN) /* (a malformed list reads as empty) */
    return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  tls_early_secret(c, cfg->psk, cfg->psk_len, t->secret);
  c->hash_update(&t->transcript, m, ch->binders_at);
  c->hash_peek(&t->transcript, h);
  tls_psk_binder(c, tls_is_dtls(t), t->secret, cfg->psk_resumption, h,
                 expected);
  if (!tls_equal(expected, binder.p, TLS_HASH_LEN))
    return tls_fail(t, TLS_ALERT_DECRYPT_ERROR);
  c->hash_update(&t->transcript, m + ch->binders_at, mlen - ch->binders_at);
  t->flags |= F_PSK;
  return 0;
}

/* ServerHello: pre_shared_key, key_share, supported_versions (the order
 * of RFC 8448) */
static int send_server_hello(tls_conn_t *t, uint8_t psk_mode, int pick,
                             const uint8_t *pub, size_t pub_len) {
  const tls_crypto_t *c = t->cfg->crypto;
  size_t exts = (psk_mode ? SELECTED_IDENTITY_EXT : 0u) +
                (t->group ? KEY_SHARE_EXT(pub_len) : 0u) +
                SUPPORTED_VERSIONS_EXT;
  uint8_t *sh = tls_hs_begin(t, HS_HDR + SERVER_HELLO_FIXED + exts);
  uint8_t *p;

  if (!sh)
    return -1;
  p = sh + HS_HDR;
  net_write16be(p, tls_legacy_version(t));
  if (c->random(c->ctx, p + 2, TLS_RANDOM_LEN) != 0)
    return -1;
  p += 2 + TLS_RANDOM_LEN;
  *p++ = t->sid_len;
  memcpy(p, t->sid, t->sid_len);
  p += t->sid_len;
  net_write16be(p, TLS_AES_128_GCM_SHA256);
  p[2] = 0; /* legacy_compression_method */
  net_write16be(p + 3, exts);
  p += 5;
  if (psk_mode) {
    net_write16be(p, TLS_EXT_PRE_SHARED_KEY);
    net_write16be(p + 2, 2);
    net_write16be(p + 4, pick);
    p += SELECTED_IDENTITY_EXT;
  }
  if (t->group) {
    net_write16be(p, TLS_EXT_KEY_SHARE);
    net_write16be(p + 2, 4 + pub_len);
    net_write16be(p + 4, t->group);
    net_write16be(p + 6, pub_len);
    memcpy(p + 8, pub, pub_len);
    p += KEY_SHARE_EXT(pub_len);
  }
  net_write16be(p, TLS_EXT_SUPPORTED_VERSIONS);
  net_write16be(p + 2, 2);
  net_write16be(p + 4, tls_version(t));
  p += SUPPORTED_VERSIONS_EXT;
  tls_hs_end(t, sh, TLS_HS_SERVER_HELLO, (size_t)(p - sh - HS_HDR));
  tls_hs_flush(t);
  return 0;
}

/* Handshake Secret and traffic keys (RFC 8446 §7.1) from the (EC)DHE
 * secret @p shared (NULL for psk_ke) — which is t->rsec, read before the
 * peer's handshake traffic secret replaces it */
static void enter_handshake_keys(tls_conn_t *t, const uint8_t *shared) {
  const tls_crypto_t *c = t->cfg->crypto;
  uint8_t h[TLS_HASH_LEN];
  tls_next_secret(c, tls_is_dtls(t), t->secret, shared, TLS_HASH_LEN);
  c->hash_peek(&t->transcript, h);
  tls_derive_secret(c, tls_is_dtls(t), t->secret, "c hs traffic", h, t->rsec);
  tls_derive_secret(c, tls_is_dtls(t), t->secret, "s hs traffic", h, t->wsec);
  tls_set_keys(t, 0);
  tls_set_keys(t, 1);
  t->flags |= F_RPROT | F_WPROT | F_CCS_OK;
  /* A client in middlebox compatibility mode (a session ID) gets the
   * dummy change_cipher_spec (RFC 8446 D.4) */
  t->step = (t->sid_len && !(t->flags & F_HRR)) ? ST_SEND_CCS : ST_SEND_EE;
}

/* RFC 8446 §4.1.1-4.1.4: pick the parameters, answer with ServerHello
 * (or a HelloRetryRequest), enter the handshake keys.  REQ-TLS-001 */
static int on_client_hello(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  const tls_config_t *cfg = t->cfg;
  const tls_crypto_t *c = cfg->crypto;
  uint8_t pub[TLS_KX_PUB_MAX];
  size_t pub_len = 0;
  client_hello_t ch;
  uint8_t psk_mode;
  int alert, pick = -1;

  if ((alert = parse_client_hello(t, m, mlen, &ch)))
    return tls_fail(t, alert);
  if (t->flags & F_COOKIE) { /* DTLS: the cookie must come back (§5.1) */
    if (ch.cookie.n != DTLS_COOKIE_LEN ||
        !tls_equal(ch.cookie.p, t->sid, DTLS_COOKIE_LEN))
      return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
    t->flags |= F_VERIFIED;
  }
  if (!ch.tls13)
    return tls_fail(t, TLS_ALERT_PROTOCOL_VERSION);
  if (!ch.our_suite)
    return tls_fail(t, TLS_ALERT_HANDSHAKE_FAILURE);
  /* RFC 8446 §9.2: supported_groups and key_share come together */
  if (ch.has_groups != ch.has_key_share)
    return tls_fail(t, TLS_ALERT_MISSING_EXTENSION);
  if (ch.has_psk) {
    if (!ch.has_psk_modes)
      return tls_fail(t, TLS_ALERT_MISSING_EXTENSION);
    if ((pick = find_our_psk(cfg, ch.identities)) == -2)
      return tls_fail(t, TLS_ALERT_DECODE_ERROR);
  }
  psk_mode = choose_psk_mode(cfg, &ch, pick);

  /* No share we can use: ask for one, once, if this handshake needs
   * (EC)DHE and a group is in common */
  if (!psk_mode && !ch.group) {
    int psk_dhe =
        pick >= 0 && (ch.psk_modes & server_psk_modes(cfg) & TLS_PSK_DHE_KE);
    if (t->flags & F_HRR)
      return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
    if (ch.retry_group && ch.has_key_share && (psk_dhe || cfg->cert_count)) {
      if (!psk_dhe && !ch.has_sig_algs)
        return tls_fail(t, TLS_ALERT_MISSING_EXTENSION);
      if (!psk_dhe && !ch.our_sig)
        return tls_fail(t, TLS_ALERT_HANDSHAKE_FAILURE);
      return send_hello_retry(t, m, mlen, ch.retry_group);
    }
  }
  if (!psk_mode) { /* certificate authentication */
    if (!cfg->cert_count)
      return tls_fail(t, ch.has_psk ? TLS_ALERT_UNKNOWN_PSK_IDENTITY
                                    : TLS_ALERT_HANDSHAKE_FAILURE);
    if (!ch.has_key_share || !ch.has_sig_algs || !ch.has_groups)
      return tls_fail(t, TLS_ALERT_MISSING_EXTENSION);
    if (!ch.our_sig || !ch.group)
      return tls_fail(t, TLS_ALERT_HANDSHAKE_FAILURE);
  }
  if (psk_mode == TLS_PSK_KE)
    ch.group = 0;
  if (ch.group &&
      ch.share_len != (ch.group == TLS_GROUP_X25519 ? X25519_SHARE_LEN
                                                    : SECP256R1_SHARE_LEN))
    return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  /* DTLS: a first ClientHello that would get a ServerHello gets a cookie to
   * return first (RFC 9147 §5.1); the second must use the same share */
  if (tls_is_dtls(t) && !(t->flags & F_HRR) && !cfg->dtls_no_cookie) {
    alert = send_hello_retry(t, m, mlen, 0);
    t->group = ch.group;
    return alert;
  }
  if ((alert = take_early_secret(t, &ch, m, mlen, psk_mode ? pick : -1)))
    return alert;

  /* Our share, and the shared secret (the peer's share checked).  The key
   * pair goes in kx_priv and the secret in rsec, which the handshake
   * traffic secret replaces: nothing is left on the stack, and a failure's
   * tls_fail() wipes both, whatever the backend wrote before failing. */
  t->group = ch.group;
  if (t->group) {
    if (c->kx_keygen(c->ctx, t->group, t->kx_priv, pub, &pub_len) != 0)
      return tls_fail(t, TLS_ALERT_INTERNAL_ERROR);
    alert = c->kx_shared(c->ctx, t->group, t->kx_priv, ch.share, ch.share_len,
                         t->rsec) != 0;
    tls_wipe(t->kx_priv, sizeof(t->kx_priv));
    if (alert)
      return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  }
  if (send_server_hello(t, psk_mode, pick, pub, pub_len) != 0)
    return tls_fail(t, TLS_ALERT_INTERNAL_ERROR);
  enter_handshake_keys(t, t->group ? t->rsec : NULL);
  return HS_KEYS;
}

/* ── The server's flight, one message per step ── */

/* EncryptedExtensions: max_fragment_length, if granted */
static int send_encrypted_extensions(tls_conn_t *t) {
  uint8_t *m = tls_hs_begin(t, HS_HDR + 2 + EXT_HDR + 1);
  size_t i;
  uint8_t code = TLS_MFL_512;
  if (!m)
    return 0;
  net_write16be(m + HS_HDR, 0);
  if (t->max_frag) {
    for (i = 512; i < t->max_frag; i <<= 1)
      code++;
    net_write16be(m + HS_HDR, EXT_HDR + 1);
    net_write16be(m + HS_HDR + 2, TLS_EXT_MAX_FRAGMENT_LENGTH);
    net_write16be(m + HS_HDR + 4, 1);
    m[HS_HDR + 6] = code;
  }
  tls_hs_end(t, m, TLS_HS_ENCRYPTED_EXTENSIONS,
             t->max_frag ? 2u + EXT_HDR + 1u : 2u);
  return 1;
}

/* Certificate: an empty context, then each DER certificate without
 * extensions */
static int send_certificate(tls_conn_t *t) {
  const tls_config_t *cfg = t->cfg;
  size_t i, n = HS_HDR + 1 + 3;
  uint8_t *m;
  for (i = 0; i < cfg->cert_count; i++)
    n += 3 + (size_t)cfg->cert_len[i] + 2;
  if (!(m = tls_hs_begin(t, n)))
    return 0;
  m[HS_HDR] = 0;
  net_write24be(m + HS_HDR + 1, (uint32_t)(n - HS_HDR - 4));
  n = HS_HDR + 4;
  for (i = 0; i < cfg->cert_count; i++) {
    net_write24be(m + n, cfg->cert_len[i]);
    memcpy(m + n + 3, cfg->cert[i], cfg->cert_len[i]);
    n += 3 + (size_t)cfg->cert_len[i];
    net_write16be(m + n, 0);
    n += 2;
  }
  tls_hs_end(t, m, TLS_HS_CERTIFICATE, n - HS_HDR);
  return 1;
}

/* CertificateVerify (RFC 8446 §4.4.3): 1 sent, 0 no room, < 0 failed */
static int send_certificate_verify(tls_conn_t *t) {
  const tls_config_t *cfg = t->cfg;
  const tls_crypto_t *c = cfg->crypto;
  uint8_t content[TLS_CV_CONTENT_LEN];
  size_t sig_len = 0, cap = sig_max(cfg->sig_scheme);
  uint8_t *m = tls_hs_begin(t, HS_HDR + 4 + cap);
  if (!m)
    return 0;
  tls_cert_verify_content(t, content);
  if (c->sign(c->ctx, cfg->key, cfg->sig_scheme, content, sizeof(content),
              m + HS_HDR + 4, &sig_len, cap) != 0 ||
      sig_len > cap)
    return tls_fail(t, TLS_ALERT_INTERNAL_ERROR);
  net_write16be(m + HS_HDR, cfg->sig_scheme);
  net_write16be(m + HS_HDR + 2, sig_len);
  tls_hs_end(t, m, TLS_HS_CERTIFICATE_VERIFY, 4 + sig_len);
  return 1;
}

/* Finished; then the Master Secret — our application keys now, the
 * client's once its Finished checks out */
static int send_finished(tls_conn_t *t) {
  const tls_crypto_t *c = t->cfg->crypto;
  uint8_t h[TLS_HASH_LEN], master[TLS_HASH_LEN];
  uint8_t *m = tls_hs_begin(t, HS_HDR + TLS_HASH_LEN);
  if (!m)
    return 0;
  c->hash_peek(&t->transcript, h);
  tls_finished_mac(c, tls_is_dtls(t), t->wsec, h, m + HS_HDR);
  tls_hs_end(t, m, TLS_HS_FINISHED, TLS_HASH_LEN);
  tls_hs_flush(t);
  c->hash_peek(&t->transcript, h);
  memcpy(master, t->secret, sizeof(master));
  tls_next_secret(c, tls_is_dtls(t), master, NULL, 0);
  tls_derive_secret(c, tls_is_dtls(t), master, "c ap traffic", h, t->secret);
  tls_derive_secret(c, tls_is_dtls(t), master, "s ap traffic", h, t->wsec);
  tls_wipe(master, sizeof(master));
  tls_set_keys(t, 1);
  return 1;
}

/* The flight after ServerHello, as far as tx allows */
static int pump_server(tls_conn_t *t) {
  int sent;
  for (;;) {
    switch (t->step) {
    case ST_SEND_CCS:
      if (tls_queue_ccs(t) != 0)
        return 0;
      t->step = ST_SEND_EE;
      break;
    case ST_SEND_EE:
      if (!send_encrypted_extensions(t))
        return 0;
      t->step = (t->flags & F_PSK) ? ST_SEND_FIN : ST_SEND_CERT;
      break;
    case ST_SEND_CERT:
      if (!send_certificate(t))
        return 0;
      t->step = ST_SEND_CV;
      break;
    case ST_SEND_CV:
      if ((sent = send_certificate_verify(t)) <= 0)
        return sent;
      t->step = ST_SEND_FIN;
      break;
    case ST_SEND_FIN:
      if (send_finished(t))
        t->step = ST_WAIT_FIN;
      return 0;
    default:
      return 0;
    }
  }
}

/* The client's Finished (RFC 8446 §4.4.4): the handshake is done */
static int on_client_finished(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  const tls_crypto_t *c = t->cfg->crypto;
  uint8_t h[TLS_HASH_LEN], mac[TLS_HASH_LEN];
  if (mlen != HS_HDR + TLS_HASH_LEN)
    return tls_fail(t, TLS_ALERT_DECODE_ERROR);
  c->hash_peek(&t->transcript, h);
  tls_finished_mac(c, tls_is_dtls(t), t->rsec, h, mac);
  if (!tls_equal(mac, m + HS_HDR, TLS_HASH_LEN))
    return tls_fail(t, TLS_ALERT_DECRYPT_ERROR);
  c->hash_update(&t->transcript, m, mlen);
  memcpy(t->rsec, t->secret, TLS_HASH_LEN);
  tls_wipe(t->secret, sizeof(t->secret));
  tls_set_keys(t, 0);
  t->flags &= (uint16_t)~F_CCS_OK;
  t->step = ST_DONE;
  t->state = TLS_STATE_CONNECTED;
  tls_notify(t, TLS_EVT_CONNECTED);
  return HS_KEYS;
}

static int on_server_message(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  if (t->step == ST_WAIT_CH && m[0] == TLS_HS_CLIENT_HELLO)
    return on_client_hello(t, m, mlen);
  if (t->step == ST_WAIT_FIN && m[0] == TLS_HS_FINISHED)
    return on_client_finished(t, m, mlen);
  return tls_fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
}

const tls_role_t tls_server_role = {on_server_message, pump_server};

static int config_complete(const tls_config_t *cfg) {
  if (!cfg->cert_count && !cfg->psk)
    return 0;
  if (cfg->cert_count &&
      (!cfg->cert || !cfg->cert_len || !cfg->key || !cfg->sig_scheme))
    return 0;
  return !cfg->psk || (cfg->psk_len && cfg->psk_id && cfg->psk_id_len);
}

int tls_accept(tls_conn_t *t) {
  if (t->state != TLS_STATE_IDLE || !config_complete(t->cfg))
    return -1;
  t->role = &tls_server_role;
  t->flags = F_SERVER;
  t->state = TLS_STATE_HANDSHAKE;
  t->step = ST_WAIT_CH;
  t->cfg->crypto->hash_init(&t->transcript);
  return 0;
}
