/**
 * @file tls_client.c
 * @brief The TLS 1.3 client handshake (RFC 8446 §4): ClientHello out; the
 *        server's hello, extensions, certificate and Finished in; our
 *        Finished out.  REQ-TLS-031..050.
 */

#include "tls_internal.h"

#define CHAIN_MAX 6 /* certificates passed to verify_chain */
#define PSK_BINDER_LIST_LEN (2 + 1 + TLS_HASH_LEN) /* one binder */

/* Bytes of the ClientHello before its extensions: version, random, empty
 * session ID, one cipher suite, null compression, extensions length */
#define CLIENT_HELLO_FIXED (2 + TLS_RANDOM_LEN + 1 + 4 + 2 + 2)

/* A literal IPv4 or IPv6 address is not sent as server_name (RFC 6066 §3) */
static int ip_literal(const char *h) {
  int dots_and_digits_only = 1;
  for (; *h; h++) {
    if (*h == ':')
      return 1;
    if (*h != '.' && (*h < '0' || *h > '9'))
      dots_and_digits_only = 0;
  }
  return dots_and_digits_only;
}

static int sends_server_name(const tls_conn_t *t) {
  return t->host && !ip_literal(t->host);
}

static uint8_t offered_psk_modes(const tls_config_t *cfg) {
  if (!cfg->psk)
    return 0;
  return cfg->psk_modes ? cfg->psk_modes : TLS_PSK_DHE_KE;
}

static uint8_t group_count(const tls_config_t *cfg) {
  uint8_t mask = tls_groups(cfg);
  return (uint8_t)(((mask & TLS_GROUPS_X25519) ? 1 : 0) +
                   ((mask & TLS_GROUPS_SECP256R1) ? 1 : 0));
}

/* ── ClientHello extensions, each writer returning the end ── */

static uint8_t *put_extension_header(uint8_t *p, uint16_t type, size_t len) {
  net_write16be(p, type);
  net_write16be(p + 2, len);
  return p + EXT_HDR;
}

static size_t server_name_size(const tls_conn_t *t) {
  return sends_server_name(t) ? EXT_HDR + 5 + strlen(t->host) : 0;
}

static uint8_t *put_server_name(const tls_conn_t *t, uint8_t *p) {
  size_t len = strlen(t->host);
  p = put_extension_header(p, TLS_EXT_SERVER_NAME, 5 + len);
  net_write16be(p, 3 + len); /* one host_name */
  p[2] = 0;
  net_write16be(p + 3, len);
  memcpy(p + 5, t->host, len);
  return p + 5 + len;
}

static uint8_t *put_versions_and_signatures(uint8_t *p) {
  p = put_extension_header(p, TLS_EXT_SUPPORTED_VERSIONS, 3);
  p[0] = 2;
  net_write16be(p + 1, TLS_VERSION_13);
  p = put_extension_header(p + 3, TLS_EXT_SIGNATURE_ALGORITHMS, 6);
  net_write16be(p, 4);
  net_write16be(p + 2, TLS_SIG_ECDSA_SECP256R1_SHA256);
  net_write16be(p + 4, TLS_SIG_RSA_PSS_RSAE_SHA256);
  return p + 6;
}
#define VERSIONS_AND_SIGNATURES_SIZE (EXT_HDR + 3 + EXT_HDR + 6)

static size_t key_share_size(const tls_conn_t *t, size_t pub_len) {
  return t->group
             ? EXT_HDR + 2 + 2u * group_count(t->cfg) + EXT_HDR + 6 + pub_len
             : 0;
}

/* supported_groups, then key_share with one share, of t->group */
static uint8_t *put_groups_and_share(const tls_conn_t *t, uint8_t *p,
                                     const uint8_t *pub, size_t pub_len) {
  uint8_t mask = tls_groups(t->cfg), n = group_count(t->cfg);
  p = put_extension_header(p, TLS_EXT_SUPPORTED_GROUPS, 2u + 2u * n);
  net_write16be(p, 2u * n);
  p += 2;
  if (mask & TLS_GROUPS_X25519) {
    net_write16be(p, TLS_GROUP_X25519);
    p += 2;
  }
  if (mask & TLS_GROUPS_SECP256R1) {
    net_write16be(p, TLS_GROUP_SECP256R1);
    p += 2;
  }
  p = put_extension_header(p, TLS_EXT_KEY_SHARE, 6 + pub_len);
  net_write16be(p, 4 + pub_len);
  net_write16be(p + 2, t->group);
  net_write16be(p + 4, pub_len);
  memcpy(p + 6, pub, pub_len);
  return p + 6 + pub_len;
}

static uint8_t *put_max_fragment(uint8_t *p, uint8_t code) {
  p = put_extension_header(p, TLS_EXT_MAX_FRAGMENT_LENGTH, 1);
  *p = code;
  return p + 1;
}

static uint8_t *put_cookie(uint8_t *p, const uint8_t *cookie, size_t len) {
  p = put_extension_header(p, TLS_EXT_COOKIE, 2 + len);
  net_write16be(p, len);
  memcpy(p + 2, cookie, len);
  return p + 2 + len;
}

static size_t psk_size(const tls_config_t *cfg) {
  return cfg->psk ? EXT_HDR + 3 + EXT_HDR + 2 + 2 + cfg->psk_id_len + 4 +
                        PSK_BINDER_LIST_LEN
                  : 0;
}

/* psk_key_exchange_modes, then pre_shared_key — the last extension — with
 * one identity and room for its binder at *binders */
static uint8_t *put_psk(const tls_config_t *cfg, uint8_t *p,
                        uint8_t **binders) {
  uint8_t modes = offered_psk_modes(cfg);
  uint8_t n = (uint8_t)(((modes & TLS_PSK_DHE_KE) ? 1 : 0) +
                        ((modes & TLS_PSK_KE) ? 1 : 0));
  size_t idl = cfg->psk_id_len;
  p = put_extension_header(p, TLS_EXT_PSK_KEY_EXCHANGE_MODES, 1u + n);
  *p++ = n;
  if (modes & TLS_PSK_DHE_KE)
    *p++ = 1;
  if (modes & TLS_PSK_KE)
    *p++ = 0;
  p = put_extension_header(p, TLS_EXT_PRE_SHARED_KEY,
                           2 + 2 + idl + 4 + PSK_BINDER_LIST_LEN);
  net_write16be(p, 2 + idl + 4);
  net_write16be(p + 2, idl);
  memcpy(p + 4, cfg->psk_id, idl);
  memset(p + 4 + idl, 0, 4); /* obfuscated_ticket_age */
  p += 8 + idl;
  *binders = p;
  net_write16be(p, 1 + TLS_HASH_LEN);
  p[2] = TLS_HASH_LEN;
  return p + PSK_BINDER_LIST_LEN;
}

/* The PSK binder over the ClientHello up to its binders (and, after a
 * HelloRetryRequest, the message_hash @p mh and the HRR before it) */
static void write_binder(tls_conn_t *t, uint8_t *m, uint8_t *binders,
                         uint8_t *end, const uint8_t *mh, const uint8_t *hrr,
                         size_t hrr_len) {
  const tls_config_t *cfg = t->cfg;
  const tls_crypto_t *c = cfg->crypto;
  uint8_t h[TLS_HASH_LEN];
  tls_hash_t th;
  m[0] = TLS_HS_CLIENT_HELLO;
  net_write24be(m + 1, (uint32_t)(end - m - HS_HDR));
  tls_early_secret(c, cfg->psk, cfg->psk_len, t->secret);
  c->hash_init(&th);
  if (mh) {
    c->hash_update(&th, mh, HS_HDR + TLS_HASH_LEN);
    c->hash_update(&th, hrr, hrr_len);
  }
  c->hash_update(&th, m, (size_t)(binders - m));
  c->hash_peek(&th, h);
  tls_psk_binder(c, t->secret, cfg->psk_resumption, h, binders + 3);
}

/*
 * A ClientHello into tx (RFC 8446 §4.1.2): the first, or after a
 * HelloRetryRequest (@p mh its message_hash, @p hrr the HRR) the second —
 * the same random, a share of t->group, the server's cookie, a new binder.
 */
static int client_hello(tls_conn_t *t, const uint8_t *cookie, size_t cookie_len,
                        const uint8_t *mh, const uint8_t *hrr, size_t hrr_len) {
  const tls_config_t *cfg = t->cfg;
  const tls_crypto_t *c = cfg->crypto;
  uint8_t pub[TLS_KX_PUB_MAX], *m, *p, *exts, *binders = NULL;
  size_t pub_len = 0;

  if (t->group &&
      c->kx_keygen(c->ctx, t->group, t->kx_priv, pub, &pub_len) != 0)
    return -1;
  m = tls_hs_begin(
      t, HS_HDR + CLIENT_HELLO_FIXED + server_name_size(t) +
             VERSIONS_AND_SIGNATURES_SIZE + key_share_size(t, pub_len) +
             (cookie_len ? EXT_HDR + 2 + cookie_len : 0) +
             (cfg->max_fragment ? EXT_HDR + 1 : 0) + psk_size(cfg));
  if (!m)
    return -1;

  p = m + HS_HDR;
  net_write16be(p, TLS_LEGACY_VERSION);
  memcpy(p + 2, t->sid, TLS_RANDOM_LEN); /* a client keeps its random in sid */
  p += 2 + TLS_RANDOM_LEN;
  *p++ = 0; /* legacy_session_id: none (no middlebox compatibility mode) */
  net_write16be(p, 2);
  net_write16be(p + 2, TLS_AES_128_GCM_SHA256);
  p[4] = 1; /* legacy_compression_methods: null */
  p[5] = 0;
  exts = p + 6;
  p = exts + 2;
  if (sends_server_name(t))
    p = put_server_name(t, p);
  p = put_versions_and_signatures(p);
  if (t->group)
    p = put_groups_and_share(t, p, pub, pub_len);
  if (cfg->max_fragment)
    p = put_max_fragment(p, cfg->max_fragment);
  if (cookie_len)
    p = put_cookie(p, cookie, cookie_len);
  if (cfg->psk)
    p = put_psk(cfg, p, &binders);
  net_write16be(exts, (size_t)(p - exts - 2));
  if (binders)
    write_binder(t, m, binders, p, mh, hrr, hrr_len);
  tls_hs_end(t, m, TLS_HS_CLIENT_HELLO, (size_t)(p - m - HS_HDR));
  tls_rec_close(t);
  return 0;
}

/* ── The server's messages ── */

/* RFC 8446 §4.1.4: the server wants another share (or a cookie back): a
 * second ClientHello, once */
static int on_hello_retry(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  const tls_crypto_t *c = t->cfg->crypto;
  uint8_t message_hash[HS_HDR + TLS_HASH_LEN] = {254, 0, 0, TLS_HASH_LEN};
  rd_t r, v, exts, cookie = {NULL, 0, 0};
  uint32_t seen[2] = {0, 0}, selected = 0;
  int tls13 = 0, alert;

  if (t->flags & F_HRR)
    return tls_fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
  r = rd_body(m, mlen);
  rd_take(&r, 2 + TLS_RANDOM_LEN);
  v = rd_vec(&r, 1);
  if (r.bad)
    return tls_fail(t, TLS_ALERT_DECODE_ERROR);
  if (v.n != 0 || rd_uint(&r, 2) != TLS_AES_128_GCM_SHA256 ||
      rd_uint(&r, 1) != 0)
    return tls_fail(t, r.bad ? TLS_ALERT_DECODE_ERROR
                             : TLS_ALERT_ILLEGAL_PARAMETER);
  exts = rd_vec(&r, 2);
  if (r.bad || r.n)
    return tls_fail(t, TLS_ALERT_DECODE_ERROR);
  while (exts.n) {
    uint16_t type;
    rd_t d;
    if ((alert = tls_next_extension(&exts, seen, &type, &d)))
      return tls_fail(t, alert);
    switch (type) {
    case TLS_EXT_SUPPORTED_VERSIONS:
      if (rd_uint(&d, 2) != TLS_VERSION_13)
        return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
      tls13 = 1;
      break;
    case TLS_EXT_KEY_SHARE: /* selected_group */
      selected = rd_uint(&d, 2);
      break;
    case TLS_EXT_COOKIE:
      cookie = rd_vec(&d, 2);
      if (!cookie.n)
        return tls_fail(t, TLS_ALERT_DECODE_ERROR);
      break;
    default:
      return tls_fail(t, TLS_ALERT_UNSUPPORTED_EXTENSION);
    }
    if (d.bad || d.n)
      return tls_fail(t, TLS_ALERT_DECODE_ERROR);
  }
  if (!tls13)
    return tls_fail(t, TLS_ALERT_PROTOCOL_VERSION);
  /* it must change something: a group we have, other than our share's */
  if ((!selected && !cookie.p) ||
      (selected && (!t->group || selected == t->group ||
                    !tls_group_allowed(t->cfg, selected))))
    return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);

  c->hash_peek(&t->transcript, message_hash + HS_HDR);
  tls_transcript_hrr(c, &t->transcript);
  c->hash_update(&t->transcript, m, mlen);
  if (selected)
    t->group = (uint16_t)selected;
  t->flags |= F_HRR;
  if (client_hello(t, cookie.p, cookie.n, message_hash, m, mlen) != 0)
    return tls_fail(t, TLS_ALERT_INTERNAL_ERROR);
  return 0;
}

/* Handshake Secret and traffic keys (RFC 8446 §7.1) from the (EC)DHE
 * secret @p shared (NULL for psk_ke) */
static void enter_handshake_keys(tls_conn_t *t, const uint8_t *shared) {
  const tls_crypto_t *c = t->cfg->crypto;
  uint8_t h[TLS_HASH_LEN];
  if (!(t->flags & F_PSK)) /* else t->secret holds the PSK's Early Secret */
    tls_early_secret(c, NULL, 0, t->secret);
  tls_next_secret(c, t->secret, shared, TLS_HASH_LEN);
  c->hash_peek(&t->transcript, h);
  tls_derive_secret(c, t->secret, "s hs traffic", h, t->rsec);
  tls_derive_secret(c, t->secret, "c hs traffic", h, t->wsec);
  tls_traffic_keys(c, t->rsec, &t->rkeys);
  tls_traffic_keys(c, t->wsec, &t->wkeys);
  t->flags |= F_RPROT | F_WPROT;
  t->step = ST_C_WAIT_EE;
}

/* RFC 8446 §4.1.3: the server's parameters; enter the handshake keys */
static int on_server_hello(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  const tls_crypto_t *c = t->cfg->crypto;
  rd_t r = rd_body(m, mlen), v, exts, share = {NULL, 0, 0};
  const uint8_t *random;
  uint32_t seen[2] = {0, 0};
  int tls13 = 0, psk = 0, alert;
  uint8_t shared[TLS_HASH_LEN];

  rd_uint(&r, 2); /* legacy_version */
  random = rd_take(&r, TLS_RANDOM_LEN);
  v = rd_vec(&r, 1); /* legacy_session_id_echo */
  if (r.bad)
    return tls_fail(t, TLS_ALERT_DECODE_ERROR);
  if (memcmp(random, tls_hrr_random, TLS_RANDOM_LEN) == 0)
    return on_hello_retry(t, m, mlen);
  if (v.n != t->sid_len || memcmp(v.p, t->sid, v.n) != 0)
    return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  if (rd_uint(&r, 2) != TLS_AES_128_GCM_SHA256 || rd_uint(&r, 1) != 0)
    return tls_fail(t, r.bad ? TLS_ALERT_DECODE_ERROR
                             : TLS_ALERT_ILLEGAL_PARAMETER);
  exts = rd_vec(&r, 2);
  if (r.bad || r.n)
    return tls_fail(t, TLS_ALERT_DECODE_ERROR);

  while (exts.n) {
    uint16_t type;
    rd_t d;
    if ((alert = tls_next_extension(&exts, seen, &type, &d)))
      return tls_fail(t, alert);
    switch (type) {
    case TLS_EXT_SUPPORTED_VERSIONS:
      if (rd_uint(&d, 2) != TLS_VERSION_13)
        return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
      tls13 = 1;
      break;
    case TLS_EXT_KEY_SHARE: /* the group we offered a share of */
      if (rd_uint(&d, 2) != t->group)
        return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
      share = rd_vec(&d, 2);
      break;
    case TLS_EXT_PRE_SHARED_KEY: /* the one identity we offered */
      if (!t->cfg->psk)
        return tls_fail(t, TLS_ALERT_UNSUPPORTED_EXTENSION);
      if (rd_uint(&d, 2) != 0)
        return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
      psk = 1;
      break;
    default: /* nothing else was offered for a ServerHello */
      return tls_fail(t, TLS_ALERT_UNSUPPORTED_EXTENSION);
    }
    if (d.bad || d.n)
      return tls_fail(t, TLS_ALERT_DECODE_ERROR);
  }
  if (!tls13) /* a TLS 1.2 (or older) server */
    return tls_fail(t, TLS_ALERT_PROTOCOL_VERSION);
  /* without a share: only the PSK alone, if psk_ke was offered */
  if (!share.p && !(psk && (t->cfg->psk_modes & TLS_PSK_KE)))
    return tls_fail(t, TLS_ALERT_MISSING_EXTENSION);
  if (share.p &&
      c->kx_shared(c->ctx, t->group, t->kx_priv, share.p, share.n, shared) != 0)
    return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  tls_wipe(t->kx_priv, sizeof(t->kx_priv));
  if (!share.p)
    t->group = 0;

  c->hash_update(&t->transcript, m, mlen);
  if (psk)
    t->flags |= F_PSK;
  enter_handshake_keys(t, share.p ? shared : NULL);
  tls_wipe(shared, sizeof(shared));
  return HS_KEYS;
}

/* Extensions we offered that the server may answer here: server_name
 * (empty), max_fragment_length (the code we asked for) and
 * supported_groups (its preference, for later) */
static int on_encrypted_extensions(tls_conn_t *t, const uint8_t *m,
                                   size_t mlen) {
  rd_t r = rd_body(m, mlen), exts = rd_vec(&r, 2);
  uint32_t seen[2] = {0, 0};
  int alert;
  if (r.bad || r.n)
    return tls_fail(t, TLS_ALERT_DECODE_ERROR);
  while (exts.n) {
    uint16_t type;
    rd_t d;
    if ((alert = tls_next_extension(&exts, seen, &type, &d)))
      return tls_fail(t, alert);
    if (type == TLS_EXT_SERVER_NAME && d.n == 0)
      continue;
    if (type == TLS_EXT_MAX_FRAGMENT_LENGTH && t->cfg->max_fragment) {
      if (d.n != 1 || d.p[0] != t->cfg->max_fragment) /* RFC 6066 §4 */
        return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
      t->max_frag = (uint16_t)(256u << d.p[0]);
      continue;
    }
    if (type != TLS_EXT_SUPPORTED_GROUPS)
      return tls_fail(t, TLS_ALERT_UNSUPPORTED_EXTENSION);
  }
  t->cfg->crypto->hash_update(&t->transcript, m, mlen);
  t->step = (t->flags & F_PSK) ? ST_C_WAIT_FIN : ST_C_WAIT_CERT;
  return 0;
}

/* The server wants our certificate; we have none and will say so */
static int on_certificate_request(tls_conn_t *t, const uint8_t *m,
                                  size_t mlen) {
  rd_t r = rd_body(m, mlen);
  rd_t context = rd_vec(&r, 1); /* empty in a handshake */
  rd_vec(&r, 2);                /* extensions */
  if (r.bad || r.n)
    return tls_fail(t, TLS_ALERT_DECODE_ERROR);
  if (context.n)
    return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
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
  rd_t r = rd_body(m, mlen), context, list;
  int alert;

  context = rd_vec(&r, 1);
  list = rd_vec(&r, 3);
  if (r.bad || r.n)
    return tls_fail(t, TLS_ALERT_DECODE_ERROR);
  if (context.n)
    return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  while (list.n) {
    rd_t data = rd_vec(&list, 3);
    rd_vec(&list, 2); /* CertificateEntry extensions */
    if (list.bad || data.n == 0)
      return tls_fail(t, TLS_ALERT_DECODE_ERROR);
    if (count == CHAIN_MAX || data.n > 0xFFFFu)
      return tls_fail(t, TLS_ALERT_BAD_CERTIFICATE);
    cert[count] = data.p;
    len[count++] = (uint16_t)data.n;
  }
  if (!count) /* §4.4.2.4 */
    return tls_fail(t, TLS_ALERT_DECODE_ERROR);
  if ((alert = c->verify_chain(c->ctx, cert, len, count, t->host)) != 0)
    return tls_fail(t, alert > 0 ? alert : TLS_ALERT_BAD_CERTIFICATE);
  c->hash_update(&t->transcript, m, mlen);
  t->leaf_off = (uint16_t)(cert[0] - t->rx);
  t->leaf_len = len[0];
  t->step = ST_C_WAIT_CV;
  return HS_KEEP;
}

/* RFC 8446 §4.4.3: the server holds the certificate's private key */
static int on_certificate_verify(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  const tls_crypto_t *c = t->cfg->crypto;
  uint8_t content[TLS_CV_CONTENT_LEN];
  rd_t r = rd_body(m, mlen), sig;
  uint16_t scheme = (uint16_t)rd_uint(&r, 2);

  sig = rd_vec(&r, 2);
  if (r.bad || r.n)
    return tls_fail(t, TLS_ALERT_DECODE_ERROR);
  if (scheme != TLS_SIG_ECDSA_SECP256R1_SHA256 &&
      scheme != TLS_SIG_RSA_PSS_RSAE_SHA256) /* not offered */
    return tls_fail(t, TLS_ALERT_ILLEGAL_PARAMETER);
  tls_cert_verify_content(t, content);
  if (c->verify(c->ctx, t->rx + t->leaf_off, t->leaf_len, scheme, content,
                sizeof(content), sig.p, sig.n) != 0)
    return tls_fail(t, TLS_ALERT_DECRYPT_ERROR);
  c->hash_update(&t->transcript, m, mlen);
  t->step = ST_C_WAIT_FIN;
  return HS_RELEASE;
}

/* The server's Finished: its application keys now, ours after our own
 * Finished (pump_client) */
static int on_server_finished(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  const tls_crypto_t *c = t->cfg->crypto;
  uint8_t h[TLS_HASH_LEN], mac[TLS_HASH_LEN], master[TLS_HASH_LEN];
  if (mlen != HS_HDR + TLS_HASH_LEN)
    return tls_fail(t, TLS_ALERT_DECODE_ERROR);
  c->hash_peek(&t->transcript, h);
  tls_finished_mac(c, t->rsec, h, mac);
  if (!tls_equal(mac, m + HS_HDR, TLS_HASH_LEN))
    return tls_fail(t, TLS_ALERT_DECRYPT_ERROR);
  c->hash_update(&t->transcript, m, mlen);
  c->hash_peek(&t->transcript, h);
  memcpy(master, t->secret, sizeof(master));
  tls_next_secret(c, master, NULL, 0);
  tls_derive_secret(c, master, "s ap traffic", h, t->rsec);
  tls_derive_secret(c, master, "c ap traffic", h, t->secret);
  tls_wipe(master, sizeof(master));
  tls_traffic_keys(c, t->rsec, &t->rkeys);
  t->flags &= (uint16_t)~F_CCS_OK;
  t->step = ST_C_SEND_FIN;
  return HS_KEYS;
}

/* Our flight after the server's Finished: an empty Certificate if one was
 * requested (§4.4.2), then Finished */
static int pump_client(tls_conn_t *t) {
  const tls_crypto_t *c = t->cfg->crypto;
  int send_cert = (t->flags & F_CERT_REQ) != 0;
  uint8_t *m, h[TLS_HASH_LEN];

  if (t->step != ST_C_SEND_FIN)
    return 0;
  if (!(m = tls_hs_begin(t, (send_cert ? HS_HDR + 4u : 0u) + HS_HDR +
                                TLS_HASH_LEN)))
    return 0;
  if (send_cert) {
    memset(m + HS_HDR, 0, 4); /* empty context, empty list */
    tls_hs_end(t, m, TLS_HS_CERTIFICATE, 4);
    m += HS_HDR + 4;
  }
  c->hash_peek(&t->transcript, h);
  tls_finished_mac(c, t->wsec, h, m + HS_HDR);
  tls_hs_end(t, m, TLS_HS_FINISHED, TLS_HASH_LEN);
  tls_rec_close(t);
  memcpy(t->wsec, t->secret, TLS_HASH_LEN);
  tls_wipe(t->secret, sizeof(t->secret));
  tls_traffic_keys(c, t->wsec, &t->wkeys);
  t->step = ST_DONE;
  t->state = TLS_STATE_CONNECTED;
  tls_notify(t, TLS_EVT_CONNECTED);
  return 0;
}

static int on_client_message(tls_conn_t *t, const uint8_t *m, size_t mlen) {
  uint8_t type = m[0];
  switch (t->step) {
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
  return tls_fail(t, TLS_ALERT_UNEXPECTED_MESSAGE);
}

const tls_role_t tls_client_role = {on_client_message, pump_client};

/* (EC)DHE unless the PSK is to be used alone; x25519 first */
static uint16_t first_group(const tls_config_t *cfg) {
  int dhe = !cfg->psk || !cfg->psk_modes || (cfg->psk_modes & TLS_PSK_DHE_KE);
  if (!dhe)
    return 0;
  return (tls_groups(cfg) & TLS_GROUPS_X25519) ? TLS_GROUP_X25519
                                               : TLS_GROUP_SECP256R1;
}

int tls_connect(tls_conn_t *t, const char *host) {
  const tls_config_t *cfg = t->cfg;
  const tls_crypto_t *c = cfg->crypto;

  if (t->state != TLS_STATE_IDLE)
    return -1;
  if (host && !ip_literal(host) && strlen(host) > 255)
    return -1;
  if (cfg->psk && (!cfg->psk_len || !cfg->psk_id || !cfg->psk_id_len))
    return -1;
  t->role = &tls_client_role;
  t->host = host;
  t->group = first_group(cfg);
  c->hash_init(&t->transcript);
  if (c->random(c->ctx, t->sid, TLS_RANDOM_LEN) != 0 ||
      client_hello(t, NULL, 0, NULL, NULL, 0) != 0)
    return -1;
  t->state = TLS_STATE_HANDSHAKE;
  t->step = ST_C_WAIT_SH;
  t->flags = F_CCS_OK; /* a server may send the dummy one anyway */
  return 0;
}
