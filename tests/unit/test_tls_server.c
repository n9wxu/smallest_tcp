/**
 * @file test_tls_server.c
 * @brief TLS 1.3 server handshake (RFC 8446 §4) against a scripted client.
 *
 * The client here is test code: it builds ClientHellos, reads the server's
 * flight and checks every message — ServerHello fields, EncryptedExtensions,
 * the Certificate bytes, the CertificateVerify signature (Mbed TLS verify),
 * the Finished MAC — then sends its Finished and application data.  With a
 * backend whose random numbers and key share are the RFC 8448 server's, the
 * ServerHello is the RFC's byte for byte.
 */

#include "test_main.h"
#include "tls.h"
#include "tls_crypto_mbedtls.h"
#include "tls_rfc8448.h"
#include "tls_test_data.h"
#include <string.h>

static tls_mbedtls_t be;
static tls_crypto_t c;     /* Mbed TLS */
static tls_crypto_t fixed; /* .. with the RFC 8448 server's randomness */
static mbedtls_pk_context ec_key, rsa_key;

static const uint8_t *const ec_chain[1] = {server_der};
static const uint16_t ec_chain_len[1] = {sizeof(server_der)};
static const uint8_t *const rsa_chain[1] = {rsa_der};
static const uint16_t rsa_chain_len[1] = {sizeof(rsa_der)};

static tls_config_t cfg_ec, cfg_rsa, cfg_fixed;

static uint8_t srv_rx[4096], srv_tx[4096];
static uint8_t out[16384]; /* what the server sent */
static size_t out_len;
static uint8_t evts;

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x))                                                                  \
      return __LINE__;                                                         \
  } while (0)

static void put16(uint8_t *p, size_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)v;
}
static void put24(uint8_t *p, size_t v) {
  p[0] = (uint8_t)(v >> 16);
  put16(p + 1, v);
}
static size_t be16(const uint8_t *p) { return ((size_t)p[0] << 8) | p[1]; }
static size_t be24(const uint8_t *p) {
  return ((size_t)p[0] << 16) | be16(p + 1);
}

static int fixed_random(void *ctx, uint8_t *o, size_t len) {
  if (len == 32) { /* ServerHello.random */
    memcpy(o, r3_server_hello + 6, 32);
    return 0;
  }
  return c.random(ctx, o, len);
}

static int fixed_keygen(void *ctx, uint16_t group, uint8_t *priv,
                        uint8_t *pub, size_t *pub_len) {
  if (group != TLS_GROUP_X25519)
    return c.kx_keygen(ctx, group, priv, pub, pub_len);
  memcpy(priv, r3_s_x25519_priv, 32);
  memcpy(pub, r3_s_x25519_pub, 32);
  *pub_len = 32;
  return 0;
}

static void on_evt(tls_conn_t *t, uint8_t e) {
  (void)t;
  evts |= e;
}

/* ── Server side ───────────────────────────────────────────────────── */

static int server_start(tls_conn_t *s, const tls_config_t *cfg,
                        size_t tx_cap) {
  if (tls_init(s, cfg, srv_rx, sizeof(srv_rx), srv_tx, tx_cap) != 0)
    return -1;
  s->on_event = on_evt;
  evts = 0;
  out_len = 0;
  return tls_accept(s);
}

/* Collect everything the server has to send */
static size_t drain(tls_conn_t *s) {
  size_t before = out_len, n;
  const uint8_t *p;
  while ((n = tls_tx_pending(s, &p)) > 0) {
    memcpy(out + out_len, p, n);
    out_len += n;
    tls_tx_done(s, n);
  }
  return out_len - before;
}

/* ── The scripted client ───────────────────────────────────────────── */

typedef struct {
  uint8_t sid[33];
  uint8_t sid_len;
  uint16_t suite;
  uint8_t comp[2], comp_len;
  uint16_t versions[2];
  int nversions; /* 0: no supported_versions */
  uint16_t groups[3];
  int ngroups;
  uint16_t sigs[3];
  int nsigs;
  uint16_t shares[2]; /* one key share per group */
  int nshares;
  int no_key_share;
  int zero_share;  /* an all-zero x25519 share */
  int short_share; /* a 31-byte x25519 share */
  int dup_groups;  /* supported_groups twice */
  int odd_suites;  /* cipher_suites of odd length */
  int ks_overrun;  /* a key share running past its list */
  int sv_overrun;  /* supported_versions running past its extension */
  int trailing;    /* a byte after the extensions */
} ch_opt_t;

typedef struct {
  uint8_t p256_priv[32], p256_pub[65];
  tls_hash_t th;
  uint16_t group;
  uint8_t sid[33], sid_len;
  const tls_config_t *cfg; /* what the server should present */
  uint8_t hs[32], c_hs[32], s_hs[32], c_ap[32], s_ap[32];
  tls_keys_t rd, wr;
  int ccs_seen, records;
  uint8_t msgs[4096];
  size_t mlen;
} peer_t;

static peer_t peer;

static void ch_default(ch_opt_t *o) {
  memset(o, 0, sizeof(*o));
  o->suite = TLS_AES_128_GCM_SHA256;
  o->comp_len = 1;
  o->versions[0] = 0x0304;
  o->nversions = 1;
  o->groups[0] = TLS_GROUP_X25519;
  o->groups[1] = TLS_GROUP_SECP256R1;
  o->ngroups = 2;
  o->sigs[0] = TLS_SIG_ECDSA_SECP256R1_SHA256;
  o->sigs[1] = TLS_SIG_RSA_PSS_RSAE_SHA256;
  o->nsigs = 2;
  o->shares[0] = TLS_GROUP_X25519;
  o->nshares = 1;
}

static void peer_init(peer_t *p, const tls_config_t *cfg) {
  size_t n;
  memset(p, 0, sizeof(*p));
  p->cfg = cfg;
  c.kx_keygen(c.ctx, TLS_GROUP_SECP256R1, p->p256_priv, p->p256_pub, &n);
  c.hash_init(&p->th);
}

static uint8_t *ext_begin(uint8_t *q, uint16_t type) {
  put16(q, type);
  return q + 4;
}
static uint8_t *ext_end(uint8_t *start, uint8_t *q) {
  put16(start + 2, (size_t)(q - start - 4));
  return q;
}

/* A ClientHello message (header included) */
static size_t build_ch(peer_t *p, const ch_opt_t *o, uint8_t *m) {
  uint8_t *q = m + 4, *ext, *e;
  int i, rep;
  put16(q, 0x0303);
  q += 2;
  memset(q, 0x5a, 32);
  q += 32;
  *q++ = o->sid_len;
  memcpy(q, o->sid, o->sid_len);
  q += o->sid_len;
  memcpy(p->sid, o->sid, o->sid_len);
  p->sid_len = o->sid_len;
  put16(q, o->odd_suites ? 5 : 4);
  put16(q + 2, 0x1302); /* TLS_AES_256_GCM_SHA384: not ours */
  put16(q + 4, o->suite);
  q += 6;
  if (o->odd_suites)
    *q++ = 0x13;
  *q++ = o->comp_len;
  memcpy(q, o->comp, o->comp_len);
  q += o->comp_len;
  ext = q;
  q += 2;
  e = q; /* GREASE (RFC 8701): an unknown, empty extension */
  q = ext_end(e, ext_begin(q, 0x0a0a));
  if (o->nversions) {
    e = q;
    q = ext_begin(q, TLS_EXT_SUPPORTED_VERSIONS);
    *q++ = (uint8_t)(2 * o->nversions + (o->sv_overrun ? 2 : 0));
    for (i = 0; i < o->nversions; i++, q += 2)
      put16(q, o->versions[i]);
    q = ext_end(e, q);
  }
  for (rep = 0; rep < (o->dup_groups ? 2 : 1) && o->ngroups; rep++) {
    e = q;
    q = ext_begin(q, TLS_EXT_SUPPORTED_GROUPS);
    put16(q, (size_t)(2 * o->ngroups));
    q += 2;
    for (i = 0; i < o->ngroups; i++, q += 2)
      put16(q, o->groups[i]);
    q = ext_end(e, q);
  }
  if (o->nsigs) {
    e = q;
    q = ext_begin(q, TLS_EXT_SIGNATURE_ALGORITHMS);
    put16(q, (size_t)(2 * o->nsigs));
    q += 2;
    for (i = 0; i < o->nsigs; i++, q += 2)
      put16(q, o->sigs[i]);
    q = ext_end(e, q);
  }
  if (!o->no_key_share) {
    uint8_t *list;
    e = q;
    q = ext_begin(q, TLS_EXT_KEY_SHARE);
    list = q;
    q += 2;
    for (i = 0; i < o->nshares; i++) {
      put16(q, o->shares[i]);
      if (o->shares[i] == TLS_GROUP_X25519) {
        size_t n = o->short_share ? 31 : 32;
        put16(q + 2, n + (o->ks_overrun ? 1 : 0));
        if (o->zero_share)
          memset(q + 4, 0, n);
        else
          memcpy(q + 4, r3_c_x25519_pub, n);
        q += 4 + n;
      } else if (o->shares[i] == TLS_GROUP_SECP256R1) {
        put16(q + 2, 65);
        memcpy(q + 4, p->p256_pub, 65);
        q += 4 + 65;
      } else { /* a group we do not do: some bytes */
        put16(q + 2, 49);
        memset(q + 4, 0x04, 49);
        q += 4 + 49;
      }
    }
    put16(list, (size_t)(q - list - 2));
    q = ext_end(e, q);
  }
  put16(ext, (size_t)(q - ext - 2));
  if (o->trailing)
    *q++ = 0;
  m[0] = TLS_HS_CLIENT_HELLO;
  put24(m + 1, (size_t)(q - m - 4));
  return (size_t)(q - m);
}

static size_t plain_record(uint8_t type, const uint8_t *msg, size_t len,
                           uint8_t *rec) {
  rec[0] = type;
  rec[1] = 3;
  rec[2] = 3;
  put16(rec + 3, len);
  memmove(rec + 5, msg, len);
  return len + 5;
}

/* Send ClientHello @p m (message) in one record */
static size_t send_ch(tls_conn_t *s, peer_t *p, const uint8_t *m, size_t n) {
  static uint8_t rec[2048];
  size_t rl = plain_record(TLS_CT_HANDSHAKE, m, n, rec);
  c.hash_update(&p->th, m, n);
  return tls_input(s, rec, rl);
}

/* The Certificate message the server should send */
static size_t cert_msg(const tls_config_t *cfg, uint8_t *m) {
  size_t n = 8, i;
  m[0] = TLS_HS_CERTIFICATE;
  m[4] = 0;
  for (i = 0; i < cfg->cert_count; i++) {
    put24(m + n, cfg->cert_len[i]);
    memcpy(m + n + 3, cfg->cert[i], cfg->cert_len[i]);
    n += 3 + cfg->cert_len[i];
    put16(m + n, 0);
    n += 2;
  }
  put24(m + 1, n - 4);
  put24(m + 5, n - 8);
  return n;
}

/* Read and check the ServerHello (and a dummy CCS) at the start of
 * out[]; derive the handshake keys.  *off: the bytes read. */
static int peer_read_sh(peer_t *p, size_t *off) {
  const uint8_t *sh, *q, *key = NULL;
  size_t rl, sh_len, elen, klen = 0;
  uint8_t z[32], h[32];
  int sv = 0;

  /* ServerHello, in plaintext */
  CHECK(out_len >= 5 && out[0] == TLS_CT_HANDSHAKE && out[1] == 3 &&
        out[2] == 3);
  rl = 5 + be16(out + 3);
  CHECK(rl <= out_len);
  sh = out + 5;
  sh_len = rl - 5;
  CHECK(sh[0] == TLS_HS_SERVER_HELLO && be24(sh + 1) == sh_len - 4);
  q = sh + 4;
  CHECK(be16(q) == 0x0303);
  q += 2 + 32;
  CHECK(q[0] == p->sid_len && memcmp(q + 1, p->sid, p->sid_len) == 0);
  q += 1 + p->sid_len;
  CHECK(be16(q) == TLS_AES_128_GCM_SHA256 && q[2] == 0);
  q += 3;
  elen = be16(q);
  q += 2;
  CHECK(q + elen == sh + sh_len);
  while (elen) {
    size_t type16 = be16(q), l = be16(q + 2);
    CHECK(4 + l <= elen);
    if (type16 == TLS_EXT_KEY_SHARE) {
      p->group = (uint16_t)be16(q + 4);
      klen = be16(q + 6);
      key = q + 8;
      CHECK(klen == l - 4);
    } else if (type16 == TLS_EXT_SUPPORTED_VERSIONS) {
      CHECK(l == 2 && be16(q + 4) == 0x0304);
      sv = 1;
    } else {
      CHECK(0); /* nothing else belongs in a ServerHello here */
    }
    q += 4 + l;
    elen -= 4 + l;
  }
  CHECK(sv && key);
  CHECK(c.kx_shared(c.ctx, p->group,
                    p->group == TLS_GROUP_X25519 ? r3_c_x25519_priv
                                                 : p->p256_priv,
                    key, klen, z) == 0);
  c.hash_update(&p->th, sh, sh_len);
  tls_early_secret(&c, NULL, 0, p->hs);
  tls_next_secret(&c, p->hs, z, 32);
  c.hash_peek(&p->th, h);
  tls_derive_secret(&c, p->hs, "c hs traffic", h, p->c_hs);
  tls_derive_secret(&c, p->hs, "s hs traffic", h, p->s_hs);
  tls_traffic_keys(&c, p->s_hs, &p->rd);
  tls_traffic_keys(&c, p->c_hs, &p->wr);
  *off = rl;

  /* The dummy change_cipher_spec, for a client with a session id */
  if (*off < out_len && out[*off] == TLS_CT_CHANGE_CIPHER_SPEC) {
    CHECK(*off + 6 <= out_len &&
          memcmp(out + *off, "\x14\x03\x03\x00\x01\x01", 6) == 0);
    p->ccs_seen = 1;
    *off += 6;
  }
  return 0;
}

/* Read and check the server's first flight in out[] */
static int peer_read_flight(peer_t *p) {
  static uint8_t buf[4096], want[2048];
  const uint8_t *q;
  size_t off, rl, m;
  uint8_t z[32], h[32], ms[32], type;
  int r;

  if ((r = peer_read_sh(p, &off)) != 0)
    return r;

  /* The rest under the server's handshake keys */
  p->mlen = 0;
  p->records = 0;
  while (off < out_len) {
    CHECK(off + 5 <= out_len);
    rl = 5 + be16(out + off + 3);
    CHECK(off + rl <= out_len);
    memcpy(buf, out + off, rl);
    r = tls_record_open(&c, &p->rd, buf, rl, &type);
    CHECK(r > 0 && type == TLS_CT_HANDSHAKE);
    memcpy(p->msgs + p->mlen, buf + 5, (size_t)r);
    p->mlen += (size_t)r;
    p->records++;
    off += rl;
  }

  /* EncryptedExtensions: none */
  q = p->msgs;
  CHECK(p->mlen >= 6 &&
        memcmp(q, "\x08\x00\x00\x02\x00\x00", 6) == 0);
  c.hash_update(&p->th, q, 6);
  q += 6;
  /* Certificate: exactly the configured chain */
  m = cert_msg(p->cfg, want);
  CHECK((size_t)(q - p->msgs) + m <= p->mlen && memcmp(q, want, m) == 0);
  c.hash_update(&p->th, q, m);
  q += m;
  /* CertificateVerify: the configured scheme, a valid signature */
  {
    uint8_t content[130];
    size_t sl;
    CHECK(q[0] == TLS_HS_CERTIFICATE_VERIFY);
    m = 4 + be24(q + 1);
    CHECK(be16(q + 4) == p->cfg->sig_scheme);
    sl = be16(q + 6);
    CHECK(8 + sl == m);
    memset(content, 0x20, 64);
    memcpy(content + 64, "TLS 1.3, server CertificateVerify", 34);
    c.hash_peek(&p->th, content + 98);
    CHECK(c.verify(c.ctx, p->cfg->cert[0], p->cfg->cert_len[0],
                   p->cfg->sig_scheme, content, sizeof(content), q + 8,
                   sl) == 0);
    c.hash_update(&p->th, q, m);
    q += m;
  }
  /* Finished */
  CHECK(memcmp(q, "\x14\x00\x00\x20", 4) == 0);
  c.hash_peek(&p->th, h);
  tls_finished_mac(&c, p->s_hs, h, z);
  CHECK(memcmp(q + 4, z, 32) == 0);
  c.hash_update(&p->th, q, 36);
  q += 36;
  CHECK((size_t)(q - p->msgs) == p->mlen);

  /* Application secrets */
  c.hash_peek(&p->th, h);
  memcpy(ms, p->hs, 32);
  tls_next_secret(&c, ms, NULL, 0);
  tls_derive_secret(&c, ms, "c ap traffic", h, p->c_ap);
  tls_derive_secret(&c, ms, "s ap traffic", h, p->s_ap);
  tls_traffic_keys(&c, p->s_ap, &p->rd);
  out_len = 0;
  return 0;
}

/* The client's Finished record; the client then uses its application keys */
static size_t peer_finished(peer_t *p, uint8_t *rec) {
  uint8_t h[32];
  size_t n;
  c.hash_peek(&p->th, h);
  memcpy(rec + 5, "\x14\x00\x00\x20", 4);
  tls_finished_mac(&c, p->c_hs, h, rec + 9);
  c.hash_update(&p->th, rec + 5, 36);
  n = tls_record_seal(&c, &p->wr, TLS_CT_HANDSHAKE, rec, 36);
  tls_traffic_keys(&c, p->c_ap, &p->wr);
  return n;
}

static size_t peer_seal(peer_t *p, uint8_t type, const void *data,
                        size_t len, uint8_t *rec) {
  memcpy(rec + 5, data, len);
  return tls_record_seal(&c, &p->wr, type, rec, len);
}

/* Open the next server record in out[] at *off */
static int peer_open(peer_t *p, size_t *off, uint8_t *type, uint8_t *buf) {
  size_t rl;
  if (*off + 5 > out_len)
    return -1000;
  rl = 5 + be16(out + *off + 3);
  if (*off + rl > out_len)
    return -1001;
  memcpy(buf, out + *off, rl);
  *off += rl;
  return tls_record_open(&c, &p->rd, buf, rl, type);
}

/* Full handshake with ClientHello options @p o */
static int handshake(tls_conn_t *s, const tls_config_t *cfg,
                     const ch_opt_t *o, size_t tx_cap) {
  static uint8_t m[2048], rec[256];
  size_t n;
  int r;
  CHECK(server_start(s, cfg, tx_cap) == 0);
  peer_init(&peer, cfg);
  n = build_ch(&peer, o, m);
  CHECK(send_ch(s, &peer, m, n) == n + 5);
  CHECK(tls_state(s) == TLS_STATE_HANDSHAKE);
  drain(s);
  if ((r = peer_read_flight(&peer)) != 0)
    return 10000 + r;
  CHECK(tls_state(s) == TLS_STATE_HANDSHAKE && evts == 0);
  n = peer_finished(&peer, rec);
  CHECK(tls_input(s, rec, n) == n);
  CHECK(tls_state(s) == TLS_STATE_CONNECTED && evts == TLS_EVT_CONNECTED);
  CHECK(drain(s) == 0);
  return 0;
}

/* ClientHello with options @p o; the server must answer with fatal alert
 * @p alert in plaintext, as its only output */
static int refused(const ch_opt_t *o, uint8_t alert) {
  static uint8_t m[2048];
  tls_conn_t s;
  uint8_t want[7] = {TLS_CT_ALERT, 3, 3, 0, 2, 2, 0};
  size_t n;
  want[6] = alert;
  CHECK(server_start(&s, &cfg_ec, sizeof(srv_tx)) == 0);
  peer_init(&peer, &cfg_ec);
  n = build_ch(&peer, o, m);
  send_ch(&s, &peer, m, n);
  CHECK(tls_state(&s) == TLS_STATE_ERROR && s.alert == alert);
  CHECK(evts == TLS_EVT_ERROR);
  CHECK(drain(&s) == 7 && memcmp(out, want, 7) == 0);
  return 0;
}

/* After a handshake: the server's next output must be fatal alert
 * @p alert under the application keys */
/* After a fatal error no key material is left in the connection */
static int wiped(const tls_conn_t *s) {
  static const uint8_t zero[sizeof(tls_keys_t)];
  return memcmp(s->secret, zero, 32) == 0 && memcmp(s->rsec, zero, 32) == 0 &&
         memcmp(s->wsec, zero, 32) == 0 &&
         memcmp(&s->rkeys, zero, sizeof(tls_keys_t)) == 0 &&
         memcmp(&s->wkeys, zero, sizeof(tls_keys_t)) == 0;
}

static int prot_alert(tls_conn_t *s, uint8_t alert) {
  uint8_t buf[64], type;
  size_t off = 0;
  CHECK(tls_state(s) == TLS_STATE_ERROR && s->alert == alert);
  CHECK(wiped(s));
  CHECK(evts & TLS_EVT_ERROR);
  out_len = 0;
  drain(s);
  CHECK(peer_open(&peer, &off, &type, buf) == 2);
  CHECK(type == TLS_CT_ALERT && buf[5] == 2 && buf[6] == alert);
  CHECK(off == out_len);
  return 0;
}

/* ══ RFC 8448 ═════════════════════════════════════════════════════ */

TEST(test_rfc8448_server_hello) {
  /* The RFC's ClientHello, our randomness and key share set to the RFC
   * server's: our ServerHello record is the RFC's */
  tls_conn_t s;
  tls_keys_t k;
  uint8_t buf[2048], type;
  size_t off;
  ASSERT_EQ(server_start(&s, &cfg_fixed, sizeof(srv_tx)), 0);
  ASSERT_EQ(tls_input(&s, r3_ch_record, sizeof(r3_ch_record)),
            sizeof(r3_ch_record));
  ASSERT_EQ(tls_state(&s), TLS_STATE_HANDSHAKE);
  drain(&s);
  ASSERT_TRUE(out_len > sizeof(r3_sh_record));
  ASSERT_MEM_EQ(out, r3_sh_record, sizeof(r3_sh_record));
  /* .. so the rest opens with the RFC's server handshake keys */
  memcpy(k.key, r3_s_hs_key, 16);
  memcpy(k.iv, r3_s_hs_iv, 12);
  k.seq = 0;
  off = sizeof(r3_sh_record);
  memcpy(buf, out + off, out_len - off);
  ASSERT_TRUE(tls_record_open(&c, &k, buf, out_len - off, &type) > 0);
  ASSERT_EQ(type, TLS_CT_HANDSHAKE);
  ASSERT_MEM_EQ(buf + 5, "\x08\x00\x00\x02\x00\x00", 6);
}

TEST(test_rfc8448_client_hello_full_handshake) {
  /* The RFC's ClientHello (GREASE-free, lots of extensions we ignore)
   * through to application data */
  tls_conn_t s;
  uint8_t rec[256], buf[256], type;
  size_t n, off = 0;
  ASSERT_EQ(server_start(&s, &cfg_ec, sizeof(srv_tx)), 0);
  peer_init(&peer, &cfg_ec);
  c.hash_update(&peer.th, r3_client_hello, sizeof(r3_client_hello));
  ASSERT_EQ(tls_input(&s, r3_ch_record, sizeof(r3_ch_record)),
            sizeof(r3_ch_record));
  drain(&s);
  ASSERT_EQ(peer_read_flight(&peer), 0);
  ASSERT_EQ(peer.ccs_seen, 0); /* no session id: no dummy CCS */
  n = peer_finished(&peer, rec);
  ASSERT_EQ(tls_input(&s, rec, n), n);
  ASSERT_EQ(tls_state(&s), TLS_STATE_CONNECTED);
  /* data both ways */
  n = peer_seal(&peer, TLS_CT_APPLICATION_DATA, "ping", 4, rec);
  ASSERT_EQ(tls_input(&s, rec, n), n);
  ASSERT_EQ(tls_read(&s, buf, sizeof(buf)), 4);
  ASSERT_MEM_EQ(buf, "ping", 4);
  ASSERT_EQ(tls_write(&s, (const uint8_t *)"pong", 4), 4);
  drain(&s);
  ASSERT_EQ(peer_open(&peer, &off, &type, buf), 4);
  ASSERT_EQ(type, TLS_CT_APPLICATION_DATA);
  ASSERT_MEM_EQ(buf + 5, "pong", 4);
}

/* ══ Handshakes ═══════════════════════════════════════════════════ */

TEST(test_handshake_ecdsa) {
  tls_conn_t s;
  ch_opt_t o;
  ch_default(&o);
  ASSERT_EQ(handshake(&s, &cfg_ec, &o, sizeof(srv_tx)), 0);
  ASSERT_EQ(peer.group, TLS_GROUP_X25519);
  ASSERT_EQ(peer.ccs_seen, 0);
  ASSERT_EQ(peer.records, 1); /* EE .. Finished in one record */
}

TEST(test_handshake_rsa_pss) {
  tls_conn_t s;
  ch_opt_t o;
  ch_default(&o);
  ASSERT_EQ(handshake(&s, &cfg_rsa, &o, sizeof(srv_tx)), 0);
}

TEST(test_handshake_p256) {
  tls_conn_t s;
  ch_opt_t o;
  ch_default(&o);
  o.groups[0] = TLS_GROUP_SECP256R1;
  o.ngroups = 1;
  o.shares[0] = TLS_GROUP_SECP256R1;
  ASSERT_EQ(handshake(&s, &cfg_ec, &o, sizeof(srv_tx)), 0);
  ASSERT_EQ(peer.group, TLS_GROUP_SECP256R1);
  ASSERT_EQ(s.group, TLS_GROUP_SECP256R1);
}

TEST(test_prefers_x25519) {
  /* Shares for an unknown group, P-256 and x25519: x25519 wins */
  tls_conn_t s;
  ch_opt_t o;
  ch_default(&o);
  o.shares[0] = TLS_GROUP_SECP256R1;
  o.shares[1] = TLS_GROUP_X25519;
  o.nshares = 2;
  ASSERT_EQ(handshake(&s, &cfg_ec, &o, sizeof(srv_tx)), 0);
  ASSERT_EQ(peer.group, TLS_GROUP_X25519);
}

TEST(test_skips_unknown_share) {
  tls_conn_t s;
  ch_opt_t o;
  ch_default(&o);
  o.shares[0] = 0x0018; /* secp384r1 */
  o.shares[1] = TLS_GROUP_X25519;
  o.nshares = 2;
  ASSERT_EQ(handshake(&s, &cfg_ec, &o, sizeof(srv_tx)), 0);
  ASSERT_EQ(peer.group, TLS_GROUP_X25519);
}

TEST(test_compat_mode_ccs) {
  /* A session id: echoed, then a dummy change_cipher_spec each way */
  tls_conn_t s;
  static uint8_t m[2048], rec[256];
  ch_opt_t o;
  size_t n;
  ch_default(&o);
  o.sid_len = 32;
  memset(o.sid, 0xC5, 32);
  ASSERT_EQ(server_start(&s, &cfg_ec, sizeof(srv_tx)), 0);
  peer_init(&peer, &cfg_ec);
  n = build_ch(&peer, &o, m);
  send_ch(&s, &peer, m, n);
  drain(&s);
  ASSERT_EQ(peer_read_flight(&peer), 0);
  ASSERT_EQ(peer.ccs_seen, 1);
  ASSERT_EQ(tls_input(&s, (const uint8_t *)"\x14\x03\x03\x00\x01\x01", 6),
            6);
  ASSERT_EQ(tls_state(&s), TLS_STATE_HANDSHAKE);
  n = peer_finished(&peer, rec);
  ASSERT_EQ(tls_input(&s, rec, n), n);
  ASSERT_EQ(tls_state(&s), TLS_STATE_CONNECTED);
}

TEST(test_fragmented_client_hello) {
  /* ClientHello over two records, fed one byte at a time */
  tls_conn_t s;
  static uint8_t m[2048], stream[2100], rec[256];
  ch_opt_t o;
  size_t n, a, i, sl;
  ch_default(&o);
  ASSERT_EQ(server_start(&s, &cfg_ec, sizeof(srv_tx)), 0);
  peer_init(&peer, &cfg_ec);
  n = build_ch(&peer, &o, m);
  c.hash_update(&peer.th, m, n);
  a = 50;
  sl = plain_record(TLS_CT_HANDSHAKE, m, a, stream);
  sl += plain_record(TLS_CT_HANDSHAKE, m + a, n - a, stream + sl);
  for (i = 0; i < sl; i++)
    ASSERT_EQ(tls_input(&s, stream + i, 1), 1);
  drain(&s);
  ASSERT_EQ(peer_read_flight(&peer), 0);
  n = peer_finished(&peer, rec);
  for (i = 0; i < n; i++)
    ASSERT_EQ(tls_input(&s, rec + i, 1), 1);
  ASSERT_EQ(tls_state(&s), TLS_STATE_CONNECTED);
}

TEST(test_small_tx_buffer) {
  /* 600 bytes: the flight leaves in several records as tx drains */
  tls_conn_t s;
  ch_opt_t o;
  ch_default(&o);
  ASSERT_EQ(handshake(&s, &cfg_ec, &o, 600), 0);
  ASSERT_TRUE(peer.records >= 3);
}

TEST(test_tx_too_small_for_certificate) {
  tls_conn_t s;
  static uint8_t m[2048];
  ch_opt_t o;
  size_t n;
  ch_default(&o);
  ASSERT_EQ(server_start(&s, &cfg_ec, 300), 0);
  peer_init(&peer, &cfg_ec);
  n = build_ch(&peer, &o, m);
  send_ch(&s, &peer, m, n);
  drain(&s);
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_INTERNAL_ERROR);
}

/* ══ ClientHellos refused ═════════════════════════════════════════ */

TEST(test_refuse_no_supported_versions) {
  /* REQ-TLS-001: a TLS 1.2 ClientHello */
  ch_opt_t o;
  ch_default(&o);
  o.nversions = 0;
  ASSERT_EQ(refused(&o, TLS_ALERT_PROTOCOL_VERSION), 0);
}

TEST(test_refuse_tls12_only) {
  ch_opt_t o;
  ch_default(&o);
  o.versions[0] = 0x0303;
  ASSERT_EQ(refused(&o, TLS_ALERT_PROTOCOL_VERSION), 0);
}

TEST(test_refuse_no_common_suite) {
  ch_opt_t o;
  ch_default(&o);
  o.suite = 0x1303; /* ChaCha20-Poly1305 only (with AES-256) */
  ASSERT_EQ(refused(&o, TLS_ALERT_HANDSHAKE_FAILURE), 0);
}

TEST(test_refuse_compression) {
  ch_opt_t o;
  ch_default(&o);
  o.comp_len = 2;
  o.comp[0] = 1; /* DEFLATE */
  ASSERT_EQ(refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
}

TEST(test_refuse_missing_key_share) {
  ch_opt_t o;
  ch_default(&o);
  o.no_key_share = 1;
  ASSERT_EQ(refused(&o, TLS_ALERT_MISSING_EXTENSION), 0);
}

TEST(test_refuse_missing_groups) {
  ch_opt_t o;
  ch_default(&o);
  o.ngroups = 0;
  ASSERT_EQ(refused(&o, TLS_ALERT_MISSING_EXTENSION), 0);
}

TEST(test_refuse_missing_signature_algorithms) {
  ch_opt_t o;
  ch_default(&o);
  o.nsigs = 0;
  ASSERT_EQ(refused(&o, TLS_ALERT_MISSING_EXTENSION), 0);
}

TEST(test_refuse_no_common_group) {
  ch_opt_t o;
  ch_default(&o);
  o.groups[0] = 0x0018;
  o.ngroups = 1;
  o.shares[0] = 0x0018;
  ASSERT_EQ(refused(&o, TLS_ALERT_HANDSHAKE_FAILURE), 0);
}

TEST(test_refuse_no_common_signature) {
  /* ECDSA certificate, client takes RSA-PSS only */
  ch_opt_t o;
  ch_default(&o);
  o.sigs[0] = TLS_SIG_RSA_PSS_RSAE_SHA256;
  o.nsigs = 1;
  ASSERT_EQ(refused(&o, TLS_ALERT_HANDSHAKE_FAILURE), 0);
}

TEST(test_refuse_duplicate_extension) {
  ch_opt_t o;
  ch_default(&o);
  o.dup_groups = 1;
  ASSERT_EQ(refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
}

TEST(test_refuse_zero_share) {
  /* x25519 of an all-zero point is zero: rejected */
  ch_opt_t o;
  ch_default(&o);
  o.zero_share = 1;
  ASSERT_EQ(refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
}

TEST(test_refuse_short_share) {
  ch_opt_t o;
  ch_default(&o);
  o.short_share = 1;
  ASSERT_EQ(refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
}

TEST(test_refuse_truncated_client_hello) {
  static uint8_t m[2048];
  tls_conn_t s;
  ch_opt_t o;
  size_t n;
  ch_default(&o);
  ASSERT_EQ(server_start(&s, &cfg_ec, sizeof(srv_tx)), 0);
  peer_init(&peer, &cfg_ec);
  n = build_ch(&peer, &o, m) - 1; /* the last byte gone .. */
  put24(m + 1, n - 4);            /* .. and the length to match */
  send_ch(&s, &peer, m, n);
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_DECODE_ERROR);
}

TEST(test_refuse_long_session_id) {
  static uint8_t m[2048];
  tls_conn_t s;
  ch_opt_t o;
  size_t n;
  ch_default(&o);
  o.sid_len = 32;
  ASSERT_EQ(server_start(&s, &cfg_ec, sizeof(srv_tx)), 0);
  peer_init(&peer, &cfg_ec);
  n = build_ch(&peer, &o, m);
  m[4 + 2 + 32] = 33; /* legacy_session_id<0..32> */
  send_ch(&s, &peer, m, n);
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_DECODE_ERROR);
}

TEST(test_refuse_wrong_first_message) {
  tls_conn_t s;
  uint8_t rec[64];
  size_t n;
  ASSERT_EQ(server_start(&s, &cfg_ec, sizeof(srv_tx)), 0);
  memset(rec, 0, sizeof(rec));
  n = plain_record(TLS_CT_HANDSHAKE,
                   (const uint8_t *)"\x14\x00\x00\x20"
                                    "0123456789abcdef0123456789abcdef",
                   36, rec);
  tls_input(&s, rec, n);
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(test_refuse_ccs_before_client_hello) {
  tls_conn_t s;
  ASSERT_EQ(server_start(&s, &cfg_ec, sizeof(srv_tx)), 0);
  tls_input(&s, (const uint8_t *)"\x14\x03\x03\x00\x01\x01", 6);
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(test_refuse_unknown_record_type) {
  tls_conn_t s;
  ASSERT_EQ(server_start(&s, &cfg_ec, sizeof(srv_tx)), 0);
  tls_input(&s, (const uint8_t *)"\x18\x03\x03\x00\x01\x01", 6);
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_UNEXPECTED_MESSAGE);
  /* below the four types too, on the header alone */
  ASSERT_EQ(server_start(&s, &cfg_ec, sizeof(srv_tx)), 0);
  tls_input(&s, (const uint8_t *)"\x13\x03\x03\x08\x00", 5);
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(test_refuse_bad_header_at_once) {
  /* Not TLS ("GET /" reads as a 12 kB record of type 0x47): refused on
   * the header, not after waiting for a body that never comes */
  tls_conn_t s;
  ASSERT_EQ(server_start(&s, &cfg_ec, sizeof(srv_tx)), 0);
  tls_input(&s, (const uint8_t *)"GET / HTTP/1.0\r\n\r\n", 18);
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_UNEXPECTED_MESSAGE);
  ASSERT_EQ(drain(&s), 7);
  ASSERT_MEM_EQ(out, "\x15\x03\x03\x00\x02\x02\x0a", 7);
}

TEST(test_refuse_oversize_header_at_once) {
  /* A plaintext record over 2^14, a protected one over 2^14 + 256: the
   * header alone is enough */
  tls_conn_t s;
  ASSERT_EQ(server_start(&s, &cfg_ec, sizeof(srv_tx)), 0);
  tls_input(&s, (const uint8_t *)"\x16\x03\x01\x40\x01", 5);
  ASSERT_EQ(s.alert, TLS_ALERT_RECORD_OVERFLOW);
  ASSERT_EQ(server_start(&s, &cfg_ec, sizeof(srv_tx)), 0);
  tls_input(&s, (const uint8_t *)"\x17\x03\x03\x41\x01", 5);
  ASSERT_EQ(s.alert, TLS_ALERT_RECORD_OVERFLOW);
}

TEST(test_refuse_record_larger_than_buffer) {
  tls_conn_t s;
  ASSERT_EQ(tls_init(&s, &cfg_ec, srv_rx, 1024, srv_tx, sizeof(srv_tx)), 0);
  ASSERT_EQ(tls_accept(&s), 0);
  tls_input(&s, (const uint8_t *)"\x16\x03\x01\x08\x00", 5);
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_RECORD_OVERFLOW);
}

TEST(test_refuse_message_larger_than_buffer) {
  tls_conn_t s;
  ASSERT_EQ(tls_init(&s, &cfg_ec, srv_rx, 1024, srv_tx, sizeof(srv_tx)), 0);
  ASSERT_EQ(tls_accept(&s), 0);
  tls_input(&s, (const uint8_t *)"\x16\x03\x01\x00\x04\x01\x00\x10\x00", 9);
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_RECORD_OVERFLOW);
}

TEST(test_refuse_unaligned_key_change) {
  /* ClientHello and the start of another message in one record: the
   * handshake keys would apply mid-record */
  static uint8_t m[2048], rec[2100];
  tls_conn_t s;
  ch_opt_t o;
  size_t n;
  ch_default(&o);
  ASSERT_EQ(server_start(&s, &cfg_ec, sizeof(srv_tx)), 0);
  peer_init(&peer, &cfg_ec);
  n = build_ch(&peer, &o, m);
  memcpy(m + n, "\x14\x00\x00\x20", 4);
  n = plain_record(TLS_CT_HANDSHAKE, m, n + 4, rec);
  tls_input(&s, rec, n);
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_UNEXPECTED_MESSAGE);
}

/* ══ After the server's flight ════════════════════════════════════ */

/* Handshake up to the client's Finished */
static int to_client_finished(tls_conn_t *s) {
  static uint8_t m[2048];
  ch_opt_t o;
  size_t n;
  ch_default(&o);
  CHECK(server_start(s, &cfg_ec, sizeof(srv_tx)) == 0);
  peer_init(&peer, &cfg_ec);
  n = build_ch(&peer, &o, m);
  send_ch(s, &peer, m, n);
  drain(s);
  CHECK(peer_read_flight(&peer) == 0);
  return 0;
}

TEST(test_bad_client_finished) {
  /* REQ-TLS-022 */
  tls_conn_t s;
  uint8_t rec[256], h[32];
  size_t n;
  ASSERT_EQ(to_client_finished(&s), 0);
  c.hash_peek(&peer.th, h);
  memcpy(rec + 5, "\x14\x00\x00\x20", 4);
  tls_finished_mac(&c, peer.c_hs, h, rec + 9);
  rec[9 + 31] ^= 0x80;
  n = tls_record_seal(&c, &peer.wr, TLS_CT_HANDSHAKE, rec, 36);
  tls_input(&s, rec, n);
  ASSERT_EQ(prot_alert(&s, TLS_ALERT_DECRYPT_ERROR), 0);
}

TEST(test_bad_record_mac) {
  /* REQ-TLS-030 */
  tls_conn_t s;
  uint8_t rec[256];
  size_t n;
  ASSERT_EQ(to_client_finished(&s), 0);
  n = peer_finished(&peer, rec);
  rec[n - 1] ^= 1;
  tls_input(&s, rec, n);
  ASSERT_EQ(prot_alert(&s, TLS_ALERT_BAD_RECORD_MAC), 0);
}

TEST(test_refuse_app_data_before_finished) {
  tls_conn_t s;
  uint8_t rec[256];
  size_t n;
  ASSERT_EQ(to_client_finished(&s), 0);
  n = peer_seal(&peer, TLS_CT_APPLICATION_DATA, "early", 5, rec);
  tls_input(&s, rec, n);
  ASSERT_EQ(prot_alert(&s, TLS_ALERT_UNEXPECTED_MESSAGE), 0);
}

TEST(test_refuse_plaintext_handshake_after_hello) {
  tls_conn_t s;
  uint8_t rec[256];
  size_t n;
  ASSERT_EQ(to_client_finished(&s), 0);
  n = plain_record(TLS_CT_HANDSHAKE,
                   (const uint8_t *)"\x14\x00\x00\x20"
                                    "0123456789abcdef0123456789abcdef",
                   36, rec);
  tls_input(&s, rec, n);
  ASSERT_EQ(prot_alert(&s, TLS_ALERT_UNEXPECTED_MESSAGE), 0);
}

TEST(test_refuse_bad_ccs) {
  tls_conn_t s;
  ASSERT_EQ(to_client_finished(&s), 0);
  tls_input(&s, (const uint8_t *)"\x14\x03\x03\x00\x01\x02", 6);
  ASSERT_EQ(prot_alert(&s, TLS_ALERT_UNEXPECTED_MESSAGE), 0);
}

TEST(test_client_alert_in_handshake) {
  /* A client that gives up sends a plaintext alert: no alert back */
  tls_conn_t s;
  ASSERT_EQ(to_client_finished(&s), 0);
  evts = 0;
  ASSERT_EQ(tls_input(&s, (const uint8_t *)"\x15\x03\x03\x00\x02\x02\x2a",
                      7),
            7);
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_BAD_CERTIFICATE);
  ASSERT_EQ(evts, TLS_EVT_ERROR);
  ASSERT_TRUE(wiped(&s));
  ASSERT_EQ(drain(&s), 0);
}

/* ══ Connected ════════════════════════════════════════════════════ */

static int connected(tls_conn_t *s) {
  ch_opt_t o;
  ch_default(&o);
  return handshake(s, &cfg_ec, &o, sizeof(srv_tx));
}

TEST(test_close_notify_both_ways) {
  /* REQ-TLS-035, REQ-TLS-039 */
  tls_conn_t s;
  uint8_t rec[64], buf[64], type;
  size_t n, off = 0;
  ASSERT_EQ(connected(&s), 0);
  evts = 0;
  n = peer_seal(&peer, TLS_CT_ALERT, "\x01\x00", 2, rec);
  ASSERT_EQ(tls_input(&s, rec, n), n);
  ASSERT_EQ(tls_state(&s), TLS_STATE_CLOSED);
  ASSERT_EQ(evts, TLS_EVT_CLOSED);
  /* we may still write, then close */
  ASSERT_EQ(tls_write(&s, (const uint8_t *)"bye", 3), 3);
  ASSERT_EQ(tls_close(&s), 0);
  ASSERT_EQ(tls_write(&s, (const uint8_t *)"x", 1), -1);
  drain(&s);
  ASSERT_EQ(peer_open(&peer, &off, &type, buf), 3);
  ASSERT_EQ(type, TLS_CT_APPLICATION_DATA);
  ASSERT_EQ(peer_open(&peer, &off, &type, buf), 2);
  ASSERT_EQ(type, TLS_CT_ALERT);
  ASSERT_MEM_EQ(buf + 5, "\x01\x00", 2);
  ASSERT_EQ(off, out_len);
}

TEST(test_fatal_alert_from_client) {
  /* REQ-TLS-036 */
  tls_conn_t s;
  uint8_t rec[64];
  size_t n;
  ASSERT_EQ(connected(&s), 0);
  evts = 0;
  n = peer_seal(&peer, TLS_CT_ALERT, "\x02\x50", 2, rec);
  tls_input(&s, rec, n);
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_INTERNAL_ERROR);
  ASSERT_EQ(evts, TLS_EVT_ERROR);
  ASSERT_EQ(drain(&s), 0);
  ASSERT_EQ(tls_write(&s, (const uint8_t *)"x", 1), -1);
}

TEST(test_records_queue_behind_reader) {
  /* Two records in one input: the second waits for the first to be read */
  tls_conn_t s;
  uint8_t rec[256], buf[16];
  size_t n;
  ASSERT_EQ(connected(&s), 0);
  n = peer_seal(&peer, TLS_CT_APPLICATION_DATA, "hello", 5, rec);
  n += peer_seal(&peer, TLS_CT_APPLICATION_DATA, "world!", 6, rec + n);
  ASSERT_EQ(tls_input(&s, rec, n), n);
  ASSERT_EQ(tls_read(&s, buf, 3), 3);
  ASSERT_MEM_EQ(buf, "hel", 3);
  ASSERT_EQ(tls_read(&s, buf, sizeof(buf)), 2);
  ASSERT_MEM_EQ(buf, "lo", 2);
  ASSERT_EQ(tls_read(&s, buf, sizeof(buf)), 6);
  ASSERT_MEM_EQ(buf, "world!", 6);
  ASSERT_EQ(tls_read(&s, buf, sizeof(buf)), 0);
}

TEST(test_empty_app_record) {
  tls_conn_t s;
  uint8_t rec[256], buf[16];
  size_t n;
  ASSERT_EQ(connected(&s), 0);
  n = peer_seal(&peer, TLS_CT_APPLICATION_DATA, "", 0, rec);
  n += peer_seal(&peer, TLS_CT_APPLICATION_DATA, "x", 1, rec + n);
  ASSERT_EQ(tls_input(&s, rec, n), n);
  ASSERT_EQ(tls_read(&s, buf, sizeof(buf)), 1);
  ASSERT_EQ(buf[0], 'x');
}

TEST(test_write_partial_when_tx_full) {
  tls_conn_t s;
  static uint8_t big[5000];
  const uint8_t *p;
  int w;
  ASSERT_EQ(connected(&s), 0);
  w = tls_write(&s, big, sizeof(big));
  ASSERT_EQ(w, (int)(sizeof(srv_tx) - TLS_RECORD_OVERHEAD));
  ASSERT_EQ(tls_write(&s, big, sizeof(big)), 0);
  ASSERT_EQ(tls_tx_pending(&s, &p), sizeof(srv_tx));
}

TEST(test_key_update_requested) {
  /* The client updates its keys and asks the server to follow */
  tls_conn_t s;
  uint8_t rec[256], buf[256], type;
  size_t n, off = 0;
  ASSERT_EQ(connected(&s), 0);
  n = peer_seal(&peer, TLS_CT_HANDSHAKE, "\x18\x00\x00\x01\x01", 5, rec);
  tls_update_secret(&c, peer.c_ap);
  tls_traffic_keys(&c, peer.c_ap, &peer.wr);
  n += peer_seal(&peer, TLS_CT_APPLICATION_DATA, "new", 3, rec + n);
  ASSERT_EQ(tls_input(&s, rec, n), n);
  ASSERT_EQ(tls_read(&s, buf, sizeof(buf)), 3);
  ASSERT_MEM_EQ(buf, "new", 3);
  /* the server's KeyUpdate(update_not_requested) under its old keys .. */
  drain(&s);
  ASSERT_EQ(peer_open(&peer, &off, &type, buf), 5);
  ASSERT_EQ(type, TLS_CT_HANDSHAKE);
  ASSERT_MEM_EQ(buf + 5, "\x18\x00\x00\x01\x00", 5);
  /* .. then its new ones */
  tls_update_secret(&c, peer.s_ap);
  tls_traffic_keys(&c, peer.s_ap, &peer.rd);
  ASSERT_EQ(tls_write(&s, (const uint8_t *)"ok", 2), 2);
  drain(&s);
  ASSERT_EQ(peer_open(&peer, &off, &type, buf), 2);
  ASSERT_MEM_EQ(buf + 5, "ok", 2);
}

TEST(test_key_update_not_requested) {
  tls_conn_t s;
  uint8_t rec[256], buf[16];
  size_t n;
  ASSERT_EQ(connected(&s), 0);
  n = peer_seal(&peer, TLS_CT_HANDSHAKE, "\x18\x00\x00\x01\x00", 5, rec);
  tls_update_secret(&c, peer.c_ap);
  tls_traffic_keys(&c, peer.c_ap, &peer.wr);
  n += peer_seal(&peer, TLS_CT_APPLICATION_DATA, "a", 1, rec + n);
  ASSERT_EQ(tls_input(&s, rec, n), n);
  ASSERT_EQ(tls_read(&s, buf, sizeof(buf)), 1);
  ASSERT_EQ(drain(&s), 0); /* nothing owed */
}

TEST(test_refuse_bad_key_update) {
  tls_conn_t s;
  uint8_t rec[256];
  size_t n;
  ASSERT_EQ(connected(&s), 0);
  n = peer_seal(&peer, TLS_CT_HANDSHAKE, "\x18\x00\x00\x01\x02", 5, rec);
  tls_input(&s, rec, n);
  ASSERT_EQ(prot_alert(&s, TLS_ALERT_ILLEGAL_PARAMETER), 0);
}

TEST(test_refuse_ccs_after_handshake) {
  tls_conn_t s;
  ASSERT_EQ(connected(&s), 0);
  tls_input(&s, (const uint8_t *)"\x14\x03\x03\x00\x01\x01", 6);
  ASSERT_EQ(prot_alert(&s, TLS_ALERT_UNEXPECTED_MESSAGE), 0);
}

TEST(test_refuse_handshake_message_after_handshake) {
  /* A NewSessionTicket from a client */
  tls_conn_t s;
  uint8_t rec[256];
  size_t n;
  ASSERT_EQ(connected(&s), 0);
  n = peer_seal(&peer, TLS_CT_HANDSHAKE, "\x04\x00\x00\x00", 4, rec);
  tls_input(&s, rec, n);
  ASSERT_EQ(prot_alert(&s, TLS_ALERT_UNEXPECTED_MESSAGE), 0);
}

/* ══ More malformed input ═════════════════════════════════════════ */

TEST(test_refuse_odd_cipher_suites) {
  ch_opt_t o;
  ch_default(&o);
  o.odd_suites = 1;
  ASSERT_EQ(refused(&o, TLS_ALERT_DECODE_ERROR), 0);
}

TEST(test_refuse_key_share_overrun) {
  ch_opt_t o;
  ch_default(&o);
  o.ks_overrun = 1;
  ASSERT_EQ(refused(&o, TLS_ALERT_DECODE_ERROR), 0);
}

TEST(test_refuse_extension_overrun) {
  ch_opt_t o;
  ch_default(&o);
  o.sv_overrun = 1;
  ASSERT_EQ(refused(&o, TLS_ALERT_DECODE_ERROR), 0);
}

TEST(test_refuse_trailing_bytes) {
  ch_opt_t o;
  ch_default(&o);
  o.trailing = 1;
  ASSERT_EQ(refused(&o, TLS_ALERT_DECODE_ERROR), 0);
}

TEST(test_refuse_33_byte_session_id) {
  ch_opt_t o;
  ch_default(&o);
  o.sid_len = 33;
  ASSERT_EQ(refused(&o, TLS_ALERT_DECODE_ERROR), 0);
}

TEST(test_x25519_then_p256) {
  tls_conn_t s;
  ch_opt_t o;
  ch_default(&o);
  o.shares[0] = TLS_GROUP_X25519;
  o.shares[1] = TLS_GROUP_SECP256R1;
  o.nshares = 2;
  ASSERT_EQ(handshake(&s, &cfg_ec, &o, sizeof(srv_tx)), 0);
  ASSERT_EQ(peer.group, TLS_GROUP_X25519);
}

TEST(test_refuse_empty_handshake_record) {
  tls_conn_t s;
  ASSERT_EQ(server_start(&s, &cfg_ec, sizeof(srv_tx)), 0);
  tls_input(&s, (const uint8_t *)"\x16\x03\x01\x00\x00", 5);
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(test_refuse_protected_record_before_hello) {
  tls_conn_t s;
  uint8_t rec[5 + 32];
  memset(rec, 0x11, sizeof(rec));
  memcpy(rec, "\x17\x03\x03\x00\x20", 5);
  ASSERT_EQ(server_start(&s, &cfg_ec, sizeof(srv_tx)), 0);
  tls_input(&s, rec, sizeof(rec));
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(test_refuse_oversize_plaintext_record) {
  /* 2^14 + 1 bytes of handshake, in a buffer big enough to take it */
  static uint8_t big_rx[17000], rec[16390];
  tls_conn_t s;
  memset(rec, 0, sizeof(rec));
  memcpy(rec, "\x16\x03\x01\x40\x01", 5);
  ASSERT_EQ(tls_init(&s, &cfg_ec, big_rx, sizeof(big_rx), srv_tx,
                     sizeof(srv_tx)),
            0);
  ASSERT_EQ(tls_accept(&s), 0);
  tls_input(&s, rec, 5 + 16385);
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_RECORD_OVERFLOW);
}

TEST(test_signing_failure_drops_flight) {
  /* The key cannot make the promised signature: the half-built record
   * (EncryptedExtensions, Certificate) is dropped for the alert */
  static uint8_t m[2048];
  tls_conn_t s;
  tls_config_t bad = cfg_ec;
  ch_opt_t o;
  uint8_t buf[256], type;
  size_t n, off;
  bad.sig_scheme = TLS_SIG_RSA_PSS_RSAE_SHA256; /* with an EC key */
  ch_default(&o);
  ASSERT_EQ(server_start(&s, &bad, sizeof(srv_tx)), 0);
  peer_init(&peer, &bad);
  n = build_ch(&peer, &o, m);
  send_ch(&s, &peer, m, n);
  ASSERT_EQ(tls_state(&s), TLS_STATE_ERROR);
  ASSERT_EQ(s.alert, TLS_ALERT_INTERNAL_ERROR);
  drain(&s);
  ASSERT_EQ(peer_read_sh(&peer, &off), 0);
  ASSERT_EQ(peer_open(&peer, &off, &type, buf), 2);
  ASSERT_EQ(type, TLS_CT_ALERT);
  ASSERT_MEM_EQ(buf + 5, "\x02\x50", 2);
  ASSERT_EQ(off, out_len);
}

TEST(test_refuse_long_finished) {
  tls_conn_t s;
  uint8_t rec[256], h[32];
  size_t n;
  ASSERT_EQ(to_client_finished(&s), 0);
  c.hash_peek(&peer.th, h);
  memcpy(rec + 5, "\x14\x00\x00\x21", 4);
  tls_finished_mac(&c, peer.c_hs, h, rec + 9);
  rec[9 + 32] = 0;
  n = tls_record_seal(&c, &peer.wr, TLS_CT_HANDSHAKE, rec, 37);
  tls_input(&s, rec, n);
  ASSERT_EQ(prot_alert(&s, TLS_ALERT_DECODE_ERROR), 0);
}

TEST(test_refuse_plaintext_alert_after_handshake) {
  tls_conn_t s;
  ASSERT_EQ(connected(&s), 0);
  tls_input(&s, (const uint8_t *)"\x15\x03\x03\x00\x02\x02\x28", 7);
  ASSERT_EQ(prot_alert(&s, TLS_ALERT_UNEXPECTED_MESSAGE), 0);
}

TEST(test_refuse_empty_protected_handshake) {
  tls_conn_t s;
  uint8_t rec[64];
  size_t n;
  ASSERT_EQ(connected(&s), 0);
  n = peer_seal(&peer, TLS_CT_HANDSHAKE, "", 0, rec);
  tls_input(&s, rec, n);
  ASSERT_EQ(prot_alert(&s, TLS_ALERT_UNEXPECTED_MESSAGE), 0);
}

TEST(test_refuse_data_inside_handshake_message) {
  /* RFC 8446 §5.1: no other records between a message's fragments */
  tls_conn_t s;
  uint8_t rec[128];
  size_t n;
  ASSERT_EQ(connected(&s), 0);
  n = peer_seal(&peer, TLS_CT_HANDSHAKE, "\x18\x00", 2, rec);
  n += peer_seal(&peer, TLS_CT_APPLICATION_DATA, "x", 1, rec + n);
  tls_input(&s, rec, n);
  ASSERT_EQ(prot_alert(&s, TLS_ALERT_UNEXPECTED_MESSAGE), 0);
}

TEST(test_refuse_short_key_update) {
  tls_conn_t s;
  uint8_t rec[64];
  size_t n;
  ASSERT_EQ(connected(&s), 0);
  n = peer_seal(&peer, TLS_CT_HANDSHAKE, "\x18\x00\x00\x00", 4, rec);
  tls_input(&s, rec, n);
  ASSERT_EQ(prot_alert(&s, TLS_ALERT_DECODE_ERROR), 0);
}

TEST(test_refuse_long_key_update) {
  tls_conn_t s;
  uint8_t rec[64];
  size_t n;
  ASSERT_EQ(connected(&s), 0);
  n = peer_seal(&peer, TLS_CT_HANDSHAKE, "\x18\x00\x00\x02\x00\x00", 6,
                rec);
  tls_input(&s, rec, n);
  ASSERT_EQ(prot_alert(&s, TLS_ALERT_DECODE_ERROR), 0);
}

TEST(test_user_canceled_ignored) {
  tls_conn_t s;
  uint8_t rec[128], buf[8];
  size_t n;
  ASSERT_EQ(connected(&s), 0);
  n = peer_seal(&peer, TLS_CT_ALERT, "\x01\x5a", 2, rec);
  n += peer_seal(&peer, TLS_CT_APPLICATION_DATA, "y", 1, rec + n);
  ASSERT_EQ(tls_input(&s, rec, n), n);
  ASSERT_EQ(tls_state(&s), TLS_STATE_CONNECTED);
  ASSERT_EQ(tls_read(&s, buf, sizeof(buf)), 1);
}

TEST(test_input_discarded_after_close) {
  static uint8_t junk[5000];
  tls_conn_t s;
  uint8_t rec[64];
  size_t n;
  ASSERT_EQ(connected(&s), 0);
  n = peer_seal(&peer, TLS_CT_ALERT, "\x01\x00", 2, rec);
  ASSERT_EQ(tls_input(&s, rec, n), n);
  ASSERT_EQ(tls_state(&s), TLS_STATE_CLOSED);
  ASSERT_EQ(tls_input(&s, junk, sizeof(junk)), sizeof(junk));
  ASSERT_EQ(tls_state(&s), TLS_STATE_CLOSED);
}

TEST(test_close_once) {
  tls_conn_t s;
  ASSERT_EQ(connected(&s), 0);
  ASSERT_EQ(tls_close(&s), 0);
  ASSERT_EQ(tls_close(&s), 0);
  ASSERT_EQ(drain(&s), (size_t)(2 + TLS_RECORD_OVERHEAD));
}

TEST(test_write_needs_room_for_a_byte) {
  /* 20 bytes free cannot carry a record: nothing is written */
  static uint8_t big[5000];
  tls_conn_t s;
  const uint8_t *p;
  size_t first = sizeof(srv_tx) - TLS_RECORD_OVERHEAD - 20;
  ASSERT_EQ(connected(&s), 0);
  ASSERT_EQ(tls_write(&s, big, first), (int)first);
  ASSERT_EQ(tls_write(&s, big, 10), 0);
  ASSERT_EQ(tls_tx_pending(&s, &p), sizeof(srv_tx) - 20);
}

/* ══ API ══════════════════════════════════════════════════════════ */

TEST(test_init_and_accept_checks) {
  tls_conn_t s;
  tls_config_t bare = cfg_ec;
  ASSERT_EQ(tls_init(&s, NULL, srv_rx, 1024, srv_tx, 1024), -1);
  ASSERT_EQ(tls_init(&s, &cfg_ec, srv_rx, 100, srv_tx, 1024), -1);
  ASSERT_EQ(tls_init(&s, &cfg_ec, srv_rx, 1024, srv_tx, 100), -1);
  ASSERT_EQ(tls_init(&s, &cfg_ec, NULL, 1024, srv_tx, 1024), -1);
  ASSERT_EQ(tls_init(&s, &cfg_ec, srv_rx, 1024, srv_tx, 1024), 0);
  ASSERT_EQ(tls_state(&s), TLS_STATE_IDLE);
  ASSERT_EQ(tls_write(&s, (const uint8_t *)"x", 1), -1);
  ASSERT_EQ(tls_accept(&s), 0);
  ASSERT_EQ(tls_accept(&s), -1);
  ASSERT_EQ(tls_write(&s, (const uint8_t *)"x", 1), -1);
  bare.cert_count = 0;
  ASSERT_EQ(tls_init(&s, &bare, srv_rx, 1024, srv_tx, 1024), 0);
  ASSERT_EQ(tls_accept(&s), -1);
}

int main(void) {
  fprintf(stderr, "=== TLS server handshake tests ===\n");
  if (tls_mbedtls_init(&be, &c) != 0 ||
      tls_mbedtls_parse_key(&be, &ec_key, (const uint8_t *)server_key_pem,
                            sizeof(server_key_pem)) != 0 ||
      tls_mbedtls_parse_key(&be, &rsa_key, (const uint8_t *)rsa_key_pem,
                            sizeof(rsa_key_pem)) != 0) {
    fprintf(stderr, "backend init failed\n");
    return 1;
  }
  fixed = c;
  fixed.random = fixed_random;
  fixed.kx_keygen = fixed_keygen;

  cfg_ec.crypto = &c;
  cfg_ec.cert = ec_chain;
  cfg_ec.cert_len = ec_chain_len;
  cfg_ec.cert_count = 1;
  cfg_ec.key = &ec_key;
  cfg_ec.sig_scheme = TLS_SIG_ECDSA_SECP256R1_SHA256;
  cfg_fixed = cfg_ec;
  cfg_fixed.crypto = &fixed;
  cfg_rsa = cfg_ec;
  cfg_rsa.cert = rsa_chain;
  cfg_rsa.cert_len = rsa_chain_len;
  cfg_rsa.key = &rsa_key;
  cfg_rsa.sig_scheme = TLS_SIG_RSA_PSS_RSAE_SHA256;

  RUN_TEST(test_rfc8448_server_hello);
  RUN_TEST(test_rfc8448_client_hello_full_handshake);

  RUN_TEST(test_handshake_ecdsa);
  RUN_TEST(test_handshake_rsa_pss);
  RUN_TEST(test_handshake_p256);
  RUN_TEST(test_prefers_x25519);
  RUN_TEST(test_skips_unknown_share);
  RUN_TEST(test_compat_mode_ccs);
  RUN_TEST(test_fragmented_client_hello);
  RUN_TEST(test_small_tx_buffer);
  RUN_TEST(test_tx_too_small_for_certificate);

  RUN_TEST(test_refuse_no_supported_versions);
  RUN_TEST(test_refuse_tls12_only);
  RUN_TEST(test_refuse_no_common_suite);
  RUN_TEST(test_refuse_compression);
  RUN_TEST(test_refuse_missing_key_share);
  RUN_TEST(test_refuse_missing_groups);
  RUN_TEST(test_refuse_missing_signature_algorithms);
  RUN_TEST(test_refuse_no_common_group);
  RUN_TEST(test_refuse_no_common_signature);
  RUN_TEST(test_refuse_duplicate_extension);
  RUN_TEST(test_refuse_zero_share);
  RUN_TEST(test_refuse_short_share);
  RUN_TEST(test_refuse_truncated_client_hello);
  RUN_TEST(test_refuse_long_session_id);
  RUN_TEST(test_refuse_wrong_first_message);
  RUN_TEST(test_refuse_ccs_before_client_hello);
  RUN_TEST(test_refuse_unknown_record_type);
  RUN_TEST(test_refuse_bad_header_at_once);
  RUN_TEST(test_refuse_oversize_header_at_once);
  RUN_TEST(test_refuse_record_larger_than_buffer);
  RUN_TEST(test_refuse_message_larger_than_buffer);
  RUN_TEST(test_refuse_unaligned_key_change);

  RUN_TEST(test_bad_client_finished);
  RUN_TEST(test_bad_record_mac);
  RUN_TEST(test_refuse_app_data_before_finished);
  RUN_TEST(test_refuse_plaintext_handshake_after_hello);
  RUN_TEST(test_refuse_bad_ccs);
  RUN_TEST(test_client_alert_in_handshake);

  RUN_TEST(test_close_notify_both_ways);
  RUN_TEST(test_fatal_alert_from_client);
  RUN_TEST(test_records_queue_behind_reader);
  RUN_TEST(test_empty_app_record);
  RUN_TEST(test_write_partial_when_tx_full);
  RUN_TEST(test_key_update_requested);
  RUN_TEST(test_key_update_not_requested);
  RUN_TEST(test_refuse_bad_key_update);
  RUN_TEST(test_refuse_ccs_after_handshake);
  RUN_TEST(test_refuse_handshake_message_after_handshake);

  RUN_TEST(test_refuse_odd_cipher_suites);
  RUN_TEST(test_refuse_key_share_overrun);
  RUN_TEST(test_refuse_extension_overrun);
  RUN_TEST(test_refuse_trailing_bytes);
  RUN_TEST(test_refuse_33_byte_session_id);
  RUN_TEST(test_x25519_then_p256);
  RUN_TEST(test_refuse_empty_handshake_record);
  RUN_TEST(test_refuse_protected_record_before_hello);
  RUN_TEST(test_refuse_oversize_plaintext_record);
  RUN_TEST(test_signing_failure_drops_flight);
  RUN_TEST(test_refuse_long_finished);
  RUN_TEST(test_refuse_plaintext_alert_after_handshake);
  RUN_TEST(test_refuse_empty_protected_handshake);
  RUN_TEST(test_refuse_data_inside_handshake_message);
  RUN_TEST(test_refuse_short_key_update);
  RUN_TEST(test_refuse_long_key_update);
  RUN_TEST(test_user_canceled_ignored);
  RUN_TEST(test_input_discarded_after_close);
  RUN_TEST(test_close_once);
  RUN_TEST(test_write_needs_room_for_a_byte);

  RUN_TEST(test_init_and_accept_checks);

  mbedtls_pk_free(&ec_key);
  mbedtls_pk_free(&rsa_key);
  tls_mbedtls_free(&be);
  TEST_REPORT();
  return test_failures;
}
