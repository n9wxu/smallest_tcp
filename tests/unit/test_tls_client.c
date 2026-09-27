/**
 * @file test_tls_client.c
 * @brief TLS 1.3 client handshake (RFC 8446 §4).
 *
 * Two kinds of peer: our own server (tls.c, server role) over an in-memory
 * transport, and a scripted server — test code that answers the client's
 * ClientHello with a flight built from the key-schedule primitives, able to
 * get any part of it wrong on purpose.  Mbed TLS is the backend.
 */

#include "test_main.h"
#include "tls.h"
#include "tls_crypto_mbedtls.h"
#include "tls_test_data.h"
#include <string.h>

static tls_mbedtls_t be, be_noca, be_other;
static tls_crypto_t c, c_noca, c_other;
static mbedtls_pk_context ec_key, rsa_key;

static const uint8_t *const ec_chain[1] = {server_der};
static const uint16_t ec_chain_len[1] = {sizeof(server_der)};
static const uint8_t *const rsa_chain[1] = {rsa_der};
static const uint16_t rsa_chain_len[1] = {sizeof(rsa_der)};

static tls_config_t srv_ec, srv_rsa;       /* our server */
static tls_config_t cli, cli_noca, cli_other; /* the client */
static tls_config_t srv_psk, srv_psk_only;    /* .. with a PSK */
static tls_config_t cli_psk, cli_psk_ke, cli_psk_both, cli_psk_other;
static tls_config_t srv_p256, srv_psk_p256, cli_p256; /* secp256r1 only */

static const uint8_t test_psk[32] = {
    0x70, 0x73, 0x6b, 0x21, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc,
    0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x11, 0x22,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc};
#define TEST_PSK_ID "device-1"

static uint8_t cli_rx[4096], cli_tx[2048], srv_rx[4096], srv_tx[4096];
static uint8_t cli_evts, srv_evts;

#define HOST "pyro-dead01.local"

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

static void on_cli(tls_conn_t *t, uint8_t e) {
  (void)t;
  cli_evts |= e;
}
static void on_srv(tls_conn_t *t, uint8_t e) {
  (void)t;
  srv_evts |= e;
}

static int client_start(tls_conn_t *t, const tls_config_t *cfg,
                        size_t rx_cap, size_t tx_cap, const char *host) {
  if (tls_init(t, cfg, cli_rx, rx_cap, cli_tx, tx_cap) != 0)
    return -1;
  t->on_event = on_cli;
  cli_evts = 0;
  return tls_connect(t, host);
}

static int server_start(tls_conn_t *t, const tls_config_t *cfg) {
  if (tls_init(t, cfg, srv_rx, sizeof(srv_rx), srv_tx, sizeof(srv_tx)) != 0)
    return -1;
  t->on_event = on_srv;
  srv_evts = 0;
  return tls_accept(t);
}

/* Move ciphertext from @p a to @p b, @p step bytes at a time */
static size_t carry(tls_conn_t *a, tls_conn_t *b, size_t step) {
  const uint8_t *p;
  size_t n, moved = 0;
  while ((n = tls_tx_pending(a, &p)) > 0) {
    size_t k = n < step ? n : step, took = tls_input(b, p, k);
    tls_tx_done(a, took);
    moved += took;
    if (took < k)
      break;
  }
  return moved;
}

/* Run the pair until nothing moves */
static void shuttle(tls_conn_t *cl, tls_conn_t *sv, size_t step) {
  while (carry(cl, sv, step) + carry(sv, cl, step) > 0)
    ;
}

/* ══ Against our server ═══════════════════════════════════════════ */

static tls_conn_t cl, sv;

static int pair(const tls_config_t *ccfg, const tls_config_t *scfg,
                const char *host, size_t step) {
  CHECK(client_start(&cl, ccfg, sizeof(cli_rx), sizeof(cli_tx), host) == 0);
  CHECK(server_start(&sv, scfg) == 0);
  shuttle(&cl, &sv, step);
  return 0;
}

TEST(test_handshake_with_our_server) {
  ASSERT_EQ(pair(&cli, &srv_ec, HOST, 65536), 0);
  ASSERT_EQ(tls_state(&cl), TLS_STATE_CONNECTED);
  ASSERT_EQ(tls_state(&sv), TLS_STATE_CONNECTED);
  ASSERT_EQ(cli_evts, TLS_EVT_CONNECTED);
  ASSERT_EQ(srv_evts, TLS_EVT_CONNECTED);
  ASSERT_EQ(cl.group, TLS_GROUP_X25519);
  ASSERT_EQ(sv.group, TLS_GROUP_X25519);
}

TEST(test_data_both_ways) {
  uint8_t buf[64];
  ASSERT_EQ(pair(&cli, &srv_ec, HOST, 65536), 0);
  ASSERT_EQ(tls_write(&cl, (const uint8_t *)"GET /", 5), 5);
  shuttle(&cl, &sv, 65536);
  ASSERT_EQ(tls_read(&sv, buf, sizeof(buf)), 5);
  ASSERT_MEM_EQ(buf, "GET /", 5);
  ASSERT_EQ(tls_write(&sv, (const uint8_t *)"200 OK", 6), 6);
  shuttle(&cl, &sv, 65536);
  ASSERT_EQ(tls_read(&cl, buf, sizeof(buf)), 6);
  ASSERT_MEM_EQ(buf, "200 OK", 6);
}

TEST(test_close_notify_from_client) {
  ASSERT_EQ(pair(&cli, &srv_ec, HOST, 65536), 0);
  ASSERT_EQ(tls_close(&cl), 0);
  shuttle(&cl, &sv, 65536);
  ASSERT_EQ(tls_state(&sv), TLS_STATE_CLOSED);
  ASSERT_EQ(tls_close(&sv), 0);
  shuttle(&cl, &sv, 65536);
  ASSERT_EQ(tls_state(&cl), TLS_STATE_CLOSED);
}

TEST(test_rsa_pss_server) {
  ASSERT_EQ(pair(&cli, &srv_rsa, "rsa.example", 65536), 0);
  ASSERT_EQ(tls_state(&cl), TLS_STATE_CONNECTED);
}

TEST(test_byte_at_a_time) {
  ASSERT_EQ(pair(&cli, &srv_ec, HOST, 1), 0);
  ASSERT_EQ(tls_state(&cl), TLS_STATE_CONNECTED);
  ASSERT_EQ(tls_state(&sv), TLS_STATE_CONNECTED);
}

TEST(test_small_client_buffers) {
  /* The server's flight is one ~650-byte record: 700 bytes of rx hold it */
  ASSERT_EQ(client_start(&cl, &cli, 700, 256, HOST), 0);
  ASSERT_EQ(server_start(&sv, &srv_ec), 0);
  shuttle(&cl, &sv, 65536);
  ASSERT_EQ(tls_state(&cl), TLS_STATE_CONNECTED);
}

TEST(test_no_name_check) {
  ASSERT_EQ(pair(&cli, &srv_ec, NULL, 65536), 0);
  ASSERT_EQ(tls_state(&cl), TLS_STATE_CONNECTED);
}

TEST(test_address_literal) {
  /* Checked against the certificate's iPAddress; never sent as SNI */
  ASSERT_EQ(pair(&cli, &srv_ec, "10.0.0.2", 65536), 0);
  ASSERT_EQ(tls_state(&cl), TLS_STATE_CONNECTED);
}

/* The client's fatal alert reaches our server, which reports it */
static int refused_by_client(const tls_config_t *ccfg, const char *host,
                             uint8_t alert) {
  CHECK(pair(ccfg, &srv_ec, host, 65536) == 0);
  CHECK(tls_state(&cl) == TLS_STATE_ERROR && cl.alert == alert);
  CHECK(cli_evts == TLS_EVT_ERROR);
  CHECK(tls_state(&sv) == TLS_STATE_ERROR && sv.alert == alert);
  return 0;
}

TEST(test_refuse_wrong_name) {
  /* REQ-TLS-014 */
  ASSERT_EQ(refused_by_client(&cli, "evil.example", TLS_ALERT_BAD_CERTIFICATE),
            0);
}

TEST(test_refuse_wrong_address) {
  ASSERT_EQ(refused_by_client(&cli, "10.0.0.3", TLS_ALERT_BAD_CERTIFICATE), 0);
}

TEST(test_refuse_untrusted_chain) {
  ASSERT_EQ(refused_by_client(&cli_other, HOST, TLS_ALERT_UNKNOWN_CA), 0);
}

TEST(test_refuse_without_trust_anchors) {
  ASSERT_EQ(refused_by_client(&cli_noca, HOST, TLS_ALERT_UNKNOWN_CA), 0);
}

/* ══ The scripted server ══════════════════════════════════════════ */

typedef struct {
  /* ServerHello */
  int bad_sid, bad_suite, bad_comp, hrr;
  int no_versions;          /* a TLS 1.2 ServerHello */
  uint16_t version;         /* in supported_versions (0: 0x0304) */
  uint16_t group;           /* in key_share (0: x25519) */
  int no_key_share, dup_versions;
  int long_versions;        /* supported_versions with a byte too many */
  uint16_t sh_ext;          /* an extra ServerHello extension, empty
                               (0: none) */
  int ccs;                  /* a dummy change_cipher_spec after it */
  /* EncryptedExtensions */
  uint16_t ee_ext;          /* an extension, empty (0: none) */
  int ee_sni;               /* server_name: 1 empty (the acknowledgement),
                               2 with a byte (wrong) */
  int cert_req;             /* CertificateRequest (2: twice) */
  int cert_req_ctx;         /* .. with a context */
  /* Certificate */
  int empty_chain, cert_ctx, no_certificate;
  int empty_entry;          /* a zero-length certificate in the list */
  int chain;                /* certificates sent (0: 1) */
  /* CertificateVerify */
  uint16_t scheme;          /* 0: ECDSA P-256 */
  const void *sign_key;     /* 0: the certificate's key */
  int bad_sig;
  int cv_len_lie;           /* CertificateVerify claims 700 bytes */
  /* Finished */
  int bad_fin;
  /* A PSK (the client's must be test_psk) */
  int psk;                  /* accept it */
  int psk_index;            /* selected_identity sent */
  int psk_ke;               /* .. without a key share */
  int psk_cert;             /* .. and send certificates anyway */
  /* A HelloRetryRequest first */
  uint16_t hrr_group;       /* asking for a share of this group */
  int hrr_cookie;           /* .. with a cookie */
  int hrr_twice;            /* two of them */
  uint16_t hrr_version;     /* in its supported_versions (0: 0x0304) */
  int hrr_no_versions, hrr_empty_cookie, hrr_empty, hrr_bad_sid;
  uint16_t hrr_ext;         /* an unknown extension in it */
} script_t;

typedef struct {
  tls_hash_t th;
  uint8_t hs[32], c_hs[32], s_hs[32], c_ap[32], s_ap[32];
  tls_keys_t rd, wr; /* reading the client, writing to it */
  int sni;           /* the ClientHello carried server_name */
  uint8_t ch_sid_len;
  uint8_t random[32];      /* ClientHello1's */
  const uint8_t *share;    /* the client's last share .. */
  uint16_t share_group;    /* .. of this group */
  size_t share_len;
  int cookie_echoed;       /* ClientHello2 carried our cookie */
  int shares;              /* entries in its key_share */
} peer_t;

static peer_t sp;
static uint8_t resp[8192];
static size_t resp_len;

static void add_msg(uint8_t *msgs, size_t *n, uint8_t type, const uint8_t *b,
                    size_t blen) {
  msgs[*n] = type;
  put24(msgs + *n + 1, blen);
  memcpy(msgs + *n + 4, b, blen);
  c.hash_update(&sp.th, msgs + *n, 4 + blen);
  *n += 4 + blen;
}

static const uint8_t cookie[16] = "smallest cookie";

/* The client's pending ClientHello: into the transcript, its facts into
 * sp; taken from tx */
static int read_ch(tls_conn_t *t) {
  const uint8_t *out, *ch, *q;
  size_t n, len, elen;
  n = tls_tx_pending(t, &out);
  CHECK(n > 9 && out[0] == TLS_CT_HANDSHAKE && out[5] == 1);
  len = be16(out + 3);
  CHECK(n == 5 + len && be24(out + 6) == len - 4);
  ch = out + 5;
  c.hash_update(&sp.th, ch, len);
  memcpy(sp.random, ch + 6, 32);
  q = ch + 4 + 2 + 32;
  sp.ch_sid_len = q[0];
  q += 1 + q[0];
  q += 2 + be16(q); /* cipher_suites */
  q += 1 + q[0];    /* compression */
  elen = be16(q);
  q += 2;
  sp.share = NULL;
  sp.shares = 0;
  while (elen) {
    size_t type = be16(q), l = be16(q + 2);
    if (type == TLS_EXT_SERVER_NAME)
      sp.sni = 1;
    if (type == 44 && l == 2 + sizeof(cookie) &&
        memcmp(q + 6, cookie, sizeof(cookie)) == 0)
      sp.cookie_echoed = 1;
    if (type == TLS_EXT_KEY_SHARE) {
      const uint8_t *e = q + 6, *end = q + 4 + l;
      while (e < end) {
        sp.share_group = (uint16_t)be16(e);
        sp.share_len = be16(e + 2);
        sp.share = e + 4;
        sp.shares++;
        e += 4 + sp.share_len;
      }
    }
    q += 4 + l;
    elen -= 4 + l;
  }
  tls_tx_done(t, n);
  return 0;
}

/* A HelloRetryRequest to the client, per @p o */
static void send_hrr(tls_conn_t *t, const script_t *o) {
  uint8_t rec[128], *b = rec + 5 + 4;
  size_t bn = 0, n = 0;
  put16(b, 0x0303);
  memcpy(b + 2,
         "\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91"
         "\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c",
         32);
  bn = 34;
  b[bn++] = o->hrr_bad_sid ? 1 : 0; /* legacy_session_id_echo */
  if (o->hrr_bad_sid)
    b[bn++] = 0x77;
  put16(b + bn, TLS_AES_128_GCM_SHA256);
  b[bn + 2] = 0;
  bn += 5;
  if (o->hrr_group) {
    put16(b + bn, TLS_EXT_KEY_SHARE);
    put16(b + bn + 2, 2);
    put16(b + bn + 4, o->hrr_group);
    bn += 6;
  }
  if (o->hrr_cookie) {
    size_t cl = o->hrr_empty_cookie ? 0 : sizeof(cookie);
    put16(b + bn, 44);
    put16(b + bn + 2, 2 + cl);
    put16(b + bn + 4, cl);
    memcpy(b + bn + 6, cookie, cl);
    bn += 6 + cl;
  }
  if (o->hrr_ext) {
    put16(b + bn, o->hrr_ext);
    put16(b + bn + 2, 0);
    bn += 4;
  }
  if (!o->hrr_no_versions) {
    put16(b + bn, TLS_EXT_SUPPORTED_VERSIONS);
    put16(b + bn + 2, 2);
    put16(b + bn + 4, o->hrr_version ? o->hrr_version : 0x0304);
    bn += 6;
  }
  put16(b + 38 + (o->hrr_bad_sid ? 1 : 0),
        bn - 40 - (o->hrr_bad_sid ? 1u : 0u));
  tls_transcript_hrr(&c, &sp.th);
  rec[0] = TLS_CT_HANDSHAKE;
  rec[1] = 3;
  rec[2] = 3;
  put16(rec + 3, 4 + bn);
  add_msg(rec + 5, &n, TLS_HS_SERVER_HELLO, b, bn);
  tls_input(t, rec, 5 + n);
}

/* Answer the client's ClientHello (its pending output) per @p o */
static int script(tls_conn_t *t, const script_t *o) {
  static uint8_t msgs[8192], body[4096];
  size_t mn = 0, bn;
  uint8_t priv[32], pub[65], z[32], h[32], ms[32];
  size_t pub_len;
  uint16_t grp;
  int k;

  memset(&sp, 0, sizeof(sp));
  c.hash_init(&sp.th);
  resp_len = 0;

  /* The ClientHello; a HelloRetryRequest and the second ClientHello */
  CHECK(read_ch(t) == 0);
  if (o->hrr_group || o->hrr_cookie || o->hrr_empty) {
    uint8_t random1[32];
    memcpy(random1, sp.random, 32);
    send_hrr(t, o);
    if (o->hrr_twice)
      send_hrr(t, o);
    if (tls_state(t) != TLS_STATE_HANDSHAKE)
      return 0; /* refused: the caller looks */
    CHECK(read_ch(t) == 0);
    CHECK(memcmp(random1, sp.random, 32) == 0); /* the same ClientHello */
    CHECK(sp.shares == 1);
    CHECK(!o->hrr_cookie || sp.cookie_echoed);
  }
  grp = sp.share ? sp.share_group : TLS_GROUP_X25519;
  CHECK(sp.share || o->psk_ke);

  /* ServerHello */
  CHECK(c.kx_keygen(c.ctx, grp, priv, pub, &pub_len) == 0);
  if (sp.share)
    CHECK(c.kx_shared(c.ctx, grp, priv, sp.share, sp.share_len, z) == 0);
  bn = 0;
  put16(body, 0x0303);
  memset(body + 2, 0x33, 32);
  if (o->hrr)
    memcpy(body + 2,
           "\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91"
           "\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c",
           32);
  bn = 34;
  if (o->bad_sid) {
    body[bn++] = 1;
    body[bn++] = 0x77;
  } else {
    body[bn++] = 0;
  }
  put16(body + bn, o->bad_suite ? 0x1302 : TLS_AES_128_GCM_SHA256);
  body[bn + 2] = (uint8_t)(o->bad_comp ? 1 : 0);
  bn += 3;
  {
    uint8_t *ext = body + bn;
    int i;
    bn += 2;
    if (o->psk) {
      put16(body + bn, TLS_EXT_PRE_SHARED_KEY);
      put16(body + bn + 2, 2);
      put16(body + bn + 4, (size_t)o->psk_index);
      bn += 6;
    }
    if (!o->no_key_share && !o->psk_ke) {
      put16(body + bn, TLS_EXT_KEY_SHARE);
      put16(body + bn + 2, 4 + pub_len);
      put16(body + bn + 4, o->group ? o->group : grp);
      put16(body + bn + 6, pub_len);
      memcpy(body + bn + 8, pub, pub_len);
      bn += 8 + pub_len;
    }
    for (i = 0; i < (o->dup_versions ? 2 : 1) && !o->no_versions; i++) {
      put16(body + bn, TLS_EXT_SUPPORTED_VERSIONS);
      put16(body + bn + 2, o->long_versions ? 3 : 2);
      put16(body + bn + 4, o->version ? o->version : 0x0304);
      bn += 6;
      if (o->long_versions)
        body[bn++] = 0;
    }
    if (o->sh_ext) {
      put16(body + bn, o->sh_ext);
      put16(body + bn + 2, 0);
      bn += 4;
    }
    put16(ext, (size_t)(body + bn - ext - 2));
  }
  resp[0] = TLS_CT_HANDSHAKE;
  resp[1] = 3;
  resp[2] = 3;
  put16(resp + 3, 4 + bn);
  add_msg(resp + 5, &mn, TLS_HS_SERVER_HELLO, body, bn);
  resp_len = 5 + mn;
  mn = 0;
  if (o->ccs) {
    memcpy(resp + resp_len, "\x14\x03\x03\x00\x01\x01", 6);
    resp_len += 6;
  }

  if (o->psk)
    tls_early_secret(&c, test_psk, sizeof(test_psk), sp.hs);
  else
    tls_early_secret(&c, NULL, 0, sp.hs);
  tls_next_secret(&c, sp.hs, o->psk_ke ? NULL : z, 32);
  c.hash_peek(&sp.th, h);
  tls_derive_secret(&c, sp.hs, "c hs traffic", h, sp.c_hs);
  tls_derive_secret(&c, sp.hs, "s hs traffic", h, sp.s_hs);
  tls_traffic_keys(&c, sp.s_hs, &sp.wr);
  tls_traffic_keys(&c, sp.c_hs, &sp.rd);

  /* EncryptedExtensions */
  bn = 2;
  if (o->ee_sni) {
    put16(body + bn, TLS_EXT_SERVER_NAME);
    put16(body + bn + 2, (size_t)(o->ee_sni - 1));
    bn += 4;
    if (o->ee_sni == 2)
      body[bn++] = 0;
  }
  if (o->ee_ext) {
    put16(body + bn, o->ee_ext);
    put16(body + bn + 2, 0);
    bn += 4;
  }
  put16(body, bn - 2);
  add_msg(msgs, &mn, TLS_HS_ENCRYPTED_EXTENSIONS, body, bn);

  /* CertificateRequest */
  for (k = 0; k < o->cert_req; k++) {
    bn = 0;
    body[bn++] = (uint8_t)(o->cert_req_ctx ? 1 : 0);
    if (o->cert_req_ctx)
      body[bn++] = 0x42;
    put16(body + bn, 8); /* signature_algorithms: ECDSA P-256 */
    put16(body + bn + 2, TLS_EXT_SIGNATURE_ALGORITHMS);
    put16(body + bn + 4, 4);
    put16(body + bn + 6, 2);
    put16(body + bn + 8, TLS_SIG_ECDSA_SECP256R1_SHA256);
    add_msg(msgs, &mn, TLS_HS_CERTIFICATE_REQUEST, body, bn + 10);
  }

  if (!o->no_certificate && (!o->psk || o->psk_cert)) {
    /* Certificate */
    bn = 0;
    body[bn++] = (uint8_t)(o->cert_ctx ? 1 : 0);
    if (o->cert_ctx)
      body[bn++] = 0x42;
    if (o->empty_chain) {
      put24(body + bn, 0);
      bn += 3;
    } else if (o->empty_entry) {
      put24(body + bn, 5);
      put24(body + bn + 3, 0);
      put16(body + bn + 6, 0);
      bn += 8;
    } else {
      int count = o->chain ? o->chain : 1;
      put24(body + bn, (size_t)count * (3 + sizeof(server_der) + 2));
      bn += 3;
      for (k = 0; k < count; k++) {
        put24(body + bn, sizeof(server_der));
        memcpy(body + bn + 3, server_der, sizeof(server_der));
        bn += 3 + sizeof(server_der);
        put16(body + bn, 0);
        bn += 2;
      }
    }
    add_msg(msgs, &mn, TLS_HS_CERTIFICATE, body, bn);

    /* CertificateVerify */
    {
      uint8_t content[130];
      size_t sl = 0;
      uint16_t scheme = o->scheme ? o->scheme : TLS_SIG_ECDSA_SECP256R1_SHA256;
      uint16_t sign_as = scheme == 0x0503 ? TLS_SIG_ECDSA_SECP256R1_SHA256
                                          : scheme;
      memset(content, 0x20, 64);
      memcpy(content + 64, "TLS 1.3, server CertificateVerify", 34);
      c.hash_peek(&sp.th, content + 98);
      CHECK(c.sign(c.ctx, o->sign_key ? o->sign_key : &ec_key, sign_as,
                   content, sizeof(content), body + 4, &sl, 512) == 0);
      if (o->bad_sig)
        body[4 + sl - 1] ^= 1;
      put16(body, scheme);
      put16(body + 2, sl);
      add_msg(msgs, &mn, TLS_HS_CERTIFICATE_VERIFY, body, 4 + sl);
      if (o->cv_len_lie)
        put24(msgs + mn - (4 + sl) - 3, 700);
    }
  }

  /* Finished */
  c.hash_peek(&sp.th, h);
  tls_finished_mac(&c, sp.s_hs, h, body);
  if (o->bad_fin)
    body[0] ^= 1;
  add_msg(msgs, &mn, TLS_HS_FINISHED, body, 32);

  memcpy(resp + resp_len + 5, msgs, mn);
  resp_len += tls_record_seal(&c, &sp.wr, TLS_CT_HANDSHAKE, resp + resp_len,
                              mn);

  /* Application secrets */
  c.hash_peek(&sp.th, h);
  memcpy(ms, sp.hs, 32);
  tls_next_secret(&c, ms, NULL, 0);
  tls_derive_secret(&c, ms, "c ap traffic", h, sp.c_ap);
  tls_derive_secret(&c, ms, "s ap traffic", h, sp.s_ap);
  tls_traffic_keys(&c, sp.s_ap, &sp.wr);
  return 0;
}

/* Client (configuration @p cfg) with the scripted server: ClientHello,
 * answer, feed it */
static int scripted_as(const tls_config_t *cfg, tls_conn_t *t,
                       const script_t *o) {
  int r;
  CHECK(client_start(t, cfg, sizeof(cli_rx), sizeof(cli_tx), HOST) == 0);
  if ((r = script(t, o)) != 0)
    return 1000 + r;
  tls_input(t, resp, resp_len);
  return 0;
}

static int scripted(tls_conn_t *t, const script_t *o) {
  return scripted_as(&cli, t, o);
}

/* The client's closing flight: (empty Certificate,) Finished, checked */
static int client_flight_ok(tls_conn_t *t, int cert_expected) {
  uint8_t rec[256], h[32], mac[32], type;
  const uint8_t *out;
  size_t n = tls_tx_pending(t, &out), off = 0;
  int r;
  CHECK(n > 5 && n < sizeof(rec));
  memcpy(rec, out, n);
  r = tls_record_open(&c, &sp.rd, rec, n, &type);
  CHECK(r > 0 && type == TLS_CT_HANDSHAKE && (size_t)r + 22 == n);
  if (cert_expected) {
    CHECK(memcmp(rec + 5, "\x0b\x00\x00\x04\x00\x00\x00\x00", 8) == 0);
    c.hash_update(&sp.th, rec + 5, 8);
    off = 8;
  }
  CHECK((size_t)r == off + 36);
  CHECK(memcmp(rec + 5 + off, "\x14\x00\x00\x20", 4) == 0);
  c.hash_peek(&sp.th, h);
  tls_finished_mac(&c, sp.c_hs, h, mac);
  CHECK(memcmp(rec + 9 + off, mac, 32) == 0);
  tls_tx_done(t, n);
  tls_traffic_keys(&c, sp.c_ap, &sp.rd);
  return 0;
}

static int script_refused_as(const tls_config_t *cfg, const script_t *o,
                             uint8_t alert) {
  tls_conn_t t;
  int r;
  if ((r = scripted_as(cfg, &t, o)) != 0)
    return r;
  CHECK(tls_state(&t) == TLS_STATE_ERROR);
  if (t.alert != alert)
    return 2000 + t.alert;
  CHECK(cli_evts == TLS_EVT_ERROR);
  return 0;
}

static int script_refused(const script_t *o, uint8_t alert) {
  return script_refused_as(&cli, o, alert);
}

TEST(test_scripted_handshake) {
  /* REQ-TLS-010..017 */
  tls_conn_t t;
  script_t o;
  uint8_t rec[128], buf[16];
  size_t n;
  memset(&o, 0, sizeof(o));
  ASSERT_EQ(scripted(&t, &o), 0);
  ASSERT_EQ(sp.sni, 1);
  ASSERT_EQ(sp.ch_sid_len, 0);
  ASSERT_EQ(tls_state(&t), TLS_STATE_CONNECTED);
  ASSERT_EQ(client_flight_ok(&t, 0), 0);
  /* application data both ways */
  memcpy(rec + 5, "hi", 2);
  n = tls_record_seal(&c, &sp.wr, TLS_CT_APPLICATION_DATA, rec, 2);
  ASSERT_EQ(tls_input(&t, rec, n), n);
  ASSERT_EQ(tls_read(&t, buf, sizeof(buf)), 2);
  ASSERT_EQ(tls_write(&t, (const uint8_t *)"yo", 2), 2);
  {
    const uint8_t *out;
    uint8_t type;
    n = tls_tx_pending(&t, &out);
    memcpy(rec, out, n);
    ASSERT_EQ(tls_record_open(&c, &sp.rd, rec, n, &type), 2);
    ASSERT_MEM_EQ(rec + 5, "yo", 2);
  }
}

TEST(test_scripted_ccs_accepted) {
  tls_conn_t t;
  script_t o;
  memset(&o, 0, sizeof(o));
  o.ccs = 1;
  ASSERT_EQ(scripted(&t, &o), 0);
  ASSERT_EQ(tls_state(&t), TLS_STATE_CONNECTED);
}

TEST(test_scripted_server_name_acknowledged) {
  tls_conn_t t;
  script_t o;
  memset(&o, 0, sizeof(o));
  o.ee_sni = 1;
  o.ee_ext = TLS_EXT_SUPPORTED_GROUPS; /* the server's preference */
  ASSERT_EQ(scripted(&t, &o), 0);
  ASSERT_EQ(tls_state(&t), TLS_STATE_CONNECTED);
}

TEST(test_scripted_certificate_request) {
  /* No client certificate: an empty Certificate before Finished */
  tls_conn_t t;
  script_t o;
  memset(&o, 0, sizeof(o));
  o.cert_req = 1;
  ASSERT_EQ(scripted(&t, &o), 0);
  ASSERT_EQ(tls_state(&t), TLS_STATE_CONNECTED);
  ASSERT_EQ(client_flight_ok(&t, 1), 0);
}

TEST(test_scripted_ticket_ignored) {
  tls_conn_t t;
  script_t o;
  uint8_t rec[128], buf[8];
  size_t n;
  memset(&o, 0, sizeof(o));
  ASSERT_EQ(scripted(&t, &o), 0);
  /* NewSessionTicket and data in one go */
  memcpy(rec + 5,
         "\x04\x00\x00\x0d\x00\x00\x0e\x10\x01\x02\x03\x04\x00\x00\x01\x55"
         "\x00",
         17);
  n = tls_record_seal(&c, &sp.wr, TLS_CT_HANDSHAKE, rec, 17);
  memcpy(rec + n + 5, "ok", 2);
  n += tls_record_seal(&c, &sp.wr, TLS_CT_APPLICATION_DATA, rec + n, 2);
  ASSERT_EQ(tls_input(&t, rec, n), n);
  ASSERT_EQ(tls_state(&t), TLS_STATE_CONNECTED);
  ASSERT_EQ(tls_read(&t, buf, sizeof(buf)), 2);
}

TEST(test_scripted_refusals_server_hello) {
  script_t o;
  memset(&o, 0, sizeof(o));
  o.bad_sid = 1;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
  memset(&o, 0, sizeof(o));
  o.bad_suite = 1;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
  memset(&o, 0, sizeof(o));
  o.bad_comp = 1;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
  memset(&o, 0, sizeof(o));
  o.no_versions = 1; /* TLS 1.2 */
  ASSERT_EQ(script_refused(&o, TLS_ALERT_PROTOCOL_VERSION), 0);
  memset(&o, 0, sizeof(o));
  o.version = 0x0303;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
  memset(&o, 0, sizeof(o));
  o.group = TLS_GROUP_SECP256R1; /* no share was offered for it */
  ASSERT_EQ(script_refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
  memset(&o, 0, sizeof(o));
  o.no_key_share = 1;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_MISSING_EXTENSION), 0);
  memset(&o, 0, sizeof(o));
  o.dup_versions = 1;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
  memset(&o, 0, sizeof(o));
  o.sh_ext = TLS_EXT_SIGNATURE_ALGORITHMS; /* not for a ServerHello */
  ASSERT_EQ(script_refused(&o, TLS_ALERT_UNSUPPORTED_EXTENSION), 0);
  memset(&o, 0, sizeof(o));
  o.hrr = 1; /* the HRR random on a full ServerHello: its key_share is
                not a selected_group */
  ASSERT_EQ(script_refused(&o, TLS_ALERT_DECODE_ERROR), 0);
}

TEST(test_scripted_refusals_more) {
  script_t o;
  memset(&o, 0, sizeof(o));
  o.long_versions = 1;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_DECODE_ERROR), 0);
  memset(&o, 0, sizeof(o));
  o.empty_entry = 1;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_DECODE_ERROR), 0);
  memset(&o, 0, sizeof(o));
  o.cert_req = 2;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_UNEXPECTED_MESSAGE), 0);
  memset(&o, 0, sizeof(o));
  o.ee_sni = 2; /* the acknowledgement is empty (RFC 6066 §3) */
  ASSERT_EQ(script_refused(&o, TLS_ALERT_UNSUPPORTED_EXTENSION), 0);
  memset(&o, 0, sizeof(o));
  o.chain = 7; /* more than verify_chain is given */
  ASSERT_EQ(script_refused(&o, TLS_ALERT_BAD_CERTIFICATE), 0);
}

TEST(test_scripted_longest_chain) {
  /* Six certificates (the leaf, then repeats of it, which the backend
   * skips on its way to the trust anchor) are all passed on */
  tls_conn_t t;
  script_t o;
  memset(&o, 0, sizeof(o));
  o.chain = 6;
  ASSERT_EQ(scripted(&t, &o), 0);
  ASSERT_EQ(tls_state(&t), TLS_STATE_CONNECTED);
}

TEST(test_scripted_message_beside_kept_certificate) {
  /* The Certificate stays in rx until CertificateVerify is checked: a
   * message too big for what is left is refused at once */
  tls_conn_t t;
  script_t o;
  memset(&o, 0, sizeof(o));
  o.cv_len_lie = 1;
  ASSERT_EQ(client_start(&t, &cli, 1024, sizeof(cli_tx), HOST), 0);
  ASSERT_EQ(script(&t, &o), 0);
  tls_input(&t, resp, resp_len);
  ASSERT_EQ(tls_state(&t), TLS_STATE_ERROR);
  ASSERT_EQ(t.alert, TLS_ALERT_RECORD_OVERFLOW);
}

TEST(test_scripted_ccs_refused_after_handshake) {
  tls_conn_t t;
  script_t o;
  memset(&o, 0, sizeof(o));
  ASSERT_EQ(scripted(&t, &o), 0);
  ASSERT_EQ(tls_state(&t), TLS_STATE_CONNECTED);
  tls_input(&t, (const uint8_t *)"\x14\x03\x03\x00\x01\x01", 6);
  ASSERT_EQ(tls_state(&t), TLS_STATE_ERROR);
  ASSERT_EQ(t.alert, TLS_ALERT_UNEXPECTED_MESSAGE);
}

TEST(test_key_share_wiped) {
  static const uint8_t zero[TLS_KX_PRIV_MAX];
  tls_conn_t t;
  script_t o;
  memset(&o, 0, sizeof(o));
  ASSERT_EQ(scripted(&t, &o), 0);
  ASSERT_MEM_EQ(t.kx_priv, zero, sizeof(zero));
}

TEST(test_scripted_refusals_encrypted_extensions) {
  script_t o;
  memset(&o, 0, sizeof(o));
  o.ee_ext = 16; /* ALPN: never offered */
  ASSERT_EQ(script_refused(&o, TLS_ALERT_UNSUPPORTED_EXTENSION), 0);
  memset(&o, 0, sizeof(o));
  o.cert_req = 1;
  o.cert_req_ctx = 1;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
}

TEST(test_scripted_refusals_certificate) {
  script_t o;
  memset(&o, 0, sizeof(o));
  o.empty_chain = 1;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_DECODE_ERROR), 0);
  memset(&o, 0, sizeof(o));
  o.cert_ctx = 1;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
  memset(&o, 0, sizeof(o));
  o.no_certificate = 1; /* straight to Finished: no authentication */
  ASSERT_EQ(script_refused(&o, TLS_ALERT_UNEXPECTED_MESSAGE), 0);
}

TEST(test_scripted_refusals_certificate_verify) {
  /* REQ-TLS-015 */
  script_t o;
  memset(&o, 0, sizeof(o));
  o.bad_sig = 1;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_DECRYPT_ERROR), 0);
  memset(&o, 0, sizeof(o));
  o.sign_key = &rsa_key; /* not the certificate's key */
  o.scheme = TLS_SIG_RSA_PSS_RSAE_SHA256;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_DECRYPT_ERROR), 0);
  memset(&o, 0, sizeof(o));
  o.scheme = 0x0503; /* ecdsa_secp384r1_sha384: not offered */
  ASSERT_EQ(script_refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
}

TEST(test_scripted_refusals_finished) {
  /* REQ-TLS-016 */
  script_t o;
  memset(&o, 0, sizeof(o));
  o.bad_fin = 1;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_DECRYPT_ERROR), 0);
}

/* The data of extension @p type in the client's pending ClientHello */
static const uint8_t *ch_ext(tls_conn_t *t, uint16_t type, size_t *len) {
  const uint8_t *out, *q;
  size_t elen;
  tls_tx_pending(t, &out);
  q = out + 5 + 4 + 2 + 32;
  q += 1 + q[0];
  q += 2 + be16(q);
  q += 1 + q[0];
  elen = be16(q);
  q += 2;
  while (elen >= 4) {
    size_t l = be16(q + 2);
    if (be16(q) == type) {
      *len = l;
      return q + 4;
    }
    q += 4 + l;
    elen -= 4 + l;
  }
  return NULL;
}

TEST(test_client_hello_contents) {
  /* REQ-TLS-010..013: TLS 1.3 only, our suite, a key share, signature
   * algorithms, server_name for a DNS name but not for an address */
  tls_conn_t t;
  const uint8_t *out, *e;
  size_t n;
  ASSERT_EQ(client_start(&t, &cli, sizeof(cli_rx), sizeof(cli_tx), HOST), 0);
  n = tls_tx_pending(&t, &out);
  ASSERT_TRUE(n > 0);
  /* no session id; TLS_AES_128_GCM_SHA256 only; null compression */
  ASSERT_MEM_EQ(out + 5 + 4 + 2 + 32, "\x00\x00\x02\x13\x01\x01\x00", 7);
  e = ch_ext(&t, TLS_EXT_SUPPORTED_VERSIONS, &n);
  ASSERT_TRUE(e && n == 3 && memcmp(e, "\x02\x03\x04", 3) == 0);
  e = ch_ext(&t, TLS_EXT_SIGNATURE_ALGORITHMS, &n);
  ASSERT_TRUE(e && n == 6 && memcmp(e, "\x00\x04\x04\x03\x08\x04", 6) == 0);
  e = ch_ext(&t, TLS_EXT_SUPPORTED_GROUPS, &n);
  ASSERT_TRUE(e && n == 6 && memcmp(e, "\x00\x04\x00\x1d\x00\x17", 6) == 0);
  e = ch_ext(&t, TLS_EXT_KEY_SHARE, &n);
  ASSERT_TRUE(e && n == 38 && memcmp(e, "\x00\x24\x00\x1d\x00\x20", 6) == 0);
  e = ch_ext(&t, TLS_EXT_SERVER_NAME, &n);
  ASSERT_TRUE(e && n == 5 + strlen(HOST));
  ASSERT_MEM_EQ(e, "\x00\x14\x00\x00\x11", 5);
  ASSERT_MEM_EQ(e + 5, HOST, strlen(HOST));

  ASSERT_EQ(client_start(&t, &cli, sizeof(cli_rx), sizeof(cli_tx),
                         "10.0.0.2"),
            0);
  ASSERT_NULL(ch_ext(&t, TLS_EXT_SERVER_NAME, &n));
  ASSERT_NOT_NULL(ch_ext(&t, TLS_EXT_KEY_SHARE, &n));
  ASSERT_EQ(client_start(&t, &cli, sizeof(cli_rx), sizeof(cli_tx), "fe80::1"),
            0);
  ASSERT_NULL(ch_ext(&t, TLS_EXT_SERVER_NAME, &n));
  ASSERT_EQ(client_start(&t, &cli, sizeof(cli_rx), sizeof(cli_tx), NULL), 0);
  ASSERT_NULL(ch_ext(&t, TLS_EXT_SERVER_NAME, &n));
}

TEST(test_connect_checks) {
  tls_conn_t t;
  char longname[300];
  memset(longname, 'a', sizeof(longname) - 1);
  longname[sizeof(longname) - 1] = 0;
  ASSERT_EQ(tls_init(&t, &cli, cli_rx, sizeof(cli_rx), cli_tx, sizeof(cli_tx)),
            0);
  ASSERT_EQ(tls_connect(&t, longname), -1);
  ASSERT_EQ(tls_connect(&t, HOST), 0);
  ASSERT_EQ(tls_connect(&t, HOST), -1); /* already started */
  ASSERT_EQ(tls_accept(&t), -1);
}

/* ══ Pre-shared keys (REQ-TLS-023/024) ════════════════════════════ */

TEST(test_psk_dhe_with_our_server) {
  /* No trust anchors on the client: the PSK alone authenticates */
  ASSERT_EQ(pair(&cli_psk, &srv_psk, HOST, 65536), 0);
  ASSERT_EQ(tls_state(&cl), TLS_STATE_CONNECTED);
  ASSERT_EQ(tls_state(&sv), TLS_STATE_CONNECTED);
  ASSERT_EQ(cl.group, TLS_GROUP_X25519);
}

TEST(test_psk_ke_with_our_server) {
  ASSERT_EQ(pair(&cli_psk_ke, &srv_psk, HOST, 65536), 0);
  ASSERT_EQ(tls_state(&cl), TLS_STATE_CONNECTED);
  ASSERT_EQ(cl.group, 0);
  ASSERT_EQ(sv.group, 0);
}

TEST(test_psk_both_modes_with_psk_only_server) {
  uint8_t buf[8];
  ASSERT_EQ(pair(&cli_psk_both, &srv_psk_only, HOST, 1), 0);
  ASSERT_EQ(tls_state(&cl), TLS_STATE_CONNECTED);
  ASSERT_EQ(cl.group, TLS_GROUP_X25519);
  ASSERT_EQ(tls_write(&cl, (const uint8_t *)"psk", 3), 3);
  shuttle(&cl, &sv, 65536);
  ASSERT_EQ(tls_read(&sv, buf, sizeof(buf)), 3);
}

TEST(test_psk_ke_chosen_by_server) {
  /* Both modes offered, a psk_ke-only server: no (EC)DHE after all */
  tls_config_t ke = srv_psk;
  ke.psk_modes = TLS_PSK_KE;
  ASSERT_EQ(pair(&cli_psk_both, &ke, HOST, 65536), 0);
  ASSERT_EQ(tls_state(&cl), TLS_STATE_CONNECTED);
  ASSERT_EQ(cl.group, 0);
}

TEST(test_psk_unknown_to_server_falls_back) {
  /* Another identity: certificates, checked against the trust anchors */
  ASSERT_EQ(pair(&cli_psk_other, &srv_psk, HOST, 65536), 0);
  ASSERT_EQ(tls_state(&cl), TLS_STATE_CONNECTED);
}

TEST(test_psk_wrong_key) {
  /* Same identity, another key: the binder fails */
  static const uint8_t other[32] = {1};
  tls_config_t wrong = cli_psk;
  wrong.psk = other;
  ASSERT_EQ(pair(&wrong, &srv_psk, HOST, 65536), 0);
  ASSERT_EQ(tls_state(&sv), TLS_STATE_ERROR);
  ASSERT_EQ(sv.alert, TLS_ALERT_DECRYPT_ERROR);
  ASSERT_EQ(tls_state(&cl), TLS_STATE_ERROR);
  ASSERT_EQ(cl.alert, TLS_ALERT_DECRYPT_ERROR);
}

TEST(test_psk_client_hello) {
  /* psk_key_exchange_modes; pre_shared_key last, with a binder over the
   * ClientHello up to it; psk_ke only: no key share, no groups */
  tls_conn_t t;
  const uint8_t *out, *e, *q;
  size_t n, elen, last = 0, trunc;
  uint8_t early[32], h[32], b[32];
  tls_hash_t th;
  ASSERT_EQ(client_start(&t, &cli_psk_both, sizeof(cli_rx), sizeof(cli_tx),
                         HOST),
            0);
  e = ch_ext(&t, TLS_EXT_PSK_KEY_EXCHANGE_MODES, &n);
  ASSERT_TRUE(e && n == 3 && memcmp(e, "\x02\x01\x00", 3) == 0);
  e = ch_ext(&t, TLS_EXT_PRE_SHARED_KEY, &n);
  ASSERT_TRUE(e && n == 2 + 2 + 8 + 4 + 2 + 33);
  ASSERT_MEM_EQ(e, "\x00\x0e\x00\x08" TEST_PSK_ID "\x00\x00\x00\x00", 16);
  ASSERT_MEM_EQ(e + 16, "\x00\x21\x20", 3);
  /* the last extension */
  n = tls_tx_pending(&t, &out);
  q = out + 5 + 4 + 2 + 32;
  q += 1 + q[0];
  q += 2 + be16(q);
  q += 1 + q[0];
  elen = be16(q);
  q += 2;
  while (elen) {
    last = be16(q);
    elen -= 4 + be16(q + 2);
    q += 4 + be16(q + 2);
  }
  ASSERT_EQ(last, TLS_EXT_PRE_SHARED_KEY);
  /* its binder */
  trunc = (size_t)(e + 16 - (out + 5));
  tls_early_secret(&c, test_psk, sizeof(test_psk), early);
  c.hash_init(&th);
  c.hash_update(&th, out + 5, trunc);
  c.hash_peek(&th, h);
  tls_psk_binder(&c, early, 0, h, b);
  ASSERT_MEM_EQ(e + 19, b, 32);
  ASSERT_NOT_NULL(ch_ext(&t, TLS_EXT_KEY_SHARE, &n));
  ASSERT_EQ(client_start(&t, &cli_psk_ke, sizeof(cli_rx), sizeof(cli_tx),
                         HOST),
            0);
  e = ch_ext(&t, TLS_EXT_PSK_KEY_EXCHANGE_MODES, &n);
  ASSERT_TRUE(e && n == 2 && memcmp(e, "\x01\x00", 2) == 0);
  ASSERT_NULL(ch_ext(&t, TLS_EXT_KEY_SHARE, &n));
  ASSERT_NULL(ch_ext(&t, TLS_EXT_SUPPORTED_GROUPS, &n));
}

TEST(test_scripted_psk) {
  tls_conn_t t;
  script_t o;
  memset(&o, 0, sizeof(o));
  o.psk = 1;
  ASSERT_EQ(scripted_as(&cli_psk, &t, &o), 0);
  ASSERT_EQ(tls_state(&t), TLS_STATE_CONNECTED);
  ASSERT_EQ(client_flight_ok(&t, 0), 0);
  memset(&o, 0, sizeof(o));
  o.psk = 1;
  o.psk_ke = 1;
  ASSERT_EQ(scripted_as(&cli_psk_ke, &t, &o), 0);
  ASSERT_EQ(tls_state(&t), TLS_STATE_CONNECTED);
  ASSERT_EQ(client_flight_ok(&t, 0), 0);
  /* the server declines the PSK: certificates */
  memset(&o, 0, sizeof(o));
  ASSERT_EQ(scripted_as(&cli_psk_both, &t, &o), 0);
  ASSERT_EQ(tls_state(&t), TLS_STATE_CONNECTED);
}

TEST(test_scripted_psk_refusals) {
  script_t o;
  memset(&o, 0, sizeof(o));
  o.psk = 1;
  o.psk_index = 1; /* only one identity was offered */
  ASSERT_EQ(script_refused_as(&cli_psk, &o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
  memset(&o, 0, sizeof(o));
  o.psk = 1; /* no PSK was offered */
  ASSERT_EQ(script_refused(&o, TLS_ALERT_UNSUPPORTED_EXTENSION), 0);
  memset(&o, 0, sizeof(o));
  o.psk = 1;
  o.psk_ke = 1; /* the client offered psk_dhe_ke only */
  ASSERT_EQ(script_refused_as(&cli_psk, &o, TLS_ALERT_MISSING_EXTENSION), 0);
  memset(&o, 0, sizeof(o));
  o.psk = 1;
  o.psk_cert = 1; /* no certificates in a PSK handshake */
  ASSERT_EQ(script_refused_as(&cli_psk, &o, TLS_ALERT_UNEXPECTED_MESSAGE),
            0);
  memset(&o, 0, sizeof(o));
  o.psk = 1;
  o.cert_req = 1; /* nor a CertificateRequest */
  ASSERT_EQ(script_refused_as(&cli_psk, &o, TLS_ALERT_UNEXPECTED_MESSAGE),
            0);
}

TEST(test_psk_connect_checks) {
  tls_conn_t t;
  tls_config_t bad = cli_psk;
  bad.psk_id_len = 0;
  ASSERT_EQ(tls_init(&t, &bad, cli_rx, sizeof(cli_rx), cli_tx, sizeof(cli_tx)),
            0);
  ASSERT_EQ(tls_connect(&t, HOST), -1);
  bad = cli_psk;
  bad.psk_len = 0;
  ASSERT_EQ(tls_init(&t, &bad, cli_rx, sizeof(cli_rx), cli_tx, sizeof(cli_tx)),
            0);
  ASSERT_EQ(tls_connect(&t, HOST), -1);
}

/* ══ HelloRetryRequest (RFC 8446 §4.1.4) ══════════════════════════ */

TEST(test_hrr_from_our_server) {
  /* A secp256r1-only server: our x25519 share draws an HRR */
  ASSERT_EQ(pair(&cli, &srv_p256, HOST, 65536), 0);
  ASSERT_EQ(tls_state(&cl), TLS_STATE_CONNECTED);
  ASSERT_EQ(cl.group, TLS_GROUP_SECP256R1);
  ASSERT_EQ(sv.group, TLS_GROUP_SECP256R1);
}

TEST(test_hrr_with_psk_from_our_server) {
  /* The second ClientHello's binder covers the HRR */
  ASSERT_EQ(pair(&cli_psk, &srv_psk_p256, HOST, 65536), 0);
  ASSERT_EQ(tls_state(&cl), TLS_STATE_CONNECTED);
  ASSERT_EQ(tls_psk_used(&cl), 1);
  ASSERT_EQ(cl.group, TLS_GROUP_SECP256R1);
}

TEST(test_p256_client) {
  /* A secp256r1-only client offers that share first: no HRR */
  const uint8_t *e;
  size_t n;
  tls_conn_t t;
  ASSERT_EQ(client_start(&t, &cli_p256, sizeof(cli_rx), sizeof(cli_tx), HOST),
            0);
  e = ch_ext(&t, TLS_EXT_SUPPORTED_GROUPS, &n);
  ASSERT_TRUE(e && n == 4 && memcmp(e, "\x00\x02\x00\x17", 4) == 0);
  e = ch_ext(&t, TLS_EXT_KEY_SHARE, &n);
  ASSERT_TRUE(e && n == 2 + 4 + 65 && be16(e + 2) == TLS_GROUP_SECP256R1);
  ASSERT_EQ(pair(&cli_p256, &srv_ec, HOST, 65536), 0);
  ASSERT_EQ(tls_state(&cl), TLS_STATE_CONNECTED);
  ASSERT_EQ(cl.group, TLS_GROUP_SECP256R1);
}

TEST(test_scripted_hrr) {
  tls_conn_t t;
  script_t o;
  memset(&o, 0, sizeof(o));
  o.hrr_group = TLS_GROUP_SECP256R1;
  ASSERT_EQ(scripted(&t, &o), 0);
  ASSERT_EQ(sp.share_group, TLS_GROUP_SECP256R1);
  ASSERT_EQ(tls_state(&t), TLS_STATE_CONNECTED);
  ASSERT_EQ(client_flight_ok(&t, 0), 0);
  /* a cookie is echoed; with no group asked for, the share stays x25519 */
  memset(&o, 0, sizeof(o));
  o.hrr_cookie = 1;
  ASSERT_EQ(scripted(&t, &o), 0);
  ASSERT_EQ(sp.cookie_echoed, 1);
  ASSERT_EQ(sp.share_group, TLS_GROUP_X25519);
  ASSERT_EQ(tls_state(&t), TLS_STATE_CONNECTED);
  memset(&o, 0, sizeof(o));
  o.hrr_group = TLS_GROUP_SECP256R1;
  o.hrr_cookie = 1;
  ASSERT_EQ(scripted(&t, &o), 0);
  ASSERT_EQ(sp.cookie_echoed, 1);
  ASSERT_EQ(tls_state(&t), TLS_STATE_CONNECTED);
  /* with a PSK */
  memset(&o, 0, sizeof(o));
  o.hrr_group = TLS_GROUP_SECP256R1;
  o.psk = 1;
  ASSERT_EQ(scripted_as(&cli_psk, &t, &o), 0);
  ASSERT_EQ(tls_state(&t), TLS_STATE_CONNECTED);
}

TEST(test_scripted_hrr_refusals) {
  script_t o;
  memset(&o, 0, sizeof(o));
  o.hrr_group = TLS_GROUP_X25519; /* the share it already has */
  ASSERT_EQ(script_refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
  memset(&o, 0, sizeof(o));
  o.hrr_group = 0x0018; /* not offered */
  ASSERT_EQ(script_refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
  memset(&o, 0, sizeof(o));
  o.hrr_group = TLS_GROUP_SECP256R1;
  o.hrr_twice = 1;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_UNEXPECTED_MESSAGE), 0);
  memset(&o, 0, sizeof(o));
  o.hrr_group = TLS_GROUP_X25519; /* a secp256r1-only client */
  ASSERT_EQ(script_refused_as(&cli_p256, &o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
  memset(&o, 0, sizeof(o));
  o.hrr_group = TLS_GROUP_SECP256R1; /* a client that sent no share */
  ASSERT_EQ(script_refused_as(&cli_psk_ke, &o, TLS_ALERT_ILLEGAL_PARAMETER),
            0);
  memset(&o, 0, sizeof(o));
  o.hrr_group = TLS_GROUP_SECP256R1;
  o.hrr_bad_sid = 1;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
  memset(&o, 0, sizeof(o));
  o.hrr_empty = 1; /* asks for nothing */
  ASSERT_EQ(script_refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
  memset(&o, 0, sizeof(o));
  o.hrr_group = TLS_GROUP_SECP256R1;
  o.hrr_version = 0x0303;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_ILLEGAL_PARAMETER), 0);
  memset(&o, 0, sizeof(o));
  o.hrr_group = TLS_GROUP_SECP256R1;
  o.hrr_no_versions = 1;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_PROTOCOL_VERSION), 0);
  memset(&o, 0, sizeof(o));
  o.hrr_cookie = 1;
  o.hrr_empty_cookie = 1;
  ASSERT_EQ(script_refused(&o, TLS_ALERT_DECODE_ERROR), 0);
  memset(&o, 0, sizeof(o));
  o.hrr_group = TLS_GROUP_SECP256R1;
  o.hrr_ext = TLS_EXT_SERVER_NAME + 16; /* ALPN: not for an HRR */
  ASSERT_EQ(script_refused(&o, TLS_ALERT_UNSUPPORTED_EXTENSION), 0);
}

TEST(test_client_random_differs) {
  tls_conn_t t;
  uint8_t r1[32];
  const uint8_t *out;
  ASSERT_EQ(client_start(&t, &cli, sizeof(cli_rx), sizeof(cli_tx), HOST), 0);
  tls_tx_pending(&t, &out);
  memcpy(r1, out + 5 + 4 + 2, 32);
  ASSERT_EQ(client_start(&t, &cli, sizeof(cli_rx), sizeof(cli_tx), HOST), 0);
  tls_tx_pending(&t, &out);
  ASSERT_TRUE(memcmp(r1, out + 5 + 4 + 2, 32) != 0);
}

int main(void) {
  fprintf(stderr, "=== TLS client handshake tests ===\n");
  if (tls_mbedtls_init(&be, &c) != 0 || tls_mbedtls_init(&be_noca, &c_noca) ||
      tls_mbedtls_init(&be_other, &c_other) ||
      tls_mbedtls_set_ca(&be, (const uint8_t *)ca_pem, sizeof(ca_pem)) ||
      tls_mbedtls_set_ca(&be_other, rsa_der, sizeof(rsa_der)) ||
      tls_mbedtls_parse_key(&be, &ec_key, (const uint8_t *)server_key_pem,
                            sizeof(server_key_pem)) ||
      tls_mbedtls_parse_key(&be, &rsa_key, (const uint8_t *)rsa_key_pem,
                            sizeof(rsa_key_pem))) {
    fprintf(stderr, "backend init failed\n");
    return 1;
  }
  srv_ec.crypto = &c;
  srv_ec.cert = ec_chain;
  srv_ec.cert_len = ec_chain_len;
  srv_ec.cert_count = 1;
  srv_ec.key = &ec_key;
  srv_ec.sig_scheme = TLS_SIG_ECDSA_SECP256R1_SHA256;
  srv_rsa = srv_ec;
  srv_rsa.cert = rsa_chain;
  srv_rsa.cert_len = rsa_chain_len;
  srv_rsa.key = &rsa_key;
  srv_rsa.sig_scheme = TLS_SIG_RSA_PSS_RSAE_SHA256;
  cli.crypto = &c;
  cli_noca.crypto = &c_noca;
  cli_other.crypto = &c_other;
  srv_psk = srv_ec;
  srv_psk.psk = test_psk;
  srv_psk.psk_len = sizeof(test_psk);
  srv_psk.psk_id = (const uint8_t *)TEST_PSK_ID;
  srv_psk.psk_id_len = sizeof(TEST_PSK_ID) - 1;
  srv_psk.psk_modes = TLS_PSK_KE | TLS_PSK_DHE_KE;
  srv_psk_only = srv_psk;
  srv_psk_only.cert = NULL;
  srv_psk_only.cert_len = NULL;
  srv_psk_only.cert_count = 0;
  srv_psk_only.key = NULL;
  srv_psk_only.sig_scheme = 0;
  cli_psk = cli_noca; /* no trust anchors: the PSK must do */
  cli_psk.psk = test_psk;
  cli_psk.psk_len = sizeof(test_psk);
  cli_psk.psk_id = (const uint8_t *)TEST_PSK_ID;
  cli_psk.psk_id_len = sizeof(TEST_PSK_ID) - 1;
  cli_psk_ke = cli_psk;
  cli_psk_ke.psk_modes = TLS_PSK_KE;
  cli_psk_both = cli_psk;
  cli_psk_both.crypto = &c; /* may fall back to certificates */
  cli_psk_both.psk_modes = TLS_PSK_KE | TLS_PSK_DHE_KE;
  cli_psk_other = cli_psk_both;
  cli_psk_other.psk_id = (const uint8_t *)"device-2";
  srv_p256 = srv_ec;
  srv_p256.groups = TLS_GROUPS_SECP256R1;
  srv_psk_p256 = srv_psk;
  srv_psk_p256.groups = TLS_GROUPS_SECP256R1;
  cli_p256 = cli;
  cli_p256.groups = TLS_GROUPS_SECP256R1;

  RUN_TEST(test_handshake_with_our_server);
  RUN_TEST(test_data_both_ways);
  RUN_TEST(test_close_notify_from_client);
  RUN_TEST(test_rsa_pss_server);
  RUN_TEST(test_byte_at_a_time);
  RUN_TEST(test_small_client_buffers);
  RUN_TEST(test_no_name_check);
  RUN_TEST(test_address_literal);
  RUN_TEST(test_refuse_wrong_name);
  RUN_TEST(test_refuse_wrong_address);
  RUN_TEST(test_refuse_untrusted_chain);
  RUN_TEST(test_refuse_without_trust_anchors);

  RUN_TEST(test_scripted_handshake);
  RUN_TEST(test_scripted_ccs_accepted);
  RUN_TEST(test_scripted_server_name_acknowledged);
  RUN_TEST(test_scripted_certificate_request);
  RUN_TEST(test_scripted_ticket_ignored);
  RUN_TEST(test_scripted_refusals_server_hello);
  RUN_TEST(test_scripted_refusals_more);
  RUN_TEST(test_scripted_longest_chain);
  RUN_TEST(test_scripted_message_beside_kept_certificate);
  RUN_TEST(test_scripted_ccs_refused_after_handshake);
  RUN_TEST(test_key_share_wiped);
  RUN_TEST(test_scripted_refusals_encrypted_extensions);
  RUN_TEST(test_scripted_refusals_certificate);
  RUN_TEST(test_scripted_refusals_certificate_verify);
  RUN_TEST(test_scripted_refusals_finished);
  RUN_TEST(test_client_hello_contents);
  RUN_TEST(test_connect_checks);

  RUN_TEST(test_psk_dhe_with_our_server);
  RUN_TEST(test_psk_ke_with_our_server);
  RUN_TEST(test_psk_both_modes_with_psk_only_server);
  RUN_TEST(test_psk_ke_chosen_by_server);
  RUN_TEST(test_psk_unknown_to_server_falls_back);
  RUN_TEST(test_psk_wrong_key);
  RUN_TEST(test_psk_client_hello);
  RUN_TEST(test_scripted_psk);
  RUN_TEST(test_scripted_psk_refusals);
  RUN_TEST(test_psk_connect_checks);

  RUN_TEST(test_hrr_from_our_server);
  RUN_TEST(test_hrr_with_psk_from_our_server);
  RUN_TEST(test_p256_client);
  RUN_TEST(test_scripted_hrr);
  RUN_TEST(test_scripted_hrr_refusals);
  RUN_TEST(test_client_random_differs);

  mbedtls_pk_free(&ec_key);
  mbedtls_pk_free(&rsa_key);
  tls_mbedtls_free(&be);
  tls_mbedtls_free(&be_noca);
  tls_mbedtls_free(&be_other);
  TEST_REPORT();
  return test_failures;
}
