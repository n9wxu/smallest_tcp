/**
 * @file test_dtls.c
 * @brief DTLS 1.3 (RFC 9147): records — the unified header, record number
 *        encryption, sequence number reconstruction, the replay window —
 *        with the Mbed TLS backend.
 */

#include "dtls.h"
#include "test_main.h"
#include "tls_crypto_mbedtls.h"
#include "tls_dtls13.h"
#include "tls_rfc8448.h"
#include "tls_test_data.h"
#include <string.h>

static tls_mbedtls_t be;
static tls_crypto_t c;
static mbedtls_pk_context ec_key;

/* The keys of one epoch, as each side derives them from its secret */
static void keys(dtls_keys_t *k) { dtls_keys_derive(&c, r3_s_hs_traffic, k); }

/* A record as the RFC describes it, built from the backend's primitives:
 * the header's sequence bits (@p seq_len 1 or 2, with or without the
 * length) are the plaintext ones in the AEAD's additional data and masked
 * on the wire.  Returns the record length. */
static size_t build_record(const dtls_keys_t *k, uint8_t epoch_bits,
                           uint64_t seq, int seq_len, int with_len,
                           uint8_t type, const uint8_t *content, size_t n,
                           size_t padding, uint8_t *out) {
  uint8_t nonce[12], mask[16];
  size_t h = 0, i, inner = n + 1 + padding;
  uint64_t s = seq;
  out[h++] = (uint8_t)(0x20 | (seq_len == 2 ? 0x08 : 0) |
                       (with_len ? 0x04 : 0) | (epoch_bits & 3));
  if (seq_len == 2)
    out[h++] = (uint8_t)(seq >> 8);
  out[h++] = (uint8_t)seq;
  if (with_len) {
    out[h++] = (uint8_t)((inner + 16) >> 8);
    out[h++] = (uint8_t)(inner + 16);
  }
  memcpy(out + h, content, n);
  out[h + n] = type;
  memset(out + h + n + 1, 0, padding);
  memcpy(nonce, k->k.iv, 12);
  for (i = 11; i >= 4; i--) {
    nonce[i] ^= (uint8_t)s;
    s >>= 8;
  }
  c.aead_seal(k->k.key, nonce, out, h, out + h, inner, out + h,
              out + h + inner);
  c.aes_block(k->sn, out + h, mask);
  out[1] ^= mask[0];
  if (seq_len == 2)
    out[2] ^= mask[1];
  return h + inner + 16;
}

/* Open @p rec with @p k; the content length, or -1 */
static int open_record(dtls_keys_t *k, const uint8_t *rec, size_t len,
                       uint8_t *out, uint8_t *type, uint64_t *seq) {
  dtls_rec_t r;
  if (dtls_record_parse(rec, len, &r) != 0)
    return -2;
  return dtls_record_open(&c, k, rec, &r, out, type, seq);
}

/* ══ Keys ═════════════════════════════════════════════════════════ */

TEST(test_keys_from_secret) {
  dtls_keys_t k;
  keys(&k);
  ASSERT_MEM_EQ(k.k.key, d13_key, 16);
  ASSERT_MEM_EQ(k.k.iv, d13_iv, 12);
  ASSERT_MEM_EQ(k.sn, d13_sn, 16);
  ASSERT_TRUE(k.k.seq == 0 && k.window == 0);
}

/* ══ Sealing ══════════════════════════════════════════════════════ */

/* 0x2C | epoch bits: fixed bits 001, no CID, 16-bit sequence number,
 * length present; the rest exactly as the RFC builds it */
TEST(test_seal_as_rfc_describes) {
  static const uint8_t hello[5] = {'h', 'e', 'l', 'l', 'o'};
  dtls_keys_t w, ref;
  uint8_t rec[64], want[64];
  size_t n, wn;
  keys(&w);
  keys(&ref);
  w.k.seq = 0x1234;
  memcpy(rec + DTLS_RECORD_HDR, hello, 5);
  n = dtls_record_seal(&c, &w, 7, TLS_CT_APPLICATION_DATA, rec, 5);
  wn = build_record(&ref, 7, 0x1234, 2, 1, TLS_CT_APPLICATION_DATA, hello, 5, 0,
                    want);
  ASSERT_EQ(n, 5 + DTLS_RECORD_OVERHEAD);
  ASSERT_EQ(n, wn);
  ASSERT_EQ(rec[0], 0x2F);
  ASSERT_MEM_EQ(rec, want, n);
  ASSERT_TRUE(w.k.seq == 0x1235);
}

/* The record number on the wire is masked: two records with consecutive
 * numbers do not show them */
TEST(test_seal_masks_the_record_number) {
  dtls_keys_t w;
  uint8_t a[64], b[64];
  keys(&w);
  memset(a + DTLS_RECORD_HDR, 'x', 4);
  memset(b + DTLS_RECORD_HDR, 'x', 4);
  dtls_record_seal(&c, &w, 3, TLS_CT_APPLICATION_DATA, a, 4);
  dtls_record_seal(&c, &w, 3, TLS_CT_APPLICATION_DATA, b, 4);
  ASSERT_FALSE(a[1] == 0 && a[2] == 0 && b[1] == 0 && b[2] == 1);
}

/* ══ Opening ══════════════════════════════════════════════════════ */

TEST(test_open_what_was_sealed) {
  dtls_keys_t w, r;
  uint8_t rec[64], out[64], type = 0;
  uint64_t seq = 99;
  int n;
  keys(&w);
  keys(&r);
  memcpy(rec + DTLS_RECORD_HDR, "ping", 4);
  dtls_record_seal(&c, &w, 2, TLS_CT_HANDSHAKE, rec, 4);
  n = open_record(&r, rec, 4 + DTLS_RECORD_OVERHEAD, out, &type, &seq);
  ASSERT_EQ(n, 4);
  ASSERT_MEM_EQ(out, "ping", 4);
  ASSERT_EQ(type, TLS_CT_HANDSHAKE);
  ASSERT_TRUE(seq == 0 && r.k.seq == 1 && r.window == 1);
}

/* REQ-DTLS-012: an 8-bit sequence number, and no length — the record
 * takes the rest of the datagram */
TEST(test_open_short_header) {
  dtls_keys_t k, r;
  uint8_t rec[64], out[64], type;
  uint64_t seq;
  dtls_rec_t h;
  size_t n;
  keys(&k);
  keys(&r);
  n = build_record(&k, 2, 0, 1, 0, TLS_CT_HANDSHAKE, (const uint8_t *)"abc", 3,
                   0, rec);
  ASSERT_EQ(dtls_record_parse(rec, n, &h), 0);
  ASSERT_EQ(h.hlen, 2);
  ASSERT_EQ(h.len, n - 2);
  ASSERT_EQ(h.epoch, 2);
  ASSERT_EQ(dtls_record_open(&c, &r, rec, &h, out, &type, &seq), 3);
  ASSERT_MEM_EQ(out, "abc", 3);
}

/* With a length, the record ends there: what follows is the next one */
TEST(test_parse_uses_the_length) {
  dtls_keys_t k;
  uint8_t rec[128];
  dtls_rec_t h;
  size_t n;
  keys(&k);
  n = build_record(&k, 3, 5, 1, 1, TLS_CT_APPLICATION_DATA,
                   (const uint8_t *)"abc", 3, 0, rec);
  memset(rec + n, 0xAA, 20); /* another record's bytes */
  ASSERT_EQ(dtls_record_parse(rec, n + 20, &h), 0);
  ASSERT_EQ(h.hlen, 4);
  ASSERT_EQ(h.len, n - 4);
}

/* REQ-DTLS-013, -014: a CID we never negotiated, a first byte that is no
 * DTLSCiphertext, a header or length running past the datagram */
TEST(test_parse_refuses) {
  uint8_t rec[40];
  dtls_rec_t h;
  memset(rec, 0, sizeof(rec));
  rec[0] = 0x3C; /* C set */
  ASSERT_EQ(dtls_record_parse(rec, sizeof(rec), &h), -1);
  rec[0] = 0x4C; /* 010: not DTLS 1.3 ciphertext */
  ASSERT_EQ(dtls_record_parse(rec, sizeof(rec), &h), -1);
  rec[0] = 0x2C; /* header of 5 bytes, only 4 there */
  ASSERT_EQ(dtls_record_parse(rec, 4, &h), -1);
  rec[3] = 0;
  rec[4] = 36; /* 36 bytes claimed, 35 there */
  ASSERT_EQ(dtls_record_parse(rec, 40, &h), -1);
  rec[4] = 35;
  ASSERT_EQ(dtls_record_parse(rec, 40, &h), 0);
}

/* REQ-DTLS-016: less than 16 bytes of ciphertext cannot be unmasked */
TEST(test_open_refuses_short_ciphertext) {
  dtls_keys_t r;
  uint8_t rec[40], out[40], type;
  uint64_t seq;
  memset(rec, 0x55, sizeof(rec));
  rec[0] = 0x2E;
  rec[3] = 0;
  rec[4] = 15;
  keys(&r);
  ASSERT_EQ(open_record(&r, rec, 20, out, &type, &seq), -1);
}

/* REQ-DTLS-022: a forged or damaged record is refused, and the window
 * does not move (§4.5.1) */
TEST(test_open_refuses_tampering) {
  dtls_keys_t w, r;
  uint8_t rec[64], out[64], type;
  uint64_t seq;
  keys(&w);
  keys(&r);
  w.k.seq = 100;
  memcpy(rec + DTLS_RECORD_HDR, "data", 4);
  dtls_record_seal(&c, &w, 3, TLS_CT_APPLICATION_DATA, rec, 4);
  rec[DTLS_RECORD_HDR + 2] ^= 1;
  ASSERT_EQ(open_record(&r, rec, 4 + DTLS_RECORD_OVERHEAD, out, &type, &seq),
            -1);
  ASSERT_TRUE(r.k.seq == 0 && r.window == 0);
  rec[DTLS_RECORD_HDR + 2] ^= 1;
  rec[0] ^= 0x01; /* the header is authenticated */
  ASSERT_EQ(open_record(&r, rec, 4 + DTLS_RECORD_OVERHEAD, out, &type, &seq),
            -1);
}

/* Padding is stripped; a record of nothing but zeros has no type */
TEST(test_open_strips_padding) {
  dtls_keys_t k, r;
  uint8_t rec[64], out[64], type;
  uint64_t seq;
  size_t n;
  keys(&k);
  keys(&r);
  n = build_record(&k, 3, 0, 2, 1, TLS_CT_ALERT, (const uint8_t *)"\x01\x00", 2,
                   7, rec);
  ASSERT_EQ(open_record(&r, rec, n, out, &type, &seq), 2);
  ASSERT_EQ(type, TLS_CT_ALERT);
  n = build_record(&k, 3, 1, 2, 1, 0, NULL, 0, 4, rec);
  ASSERT_EQ(open_record(&r, rec, n, out, &type, &seq), -1);
}

/* ══ Record numbers ═══════════════════════════════════════════════ */

/* REQ-DTLS-017: the number closest to the next one expected */
TEST(test_seq_expand) {
  ASSERT_TRUE(dtls_seq_expand(0, 0x05, 8) == 0x05);
  ASSERT_TRUE(dtls_seq_expand(0x1FE, 0x01, 8) == 0x201); /* wrapped */
  ASSERT_TRUE(dtls_seq_expand(0x1FE, 0xFD, 8) == 0x1FD);
  ASSERT_TRUE(dtls_seq_expand(0x201, 0xFF, 8) == 0x1FF); /* late */
  ASSERT_TRUE(dtls_seq_expand(0x10000, 0xFFFF, 16) == 0xFFFF);
  ASSERT_TRUE(dtls_seq_expand(0x1FFF0, 0x0005, 16) == 0x20005);
  ASSERT_TRUE(dtls_seq_expand(0x10, 0xF0, 8) == 0xF0); /* none below 0 */
  /* half a window either way: forward, as in RFC 9000 §A.3 */
  ASSERT_TRUE(dtls_seq_expand(0x180, 0x00, 8) == 0x200);
}

/* The full number is recovered from its low byte and opens the record */
TEST(test_open_reconstructs_the_number) {
  dtls_keys_t k, r;
  uint8_t rec[64], out[64], type;
  uint64_t seq = 0;
  size_t n;
  keys(&k);
  keys(&r);
  r.k.seq = 0x1FE;
  n = build_record(&k, 3, 0x201, 1, 1, TLS_CT_APPLICATION_DATA,
                   (const uint8_t *)"z", 1, 0, rec);
  ASSERT_EQ(open_record(&r, rec, n, out, &type, &seq), 1);
  ASSERT_TRUE(seq == 0x201 && r.k.seq == 0x202);
}

/* REQ-DTLS-021: duplicates refused, reordering within the window taken,
 * anything older than the window refused */
TEST(test_replay_window) {
  dtls_keys_t k, r;
  uint8_t rec[64], out[64], type;
  uint64_t seq;
  size_t n;
  keys(&k);
  keys(&r);
#define REC(s)                                                                 \
  (n = build_record(&k, 3, (s), 2, 1, TLS_CT_APPLICATION_DATA,                 \
                    (const uint8_t *)"q", 1, 0, rec),                          \
   open_record(&r, rec, n, out, &type, &seq))
  ASSERT_EQ(REC(10), 1);
  ASSERT_EQ(REC(10), -1); /* again */
  ASSERT_EQ(REC(9), 1);   /* late, new */
  ASSERT_EQ(REC(9), -1);
  ASSERT_EQ(REC(50), 1);  /* the window moves */
  ASSERT_EQ(REC(18), -1); /* 32 behind: out of the window */
  ASSERT_EQ(REC(19), 1);  /* 31 behind: in it */
  ASSERT_EQ(REC(49), 1);
  ASSERT_EQ(REC(49), -1);
  ASSERT_EQ(REC(1000), 1); /* a jump past the window clears it */
  ASSERT_EQ(REC(999), 1);
#undef REC
}

/* ══ Connections: our client and our server over a memory network ══ */

static const uint8_t *const ec_chain[1] = {server_der};
static const uint16_t ec_chain_len[1] = {sizeof(server_der)};
static tls_config_t srv, srv_nocookie, cli;

#define HOST "pyro-dead01.local"
#define MTU 1200

static dtls_conn_t cl, sv;
static uint8_t cl_rx[4096], cl_tx[4096], sv_rx[4096], sv_tx[4096];
static uint8_t cl_evts, sv_evts;

static void on_cl(tls_conn_t *t, uint8_t e) {
  (void)t;
  cl_evts |= e;
}
static void on_sv(tls_conn_t *t, uint8_t e) {
  (void)t;
  sv_evts |= e;
}

/* The network: datagrams on their way, [0] to the server, [1] to the
 * client; everything sent is also kept in the trace */
#define NET_MAX 48
typedef struct {
  uint8_t b[1600];
  size_t n;
} dg_t;
static dg_t wire[2][NET_MAX], trace[2][NET_MAX];
static int wire_n[2], trace_n[2];
static int reorder; /* deliver each batch last first */

/* What happens to the @p i th datagram sent in direction @p dir: 0
 * delivered, 1 lost, 2 duplicated */
static int (*fate)(int dir, int i, const uint8_t *dg, size_t n);

static void net_reset(void) {
  wire_n[0] = wire_n[1] = trace_n[0] = trace_n[1] = 0;
  reorder = 0;
  fate = NULL;
}

static void put(int dir, const uint8_t *p, size_t n) {
  if (wire_n[dir] < NET_MAX) {
    memcpy(wire[dir][wire_n[dir]].b, p, n);
    wire[dir][wire_n[dir]++].n = n;
  }
}

static void collect(dtls_conn_t *d, int dir) {
  const uint8_t *p;
  size_t n;
  while ((n = dtls_pending(d, &p)) > 0) {
    int f = fate ? fate(dir, trace_n[dir], p, n) : 0;
    if (trace_n[dir] < NET_MAX) {
      memcpy(trace[dir][trace_n[dir]].b, p, n);
      trace[dir][trace_n[dir]].n = n;
    }
    trace_n[dir]++;
    if (f != 1)
      put(dir, p, n);
    if (f == 2)
      put(dir, p, n);
    dtls_sent(d);
  }
}

static int deliver(int dir, dtls_conn_t *to) {
  static dg_t batch[NET_MAX];
  int i, k = wire_n[dir];
  memcpy(batch, wire[dir], (size_t)k * sizeof(dg_t));
  wire_n[dir] = 0;
  for (i = 0; i < k; i++) {
    const dg_t *g = &batch[reorder ? k - 1 - i : i];
    (void)dtls_input(to, g->b, g->n);
  }
  return k;
}

/* Run the pair; when nothing moves, a second passes — @p seconds of them */
static void run(int seconds) {
  for (;;) {
    collect(&cl, 0);
    collect(&sv, 1);
    if (deliver(0, &sv) + deliver(1, &cl) > 0)
      continue;
    if (seconds-- <= 0)
      return;
    dtls_tick(&cl, 1000);
    dtls_tick(&sv, 1000);
  }
}

static int client_start(const tls_config_t *cfg, size_t mtu) {
  if (dtls_init(&cl, cfg, cl_rx, sizeof(cl_rx), cl_tx, sizeof(cl_tx), mtu))
    return -1;
  cl.tls.on_event = on_cl;
  cl_evts = 0;
  return dtls_connect(&cl, HOST);
}

static int server_start(const tls_config_t *cfg, size_t mtu) {
  if (dtls_init(&sv, cfg, sv_rx, sizeof(sv_rx), sv_tx, sizeof(sv_tx), mtu))
    return -1;
  sv.tls.on_event = on_sv;
  sv_evts = 0;
  return dtls_accept(&sv);
}

static int pair(const tls_config_t *ccfg, const tls_config_t *scfg, size_t mtu,
                int seconds) {
  net_reset();
  if (server_start(scfg, mtu) || client_start(ccfg, mtu))
    return -1;
  run(seconds);
  return 0;
}

static int connected(void) {
  return dtls_state(&cl) == TLS_STATE_CONNECTED &&
         dtls_state(&sv) == TLS_STATE_CONNECTED &&
         cl_evts == TLS_EVT_CONNECTED && sv_evts == TLS_EVT_CONNECTED;
}

TEST(test_handshake) {
  ASSERT_EQ(pair(&cli, &srv, MTU, 3), 0);
  ASSERT_TRUE(connected());
  ASSERT_EQ(cl.tls.group, TLS_GROUP_X25519);
  ASSERT_TRUE(dtls_peer_verified(&sv));
  ASSERT_TRUE(cl.wepoch == 3 && cl.repoch == 3 && sv.wepoch == 3 &&
              sv.repoch == 3);
}

/* SHA-256("HelloRetryRequest"), the random of a HelloRetryRequest */
static const uint8_t tls_hrr_random_for_tests[32] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c,
    0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
    0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};

/* ── Reading datagrams ── */

static size_t be16(const uint8_t *p) { return ((size_t)p[0] << 8) | p[1]; }
static size_t be24(const uint8_t *p) {
  return ((size_t)p[0] << 16) | be16(p + 1);
}

/* A DTLSPlaintext datagram's first handshake fragment: its body */
static const uint8_t *hs_body(const uint8_t *dg, size_t *len) {
  *len = be24(dg + 13 + 9);
  return dg + 13 + 12;
}

/* Extension @p type of a hello body (@p ch: a ClientHello), or NULL */
static const uint8_t *hello_ext(const uint8_t *b, int ch, uint16_t type,
                                size_t *len) {
  size_t off = 2 + 32, end;
  off += 1 + b[off]; /* session id */
  if (ch) {
    off += 1 + b[off];        /* legacy_cookie */
    off += 2 + be16(b + off); /* cipher_suites */
    off += 1 + b[off];        /* compression */
  } else {
    off += 3;
  }
  end = off + 2 + be16(b + off);
  for (off += 2; off + 4 <= end; off += 4 + be16(b + off + 2))
    if (be16(b + off) == type) {
      *len = be16(b + off + 2);
      return b + off + 4;
    }
  return NULL;
}

/* A DTLSPlaintext datagram carrying one handshake fragment: the bytes
 * [@p off, @p off + @p n) of a message whose body is @p body */
static size_t plain_hs(uint8_t *out, uint8_t type, const uint8_t *body,
                       size_t len, uint16_t mseq, uint16_t rseq, size_t off,
                       size_t n) {
  static const uint8_t hdr[3] = {22, 0xfe, 0xfd};
  memcpy(out, hdr, 3);
  memset(out + 3, 0, 6);
  out[9] = (uint8_t)(rseq >> 8);
  out[10] = (uint8_t)rseq;
  out[11] = (uint8_t)((12 + n) >> 8);
  out[12] = (uint8_t)(12 + n);
  out[13] = type;
  out[14] = (uint8_t)(len >> 16);
  out[15] = (uint8_t)(len >> 8);
  out[16] = (uint8_t)len;
  out[17] = (uint8_t)(mseq >> 8);
  out[18] = (uint8_t)mseq;
  out[19] = (uint8_t)(off >> 16);
  out[20] = (uint8_t)(off >> 8);
  out[21] = (uint8_t)off;
  out[22] = (uint8_t)(n >> 16);
  out[23] = (uint8_t)(n >> 8);
  out[24] = (uint8_t)n;
  memcpy(out + 25, body + off, n);
  return 25 + n;
}

/* The client's ClientHello (the first datagram it sends) */
static size_t first_client_hello(uint8_t *out) {
  const uint8_t *p;
  size_t n;
  net_reset();
  if (server_start(&srv, MTU) || client_start(&cli, MTU))
    return 0;
  n = dtls_pending(&cl, &p);
  memcpy(out, p, n);
  dtls_sent(&cl);
  return n;
}

/* ── Formats ── */

/* REQ-DTLS-002, -010, -030, -031: DTLSPlaintext, epoch 0, record 0; the
 * whole ClientHello as message 0; legacy_version {254, 253}, no session
 * id, an empty legacy_cookie, DTLS 1.3 in supported_versions */
TEST(test_client_hello_format) {
  uint8_t dg[1600];
  const uint8_t *b, *v;
  size_t n = first_client_hello(dg), len, vl;
  ASSERT_TRUE(n > 25);
  ASSERT_EQ(dg[0], TLS_CT_HANDSHAKE);
  ASSERT_TRUE(be16(dg + 1) == 0xfefd && be16(dg + 3) == 0);
  ASSERT_TRUE(be16(dg + 5) == 0 && be16(dg + 7) == 0 && be16(dg + 9) == 0);
  ASSERT_EQ(be16(dg + 11), n - 13);
  b = hs_body(dg, &len);
  ASSERT_EQ(dg[13], TLS_HS_CLIENT_HELLO);
  ASSERT_EQ(be24(dg + 14), len);                         /* length */
  ASSERT_TRUE(be16(dg + 17) == 0 && be24(dg + 19) == 0); /* seq, offset */
  ASSERT_EQ(len, n - 25);
  ASSERT_EQ(be16(b), 0xfefd);
  ASSERT_TRUE(b[34] == 0 && b[35] == 0); /* legacy_session_id, _cookie */
  v = hello_ext(b, 1, TLS_EXT_SUPPORTED_VERSIONS, &vl);
  ASSERT_TRUE(v && vl == 3 && v[0] == 2 && be16(v + 1) == 0xfefc);
}

/* REQ-DTLS-004, -005, -043: the server's first answer is a
 * HelloRetryRequest with a cookie; its ServerHello and HelloRetryRequest
 * say {254, 253}, echo no session id, select DTLS 1.3; nothing is a
 * change_cipher_spec */
TEST(test_server_hello_format) {
  const uint8_t *b, *v;
  size_t len, vl;
  int d, i;
  ASSERT_EQ(pair(&cli, &srv, MTU, 3), 0);
  ASSERT_TRUE(connected());
  b = hs_body(trace[1][0].b, &len); /* HelloRetryRequest */
  ASSERT_EQ(trace[1][0].b[13], TLS_HS_SERVER_HELLO);
  ASSERT_EQ(be16(b), 0xfefd);
  ASSERT_EQ(b[34], 0);
  v = hello_ext(b, 0, TLS_EXT_SUPPORTED_VERSIONS, &vl);
  ASSERT_TRUE(v && vl == 2 && be16(v) == 0xfefc);
  v = hello_ext(b, 0, TLS_EXT_COOKIE, &vl);
  ASSERT_TRUE(v && vl == 2 + 16 && be16(v) == 16);
  ASSERT_TRUE(hello_ext(b, 0, TLS_EXT_KEY_SHARE, &vl) == NULL);
  b = hs_body(trace[1][1].b, &len); /* ServerHello */
  ASSERT_EQ(be16(b), 0xfefd);
  ASSERT_EQ(b[34], 0);
  v = hello_ext(b, 0, TLS_EXT_SUPPORTED_VERSIONS, &vl);
  ASSERT_TRUE(v && be16(v) == 0xfefc);
  for (d = 0; d < 2; d++)
    for (i = 0; i < trace_n[d]; i++)
      ASSERT_TRUE(trace[d][i].b[0] != TLS_CT_CHANGE_CIPHER_SPEC);
}

/* REQ-DTLS-018, -011: epochs 0, 2, 3 as the handshake goes */
TEST(test_epochs) {
  ASSERT_EQ(pair(&cli, &srv, MTU, 3), 0);
  ASSERT_TRUE(connected());
  ASSERT_EQ(trace[0][0].b[0], TLS_CT_HANDSHAKE); /* ClientHello */
  ASSERT_EQ(trace[0][1].b[0], TLS_CT_HANDSHAKE); /* .. with the cookie */
  ASSERT_EQ(trace[0][2].b[0], 0x2E);             /* Finished: epoch 2 */
  ASSERT_EQ(trace[1][0].b[0], TLS_CT_HANDSHAKE); /* HelloRetryRequest */
  ASSERT_EQ(trace[1][1].b[0], TLS_CT_HANDSHAKE); /* ServerHello .. */
  ASSERT_EQ(trace[1][1].b[13 + be16(trace[1][1].b + 11)], 0x2E); /* .. EE.. */
  ASSERT_EQ(trace[1][2].b[0], 0x2F); /* the ACK: epoch 3 */
  ASSERT_EQ(trace_n[0], 3);
  ASSERT_EQ(trace_n[1], 3);
}

/* REQ-DTLS-043: configured not to, the server answers with a ServerHello */
TEST(test_no_cookie) {
  const uint8_t *b;
  size_t len;
  ASSERT_EQ(pair(&cli, &srv_nocookie, MTU, 3), 0);
  ASSERT_TRUE(connected());
  b = hs_body(trace[1][0].b, &len);
  ASSERT_TRUE(memcmp(b + 2, tls_hrr_random_for_tests, 32) != 0);
  ASSERT_EQ(trace_n[0], 2);
}

/* ── Refusals ── */

/* The server's answer to a crafted ClientHello: its state and alert */
static int server_refuses(const uint8_t *dg, size_t n, uint8_t alert) {
  const uint8_t *p;
  size_t k;
  if (dtls_input(&sv, dg, n) != -alert)
    return 0;
  k = dtls_pending(&sv, &p); /* the alert, in plaintext */
  return dtls_state(&sv) == TLS_STATE_ERROR && sv.tls.alert == alert &&
         k == 15 && p[0] == TLS_CT_ALERT && p[13] == 2 && p[14] == alert;
}

/* REQ-DTLS-003: a legacy_cookie in a DTLS 1.3 ClientHello */
TEST(test_refuse_legacy_cookie) {
  uint8_t dg[1600], body[1600], out[1600];
  const uint8_t *b;
  size_t len, n = first_client_hello(dg);
  ASSERT_TRUE(n > 0);
  b = hs_body(dg, &len);
  memcpy(body, b, 35);
  body[35] = 1; /* legacy_cookie: one byte */
  body[36] = 0xAA;
  memcpy(body + 37, b + 36, len - 36);
  n = plain_hs(out, TLS_HS_CLIENT_HELLO, body, len + 1, 0, 0, 0, len + 1);
  ASSERT_TRUE(server_refuses(out, n, TLS_ALERT_ILLEGAL_PARAMETER));
}

/* REQ-DTLS-001: a ClientHello offering DTLS 1.2 only */
TEST(test_refuse_dtls12) {
  uint8_t dg[1600];
  const uint8_t *b, *v;
  size_t len, vl, n = first_client_hello(dg);
  b = hs_body(dg, &len);
  v = hello_ext(b, 1, TLS_EXT_SUPPORTED_VERSIONS, &vl);
  ASSERT_TRUE(v != NULL);
  dg[(size_t)(v - dg) + 2] = 0xfd; /* fefc → fefd */
  ASSERT_TRUE(server_refuses(dg, n, TLS_ALERT_PROTOCOL_VERSION));
}

/* REQ-DTLS-044: the second ClientHello's cookie is not the one sent */
static int cookie_fate(int dir, int i, const uint8_t *dg, size_t n) {
  const uint8_t *b, *v;
  size_t len, vl;
  (void)n;
  if (dir != 0 || i != 1)
    return 0;
  b = hs_body(dg, &len);
  v = hello_ext(b, 1, TLS_EXT_COOKIE, &vl);
  if (v)
    ((uint8_t *)v)[5] ^= 1; /* (the network's copy is taken after this) */
  return 0;
}

TEST(test_refuse_wrong_cookie) {
  net_reset();
  ASSERT_EQ(server_start(&srv, MTU), 0);
  ASSERT_EQ(client_start(&cli, MTU), 0);
  fate = cookie_fate;
  run(0);
  ASSERT_EQ(dtls_state(&sv), TLS_STATE_ERROR);
  ASSERT_EQ(sv.tls.alert, TLS_ALERT_ILLEGAL_PARAMETER);
  ASSERT_FALSE(dtls_peer_verified(&sv));
}

/* REQ-DTLS-034: overlapping fragments must agree */
TEST(test_refuse_changed_bytes) {
  uint8_t dg[1600], body[1600], out[1600];
  const uint8_t *b;
  size_t len, n = first_client_hello(dg);
  ASSERT_TRUE(n > 0);
  b = hs_body(dg, &len);
  memcpy(body, b, len);
  n = plain_hs(out, TLS_HS_CLIENT_HELLO, body, len, 0, 0, 0, 100);
  ASSERT_EQ(dtls_input(&sv, out, n), 0);
  body[70] ^= 1;
  n = plain_hs(out, TLS_HS_CLIENT_HELLO, body, len, 0, 1, 50, len - 50);
  ASSERT_TRUE(server_refuses(out, n, TLS_ALERT_ILLEGAL_PARAMETER));
}

/* REQ-DTLS-034: fragments in any order, overlapping, repeated */
TEST(test_fragments_in_any_order) {
  uint8_t dg[1600], out[1600];
  const uint8_t *b, *p;
  size_t len, n = first_client_hello(dg);
  b = hs_body(dg, &len);
  n = plain_hs(out, TLS_HS_CLIENT_HELLO, b, len, 0, 0, 60, len - 60);
  ASSERT_EQ(dtls_input(&sv, out, n), 0); /* after a gap: not taken */
  ASSERT_EQ(dtls_pending(&sv, &p), 0);
  n = plain_hs(out, TLS_HS_CLIENT_HELLO, b, len, 0, 1, 0, 40);
  ASSERT_EQ(dtls_input(&sv, out, n), 0);
  n = plain_hs(out, TLS_HS_CLIENT_HELLO, b, len, 0, 2, 20, 40); /* overlap */
  ASSERT_EQ(dtls_input(&sv, out, n), 0);
  ASSERT_EQ(dtls_pending(&sv, &p), 0);
  n = plain_hs(out, TLS_HS_CLIENT_HELLO, b, len, 0, 3, 50, len - 50);
  ASSERT_EQ(dtls_input(&sv, out, n), 0);
  ASSERT_TRUE(dtls_pending(&sv, &p) > 0); /* whole: the HelloRetryRequest */
  ASSERT_EQ(p[13], TLS_HS_SERVER_HELLO);
}

/* ── Loss, duplication, reordering ── */

static int lose_dir, lose_index;
static int lose_one(int dir, int i, const uint8_t *dg, size_t n) {
  (void)dg;
  (void)n;
  return dir == lose_dir && i == lose_index;
}

/* REQ-DTLS-036, -038, -039: each datagram of the handshake lost once in
 * turn — the flight it was part of is sent again, the ACK too */
TEST(test_each_datagram_lost) {
  for (lose_dir = 0; lose_dir < 2; lose_dir++)
    for (lose_index = 0; lose_index < 3; lose_index++) {
      net_reset();
      ASSERT_EQ(server_start(&srv, MTU), 0);
      ASSERT_EQ(client_start(&cli, MTU), 0);
      fate = lose_one;
      run(10);
      ASSERT_TRUE(connected());
      ASSERT_TRUE(trace_n[lose_dir] >= 4); /* one more than without loss */
      ASSERT_TRUE(cl.fl_state == 0 && sv.fl_state == 0); /* all answered */
    }
}

static int duplicate_all(int dir, int i, const uint8_t *dg, size_t n) {
  (void)dir;
  (void)i;
  (void)dg;
  (void)n;
  return 2;
}

/* REQ-DTLS-032: every datagram twice */
TEST(test_duplicates) {
  net_reset();
  ASSERT_EQ(server_start(&srv, MTU), 0);
  ASSERT_EQ(client_start(&cli, MTU), 0);
  fate = duplicate_all;
  run(5);
  ASSERT_TRUE(connected());
}

static size_t largest;
static int measure(int dir, int i, const uint8_t *dg, size_t n) {
  (void)dir;
  (void)i;
  (void)dg;
  if (n > largest)
    largest = n;
  return 0;
}

/* REQ-DTLS-019, -020, -033: small datagrams — the flight in fragments */
TEST(test_small_mtu) {
  largest = 0;
  net_reset();
  ASSERT_EQ(server_start(&srv, 200), 0);
  ASSERT_EQ(client_start(&cli, 200), 0);
  fate = measure;
  run(3);
  ASSERT_TRUE(connected());
  ASSERT_TRUE(largest <= 200);
  ASSERT_TRUE(trace_n[1] >= 6); /* HRR, 4+ for the flight, ACK */
}

/* REQ-DTLS-041: no more than 10 records a transmission */
TEST(test_records_per_transmission) {
  ASSERT_EQ(pair(&cli, &srv, 200, 3), 0);
  ASSERT_TRUE(connected());
  ASSERT_TRUE(sv.sent_n <= 10 && sv.pass_lost == 0);
}

/* Every batch arrives last datagram first, retransmissions too: fragments
 * after a gap, and later messages, are dropped (RFC 9147 §5.2 MAY), so each
 * transmission completes a little more — within the retransmission budget
 * the handshake still completes */
TEST(test_reordered) {
  net_reset();
  ASSERT_EQ(server_start(&srv, 200), 0);
  ASSERT_EQ(client_start(&cli, 200), 0);
  reorder = 1;
  run(130);
  ASSERT_TRUE(connected());
}

/* REQ-DTLS-034: a retransmission cut differently (the MTU shrank) overlaps
 * what arrived of the first */
static int shrink_after_loss(int dir, int i, const uint8_t *dg, size_t n) {
  (void)dg;
  (void)n;
  if (dir == 1 && i == 2) { /* the flight's second datagram */
    sv.mtu = 150;
    return 1;
  }
  return 0;
}

TEST(test_retransmission_cut_differently) {
  net_reset();
  ASSERT_EQ(server_start(&srv, 400), 0);
  ASSERT_EQ(client_start(&cli, 400), 0);
  fate = shrink_after_loss;
  run(10);
  ASSERT_TRUE(connected());
}

/* ── The timer ── */

/* REQ-DTLS-037: 1 s, doubling, at most 60 s; given up after
 * DTLS_MAX_RETRANSMITS retransmissions (REQ-DTLS-038) */
TEST(test_timer) {
  static const uint32_t wait[] = {1000, 2000, 4000, 8000, 16000, 32000};
  const uint8_t *p;
  size_t i;
  uint8_t first[1600];
  size_t n = first_client_hello(first);
  ASSERT_TRUE(n > 0);
  for (i = 0; i < sizeof(wait) / sizeof(wait[0]); i++) {
    dtls_tick(&cl, wait[i] - 1);
    ASSERT_EQ(dtls_pending(&cl, &p), 0);
    dtls_tick(&cl, 1);
    ASSERT_EQ(dtls_pending(&cl, &p), n); /* the same ClientHello .. */
    ASSERT_EQ(be16(p + 9), i + 1);       /* .. in a new record */
    ASSERT_MEM_EQ(p + 13, first + 13, n - 13);
    dtls_sent(&cl);
  }
  dtls_tick(&cl, 59999);
  ASSERT_EQ(dtls_state(&cl), TLS_STATE_HANDSHAKE);
  dtls_tick(&cl, 1);
  ASSERT_EQ(dtls_state(&cl), TLS_STATE_ERROR);
  ASSERT_EQ(cl.tls.alert, DTLS_TIMEOUT);
  ASSERT_EQ(cl_evts, TLS_EVT_ERROR);
  ASSERT_EQ(dtls_pending(&cl, &p), 0); /* no alert: nobody is listening */
}

/* ── ACKs ── */

/* REQ-DTLS-052, -053, -056: the server acknowledges the client's last
 * flight, in epoch 3, naming its record; the client stops sending it */
static dtls_keys_t ack_keys;
static int ack_seen;
static int open_ack(int dir, int i, const uint8_t *dg, size_t n) {
  dtls_rec_t h;
  uint8_t out[256], type;
  uint64_t seq;
  int k;
  (void)i;
  if (dir != 1 || dtls_state(&cl) != TLS_STATE_CONNECTED ||
      dtls_record_parse(dg, n, &h) != 0)
    return 0;
  ack_keys = cl.r;
  k = dtls_record_open(&c, &ack_keys, dg, &h, out, &type, &seq);
  if (k == 2 + 16 && type == DTLS_CT_ACK && be16(out) == 16 &&
      be16(out + 2 + 6) == 2 && be16(out + 2 + 14) == 0)
    ack_seen++;
  return 0;
}

TEST(test_last_flight_acknowledged) {
  int before;
  ack_seen = 0;
  net_reset();
  ASSERT_EQ(server_start(&srv, MTU), 0);
  ASSERT_EQ(client_start(&cli, MTU), 0);
  fate = open_ack;
  run(0);
  ASSERT_TRUE(connected());
  ASSERT_EQ(ack_seen, 1);
  before = trace_n[0];
  run(100); /* nothing more from the client */
  ASSERT_EQ(trace_n[0], before);
}

/* REQ-DTLS-039: the ACK lost — the client's Finished again, the ACK again */
TEST(test_ack_lost) {
  net_reset();
  ASSERT_EQ(server_start(&srv, MTU), 0);
  ASSERT_EQ(client_start(&cli, MTU), 0);
  lose_dir = 1;
  lose_index = 2;
  fate = lose_one;
  run(5);
  ASSERT_TRUE(connected());
  ASSERT_EQ(trace_n[0], 4); /* CH, CH, Finished, Finished */
  ASSERT_EQ(trace_n[1], 4); /* HRR, flight, ACK (lost), ACK */
  ASSERT_EQ(cl.fl_state, 0);
}

/* REQ-DTLS-038: the client's Finished lost — the server's retransmitted
 * flight makes the client send it again at once */
TEST(test_finished_lost) {
  net_reset();
  ASSERT_EQ(server_start(&srv, MTU), 0);
  ASSERT_EQ(client_start(&cli, MTU), 0);
  lose_dir = 0;
  lose_index = 2;
  fate = lose_one;
  run(0);
  ASSERT_EQ(dtls_state(&sv), TLS_STATE_HANDSHAKE);
  dtls_tick(&sv, 1000); /* the server's timer: its flight again .. */
  run(0);               /* .. and the client's Finished at once */
  ASSERT_TRUE(connected());
}

/* REQ-DTLS-055: a later fragment first — the client says what it has */
TEST(test_ack_on_disruption) {
  uint8_t out[256], type;
  const uint8_t *p;
  dtls_keys_t r;
  dtls_rec_t h;
  uint64_t seq;
  size_t n;
  net_reset();
  ASSERT_EQ(server_start(&srv, 200), 0);
  ASSERT_EQ(client_start(&cli, 200), 0);
  collect(&cl, 0);
  (void)deliver(0, &sv); /* ClientHello → HelloRetryRequest */
  collect(&sv, 1);
  (void)deliver(1, &cl); /* → ClientHello 2 */
  collect(&cl, 0);
  (void)deliver(0, &sv); /* → the server's flight, in pieces */
  collect(&sv, 1);
  ASSERT_TRUE(wire_n[1] >= 3);
  ASSERT_EQ(dtls_input(&cl, wire[1][0].b, wire[1][0].n), 0);
  ASSERT_EQ(dtls_pending(&cl, &p), 0); /* all in order so far */
  ASSERT_EQ(dtls_input(&cl, wire[1][2].b, wire[1][2].n), 0); /* a gap */
  n = dtls_pending(&cl, &p);
  ASSERT_TRUE(n > 0 && p[0] == 0x2E); /* epoch 2 */
  r = sv.r;
  ASSERT_EQ(dtls_record_parse(p, n, &h), 0);
  ASSERT_TRUE(dtls_record_open(&c, &r, p, &h, out, &type, &seq) >= 2 + 16);
  ASSERT_EQ(type, DTLS_CT_ACK);
  ASSERT_TRUE(be16(out + 2 + 6) == 0); /* the ServerHello's record first */
}

/* ── Configurations ── */

static tls_config_t srv_p256, srv_psk, cli_psk, cli_mfl;
static tls_mbedtls_t be_noca;
static tls_crypto_t c_noca;
static const uint8_t psk_bytes[32] = {
    1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

/* A HelloRetryRequest asks for a share and a cookie at once */
TEST(test_hello_retry_for_a_group) {
  ASSERT_EQ(pair(&cli, &srv_p256, MTU, 3), 0);
  ASSERT_TRUE(connected());
  ASSERT_EQ(cl.tls.group, TLS_GROUP_SECP256R1);
  ASSERT_EQ(trace_n[0], 3);
}

TEST(test_psk) {
  ASSERT_EQ(pair(&cli_psk, &srv_psk, MTU, 3), 0);
  ASSERT_TRUE(connected());
  ASSERT_TRUE(tls_psk_used(&cl.tls) && tls_psk_used(&sv.tls));
}

/* max_fragment_length: the server's records carry at most 512 bytes */
static int records_max_512(int dir, int i, const uint8_t *dg, size_t n) {
  size_t off = 0;
  (void)i;
  if (dir == 1)
    while (off < n) {
      size_t len = dg[off] == TLS_CT_HANDSHAKE ? 13 + be16(dg + off + 11)
                                               : 5 + be16(dg + off + 3);
      if (len > (dg[off] == TLS_CT_HANDSHAKE ? 13u : 22u) + 512u)
        largest = len;
      off += len;
    }
  return 0;
}

TEST(test_max_fragment_length) {
  largest = 0;
  net_reset();
  ASSERT_EQ(server_start(&srv, MTU), 0);
  ASSERT_EQ(client_start(&cli_mfl, MTU), 0);
  fate = records_max_512;
  run(3);
  ASSERT_TRUE(connected());
  ASSERT_EQ(sv.tls.max_frag, 512);
  ASSERT_EQ(largest, 0);
}

/* ── Records that do not belong ── */

/* REQ-DTLS-014, -022: garbage, a damaged record, a truncated one: dropped
 * without a word, and the handshake goes on */
TEST(test_bad_records_dropped) {
  static const uint8_t junk[] = {0x40, 1, 2, 3, 4, 5, 6, 7};
  uint8_t bad[1600];
  const uint8_t *p;
  size_t n;
  net_reset();
  ASSERT_EQ(server_start(&srv, MTU), 0);
  ASSERT_EQ(client_start(&cli, MTU), 0);
  collect(&cl, 0);
  (void)deliver(0, &sv); /* ClientHello → HelloRetryRequest */
  collect(&sv, 1);
  (void)deliver(1, &cl); /* → ClientHello 2 */
  collect(&cl, 0);
  (void)deliver(0, &sv); /* → ServerHello .. Finished */
  collect(&sv, 1);
  ASSERT_EQ(wire_n[1], 1);
  n = wire[1][0].n;
  memcpy(bad, wire[1][0].b, n);
  bad[n - 30] ^= 0x10; /* inside the protected record */
  ASSERT_EQ(dtls_input(&cl, junk, sizeof(junk)), 0);
  ASSERT_EQ(dtls_input(&cl, bad, n), 0);
  ASSERT_EQ(dtls_input(&cl, bad, 20), 0); /* truncated */
  ASSERT_EQ(dtls_state(&cl), TLS_STATE_HANDSHAKE);
  ASSERT_EQ(cl.bad_records, 1);
  ASSERT_EQ(dtls_pending(&cl, &p), 0); /* no alert */
  run(3);                              /* the real one still works */
  ASSERT_TRUE(connected());
}

/* Once the peer's records are protected, a new handshake message in
 * plaintext can only be forged: not taken.  (Here a "Finished" between
 * the ServerHello and the protected records after it.) */
TEST(test_plaintext_after_keys_ignored) {
  uint8_t forged[64], body[32];
  const dg_t *g;
  size_t sh;
  net_reset();
  ASSERT_EQ(server_start(&srv, MTU), 0);
  ASSERT_EQ(client_start(&cli, MTU), 0);
  collect(&cl, 0);
  (void)deliver(0, &sv); /* ClientHello → HelloRetryRequest */
  collect(&sv, 1);
  (void)deliver(1, &cl); /* → ClientHello 2 */
  collect(&cl, 0);
  (void)deliver(0, &sv); /* → ServerHello and the protected rest */
  collect(&sv, 1);
  g = &wire[1][0];
  sh = 13 + be16(g->b + 11);
  ASSERT_EQ(dtls_input(&cl, g->b, sh), 0); /* the ServerHello alone */
  ASSERT_TRUE(cl.tls.flags & 0x02);        /* F_RPROT */
  memset(body, 0x5A, sizeof(body));
  ASSERT_EQ(dtls_input(&cl, forged,
                       plain_hs(forged, TLS_HS_FINISHED, body, 32, cl.rx_seq, 9,
                                0, 32)),
            0);
  ASSERT_EQ(dtls_input(&cl, g->b + sh, g->n - sh), 0);
  wire_n[1] = 0;
  run(0);
  ASSERT_TRUE(connected());
}

/* REQ-DTLS-060: a KeyUpdate waits while the last flight is unanswered —
 * here until the server's ACK, held back, arrives */
TEST(test_key_update_waits_for_flight) {
  uint8_t buf[16];
  net_reset();
  ASSERT_EQ(server_start(&srv, MTU), 0);
  ASSERT_EQ(client_start(&cli, MTU), 0);
  lose_dir = 1;
  lose_index = 2; /* the server's ACK of the client's Finished: held */
  fate = lose_one;
  run(0);
  ASSERT_TRUE(connected());
  ASSERT_EQ(cl.fl_state, 3); /* FL_WAITING: the Finished unanswered */
  ASSERT_EQ(dtls_key_update(&cl, 0), 0);
  ASSERT_EQ(dtls_input(&cl, trace[1][2].b, trace[1][2].n), 0); /* late */
  run(3);
  ASSERT_TRUE(cl.wepoch == 4 && sv.repoch == 4);
  ASSERT_EQ(dtls_write(&cl, (const uint8_t *)"ok", 2), 2);
  run(0);
  ASSERT_EQ(dtls_read(&sv, buf, sizeof(buf)), 2);
}

/* ── Buffers ── */

TEST(test_init_checks) {
  tls_config_t no_block = cli;
  tls_crypto_t c2 = c;
  c2.aes_block = NULL;
  no_block.crypto = &c2;
  ASSERT_EQ(dtls_init(&cl, &cli, cl_rx, sizeof(cl_rx), cl_tx, sizeof(cl_tx),
                      DTLS_MTU_MIN - 1),
            -1);
  ASSERT_EQ(dtls_init(&cl, &no_block, cl_rx, sizeof(cl_rx), cl_tx,
                      sizeof(cl_tx), MTU),
            -1);
  ASSERT_EQ(dtls_init(&cl, &cli, cl_rx, 255, cl_tx, sizeof(cl_tx), MTU), -1);
  ASSERT_EQ(dtls_init(&cl, &cli, cl_rx, sizeof(cl_rx), cl_tx, sizeof(cl_tx),
                      DTLS_MTU_MIN),
            0);
}

/* A flight that cannot fit even in an empty tx */
TEST(test_tx_too_small) {
  net_reset();
  ASSERT_EQ(dtls_init(&sv, &srv, sv_rx, sizeof(sv_rx), sv_tx, 600, MTU), 0);
  ASSERT_EQ(dtls_accept(&sv), 0);
  ASSERT_EQ(client_start(&cli, MTU), 0);
  run(0);
  ASSERT_EQ(dtls_state(&sv), TLS_STATE_ERROR);
  ASSERT_EQ(sv.tls.alert, TLS_ALERT_INTERNAL_ERROR);
}

/* A message that cannot fit in rx with the record it comes in */
TEST(test_rx_too_small) {
  net_reset();
  ASSERT_EQ(server_start(&srv, MTU), 0);
  ASSERT_EQ(dtls_init(&cl, &cli, cl_rx, 700, cl_tx, sizeof(cl_tx), MTU), 0);
  ASSERT_EQ(dtls_connect(&cl, HOST), 0);
  run(0);
  ASSERT_EQ(dtls_state(&cl), TLS_STATE_ERROR);
  ASSERT_EQ(cl.tls.alert, TLS_ALERT_RECORD_OVERFLOW);
}

/* ══ After the handshake ══════════════════════════════════════════ */

static int handshake(void) {
  return pair(&cli, &srv, MTU, 3) == 0 && connected();
}

/* One datagram each way, and nothing else */
static void exchange(void) { run(0); }

TEST(test_data_both_ways) {
  uint8_t buf[64];
  int before;
  ASSERT_TRUE(handshake());
  before = trace_n[0];
  ASSERT_EQ(dtls_write(&cl, (const uint8_t *)"GET /", 5), 5);
  exchange();
  ASSERT_EQ(trace_n[0], before + 1); /* one record, one datagram */
  ASSERT_EQ(trace[0][before].b[0], 0x2F);
  ASSERT_EQ(trace[0][before].n, 5 + DTLS_RECORD_OVERHEAD);
  ASSERT_EQ(dtls_read(&sv, buf, sizeof(buf)), 5);
  ASSERT_MEM_EQ(buf, "GET /", 5);
  ASSERT_EQ(dtls_read(&sv, buf, sizeof(buf)), 0);
  ASSERT_EQ(dtls_write(&sv, (const uint8_t *)"200 OK", 6), 6);
  exchange();
  ASSERT_EQ(dtls_read(&cl, buf, sizeof(buf)), 6);
  ASSERT_MEM_EQ(buf, "200 OK", 6);
}

/* A record per read: the datagrams' boundaries survive; a record read in
 * parts goes on where it left off */
TEST(test_datagram_boundaries) {
  uint8_t buf[64];
  const uint8_t *p;
  ASSERT_TRUE(handshake());
  ASSERT_EQ(dtls_write(&cl, (const uint8_t *)"a", 1), 1);
  ASSERT_EQ(dtls_write(&cl, (const uint8_t *)"bb", 2), 0); /* one waits */
  ASSERT_TRUE(dtls_pending(&cl, &p) > 0);
  ASSERT_EQ(dtls_input(&sv, p, dtls_pending(&cl, &p)), 0);
  dtls_sent(&cl);
  ASSERT_EQ(dtls_write(&cl, (const uint8_t *)"bcd", 3), 3);
  exchange();
  ASSERT_EQ(dtls_read(&sv, buf, sizeof(buf)), 1);
  ASSERT_EQ(buf[0], 'a');
  ASSERT_EQ(dtls_read(&sv, buf, 2), 2);
  ASSERT_MEM_EQ(buf, "bc", 2);
  ASSERT_EQ(dtls_read(&sv, buf, sizeof(buf)), 1);
  ASSERT_EQ(buf[0], 'd');
}

TEST(test_max_data) {
  static uint8_t big[MTU];
  ASSERT_TRUE(handshake());
  ASSERT_EQ(dtls_max_data(&cl), MTU - DTLS_RECORD_OVERHEAD);
  ASSERT_EQ(dtls_write(&cl, big, MTU - DTLS_RECORD_OVERHEAD + 1), -1);
  ASSERT_EQ(dtls_write(&cl, big, MTU - DTLS_RECORD_OVERHEAD),
            MTU - DTLS_RECORD_OVERHEAD);
  exchange();
  ASSERT_EQ(trace[0][trace_n[0] - 1].n, MTU);
  ASSERT_EQ(dtls_read(&sv, big, sizeof(big)), MTU - DTLS_RECORD_OVERHEAD);
}

/* REQ-DTLS-040: data under the new keys before the Finished that installs
 * them is not taken — here it cannot even be opened yet */
static int lose_finished_keep_data(int dir, int i, const uint8_t *dg,
                                   size_t n) {
  (void)dg;
  (void)n;
  return dir == 0 && i == 2;
}

TEST(test_data_before_finished_dropped) {
  uint8_t buf[16];
  net_reset();
  ASSERT_EQ(server_start(&srv, MTU), 0);
  ASSERT_EQ(client_start(&cli, MTU), 0);
  fate = lose_finished_keep_data;
  run(0); /* the client is connected; its Finished is lost */
  ASSERT_EQ(dtls_state(&cl), TLS_STATE_CONNECTED);
  ASSERT_EQ(dtls_write(&cl, (const uint8_t *)"early", 5), 5);
  run(0);
  ASSERT_EQ(dtls_state(&sv), TLS_STATE_HANDSHAKE);
  run(2); /* the Finished again */
  ASSERT_TRUE(connected());
  ASSERT_EQ(dtls_read(&sv, buf, sizeof(buf)), 0);
}

/* REQ-DTLS-060: our KeyUpdate goes in the old epoch, and the new keys are
 * used only once the peer has acknowledged it */
TEST(test_key_update) {
  uint8_t buf[16];
  const uint8_t *p;
  size_t n;
  ASSERT_TRUE(handshake());
  ASSERT_EQ(dtls_key_update(&cl, 0), 0);
  n = dtls_pending(&cl, &p);
  ASSERT_TRUE(n > 0 && p[0] == 0x2F); /* epoch 3 */
  ASSERT_EQ(dtls_input(&sv, p, n), 0);
  dtls_sent(&cl);
  ASSERT_EQ(cl.wepoch, 3);
  ASSERT_EQ(sv.repoch, 4);
  ASSERT_EQ(dtls_write(&cl, (const uint8_t *)"old", 3), 3); /* still 3 */
  n = dtls_pending(&cl, &p);
  ASSERT_EQ(p[0], 0x2F);
  ASSERT_EQ(dtls_input(&sv, p, n), 0); /* the old epoch still opens */
  dtls_sent(&cl);
  ASSERT_EQ(dtls_read(&sv, buf, sizeof(buf)), 3);
  run(0); /* the server's ACK */
  ASSERT_EQ(cl.wepoch, 4);
  ASSERT_EQ(cl.fl_state, 0);
  ASSERT_EQ(dtls_write(&cl, (const uint8_t *)"new", 3), 3);
  exchange();
  ASSERT_EQ(trace[0][trace_n[0] - 1].b[0], 0x2C); /* epoch 4 */
  ASSERT_EQ(dtls_read(&sv, buf, sizeof(buf)), 3);
  ASSERT_MEM_EQ(buf, "new", 3);
}

/* REQ-DTLS-060, -039: the ACK lost: the KeyUpdate again, the ACK again */
TEST(test_key_update_ack_lost) {
  int acks;
  ASSERT_TRUE(handshake());
  lose_dir = 1;
  lose_index = trace_n[1];
  fate = lose_one;
  ASSERT_EQ(dtls_key_update(&cl, 0), 0);
  run(0);
  ASSERT_EQ(cl.wepoch, 3); /* no ACK yet */
  acks = trace_n[1];
  run(2);
  ASSERT_EQ(trace_n[1], acks + 1);
  ASSERT_EQ(cl.wepoch, 4);
  ASSERT_EQ(sv.repoch, 4);
}

/* A KeyUpdate that asks the peer to update too: its own, not asking */
TEST(test_key_update_requested) {
  uint8_t buf[16];
  ASSERT_TRUE(handshake());
  ASSERT_EQ(dtls_key_update(&cl, 1), 0);
  run(0);
  ASSERT_TRUE(cl.wepoch == 4 && sv.wepoch == 4 && cl.repoch == 4 &&
              sv.repoch == 4);
  ASSERT_EQ(dtls_write(&sv, (const uint8_t *)"x", 1), 1);
  exchange();
  ASSERT_EQ(dtls_read(&cl, buf, sizeof(buf)), 1);
  ASSERT_EQ(sv.wepoch, 4); /* the client's did not ask back */
}

/* REQ-DTLS-061: a record of the old epoch that arrives late still opens */
TEST(test_late_record_of_old_epoch) {
  uint8_t late[64], buf[16];
  const uint8_t *p;
  size_t n;
  ASSERT_TRUE(handshake());
  ASSERT_EQ(dtls_write(&cl, (const uint8_t *)"late", 4), 4);
  n = dtls_pending(&cl, &p);
  memcpy(late, p, n);
  dtls_sent(&cl);
  ASSERT_EQ(dtls_key_update(&cl, 0), 0);
  run(0);
  ASSERT_EQ(cl.wepoch, 4);
  ASSERT_EQ(dtls_write(&cl, (const uint8_t *)"new", 3), 3);
  exchange();
  ASSERT_EQ(dtls_read(&sv, buf, sizeof(buf)), 3);
  ASSERT_EQ(dtls_input(&sv, late, n), 0);
  ASSERT_EQ(dtls_read(&sv, buf, sizeof(buf)), 4);
  ASSERT_MEM_EQ(buf, "late", 4);
}

/* REQ-DTLS-024: after 2^24 records under one key a KeyUpdate goes by
 * itself; data goes on under the old keys until it is acknowledged.  (The
 * KeyUpdate reaches the server behind data it has not read yet.) */
TEST(test_key_update_at_record_limit) {
  uint8_t buf[16];
  ASSERT_TRUE(handshake());
  cl.w.k.seq = TLS_KEY_UPDATE_RECORDS;
  sv.r.k.seq = TLS_KEY_UPDATE_RECORDS; /* (as if it had seen them all) */
  ASSERT_EQ(dtls_write(&cl, (const uint8_t *)"n", 1), 1);
  ASSERT_EQ(cl.wepoch, 3);
  run(0);
  ASSERT_EQ(dtls_read(&sv, buf, sizeof(buf)), 1);
  ASSERT_TRUE(cl.wepoch == 4 && sv.repoch == 4 && cl.w.k.seq == 0);
}

/* REQ-DTLS-062: no KeyUpdate past the last epoch */
TEST(test_last_epoch) {
  const uint8_t *p;
  ASSERT_TRUE(handshake());
  cl.wepoch = 0xFFFF;
  ASSERT_EQ(dtls_key_update(&cl, 0), 0);
  ASSERT_EQ(dtls_pending(&cl, &p), 0);
}

/* REQ-DTLS-046, -047: close_notify once; what comes after is ignored */
TEST(test_close_notify) {
  uint8_t after[64], buf[16];
  const uint8_t *p;
  size_t n;
  ASSERT_TRUE(handshake());
  ASSERT_EQ(dtls_write(&cl, (const uint8_t *)"late", 4), 4);
  n = dtls_pending(&cl, &p);
  memcpy(after, p, n);
  dtls_sent(&cl);
  ASSERT_EQ(dtls_close(&cl), 0);
  exchange();
  ASSERT_EQ(dtls_state(&sv), TLS_STATE_CLOSED);
  ASSERT_TRUE(sv_evts & TLS_EVT_CLOSED);
  ASSERT_EQ(dtls_input(&sv, after, n), 0); /* after close_notify: ignored */
  ASSERT_EQ(dtls_read(&sv, buf, sizeof(buf)), 0);
  ASSERT_EQ(dtls_write(&sv, (const uint8_t *)"bye", 3), 3); /* may still */
  ASSERT_EQ(dtls_close(&sv), 0);
  exchange();
  ASSERT_EQ(dtls_read(&cl, buf, sizeof(buf)), 3);
  ASSERT_EQ(dtls_state(&cl), TLS_STATE_CLOSED);
  ASSERT_EQ(dtls_write(&cl, (const uint8_t *)"x", 1), -1);
  run(100); /* nothing is retransmitted */
  ASSERT_EQ(dtls_pending(&cl, &p), 0);
  ASSERT_EQ(dtls_pending(&sv, &p), 0);
}

/* REQ-DTLS-046: a fatal alert goes once */
TEST(test_alert_not_retransmitted) {
  int sent;
  net_reset();
  ASSERT_EQ(server_start(&srv, MTU), 0);
  ASSERT_EQ(client_start(&cli, MTU), 0);
  fate = cookie_fate;
  run(0);
  ASSERT_EQ(dtls_state(&sv), TLS_STATE_ERROR);
  sent = trace_n[1];
  fate = NULL;
  run(100);
  ASSERT_EQ(trace_n[1], sent);
}

TEST(test_release) {
  static const uint8_t zero[64];
  ASSERT_TRUE(handshake());
  dtls_release(&cl);
  ASSERT_EQ(dtls_state(&cl), TLS_STATE_IDLE);
  ASSERT_MEM_EQ(&cl.w, zero, sizeof(cl.w));
  ASSERT_MEM_EQ(cl.tls.wsec, zero, 32);
  ASSERT_MEM_EQ(cl_rx, zero, 64);
  ASSERT_EQ(cl.mtu, MTU);
  ASSERT_TRUE(cl.tls.on_event == on_cl);
  /* and again, with a fresh server */
  net_reset();
  ASSERT_EQ(server_start(&srv, MTU), 0);
  cl_evts = 0;
  ASSERT_EQ(dtls_connect(&cl, HOST), 0);
  run(3);
  ASSERT_TRUE(connected());
}

/* REQ-DTLS-052, -053: a NewSessionTicket is ignored — and acknowledged */
TEST(test_new_session_ticket_acknowledged) {
  uint8_t rec[128], out[128], type;
  const uint8_t *p;
  dtls_keys_t r;
  dtls_rec_t h;
  uint64_t seq, nst_seq;
  size_t n;
  static const uint8_t nst[] = {0, 0, 0,   60,  1,   2,   3, 4, 0,
                                0, 4, 't', 'i', 'c', 'k', 0, 0};
  ASSERT_TRUE(handshake());
  memset(rec, 0, sizeof(rec));
  rec[5] = TLS_HS_NEW_SESSION_TICKET;
  rec[5 + 3] = sizeof(nst);
  rec[5 + 5] = (uint8_t)sv.fl_seq; /* the server's next message_seq */
  rec[5 + 11] = sizeof(nst);
  memcpy(rec + 5 + 12, nst, sizeof(nst));
  nst_seq = sv.w.k.seq;
  n = dtls_record_seal(&c, &sv.w, sv.wepoch, TLS_CT_HANDSHAKE, rec,
                       12 + sizeof(nst));
  ASSERT_EQ(dtls_input(&cl, rec, n), 0);
  ASSERT_EQ(dtls_state(&cl), TLS_STATE_CONNECTED);
  n = dtls_pending(&cl, &p);
  ASSERT_TRUE(n > 0);
  r = sv.r;
  ASSERT_EQ(dtls_record_parse(p, n, &h), 0);
  ASSERT_EQ(dtls_record_open(&c, &r, p, &h, out, &type, &seq), 2 + 16);
  ASSERT_EQ(type, DTLS_CT_ACK);
  ASSERT_TRUE(be16(out + 2 + 6) == 3 && be16(out + 2 + 14) == nst_seq);
}

int main(void) {
  fprintf(stderr, "=== DTLS 1.3 tests ===\n");
  if (tls_mbedtls_init(&be, &c) != 0 ||
      tls_mbedtls_set_ca(&be, (const uint8_t *)ca_pem, sizeof(ca_pem)) ||
      tls_mbedtls_parse_key(&be, &ec_key, (const uint8_t *)server_key_pem,
                            sizeof(server_key_pem))) {
    fprintf(stderr, "backend init failed\n");
    return 1;
  }
  srv.crypto = &c;
  srv.cert = ec_chain;
  srv.cert_len = ec_chain_len;
  srv.cert_count = 1;
  srv.key = &ec_key;
  srv.sig_scheme = TLS_SIG_ECDSA_SECP256R1_SHA256;
  srv_nocookie = srv;
  srv_nocookie.dtls_no_cookie = 1;
  cli.crypto = &c;
  if (tls_mbedtls_init(&be_noca, &c_noca) != 0)
    return 1;
  srv_p256 = srv;
  srv_p256.groups = TLS_GROUPS_SECP256R1;
  srv_psk = srv;
  srv_psk.psk = psk_bytes;
  srv_psk.psk_len = sizeof(psk_bytes);
  srv_psk.psk_id = (const uint8_t *)"device-1";
  srv_psk.psk_id_len = 8;
  cli_psk = cli;
  cli_psk.crypto = &c_noca; /* no trust anchors: the PSK must do */
  cli_psk.psk = psk_bytes;
  cli_psk.psk_len = sizeof(psk_bytes);
  cli_psk.psk_id = (const uint8_t *)"device-1";
  cli_psk.psk_id_len = 8;
  cli_mfl = cli;
  cli_mfl.max_fragment = TLS_MFL_512;

  RUN_TEST(test_keys_from_secret);
  RUN_TEST(test_seal_as_rfc_describes);
  RUN_TEST(test_seal_masks_the_record_number);
  RUN_TEST(test_open_what_was_sealed);
  RUN_TEST(test_open_short_header);
  RUN_TEST(test_parse_uses_the_length);
  RUN_TEST(test_parse_refuses);
  RUN_TEST(test_open_refuses_short_ciphertext);
  RUN_TEST(test_open_refuses_tampering);
  RUN_TEST(test_open_strips_padding);
  RUN_TEST(test_seq_expand);
  RUN_TEST(test_open_reconstructs_the_number);
  RUN_TEST(test_replay_window);

  RUN_TEST(test_handshake);
  RUN_TEST(test_client_hello_format);
  RUN_TEST(test_server_hello_format);
  RUN_TEST(test_epochs);
  RUN_TEST(test_no_cookie);
  RUN_TEST(test_refuse_legacy_cookie);
  RUN_TEST(test_refuse_dtls12);
  RUN_TEST(test_refuse_wrong_cookie);
  RUN_TEST(test_refuse_changed_bytes);
  RUN_TEST(test_fragments_in_any_order);
  RUN_TEST(test_each_datagram_lost);
  RUN_TEST(test_duplicates);
  RUN_TEST(test_small_mtu);
  RUN_TEST(test_records_per_transmission);
  RUN_TEST(test_reordered);
  RUN_TEST(test_retransmission_cut_differently);
  RUN_TEST(test_timer);
  RUN_TEST(test_last_flight_acknowledged);
  RUN_TEST(test_ack_lost);
  RUN_TEST(test_finished_lost);
  RUN_TEST(test_ack_on_disruption);
  RUN_TEST(test_hello_retry_for_a_group);
  RUN_TEST(test_psk);
  RUN_TEST(test_max_fragment_length);
  RUN_TEST(test_bad_records_dropped);
  RUN_TEST(test_plaintext_after_keys_ignored);
  RUN_TEST(test_init_checks);
  RUN_TEST(test_tx_too_small);
  RUN_TEST(test_rx_too_small);

  RUN_TEST(test_data_both_ways);
  RUN_TEST(test_datagram_boundaries);
  RUN_TEST(test_max_data);
  RUN_TEST(test_data_before_finished_dropped);
  RUN_TEST(test_key_update);
  RUN_TEST(test_key_update_ack_lost);
  RUN_TEST(test_key_update_requested);
  RUN_TEST(test_key_update_waits_for_flight);
  RUN_TEST(test_late_record_of_old_epoch);
  RUN_TEST(test_key_update_at_record_limit);
  RUN_TEST(test_last_epoch);
  RUN_TEST(test_close_notify);
  RUN_TEST(test_alert_not_retransmitted);
  RUN_TEST(test_release);
  RUN_TEST(test_new_session_ticket_acknowledged);

  tls_mbedtls_free(&be);
  tls_mbedtls_free(&be_noca);
  TEST_REPORT();
  return test_failures;
}
