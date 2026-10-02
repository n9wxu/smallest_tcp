/**
 * @file itest_dtls.c
 * @brief DTLS 1.3 (RFC 9147), black box: the stack's server and client
 *        through the DTLS API, their datagrams read and written by a
 *        pre-shared-key peer of the tests' own (tls_peer.h) — records,
 *        record number encryption, handshake fragments, ACKs and the key
 *        schedule all from the RFC — and, for certificates and lossy
 *        networks, by the stack's other role.
 *
 * The suite links the TLS library and the crypto backend only: no test
 * here has the stack's UDP, so every datagram is moved by the test, as an
 * application moves it (REQ-DTLS-073).
 */

#include "dtls.h"
#include "itest.h"
#include "tls_crypto_mbedtls.h"
#include "tls_peer.h"
#include "tls_test_data.h"
#include <string.h>

#define PSK_ID "itest-device"
#define HOST "pyro-dead01.local" /* the test certificate's name */
#define MTU 1200

static const uint8_t psk[32] = {0x69, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x70, 0x73,
                                0x6b, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};

static tls_mbedtls_t backend, backend_no_ca;
static tls_crypto_t crypto, crypto_no_ca;
static mbedtls_pk_context ec_key;
static const uint8_t *const ec_chain[1] = {server_der};
static const uint16_t ec_chain_len[1] = {sizeof(server_der)};

/* A server with the pre-shared key alone (both modes), one with the ECDSA
 * certificate; a client with the key, one with the trust anchor */
static tls_config_t srv_psk, srv_cert, cli_psk, cli_cert;

/* A failed check in a helper says where, and the helper returns 0 */
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "    check failed: %s (%s:%d)\n", #x, __FILE__,          \
              __LINE__);                                                       \
      return 0;                                                                \
    }                                                                          \
  } while (0)

/* ── The connection under test ── */

static dtls_conn_t sut;
static uint8_t sut_rx[4096], sut_tx[4096];
static size_t sut_mtu = MTU; /* of the next start; then MTU again */
static size_t sut_rx_cap = sizeof(sut_rx), sut_tx_cap = sizeof(sut_tx);
static uint8_t events[16];
static int n_events;

static void on_event(tls_conn_t *c, uint8_t e) {
  (void)c;
  if (n_events < (int)sizeof(events))
    events[n_events] = e;
  n_events++;
}

/* The datagrams it has sent, oldest first, and how far they have been read */
#define DG_MAX 96
static struct {
  uint8_t b[1600];
  size_t n;
} dgs[DG_MAX];
static int n_dgs, dg_at;
static size_t dg_off, largest_dg;
static int n_recs; /* records read since the last reset */

/* Take every datagram the connection has to send; how many there were */
static int collect(void) {
  const uint8_t *p;
  size_t n;
  int before = n_dgs;
  while ((n = dtls_pending(&sut, &p)) > 0) {
    if (n_dgs < DG_MAX && n <= sizeof(dgs[0].b)) {
      memcpy(dgs[n_dgs].b, p, n);
      dgs[n_dgs].n = n;
    }
    if (n > largest_dg)
      largest_dg = n;
    n_dgs++;
    dtls_sent(&sut);
  }
  return n_dgs - before;
}

/* ── The scripted peer ── */

static tp_t peer;
static tp_keys_t rk[4], wk[4]; /* its keys by the epoch's two low bits */
static int rk_set[4];
static unsigned rk_epoch[4];
static uint32_t p_seq0; /* its next epoch-0 record number */
static uint16_t p_mseq; /* its next message_seq */
static tp_ch_t ch_psk_ke, ch_psk_dhe;
static tp_sh_t sh_psk_ke;

/* The peer reads records of @p epoch under traffic secret @p secret */
static void read_keys(unsigned epoch, const uint8_t secret[32]) {
  tp_traffic_keys(1, secret, &rk[epoch & 3]);
  rk_set[epoch & 3] = 1;
  rk_epoch[epoch & 3] = epoch;
}

static void write_keys(unsigned epoch, const uint8_t secret[32]) {
  tp_traffic_keys(1, secret, &wk[epoch & 3]);
}

/* A record the connection under test sent */
typedef struct {
  unsigned epoch;
  uint32_t seq;
  uint8_t type;
  uint8_t body[1600];
  size_t len;
  int dgram; /* the datagram it came in */
} drec_t;

/* The next record sent: 1, 0 if there is none, -1 if it cannot be read.
 * A DTLSPlaintext record is as RFC 9147 §4 writes it — version {254, 253},
 * epoch 0; a DTLSCiphertext record has the unified header 001 0 1 1 E E
 * and opens under the keys of its epoch (tp_dopen()). */
static int next_rec(drec_t *r) {
  const uint8_t *d;
  size_t n, used;
  if (dg_at >= n_dgs)
    return 0;
  d = dgs[dg_at].b + dg_off;
  n = dgs[dg_at].n - dg_off;
  r->dgram = dg_at;
  if (d[0] == TP_HANDSHAKE || d[0] == TP_ALERT || d[0] == TP_ACK) {
    if (n < 13 || tp_get(d + 1, 2) != 0xFEFD || tp_get(d + 3, 2) != 0 ||
        tp_get(d + 5, 2) != 0 || 13 + tp_get(d + 11, 2) > n)
      return -1;
    r->epoch = 0;
    r->seq = tp_get(d + 7, 4);
    r->type = d[0];
    r->len = tp_get(d + 11, 2);
    memcpy(r->body, d + 13, r->len);
    used = 13 + r->len;
  } else {
    tp_drec_t info;
    unsigned bits = d[0] & 3u;
    int k;
    if (!rk_set[bits] ||
        (k = tp_dopen(&rk[bits], d, n, r->body, &r->type, &info)) < 0)
      return -1;
    r->epoch = rk_epoch[bits];
    r->seq = info.seq;
    r->len = (size_t)k;
    used = info.rec_len;
  }
  dg_off += used;
  if (dg_off == dgs[dg_at].n) {
    dg_at++;
    dg_off = 0;
  }
  n_recs++;
  return 1;
}

/* The connection's handshake messages, put together from their fragments */
static tp_reasm_t reasm;
static drec_t cur; /* the record being taken apart */
static size_t cur_off;
static int cur_valid;

/* The next whole handshake message sent, in TLS form in reasm.msg: its
 * length, or 0 if what comes next is no handshake record.  @p epoch: that
 * of the record its last fragment came in. */
static size_t next_msg(unsigned *epoch) {
  size_t done = 0, used;
  for (;;) {
    if (!cur_valid || cur_off >= cur.len) {
      if (next_rec(&cur) != 1 || cur.type != TP_HANDSHAKE) {
        cur_valid = 0;
        return 0;
      }
      cur_valid = 1;
      cur_off = 0;
    }
    used = tp_reassemble(&reasm, cur.body + cur_off, cur.len - cur_off, &done);
    if (!used)
      return 0;
    cur_off += used;
    if (done) {
      *epoch = cur.epoch;
      return done;
    }
  }
}

/* Everything sent so far has been read */
static int all_read(void) {
  return dg_at == n_dgs && (!cur_valid || cur_off >= cur.len);
}

/* A record of the peer's: DTLSPlaintext for epoch 0, else sealed */
static size_t p_record(unsigned epoch, uint8_t type, const uint8_t *content,
                       size_t n, uint8_t *rec) {
  if (!epoch)
    return tp_drecord(type, p_seq0++, content, n, rec);
  return tp_dseal(&wk[epoch & 3], epoch, type, content, n, 0, rec);
}

/* One record of the peer's in a datagram of its own; dtls_input()'s result */
static int p_send(unsigned epoch, uint8_t type, const void *content, size_t n) {
  static uint8_t rec[2200];
  size_t len = p_record(epoch, type, (const uint8_t *)content, n, rec);
  return dtls_input(&sut, rec, len);
}

/* The peer's handshake message @p msg (TLS form) as message @p mseq,
 * whole, in one record */
static int p_send_msg_as(unsigned epoch, const uint8_t *msg, size_t n,
                         uint16_t mseq) {
  static uint8_t frag[2100];
  return p_send(epoch, TP_HANDSHAKE, frag,
                tp_dfragment(msg, mseq, 0, n - 4, frag));
}

/* .. as its next message */
static int p_send_msg(unsigned epoch, const uint8_t *msg, size_t n) {
  return p_send_msg_as(epoch, msg, n, p_mseq++);
}

/* An ACK of the peer's, in @p epoch, naming @p count records */
static int p_send_ack(unsigned epoch, const drec_t *recs, int count) {
  uint8_t body[2 + 16 * 8];
  int i;
  tp_put(body, 2, (uint32_t)(16 * count));
  for (i = 0; i < count; i++) {
    tp_put(body + 2 + 16 * i, 4, 0);
    tp_put(body + 2 + 16 * i + 4, 4, recs[i].epoch);
    tp_put(body + 2 + 16 * i + 8, 4, 0);
    tp_put(body + 2 + 16 * i + 12, 4, recs[i].seq);
  }
  return p_send(epoch, TP_ACK, body, (size_t)(2 + 16 * count));
}

static void reset(void) {
  n_events = 0;
  memset(events, 0, sizeof(events));
  n_dgs = dg_at = n_recs = 0;
  dg_off = largest_dg = 0;
  cur_valid = 0;
  memset(&reasm, 0, sizeof(reasm));
  memset(rk_set, 0, sizeof(rk_set));
  p_seq0 = 0;
  p_mseq = 0;
  tp_init(&peer, 1, psk, sizeof(psk), PSK_ID);
}

static int start(const tls_config_t *cfg) {
  int r;
  reset();
  r = dtls_init(&sut, cfg, sut_rx, sut_rx_cap, sut_tx, sut_tx_cap, sut_mtu);
  sut_mtu = MTU;
  sut_rx_cap = sizeof(sut_rx);
  sut_tx_cap = sizeof(sut_tx);
  sut.tls.on_event = on_event;
  return r == 0;
}

/* The connection ended with alert @p desc, and said so */
static int failed_with(uint8_t desc) {
  CHECK(dtls_state(&sut) == TLS_STATE_ERROR && sut.tls.alert == desc);
  CHECK(n_events >= 1 && events[n_events - 1] == TLS_EVT_ERROR);
  return 1;
}

/* The next record sent is a fatal alert @p desc in @p epoch, alone in its
 * datagram, and nothing follows it */
static int alert_sent(unsigned epoch, uint8_t desc) {
  drec_t r;
  collect();
  CHECK(next_rec(&r) == 1 && r.type == TP_ALERT && r.epoch == epoch);
  CHECK(r.len == 2 && r.body[0] == 2 && r.body[1] == desc);
  CHECK(all_read());
  return 1;
}

/* ── The stack's server against the scripted client ── */

static uint8_t cookie[64];
static size_t cookie_len;
static uint8_t dhe[32];
static tp_hello_t hello;
static drec_t hello_rec; /* the record the last hello read came in */

/* The peer's first ClientHello @p o; the server's HelloRetryRequest read
 * and checked (RFC 9147 §5.1, §5.4): legacy_version {254, 253}, no
 * session id echoed, DTLS 1.3 in supported_versions, a cookie */
static int cookie_exchange(const tp_ch_t *o) {
  static uint8_t m[2048];
  const uint8_t *x;
  size_t n, len, xl;
  unsigned epoch;
  n = tp_client_hello(&peer, o, m);
  CHECK(p_send_msg(0, m, n) == 0);
  CHECK(collect() == 1);
  CHECK((len = next_msg(&epoch)) > 0 && epoch == 0 && all_read());
  CHECK(reasm.msg[0] == TP_SERVER_HELLO);
  CHECK(tp_parse_hello(reasm.msg, len, 1, &hello));
  CHECK(memcmp(hello.random, tp_hrr_random, 32) == 0);
  CHECK(hello.legacy_version == 0xFEFD && hello.session_id_len == 0);
  CHECK(hello.suite == TP_SUITE);
  x = tp_ext(&hello, TP_EXT_SUPPORTED_VERSIONS, &xl);
  CHECK(x && xl == 2 && tp_get(x, 2) == 0xFEFC);
  x = tp_ext(&hello, TP_EXT_COOKIE, &xl);
  CHECK(x && xl > 2 && tp_get(x, 2) == xl - 2 && xl - 2 <= sizeof(cookie));
  cookie_len = xl - 2;
  memcpy(cookie, x + 2, cookie_len);
  tp_message_hash(&peer);
  tp_add(&peer, reasm.msg, len);
  return 1;
}

/* The server's flight read and checked: ServerHello in a DTLSPlaintext
 * record; EncryptedExtensions and Finished under the handshake keys of
 * epoch 2 (RFC 9147 §6.1), the Finished's MAC over the transcript of
 * TLS-form messages (§5.2) with the "dtls13" labels (§5.9).  Then the
 * application keys, epoch 3. */
static int read_server_flight(const tp_ch_t *o) {
  const uint8_t *x;
  uint8_t want[32];
  size_t len, xl;
  unsigned epoch;
  int with_dhe;
  CHECK((len = next_msg(&epoch)) > 0 && epoch == 0);
  hello_rec = cur;
  CHECK(reasm.msg[0] == TP_SERVER_HELLO);
  CHECK(tp_parse_hello(reasm.msg, len, 1, &hello));
  CHECK(memcmp(hello.random, tp_hrr_random, 32) != 0);
  CHECK(hello.legacy_version == 0xFEFD && hello.session_id_len == 0);
  CHECK(hello.suite == TP_SUITE && hello.compression[0] == 0);
  x = tp_ext(&hello, TP_EXT_SUPPORTED_VERSIONS, &xl);
  CHECK(x && xl == 2 && tp_get(x, 2) == 0xFEFC);
  x = tp_ext(&hello, TP_EXT_PRE_SHARED_KEY, &xl);
  if (o->no_psk)
    CHECK(x == NULL);
  else
    CHECK(x && xl == 2 && tp_get(x, 2) == 0);
  x = tp_ext(&hello, TP_EXT_KEY_SHARE, &xl);
  with_dhe = x != NULL;
  CHECK(with_dhe == (o->share && (o->psk_dhe || o->no_psk)));
  if (with_dhe)
    CHECK(xl == 36 && tp_x25519(peer.x_priv, x + 4, dhe) == 0);
  tp_early_secret(&peer, !o->no_psk);
  tp_add(&peer, reasm.msg, len);
  tp_handshake_secrets(&peer, with_dhe ? dhe : NULL);
  read_keys(2, peer.s_hs);
  write_keys(2, peer.c_hs);

  CHECK((len = next_msg(&epoch)) == 6 && epoch == 2);
  CHECK(reasm.msg[0] == TP_ENCRYPTED_EXTENSIONS);
  tp_add(&peer, reasm.msg, len);
  if (o->no_psk) { /* Certificate: the chain; CertificateVerify */
    CHECK((len = next_msg(&epoch)) > 0 && epoch == 2);
    CHECK(reasm.msg[0] == TP_CERTIFICATE && len == 4 + 4 + 3 + 481 + 2);
    CHECK(memcmp(reasm.msg + 11, server_der, sizeof(server_der)) == 0);
    tp_add(&peer, reasm.msg, len);
    CHECK((len = next_msg(&epoch)) > 0 && epoch == 2);
    CHECK(reasm.msg[0] == 15 && tp_get(reasm.msg + 4, 2) == 0x0403);
    tp_add(&peer, reasm.msg, len);
  }
  CHECK((len = next_msg(&epoch)) == 36 && epoch == 2);
  CHECK(reasm.msg[0] == TP_FINISHED);
  tp_verify_data(&peer, peer.s_hs, want);
  CHECK(memcmp(reasm.msg + 4, want, 32) == 0);
  tp_add(&peer, reasm.msg, len);
  tp_application_secrets(&peer);
  read_keys(3, peer.s_ap);
  write_keys(3, peer.c_ap);
  return 1;
}

/* The peer's ClientHello with the cookie (kept in last_hello); the
 * server's flight */
static uint8_t last_hello[2048];
static size_t last_hello_len;

static int server_flight(const tp_ch_t *o) {
  tp_ch_t o2 = *o;
  o2.cookie = cookie;
  o2.cookie_len = cookie_len;
  last_hello_len = tp_client_hello(&peer, &o2, last_hello);
  CHECK(p_send_msg(0, last_hello, last_hello_len) == 0);
  CHECK(collect() >= 1);
  return read_server_flight(o);
}

/* A server of @p cfg and the peer, as far as the server's flight */
static int server_flight_from(const tls_config_t *cfg, const tp_ch_t *o) {
  CHECK(start(cfg));
  CHECK(dtls_accept(&sut) == 0);
  CHECK(cookie_exchange(o));
  return server_flight(o);
}

/* The peer's Finished, in a record of epoch 2 */
static int client_finished(void) {
  uint8_t fin[36];
  tp_finished(&peer, peer.c_hs, fin);
  CHECK(p_send_msg(2, fin, 36) == 0);
  return 1;
}

/* The ACK the connection under test sends next: in @p epoch, naming
 * exactly the @p count records of @p want, in order (RFC 9147 §7) */
static int ack_sent(unsigned epoch, const drec_t *want, int count) {
  drec_t r;
  int i;
  CHECK(next_rec(&r) == 1 && r.type == TP_ACK && r.epoch == epoch);
  CHECK(r.len == (size_t)(2 + 16 * count) && tp_get(r.body, 2) == r.len - 2);
  for (i = 0; i < count; i++) {
    const uint8_t *e = r.body + 2 + 16 * i;
    CHECK(tp_get(e, 4) == 0 && tp_get(e + 4, 4) == want[i].epoch);
    CHECK(tp_get(e + 8, 4) == 0 && tp_get(e + 12, 4) == want[i].seq);
  }
  return 1;
}

/* The whole handshake with a server of @p cfg; its ACK of the peer's
 * Finished read */
static int connect_to_server(const tls_config_t *cfg, const tp_ch_t *o) {
  drec_t fin;
  CHECK(server_flight_from(cfg, o));
  CHECK(all_read() && dtls_state(&sut) == TLS_STATE_HANDSHAKE);
  fin.epoch = 2;
  fin.seq = (uint32_t)wk[2].seq;
  CHECK(client_finished());
  CHECK(dtls_state(&sut) == TLS_STATE_CONNECTED);
  CHECK(collect() == 1);
  CHECK(ack_sent(3, &fin, 1) && all_read());
  return 1;
}

/* ── The stack's client against the scripted server ── */

static uint8_t hello_msg[2048];
static size_t hello_len;

/* The ClientHello the client sent next, read: whole in one DTLSPlaintext
 * record */
static int read_client_hello(void) {
  unsigned epoch;
  CHECK((hello_len = next_msg(&epoch)) > 0 && epoch == 0);
  hello_rec = cur;
  CHECK(reasm.msg[0] == TP_CLIENT_HELLO);
  memcpy(hello_msg, reasm.msg, hello_len);
  CHECK(tp_parse_hello(hello_msg, hello_len, 1, &hello));
  return 1;
}

/* A client of @p cfg started; its first ClientHello read */
static int client_hello_from(const tls_config_t *cfg) {
  CHECK(start(cfg));
  CHECK(dtls_connect(&sut, NULL) == 0);
  CHECK(collect() == 1);
  CHECK(read_client_hello() && all_read());
  return 1;
}

static const uint8_t peer_cookie[9] = {'a', ' ', 'c', 'o', 'o',
                                       'k', 'i', 'e', 0};

/* The peer's HelloRetryRequest with a cookie; the second ClientHello read */
static int send_hello_retry(void) {
  static uint8_t m[512];
  tp_sh_t hrr;
  size_t n;
  memset(&hrr, 0, sizeof(hrr));
  hrr.hrr = 1;
  hrr.cookie = peer_cookie;
  hrr.cookie_len = sizeof(peer_cookie);
  tp_add(&peer, hello_msg, hello_len);
  n = tp_server_hello(&peer, &hrr, m);
  CHECK(p_send_msg(0, m, n) == 0);
  collect();
  return 1;
}

/* The peer's ServerHello taking the PSK alone, and the handshake keys */
static int send_server_hello(void) {
  static uint8_t m[512];
  size_t n;
  CHECK(tp_binder_ok(&peer, hello_msg, hello_len));
  tp_add(&peer, hello_msg, hello_len);
  tp_early_secret(&peer, 1);
  n = tp_server_hello(&peer, &sh_psk_ke, m);
  tp_handshake_secrets(&peer, NULL);
  write_keys(2, peer.s_hs);
  read_keys(2, peer.c_hs);
  CHECK(p_send_msg(0, m, n) == 0);
  return 1;
}

/* The peer's EncryptedExtensions and Finished, a record and a datagram
 * each; the application keys */
static int send_server_finished(void) {
  uint8_t m[64];
  size_t n = tp_encrypted_extensions(&peer, -1, NULL, 0, m);
  CHECK(p_send_msg(2, m, n) == 0);
  n = tp_finished(&peer, peer.s_hs, m);
  CHECK(p_send_msg(2, m, n) == 0);
  return 1;
}

/* The client's Finished read: in a record of epoch 2, its MAC over the
 * transcript; @p rec: that record */
static int read_client_finished(drec_t *rec) {
  uint8_t want[32];
  unsigned epoch;
  tp_verify_data(&peer, peer.c_hs, want);
  CHECK(next_msg(&epoch) == 36 && epoch == 2);
  CHECK(reasm.msg[0] == TP_FINISHED && memcmp(reasm.msg + 4, want, 32) == 0);
  tp_add(&peer, reasm.msg, 36);
  *rec = cur;
  return 1;
}

/* The whole handshake of a client of @p cfg with the scripted server —
 * with a cookie exchange if @p with_cookie — the client's Finished
 * acknowledged */
static int connect_from_client(const tls_config_t *cfg, int with_cookie) {
  drec_t fin;
  CHECK(client_hello_from(cfg));
  if (with_cookie) {
    CHECK(send_hello_retry());
    CHECK(read_client_hello() && all_read());
  }
  CHECK(send_server_hello());
  CHECK(send_server_finished());
  tp_application_secrets(&peer);
  CHECK(dtls_state(&sut) == TLS_STATE_CONNECTED);
  CHECK(collect() == 1);
  CHECK(read_client_finished(&fin) && all_read());
  write_keys(3, peer.s_ap);
  read_keys(3, peer.c_ap);
  CHECK(p_send_ack(3, &fin, 1) == 0);
  CHECK(collect() == 0);
  return 1;
}

/* ══ The server's handshake ═══════════════════════════════════════ */

/* REQ-DTLS-001, 004, 005, 006, 007, 010, 011, 015, 016, 018, 019, 030;
 * REQ-DTLS-031, 043: a whole handshake with the stack's server.  Its first
 * answer is a HelloRetryRequest with a cookie; both it and the ServerHello say
 * {254, 253}, select 0xfefc and echo no session id though the client sent
 * one; hellos travel in DTLSPlaintext records of epoch 0, the rest in
 * DTLSCiphertext records of epoch 2 that open as RFC 9147 §4 seals them;
 * messages are numbered 0, 1, 2, 3; the Finished verifies over TLS-form
 * messages under "dtls13" labels; the ServerHello and the protected
 * record after it share a datagram; and no record is a change_cipher_spec
 * (one would not parse here) */
TEST(itest_dtls_004_handshake_with_the_server) {
  static const uint8_t sid[32] = {1, 2, 3, 4, 5, 6, 7, 8};
  tp_ch_t o = ch_psk_ke;
  o.session_id = sid;
  o.session_id_len = sizeof(sid);
  ASSERT_TRUE(server_flight_from(&srv_psk, &o));
  ASSERT_EQ(hello_rec.seq, 1); /* the HelloRetryRequest's was 0 */
  ASSERT_EQ(cur.epoch, 2);     /* EncryptedExtensions and Finished */
  ASSERT_EQ(cur.seq, 0);       /* the first record of its epoch */
  ASSERT_EQ(cur.dgram, hello_rec.dgram);
  ASSERT_EQ(n_dgs, 2);
  ASSERT_EQ(reasm.next_seq, 4); /* HRR 0, ServerHello 1, EE 2, Finished 3 */
  ASSERT_EQ(reasm.bad, 0);
  ASSERT_TRUE(all_read());
  ASSERT_TRUE(tls_psk_used(&sut.tls));
}

/* REQ-DTLS-050, 052, 053, 056: the client's Finished completes the
 * handshake (TLS_EVT_CONNECTED) and is answered with an ACK — content
 * type 26, in epoch 3, one RecordNumber of a 64-bit epoch and a 64-bit
 * sequence number: the Finished's record.  The server's flight, answered,
 * is not sent again. */
TEST(itest_dtls_052_final_flight_acknowledged) {
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  ASSERT_EQ(n_events, 1);
  ASSERT_EQ(events[0], TLS_EVT_CONNECTED);
  ASSERT_TRUE(dtls_peer_verified(&sut));
  dtls_tick(&sut, 200000);
  ASSERT_EQ(collect(), 0);
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
}

/* REQ-DTLS-039, 021, 032, 050: a server that has finished answers the client's
 * Finished, retransmitted — the same message_seq in a new record — with
 * its ACK again, naming both records; the very same record again is a
 * replay, and gets nothing */
TEST(itest_dtls_039_ack_again_for_a_repeated_finished) {
  static uint8_t frag[64], rec[128];
  uint8_t fin[36];
  drec_t r[2];
  size_t fl, rl;
  ASSERT_TRUE(server_flight_from(&srv_psk, &ch_psk_ke));
  tp_finished(&peer, peer.c_hs, fin);
  fl = tp_dfragment(fin, p_mseq, 0, 32, frag);
  r[0].epoch = r[1].epoch = 2;
  r[0].seq = (uint32_t)wk[2].seq;
  rl = p_record(2, TP_HANDSHAKE, frag, fl, rec);
  ASSERT_EQ(dtls_input(&sut, rec, rl), 0);
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
  ASSERT_EQ(collect(), 1);
  ASSERT_TRUE(ack_sent(3, r, 1));
  ASSERT_EQ(dtls_input(&sut, rec, rl), 0); /* the same record: a replay */
  ASSERT_EQ(collect(), 0);
  r[1].seq = (uint32_t)wk[2].seq;
  rl = p_record(2, TP_HANDSHAKE, frag, fl, rec);
  ASSERT_EQ(dtls_input(&sut, rec, rl), 0);
  ASSERT_EQ(collect(), 1);
  ASSERT_TRUE(ack_sent(3, r, 2));
  ASSERT_TRUE(all_read());
  ASSERT_EQ(n_events, 1);
}

/* REQ-DTLS-001: a ClientHello that does not offer DTLS 1.3 (0xfefc) in
 * supported_versions — DTLS 1.2 only, or no extension — is refused with
 * protocol_version, in a DTLSPlaintext alert */
TEST(itest_dtls_001_dtls12_client_refused) {
  static uint8_t m[2048];
  tp_ch_t o = ch_psk_ke;
  int i;
  for (i = 0; i < 2; i++) {
    o.version = i ? 0 : 0xFEFD;
    o.no_versions = i;
    ASSERT_TRUE(start(&srv_psk));
    ASSERT_EQ(dtls_accept(&sut), 0);
    ASSERT_EQ(p_send_msg(0, m, tp_client_hello(&peer, &o, m)), -70);
    ASSERT_TRUE(failed_with(70));
    ASSERT_TRUE(alert_sent(0, 70));
  }
}

/* REQ-DTLS-003: a ClientHello whose legacy_cookie is not empty is
 * illegal_parameter */
TEST(itest_dtls_003_legacy_cookie_refused) {
  static uint8_t m[2048];
  tp_ch_t o = ch_psk_ke;
  o.legacy_cookie = (const uint8_t *)"\x01\x02";
  o.legacy_cookie_len = 2;
  ASSERT_TRUE(start(&srv_psk));
  ASSERT_EQ(dtls_accept(&sut), 0);
  ASSERT_EQ(p_send_msg(0, m, tp_client_hello(&peer, &o, m)), -47);
  ASSERT_TRUE(failed_with(47));
  ASSERT_TRUE(alert_sent(0, 47));
}

/* REQ-DTLS-044: a second ClientHello with a cookie that is not the one
 * the HelloRetryRequest carried, or with none, is illegal_parameter */
TEST(itest_dtls_044_wrong_cookie_refused) {
  static uint8_t m[2048];
  tp_ch_t o = ch_psk_ke;
  int i;
  for (i = 0; i < 2; i++) {
    ASSERT_TRUE(start(&srv_psk));
    ASSERT_EQ(dtls_accept(&sut), 0);
    ASSERT_TRUE(cookie_exchange(&ch_psk_ke));
    cookie[3] ^= 0x40;
    o.cookie = cookie;
    o.cookie_len = i ? 0 : cookie_len;
    ASSERT_EQ(p_send_msg(0, m, tp_client_hello(&peer, &o, m)), -47);
    ASSERT_TRUE(failed_with(47));
    ASSERT_TRUE(alert_sent(0, 47));
    ASSERT_FALSE(dtls_peer_verified(&sut));
  }
}

/* REQ-DTLS-043: the cookie exchange is the default — a client that
 * returns its cookie has shown it receives at its address
 * (dtls_peer_verified()) before the server's flight goes; configured not
 * to (dtls_no_cookie), the server answers the first ClientHello with its
 * ServerHello, and the peer is verified by its Finished */
TEST(itest_dtls_043_cookie_exchange_by_default) {
  static uint8_t m[2048];
  tls_config_t cfg = srv_psk;
  ASSERT_TRUE(start(&srv_psk));
  ASSERT_EQ(dtls_accept(&sut), 0);
  ASSERT_TRUE(cookie_exchange(&ch_psk_ke));
  ASSERT_FALSE(dtls_peer_verified(&sut));
  ASSERT_TRUE(server_flight(&ch_psk_ke));
  ASSERT_TRUE(dtls_peer_verified(&sut));

  cfg.dtls_no_cookie = 1;
  ASSERT_TRUE(start(&cfg));
  ASSERT_EQ(dtls_accept(&sut), 0);
  ASSERT_EQ(p_send_msg(0, m, tp_client_hello(&peer, &ch_psk_ke, m)), 0);
  ASSERT_EQ(collect(), 1);
  ASSERT_TRUE(read_server_flight(&ch_psk_ke));
  ASSERT_FALSE(dtls_peer_verified(&sut));
  ASSERT_TRUE(client_finished());
  ASSERT_TRUE(dtls_peer_verified(&sut));
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
}

/* REQ-DTLS-031, 035, 036, 037, 038: an unanswered flight is sent again
 * when the timer expires — after 1 s, then 2, 4, 8, 16, 32 — each time the
 * same messages, byte for byte with their message_seq, in new records of
 * the epochs of the first transmission (the ServerHello in epoch 0, the
 * rest in epoch 2).  After the sixth retransmission and 60 s more, the
 * connection ends: TLS_EVT_ERROR, DTLS_TIMEOUT, and no alert. */
TEST(itest_dtls_038_flight_retransmitted_by_the_timer) {
  static const uint32_t wait[6] = {1000, 2000, 4000, 8000, 16000, 32000};
  static drec_t first[2], r;
  unsigned i;
  ASSERT_TRUE(server_flight_from(&srv_psk, &ch_psk_ke));
  first[0] = hello_rec;
  first[1] = cur;
  for (i = 0; i < 6; i++) {
    dtls_tick(&sut, wait[i] - 1);
    ASSERT_EQ(collect(), 0);
    dtls_tick(&sut, 1);
    ASSERT_EQ(collect(), 1);
    ASSERT_EQ(next_rec(&r), 1);
    ASSERT_TRUE(r.epoch == 0 && r.type == TP_HANDSHAKE);
    ASSERT_EQ(r.seq, first[0].seq + 1 + i);
    ASSERT_EQ(r.len, first[0].len);
    ASSERT_MEM_EQ(r.body, first[0].body, r.len);
    ASSERT_EQ(next_rec(&r), 1);
    ASSERT_TRUE(r.epoch == 2 && r.type == TP_HANDSHAKE);
    ASSERT_EQ(r.seq, first[1].seq + 1 + i);
    ASSERT_EQ(r.len, first[1].len);
    ASSERT_MEM_EQ(r.body, first[1].body, r.len);
    ASSERT_TRUE(all_read());
  }
  dtls_tick(&sut, 59999);
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_HANDSHAKE);
  dtls_tick(&sut, 1);
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_ERROR);
  ASSERT_EQ(sut.tls.alert, DTLS_TIMEOUT);
  ASSERT_EQ(n_events, 1);
  ASSERT_EQ(events[0], TLS_EVT_ERROR);
  ASSERT_EQ(collect(), 0);
}

/* REQ-DTLS-038, 032: the peer's flight again — its ClientHello with the
 * same message_seq in a new record — shows it did not get ours: the
 * flight is sent again at once, and the repeated message is not
 * processed a second time */
TEST(itest_dtls_038_flight_again_for_a_repeated_client_hello) {
  drec_t r;
  ASSERT_TRUE(server_flight_from(&srv_psk, &ch_psk_ke));
  ASSERT_TRUE(all_read());
  ASSERT_EQ(
      p_send_msg_as(0, last_hello, last_hello_len, (uint16_t)(p_mseq - 1)), 0);
  ASSERT_EQ(collect(), 1);
  ASSERT_EQ(next_rec(&r), 1);
  ASSERT_TRUE(r.epoch == 0 && r.len == hello_rec.len);
  ASSERT_MEM_EQ(r.body, hello_rec.body, r.len);
  ASSERT_EQ(next_rec(&r), 1);
  ASSERT_EQ(r.epoch, 2);
  ASSERT_TRUE(all_read());
  ASSERT_TRUE(client_finished());
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
}

/* A fragment — bytes [off, off + n) — of the peer's message @p m, in a
 * DTLSPlaintext record of its own */
static int p_send_fragment(const uint8_t *m, uint16_t mseq, size_t off,
                           size_t n) {
  static uint8_t frag[2100];
  return p_send(0, TP_HANDSHAKE, frag, tp_dfragment(m, mseq, off, n, frag));
}

/* REQ-DTLS-034: a ClientHello in fragments that overlap and repeat is
 * reassembled; a fragment after a gap is not taken, and has to come
 * again; a fragment whose bytes differ from those already there is
 * illegal_parameter */
TEST(itest_dtls_034_fragments_reassembled) {
  static uint8_t m[2048];
  size_t n, body;
  unsigned epoch;
  ASSERT_TRUE(start(&srv_psk));
  ASSERT_EQ(dtls_accept(&sut), 0);
  n = tp_client_hello(&peer, &ch_psk_ke, m);
  body = n - 4;
  ASSERT_EQ(p_send_fragment(m, 0, 0, 50), 0);
  ASSERT_EQ(p_send_fragment(m, 0, 90, body - 90), 0); /* after a gap */
  ASSERT_EQ(p_send_fragment(m, 0, 30, 60), 0);        /* overlapping */
  ASSERT_EQ(p_send_fragment(m, 0, 0, 50), 0);         /* again */
  ASSERT_EQ(collect(), 0);
  ASSERT_EQ(p_send_fragment(m, 0, 80, body - 80), 0);
  ASSERT_EQ(collect(), 1);
  ASSERT_TRUE(next_msg(&epoch) > 0);
  ASSERT_EQ(reasm.msg[0], TP_SERVER_HELLO); /* the HelloRetryRequest */

  ASSERT_TRUE(start(&srv_psk));
  ASSERT_EQ(dtls_accept(&sut), 0);
  n = tp_client_hello(&peer, &ch_psk_ke, m);
  ASSERT_EQ(p_send_fragment(m, 0, 0, 50), 0);
  m[4 + 45] ^= 0x01;
  ASSERT_EQ(p_send_fragment(m, 0, 40, 20), -47);
  ASSERT_TRUE(failed_with(47));
  ASSERT_TRUE(alert_sent(0, 47));
}

/* REQ-DTLS-040: application data of epoch 3 that arrives before the
 * client's Finished is not delivered, then or later */
TEST(itest_dtls_040_no_application_data_before_finished) {
  uint8_t buf[16];
  ASSERT_TRUE(server_flight_from(&srv_psk, &ch_psk_ke));
  ASSERT_EQ(p_send(3, TP_APPDATA, "early", 5), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 0);
  ASSERT_TRUE(client_finished());
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 0);
  ASSERT_EQ(p_send(3, TP_APPDATA, "now", 3), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 3);
}

/* ══ Records ══════════════════════════════════════════════════════ */

/* REQ-DTLS-011, 015, 016: application data sent — one record, one
 * datagram: the unified header 0x2F (001, no CID, a 16-bit sequence
 * number, a length, epoch bits 11), its record number masked with
 * AES-ECB of the ciphertext's first block, opening with the unmasked
 * header as additional data and the 64-bit record number in the nonce.
 * Record numbers count from 0 in each epoch. */
TEST(itest_dtls_011_application_data_record) {
  drec_t r;
  int i;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  for (i = 0; i < 3; i++) {
    ASSERT_EQ(dtls_write(&sut, (const uint8_t *)"datagram", 8), 8);
    ASSERT_EQ(collect(), 1);
    ASSERT_EQ(dgs[n_dgs - 1].b[0], 0x2F);
    ASSERT_EQ(dgs[n_dgs - 1].n, 5 + 8 + 1 + 16);
    ASSERT_EQ(tp_get(dgs[n_dgs - 1].b + 3, 2), 8 + 1 + 16);
    ASSERT_EQ(next_rec(&r), 1);
    ASSERT_TRUE(r.epoch == 3 && r.type == TP_APPDATA && r.len == 8);
    ASSERT_EQ(r.seq, 1u + (unsigned)i); /* the ACK was record 0 */
    ASSERT_MEM_EQ(r.body, "datagram", 8);
  }
}

/* REQ-DTLS-012, 017, 019: records with an 8-bit sequence number and no
 * length are received — such a record takes the rest of its datagram,
 * after one with a length — and the full record number is the one
 * closest to the next expected, also across a wrap of the 8 bits */
TEST(itest_dtls_012_short_header_received) {
  static uint8_t dg[256];
  uint8_t buf[16];
  size_t n;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  n = tp_dseal(&wk[3], 3, TP_APPDATA, (const uint8_t *)"short", 5, 1, dg);
  ASSERT_EQ(dg[0], 0x23);
  ASSERT_EQ(n, 2 + 5 + 1 + 16);
  ASSERT_EQ(dtls_input(&sut, dg, n), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 5);

  n = tp_dseal(&wk[3], 3, TP_APPDATA, (const uint8_t *)"one", 3, 0, dg);
  n += tp_dseal(&wk[3], 3, TP_APPDATA, (const uint8_t *)"two", 3, 1, dg + n);
  ASSERT_EQ(dtls_input(&sut, dg, n), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 3);
  ASSERT_MEM_EQ(buf, "one", 3);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 3);
  ASSERT_MEM_EQ(buf, "two", 3);

  wk[3].seq = 103; /* a hundred records lost */
  n = tp_dseal(&wk[3], 3, TP_APPDATA, (const uint8_t *)"far", 3, 1, dg);
  ASSERT_EQ(dtls_input(&sut, dg, n), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 3);
  wk[3].seq = 250;
  n = tp_dseal(&wk[3], 3, TP_APPDATA, (const uint8_t *)"250", 3, 1, dg);
  ASSERT_EQ(dtls_input(&sut, dg, n), 0);
  wk[3].seq = 260; /* low bits 4: past the wrap, not 250 behind */
  n = tp_dseal(&wk[3], 3, TP_APPDATA, (const uint8_t *)"260", 3, 1, dg);
  ASSERT_EQ(dtls_input(&sut, dg, n), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 3);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 3);
  ASSERT_MEM_EQ(buf, "260", 3);
  /* with 16 bits: across their wrap too, in steps of less than 2^15 */
  for (wk[3].seq = 30000; wk[3].seq < 100000; wk[3].seq += 29999) {
    n = tp_dseal(&wk[3], 3, TP_APPDATA, (const uint8_t *)"16", 2, 0, dg);
    ASSERT_EQ(dtls_input(&sut, dg, n), 0);
    ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 2); /* .. 60000, 90000 */
  }
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
}

/* REQ-DTLS-021: a record received twice is delivered once; records out of
 * order within the window are taken, each once; one older than the window
 * is dropped */
TEST(itest_dtls_021_replayed_record_dropped) {
  static uint8_t a[64], b[64], c[64];
  uint8_t buf[16];
  size_t an, bn, cn;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  an = tp_dseal(&wk[3], 3, TP_APPDATA, (const uint8_t *)"a", 1, 0, a);
  bn = tp_dseal(&wk[3], 3, TP_APPDATA, (const uint8_t *)"b", 1, 0, b);
  cn = tp_dseal(&wk[3], 3, TP_APPDATA, (const uint8_t *)"c", 1, 0, c);
  ASSERT_EQ(dtls_input(&sut, a, an), 0);
  ASSERT_EQ(dtls_input(&sut, a, an), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 1);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 0);
  ASSERT_EQ(dtls_input(&sut, c, cn), 0);
  ASSERT_EQ(dtls_input(&sut, b, bn), 0);
  ASSERT_EQ(dtls_input(&sut, c, cn), 0);
  ASSERT_EQ(dtls_input(&sut, b, bn), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 1);
  ASSERT_EQ(buf[0], 'c');
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 1);
  ASSERT_EQ(buf[0], 'b');
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 0);

  wk[3].seq = 50;
  an = tp_dseal(&wk[3], 3, TP_APPDATA, (const uint8_t *)"n", 1, 0, a);
  ASSERT_EQ(dtls_input(&sut, a, an), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 1);
  wk[3].seq = 10; /* never received, but 40 behind: outside the window */
  an = tp_dseal(&wk[3], 3, TP_APPDATA, (const uint8_t *)"o", 1, 0, a);
  ASSERT_EQ(dtls_input(&sut, a, an), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 0);
  wk[3].seq = 30; /* 20 behind: inside it, and new */
  an = tp_dseal(&wk[3], 3, TP_APPDATA, (const uint8_t *)"w", 1, 0, a);
  ASSERT_EQ(dtls_input(&sut, a, an), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 1);
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
  ASSERT_EQ(collect(), 0);
}

/* REQ-DTLS-013, 014, 016, 022, 023, 054: what is no valid record is dropped
 * without an alert and the connection goes on: a first byte that is
 * neither a plaintext type nor 001xxxxx, a record with the Connection ID
 * bit, one with less than 16 bytes of ciphertext, one that fails
 * authentication, a truncated one, an unprotected ACK or alert, a
 * DTLSPlaintext record of another epoch.  The two that failed
 * deprotection are counted. */
TEST(itest_dtls_022_invalid_records_dropped_silently) {
  static const uint8_t junk[8] = {0x40, 1, 2, 3, 4, 5, 6, 7};
  static const uint8_t tiny[20] = {0x2F, 0, 0, 0, 15};
  static const uint8_t alert[2] = {2, 40};
  static uint8_t good[64], bad[64], plain[64];
  uint8_t buf[16];
  drec_t none;
  size_t n, pn;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  n = tp_dseal(&wk[3], 3, TP_APPDATA, (const uint8_t *)"good", 4, 0, good);
  ASSERT_EQ(dtls_input(&sut, junk, sizeof(junk)), 0);
  memcpy(bad, good, n);
  bad[0] |= 0x10; /* C: a Connection ID follows */
  ASSERT_EQ(dtls_input(&sut, bad, n), 0);
  ASSERT_EQ(dtls_input(&sut, tiny, sizeof(tiny)), 0);
  memcpy(bad, good, n);
  bad[n - 1] ^= 0x01;
  ASSERT_EQ(dtls_input(&sut, bad, n), 0);
  ASSERT_EQ(dtls_input(&sut, good, 12), 0); /* cut short */
  none.epoch = 3;
  none.seq = 0;
  memset(buf, 0, sizeof(buf));
  buf[1] = 16; /* an ACK of record {3, 0}, unprotected */
  buf[9] = 3;
  pn = tp_drecord(TP_ACK, 9, buf, 2 + 16, plain);
  ASSERT_EQ(dtls_input(&sut, plain, pn), 0);
  pn = tp_drecord(TP_ALERT, 10, alert, 2, plain);
  ASSERT_EQ(dtls_input(&sut, plain, pn), 0);
  pn = tp_drecord(TP_HANDSHAKE, 11, last_hello, 40, plain);
  plain[4] = 1; /* epoch 1 */
  ASSERT_EQ(dtls_input(&sut, plain, pn), 0);
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
  ASSERT_EQ(collect(), 0);
  ASSERT_EQ(n_events, 1);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 0);
  ASSERT_EQ(sut.bad_records, 2);
  ASSERT_EQ(dtls_input(&sut, good, n), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 4);
  (void)none;
}

/* REQ-DTLS-046, 047: the peer's close_notify is reported
 * (TLS_EVT_CLOSED) and what it sends afterwards is ignored; the
 * connection may still write, and dtls_close() sends its own close_notify
 * — once: it is not retransmitted */
TEST(itest_dtls_047_close_notify) {
  static const uint8_t close_notify[2] = {1, 0};
  uint8_t buf[16];
  drec_t r;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  ASSERT_EQ(p_send(3, TP_ALERT, close_notify, 2), 0);
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CLOSED);
  ASSERT_EQ(n_events, 2);
  ASSERT_EQ(events[1], TLS_EVT_CLOSED);
  ASSERT_EQ(p_send(3, TP_APPDATA, "late", 4), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 0);
  ASSERT_EQ(collect(), 0);

  ASSERT_EQ(dtls_write(&sut, (const uint8_t *)"bye", 3), 3);
  ASSERT_EQ(collect(), 1);
  ASSERT_EQ(next_rec(&r), 1);
  ASSERT_TRUE(r.type == TP_APPDATA && r.len == 3);
  ASSERT_EQ(dtls_close(&sut), 0);
  ASSERT_EQ(collect(), 1);
  ASSERT_EQ(next_rec(&r), 1);
  ASSERT_TRUE(r.type == TP_ALERT && r.epoch == 3 && r.len == 2);
  ASSERT_TRUE(r.body[0] == 1 && r.body[1] == 0);
  ASSERT_EQ(dtls_close(&sut), 0);
  dtls_tick(&sut, 200000);
  ASSERT_EQ(collect(), 0);
  ASSERT_EQ(dtls_write(&sut, (const uint8_t *)"x", 1), -1);
}

/* REQ-DTLS-046: a fatal alert is sent once — here decrypt_error for a
 * Finished that does not verify — and never again, whatever the timer or
 * the peer does */
TEST(itest_dtls_046_alert_not_retransmitted) {
  uint8_t fin[36];
  ASSERT_TRUE(server_flight_from(&srv_psk, &ch_psk_ke));
  tp_finished(&peer, peer.c_hs, fin);
  fin[20] ^= 0x04;
  ASSERT_EQ(p_send_msg(2, fin, 36), -51);
  ASSERT_TRUE(failed_with(51));
  ASSERT_TRUE(alert_sent(3, 51));
  dtls_tick(&sut, 200000);
  ASSERT_EQ(p_send_msg_as(2, fin, 36, (uint16_t)(p_mseq - 1)), -51);
  ASSERT_EQ(collect(), 0);
}

/* ══ ACKs ═════════════════════════════════════════════════════════ */

/* REQ-DTLS-057, 056: a flight is answered once every record of one of its
 * transmissions has been named in some ACK.  An ACK of the ServerHello's
 * record alone leaves the timer running; a second ACK, of the other
 * record, stops it — though the flight has been sent again since. */
TEST(itest_dtls_057_record_acknowledged_by_any_ack) {
  drec_t sh, rest;
  ASSERT_TRUE(server_flight_from(&srv_psk, &ch_psk_ke));
  sh = hello_rec;
  rest = cur;
  ASSERT_EQ(p_send_ack(2, &sh, 1), 0);
  dtls_tick(&sut, 1000);
  ASSERT_EQ(collect(), 1); /* not all of it was acknowledged */
  ASSERT_EQ(p_send_ack(2, &rest, 1), 0);
  dtls_tick(&sut, 200000);
  ASSERT_EQ(collect(), 1 - 1);
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_HANDSHAKE);
  ASSERT_TRUE(client_finished());
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
}

/* ══ KeyUpdate ════════════════════════════════════════════════════ */

static const uint8_t ku_requested[5] = {TP_KEY_UPDATE, 0, 0, 1, 1};
static const uint8_t ku_not_requested[5] = {TP_KEY_UPDATE, 0, 0, 1, 0};

/* REQ-DTLS-060, 018, 038, 057: dtls_key_update() sends a KeyUpdate in the
 * current epoch, and records go on under the current keys — no second
 * KeyUpdate either — until the peer acknowledges it; unanswered, it is
 * retransmitted; acknowledged (by an ACK of either transmission), the
 * next epoch begins, with record numbers from 0 */
TEST(itest_dtls_060_key_update_of_ours) {
  drec_t ku, r;
  unsigned epoch;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  ASSERT_EQ(dtls_key_update(&sut, 0), 0);
  ASSERT_EQ(collect(), 1);
  ASSERT_EQ(next_msg(&epoch), 5);
  ASSERT_EQ(epoch, 3);
  ASSERT_MEM_EQ(reasm.msg, ku_not_requested, 5);
  ku = cur;
  ASSERT_EQ(dtls_key_update(&sut, 0), 0); /* owed: not before the ACK */
  ASSERT_EQ(collect(), 0);
  ASSERT_EQ(dtls_write(&sut, (const uint8_t *)"old", 3), 3);
  ASSERT_EQ(collect(), 1);
  ASSERT_EQ(next_rec(&r), 1);
  ASSERT_TRUE(r.epoch == 3 && r.type == TP_APPDATA);
  dtls_tick(&sut, 1000);
  ASSERT_EQ(collect(), 1);
  ASSERT_EQ(next_rec(&r), 1);
  ASSERT_TRUE(r.epoch == 3 && r.type == TP_HANDSHAKE && r.seq > ku.seq);
  ASSERT_EQ(r.len, ku.len);
  ASSERT_MEM_EQ(r.body, ku.body, r.len);

  ASSERT_EQ(p_send_ack(3, &ku, 1), 0);
  tp_update_secret(1, peer.s_ap);
  read_keys(4, peer.s_ap);
  ASSERT_EQ(collect(), 1); /* the second KeyUpdate, in the new epoch */
  ASSERT_EQ(next_msg(&epoch), 5);
  ASSERT_EQ(epoch, 4);
  ASSERT_EQ(cur.seq, 0);
  ku = cur;
  ASSERT_EQ(dtls_write(&sut, (const uint8_t *)"new", 3), 3);
  ASSERT_EQ(collect(), 1);
  ASSERT_EQ(next_rec(&r), 1);
  ASSERT_TRUE(r.epoch == 4 && r.type == TP_APPDATA && r.seq == 1);
  ASSERT_EQ(p_send_ack(3, &ku, 1), 0);
  tp_update_secret(1, peer.s_ap);
  read_keys(5, peer.s_ap);
  ASSERT_EQ(dtls_write(&sut, (const uint8_t *)"newer", 5), 5);
  ASSERT_EQ(collect(), 1);
  ASSERT_EQ(next_rec(&r), 1);
  ASSERT_TRUE(r.epoch == 5 && r.type == TP_APPDATA && r.seq == 0);
  dtls_tick(&sut, 200000);
  ASSERT_EQ(collect(), 0);
}

/* REQ-DTLS-052, 053, 061, 060: the peer's KeyUpdate is acknowledged — in
 * the highest sending epoch — and its records are read under the new keys
 * and, arriving late, still under the old ones; asked to update too, the
 * connection sends a KeyUpdate of its own that does not ask back */
TEST(itest_dtls_061_key_update_from_the_peer) {
  static uint8_t late[64];
  uint8_t buf[16];
  drec_t acked[3], r;
  unsigned epoch;
  size_t late_len;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  acked[0].epoch = 2; /* the Finished: still on the list */
  acked[0].seq = 0;
  acked[1].epoch = 3;
  acked[1].seq = (uint32_t)wk[3].seq;
  ASSERT_EQ(p_send_msg(3, ku_not_requested, 5), 0);
  ASSERT_EQ(collect(), 1);
  ASSERT_TRUE(ack_sent(3, acked, 2) && all_read());
  late_len =
      tp_dseal(&wk[3], 3, TP_APPDATA, (const uint8_t *)"late", 4, 0, late);
  tp_update_secret(1, peer.c_ap);
  write_keys(4, peer.c_ap);
  ASSERT_EQ(p_send(4, TP_APPDATA, "new", 3), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 3);
  ASSERT_MEM_EQ(buf, "new", 3);
  ASSERT_EQ(dtls_input(&sut, late, late_len), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 4);
  ASSERT_MEM_EQ(buf, "late", 4);

  acked[2].epoch = 4;
  acked[2].seq = (uint32_t)wk[0].seq;
  ASSERT_EQ(p_send_msg(4, ku_requested, 5), 0);
  ASSERT_EQ(collect(), 1);
  ASSERT_TRUE(ack_sent(3, acked, 3));
  ASSERT_EQ(next_msg(&epoch), 5);
  ASSERT_EQ(epoch, 3);
  ASSERT_MEM_EQ(reasm.msg, ku_not_requested, 5);
  ASSERT_TRUE(all_read());
  r = cur;
  ASSERT_EQ(p_send_ack(4, &r, 1), 0);
  tp_update_secret(1, peer.s_ap);
  read_keys(4, peer.s_ap);
  ASSERT_EQ(dtls_write(&sut, (const uint8_t *)"mine", 4), 4);
  ASSERT_EQ(collect(), 1);
  ASSERT_EQ(next_rec(&r), 1);
  ASSERT_TRUE(r.epoch == 4 && r.type == TP_APPDATA);
}

/* ══ The client's handshake ═══════════════════════════════════════ */

/* REQ-DTLS-001, 002, 010, 030, 031: the ClientHello — a DTLSPlaintext
 * record: content type 22, version {254, 253}, epoch 0, record number 0 —
 * is message 0, whole (fragment_offset 0, fragment_length its length);
 * legacy_version {254, 253}, an empty legacy_session_id and
 * legacy_cookie, and DTLS 1.3 alone in supported_versions */
TEST(itest_dtls_002_client_hello) {
  const uint8_t *d, *x;
  size_t xl;
  ASSERT_TRUE(client_hello_from(&cli_psk));
  d = dgs[0].b;
  ASSERT_EQ(d[0], TP_HANDSHAKE);
  ASSERT_EQ(tp_get(d + 1, 2), 0xFEFD);
  ASSERT_EQ(tp_get(d + 3, 2), 0);
  ASSERT_TRUE(tp_get(d + 5, 2) == 0 && tp_get(d + 7, 4) == 0);
  ASSERT_EQ(tp_get(d + 11, 2), dgs[0].n - 13);
  ASSERT_EQ(d[13], TP_CLIENT_HELLO);
  ASSERT_EQ(tp_get(d + 14, 3), hello_len - 4);
  ASSERT_EQ(tp_get(d + 17, 2), 0); /* message_seq */
  ASSERT_EQ(tp_get(d + 19, 3), 0); /* fragment_offset */
  ASSERT_EQ(tp_get(d + 22, 3), hello_len - 4);
  ASSERT_EQ(dgs[0].n, 13 + 12 + hello_len - 4);
  ASSERT_EQ(hello.legacy_version, 0xFEFD);
  ASSERT_EQ(hello.session_id_len, 0);
  ASSERT_EQ(hello.legacy_cookie_len, 0);
  x = tp_ext(&hello, TP_EXT_SUPPORTED_VERSIONS, &xl);
  ASSERT_TRUE(x && xl == 3 && x[0] == 2 && tp_get(x + 1, 2) == 0xFEFC);
  ASSERT_TRUE(tp_ext(&hello, TP_EXT_COOKIE, &xl) == NULL);
}

/* REQ-DTLS-042, 031, 006, 007: a HelloRetryRequest's cookie comes back in
 * the second ClientHello — message 1, in record 1, with the same random —
 * and the handshake completes on the transcript that begins with
 * message_hash; without a cookie exchange it completes too */
TEST(itest_dtls_042_cookie_echoed) {
  static uint8_t first_random[32];
  const uint8_t *x;
  size_t xl;
  ASSERT_TRUE(client_hello_from(&cli_psk));
  memcpy(first_random, hello.random, 32);
  ASSERT_TRUE(send_hello_retry());
  ASSERT_TRUE(read_client_hello() && all_read());
  ASSERT_EQ(hello_rec.seq, 1);
  ASSERT_EQ(tp_get(hello_rec.body + 4, 2), 1); /* message_seq */
  ASSERT_MEM_EQ(hello.random, first_random, 32);
  x = tp_ext(&hello, TP_EXT_COOKIE, &xl);
  ASSERT_TRUE(x && xl == 2 + sizeof(peer_cookie));
  ASSERT_EQ(tp_get(x, 2), sizeof(peer_cookie));
  ASSERT_MEM_EQ(x + 2, peer_cookie, sizeof(peer_cookie));

  ASSERT_TRUE(connect_from_client(&cli_psk, 1));
  ASSERT_EQ(n_events, 1);
  ASSERT_EQ(events[0], TLS_EVT_CONNECTED);
  ASSERT_TRUE(connect_from_client(&cli_psk, 0));
}

/* REQ-DTLS-045: a second HelloRetryRequest is unexpected_message */
TEST(itest_dtls_045_second_hello_retry_refused) {
  static uint8_t m[512];
  tp_sh_t hrr;
  ASSERT_TRUE(client_hello_from(&cli_psk));
  ASSERT_TRUE(send_hello_retry());
  ASSERT_TRUE(read_client_hello() && all_read());
  memset(&hrr, 0, sizeof(hrr));
  hrr.hrr = 1;
  hrr.cookie = peer_cookie;
  hrr.cookie_len = sizeof(peer_cookie);
  tp_add(&peer, hello_msg, hello_len);
  ASSERT_EQ(p_send_msg(0, m, tp_server_hello(&peer, &hrr, m)), -10);
  ASSERT_TRUE(failed_with(10));
  ASSERT_TRUE(alert_sent(0, 10));
}

/* REQ-DTLS-001: a ServerHello that selects DTLS 1.2 is refused
 * (illegal_parameter: not a version the client offered) */
TEST(itest_dtls_001_dtls12_server_refused) {
  static uint8_t m[512];
  tp_sh_t o = sh_psk_ke;
  o.version = 0xFEFD;
  ASSERT_TRUE(client_hello_from(&cli_psk));
  tp_add(&peer, hello_msg, hello_len);
  ASSERT_EQ(p_send_msg(0, m, tp_server_hello(&peer, &o, m)), -47);
  ASSERT_TRUE(failed_with(47));
  ASSERT_TRUE(alert_sent(0, 47));
}

/* REQ-DTLS-036, 038, 056: the client's Finished, unanswered, is sent
 * again when the timer expires — under the handshake keys of epoch 2 it
 * first went under, though the client already sends data in epoch 3 —
 * until an ACK names its record */
TEST(itest_dtls_036_finished_resent_under_its_own_keys) {
  drec_t fin, r;
  ASSERT_TRUE(client_hello_from(&cli_psk));
  ASSERT_TRUE(send_server_hello());
  ASSERT_TRUE(send_server_finished());
  tp_application_secrets(&peer);
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
  ASSERT_EQ(collect(), 1);
  ASSERT_TRUE(read_client_finished(&fin) && all_read());
  write_keys(3, peer.s_ap);
  read_keys(3, peer.c_ap);
  ASSERT_EQ(dtls_write(&sut, (const uint8_t *)"data", 4), 4);
  ASSERT_EQ(collect(), 1);
  ASSERT_EQ(next_rec(&r), 1);
  ASSERT_TRUE(r.epoch == 3 && r.type == TP_APPDATA);
  dtls_tick(&sut, 1000);
  ASSERT_EQ(collect(), 1);
  ASSERT_EQ(next_rec(&r), 1);
  ASSERT_TRUE(r.epoch == 2 && r.type == TP_HANDSHAKE);
  ASSERT_EQ(r.seq, fin.seq + 1);
  ASSERT_EQ(r.len, fin.len);
  ASSERT_MEM_EQ(r.body, fin.body, r.len);
  ASSERT_EQ(p_send_ack(3, &r, 1), 0);
  dtls_tick(&sut, 200000);
  ASSERT_EQ(collect(), 0);
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
}

/* REQ-DTLS-051, 053, 055: a message that arrives before the one expected
 * is not taken — and its record is not acknowledged: the ACK the client
 * sends for the disruption, in epoch 2 (the highest it can send in),
 * names the ServerHello's record alone.  The flight in order completes
 * the handshake. */
TEST(itest_dtls_051_only_records_taken_are_acknowledged) {
  uint8_t ee[16], fin[36];
  drec_t sh;
  size_t n;
  ASSERT_TRUE(client_hello_from(&cli_psk));
  sh.epoch = 0;
  sh.seq = p_seq0;
  ASSERT_TRUE(send_server_hello());
  ASSERT_EQ(collect(), 0);
  n = tp_encrypted_extensions(&peer, -1, NULL, 0, ee);
  tp_finished(&peer, peer.s_hs, fin);
  ASSERT_EQ(p_send_msg_as(2, fin, 36, (uint16_t)(p_mseq + 1)), 0);
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_HANDSHAKE);
  ASSERT_EQ(collect(), 1);
  read_keys(2, peer.c_hs);
  ASSERT_TRUE(ack_sent(2, &sh, 1) && all_read());
  ASSERT_EQ(p_send_msg(2, ee, n), 0);
  ASSERT_EQ(p_send_msg(2, fin, 36), 0);
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
}

/* REQ-DTLS-052, 054: after the handshake, a record of application data
 * draws no ACK; a NewSessionTicket — a handshake message the client
 * ignores — is acknowledged, its record alone on the list */
TEST(itest_dtls_054_only_handshake_records_acknowledged) {
  static const uint8_t ticket[19] = {TP_NEW_SESSION_TICKET,
                                     0,
                                     0,
                                     15,
                                     0,
                                     0,
                                     0,
                                     60,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     2,
                                     'T',
                                     'K',
                                     0,
                                     0};
  uint8_t buf[8];
  drec_t r;
  ASSERT_TRUE(connect_from_client(&cli_psk, 0));
  ASSERT_EQ(p_send(3, TP_APPDATA, "data", 4), 0);
  ASSERT_EQ(collect(), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 4);
  r.epoch = 3;
  r.seq = (uint32_t)wk[3].seq;
  ASSERT_EQ(p_send_msg(3, ticket, sizeof(ticket)), 0);
  ASSERT_EQ(collect(), 1);
  ASSERT_TRUE(ack_sent(3, &r, 1) && all_read());
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
}

/* REQ-DTLS-056: any record of the peer's next flight answers ours (RFC
 * 9147 §7.2) — the first fragment of the ServerHello stops the
 * ClientHello's retransmission, before the message is whole */
TEST(itest_dtls_056_flight_answered_by_a_fragment_of_the_next) {
  static uint8_t m[512];
  size_t n;
  ASSERT_TRUE(client_hello_from(&cli_psk));
  ASSERT_TRUE(tp_binder_ok(&peer, hello_msg, hello_len));
  tp_add(&peer, hello_msg, hello_len);
  tp_early_secret(&peer, 1);
  n = tp_server_hello(&peer, &sh_psk_ke, m);
  ASSERT_EQ(p_send_fragment(m, 0, 0, 20), 0);
  dtls_tick(&sut, 1000);
  ASSERT_EQ(collect(), 0);
  ASSERT_EQ(p_send_fragment(m, 0, 20, n - 4 - 20), 0);
  p_mseq = 1;
  tp_handshake_secrets(&peer, NULL);
  write_keys(2, peer.s_hs);
  read_keys(2, peer.c_hs);
  ASSERT_TRUE(send_server_finished());
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
}

/* ══ Fragmentation ════════════════════════════════════════════════ */

/* REQ-DTLS-033, 019, 020, 041: with 200-byte datagrams the server's
 * certificate flight — ServerHello, EncryptedExtensions, Certificate,
 * CertificateVerify, Finished — goes as fragments, each in a datagram of
 * at most 200 bytes that begins with a record, their ranges in order and
 * not overlapping, in no more than 10 records; reassembled, the
 * Certificate is the configured chain and the Finished verifies */
TEST(itest_dtls_033_flight_in_fragments) {
  tp_ch_t o;
  int i, before;
  memset(&o, 0, sizeof(o));
  o.no_psk = 1;
  o.share = 1;
  o.sig_algs = 1;
  sut_mtu = 200;
  ASSERT_TRUE(start(&srv_cert));
  ASSERT_EQ(dtls_accept(&sut), 0);
  ASSERT_TRUE(cookie_exchange(&o));
  before = n_recs;
  ASSERT_TRUE(server_flight(&o));
  ASSERT_TRUE(all_read());
  ASSERT_TRUE(n_dgs >= 6);
  ASSERT_TRUE(largest_dg <= 200);
  ASSERT_TRUE(n_recs - before <= 10);
  for (i = 0; i < n_dgs; i++)
    ASSERT_TRUE(dgs[i].b[0] == TP_HANDSHAKE || (dgs[i].b[0] & 0xE0) == 0x20);
  ASSERT_EQ(reasm.overlaps, 0);
  ASSERT_EQ(reasm.bad, 0);
  ASSERT_TRUE(client_finished());
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
  ASSERT_FALSE(tls_psk_used(&sut.tls));
  ASSERT_EQ(dtls_max_data(&sut), 200 - DTLS_RECORD_OVERHEAD);
}

/* REQ-DTLS-051: a record whose handshake messages find no room is not
 * acknowledged.  Here a record brings a NewSessionTicket and a KeyUpdate
 * while unread data fills the receive buffer: neither is taken, and the
 * ACK that answers names no record — naming this one would tell the peer
 * its KeyUpdate had arrived, and its next epoch could never be read.
 * Once the application has read, the record sent again is taken and
 * acknowledged, and the new epoch is read. */
TEST(itest_dtls_051_record_with_a_fragment_not_taken) {
  static const uint8_t ticket[19] = {TP_NEW_SESSION_TICKET,
                                     0,
                                     0,
                                     15,
                                     0,
                                     0,
                                     0,
                                     60,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     2,
                                     'T',
                                     'K',
                                     0,
                                     0};
  static uint8_t data[1100], frags[64], buf[1100];
  drec_t r;
  size_t fl;
  int i;
  ASSERT_TRUE(connect_from_client(&cli_psk, 0));
  for (i = 0; i < 4; i++) /* 4038 of the 4096 bytes of rx: 58 are free */
    ASSERT_EQ(p_send(3, TP_APPDATA, data, i < 3 ? 1000 : 1030), 0);
  fl = tp_dfragment(ticket, p_mseq, 0, 15, frags);
  fl +=
      tp_dfragment(ku_not_requested, (uint16_t)(p_mseq + 1), 0, 1, frags + fl);
  ASSERT_EQ(p_send(3, TP_HANDSHAKE, frags, fl), 0); /* a 57-byte record */
  ASSERT_EQ(collect(), 1);
  ASSERT_TRUE(ack_sent(3, NULL, 0) && all_read()); /* an ACK of nothing */
  for (i = 0; i < 4; i++)
    ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), i < 3 ? 1000 : 1030);
  r.epoch = 3;
  r.seq = (uint32_t)wk[3].seq;
  ASSERT_EQ(p_send(3, TP_HANDSHAKE, frags, fl), 0);
  ASSERT_EQ(collect(), 1);
  ASSERT_TRUE(ack_sent(3, &r, 1) && all_read());
  tp_update_secret(1, peer.s_ap);
  write_keys(4, peer.s_ap);
  ASSERT_EQ(p_send(4, TP_APPDATA, "epoch 4", 7), 0);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 7);
}

/* REQ-DTLS-051 (its deviation): a record is on the ACK list from its
 * first fragment taken.  Two NewSessionTickets in one record, the second
 * too long for the room unread data leaves: the first is taken, the
 * second is not — and the record is acknowledged all the same.  A client
 * ignores tickets, so nothing is lost with it. */
TEST(itest_dtls_051_record_acknowledged_in_part) {
  static uint8_t data[1100], frags[300], ticket[204], buf[1100];
  drec_t r;
  size_t fl;
  int i;
  ASSERT_TRUE(connect_from_client(&cli_psk, 0));
  for (i = 0; i < 4; i++) /* 3800 of the 4096 bytes of rx */
    ASSERT_EQ(p_send(3, TP_APPDATA, data, i < 3 ? 1000 : 792), 0);
  memset(ticket, 0, sizeof(ticket));
  ticket[0] = TP_NEW_SESSION_TICKET;
  ticket[3] = 15;
  fl = tp_dfragment(ticket, p_mseq, 0, 15, frags);
  ticket[3] = 200;
  fl += tp_dfragment(ticket, (uint16_t)(p_mseq + 1), 0, 200, frags + fl);
  r.epoch = 3;
  r.seq = (uint32_t)wk[3].seq;
  ASSERT_EQ(p_send(3, TP_HANDSHAKE, frags, fl), 0);
  ASSERT_EQ(collect(), 1);
  ASSERT_TRUE(ack_sent(3, &r, 1) && all_read());
  for (i = 0; i < 4; i++)
    ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), i < 3 ? 1000 : 792);
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
}

/* ══ The stack's client and server together ═══════════════════════ */

/* Two connections and the network between them: arrays of the test's.
 * Direction 0 is client to server. */
static dtls_conn_t pc, ps;
static uint8_t pc_rx[4096], pc_tx[4096], ps_rx[4096], ps_tx[4096];
static size_t pc_rx_cap = sizeof(pc_rx), ps_tx_cap = sizeof(ps_tx);
static uint8_t pc_events, ps_events;
#define NET_MAX 64
static struct {
  uint8_t b[1600];
  size_t n;
} in_flight[2][NET_MAX];
static int n_in_flight[2], n_sent[2];
static size_t pair_largest;
static int reversed; /* each batch is delivered last datagram first */
/* What becomes of the @p i th datagram sent in direction @p dir: 0
 * delivered, 1 lost, 2 delivered twice */
static int (*fate)(int dir, int i);

static void on_pc(tls_conn_t *c, uint8_t e) {
  (void)c;
  pc_events |= e;
}

static void on_ps(tls_conn_t *c, uint8_t e) {
  (void)c;
  ps_events |= e;
}

static void pair_put(int dir, const uint8_t *p, size_t n) {
  if (n_in_flight[dir] < NET_MAX && n <= sizeof(in_flight[0][0].b)) {
    memcpy(in_flight[dir][n_in_flight[dir]].b, p, n);
    in_flight[dir][n_in_flight[dir]++].n = n;
  }
}

static void pair_send(dtls_conn_t *d, int dir) {
  const uint8_t *p;
  size_t n;
  while ((n = dtls_pending(d, &p)) > 0) {
    int f = fate ? fate(dir, n_sent[dir]) : 0;
    n_sent[dir]++;
    if (n > pair_largest)
      pair_largest = n;
    if (f != 1)
      pair_put(dir, p, n);
    if (f == 2)
      pair_put(dir, p, n);
    dtls_sent(d);
  }
}

static int pair_deliver(int dir, dtls_conn_t *to) {
  static uint8_t batch[NET_MAX][1600];
  static size_t len[NET_MAX];
  int i, k = n_in_flight[dir];
  for (i = 0; i < k; i++) {
    len[i] = in_flight[dir][i].n;
    memcpy(batch[i], in_flight[dir][i].b, len[i]);
  }
  n_in_flight[dir] = 0;
  for (i = 0; i < k; i++) {
    int j = reversed ? k - 1 - i : i;
    (void)dtls_input(to, batch[j], len[j]);
  }
  return k;
}

/* Move datagrams until none is on its way; then let a second pass, up to
 * @p seconds of them */
static void pair_run(int seconds) {
  for (;;) {
    pair_send(&pc, 0);
    pair_send(&ps, 1);
    if (pair_deliver(0, &ps) + pair_deliver(1, &pc) > 0)
      continue;
    if (seconds-- <= 0)
      return;
    dtls_tick(&pc, 1000);
    dtls_tick(&ps, 1000);
  }
}

/* A client of @p ccfg and a server of @p scfg, datagrams of @p mtu */
static int pair_start(const tls_config_t *ccfg, const tls_config_t *scfg,
                      size_t mtu) {
  n_in_flight[0] = n_in_flight[1] = n_sent[0] = n_sent[1] = 0;
  pair_largest = 0;
  pc_events = ps_events = 0;
  CHECK(dtls_init(&ps, scfg, ps_rx, sizeof(ps_rx), ps_tx, ps_tx_cap, mtu) == 0);
  CHECK(dtls_init(&pc, ccfg, pc_rx, pc_rx_cap, pc_tx, sizeof(pc_tx), mtu) == 0);
  pc_rx_cap = sizeof(pc_rx);
  ps_tx_cap = sizeof(ps_tx);
  pc.tls.on_event = on_pc;
  ps.tls.on_event = on_ps;
  CHECK(dtls_accept(&ps) == 0);
  CHECK(dtls_connect(&pc, HOST) == 0);
  return 1;
}

static int pair_connected(void) {
  return dtls_state(&pc) == TLS_STATE_CONNECTED &&
         dtls_state(&ps) == TLS_STATE_CONNECTED &&
         pc_events == TLS_EVT_CONNECTED && ps_events == TLS_EVT_CONNECTED;
}

/* REQ-DTLS-073, 019: the application moves the datagrams — here through
 * arrays; the suite is linked without the stack's UDP.  A certificate
 * handshake, then data: each dtls_write() is one record in one datagram
 * of its length and 22 bytes, read back a record per dtls_read(); one
 * datagram waits at a time; none is longer than the MTU allows. */
TEST(itest_dtls_073_datagrams_moved_by_the_application) {
  static uint8_t big[MTU];
  uint8_t buf[64];
  int before;
  fate = NULL;
  reversed = 0;
  ASSERT_TRUE(pair_start(&cli_cert, &srv_cert, MTU));
  pair_run(0);
  ASSERT_TRUE(pair_connected());
  ASSERT_FALSE(tls_psk_used(&pc.tls));
  ASSERT_EQ(pc.tls.group, TLS_GROUP_X25519);
  before = n_sent[0];
  ASSERT_EQ(dtls_write(&pc, (const uint8_t *)"GET /", 5), 5);
  ASSERT_EQ(dtls_write(&pc, (const uint8_t *)"more", 4), 0); /* one waits */
  pair_run(0);
  ASSERT_EQ(n_sent[0], before + 1);
  ASSERT_EQ(dtls_write(&pc, (const uint8_t *)"more", 4), 4);
  pair_run(0);
  ASSERT_EQ(dtls_read(&ps, buf, sizeof(buf)), 5);
  ASSERT_MEM_EQ(buf, "GET /", 5);
  ASSERT_EQ(dtls_read(&ps, buf, 2), 2); /* a record read in two parts */
  ASSERT_EQ(dtls_read(&ps, buf + 2, sizeof(buf) - 2), 2);
  ASSERT_MEM_EQ(buf, "more", 4);
  ASSERT_EQ(dtls_read(&ps, buf, sizeof(buf)), 0);

  ASSERT_EQ(dtls_max_data(&ps), MTU - DTLS_RECORD_OVERHEAD);
  ASSERT_EQ(dtls_write(&ps, big, MTU - DTLS_RECORD_OVERHEAD + 1), -1);
  ASSERT_EQ(dtls_write(&ps, big, MTU - DTLS_RECORD_OVERHEAD),
            MTU - DTLS_RECORD_OVERHEAD);
  pair_run(0);
  ASSERT_EQ(pair_largest, MTU);
  ASSERT_EQ(dtls_read(&pc, big, sizeof(big)), MTU - DTLS_RECORD_OVERHEAD);
}

static int lose_dir, lose_index;
static int lose_one(int dir, int i) {
  return dir == lose_dir && i == lose_index;
}

/* REQ-DTLS-038, 039, 056: each datagram of the handshake lost once in
 * turn — whichever it is, a timer or the peer's retransmission brings it
 * again and the handshake completes; and once it has, every flight has
 * been answered: no more datagrams, however long the timers run */
TEST(itest_dtls_038_each_datagram_lost_once) {
  reversed = 0;
  for (lose_dir = 0; lose_dir < 2; lose_dir++)
    for (lose_index = 0; lose_index < 3; lose_index++) {
      int sent[2];
      ASSERT_TRUE(pair_start(&cli_cert, &srv_cert, MTU));
      fate = lose_one;
      pair_run(10);
      ASSERT_TRUE(pair_connected());
      ASSERT_TRUE(n_sent[lose_dir] >= 4); /* one more than without loss */
      sent[0] = n_sent[0];
      sent[1] = n_sent[1];
      pair_run(200);
      ASSERT_TRUE(n_sent[0] == sent[0] && n_sent[1] == sent[1]);
      ASSERT_TRUE(pair_connected());
    }
  fate = NULL;
}

static int twice(int dir, int i) {
  (void)dir;
  (void)i;
  return 2;
}

/* REQ-DTLS-032, 021: every datagram delivered twice — messages already
 * taken and records already seen are discarded, and the handshake and
 * the data after it are as without duplicates */
TEST(itest_dtls_032_every_datagram_twice) {
  uint8_t buf[16];
  reversed = 0;
  ASSERT_TRUE(pair_start(&cli_cert, &srv_cert, MTU));
  fate = twice;
  pair_run(5);
  ASSERT_TRUE(pair_connected());
  ASSERT_EQ(dtls_write(&pc, (const uint8_t *)"once", 4), 4);
  pair_run(0);
  ASSERT_EQ(dtls_read(&ps, buf, sizeof(buf)), 4);
  ASSERT_EQ(dtls_read(&ps, buf, sizeof(buf)), 0);
  fate = NULL;
}

/* REQ-DTLS-034, 020: 200-byte datagrams, each batch delivered last
 * first: fragments after a gap and later messages are not taken, so each
 * transmission completes a little more, and within the retransmissions
 * the timer allows the handshake completes */
TEST(itest_dtls_034_fragments_in_reverse_order) {
  fate = NULL;
  reversed = 1;
  ASSERT_TRUE(pair_start(&cli_cert, &srv_cert, 200));
  pair_run(130);
  reversed = 0;
  ASSERT_TRUE(pair_connected());
  ASSERT_TRUE(pair_largest <= 200);
}

/* REQ-DTLS-042: a server that needs another group asks for it and for its
 * cookie in one HelloRetryRequest; the client's second ClientHello brings
 * both, and the handshake takes no more datagrams than with the cookie
 * alone.  REQ-TLS-061 */
TEST(itest_dtls_042_cookie_and_group_in_one_hello_retry) {
  tls_config_t p256 = srv_cert;
  p256.groups = TLS_GROUPS_SECP256R1;
  fate = NULL;
  ASSERT_TRUE(pair_start(&cli_cert, &p256, MTU));
  pair_run(0);
  ASSERT_TRUE(pair_connected());
  ASSERT_EQ(pc.tls.group, TLS_GROUP_SECP256R1);
  ASSERT_EQ(n_sent[0], 3); /* ClientHello, ClientHello, Finished */
  ASSERT_TRUE(dtls_peer_verified(&ps));
}

/* REQ-TLS-031, 023: under DTLS as under TLS — max_fragment_length keeps
 * the records of the flight within 512 bytes of content, and the
 * pre-shared key authenticates both sides without a certificate */
TEST(itest_dtls_020_fragment_limit_and_psk) {
  tls_config_t mfl = cli_cert;
  mfl.max_fragment = TLS_MFL_512;
  fate = NULL;
  ASSERT_TRUE(pair_start(&mfl, &srv_cert, MTU));
  pair_run(0);
  ASSERT_TRUE(pair_connected());
  ASSERT_EQ(ps.tls.max_frag, 512);
  ASSERT_TRUE(pair_largest <= 13 + 512 + DTLS_RECORD_OVERHEAD + 512);
  ASSERT_EQ(dtls_max_data(&ps), 512);

  ASSERT_TRUE(pair_start(&cli_psk, &srv_psk, MTU));
  pair_run(0);
  ASSERT_TRUE(pair_connected());
  ASSERT_TRUE(tls_psk_used(&pc.tls) && tls_psk_used(&ps.tls));
}

/* REQ-TLS-014: under DTLS too the client refuses a chain that leads to no
 * trust anchor (unknown_ca) — the alert goes once, and the server, told,
 * stops as well */
TEST(itest_dtls_014_untrusted_chain_refused) {
  tls_config_t no_anchor = cli_cert;
  no_anchor.crypto = &crypto_no_ca;
  fate = NULL;
  ASSERT_TRUE(pair_start(&no_anchor, &srv_cert, MTU));
  pair_run(3);
  ASSERT_EQ(dtls_state(&pc), TLS_STATE_ERROR);
  ASSERT_EQ(pc.tls.alert, 48);
  ASSERT_EQ(dtls_state(&ps), TLS_STATE_ERROR);
  ASSERT_EQ(ps.tls.alert, 48);
  ASSERT_EQ(pc_events, TLS_EVT_ERROR);
}

/* REQ-TLS-037, 041: buffers too small for the handshake end it rather
 * than stall it — a transmit buffer that cannot hold the server's flight
 * and a datagram is internal_error, a receive buffer that cannot hold the
 * Certificate with the record it comes in record_overflow */
TEST(itest_dtls_041_buffers_too_small) {
  fate = NULL;
  ps_tx_cap = 600;
  ASSERT_TRUE(pair_start(&cli_cert, &srv_cert, MTU));
  pair_run(0);
  ASSERT_EQ(dtls_state(&ps), TLS_STATE_ERROR);
  ASSERT_EQ(ps.tls.alert, 80);
  pc_rx_cap = 700;
  ASSERT_TRUE(pair_start(&cli_cert, &srv_cert, MTU));
  pair_run(0);
  ASSERT_EQ(dtls_state(&pc), TLS_STATE_ERROR);
  ASSERT_EQ(pc.tls.alert, 22);
}

/* ══ Architecture ═════════════════════════════════════════════════ */

static tls_crypto_t counting;
static int blocks, seals, opens, expands;

static void c_aes_block(const uint8_t key[TLS_AEAD_KEY_LEN],
                        const uint8_t in[16], uint8_t out[16]) {
  blocks++;
  crypto.aes_block(key, in, out);
}
static void c_seal(const uint8_t key[TLS_AEAD_KEY_LEN],
                   const uint8_t nonce[TLS_AEAD_IV_LEN], const uint8_t *aad,
                   size_t al, const uint8_t *in, size_t n, uint8_t *o,
                   uint8_t tag[TLS_AEAD_TAG_LEN]) {
  seals++;
  crypto.aead_seal(key, nonce, aad, al, in, n, o, tag);
}
static int c_open(const uint8_t key[TLS_AEAD_KEY_LEN],
                  const uint8_t nonce[TLS_AEAD_IV_LEN], const uint8_t *aad,
                  size_t al, const uint8_t *in, size_t n,
                  const uint8_t tag[TLS_AEAD_TAG_LEN], uint8_t *o) {
  opens++;
  return crypto.aead_open(key, nonce, aad, al, in, n, tag, o);
}
static void c_expand(const uint8_t prk[TLS_HASH_LEN], const uint8_t *info,
                     size_t il, uint8_t *out, size_t n) {
  expands++;
  crypto.hkdf_expand(prk, info, il, out, n);
}

/* REQ-DTLS-070: the datagram record layer has no cryptography of its own
 * — a backend without the AES block is refused by dtls_init(), and a
 * handshake asks the backend for every record's AEAD, for the block that
 * masks each record number (one per protected record sent or received)
 * and for the keys' derivation */
TEST(itest_dtls_070_cryptography_from_the_backend) {
  tls_config_t ccfg = cli_psk, scfg = srv_psk, no_block = srv_psk;
  tls_crypto_t without = crypto;
  without.aes_block = NULL;
  no_block.crypto = &without;
  ASSERT_EQ(dtls_init(&sut, &no_block, sut_rx, sizeof(sut_rx), sut_tx,
                      sizeof(sut_tx), MTU),
            -1);
  counting = crypto;
  counting.aes_block = c_aes_block;
  counting.aead_seal = c_seal;
  counting.aead_open = c_open;
  counting.hkdf_expand = c_expand;
  ccfg.crypto = scfg.crypto = &counting;
  blocks = seals = opens = expands = 0;
  fate = NULL;
  ASSERT_TRUE(pair_start(&ccfg, &scfg, MTU));
  pair_run(0);
  ASSERT_TRUE(pair_connected());
  ASSERT_TRUE(seals >= 3); /* the server's flight, the Finished, the ACK */
  ASSERT_EQ(opens, seals);
  ASSERT_EQ(blocks, seals + opens);
  ASSERT_TRUE(expands > 0);
}

/* REQ-DTLS-071: all of a connection's state is in its dtls_conn_t and its
 * buffers — copied to another dtls_conn_t in the middle of the handshake
 * and again after it, the first overwritten, the connection carries on */
TEST(itest_dtls_071_state_in_the_connection) {
  static dtls_conn_t moved;
  uint8_t buf[16];
  fate = NULL;
  ASSERT_TRUE(pair_start(&cli_cert, &srv_cert, MTU));
  pair_send(&pc, 0);
  (void)pair_deliver(0, &ps);
  pair_send(&ps, 1); /* the HelloRetryRequest is on its way */
  moved = ps;
  memset(&ps, 0xFF, sizeof(ps));
  ps = moved;
  memset(&moved, 0xFF, sizeof(moved));
  pair_run(0);
  ASSERT_TRUE(pair_connected());
  moved = pc;
  memset(&pc, 0xFF, sizeof(pc));
  pc = moved;
  ASSERT_EQ(dtls_write(&pc, (const uint8_t *)"moved", 5), 5);
  pair_run(0);
  ASSERT_EQ(dtls_read(&ps, buf, sizeof(buf)), 5);
  ASSERT_MEM_EQ(buf, "moved", 5);
}

/* REQ-TLS-042, 065, 066: the API's checks, as TLS's — dtls_init()
 * refuses buffers under 256 bytes and an MTU under DTLS_MTU_MIN; calls
 * out of place return an error; dtls_release() zeroes both buffers and
 * leaves the connection idle, ready for the next handshake */
TEST(itest_dtls_066_api_checks) {
  uint8_t buf[8];
  size_t i;
  ASSERT_EQ(dtls_init(&sut, &srv_psk, sut_rx, 255, sut_tx, 4096, MTU), -1);
  ASSERT_EQ(dtls_init(&sut, &srv_psk, sut_rx, 4096, sut_tx, 255, MTU), -1);
  ASSERT_EQ(
      dtls_init(&sut, &srv_psk, sut_rx, 4096, sut_tx, 4096, DTLS_MTU_MIN - 1),
      -1);
  ASSERT_EQ(dtls_init(&sut, NULL, sut_rx, 4096, sut_tx, 4096, MTU), -1);
  ASSERT_EQ(dtls_init(&sut, &srv_psk, sut_rx, 4096, sut_tx, 4096, DTLS_MTU_MIN),
            0);
  ASSERT_EQ(dtls_write(&sut, (const uint8_t *)"x", 1), -1);
  ASSERT_EQ(dtls_key_update(&sut, 0), -1);
  ASSERT_EQ(dtls_close(&sut), -1);
  ASSERT_EQ(dtls_read(&sut, buf, sizeof(buf)), 0);
  ASSERT_EQ(dtls_accept(&sut), 0);
  ASSERT_EQ(dtls_accept(&sut), -1);
  ASSERT_EQ(dtls_connect(&sut, NULL), -1);
  ASSERT_EQ(collect(), 0);

  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  ASSERT_EQ(p_send(3, TP_APPDATA, "unread and private", 18), 0);
  ASSERT_EQ(dtls_write(&sut, (const uint8_t *)"unsent", 6), 6);
  dtls_release(&sut);
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_IDLE);
  for (i = 0; i < sizeof(sut_rx); i++)
    ASSERT_EQ(sut_rx[i] | sut_tx[i], 0);
  ASSERT_EQ(collect(), 0);
  reset();
  ASSERT_EQ(dtls_accept(&sut), 0);
  ASSERT_TRUE(cookie_exchange(&ch_psk_ke));
  ASSERT_TRUE(server_flight(&ch_psk_ke));
  ASSERT_TRUE(client_finished());
  ASSERT_EQ(dtls_state(&sut), TLS_STATE_CONNECTED);
  ASSERT_EQ(n_events, 1); /* the callback is still the application's */
}

int main(void) {
  fprintf(stderr, "=== itest_dtls ===\n");
  if (tls_mbedtls_init(&backend, &crypto) != 0 ||
      tls_mbedtls_init(&backend_no_ca, &crypto_no_ca) != 0 ||
      tls_mbedtls_set_ca(&backend, (const uint8_t *)ca_pem, sizeof(ca_pem)) !=
          0 ||
      tls_mbedtls_parse_key(&backend, &ec_key, (const uint8_t *)server_key_pem,
                            sizeof(server_key_pem)) != 0) {
    fprintf(stderr, "TLS backend init failed\n");
    return 1;
  }
  srv_psk.crypto = &crypto;
  srv_psk.psk = psk;
  srv_psk.psk_len = sizeof(psk);
  srv_psk.psk_id = (const uint8_t *)PSK_ID;
  srv_psk.psk_id_len = sizeof(PSK_ID) - 1;
  srv_psk.psk_modes = TLS_PSK_KE | TLS_PSK_DHE_KE;
  srv_cert.crypto = &crypto;
  srv_cert.cert = ec_chain;
  srv_cert.cert_len = ec_chain_len;
  srv_cert.cert_count = 1;
  srv_cert.key = &ec_key;
  srv_cert.sig_scheme = TLS_SIG_ECDSA_SECP256R1_SHA256;
  cli_psk = srv_psk;
  cli_cert.crypto = &crypto;
  ch_psk_ke.psk_ke = 1;
  ch_psk_dhe.psk_dhe = 1;
  ch_psk_dhe.share = 1;
  sh_psk_ke.psk = 1;
  RUN_TEST(itest_dtls_004_handshake_with_the_server);
  RUN_TEST(itest_dtls_052_final_flight_acknowledged);
  RUN_TEST(itest_dtls_039_ack_again_for_a_repeated_finished);
  RUN_TEST(itest_dtls_001_dtls12_client_refused);
  RUN_TEST(itest_dtls_003_legacy_cookie_refused);
  RUN_TEST(itest_dtls_044_wrong_cookie_refused);
  RUN_TEST(itest_dtls_043_cookie_exchange_by_default);
  RUN_TEST(itest_dtls_038_flight_retransmitted_by_the_timer);
  RUN_TEST(itest_dtls_038_flight_again_for_a_repeated_client_hello);
  RUN_TEST(itest_dtls_034_fragments_reassembled);
  RUN_TEST(itest_dtls_040_no_application_data_before_finished);
  RUN_TEST(itest_dtls_011_application_data_record);
  RUN_TEST(itest_dtls_012_short_header_received);
  RUN_TEST(itest_dtls_021_replayed_record_dropped);
  RUN_TEST(itest_dtls_022_invalid_records_dropped_silently);
  RUN_TEST(itest_dtls_047_close_notify);
  RUN_TEST(itest_dtls_046_alert_not_retransmitted);
  RUN_TEST(itest_dtls_057_record_acknowledged_by_any_ack);
  RUN_TEST(itest_dtls_060_key_update_of_ours);
  RUN_TEST(itest_dtls_061_key_update_from_the_peer);
  RUN_TEST(itest_dtls_002_client_hello);
  RUN_TEST(itest_dtls_042_cookie_echoed);
  RUN_TEST(itest_dtls_045_second_hello_retry_refused);
  RUN_TEST(itest_dtls_001_dtls12_server_refused);
  RUN_TEST(itest_dtls_036_finished_resent_under_its_own_keys);
  RUN_TEST(itest_dtls_051_only_records_taken_are_acknowledged);
  RUN_TEST(itest_dtls_054_only_handshake_records_acknowledged);
  RUN_TEST(itest_dtls_056_flight_answered_by_a_fragment_of_the_next);
  RUN_TEST(itest_dtls_033_flight_in_fragments);
  RUN_TEST(itest_dtls_051_record_with_a_fragment_not_taken);
  RUN_TEST(itest_dtls_051_record_acknowledged_in_part);
  RUN_TEST(itest_dtls_073_datagrams_moved_by_the_application);
  RUN_TEST(itest_dtls_038_each_datagram_lost_once);
  RUN_TEST(itest_dtls_032_every_datagram_twice);
  RUN_TEST(itest_dtls_034_fragments_in_reverse_order);
  RUN_TEST(itest_dtls_042_cookie_and_group_in_one_hello_retry);
  RUN_TEST(itest_dtls_020_fragment_limit_and_psk);
  RUN_TEST(itest_dtls_014_untrusted_chain_refused);
  RUN_TEST(itest_dtls_041_buffers_too_small);
  RUN_TEST(itest_dtls_070_cryptography_from_the_backend);
  RUN_TEST(itest_dtls_071_state_in_the_connection);
  RUN_TEST(itest_dtls_066_api_checks);

  tls_mbedtls_free(&backend);
  tls_mbedtls_free(&backend_no_ca);
  ITEST_REPORT();
  return test_failures;
}
