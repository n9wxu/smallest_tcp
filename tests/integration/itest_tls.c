/**
 * @file itest_tls.c
 * @brief TLS 1.3, black box: the stack's server and client through the
 *        TLS API, their bytes read and written by a pre-shared-key peer
 *        of the tests' own (tls_peer.h) — and, for certificates, by the
 *        stack's other role; over the stack's TCP on the scripted link
 *        with tls_tcp_carry().
 */

#include "itest.h"
#include "tcp.h"
#include "tls.h"
#include "tls_crypto_mbedtls.h"
#include "tls_peer.h"
#include "tls_tcp.h"
#include "tls_test_data.h"
#include <string.h>

#define PSK_ID "itest-device"
#define HOST "pyro-dead01.local" /* the test certificate's name */
#define PORT 4433

static const uint8_t psk[32] = {0x69, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x70, 0x73,
                                0x6b, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
static const uint8_t other_psk[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9};

static tls_mbedtls_t backend, backend_no_ca;
static tls_crypto_t crypto, crypto_no_ca;
static mbedtls_pk_context ec_key, rsa_key;
static const uint8_t *const ec_chain[1] = {server_der};
static const uint16_t ec_chain_len[1] = {sizeof(server_der)};
static const uint8_t *const rsa_chain[1] = {rsa_der};
static const uint16_t rsa_chain_len[1] = {sizeof(rsa_der)};

/* Configurations: a server with the pre-shared key alone (both modes), one
 * with the ECDSA certificate, one with both; a client with the key, one
 * with the trust anchor */
static tls_config_t srv_psk, srv_cert, srv_both, cli_psk, cli_cert;

/* ── The connection under test ── */

static tls_conn_t sut;
static uint8_t sut_rx[18000], sut_tx[18000];
static size_t rx_cap = sizeof(sut_rx), tx_cap = sizeof(sut_tx); /* next start */
static uint8_t events[16];
static int n_events;

static void on_event(tls_conn_t *c, uint8_t e) {
  (void)c;
  if (n_events < (int)sizeof(events))
    events[n_events] = e;
  n_events++;
}

/* Over the stack's TCP on the scripted link, when @ref over_tcp: the
 * connection under test behind a listener, its ciphertext carried by
 * tls_tcp_carry(); the peer a TCP client on the wire */
static int over_tcp;
static itest_t t;
static tcp_conn_t tcp;
static tcp_conn_t *table[1];
static tcp_saw_tx_ctx_t tcp_tx_ctx;
static tcp_saw_rx_ctx_t tcp_rx_ctx;
static uint8_t tcp_tx_mem[1460], tcp_rx_mem[2048];
static peer_client_t cl;
static uint16_t next_port = 42000, segment = 1200;
static int echoing, fin_sent, fin_after_close_notify;
static uint8_t echo_buf[1024];
static size_t echo_off, echo_len;

/* The application above TLS, as an echo server runs it (demo/tls_echo) */
static void serve(itest_t *it) {
  tcp_state_t st = tcp_status(&tcp);
  if (st != TCP_ESTABLISHED && st != TCP_CLOSE_WAIT)
    return;
  tls_tcp_carry(&it->net, &tcp, &sut);
  while (echoing) {
    int w;
    if (!echo_len) {
      echo_off = 0;
      if (!(echo_len = tls_read(&sut, echo_buf, sizeof(echo_buf))))
        break;
    }
    if ((w = tls_write(&sut, echo_buf + echo_off, echo_len)) <= 0)
      break;
    echo_off += (size_t)w;
    echo_len -= (size_t)w;
    tls_tcp_carry(&it->net, &tcp, &sut);
  }
  if (tls_state(&sut) == TLS_STATE_CLOSED)
    (void)tls_close(&sut); /* close_notify answered */
  tls_tcp_carry(&it->net, &tcp, &sut);
  if ((tls_state(&sut) == TLS_STATE_CLOSED ||
       tls_state(&sut) == TLS_STATE_ERROR) &&
      !fin_sent && tls_tcp_idle(&tcp, &sut)) {
    tcp_close(&it->net, &tcp);
    fin_sent = 1;
  }
}

/* What the connection under test has sent, and how far it has been read */
static uint8_t out[60000];
static size_t out_len, out_off;

static void take(const uint8_t *p, size_t n) {
  if (out_len + n > sizeof(out))
    n = sizeof(out) - out_len;
  memcpy(out + out_len, p, n);
  out_len += n;
}

static size_t drain(void) {
  const uint8_t *p;
  size_t n, before = out_len;
  if (over_tcp) {
    peer_collect(&t, &cl);
    /* a FIN that came with, or before, the close_notify's bytes? */
    take(cl.data, cl.len);
    cl.len = 0;
  } else {
    while ((n = tls_tx_pending(&sut, &p)) > 0) {
      take(p, n);
      tls_tx_done(&sut, n);
    }
  }
  return out_len - before;
}

/* Bytes to the connection under test; over TCP in segments */
static size_t feed(const uint8_t *p, size_t n) {
  size_t off;
  if (!over_tcp)
    return tls_input(&sut, p, n);
  for (off = 0; off < n; off += segment) {
    uint16_t k = (uint16_t)(n - off < segment ? n - off : segment);
    peer_send(&t, &cl, p + off, k);
    take(cl.data, cl.len);
    cl.len = 0;
  }
  return n;
}

/* A failed check in a helper says where, and the helper returns 0 */
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "    check failed: %s (%s:%d)\n", #x, __FILE__,          \
              __LINE__);                                                       \
      return 0;                                                                \
    }                                                                          \
  } while (0)

/* The next record the connection under test sent: NULL if there is no
 * whole one.  Its header is as RFC 8446 §5.1 writes it: a content type,
 * legacy_record_version 0x0303, a length. */
static const uint8_t *next_record(size_t *len) {
  const uint8_t *r = out + out_off;
  if (out_len - out_off < 5 || tp_get(r + 1, 2) != 0x0303 ||
      5 + tp_get(r + 3, 2) > out_len - out_off)
    return NULL;
  *len = 5 + tp_get(r + 3, 2);
  out_off += *len;
  return r;
}

/* A new connection under test with @p cfg — with buffers of rx_cap and
 * tx_cap bytes, which then go back to their full size */
static int sut_start(const tls_config_t *cfg) {
  int r;
  out_len = out_off = 0;
  n_events = 0;
  memset(events, 0, sizeof(events));
  r = tls_init(&sut, cfg, sut_rx, rx_cap, sut_tx, tx_cap);
  rx_cap = sizeof(sut_rx);
  tx_cap = sizeof(sut_tx);
  if (r != 0)
    return 0;
  sut.on_event = on_event;
  if (over_tcp) {
    itest_up(&t, 1514, 1514);
    t.service = serve;
    tcp_saw_tx_init(&tcp_tx_ctx, tcp_tx_mem, sizeof(tcp_tx_mem));
    tcp_saw_rx_init(&tcp_rx_ctx, tcp_rx_mem, sizeof(tcp_rx_mem));
    tcp_conn_init(&tcp, &tcp_saw_tx_ops, &tcp_tx_ctx, &tcp_saw_rx_ops,
                  &tcp_rx_ctx, NULL);
    table[0] = &tcp;
    tcp_set_connections(&t.net, table, 1);
    tcp_listen(&tcp, PORT);
    fin_sent = fin_after_close_notify = 0;
    echo_len = 0;
    if (!peer_connect(&t, &cl, next_port++, PORT))
      return 0;
  }
  return 1;
}

/* ── The scripted peer ── */

static tp_t peer;
static tp_keys_t pr, pw; /* the peer's keys: reading, writing */
static tp_hello_t hello; /* the hello the connection under test sent */
static uint8_t hello_msg[2048];
static size_t hello_len;
static uint8_t flight[8192]; /* its handshake messages after the hello */
static size_t flight_len;
static uint8_t dhe[32];
static tp_ch_t ch_psk_ke, ch_psk_dhe;
/* ServerHellos of the peer: taking the PSK alone, the PSK with its
 * x25519 share, and the share alone (a certificate handshake) */
static tp_sh_t sh_psk_ke, sh_psk_dhe, sh_cert;

/* The peer's handshake message @p m as one plaintext record */
static size_t feed_plain(const uint8_t *m, size_t n) {
  static uint8_t rec[4096];
  return feed(rec, tp_record(TP_HANDSHAKE, m, n, rec));
}

/* @p n bytes of content of @p type under the peer's write keys: 1 if the
 * connection under test took the whole record */
static int feed_sealed(uint8_t type, const void *content, size_t n) {
  static uint8_t rec[17000];
  size_t len = tp_seal(&pw, type, (const uint8_t *)content, n, 0, rec);
  return feed(rec, len) == len;
}

/* The next record sent, opened with the peer's read keys: its content
 * length (-1 if there is none or it does not open), its type */
static uint8_t opened[17000];
static size_t opened_record_len;
static int open_next(uint8_t *type) {
  const uint8_t *r = next_record(&opened_record_len);
  if (!r || r[0] != TP_APPDATA)
    return -1;
  return tp_open(&pr, r, opened_record_len, opened, type);
}

/* The only thing sent since the last read is a fatal alert @p desc, in
 * plaintext */
static int plain_alert_sent(uint8_t desc) {
  size_t len;
  const uint8_t *r;
  drain();
  r = next_record(&len);
  CHECK(r && len == 7 && r[0] == TP_ALERT && r[5] == 2 && r[6] == desc);
  CHECK(out_off == out_len);
  return 1;
}

/* .. or an alert under the keys the peer reads with */
static int sealed_alert_sent(uint8_t level, uint8_t desc) {
  uint8_t type;
  drain();
  CHECK(open_next(&type) == 2 && type == TP_ALERT);
  CHECK(opened[0] == level && opened[1] == desc);
  CHECK(out_off == out_len);
  return 1;
}

/* The connection ended with alert @p desc, and said so */
static int failed_with(uint8_t desc) {
  CHECK(tls_state(&sut) == TLS_STATE_ERROR && sut.alert == desc);
  CHECK(n_events >= 1 && events[n_events - 1] == TLS_EVT_ERROR);
  return 1;
}

/* ── The stack's server against the scripted client ── */

/* The peer's ClientHello to the server waiting for one */
static int send_client_hello(const tp_ch_t *o) {
  static uint8_t m[2048];
  size_t n;
  tp_init(&peer, 0, psk, sizeof(psk), PSK_ID);
  n = tp_client_hello(&peer, o, m);
  CHECK(feed_plain(m, n) == n + 5);
  drain();
  return 1;
}

/* .. to a server started with @p cfg */
static int client_hello_to(const tls_config_t *cfg, const tp_ch_t *o) {
  CHECK(sut_start(cfg));
  CHECK(tls_accept(&sut) == 0);
  return send_client_hello(o);
}

/* The server's ServerHello to the peer's ClientHello @p o, read and
 * checked; the handshake keys.  The checks are RFC 8446 §4.1.3's:
 * legacy_version 0x0303, the session id echoed, our suite, null
 * compression, supported_versions selecting TLS 1.3, the PSK's identity 0,
 * and a key share exactly when (EC)DHE is used. */
static int read_server_hello(const tp_ch_t *o) {
  const uint8_t *r, *x;
  size_t len, xl;
  uint16_t last;
  int with_dhe;

  CHECK(tls_state(&sut) == TLS_STATE_HANDSHAKE);
  r = next_record(&len);
  CHECK(r && r[0] == TP_HANDSHAKE);
  hello_len = len - 5;
  memcpy(hello_msg, r + 5, hello_len);
  CHECK(hello_msg[0] == TP_SERVER_HELLO);
  CHECK(tp_parse_hello(hello_msg, hello_len, 0, &hello));
  CHECK(hello.legacy_version == 0x0303);
  CHECK(hello.session_id_len == o->session_id_len &&
        (!o->session_id_len ||
         memcmp(hello.session_id, o->session_id, o->session_id_len) == 0));
  CHECK(hello.suite == TP_SUITE && hello.compression[0] == 0);
  x = tp_ext(&hello, TP_EXT_SUPPORTED_VERSIONS, &xl);
  CHECK(x && xl == 2 && tp_get(x, 2) == 0x0304);
  x = tp_ext(&hello, TP_EXT_PRE_SHARED_KEY, &xl);
  CHECK(x && xl == 2 && tp_get(x, 2) == 0);
  x = tp_ext(&hello, TP_EXT_KEY_SHARE, &xl);
  with_dhe = x != NULL;
  CHECK(with_dhe == (o->share && o->psk_dhe));
  CHECK(tp_ext_count(&hello, &last) == (with_dhe ? 3 : 2));
  if (with_dhe) {
    CHECK(xl == 36 && tp_get(x, 2) == TP_X25519 && tp_get(x + 2, 2) == 32);
    CHECK(tp_x25519(peer.x_priv, x + 4, dhe) == 0);
  }
  tp_add(&peer, hello_msg, hello_len);
  tp_handshake_secrets(&peer, with_dhe ? dhe : NULL);
  tp_traffic_keys(0, peer.s_hs, &pr);
  tp_traffic_keys(0, peer.c_hs, &pw);
  return 1;
}

static int server_hello_from(const tls_config_t *cfg, const tp_ch_t *o) {
  CHECK(client_hello_to(cfg, o));
  return read_server_hello(o);
}

/* The rest of the server's flight: a change_cipher_spec for a client in
 * compatibility mode, then — under the server's handshake keys —
 * EncryptedExtensions (empty, or granting max_fragment_length @p mfl) and
 * Finished and nothing else, the Finished's verify_data as RFC 8446 §4.4.4
 * computes it.  Then the application keys. */
static int server_flight(int compat, uint8_t mfl) {
  uint8_t want[32], type;
  size_t len, ee;
  int n;
  if (compat) {
    const uint8_t *r = next_record(&len);
    CHECK(r && len == 6 && r[0] == TP_CCS && r[5] == 1);
  }
  flight_len = 0;
  while (out_off < out_len) {
    CHECK((n = open_next(&type)) > 0 && type == TP_HANDSHAKE);
    memcpy(flight + flight_len, opened, (size_t)n);
    flight_len += (size_t)n;
  }
  CHECK(flight_len >= 6 && flight[0] == TP_ENCRYPTED_EXTENSIONS);
  ee = 4 + tp_get(flight + 1, 3);
  CHECK(ee + 36 == flight_len && tp_get(flight + 4, 2) == ee - 6);
  if (mfl)
    CHECK(ee == 11 && tp_get(flight + 6, 2) == TP_EXT_MAX_FRAGMENT_LENGTH &&
          tp_get(flight + 8, 2) == 1 && flight[10] == mfl);
  else
    CHECK(ee == 6);
  tp_add(&peer, flight, ee);
  CHECK(flight[ee] == TP_FINISHED && tp_get(flight + ee + 1, 3) == 32);
  tp_verify_data(&peer, peer.s_hs, want);
  CHECK(memcmp(flight + ee + 4, want, 32) == 0);
  tp_add(&peer, flight + ee, 36);
  tp_application_secrets(&peer);
  tp_traffic_keys(0, peer.s_ap, &pr);
  return 1;
}

/* The peer's Finished; from then on it writes under its application keys */
static int client_finished(void) {
  uint8_t fin[36];
  tp_finished(&peer, peer.c_hs, fin);
  CHECK(feed_sealed(TP_HANDSHAKE, fin, 36));
  tp_traffic_keys(0, peer.c_ap, &pw);
  return 1;
}

/* The whole handshake of the scripted client with a server of @p cfg */
static int connect_to_server(const tls_config_t *cfg, const tp_ch_t *o) {
  CHECK(server_hello_from(cfg, o));
  CHECK(server_flight(o->session_id_len != 0, o->mfl));
  CHECK(n_events == 0 && tls_state(&sut) == TLS_STATE_HANDSHAKE);
  CHECK(client_finished());
  CHECK(tls_state(&sut) == TLS_STATE_CONNECTED);
  CHECK(drain() == 0);
  return 1;
}

/* ── The stack's client against the scripted server ── */

/* A client started with @p cfg for @p host; its ClientHello read */
static int client_hello_from(const tls_config_t *cfg, const char *host) {
  const uint8_t *r;
  size_t len;
  CHECK(sut_start(cfg));
  CHECK(tls_connect(&sut, host) == 0);
  CHECK(tls_state(&sut) == TLS_STATE_HANDSHAKE);
  drain();
  r = next_record(&len);
  CHECK(r && r[0] == TP_HANDSHAKE && out_off == out_len);
  hello_len = len - 5;
  memcpy(hello_msg, r + 5, hello_len);
  CHECK(hello_msg[0] == TP_CLIENT_HELLO);
  CHECK(tp_parse_hello(hello_msg, hello_len, 0, &hello));
  tp_init(&peer, 0, psk, sizeof(psk), PSK_ID);
  return 1;
}

/* The peer's ServerHello @p o in answer (if it takes the PSK, the
 * ClientHello's binder checked first), and the handshake keys */
static int answer_hello(const tp_sh_t *o) {
  static uint8_t m[512];
  const uint8_t *x;
  size_t n, xl;
  if (o->psk)
    CHECK(tp_binder_ok(&peer, hello_msg, hello_len));
  tp_add(&peer, hello_msg, hello_len);
  tp_early_secret(&peer, o->psk);
  n = tp_server_hello(&peer, o, m);
  if (o->share) {
    x = tp_ext(&hello, TP_EXT_KEY_SHARE, &xl);
    CHECK(x && xl == 38 && tp_get(x + 2, 2) == TP_X25519);
    CHECK(tp_x25519(peer.x_priv, x + 6, dhe) == 0);
  }
  tp_handshake_secrets(&peer, o->share ? dhe : NULL);
  tp_traffic_keys(0, peer.s_hs, &pw);
  tp_traffic_keys(0, peer.c_hs, &pr);
  feed_plain(m, n);
  return 1;
}

/* The peer's EncryptedExtensions and Finished, in one record */
static int answer_flight(void) {
  uint8_t m[64];
  size_t n = tp_encrypted_extensions(&peer, -1, NULL, 0, m);
  n += tp_finished(&peer, peer.s_hs, m + n);
  CHECK(feed_sealed(TP_HANDSHAKE, m, n));
  tp_application_secrets(&peer);
  tp_traffic_keys(0, peer.s_ap, &pw);
  return 1;
}

/* The client's Finished: alone in its record — or, when the server asked
 * for a certificate, after a Certificate message with an empty list —
 * under its handshake keys, its verify_data over the transcript so far */
static int client_flight_read(int empty_certificate) {
  static const uint8_t no_certificates[8] = {
      TP_CERTIFICATE, 0, 0, 4, 0, 0, 0, 0};
  const uint8_t *fin = opened;
  uint8_t want[32], type;
  drain();
  CHECK(open_next(&type) == (empty_certificate ? 8 + 36 : 36));
  CHECK(type == TP_HANDSHAKE);
  if (empty_certificate) {
    CHECK(memcmp(opened, no_certificates, 8) == 0);
    tp_add(&peer, opened, 8);
    fin = opened + 8;
  }
  tp_verify_data(&peer, peer.c_hs, want);
  CHECK(fin[0] == TP_FINISHED && tp_get(fin + 1, 3) == 32);
  CHECK(memcmp(fin + 4, want, 32) == 0);
  CHECK(out_off == out_len);
  tp_traffic_keys(0, peer.c_ap, &pr);
  return 1;
}

static int client_finished_read(void) { return client_flight_read(0); }

/* The whole handshake of a client of @p cfg with the scripted server */
static int connect_from_client(const tls_config_t *cfg, const tp_sh_t *o) {
  CHECK(client_hello_from(cfg, HOST));
  CHECK(answer_hello(o));
  CHECK(tls_state(&sut) == TLS_STATE_HANDSHAKE && drain() == 0);
  CHECK(answer_flight());
  CHECK(client_finished_read());
  CHECK(tls_state(&sut) == TLS_STATE_CONNECTED);
  return 1;
}

/* ── Two of the stack's connections, joined ── */

static tls_conn_t ca, sa;
static uint8_t ca_rx[18000], ca_tx[4096], sa_rx[4096], sa_tx[4096];
/* The next pair's client receive and server transmit buffer sizes */
static size_t pair_rx = sizeof(ca_rx), pair_tx = sizeof(sa_tx);
static uint8_t c2s[16384], s2c[16384]; /* what went each way */
static size_t c2s_len, s2c_len;

static size_t move(tls_conn_t *from, tls_conn_t *to, uint8_t *log,
                   size_t *log_len, size_t chunk) {
  const uint8_t *p;
  size_t n, moved = 0;
  while ((n = tls_tx_pending(from, &p)) > 0) {
    if (n > chunk)
      n = chunk;
    if (*log_len + n <= sizeof(c2s)) {
      memcpy(log + *log_len, p, n);
      *log_len += n;
    }
    (void)tls_input(to, p, n);
    tls_tx_done(from, n);
    moved += n;
  }
  return moved;
}

/* Carry ciphertext between @p c and @p s, @p chunk bytes at a time, until
 * neither has any */
static void join(tls_conn_t *c, tls_conn_t *s, size_t chunk) {
  while (move(c, s, c2s, &c2s_len, chunk) + move(s, c, s2c, &s2c_len, chunk))
    ;
}

/* A client of @p ccfg for @p host and a server of @p scfg, joined */
static void pair(const tls_config_t *ccfg, const char *host,
                 const tls_config_t *scfg) {
  c2s_len = s2c_len = 0;
  tls_init(&ca, ccfg, ca_rx, pair_rx, ca_tx, sizeof(ca_tx));
  tls_init(&sa, scfg, sa_rx, sizeof(sa_rx), sa_tx, pair_tx);
  pair_rx = sizeof(ca_rx);
  pair_tx = sizeof(sa_tx);
  tls_accept(&sa);
  tls_connect(&ca, host);
  join(&ca, &sa, 4096);
}

static int both_connected(void) {
  return tls_state(&ca) == TLS_STATE_CONNECTED &&
         tls_state(&sa) == TLS_STATE_CONNECTED;
}

/* ══ The server's handshake ═══════════════════════════════════════ */

/* REQ-TLS-018, 019, 021, 023, 024, 002, 034: to a ClientHello offering the
 * pre-shared key alone (psk_ke), the server answers ServerHello —
 * supported_versions selecting TLS 1.3, TLS_AES_128_GCM_SHA256 out of the
 * suites offered, the key's identity — then EncryptedExtensions and
 * Finished (its MAC over the transcript so far): no Certificate, no
 * CertificateVerify */
TEST(itest_tls_018_server_flight_with_a_psk) {
  ASSERT_TRUE(server_hello_from(&srv_psk, &ch_psk_ke));
  ASSERT_TRUE(server_flight(0, 0));
  ASSERT_TRUE(tls_psk_used(&sut));
  ASSERT_EQ(sut.group, 0);
}

/* REQ-TLS-022, 038: the server verifies the client's Finished — and only
 * then is the connection CONNECTED, with one TLS_EVT_CONNECTED */
TEST(itest_tls_022_client_finished_completes_the_handshake) {
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  ASSERT_EQ(n_events, 1);
  ASSERT_EQ(events[0], TLS_EVT_CONNECTED);
}

/* REQ-TLS-022, 037, 040: a Finished whose verify_data is wrong ends the
 * handshake with decrypt_error (RFC 8446 §4.4.4), under the keys the
 * server writes with by then, and TLS_EVT_ERROR — never CONNECTED */
TEST(itest_tls_022_wrong_client_finished_refused) {
  uint8_t fin[36];
  ASSERT_TRUE(server_hello_from(&srv_psk, &ch_psk_ke));
  ASSERT_TRUE(server_flight(0, 0));
  tp_finished(&peer, peer.c_hs, fin);
  fin[35] ^= 0x01;
  ASSERT_TRUE(feed_sealed(TP_HANDSHAKE, fin, 36));
  ASSERT_TRUE(failed_with(51));
  ASSERT_EQ(n_events, 1);
  ASSERT_TRUE(sealed_alert_sent(2, 51));
}

/* REQ-TLS-004, 023, 032: psk_dhe_ke with an x25519 share — the server's
 * share comes back in key_share, and both Finished MACs check out only if
 * the (EC)DHE secret went into the Handshake Secret as RFC 8446 §7.1 says */
TEST(itest_tls_004_psk_with_x25519) {
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_dhe));
  ASSERT_EQ(sut.group, TLS_GROUP_X25519);
  ASSERT_TRUE(tls_psk_used(&sut));
}

/* REQ-TLS-001, 037: a client that does not offer TLS 1.3 — no
 * supported_versions, or only TLS 1.2 in it — is refused with
 * protocol_version */
TEST(itest_tls_001_tls12_client_refused) {
  tp_ch_t o = ch_psk_ke;
  o.no_versions = 1;
  ASSERT_TRUE(client_hello_to(&srv_psk, &o));
  ASSERT_TRUE(failed_with(70));
  ASSERT_TRUE(plain_alert_sent(70));
  o.no_versions = 0;
  o.version = 0x0303;
  ASSERT_TRUE(client_hello_to(&srv_psk, &o));
  ASSERT_TRUE(failed_with(70));
  ASSERT_TRUE(plain_alert_sent(70));
}

/* REQ-TLS-037, 040, 002, 050, 051, 053, 054: what is wrong with a ClientHello
 * decides the fatal alert (RFC 8446 §6.2) — sent in plaintext, the
 * connection in ERROR with TLS_EVT_ERROR */
TEST(itest_tls_037_alert_says_what_was_wrong) {
  static const struct {
    int no_suite, compression, no_modes, bad_binder, psk_not_last, truncated;
    int twice, zero_share;
    uint8_t alert;
  } cases[] = {
      {1, 0, 0, 0, 0, 0, 0, 0, 40},  /* no suite of ours: handshake_failure */
      {0, 1, 0, 0, 0, 0, 0, 0, 47},  /* a compression method:
                                        illegal_parameter */
      {0, 0, 1, 0, 0, 0, 0, 0, 109}, /* a PSK without modes:
                                        missing_extension */
      {0, 0, 0, 1, 0, 0, 0, 0, 51},  /* a binder that does not check:
                                        decrypt_error */
      {0, 0, 0, 0, 1, 0, 0, 0, 47},  /* pre_shared_key not last:
                                        illegal_parameter */
      {0, 0, 0, 0, 0, 1, 0, 0, 50},  /* cut short: decode_error */
      {0, 0, 0, 0, 0, 0, 1, 0, 47},  /* an extension twice:
                                        illegal_parameter */
      {0, 0, 0, 0, 0, 0, 0, 1, 47},  /* an x25519 share of zeros:
                                        illegal_parameter */
  };
  unsigned i;
  for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    tp_ch_t o = cases[i].zero_share ? ch_psk_dhe : ch_psk_ke;
    o.no_suite = cases[i].no_suite;
    o.compression = (uint8_t)cases[i].compression;
    o.no_modes = cases[i].no_modes;
    o.bad_binder = cases[i].bad_binder;
    o.psk_not_last = cases[i].psk_not_last;
    o.truncated = cases[i].truncated;
    o.twice = cases[i].twice;
    o.zero_share = cases[i].zero_share;
    ASSERT_TRUE(client_hello_to(&srv_psk, &o));
    ASSERT_TRUE(failed_with(cases[i].alert));
    ASSERT_EQ(n_events, 1);
    ASSERT_TRUE(plain_alert_sent(cases[i].alert));
  }
}

/* REQ-TLS-052: a ClientHello without a pre_shared_key must carry
 * signature_algorithms and supported_groups (RFC 8446 §9.2): without one
 * of them, missing_extension */
TEST(itest_tls_052_mandatory_extensions) {
  tp_ch_t o;
  memset(&o, 0, sizeof(o));
  o.no_psk = 1;
  o.share = 1; /* supported_groups and key_share, no signature_algorithms */
  ASSERT_TRUE(client_hello_to(&srv_cert, &o));
  ASSERT_TRUE(failed_with(109));
  ASSERT_TRUE(plain_alert_sent(109));
  o.share = 0;
  o.sig_algs = 1; /* signature_algorithms alone */
  ASSERT_TRUE(client_hello_to(&srv_cert, &o));
  ASSERT_TRUE(failed_with(109));
  ASSERT_TRUE(plain_alert_sent(109));
}

/* REQ-TLS-052: supported_groups and key_share come together (RFC 8446
 * §9.2) — a ClientHello with one and not the other is missing_extension,
 * even when its pre-shared key alone would do */
TEST(itest_tls_052_groups_and_key_share_together) {
  tp_ch_t o = ch_psk_ke;
  o.groups_only = 1;
  ASSERT_TRUE(client_hello_to(&srv_psk, &o));
  ASSERT_TRUE(failed_with(109));
  ASSERT_TRUE(plain_alert_sent(109));
}

/* REQ-TLS-061, 034: a ClientHello with a group in common but no share of it
 * gets a HelloRetryRequest — a ServerHello with the special random, the
 * selected group in key_share, supported_versions — and the handshake
 * goes on from the second ClientHello over the transcript RFC 8446 §4.4.1
 * defines (message_hash, HelloRetryRequest, ClientHello2).  A second
 * ClientHello still without the share is illegal_parameter. */
TEST(itest_tls_061_hello_retry_request_sent) {
  static uint8_t m[2048];
  tp_ch_t o = ch_psk_dhe;
  tp_hello_t hrr;
  const uint8_t *r, *x;
  uint16_t last;
  size_t n, len, xl;
  int again;
  o.share = 0;
  o.groups_no_share = 1;
  for (again = 0; again < 2; again++) {
    ASSERT_TRUE(client_hello_to(&srv_psk, &o));
    ASSERT_EQ(tls_state(&sut), TLS_STATE_HANDSHAKE);
    r = next_record(&len);
    ASSERT_TRUE(r && r[0] == TP_HANDSHAKE && out_off == out_len);
    ASSERT_TRUE(tp_parse_hello(r + 5, len - 5, 0, &hrr));
    ASSERT_EQ(r[5], TP_SERVER_HELLO);
    ASSERT_MEM_EQ(hrr.random, tp_hrr_random, 32);
    ASSERT_EQ(hrr.suite, TP_SUITE);
    x = tp_ext(&hrr, TP_EXT_KEY_SHARE, &xl);
    ASSERT_TRUE(x && xl == 2 && tp_get(x, 2) == TP_X25519);
    x = tp_ext(&hrr, TP_EXT_SUPPORTED_VERSIONS, &xl);
    ASSERT_TRUE(x && xl == 2 && tp_get(x, 2) == 0x0304);
    ASSERT_EQ(tp_ext_count(&hrr, &last), 2);
    tp_message_hash(&peer);
    tp_add(&peer, r + 5, len - 5);
    n = tp_client_hello(&peer, again ? &o : &ch_psk_dhe, m);
    ASSERT_EQ(feed_plain(m, n), n + 5);
    drain();
    if (again) {
      ASSERT_TRUE(failed_with(47));
      ASSERT_TRUE(plain_alert_sent(47));
    } else {
      ASSERT_TRUE(read_server_hello(&ch_psk_dhe));
      ASSERT_TRUE(server_flight(0, 0));
      ASSERT_TRUE(client_finished());
      ASSERT_EQ(tls_state(&sut), TLS_STATE_CONNECTED);
    }
  }
}

/* REQ-TLS-046, 045, 061: a HelloRetryRequest to a client in compatibility
 * mode echoes its session id and is followed by the dummy
 * change_cipher_spec — once: none follows the ServerHello */
TEST(itest_tls_046_hello_retry_in_compatibility_mode) {
  static const uint8_t sid[32] = {9, 8, 7, 6, 5, 4, 3, 2, 1};
  static uint8_t m[2048];
  tp_ch_t o = ch_psk_dhe, o2 = ch_psk_dhe;
  tp_hello_t hrr;
  const uint8_t *r;
  size_t n, len;
  o.share = 0;
  o.groups_no_share = 1;
  o.session_id = o2.session_id = sid;
  o.session_id_len = o2.session_id_len = sizeof(sid);
  ASSERT_TRUE(client_hello_to(&srv_psk, &o));
  r = next_record(&len);
  ASSERT_TRUE(r && tp_parse_hello(r + 5, len - 5, 0, &hrr));
  ASSERT_MEM_EQ(hrr.random, tp_hrr_random, 32);
  ASSERT_EQ(hrr.session_id_len, sizeof(sid));
  ASSERT_MEM_EQ(hrr.session_id, sid, sizeof(sid));
  tp_message_hash(&peer);
  tp_add(&peer, r + 5, len - 5);
  r = next_record(&len);
  ASSERT_TRUE(r && len == 6 && r[0] == TP_CCS && r[5] == 1);
  ASSERT_EQ(out_off, out_len);
  n = tp_client_hello(&peer, &o2, m);
  ASSERT_EQ(feed_plain(m, n), n + 5);
  drain();
  ASSERT_TRUE(read_server_hello(&o2));
  ASSERT_TRUE(server_flight(0, 0));
  ASSERT_TRUE(client_finished());
  ASSERT_EQ(tls_state(&sut), TLS_STATE_CONNECTED);
}

/* REQ-TLS-022, 037: what the server accepts after its flight is the
 * client's Finished and nothing else — another ClientHello or a KeyUpdate
 * is unexpected_message, a Finished of the wrong length decode_error */
TEST(itest_tls_022_only_finished_after_the_flight) {
  static const uint8_t key_update[5] = {TP_KEY_UPDATE, 0, 0, 1, 0};
  uint8_t fin[40];
  int i;
  for (i = 0; i < 3; i++) {
    ASSERT_TRUE(server_hello_from(&srv_psk, &ch_psk_ke));
    ASSERT_TRUE(server_flight(0, 0));
    if (i == 0) {
      (void)feed_sealed(TP_HANDSHAKE, peer.transcript, /* the ClientHello */
                        4 + tp_get(peer.transcript + 1, 3));
    } else if (i == 1) {
      (void)feed_sealed(TP_HANDSHAKE, key_update, 5);
    } else {
      tp_finished(&peer, peer.c_hs, fin);
      fin[3] = 33; /* a 33-byte verify_data */
      fin[36] = 0;
      (void)feed_sealed(TP_HANDSHAKE, fin, 37);
    }
    ASSERT_TRUE(failed_with(i == 2 ? 50 : 10));
    ASSERT_TRUE(sealed_alert_sent(2, i == 2 ? 50 : 10));
  }
}

/* REQ-TLS-025, 023: the key and its identity are the configuration's — a
 * server with another key refuses the binder (decrypt_error), one with
 * another identity does not know the PSK (unknown_psk_identity, having no
 * certificate to fall back on), and a PSK without an identity is no
 * configuration at all */
TEST(itest_tls_025_psk_from_the_configuration) {
  tls_config_t cfg = srv_psk;
  cfg.psk = other_psk;
  ASSERT_TRUE(client_hello_to(&cfg, &ch_psk_ke));
  ASSERT_TRUE(failed_with(51));
  cfg = srv_psk;
  cfg.psk_id = (const uint8_t *)"somebody-else";
  cfg.psk_id_len = 13;
  ASSERT_TRUE(client_hello_to(&cfg, &ch_psk_ke));
  ASSERT_TRUE(failed_with(115));
  ASSERT_TRUE(plain_alert_sent(115));
  cfg.psk_id = NULL;
  ASSERT_TRUE(sut_start(&cfg));
  ASSERT_EQ(tls_accept(&sut), -1);
  ASSERT_TRUE(sut_start(&cfg));
  ASSERT_EQ(tls_connect(&sut, NULL), -1);
}

/* REQ-TLS-046, 045: a client in compatibility mode (a legacy_session_id)
 * has its session id echoed and gets the dummy change_cipher_spec after
 * the ServerHello; its own, the single byte 0x01 before its Finished, is
 * dropped */
TEST(itest_tls_046_session_id_echoed) {
  static const uint8_t ccs[6] = {TP_CCS, 3, 3, 0, 1, 1};
  static const uint8_t sid[32] = {0xAA, 0xBB, 0xCC, 1, 2, 3, 4, 5, 6, 7, 8};
  tp_ch_t o = ch_psk_ke;
  o.session_id = sid;
  o.session_id_len = sizeof(sid);
  ASSERT_TRUE(server_hello_from(&srv_psk, &o));
  ASSERT_TRUE(server_flight(1, 0));
  ASSERT_EQ(feed(ccs, sizeof(ccs)), sizeof(ccs));
  ASSERT_EQ(tls_state(&sut), TLS_STATE_HANDSHAKE);
  ASSERT_TRUE(client_finished());
  ASSERT_EQ(tls_state(&sut), TLS_STATE_CONNECTED);
}

/* REQ-TLS-045: a change_cipher_spec before the ClientHello, after the
 * client's Finished, or of any other value is unexpected_message */
TEST(itest_tls_045_change_cipher_spec_only_in_the_handshake) {
  static const uint8_t ccs[6] = {TP_CCS, 3, 3, 0, 1, 1};
  static const uint8_t ccs2[6] = {TP_CCS, 3, 3, 0, 1, 2};
  ASSERT_TRUE(sut_start(&srv_psk));
  ASSERT_EQ(tls_accept(&sut), 0);
  feed(ccs, sizeof(ccs));
  ASSERT_TRUE(failed_with(10));
  ASSERT_TRUE(plain_alert_sent(10));

  ASSERT_TRUE(server_hello_from(&srv_psk, &ch_psk_ke));
  ASSERT_TRUE(server_flight(0, 0));
  feed(ccs2, sizeof(ccs2));
  ASSERT_TRUE(failed_with(10));

  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  feed(ccs, sizeof(ccs));
  ASSERT_TRUE(failed_with(10));
  ASSERT_TRUE(sealed_alert_sent(2, 10));
}

/* REQ-TLS-031: a client's max_fragment_length request (RFC 6066 §4) is
 * granted in EncryptedExtensions, and from then on no record of the
 * server's carries more — 512 bytes being the smallest; a code that is
 * none of the four is illegal_parameter */
TEST(itest_tls_031_max_fragment_length_granted) {
  static uint8_t data[2000];
  tp_ch_t o = ch_psk_ke;
  uint8_t type;
  size_t total = 0;
  int n, w;
  o.mfl = 1;
  ASSERT_TRUE(connect_to_server(&srv_psk, &o));
  ASSERT_EQ(sut.max_frag, 512);
  memset(data, 'm', sizeof(data));
  while (total < sizeof(data)) {
    ASSERT_TRUE((w = tls_write(&sut, data + total, sizeof(data) - total)) > 0);
    ASSERT_TRUE(w <= 512);
    total += (size_t)w;
  }
  drain();
  total = 0;
  while (out_off < out_len) {
    ASSERT_TRUE((n = open_next(&type)) > 0 && n <= 512);
    ASSERT_EQ(type, TP_APPDATA);
    total += (size_t)n;
  }
  ASSERT_EQ(total, sizeof(data));

  for (o.mfl = 2; o.mfl <= 4; o.mfl++) { /* 1024, 2048, 4096 */
    ASSERT_TRUE(connect_to_server(&srv_psk, &o));
    ASSERT_EQ(sut.max_frag, 256u << o.mfl);
  }
  o.mfl = 5;
  ASSERT_TRUE(client_hello_to(&srv_psk, &o));
  ASSERT_TRUE(failed_with(47));
  ASSERT_TRUE(plain_alert_sent(47));
}

/* ══ Records ══════════════════════════════════════════════════════ */

/* REQ-TLS-026, 027, 028, 029, 033: application data both ways.  Each
 * record of the server's has the five-byte header (application_data,
 * 0x0303, the length), opens under the key and IV RFC 8446 §7.3 derives
 * from its application traffic secret with the header as additional data
 * and the nonce of its place in the sequence — 0, 1, 2 — and carries the
 * content, then its type.  The peer's records, numbered the same way, are
 * read in order. */
TEST(itest_tls_026_records_both_ways) {
  static const char *const words[3] = {"one", "second", "the third record"};
  uint8_t buf[64], type;
  size_t i;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  for (i = 0; i < 3; i++)
    ASSERT_EQ(tls_write(&sut, (const uint8_t *)words[i], strlen(words[i])),
              (int)strlen(words[i]));
  drain();
  for (i = 0; i < 3; i++) {
    size_t n = strlen(words[i]);
    const uint8_t *rec = out + out_off;
    ASSERT_EQ(rec[0], TP_APPDATA);
    ASSERT_EQ(tp_get(rec + 1, 2), 0x0303);
    ASSERT_EQ(tp_get(rec + 3, 2), n + 1 + 16);
    ASSERT_TRUE(pr.seq == i);
    ASSERT_EQ(open_next(&type), (int)n);
    ASSERT_EQ(type, TP_APPDATA);
    ASSERT_MEM_EQ(opened, words[i], n);
  }
  ASSERT_EQ(out_off, out_len);
  for (i = 0; i < 3; i++) {
    ASSERT_TRUE(pw.seq == i);
    ASSERT_TRUE(feed_sealed(TP_APPDATA, words[i], strlen(words[i])));
    ASSERT_EQ(tls_read(&sut, buf, sizeof(buf)), strlen(words[i]));
    ASSERT_MEM_EQ(buf, words[i], strlen(words[i]));
  }
  ASSERT_EQ(tls_read(&sut, buf, sizeof(buf)), 0);
}

/* REQ-TLS-030, 027, 029, 037, 040: a record that does not authenticate —
 * a ciphertext bit flipped, a header byte changed (the header is the
 * additional data), or a record sent twice (the second is not at its
 * place in the sequence) — ends the connection with a fatal
 * bad_record_mac and TLS_EVT_ERROR */
TEST(itest_tls_030_record_that_fails_authentication) {
  static uint8_t rec[64];
  uint8_t buf[8];
  int variant;
  for (variant = 0; variant < 3; variant++) {
    size_t n;
    ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
    n = tp_seal(&pw, TP_APPDATA, (const uint8_t *)"data", 4, 0, rec);
    if (variant == 0)
      rec[7] ^= 0x20;
    if (variant == 1)
      rec[2] = 0x01;
    if (variant == 2) {
      ASSERT_EQ(feed(rec, n), n);
      ASSERT_EQ(tls_read(&sut, buf, sizeof(buf)), 4);
    }
    ASSERT_EQ(tls_state(&sut), TLS_STATE_CONNECTED);
    feed(rec, n);
    ASSERT_TRUE(failed_with(20));
    ASSERT_EQ(events[0], TLS_EVT_CONNECTED);
    ASSERT_EQ(n_events, 2);
    ASSERT_TRUE(sealed_alert_sent(2, 20));
    ASSERT_EQ(tls_write(&sut, (const uint8_t *)"x", 1), -1);
  }
}

/* REQ-TLS-043: a record is its plaintext and 22 bytes more — the header,
 * the content type, the tag — and tls_write() takes only what tx has room
 * for with them */
TEST(itest_tls_043_write_within_the_transmit_buffer) {
  static uint8_t data[1000];
  const uint8_t *p;
  tx_cap = 300;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  ASSERT_EQ(tls_write(&sut, data, 100), 100);
  ASSERT_EQ(tls_tx_pending(&sut, &p), 100 + 22);
  ASSERT_EQ(tls_write(&sut, data, sizeof(data)), 300 - 122 - 22);
  ASSERT_EQ(tls_tx_pending(&sut, &p), 300);
  ASSERT_EQ(tls_write(&sut, data, sizeof(data)), 0);
  drain();
  ASSERT_EQ(tls_write(&sut, data, sizeof(data)), 300 - 22);
}

/* REQ-TLS-041, 042, 007: tls_init() refuses a connection without a
 * configuration, a crypto backend or buffers, and buffers under 256
 * bytes.  The receive buffer must hold a whole record — header, content,
 * type and tag: one that fills it exactly is read, one a byte longer ends
 * the connection with record_overflow. */
TEST(itest_tls_041_receive_buffer_holds_a_record) {
  static uint8_t data[1024], rec[1100], buf[1024];
  tls_config_t no_backend = srv_psk;
  size_t n;
  no_backend.crypto = NULL;
  ASSERT_EQ(tls_init(&sut, NULL, sut_rx, 1024, sut_tx, 1024), -1);
  ASSERT_EQ(tls_init(&sut, &no_backend, sut_rx, 1024, sut_tx, 1024), -1);
  ASSERT_EQ(tls_init(&sut, &srv_psk, NULL, 1024, sut_tx, 1024), -1);
  ASSERT_EQ(tls_init(&sut, &srv_psk, sut_rx, 1024, NULL, 1024), -1);
  ASSERT_EQ(tls_init(&sut, &srv_psk, sut_rx, 255, sut_tx, 1024), -1);
  ASSERT_EQ(tls_init(&sut, &srv_psk, sut_rx, 1024, sut_tx, 255), -1);
  ASSERT_EQ(tls_init(&sut, &srv_psk, sut_rx, 256, sut_tx, 256), 0);

  rx_cap = 1024;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  n = tp_seal(&pw, TP_APPDATA, data, 1024 - 22, 0, rec);
  ASSERT_EQ(n, 1024);
  ASSERT_EQ(feed(rec, n), n);
  ASSERT_EQ(tls_read(&sut, buf, sizeof(buf)), 1024 - 22);
  n = tp_seal(&pw, TP_APPDATA, data, 1024 - 21, 0, rec);
  feed(rec, n);
  ASSERT_TRUE(failed_with(22));
  ASSERT_TRUE(sealed_alert_sent(2, 22));
}

/* REQ-TLS-047: a record that claims more than 2^14 bytes (2^14 + 256 for
 * a protected one) is record_overflow as soon as its header is in; a
 * content type that is none of TLS's is unexpected_message */
TEST(itest_tls_047_record_too_long_or_unknown) {
  static const uint8_t long_plain[5] = {TP_HANDSHAKE, 3, 3, 0x40, 0x01};
  static const uint8_t long_sealed[5] = {TP_APPDATA, 3, 3, 0x41, 0x01};
  static const uint8_t heartbeat[5] = {24, 3, 3, 0, 1};
  ASSERT_TRUE(sut_start(&srv_psk));
  ASSERT_EQ(tls_accept(&sut), 0);
  feed(long_plain, 5);
  ASSERT_TRUE(failed_with(22));
  ASSERT_TRUE(plain_alert_sent(22));

  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  feed(long_sealed, 5);
  ASSERT_TRUE(failed_with(22));
  ASSERT_TRUE(sealed_alert_sent(2, 22));

  ASSERT_TRUE(sut_start(&srv_psk));
  ASSERT_EQ(tls_accept(&sut), 0);
  feed(heartbeat, 5);
  ASSERT_TRUE(failed_with(10));
  ASSERT_TRUE(plain_alert_sent(10));
}

/* REQ-TLS-047, 057, 037: records that do not belong where they come.
 * Each row: the bytes (or the protected content and its type), and the
 * alert — 0 for a record that is dropped without ending the connection */
TEST(itest_tls_057_records_out_of_place) {
  static const uint8_t plain_handshake[9] = {
      TP_HANDSHAKE, 3, 3, 0, 4, 1, 0, 0, 0};
  static const uint8_t plain_alert[7] = {TP_ALERT, 3, 3, 0, 2, 1, 0};
  static const uint8_t short_sealed[21] = {TP_APPDATA, 3, 3, 0, 16};
  static const struct {
    const uint8_t *raw;
    size_t raw_len;
    uint8_t type; /* of protected content */
    const char *content;
    size_t content_len;
    uint8_t alert;
  } cases[] = {
      /* plaintext once the peer's records are protected */
      {plain_handshake, sizeof(plain_handshake), 0, NULL, 0, 10},
      {plain_alert, sizeof(plain_alert), 0, NULL, 0, 10},
      /* too short to hold a tag: it cannot authenticate */
      {short_sealed, sizeof(short_sealed), 0, NULL, 0, 20},
      /* a protected change_cipher_spec; an empty handshake record */
      {NULL, 0, TP_CCS, "\x01", 1, 10},
      {NULL, 0, TP_HANDSHAKE, "", 0, 10},
      /* an alert that is not two bytes */
      {NULL, 0, TP_ALERT, "\x01", 1, 50},
      /* a handshake message that has no place after the handshake */
      {NULL, 0, TP_HANDSHAKE, "\x04\x00\x00\x00", 4, 10},
      /* a KeyUpdate of two bytes */
      {NULL, 0, TP_HANDSHAKE, "\x18\x00\x00\x02\x00\x00", 6, 50},
      /* an empty application data record: dropped */
      {NULL, 0, TP_APPDATA, "", 0, 0},
  };
  uint8_t buf[8];
  unsigned i;
  for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
    if (cases[i].raw)
      feed(cases[i].raw, cases[i].raw_len);
    else
      (void)feed_sealed(cases[i].type, cases[i].content, cases[i].content_len);
    if (cases[i].alert) {
      ASSERT_TRUE(failed_with(cases[i].alert));
      ASSERT_TRUE(sealed_alert_sent(2, cases[i].alert));
    } else {
      ASSERT_EQ(tls_state(&sut), TLS_STATE_CONNECTED);
      ASSERT_EQ(tls_read(&sut, buf, sizeof(buf)), 0);
      ASSERT_TRUE(feed_sealed(TP_APPDATA, "next", 4));
      ASSERT_EQ(tls_read(&sut, buf, sizeof(buf)), 4);
    }
  }
}

/* REQ-TLS-047, 041: a protected record whose plaintext is longer than
 * 2^14 bytes and its type is record_overflow (RFC 8446 §5.4), though its
 * length is within the 2^14 + 256 a ciphertext may have; before any keys,
 * an empty handshake record is unexpected_message, and a handshake
 * message longer than the receive buffer record_overflow */
TEST(itest_tls_047_plaintext_too_long) {
  static const uint8_t empty[5] = {TP_HANDSHAKE, 3, 3, 0, 0};
  static const uint8_t huge[9] = {TP_HANDSHAKE, 3, 3, 0, 4, 1, 0, 0x10, 0};
  static uint8_t data[16385], buf[16384];
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  ASSERT_TRUE(feed_sealed(TP_APPDATA, data, 16384)); /* the most: taken */
  ASSERT_EQ(tls_read(&sut, buf, sizeof(buf)), 16384);
  (void)feed_sealed(TP_APPDATA, data, 16385);
  ASSERT_TRUE(failed_with(22));
  ASSERT_TRUE(sealed_alert_sent(2, 22));

  ASSERT_TRUE(sut_start(&srv_psk));
  ASSERT_EQ(tls_accept(&sut), 0);
  feed(empty, sizeof(empty));
  ASSERT_TRUE(failed_with(10));

  rx_cap = 1024;
  ASSERT_TRUE(sut_start(&srv_psk));
  ASSERT_EQ(tls_accept(&sut), 0);
  feed(huge, sizeof(huge)); /* a 4096-byte ClientHello begins */
  ASSERT_TRUE(failed_with(22));
  ASSERT_TRUE(plain_alert_sent(22));
}

/* REQ-TLS-059: a record that decrypts to nothing but zeros — no content
 * type — is unexpected_message (RFC 8446 §5.4); padding after the type is
 * removed */
TEST(itest_tls_059_padding_and_no_content_type) {
  static uint8_t rec[128];
  uint8_t buf[16];
  size_t n;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  n = tp_seal(&pw, TP_APPDATA, (const uint8_t *)"padded", 6, 40, rec);
  ASSERT_EQ(feed(rec, n), n);
  ASSERT_EQ(tls_read(&sut, buf, sizeof(buf)), 6);
  ASSERT_MEM_EQ(buf, "padded", 6);
  n = tp_seal(&pw, 0, NULL, 0, 12, rec);
  feed(rec, n);
  ASSERT_TRUE(failed_with(10));
  ASSERT_TRUE(sealed_alert_sent(2, 10));
}

/* ══ Alerts and closing ═══════════════════════════════════════════ */

/* REQ-TLS-035, 039, 048: the peer's close_notify is reported with
 * TLS_EVT_CLOSED; the connection may still write, and tls_close() sends
 * its own close_notify — a warning-level alert under the application keys
 * — after which nothing is written.  What the peer sends after its
 * close_notify is ignored. */
TEST(itest_tls_035_close_notify) {
  static const uint8_t close_notify[2] = {1, 0};
  uint8_t buf[16], type;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  ASSERT_TRUE(feed_sealed(TP_ALERT, close_notify, 2));
  ASSERT_EQ(tls_state(&sut), TLS_STATE_CLOSED);
  ASSERT_EQ(n_events, 2);
  ASSERT_EQ(events[1], TLS_EVT_CLOSED);
  ASSERT_EQ(drain(), 0);
  (void)feed_sealed(TP_APPDATA, "late", 4);
  ASSERT_EQ(tls_read(&sut, buf, sizeof(buf)), 0);
  ASSERT_EQ(tls_state(&sut), TLS_STATE_CLOSED);

  ASSERT_EQ(tls_write(&sut, (const uint8_t *)"bye", 3), 3);
  ASSERT_EQ(tls_close(&sut), 0);
  drain();
  ASSERT_EQ(open_next(&type), 3);
  ASSERT_EQ(type, TP_APPDATA);
  ASSERT_TRUE(sealed_alert_sent(1, 0));
  ASSERT_EQ(tls_write(&sut, (const uint8_t *)"x", 1), -1);
  ASSERT_EQ(tls_close(&sut), 0);
  ASSERT_EQ(drain(), 0);
  ASSERT_EQ(n_events, 2);
}

/* REQ-TLS-036, 040, 055: a fatal alert from the peer — and any alert but
 * close_notify and user_canceled is one, whatever level it claims (RFC
 * 8446 §6) — moves the connection to ERROR with TLS_EVT_ERROR, the alert
 * in tls->alert; nothing is sent in answer, nothing can be written, and
 * what the peer sends afterwards is not read */
TEST(itest_tls_036_fatal_alert_received) {
  static const uint8_t internal_error[2] = {2, 80};
  static const uint8_t warning_bad_mac[2] = {1, 20};
  static const uint8_t user_canceled[2] = {1, 90};
  uint8_t buf[8];
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  ASSERT_TRUE(feed_sealed(TP_ALERT, user_canceled, 2));
  ASSERT_EQ(tls_state(&sut), TLS_STATE_CONNECTED);
  (void)feed_sealed(TP_ALERT, internal_error, 2);
  ASSERT_TRUE(failed_with(80));
  ASSERT_EQ(n_events, 2);
  ASSERT_EQ(drain(), 0);
  ASSERT_EQ(tls_write(&sut, (const uint8_t *)"x", 1), -1);
  ASSERT_EQ(tls_close(&sut), -1);
  (void)feed_sealed(TP_APPDATA, "more", 4);
  ASSERT_EQ(tls_read(&sut, buf, sizeof(buf)), 0);
  ASSERT_EQ(n_events, 2);
  ASSERT_EQ(drain(), 0);

  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  (void)feed_sealed(TP_ALERT, warning_bad_mac, 2);
  ASSERT_TRUE(failed_with(20));
  ASSERT_EQ(drain(), 0);
}

/* ══ KeyUpdate ════════════════════════════════════════════════════ */

static const uint8_t ku_requested[5] = {TP_KEY_UPDATE, 0, 0, 1, 1};
static const uint8_t ku_not_requested[5] = {TP_KEY_UPDATE, 0, 0, 1, 0};

/* REQ-TLS-044: the peer's KeyUpdate moves its sending keys one generation
 * on (RFC 8446 §7.2); asked to, the connection answers with its own —
 * update_not_requested, under the old keys, before any more data — and
 * writes under its next keys from then on */
TEST(itest_tls_044_key_update_requested_by_the_peer) {
  uint8_t buf[16], type;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  ASSERT_TRUE(feed_sealed(TP_HANDSHAKE, ku_requested, 5));
  tp_update_secret(0, peer.c_ap);
  tp_traffic_keys(0, peer.c_ap, &pw);
  ASSERT_EQ(tls_write(&sut, (const uint8_t *)"after", 5), 5);
  drain();
  ASSERT_EQ(open_next(&type), 5);
  ASSERT_EQ(type, TP_HANDSHAKE);
  ASSERT_MEM_EQ(opened, ku_not_requested, 5);
  tp_update_secret(0, peer.s_ap);
  tp_traffic_keys(0, peer.s_ap, &pr);
  ASSERT_EQ(open_next(&type), 5);
  ASSERT_EQ(type, TP_APPDATA);
  ASSERT_MEM_EQ(opened, "after", 5);
  ASSERT_TRUE(feed_sealed(TP_APPDATA, "new", 3));
  ASSERT_EQ(tls_read(&sut, buf, sizeof(buf)), 3);
  ASSERT_EQ(tls_state(&sut), TLS_STATE_CONNECTED);
}

/* REQ-TLS-044: tls_key_update() sends a KeyUpdate — asking the peer's
 * too — and the next record is under the next keys; the peer's answer,
 * update_not_requested, is not answered again */
TEST(itest_tls_044_key_update_of_ours) {
  uint8_t buf[16], type;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  ASSERT_EQ(tls_key_update(&sut, 1), 0);
  ASSERT_EQ(tls_write(&sut, (const uint8_t *)"next", 4), 4);
  drain();
  ASSERT_EQ(open_next(&type), 5);
  ASSERT_EQ(type, TP_HANDSHAKE);
  ASSERT_MEM_EQ(opened, ku_requested, 5);
  tp_update_secret(0, peer.s_ap);
  tp_traffic_keys(0, peer.s_ap, &pr);
  ASSERT_EQ(open_next(&type), 4);
  ASSERT_EQ(type, TP_APPDATA);
  ASSERT_TRUE(feed_sealed(TP_HANDSHAKE, ku_not_requested, 5));
  tp_update_secret(0, peer.c_ap);
  tp_traffic_keys(0, peer.c_ap, &pw);
  ASSERT_EQ(drain(), 0);
  ASSERT_TRUE(feed_sealed(TP_APPDATA, "ok", 2));
  ASSERT_EQ(tls_read(&sut, buf, sizeof(buf)), 2);
}

/* REQ-TLS-044, 056: a KeyUpdate whose request_update is neither 0 nor 1 is
 * illegal_parameter; one followed by another message in its record — a
 * key change off a record boundary (RFC 8446 §5.1) — is
 * unexpected_message */
TEST(itest_tls_044_key_update_malformed) {
  static const uint8_t ku_two[5] = {TP_KEY_UPDATE, 0, 0, 1, 2};
  uint8_t two[10];
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  (void)feed_sealed(TP_HANDSHAKE, ku_two, 5);
  ASSERT_TRUE(failed_with(47));
  ASSERT_TRUE(sealed_alert_sent(2, 47));

  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  memcpy(two, ku_not_requested, 5);
  memcpy(two + 5, ku_not_requested, 5);
  (void)feed_sealed(TP_HANDSHAKE, two, 10);
  ASSERT_TRUE(failed_with(10));
}

/* REQ-TLS-044: a KeyUpdate owed while the transmit buffer is full waits
 * for room — and no application data is taken before it has gone, so
 * none follows it under the keys it retires */
TEST(itest_tls_044_key_update_waits_for_room) {
  static uint8_t data[300];
  uint8_t type;
  tx_cap = 300;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  ASSERT_EQ(tls_write(&sut, data, 278), 278); /* tx is full */
  ASSERT_TRUE(feed_sealed(TP_HANDSHAKE, ku_requested, 5));
  tp_update_secret(0, peer.c_ap);
  tp_traffic_keys(0, peer.c_ap, &pw);
  ASSERT_EQ(tls_write(&sut, data, 10), 0);
  drain();
  ASSERT_EQ(open_next(&type), 278);
  ASSERT_EQ(open_next(&type), 5);
  ASSERT_EQ(type, TP_HANDSHAKE);
  ASSERT_MEM_EQ(opened, ku_not_requested, 5);
  ASSERT_EQ(out_off, out_len);
  tp_update_secret(0, peer.s_ap);
  tp_traffic_keys(0, peer.s_ap, &pr);
  ASSERT_EQ(tls_write(&sut, data, 10), 10);
  drain();
  ASSERT_EQ(open_next(&type), 10);
  ASSERT_EQ(type, TP_APPDATA);
}

/* REQ-TLS-037: a NewSessionTicket is ignored by a client (it keeps no
 * tickets) and is unexpected_message to a server */
TEST(itest_tls_037_new_session_ticket) {
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
  ASSERT_TRUE(connect_from_client(&cli_psk, &sh_psk_ke));
  ASSERT_TRUE(feed_sealed(TP_HANDSHAKE, ticket, sizeof(ticket)));
  ASSERT_EQ(tls_state(&sut), TLS_STATE_CONNECTED);
  ASSERT_EQ(drain(), 0);
  ASSERT_TRUE(feed_sealed(TP_APPDATA, "data", 4));
  ASSERT_EQ(tls_read(&sut, buf, sizeof(buf)), 4);

  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  (void)feed_sealed(TP_HANDSHAKE, ticket, sizeof(ticket));
  ASSERT_TRUE(failed_with(10));
}

/* REQ-TLS-057: handshake messages are not interleaved with other records
 * (RFC 8446 §5.1) — application data between the two halves of a
 * KeyUpdate is unexpected_message — and before the handshake is done
 * application data is not taken at all */
TEST(itest_tls_057_no_data_inside_a_handshake_message) {
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  ASSERT_TRUE(feed_sealed(TP_HANDSHAKE, ku_not_requested, 3));
  ASSERT_EQ(tls_state(&sut), TLS_STATE_CONNECTED);
  (void)feed_sealed(TP_APPDATA, "data", 4);
  ASSERT_TRUE(failed_with(10));
  ASSERT_TRUE(sealed_alert_sent(2, 10));

  ASSERT_TRUE(server_hello_from(&srv_psk, &ch_psk_ke));
  ASSERT_TRUE(server_flight(0, 0));
  (void)feed_sealed(TP_APPDATA, "early", 5);
  ASSERT_TRUE(failed_with(10));
}

/* ══ The client's handshake ═══════════════════════════════════════ */

/* REQ-TLS-010, 011, 012, 013, 026, 063, 064: the ClientHello — in a
 * handshake record with legacy_record_version 0x0303 — offers TLS 1.3 and
 * nothing else in supported_versions, one x25519 share in key_share (its
 * group in supported_groups), signature_algorithms with both schemes the
 * client verifies, and the host name in server_name; an address literal,
 * or no name, is not sent as one (RFC 6066 §3) */
TEST(itest_tls_010_client_hello) {
  const uint8_t *x;
  size_t xl;
  ASSERT_TRUE(client_hello_from(&cli_cert, HOST));
  ASSERT_EQ(hello.legacy_version, 0x0303);
  ASSERT_EQ(hello.session_id_len, 0);
  ASSERT_EQ(hello.suites_len, 2);
  ASSERT_EQ(tp_get(hello.suites, 2), TP_SUITE);
  ASSERT_TRUE(hello.compression_len == 1 && hello.compression[0] == 0);
  x = tp_ext(&hello, TP_EXT_SUPPORTED_VERSIONS, &xl);
  ASSERT_TRUE(x && xl == 3 && x[0] == 2 && tp_get(x + 1, 2) == 0x0304);
  x = tp_ext(&hello, TP_EXT_KEY_SHARE, &xl);
  ASSERT_TRUE(x && xl == 38 && tp_get(x, 2) == 36);
  ASSERT_TRUE(tp_get(x + 2, 2) == TP_X25519 && tp_get(x + 4, 2) == 32);
  x = tp_ext(&hello, TP_EXT_SUPPORTED_GROUPS, &xl);
  ASSERT_TRUE(x && xl == 6 && tp_get(x, 2) == 4);
  ASSERT_TRUE(tp_get(x + 2, 2) == TP_X25519 && tp_get(x + 4, 2) == TP_P256);
  x = tp_ext(&hello, TP_EXT_SIGNATURE_ALGORITHMS, &xl);
  ASSERT_TRUE(x && xl == 6 && tp_get(x, 2) == 4);
  ASSERT_TRUE(tp_get(x + 2, 2) == 0x0403 && tp_get(x + 4, 2) == 0x0804);
  x = tp_ext(&hello, TP_EXT_SERVER_NAME, &xl);
  ASSERT_TRUE(x && xl == 5 + strlen(HOST));
  ASSERT_TRUE(tp_get(x, 2) == 3 + strlen(HOST) && x[2] == 0);
  ASSERT_EQ(tp_get(x + 3, 2), strlen(HOST));
  ASSERT_MEM_EQ(x + 5, HOST, strlen(HOST));
  ASSERT_TRUE(tp_ext(&hello, TP_EXT_PRE_SHARED_KEY, &xl) == NULL);

  ASSERT_TRUE(client_hello_from(&cli_cert, "10.0.0.2"));
  ASSERT_TRUE(tp_ext(&hello, TP_EXT_SERVER_NAME, &xl) == NULL);
  ASSERT_TRUE(client_hello_from(&cli_cert, "fe80::1"));
  ASSERT_TRUE(tp_ext(&hello, TP_EXT_SERVER_NAME, &xl) == NULL);
  ASSERT_TRUE(client_hello_from(&cli_cert, NULL));
  ASSERT_TRUE(tp_ext(&hello, TP_EXT_SERVER_NAME, &xl) == NULL);
}

/* REQ-TLS-023, 025: a client with a pre-shared key offers it —
 * psk_key_exchange_modes with the modes configured, and pre_shared_key,
 * the last extension, with the configured identity and a binder that
 * checks out under the configured key.  Configured for psk_ke alone it
 * offers no (EC)DHE share at all. */
TEST(itest_tls_023_client_offers_the_psk) {
  tls_config_t cfg = cli_psk;
  const uint8_t *x;
  uint16_t last = 0;
  size_t xl, idl = strlen(PSK_ID);
  ASSERT_TRUE(client_hello_from(&cfg, NULL));
  x = tp_ext(&hello, TP_EXT_PSK_MODES, &xl);
  ASSERT_TRUE(x && xl == 3 && x[0] == 2 && x[1] == 1 && x[2] == 0);
  ASSERT_TRUE(tp_ext_count(&hello, &last) > 0 && last == TP_EXT_PRE_SHARED_KEY);
  x = tp_ext(&hello, TP_EXT_PRE_SHARED_KEY, &xl);
  ASSERT_EQ(xl, 2 + 2 + idl + 4 + 2 + 33);
  ASSERT_TRUE(tp_get(x, 2) == 2 + idl + 4 && tp_get(x + 2, 2) == idl);
  ASSERT_MEM_EQ(x + 4, PSK_ID, idl);
  ASSERT_TRUE(tp_binder_ok(&peer, hello_msg, hello_len));
  ASSERT_TRUE(tp_ext(&hello, TP_EXT_KEY_SHARE, &xl) != NULL);

  cfg.psk_modes = TLS_PSK_KE;
  ASSERT_TRUE(client_hello_from(&cfg, NULL));
  x = tp_ext(&hello, TP_EXT_PSK_MODES, &xl);
  ASSERT_TRUE(x && xl == 2 && x[0] == 1 && x[1] == 0);
  ASSERT_TRUE(tp_ext(&hello, TP_EXT_KEY_SHARE, &xl) == NULL);
  ASSERT_TRUE(tp_ext(&hello, TP_EXT_SUPPORTED_GROUPS, &xl) == NULL);

  cfg.psk = other_psk; /* another key: another binder */
  ASSERT_TRUE(client_hello_from(&cfg, NULL));
  ASSERT_FALSE(tp_binder_ok(&peer, hello_msg, hello_len));
}

/* REQ-TLS-016, 017, 024, 034, 038: the client sends its Finished only once
 * the server's has checked out — nothing before — with the verify_data
 * RFC 8446 §4.4.4 defines over the transcript of every handshake message,
 * and then reports TLS_EVT_CONNECTED; with the PSK accepted it expects no
 * Certificate */
TEST(itest_tls_016_client_finished_after_the_servers) {
  ASSERT_TRUE(connect_from_client(&cli_psk, &sh_psk_ke));
  ASSERT_EQ(n_events, 1);
  ASSERT_EQ(events[0], TLS_EVT_CONNECTED);
  ASSERT_TRUE(tls_psk_used(&sut));
}

/* REQ-TLS-011, 004, 032: the server takes the PSK with (EC)DHE — the
 * client's x25519 share and the peer's give both sides the same secrets */
TEST(itest_tls_011_client_key_share_used) {
  ASSERT_TRUE(connect_from_client(&cli_psk, &sh_psk_dhe));
  ASSERT_EQ(sut.group, TLS_GROUP_X25519);
}

/* REQ-TLS-016, 037, 040: a server Finished that does not verify is
 * decrypt_error — under the client's handshake keys — and no Finished of
 * the client's follows */
TEST(itest_tls_016_wrong_server_finished_refused) {
  uint8_t m[64];
  size_t n;
  ASSERT_TRUE(client_hello_from(&cli_psk, NULL));
  ASSERT_TRUE(answer_hello(&sh_psk_ke));
  n = tp_encrypted_extensions(&peer, -1, NULL, 0, m);
  n += tp_finished(&peer, peer.s_hs, m + n);
  m[n - 1] ^= 0x80;
  (void)feed_sealed(TP_HANDSHAKE, m, n);
  ASSERT_TRUE(failed_with(51));
  ASSERT_EQ(n_events, 1);
  ASSERT_TRUE(sealed_alert_sent(2, 51));
}

/* REQ-TLS-001, 037: a ServerHello without supported_versions is a TLS 1.2
 * server's — protocol_version; one selecting a version the client did not
 * offer is illegal_parameter (RFC 8446 §4.2.1) */
TEST(itest_tls_001_tls12_server_refused) {
  tp_sh_t o = sh_psk_ke;
  o.no_versions = 1;
  ASSERT_TRUE(client_hello_from(&cli_psk, NULL));
  ASSERT_TRUE(answer_hello(&o));
  ASSERT_TRUE(failed_with(70));
  ASSERT_TRUE(plain_alert_sent(70));
  o.no_versions = 0;
  o.version = 0x0303;
  ASSERT_TRUE(client_hello_from(&cli_psk, NULL));
  ASSERT_TRUE(answer_hello(&o));
  ASSERT_TRUE(failed_with(47));
  ASSERT_TRUE(plain_alert_sent(47));
}

/* REQ-TLS-024: once the server has taken the PSK, a Certificate from it
 * is not part of the handshake: unexpected_message */
TEST(itest_tls_024_no_certificate_after_a_psk) {
  uint8_t m[64];
  size_t n;
  ASSERT_TRUE(client_hello_from(&cli_psk, NULL));
  ASSERT_TRUE(answer_hello(&sh_psk_ke));
  n = tp_encrypted_extensions(&peer, -1, NULL, 0, m);
  m[n] = TP_CERTIFICATE; /* an empty context, an empty list */
  tp_put(m + n + 1, 3, 4);
  memset(m + n + 4, 0, 4);
  (void)feed_sealed(TP_HANDSHAKE, m, n + 8);
  ASSERT_TRUE(failed_with(10));
  ASSERT_TRUE(sealed_alert_sent(2, 10));
}

/* REQ-TLS-053: a ServerHello with an extension the client did not offer
 * (here an empty one of type 0xFFAA) is unsupported_extension */
TEST(itest_tls_053_extension_not_offered_refused) {
  tp_sh_t o = sh_psk_ke;
  o.stray = 0xFFAA + 1;
  ASSERT_TRUE(client_hello_from(&cli_psk, NULL));
  ASSERT_TRUE(answer_hello(&o));
  ASSERT_TRUE(failed_with(110));
  ASSERT_TRUE(plain_alert_sent(110));
}

/* The peer's EncryptedExtensions with the one extension @p type (empty)
 * and Finished, to a client of @p cfg started without a host name */
static int encrypted_extension_to(const tls_config_t *cfg, int type) {
  static const uint8_t groups[4] = {0, 2, 0, 0x1D};
  uint8_t m[64];
  size_t n;
  CHECK(client_hello_from(cfg, NULL));
  CHECK(answer_hello(&sh_psk_ke));
  n = tp_encrypted_extensions(&peer, type, groups,
                              type == TP_EXT_SUPPORTED_GROUPS ? 4 : 0, m);
  n += tp_finished(&peer, peer.s_hs, m + n);
  (void)feed_sealed(TP_HANDSHAKE, m, n);
  return 1;
}

/* REQ-TLS-053: EncryptedExtensions answering an extension the client did
 * not send — server_name to a client that named no host, supported_groups
 * to one that offered the PSK alone and so no groups — is
 * unsupported_extension (RFC 8446 §4.2); each is accepted by a client
 * that did send it */
TEST(itest_tls_053_encrypted_extension_not_offered_refused) {
  tls_config_t ke_only = cli_psk;
  ke_only.psk_modes = TLS_PSK_KE;
  ASSERT_TRUE(encrypted_extension_to(&cli_psk, TP_EXT_SUPPORTED_GROUPS));
  ASSERT_EQ(tls_state(&sut), TLS_STATE_CONNECTED);
  ASSERT_TRUE(encrypted_extension_to(&cli_psk, TP_EXT_SERVER_NAME));
  ASSERT_TRUE(failed_with(110));
  ASSERT_TRUE(sealed_alert_sent(2, 110));
  ASSERT_TRUE(encrypted_extension_to(&ke_only, TP_EXT_SUPPORTED_GROUPS));
  ASSERT_TRUE(failed_with(110));
}

/* REQ-TLS-060: a ServerHello that takes the PSK without a key_share, to a
 * client that offered the PSK only with (EC)DHE, is illegal_parameter
 * (RFC 8446 §4.2.11); so is a selected identity the client did not offer */
TEST(itest_tls_060_psk_server_hello_consistent) {
  static uint8_t m[512];
  tls_config_t dhe_only = cli_psk;
  size_t n;
  dhe_only.psk_modes = TLS_PSK_DHE_KE;
  ASSERT_TRUE(client_hello_from(&dhe_only, NULL));
  ASSERT_TRUE(answer_hello(&sh_psk_ke));
  ASSERT_TRUE(failed_with(47));
  ASSERT_TRUE(plain_alert_sent(47));

  ASSERT_TRUE(client_hello_from(&cli_psk, NULL));
  tp_add(&peer, hello_msg, hello_len);
  n = tp_server_hello(&peer, &sh_psk_ke, m);
  m[n - 1] = 1; /* selected_identity 1 of the one offered */
  feed_plain(m, n);
  ASSERT_TRUE(failed_with(47));
}

/* REQ-TLS-018, 037: a ServerHello the client cannot accept — a suite or
 * compression method it did not offer, a share of another group or one
 * that is no point, one cut short — and a HelloRetryRequest with a
 * session id, an unknown extension or no supported_versions */
TEST(itest_tls_037_server_hello_refusals) {
  static const uint8_t sid[2] = {1, 2}, cookie[3] = {1, 2, 3};
  static uint8_t m[512];
  tp_sh_t o;
  size_t n;
  int i;
  for (i = 0; i < 8; i++) {
    uint8_t alert = 47;
    o = sh_psk_dhe;
    if (i == 0)
      o.suite = 0x1302;
    if (i == 1)
      o.compression = 1;
    if (i == 2)
      o.share_group = TP_P256;
    if (i == 3)
      o.zero_share = 1;
    if (i == 4) {
      o.truncated = 1;
      alert = 50;
    }
    if (i >= 5) {
      memset(&o, 0, sizeof(o));
      o.hrr = 1;
      o.cookie = cookie;
      o.cookie_len = sizeof(cookie);
    }
    if (i == 5) {
      o.session_id = sid;
      o.session_id_len = sizeof(sid);
    }
    if (i == 6) {
      o.stray = 0xFFAA + 1;
      alert = 110;
    }
    if (i == 7) {
      o.no_versions = 1;
      alert = 70;
    }
    ASSERT_TRUE(client_hello_from(&cli_psk, NULL));
    tp_add(&peer, hello_msg, hello_len);
    n = tp_server_hello(&peer, &o, m);
    feed_plain(m, n);
    ASSERT_TRUE(failed_with(alert));
    ASSERT_TRUE(plain_alert_sent(alert));
  }
}

/* ── The peer as a certificate server ── */

typedef struct {
  int request;     /* a CertificateRequest first */
  int certs;       /* certificates in the chain: the leaf, then the CA's */
  int context;     /* bytes of certificate_request_context */
  uint16_t scheme; /* of CertificateVerify; 0: ecdsa_secp256r1_sha256 */
  int bad_signature;
  int extensions_cut; /* EncryptedExtensions' list runs past the message */
} cert_opt_t;

/* The peer's ServerHello and its flight with the test certificate, signed
 * with the certificate's key, to a client that trusts its CA */
static int certificate_flight_to(const char *host, const cert_opt_t *o) {
  static uint8_t m[8192];
  const uint8_t *der[8];
  uint16_t len[8];
  size_t n, k;
  int i;
  CHECK(client_hello_from(&cli_cert, host));
  CHECK(answer_hello(&sh_cert));
  CHECK(tls_state(&sut) == TLS_STATE_HANDSHAKE);
  n = tp_encrypted_extensions(&peer, -1, NULL, 0, m);
  if (o->extensions_cut)
    m[5] = 9;
  if (o->request)
    n += tp_certificate_request(&peer, m + n);
  for (i = 0; i < o->certs; i++) {
    der[i] = i ? ca_der : server_der;
    len[i] = (uint16_t)(i ? sizeof(ca_der) : sizeof(server_der));
  }
  n += tp_certificate(&peer, der, len, o->certs, o->context, m + n);
  k = tp_certificate_verify(&peer, o->scheme ? o->scheme : 0x0403,
                            server_key_pem, sizeof(server_key_pem), m + n);
  CHECK(k > 0);
  if (o->bad_signature)
    m[n + k - 1] ^= 0x01;
  n += k;
  n += tp_finished(&peer, peer.s_hs, m + n);
  (void)feed_sealed(TP_HANDSHAKE, m, n);
  return 1;
}

/* REQ-TLS-014, 015, 016, 017: a certificate handshake with the peer as
 * the server — its chain to the client's trust anchor, the name the
 * client asked for, a CertificateVerify by the certificate's key over the
 * transcript — completes, the client's Finished as RFC 8446 §4.4.4
 * computes it; the same flight for another name is bad_certificate */
TEST(itest_tls_014_certificate_from_the_peer) {
  cert_opt_t o;
  uint8_t buf[8], type;
  memset(&o, 0, sizeof(o));
  o.certs = 2;
  ASSERT_TRUE(certificate_flight_to(HOST, &o));
  tp_application_secrets(&peer);
  tp_traffic_keys(0, peer.s_ap, &pw);
  ASSERT_TRUE(client_flight_read(0));
  ASSERT_EQ(tls_state(&sut), TLS_STATE_CONNECTED);
  ASSERT_FALSE(tls_psk_used(&sut));
  ASSERT_EQ(sut.group, TLS_GROUP_X25519);
  ASSERT_TRUE(feed_sealed(TP_APPDATA, "ping", 4));
  ASSERT_EQ(tls_read(&sut, buf, sizeof(buf)), 4);
  ASSERT_EQ(tls_write(&sut, (const uint8_t *)"pong", 4), 4);
  drain();
  ASSERT_EQ(open_next(&type), 4);
  ASSERT_MEM_EQ(opened, "pong", 4);

  ASSERT_TRUE(certificate_flight_to("other.example", &o));
  ASSERT_TRUE(failed_with(42));
  ASSERT_TRUE(sealed_alert_sent(2, 42));
}

/* REQ-TLS-067: a client the server asks for a certificate has none, and
 * says so: a Certificate message with an empty list, then its Finished */
TEST(itest_tls_067_certificate_request_answered_with_none) {
  cert_opt_t o;
  memset(&o, 0, sizeof(o));
  o.certs = 1;
  o.request = 1;
  ASSERT_TRUE(certificate_flight_to(HOST, &o));
  tp_application_secrets(&peer);
  tp_traffic_keys(0, peer.s_ap, &pw);
  ASSERT_TRUE(client_flight_read(1));
  ASSERT_EQ(tls_state(&sut), TLS_STATE_CONNECTED);
}

/* REQ-TLS-062, 015, 037: the server's Certificate and CertificateVerify
 * checked — an empty certificate list is decode_error, a
 * certificate_request_context illegal_parameter, a chain longer than the
 * six the client takes bad_certificate; a CertificateVerify with a scheme
 * the client did not offer is illegal_parameter, and one whose signature
 * does not verify (a changed byte, or another scheme than the key's)
 * decrypt_error.  Malformed EncryptedExtensions: decode_error. */
TEST(itest_tls_062_server_certificate_checked) {
  static const struct {
    int certs, context, bad_signature, extensions_cut;
    uint16_t scheme;
    uint8_t alert;
  } cases[] = {
      {0, 0, 0, 0, 0, 50},      {1, 4, 0, 0, 0, 47}, {7, 0, 0, 0, 0, 42},
      {1, 0, 0, 0, 0x0401, 47}, {1, 0, 1, 0, 0, 51}, {1, 0, 0, 0, 0x0804, 51},
      {1, 0, 0, 1, 0, 50},
  };
  unsigned i;
  for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    cert_opt_t o;
    memset(&o, 0, sizeof(o));
    o.certs = cases[i].certs;
    o.context = cases[i].context;
    o.bad_signature = cases[i].bad_signature;
    o.extensions_cut = cases[i].extensions_cut;
    o.scheme = cases[i].scheme;
    ASSERT_TRUE(certificate_flight_to(HOST, &o));
    ASSERT_TRUE(failed_with(cases[i].alert));
    ASSERT_TRUE(sealed_alert_sent(2, cases[i].alert));
  }
}

/* REQ-TLS-046: a ServerHello that echoes a session id the client did not
 * send is illegal_parameter */
TEST(itest_tls_046_session_id_echo_checked) {
  static const uint8_t sid[4] = {1, 2, 3, 4};
  tp_sh_t o = sh_psk_ke;
  o.session_id = sid;
  o.session_id_len = sizeof(sid);
  ASSERT_TRUE(client_hello_from(&cli_psk, NULL));
  ASSERT_TRUE(answer_hello(&o));
  ASSERT_TRUE(failed_with(47));
  ASSERT_TRUE(plain_alert_sent(47));
}

/* REQ-TLS-049, 064: a HelloRetryRequest with a cookie is answered with a
 * second ClientHello — the same random, the cookie in a cookie extension,
 * a new binder over message_hash, the HelloRetryRequest and itself (RFC
 * 8446 §4.4.1) — and the handshake completes on that transcript.  A
 * second HelloRetryRequest is unexpected_message. */
TEST(itest_tls_049_hello_retry_request_answered) {
  static const uint8_t cookie[5] = {'c', 'o', 'o', 'k', 'y'};
  static uint8_t m[512], first_random[32];
  tp_sh_t hrr;
  const uint8_t *r, *x;
  size_t n, len, xl;
  int twice;
  memset(&hrr, 0, sizeof(hrr));
  hrr.hrr = 1;
  hrr.cookie = cookie;
  hrr.cookie_len = sizeof(cookie);
  for (twice = 0; twice < 2; twice++) {
    ASSERT_TRUE(client_hello_from(&cli_psk, NULL));
    ASSERT_TRUE(tp_binder_ok(&peer, hello_msg, hello_len));
    memcpy(first_random, hello.random, 32);
    tp_add(&peer, hello_msg, hello_len);
    n = tp_server_hello(&peer, &hrr, m);
    ASSERT_EQ(feed_plain(m, n), n + 5);
    drain();
    r = next_record(&len);
    ASSERT_TRUE(r && r[0] == TP_HANDSHAKE && out_off == out_len);
    hello_len = len - 5;
    memcpy(hello_msg, r + 5, hello_len);
    ASSERT_TRUE(tp_parse_hello(hello_msg, hello_len, 0, &hello));
    ASSERT_MEM_EQ(hello.random, first_random, 32);
    x = tp_ext(&hello, TP_EXT_COOKIE, &xl);
    ASSERT_TRUE(x && xl == 2 + sizeof(cookie) && tp_get(x, 2) == 5);
    ASSERT_MEM_EQ(x + 2, cookie, sizeof(cookie));
    if (twice) {
      tp_add(&peer, hello_msg, hello_len);
      n = tp_server_hello(&peer, &hrr, m);
      feed_plain(m, n);
      ASSERT_TRUE(failed_with(10));
      ASSERT_TRUE(plain_alert_sent(10));
    } else {
      ASSERT_TRUE(answer_hello(&sh_psk_ke));
      ASSERT_TRUE(answer_flight());
      ASSERT_TRUE(client_finished_read());
      ASSERT_EQ(tls_state(&sut), TLS_STATE_CONNECTED);
    }
  }
}

/* REQ-TLS-049: a HelloRetryRequest that would change nothing in the
 * ClientHello — no cookie, no other group — is illegal_parameter, as is
 * one asking for the group the client already sent a share of */
TEST(itest_tls_049_hello_retry_request_must_change_something) {
  static uint8_t m[512];
  tp_sh_t hrr;
  size_t n;
  int same_group;
  memset(&hrr, 0, sizeof(hrr));
  hrr.hrr = 1;
  for (same_group = 0; same_group < 2; same_group++) {
    hrr.hrr_group = same_group ? TP_X25519 : 0;
    ASSERT_TRUE(client_hello_from(&cli_psk, NULL));
    tp_add(&peer, hello_msg, hello_len);
    n = tp_server_hello(&peer, &hrr, m);
    feed_plain(m, n);
    ASSERT_TRUE(failed_with(47));
    ASSERT_TRUE(plain_alert_sent(47));
  }
}

/* REQ-TLS-031: a client configured for 512-byte records asks for them in
 * max_fragment_length; once the server grants the same code, the client's
 * records carry no more; a different code back is illegal_parameter (RFC
 * 6066 §4) */
TEST(itest_tls_031_max_fragment_length_asked) {
  static uint8_t data[1200];
  tls_config_t cfg = cli_psk;
  uint8_t m[64], code = TLS_MFL_512, type;
  const uint8_t *x;
  size_t n, xl, total = 0;
  int k, wrong;
  cfg.max_fragment = TLS_MFL_512;
  for (wrong = 0; wrong < 2; wrong++) {
    code = (uint8_t)(wrong ? TLS_MFL_1024 : TLS_MFL_512);
    ASSERT_TRUE(client_hello_from(&cfg, NULL));
    x = tp_ext(&hello, TP_EXT_MAX_FRAGMENT_LENGTH, &xl);
    ASSERT_TRUE(x && xl == 1 && x[0] == TLS_MFL_512);
    ASSERT_TRUE(answer_hello(&sh_psk_ke));
    n = tp_encrypted_extensions(&peer, TP_EXT_MAX_FRAGMENT_LENGTH, &code, 1, m);
    n += tp_finished(&peer, peer.s_hs, m + n);
    (void)feed_sealed(TP_HANDSHAKE, m, n);
    if (wrong) {
      ASSERT_TRUE(failed_with(47));
      return;
    }
    tp_application_secrets(&peer);
    tp_traffic_keys(0, peer.s_ap, &pw);
    ASSERT_TRUE(client_finished_read());
    ASSERT_EQ(sut.max_frag, 512);
    while (total < sizeof(data)) {
      ASSERT_TRUE((k = tls_write(&sut, data + total, sizeof(data) - total)) >
                  0);
      total += (size_t)k;
    }
    drain();
    total = 0;
    while (out_off < out_len) {
      ASSERT_TRUE((k = open_next(&type)) > 0 && k <= 512);
      total += (size_t)k;
    }
    ASSERT_EQ(total, sizeof(data));
  }
}

/* REQ-TLS-039, 036, 040: the client reports the server's close_notify
 * with TLS_EVT_CLOSED, and a fatal alert — here in plaintext, from a
 * server that failed before it had keys — with TLS_EVT_ERROR */
TEST(itest_tls_039_client_told_of_close_and_alert) {
  static const uint8_t close_notify[2] = {1, 0};
  static const uint8_t alert[7] = {TP_ALERT, 3, 3, 0, 2, 2, 40};
  ASSERT_TRUE(connect_from_client(&cli_psk, &sh_psk_ke));
  ASSERT_TRUE(feed_sealed(TP_ALERT, close_notify, 2));
  ASSERT_EQ(tls_state(&sut), TLS_STATE_CLOSED);
  ASSERT_EQ(n_events, 2);
  ASSERT_EQ(events[1], TLS_EVT_CLOSED);

  ASSERT_TRUE(client_hello_from(&cli_psk, NULL));
  feed(alert, sizeof(alert));
  ASSERT_TRUE(failed_with(40));
  ASSERT_EQ(n_events, 1);
  ASSERT_EQ(drain(), 0);
}

/* ══ Certificates: the stack's client and server together ═════════ */

/* REQ-TLS-014, 015, 020, 063: a server with a certificate sends its chain
 * and a CertificateVerify, and the client completes the handshake only if
 * the chain leads to its trust anchor and names the host it asked for:
 * another name is bad_certificate, no anchor unknown_ca — alerts the
 * server receives.  Both ECDSA P-256 and RSA-PSS keys sign. */
TEST(itest_tls_014_certificate_chain_and_name) {
  tls_config_t no_anchor = cli_cert, rsa = srv_cert;
  pair(&cli_cert, HOST, &srv_cert);
  ASSERT_TRUE(both_connected());
  ASSERT_FALSE(tls_psk_used(&ca) || tls_psk_used(&sa));
  ASSERT_EQ(ca.group, TLS_GROUP_X25519);

  pair(&cli_cert, "other.example", &srv_cert);
  ASSERT_EQ(tls_state(&ca), TLS_STATE_ERROR);
  ASSERT_EQ(ca.alert, 42);
  ASSERT_EQ(tls_state(&sa), TLS_STATE_ERROR);
  ASSERT_EQ(sa.alert, 42);

  no_anchor.crypto = &crypto_no_ca;
  pair(&no_anchor, HOST, &srv_cert);
  ASSERT_EQ(tls_state(&ca), TLS_STATE_ERROR);
  ASSERT_EQ(ca.alert, 48);
  ASSERT_EQ(sa.alert, 48);

  pair(&cli_cert, NULL, &srv_cert); /* no name to check: the chain alone */
  ASSERT_TRUE(both_connected());

  rsa.cert = rsa_chain;
  rsa.cert_len = rsa_chain_len;
  rsa.key = &rsa_key;
  rsa.sig_scheme = TLS_SIG_RSA_PSS_RSAE_SHA256;
  pair(&cli_cert, NULL, &rsa);
  ASSERT_TRUE(both_connected());
}

/* REQ-TLS-015: a CertificateVerify signed by a key that is not the
 * certificate's — the server holds the wrong private key — is
 * decrypt_error (RFC 8446 §4.4.3) */
TEST(itest_tls_015_certificate_verify_checked) {
  tls_config_t wrong_key = srv_cert;
  mbedtls_pk_context key;
  mbedtls_pk_init(&key);
  ASSERT_EQ(mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)),
            0);
  ASSERT_EQ(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key),
                                mbedtls_ctr_drbg_random, &backend.drbg),
            0);
  wrong_key.key = &key;
  pair(&cli_cert, HOST, &wrong_key);
  mbedtls_pk_free(&key);
  ASSERT_EQ(tls_state(&ca), TLS_STATE_ERROR);
  ASSERT_EQ(ca.alert, 51);
  ASSERT_EQ(sa.alert, 51);
}

/* REQ-TLS-020, 037: a transmit buffer smaller than the server's flight
 * carries it a message at a time, as the transport takes it; one too
 * small for the Certificate alone ends the handshake with internal_error
 * instead of waiting for ever */
TEST(itest_tls_020_flight_through_a_small_transmit_buffer) {
  pair_tx = 600;
  pair(&cli_cert, HOST, &srv_cert);
  ASSERT_TRUE(both_connected());
  pair_tx = 256;
  pair(&cli_cert, HOST, &srv_cert);
  ASSERT_EQ(tls_state(&sa), TLS_STATE_ERROR);
  ASSERT_EQ(sa.alert, 80);
  ASSERT_EQ(tls_state(&ca), TLS_STATE_ERROR);
  ASSERT_EQ(ca.alert, 80);
}

/* REQ-TLS-031: with max_fragment_length 512 a message longer than a
 * record — the RSA certificate — leaves in records of at most 512 bytes
 * of content, and a client with an 800-byte receive buffer completes the
 * ECDSA handshake */
TEST(itest_tls_031_long_message_in_small_records) {
  tls_config_t mfl = cli_cert, rsa = srv_cert;
  size_t off, len, records = 0;
  mfl.max_fragment = TLS_MFL_512;
  rsa.cert = rsa_chain;
  rsa.cert_len = rsa_chain_len;
  rsa.key = &rsa_key;
  rsa.sig_scheme = TLS_SIG_RSA_PSS_RSAE_SHA256;
  pair(&mfl, NULL, &rsa);
  ASSERT_TRUE(both_connected());
  ASSERT_EQ(ca.max_frag, 512);
  ASSERT_EQ(sa.max_frag, 512);
  for (off = 0; off < s2c_len; off += len, records++) {
    len = 5 + tp_get(s2c + off + 3, 2);
    ASSERT_TRUE(len <= 5 + 512 + 1 + 16);
  }
  ASSERT_EQ(off, s2c_len);
  ASSERT_TRUE(records >= 4); /* ServerHello, and a flight of 1100 bytes */

  pair_rx = 800;
  pair(&mfl, HOST, &srv_cert);
  ASSERT_TRUE(both_connected());
}

/* REQ-TLS-005, 004, 061: key exchange over secp256r1 — a client restricted to
 * it sends a P-256 share; a server restricted to it asks a client that
 * sent x25519 for another share with a HelloRetryRequest, and the
 * handshake completes over P-256 */
TEST(itest_tls_005_secp256r1) {
  tls_config_t c256 = cli_cert, s256 = srv_cert;
  c256.groups = TLS_GROUPS_SECP256R1;
  s256.groups = TLS_GROUPS_SECP256R1;
  pair(&c256, HOST, &srv_cert);
  ASSERT_TRUE(both_connected());
  ASSERT_EQ(ca.group, TLS_GROUP_SECP256R1);
  ASSERT_EQ(sa.group, TLS_GROUP_SECP256R1);
  ASSERT_EQ(c2s[5], TP_CLIENT_HELLO);

  pair(&cli_cert, HOST, &s256);
  ASSERT_TRUE(both_connected());
  ASSERT_EQ(ca.group, TLS_GROUP_SECP256R1);
  ASSERT_EQ(sa.group, TLS_GROUP_SECP256R1);
}

/* REQ-TLS-023: a client and a server that both hold the key use it, in
 * either mode; a server that holds none falls back to its certificate */
TEST(itest_tls_023_psk_between_our_roles) {
  tls_config_t ke = cli_psk, both = cli_psk;
  ke.psk_modes = TLS_PSK_KE;
  both.crypto = &crypto;
  pair(&cli_psk, NULL, &srv_both);
  ASSERT_TRUE(both_connected());
  ASSERT_TRUE(tls_psk_used(&ca) && tls_psk_used(&sa));
  ASSERT_EQ(sa.group, TLS_GROUP_X25519);
  pair(&ke, NULL, &srv_both);
  ASSERT_TRUE(both_connected());
  ASSERT_TRUE(tls_psk_used(&ca) && tls_psk_used(&sa));
  ASSERT_EQ(sa.group, 0);
  pair(&both, HOST, &srv_cert);
  ASSERT_TRUE(both_connected());
  ASSERT_FALSE(tls_psk_used(&ca) || tls_psk_used(&sa));
}

/* ══ Architecture ═════════════════════════════════════════════════ */

/* A backend that counts what is asked of it, and keeps the last random
 * bytes and key share it gave */
static tls_crypto_t counting;
static int asked[15];
static int failing = -1; /* the operation (index in asked) that fails */
static uint8_t last_random[32], last_share[TLS_KX_PUB_MAX];
static size_t last_share_len;

static void c_hash_init(tls_hash_t *h) {
  asked[0]++;
  crypto.hash_init(h);
}
static void c_hash_update(tls_hash_t *h, const uint8_t *d, size_t n) {
  asked[1]++;
  crypto.hash_update(h, d, n);
}
static void c_hash_peek(const tls_hash_t *h, uint8_t out[TLS_HASH_LEN]) {
  asked[2]++;
  crypto.hash_peek(h, out);
}
static void c_hmac(const uint8_t *k, size_t kl, const uint8_t *d, size_t n,
                   uint8_t out[TLS_HASH_LEN]) {
  asked[3]++;
  crypto.hmac(k, kl, d, n, out);
}
static void c_extract(const uint8_t *s, size_t sl, const uint8_t *i, size_t il,
                      uint8_t prk[TLS_HASH_LEN]) {
  asked[4]++;
  crypto.hkdf_extract(s, sl, i, il, prk);
}
static void c_expand(const uint8_t prk[TLS_HASH_LEN], const uint8_t *info,
                     size_t il, uint8_t *out, size_t n) {
  asked[5]++;
  crypto.hkdf_expand(prk, info, il, out, n);
}
static void c_seal(const uint8_t key[TLS_AEAD_KEY_LEN],
                   const uint8_t nonce[TLS_AEAD_IV_LEN], const uint8_t *aad,
                   size_t al, const uint8_t *in, size_t n, uint8_t *o,
                   uint8_t tag[TLS_AEAD_TAG_LEN]) {
  asked[6]++;
  crypto.aead_seal(key, nonce, aad, al, in, n, o, tag);
}
static int c_open(const uint8_t key[TLS_AEAD_KEY_LEN],
                  const uint8_t nonce[TLS_AEAD_IV_LEN], const uint8_t *aad,
                  size_t al, const uint8_t *in, size_t n,
                  const uint8_t tag[TLS_AEAD_TAG_LEN], uint8_t *o) {
  asked[7]++;
  return crypto.aead_open(key, nonce, aad, al, in, n, tag, o);
}
static int c_keygen(void *ctx, uint16_t group, uint8_t *priv, uint8_t *pub,
                    size_t *pub_len) {
  int r = crypto.kx_keygen(ctx, group, priv, pub, pub_len);
  asked[8]++;
  memcpy(last_share, pub, *pub_len);
  last_share_len = *pub_len;
  if (failing == 8)
    return -1;
  return r;
}
static int c_shared(void *ctx, uint16_t group, const uint8_t *priv,
                    const uint8_t *peer_share, size_t n,
                    uint8_t shared[TLS_HASH_LEN]) {
  asked[9]++;
  return crypto.kx_shared(ctx, group, priv, peer_share, n, shared);
}
static int c_sign(void *ctx, const void *key, uint16_t scheme,
                  const uint8_t *msg, size_t n, uint8_t *sig, size_t *sig_len,
                  size_t cap) {
  asked[10]++;
  if (failing == 10)
    return -1;
  return crypto.sign(ctx, key, scheme, msg, n, sig, sig_len, cap);
}
static int c_verify(void *ctx, const uint8_t *cert, size_t cl_, uint16_t scheme,
                    const uint8_t *msg, size_t n, const uint8_t *sig,
                    size_t sl) {
  asked[11]++;
  return crypto.verify(ctx, cert, cl_, scheme, msg, n, sig, sl);
}
static int c_chain(void *ctx, const uint8_t *const *certs, const uint16_t *lens,
                   uint8_t count, const char *host) {
  asked[12]++;
  return crypto.verify_chain(ctx, certs, lens, count, host);
}
static int c_random(void *ctx, uint8_t *o, size_t n) {
  int r = crypto.random(ctx, o, n);
  asked[13]++;
  if (n == 32)
    memcpy(last_random, o, 32);
  if (failing == 13)
    return -1;
  return r;
}

/* REQ-TLS-006: every cryptographic operation of a handshake and of the
 * records after it is asked of the tls_crypto_t backend — hashing, HMAC,
 * HKDF, AEAD, key generation and agreement, signing, verifying, the chain
 * check, randomness — and what the backend returns is what goes on the
 * wire: the ServerHello's random and key share are the backend's */
TEST(itest_tls_006_cryptography_from_the_backend) {
  tls_config_t ccfg = cli_cert, scfg = srv_cert;
  tp_hello_t sh;
  const uint8_t *x;
  uint8_t buf[8];
  size_t xl;
  int i;
  ccfg.crypto = &counting;
  scfg.crypto = &counting;
  memset(asked, 0, sizeof(asked));
  pair(&ccfg, HOST, &scfg);
  ASSERT_TRUE(both_connected());
  ASSERT_EQ(tls_write(&ca, (const uint8_t *)"ping", 4), 4);
  join(&ca, &sa, 4096);
  ASSERT_EQ(tls_read(&sa, buf, sizeof(buf)), 4);
  for (i = 0; i < 14; i++)
    ASSERT_TRUE(asked[i] > 0);
  /* the server asked last: its random and its share are in its hello */
  ASSERT_TRUE(tp_parse_hello(s2c + 5, tp_get(s2c + 3, 2), 0, &sh));
  ASSERT_MEM_EQ(sh.random, last_random, 32);
  x = tp_ext(&sh, TP_EXT_KEY_SHARE, &xl);
  ASSERT_TRUE(x && xl == 4 + last_share_len);
  ASSERT_MEM_EQ(x + 4, last_share, last_share_len);
}

/* REQ-TLS-006, 037: when the backend cannot give random bytes, a key
 * pair or a signature, the handshake ends with internal_error — the
 * protocol code has nothing of its own to use instead; a client that
 * cannot build its ClientHello does not start */
TEST(itest_tls_006_backend_failure_ends_the_handshake) {
  static const int ops[3] = {13, 8, 10}; /* random, key pair, signature */
  tls_config_t scfg = srv_cert, ccfg = cli_cert;
  int i;
  scfg.crypto = &counting;
  ccfg.crypto = &counting;
  for (i = 0; i < 3; i++) {
    failing = -1;
    c2s_len = s2c_len = 0;
    tls_init(&ca, &cli_cert, ca_rx, sizeof(ca_rx), ca_tx, sizeof(ca_tx));
    tls_init(&sa, &scfg, sa_rx, sizeof(sa_rx), sa_tx, sizeof(sa_tx));
    tls_accept(&sa);
    tls_connect(&ca, HOST);
    failing = ops[i];
    join(&ca, &sa, 4096);
    failing = -1;
    ASSERT_EQ(tls_state(&sa), TLS_STATE_ERROR);
    ASSERT_EQ(sa.alert, 80);
    ASSERT_EQ(ca.alert, 80);
  }
  for (i = 0; i < 2; i++) {
    tls_init(&ca, &ccfg, ca_rx, sizeof(ca_rx), ca_tx, sizeof(ca_tx));
    failing = ops[i];
    ASSERT_EQ(tls_connect(&ca, HOST), -1);
    failing = -1;
    ASSERT_EQ(tls_state(&ca), TLS_STATE_IDLE);
  }
}

/* REQ-TLS-065: tls_release() ends a connection however far it got: both
 * buffers — which held plaintext — are zeroed, the connection is IDLE
 * with its configuration, buffers and callback, and the next handshake
 * runs on it */
TEST(itest_tls_065_release_wipes_and_readies) {
  size_t i;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  ASSERT_TRUE(feed_sealed(TP_APPDATA, "unread and private", 18));
  ASSERT_EQ(tls_write(&sut, (const uint8_t *)"unsent", 6), 6);
  tls_release(&sut);
  ASSERT_EQ(tls_state(&sut), TLS_STATE_IDLE);
  for (i = 0; i < sizeof(sut_rx); i++)
    ASSERT_EQ(sut_rx[i] | sut_tx[i], 0);
  ASSERT_EQ(drain(), 0);
  ASSERT_EQ(tls_write(&sut, (const uint8_t *)"x", 1), -1);

  out_len = out_off = 0;
  n_events = 0;
  ASSERT_EQ(tls_accept(&sut), 0);
  ASSERT_TRUE(send_client_hello(&ch_psk_ke));
  ASSERT_TRUE(read_server_hello(&ch_psk_ke));
  ASSERT_TRUE(server_flight(0, 0));
  ASSERT_TRUE(client_finished());
  ASSERT_EQ(tls_state(&sut), TLS_STATE_CONNECTED);
  ASSERT_EQ(n_events, 1); /* the callback is still the application's */
}

/* REQ-TLS-066: calls a connection's state does not allow return an error
 * and change nothing: reading and writing before the handshake is done,
 * a second tls_accept() or tls_connect(), a server without a certificate
 * and key or a complete PSK, a host name over 255 bytes, a ClientHello
 * that does not fit the transmit buffer.  tls_tx_done() takes no more
 * than was pending. */
TEST(itest_tls_066_calls_out_of_place_refused) {
  static char long_name[300];
  tls_config_t cfg = srv_cert;
  const uint8_t *p;
  uint8_t buf[8];
  ASSERT_TRUE(sut_start(&srv_psk));
  ASSERT_EQ(tls_write(&sut, (const uint8_t *)"x", 1), -1);
  ASSERT_EQ(tls_key_update(&sut, 0), -1);
  ASSERT_EQ(tls_close(&sut), -1);
  ASSERT_EQ(tls_read(&sut, buf, sizeof(buf)), 0);
  ASSERT_EQ(tls_accept(&sut), 0);
  ASSERT_EQ(tls_accept(&sut), -1);
  ASSERT_EQ(tls_connect(&sut, NULL), -1);
  ASSERT_EQ(tls_write(&sut, (const uint8_t *)"x", 1), -1);
  ASSERT_EQ(tls_key_update(&sut, 0), -1);
  ASSERT_EQ(tls_state(&sut), TLS_STATE_HANDSHAKE);
  ASSERT_EQ(drain(), 0);

  cfg.key = NULL; /* a chain without its key */
  ASSERT_TRUE(sut_start(&cfg));
  ASSERT_EQ(tls_accept(&sut), -1);
  cfg.cert_count = 0; /* nothing to authenticate with */
  ASSERT_TRUE(sut_start(&cfg));
  ASSERT_EQ(tls_accept(&sut), -1);
  ASSERT_EQ(tls_state(&sut), TLS_STATE_IDLE);

  memset(long_name, 'a', 256);
  ASSERT_TRUE(sut_start(&cli_cert));
  ASSERT_EQ(tls_connect(&sut, long_name), -1);
  long_name[200] = 0; /* 200 bytes of name: more than a 256-byte tx */
  tx_cap = 256;
  ASSERT_TRUE(sut_start(&cli_cert));
  ASSERT_EQ(tls_connect(&sut, long_name), -1);
  ASSERT_EQ(tls_state(&sut), TLS_STATE_IDLE);
  ASSERT_EQ(drain(), 0);

  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  ASSERT_EQ(tls_write(&sut, (const uint8_t *)"abc", 3), 3);
  tls_tx_done(&sut, 100000);
  ASSERT_EQ(tls_tx_pending(&sut, &p), 0);
  ASSERT_EQ(tls_write(&sut, (const uint8_t *)"abc", 3), 3);
  ASSERT_EQ(tls_tx_pending(&sut, &p), 3 + 22);
}

/* REQ-TLS-009: all of a connection's state is in its tls_conn_t and its
 * buffers.  Two servers and two clients, sharing one configuration, run
 * their handshakes a byte at a time in turn and keep their data apart;
 * and a connection copied to another tls_conn_t carries on from there,
 * the first one overwritten. */
TEST(itest_tls_009_state_in_the_connection) {
  static tls_conn_t c2, s2, moved;
  static uint8_t c2_rx[8192], c2_tx[4096], s2_rx[4096], s2_tx[4096];
  uint8_t buf[16];
  int i;
  c2s_len = s2c_len = 0;
  tls_init(&ca, &cli_cert, ca_rx, sizeof(ca_rx), ca_tx, sizeof(ca_tx));
  tls_init(&sa, &srv_cert, sa_rx, sizeof(sa_rx), sa_tx, sizeof(sa_tx));
  tls_init(&c2, &cli_cert, c2_rx, sizeof(c2_rx), c2_tx, sizeof(c2_tx));
  tls_init(&s2, &srv_cert, s2_rx, sizeof(s2_rx), s2_tx, sizeof(s2_tx));
  ASSERT_EQ(tls_accept(&sa), 0);
  ASSERT_EQ(tls_accept(&s2), 0);
  ASSERT_EQ(tls_connect(&ca, HOST), 0);
  ASSERT_EQ(tls_connect(&c2, HOST), 0);
  for (i = 0; i < 20000 &&
              !(both_connected() && tls_state(&c2) == TLS_STATE_CONNECTED &&
                tls_state(&s2) == TLS_STATE_CONNECTED);
       i++) {
    const uint8_t *p;
    tls_conn_t *from[4], *to[4];
    int k;
    from[0] = &ca, to[0] = &sa;
    from[1] = &c2, to[1] = &s2;
    from[2] = &sa, to[2] = &ca;
    from[3] = &s2, to[3] = &c2;
    for (k = 0; k < 4; k++)
      if (tls_tx_pending(from[k], &p) > 0) {
        (void)tls_input(to[k], p, 1);
        tls_tx_done(from[k], 1);
      }
  }
  ASSERT_TRUE(both_connected());
  ASSERT_EQ(tls_state(&c2), TLS_STATE_CONNECTED);
  ASSERT_EQ(tls_state(&s2), TLS_STATE_CONNECTED);
  ASSERT_EQ(tls_write(&ca, (const uint8_t *)"first", 5), 5);
  ASSERT_EQ(tls_write(&c2, (const uint8_t *)"second", 6), 6);
  join(&ca, &sa, 4096);
  join(&c2, &s2, 4096);
  ASSERT_EQ(tls_read(&sa, buf, sizeof(buf)), 5);
  ASSERT_MEM_EQ(buf, "first", 5);
  ASSERT_EQ(tls_read(&s2, buf, sizeof(buf)), 6);
  ASSERT_MEM_EQ(buf, "second", 6);

  moved = sa;
  memset(&sa, 0xFF, sizeof(sa));
  ASSERT_EQ(tls_write(&ca, (const uint8_t *)"again", 5), 5);
  join(&ca, &moved, 4096);
  ASSERT_EQ(tls_read(&moved, buf, sizeof(buf)), 5);
  ASSERT_MEM_EQ(buf, "again", 5);
  ASSERT_EQ(tls_write(&moved, (const uint8_t *)"back", 4), 4);
  join(&ca, &moved, 4096);
  ASSERT_EQ(tls_read(&ca, buf, sizeof(buf)), 4);
  ASSERT_MEM_EQ(buf, "back", 4);
}

/* ══ Over the stack's TCP (tls_tcp_carry) ═════════════════════════ */

/* REQ-TLS-018, 022, 026: the handshake over TCP on the wire — the
 * ClientHello arriving in 7-byte segments — and data echoed through the
 * connection */
TEST(itest_tls_018_handshake_over_tcp) {
  static uint8_t data[3000];
  uint8_t type;
  size_t i, total = 0;
  int n;
  over_tcp = 1;
  segment = 7;
  echoing = 1;
  ASSERT_TRUE(server_hello_from(&srv_psk, &ch_psk_dhe));
  segment = 1200;
  ASSERT_TRUE(server_flight(0, 0));
  ASSERT_TRUE(client_finished());
  ASSERT_EQ(tls_state(&sut), TLS_STATE_CONNECTED);
  for (i = 0; i < sizeof(data); i++)
    data[i] = (uint8_t)(i * 7);
  for (i = 0; i < sizeof(data); i += 1000)
    ASSERT_TRUE(feed_sealed(TP_APPDATA, data + i, 1000));
  drain();
  while (out_off < out_len) {
    ASSERT_TRUE((n = open_next(&type)) > 0 && type == TP_APPDATA);
    ASSERT_MEM_EQ(opened, data + total, (size_t)n);
    total += (size_t)n;
  }
  ASSERT_EQ(total, sizeof(data));
  over_tcp = echoing = 0;
}

/* REQ-TLS-035: closing over TCP — the peer's close_notify is answered
 * with the connection's own, and the TCP connection closes only when it
 * has been sent and acknowledged (tls_tcp_idle()): the close_notify
 * arrives before the FIN */
TEST(itest_tls_035_close_notify_before_fin) {
  static const uint8_t close_notify[2] = {1, 0};
  over_tcp = 1;
  ASSERT_TRUE(connect_to_server(&srv_psk, &ch_psk_ke));
  ASSERT_FALSE(cl.fin);
  ASSERT_TRUE(feed_sealed(TP_ALERT, close_notify, 2));
  ASSERT_TRUE(sealed_alert_sent(1, 0));
  ASSERT_TRUE(cl.fin);
  ASSERT_EQ(tls_state(&sut), TLS_STATE_CLOSED);
  over_tcp = 0;
}

int main(void) {
  fprintf(stderr, "=== itest_tls ===\n");
  if (tls_mbedtls_init(&backend, &crypto) != 0 ||
      tls_mbedtls_init(&backend_no_ca, &crypto_no_ca) != 0 ||
      tls_mbedtls_set_ca(&backend, (const uint8_t *)ca_pem, sizeof(ca_pem)) !=
          0 ||
      tls_mbedtls_parse_key(&backend, &ec_key, (const uint8_t *)server_key_pem,
                            sizeof(server_key_pem)) != 0 ||
      tls_mbedtls_parse_key(&backend, &rsa_key, (const uint8_t *)rsa_key_pem,
                            sizeof(rsa_key_pem)) != 0) {
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
  srv_both = srv_cert;
  srv_both.psk = psk;
  srv_both.psk_len = sizeof(psk);
  srv_both.psk_id = (const uint8_t *)PSK_ID;
  srv_both.psk_id_len = sizeof(PSK_ID) - 1;
  srv_both.psk_modes = TLS_PSK_KE | TLS_PSK_DHE_KE;
  cli_psk = srv_psk;
  cli_cert.crypto = &crypto;
  ch_psk_ke.psk_ke = 1;
  ch_psk_dhe.psk_dhe = 1;
  ch_psk_dhe.share = 1;
  sh_psk_ke.psk = 1;
  sh_psk_dhe.psk = sh_psk_dhe.share = 1;
  sh_cert.share = 1;
  counting = crypto;
  counting.hash_init = c_hash_init;
  counting.hash_update = c_hash_update;
  counting.hash_peek = c_hash_peek;
  counting.hmac = c_hmac;
  counting.hkdf_extract = c_extract;
  counting.hkdf_expand = c_expand;
  counting.aead_seal = c_seal;
  counting.aead_open = c_open;
  counting.kx_keygen = c_keygen;
  counting.kx_shared = c_shared;
  counting.sign = c_sign;
  counting.verify = c_verify;
  counting.verify_chain = c_chain;
  counting.random = c_random;

  RUN_TEST(itest_tls_018_server_flight_with_a_psk);
  RUN_TEST(itest_tls_022_client_finished_completes_the_handshake);
  RUN_TEST(itest_tls_022_wrong_client_finished_refused);
  RUN_TEST(itest_tls_004_psk_with_x25519);
  RUN_TEST(itest_tls_001_tls12_client_refused);
  RUN_TEST(itest_tls_037_alert_says_what_was_wrong);
  RUN_TEST(itest_tls_052_mandatory_extensions);
  RUN_TEST(itest_tls_052_groups_and_key_share_together);
  RUN_TEST(itest_tls_061_hello_retry_request_sent);
  RUN_TEST(itest_tls_046_hello_retry_in_compatibility_mode);
  RUN_TEST(itest_tls_022_only_finished_after_the_flight);
  RUN_TEST(itest_tls_025_psk_from_the_configuration);
  RUN_TEST(itest_tls_046_session_id_echoed);
  RUN_TEST(itest_tls_045_change_cipher_spec_only_in_the_handshake);
  RUN_TEST(itest_tls_031_max_fragment_length_granted);
  RUN_TEST(itest_tls_026_records_both_ways);
  RUN_TEST(itest_tls_030_record_that_fails_authentication);
  RUN_TEST(itest_tls_043_write_within_the_transmit_buffer);
  RUN_TEST(itest_tls_041_receive_buffer_holds_a_record);
  RUN_TEST(itest_tls_047_record_too_long_or_unknown);
  RUN_TEST(itest_tls_057_records_out_of_place);
  RUN_TEST(itest_tls_047_plaintext_too_long);
  RUN_TEST(itest_tls_059_padding_and_no_content_type);
  RUN_TEST(itest_tls_035_close_notify);
  RUN_TEST(itest_tls_036_fatal_alert_received);
  RUN_TEST(itest_tls_044_key_update_requested_by_the_peer);
  RUN_TEST(itest_tls_044_key_update_of_ours);
  RUN_TEST(itest_tls_044_key_update_malformed);
  RUN_TEST(itest_tls_044_key_update_waits_for_room);
  RUN_TEST(itest_tls_037_new_session_ticket);
  RUN_TEST(itest_tls_057_no_data_inside_a_handshake_message);
  RUN_TEST(itest_tls_010_client_hello);
  RUN_TEST(itest_tls_023_client_offers_the_psk);
  RUN_TEST(itest_tls_016_client_finished_after_the_servers);
  RUN_TEST(itest_tls_011_client_key_share_used);
  RUN_TEST(itest_tls_016_wrong_server_finished_refused);
  RUN_TEST(itest_tls_001_tls12_server_refused);
  RUN_TEST(itest_tls_024_no_certificate_after_a_psk);
  RUN_TEST(itest_tls_053_extension_not_offered_refused);
  RUN_TEST(itest_tls_053_encrypted_extension_not_offered_refused);
  RUN_TEST(itest_tls_060_psk_server_hello_consistent);
  RUN_TEST(itest_tls_037_server_hello_refusals);
  RUN_TEST(itest_tls_014_certificate_from_the_peer);
  RUN_TEST(itest_tls_067_certificate_request_answered_with_none);
  RUN_TEST(itest_tls_062_server_certificate_checked);
  RUN_TEST(itest_tls_046_session_id_echo_checked);
  RUN_TEST(itest_tls_049_hello_retry_request_answered);
  RUN_TEST(itest_tls_049_hello_retry_request_must_change_something);
  RUN_TEST(itest_tls_031_max_fragment_length_asked);
  RUN_TEST(itest_tls_039_client_told_of_close_and_alert);
  RUN_TEST(itest_tls_014_certificate_chain_and_name);
  RUN_TEST(itest_tls_015_certificate_verify_checked);
  RUN_TEST(itest_tls_020_flight_through_a_small_transmit_buffer);
  RUN_TEST(itest_tls_031_long_message_in_small_records);
  RUN_TEST(itest_tls_005_secp256r1);
  RUN_TEST(itest_tls_023_psk_between_our_roles);
  RUN_TEST(itest_tls_006_cryptography_from_the_backend);
  RUN_TEST(itest_tls_006_backend_failure_ends_the_handshake);
  RUN_TEST(itest_tls_065_release_wipes_and_readies);
  RUN_TEST(itest_tls_066_calls_out_of_place_refused);
  RUN_TEST(itest_tls_009_state_in_the_connection);
  RUN_TEST(itest_tls_018_handshake_over_tcp);
  RUN_TEST(itest_tls_035_close_notify_before_fin);

  tls_mbedtls_free(&backend);
  tls_mbedtls_free(&backend_no_ca);
  ITEST_REPORT();
  return test_failures;
}
