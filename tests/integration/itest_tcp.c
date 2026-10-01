/**
 * @file itest_tcp.c
 * @brief TCP, black box: the tcp_* API, segments on the wire, events.
 */

#include "itest.h"
#include "tcp.h"
#include "tcp_buf.h"
#include <string.h>

#define LPORT 80
#define RPORT 40000

static itest_t t;
static tcp_conn_t conn;
static tcp_conn_t *table[1] = {&conn};
static tcp_saw_tx_ctx_t tx_ctx;
static tcp_saw_rx_ctx_t rx_ctx;
static uint8_t tx_mem[512], rx_mem[512];
static int ev_connected, ev_reset, ev_error, ev_closed;

static void on_event(tcp_conn_t *c, uint8_t events) {
  (void)c;
  ev_connected += (events & TCP_EVT_CONNECTED) != 0;
  ev_reset += (events & TCP_EVT_RESET) != 0;
  ev_error += (events & TCP_EVT_ERROR) != 0;
  ev_closed += (events & TCP_EVT_CLOSED) != 0;
}

static void up(void) {
  itest_up(&t, 1514, 1514);
  tcp_saw_tx_init(&tx_ctx, tx_mem, sizeof(tx_mem));
  tcp_saw_rx_init(&rx_ctx, rx_mem, sizeof(rx_mem));
  tcp_conn_init(&conn, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops, &rx_ctx,
                on_event);
  tcp_set_connections(&t.net, table, 1);
  ev_connected = ev_reset = ev_error = ev_closed = 0;
}

/* A segment from the peer: @p flags at @p seq, acknowledging @p ack */
static void segment(uint16_t sport, uint32_t seq, uint32_t ack, uint8_t flags) {
  uint8_t f[128];
  peer_tcp_seg_t s;
  memset(&s, 0, sizeof(s));
  s.sport = sport;
  s.dport = LPORT;
  s.seq = seq;
  s.ack = ack;
  s.flags = flags;
  s.window = 4096;
  s.mss = (flags & TCPF_SYN) ? 1460 : 0;
  itest_receive(&t, f, peer_tcp_frame(f, &t.net, PEER_IP, &s));
}

/* LISTEN, a SYN from the peer at 1000: SYN-RECEIVED.  @return our ISS,
 * read from the SYN,ACK on the wire. */
static uint32_t syn_received(void) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  tcp_listen(&conn, LPORT);
  wire_clear(&t);
  segment(RPORT, 1000, 0, TCPF_SYN);
  if (wire_find_tcp(&t, 0, &ip, &tcp) < 0 || tcp.flags != (TCPF_SYN | TCPF_ACK))
    return 0;
  wire_clear(&t);
  return tcp.seq;
}

/* How many segments went out, and whether one was a RST */
static int sent_rst(void) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  int i = -1;
  while ((i = wire_find_tcp(&t, (uint16_t)(i + 1), &ip, &tcp)) >= 0) {
    if (tcp.flags & TCPF_RST)
      return 1;
  }
  return 0;
}

/* ── CLOSE before the connection is open (RFC 9293 §3.10.4) ── */

/* REQ-TCP-015: a listener closed is CLOSED; a SYN then draws a RST */
TEST(itest_tcp_015_close_in_listen) {
  up();
  tcp_listen(&conn, LPORT);
  ASSERT_EQ(tcp_close(&t.net, &conn), NET_OK);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_EQ(t.wire.tx_count, 0);
  segment(RPORT, 1000, 0, TCPF_SYN);
  ASSERT_TRUE(sent_rst()); /* REQ-TCP-072 */
}

/* REQ-TCP-015: an active open closed in SYN-SENT goes quietly */
TEST(itest_tcp_015_close_in_syn_sent) {
  up();
  tcp_connect(&t.net, &conn, PEER_IP, peer_mac, RPORT, LPORT);
  wire_clear(&t);
  ASSERT_EQ(tcp_close(&t.net, &conn), NET_OK);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  itest_advance(&t, 60000, 100); /* nothing retransmitted */
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-TCP-015: in SYN-RECEIVED the FIN follows the ACK of our SYN */
TEST(itest_tcp_015_close_in_syn_received) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = syn_received();
  ASSERT_EQ(tcp_close(&t.net, &conn), NET_OK);
  ASSERT_EQ(t.wire.tx_count, 0);
  segment(RPORT, 1001, iss + 1, TCPF_ACK);
  ASSERT_TRUE(wire_find_tcp(&t, 0, &ip, &tcp) >= 0);
  ASSERT_EQ(tcp.flags, TCPF_FIN | TCPF_ACK);
  ASSERT_EQ(tcp.seq, iss + 1);
  ASSERT_EQ(tcp_status(&conn), TCP_FIN_WAIT_1);
  ASSERT_EQ(ev_connected, 0);
  segment(RPORT, 1001, iss + 2, TCPF_ACK);
  ASSERT_EQ(tcp_status(&conn), TCP_FIN_WAIT_2);
}

/* ── A passive open that fails listens again (§3.10.7.4) ── */

/* REQ-TCP-046: RST in SYN-RECEIVED → LISTEN, the application none the
 * wiser; the next SYN is answered */
TEST(itest_tcp_046_rst_in_syn_received_listens_again) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  up();
  syn_received();
  segment(RPORT, 1001, 0, TCPF_RST);
  ASSERT_EQ(tcp_status(&conn), TCP_LISTEN);
  ASSERT_EQ(ev_reset + ev_error + ev_closed, 0);
  ASSERT_EQ(t.wire.tx_count, 0);
  segment(RPORT + 1, 7000, 0, TCPF_SYN);
  ASSERT_TRUE(wire_find_tcp(&t, 0, &ip, &tcp) >= 0);
  ASSERT_EQ(tcp.flags, TCPF_SYN | TCPF_ACK);
  ASSERT_EQ(tcp.dport, RPORT + 1);
  ASSERT_EQ(tcp.ack, 7001u);
}

/* REQ-TCP-046: an active (simultaneous) open reset in SYN-RECEIVED is
 * refused */
TEST(itest_tcp_046_rst_in_active_syn_received_closes) {
  uint8_t f[128];
  peer_tcp_seg_t s;
  up();
  tcp_connect(&t.net, &conn, PEER_IP, peer_mac, RPORT, LPORT);
  memset(&s, 0, sizeof(s));
  s.sport = RPORT; /* the peer's SYN crosses ours */
  s.dport = LPORT;
  s.seq = 5000;
  s.flags = TCPF_SYN;
  s.window = 4096;
  itest_receive(&t, f, peer_tcp_frame(f, &t.net, PEER_IP, &s));
  ASSERT_EQ(tcp_status(&conn), TCP_SYN_RECEIVED);
  s.seq = 5001;
  s.flags = TCPF_RST;
  itest_receive(&t, f, peer_tcp_frame(f, &t.net, PEER_IP, &s));
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_EQ(ev_reset, 1);
}

/* REQ-TCP-051: a SYN in the window of a passive SYN-RECEIVED → LISTEN,
 * without a RST */
TEST(itest_tcp_051_syn_in_syn_received_listens_again) {
  up();
  syn_received();
  segment(RPORT, 1001, 0, TCPF_SYN);
  ASSERT_EQ(tcp_status(&conn), TCP_LISTEN);
  ASSERT_FALSE(sent_rst());
  ASSERT_EQ(ev_error, 0);
}

/* REQ-TCP-090: a SYN,ACK never acknowledged leaves the listener listening */
TEST(itest_tcp_090_syn_received_given_up_listens_again) {
  up();
  syn_received();
  itest_advance(&t, 600000, 100);
  ASSERT_EQ(tcp_status(&conn), TCP_LISTEN);
  ASSERT_EQ(ev_error + ev_reset, 0);
}

/* ── ABORT (RFC 9293 §3.10.5) ── */

/* REQ-TCP-016: no RST from LISTEN — to the last peer — nor SYN-SENT */
TEST(itest_tcp_016_abort_before_open_sends_nothing) {
  up();
  syn_received();
  segment(RPORT, 1001, 0, TCPF_RST); /* LISTEN again, a MAC known */
  ASSERT_EQ(tcp_abort(&t.net, &conn), NET_OK);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(ev_reset, 1);

  up();
  tcp_connect(&t.net, &conn, PEER_IP, peer_mac, RPORT, LPORT);
  wire_clear(&t);
  tcp_abort(&t.net, &conn);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-TCP-016: where the peer holds the connection open, a RST */
TEST(itest_tcp_016_abort_in_syn_received_sends_rst) {
  up();
  syn_received();
  tcp_abort(&t.net, &conn);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_TRUE(sent_rst());
}

/* ── Initial sequence numbers (RFC 6528) ── */

/* Our ISS answering the same SYN after seeding with @p seed */
static uint32_t iss_after_seed(const uint8_t *seed, uint16_t len) {
  up();
  if (seed)
    net_random_seed(&t.net, seed, len);
  return syn_received();
}

/* REQ-TCP-028, 153: the ISS depends on the secret, and every byte of the
 * seed reaches the secret — 8 bytes or more fill the 64-bit key */
TEST(itest_tcp_153_iss_depends_on_every_seed_byte) {
  uint8_t seed[16];
  uint32_t base;
  unsigned i;
  memset(seed, 0x5A, sizeof(seed));
  base = iss_after_seed(seed, sizeof(seed));
  ASSERT_TRUE(base != iss_after_seed(NULL, 0));
  for (i = 0; i < sizeof(seed); i++) {
    seed[i] ^= 1u;
    ASSERT_TRUE(iss_after_seed(seed, sizeof(seed)) != base);
    seed[i] ^= 1u;
  }
}

int main(void) {
  fprintf(stderr, "=== itest_tcp ===\n");
  RUN_TEST(itest_tcp_015_close_in_listen);
  RUN_TEST(itest_tcp_015_close_in_syn_sent);
  RUN_TEST(itest_tcp_015_close_in_syn_received);
  RUN_TEST(itest_tcp_046_rst_in_syn_received_listens_again);
  RUN_TEST(itest_tcp_046_rst_in_active_syn_received_closes);
  RUN_TEST(itest_tcp_051_syn_in_syn_received_listens_again);
  RUN_TEST(itest_tcp_090_syn_received_given_up_listens_again);
  RUN_TEST(itest_tcp_016_abort_before_open_sends_nothing);
  RUN_TEST(itest_tcp_016_abort_in_syn_received_sends_rst);
  RUN_TEST(itest_tcp_153_iss_depends_on_every_seed_byte);
  ITEST_REPORT();
  return test_failures;
}
