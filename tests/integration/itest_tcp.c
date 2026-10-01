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

/* ── More of RFC 9293, RFC 1122 and RFC 6298 (2026-10-01) ── */

/* A passive open completed: the peer at 1000 connected; our ISS */
static uint32_t established(void) {
  uint32_t iss = syn_received();
  segment(RPORT, 1001, iss + 1, TCPF_ACK);
  wire_clear(&t);
  return iss;
}

/* A segment from the peer with options @p opt (a multiple of 4 bytes),
 * flags, data */
static void segment_opts(uint32_t seq, uint32_t ack, uint8_t flags,
                         uint16_t window, uint16_t urg, const uint8_t *opt,
                         uint8_t olen, const void *data, uint16_t len) {
  static uint8_t buf[1600], f[1700];
  peer_ip_t ip = peer_ip(PEER_IP, t.net.ipv4_addr, 6);
  uint8_t hlen = (uint8_t)(20 + olen);
  uint16_t total = (uint16_t)(hlen + len), i;
  uint32_t sum = 0;
  memset(buf, 0, hlen);
  peer_put16(buf, RPORT);
  peer_put16(buf + 2, LPORT);
  peer_put32(buf + 4, seq);
  peer_put32(buf + 8, ack);
  buf[12] = (uint8_t)((hlen / 4u) << 4);
  buf[13] = flags;
  peer_put16(buf + 14, window);
  peer_put16(buf + 18, urg);
  if (olen)
    memcpy(buf + 20, opt, olen);
  if (len)
    memcpy(buf + hlen, data, len);
  /* the pseudo-header and the segment, the peer's own arithmetic */
  sum +=
      (ip.src >> 16) + (ip.src & 0xFFFF) + (ip.dst >> 16) + (ip.dst & 0xFFFF);
  sum += 6 + total;
  for (i = 0; i + 1u < total; i += 2)
    sum += peer_get16(buf + i);
  if (total & 1u)
    sum += (uint32_t)buf[total - 1] << 8;
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
  peer_put16(buf + 16, (uint16_t)~sum);
  itest_receive(&t, f,
                peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, buf, total));
}

/* The n-th TCP segment sent since the last wire_clear() */
static int nth_segment(int n, peer_ip_t *ip, peer_tcp_t *tcp) {
  int i = -1;
  do {
    i = wire_find_tcp(&t, (uint16_t)(i + 1), ip, tcp);
  } while (i >= 0 && n-- > 0);
  return i >= 0;
}

/* REQ-TCP-063 (deviation): URG and the urgent pointer are ignored; the
 * data arrives in line */
TEST(itest_tcp_063_urgent_data_in_line) {
  uint8_t buf[16];
  uint32_t iss;
  up();
  iss = established();
  segment_opts(1001, iss + 1, TCPF_ACK | 0x20 /* URG */, 4096, 3, NULL, 0,
               "abcdef", 6);
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 6);
  ASSERT_MEM_EQ(buf, "abcdef", 6);
}

/* REQ-TCP-156: a window with its top bit set is a large window */
TEST(itest_tcp_156_window_unsigned) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = established();
  segment_opts(1001, iss + 1, TCPF_ACK, 0xFFFF, 0, NULL, 0, NULL, 0);
  wire_clear(&t);
  ASSERT_TRUE(tcp_send(&t.net, &conn, (const uint8_t *)"hello", 5) == 5);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.data_len, 5);
}

/* REQ-TCP-157, 159: options in a data segment, and options not on a word
 * boundary (an MSS after one NOP), are taken */
TEST(itest_tcp_157_options_in_any_segment) {
  static const uint8_t nops[4] = {1, 1, 1, 1};
  static const uint8_t nop_mss[8] = {1, 2, 4, 0x02, 0x00, 1, 1, 0};
  uint8_t buf[16];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = established();
  segment_opts(1001, iss + 1, TCPF_ACK | TCPF_PSH, 4096, 0, nops, 4, "xy", 2);
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 2);

  up(); /* a SYN whose MSS (512) starts at an odd offset */
  tcp_listen(&conn, LPORT);
  segment_opts(1000, 0, TCPF_SYN, 4096, 0, nop_mss, 8, NULL, 0);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  iss = tcp.seq;
  segment_opts(1001, iss + 1, TCPF_ACK, 4096, 0, NULL, 0, NULL, 0);
  wire_clear(&t);
  {
    static uint8_t big[600];
    tcp_send(&t.net, &conn, big, sizeof(big));
  }
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_TRUE(tcp.data_len <= 512);
}

/* REQ-TCP-158: an option of length 0 harms nothing */
TEST(itest_tcp_158_illegal_option_length) {
  static const uint8_t bad[4] = {2, 0, 0, 0};
  up();
  tcp_listen(&conn, LPORT);
  segment_opts(1000, 0, TCPF_SYN, 4096, 0, bad, 4, NULL, 0);
  segment(RPORT + 1, 5000, 0, TCPF_SYN); /* the stack still works */
  ASSERT_TRUE(tcp_status(&conn) == TCP_SYN_RECEIVED);
}

/* REQ-TCP-160: with the receive window zero, a RST is still processed —
 * one carrying data too */
TEST(itest_tcp_160_rst_into_zero_window) {
  static uint8_t fill[512];
  uint32_t iss;
  up();
  iss = established();
  segment_opts(1001, iss + 1, TCPF_ACK, 4096, 0, NULL, 0, fill, sizeof(fill));
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED); /* our window is 0 now */
  segment_opts(1001 + 512, iss + 1, TCPF_RST | TCPF_ACK, 0, 0, NULL, 0, "z", 1);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_EQ(ev_reset, 1);
}

/* REQ-TCP-161: the application learns a normal close from an abort */
TEST(itest_tcp_161_closed_or_aborted) {
  uint32_t iss;
  up();
  iss = established();
  segment(RPORT, 1001, iss + 1, TCPF_FIN | TCPF_ACK);
  ASSERT_EQ(ev_closed, 1);
  ASSERT_EQ(ev_reset, 0);
  up();
  iss = established();
  segment(RPORT, 1001, iss + 1, TCPF_RST);
  ASSERT_EQ(ev_reset, 1);
  ASSERT_EQ(ev_closed, 0);
}

static int ev_soft;
static void count_soft(tcp_conn_t *c, uint8_t events) {
  on_event(c, events);
  ev_soft += (events & TCP_EVT_SOFT_ERROR) != 0;
}

/* REQ-TCP-162, 165, 173: R2 is the application's; R1 (3 retransmissions)
 * is reported as a soft error, R2 closes */
TEST(itest_tcp_162_r1_and_r2) {
  int expiries;
  up();
  conn.on_event = count_soft;
  ev_soft = 0;
  established();
  ASSERT_EQ(tcp_set_max_retransmits(&conn, 5), NET_OK);
  tcp_send(&t.net, &conn, (const uint8_t *)"lost", 4);
  for (expiries = 0; expiries < 6 && tcp_status(&conn) == TCP_ESTABLISHED;
       expiries++) {
    itest_advance(&t, 61000, 1000);
    if (expiries == 2)
      ASSERT_EQ(ev_soft, 1);
  }
  ASSERT_EQ(tcp_last_error(&conn), TCP_SOFT_RETRANSMITTING);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_EQ(ev_error, 1);
  ASSERT_EQ(expiries, 6);
}

/* REQ-TCP-163, 164: a SYN is retransmitted for at least 3 minutes, whatever
 * R2 is, and the application is told when it stops */
TEST(itest_tcp_164_syn_retransmitted_three_minutes) {
  uint32_t ms, last_syn = 0;
  up();
  tcp_set_max_retransmits(&conn, 2);
  tcp_connect(&t.net, &conn, PEER_IP, peer_mac, RPORT, LPORT);
  for (ms = 0; ms < 600000 && tcp_status(&conn) == TCP_SYN_SENT; ms += 100) {
    wire_clear(&t);
    itest_advance(&t, 100, 100);
    if (t.wire.tx_count)
      last_syn = ms + 100;
  }
  ASSERT_TRUE(last_syn >= 180000u);
  ASSERT_EQ(ev_error, 1);
}

/* REQ-TCP-166: a peer shrinking its window to zero does not upset sending */
TEST(itest_tcp_166_window_shrunk) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = established();
  tcp_send(&t.net, &conn, (const uint8_t *)"abcd", 4);
  segment_opts(1001, iss + 1, TCPF_ACK, 0, 0, NULL, 0, NULL, 0);
  segment_opts(1001, iss + 5, TCPF_ACK, 4096, 0, NULL, 0, NULL, 0);
  wire_clear(&t);
  ASSERT_EQ(tcp_send(&t.net, &conn, (const uint8_t *)"efgh", 4), 4);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.seq, iss + 5);
}

/* REQ-TCP-167: a zero window answered to every probe keeps the connection
 * open, however long */
TEST(itest_tcp_167_zero_window_kept_open) {
  uint32_t iss, s;
  up();
  iss = established();
  segment_opts(1001, iss + 1, TCPF_ACK, 0, 0, NULL, 0, NULL, 0);
  tcp_write(&conn, (const uint8_t *)"wait", 4);
  tcp_output(&t.net, &conn);
  for (s = 0; s < 1800; s++) {
    itest_advance(&t, 1000, 1000);
    segment_opts(1001, iss + 1, TCPF_ACK, 0, 0, NULL, 0, NULL, 0);
  }
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
}

/* REQ-TCP-168: LISTEN on a connection in use is refused and leaves it */
TEST(itest_tcp_168_listen_on_a_live_connection) {
  up();
  established();
  ASSERT_TRUE(tcp_listen(&conn, LPORT) != NET_OK);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
}

/* REQ-TCP-169: a listener on a port beside an active open from it */
TEST(itest_tcp_169_listen_beside_an_open) {
  static tcp_conn_t listener;
  static tcp_conn_t *two[2] = {&conn, &listener};
  static tcp_saw_tx_ctx_t tx2;
  static tcp_saw_rx_ctx_t rx2;
  static uint8_t txm[512], rxm[512];
  peer_ip_t ip;
  peer_tcp_t tcp;
  up();
  tcp_saw_tx_init(&tx2, txm, sizeof(txm));
  tcp_saw_rx_init(&rx2, rxm, sizeof(rxm));
  tcp_conn_init(&listener, &tcp_saw_tx_ops, &tx2, &tcp_saw_rx_ops, &rx2, NULL);
  tcp_set_connections(&t.net, two, 2);
  tcp_connect(&t.net, &conn, PEER_IP, peer_mac, RPORT, LPORT);
  ASSERT_EQ(tcp_listen(&listener, LPORT), NET_OK);
  wire_clear(&t);
  segment(RPORT + 7, 9000, 0, TCPF_SYN);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_SYN | TCPF_ACK);
  ASSERT_EQ(tcp_status(&listener), TCP_SYN_RECEIVED);
  ASSERT_EQ(tcp_status(&conn), TCP_SYN_SENT);
}

/* REQ-TCP-170: OPEN on our (one) IPv4 address */
TEST(itest_tcp_170_local_address) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  up();
  syn_received();
  segment(RPORT, 1001, 0, TCPF_RST);
  segment(RPORT, 1000, 0, TCPF_SYN);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(ip.src, t.net.ipv4_addr);
}

/* REQ-TCP-171: the connection keeps its local address; if the host's
 * address changes, the connection ends rather than continue from another */
TEST(itest_tcp_171_same_local_address) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  int i;
  up();
  established();
  t.net.ipv4_addr = 0x0A000009u; /* renumbered */
  tcp_send(&t.net, &conn, (const uint8_t *)"x", 1);
  for (i = 0; nth_segment(i, &ip, &tcp); i++)
    ASSERT_TRUE(ip.src != 0x0A000009u);
  ASSERT_TRUE(tcp_status(&conn) != TCP_ESTABLISHED);
}

/* REQ-TCP-172: no OPEN to a broadcast or multicast address */
TEST(itest_tcp_172_open_to_broadcast_refused) {
  up();
  ASSERT_TRUE(tcp_connect(&t.net, &conn, 0xFFFFFFFFu, broadcast_mac, RPORT,
                          LPORT) != NET_OK);
  ASSERT_TRUE(tcp_connect(&t.net, &conn, 0x0A0000FFu, broadcast_mac, RPORT,
                          LPORT) != NET_OK);
  ASSERT_TRUE(tcp_connect(&t.net, &conn, 0xE0000001u, peer_mac, RPORT, LPORT) !=
              NET_OK);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-TCP-174: the application sets the TOS of a connection's segments */
TEST(itest_tcp_174_tos) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  up();
  ASSERT_EQ(tcp_set_tos(&conn, 0xB8), NET_OK);
  tcp_connect(&t.net, &conn, PEER_IP, peer_mac, RPORT, LPORT);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(ip.tos, 0xB8);
}

/* REQ-TCP-176: a SYN to a broadcast address is dropped silently */
TEST(itest_tcp_176_syn_to_broadcast_dropped) {
  uint8_t f[128], s2[64];
  peer_ip_t ip;
  uint16_t n;
  up();
  tcp_listen(&conn, LPORT);
  ip = peer_ip(PEER_IP, 0x0A0000FFu, 6);
  memset(s2, 0, 20);
  peer_put16(s2, RPORT);
  peer_put16(s2 + 2, LPORT);
  s2[12] = 0x50;
  s2[13] = TCPF_SYN;
  n = 20;
  itest_receive(&t, f, peer_ipv4_frame(f, broadcast_mac, peer_mac, &ip, s2, n));
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(tcp_status(&conn), TCP_LISTEN);
}

/* REQ-TCP-177: a SYN from 0.0.0.0 is ignored */
TEST(itest_tcp_177_syn_from_unspecified_ignored) {
  uint8_t f[128];
  peer_tcp_seg_t sg;
  up();
  tcp_listen(&conn, LPORT);
  memset(&sg, 0, sizeof(sg));
  sg.sport = RPORT;
  sg.dport = LPORT;
  sg.seq = 1000;
  sg.flags = TCPF_SYN;
  sg.window = 4096;
  itest_receive(&t, f, peer_tcp_frame(f, &t.net, 0, &sg));
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(tcp_status(&conn), TCP_LISTEN);
}

/* REQ-TCP-179: no retransmission before the RTO (1 s at first) */
TEST(itest_tcp_179_retransmit_not_early) {
  up();
  syn_received(); /* our SYN,ACK went at time 0 */
  itest_advance(&t, 999, 1);
  ASSERT_EQ(t.wire.tx_count, 0);
  itest_advance(&t, 1, 1);
  ASSERT_EQ(t.wire.tx_count, 1);
}

/* REQ-TCP-180: the segment that empties the send buffer carries PSH, and
 * data written without tcp_output() is sent without waiting for an ACK */
TEST(itest_tcp_180_push_and_no_indefinite_buffering) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = established();
  tcp_send(&t.net, &conn, (const uint8_t *)"abc", 3);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_TRUE(tcp.flags & TCPF_PSH);
  segment(RPORT, 1001, iss + 4, TCPF_ACK);
  wire_clear(&t);
  tcp_write(&conn, (const uint8_t *)"def", 3);
  itest_advance(&t, 10, 10);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.data_len, 3);
}

/* REQ-TCP-181 (RFC 6298 5.7): after the SYN timed out, data starts with an
 * RTO of 3 s */
TEST(itest_tcp_181_rto_three_seconds_after_syn_timeout) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  tcp_connect(&t.net, &conn, PEER_IP, peer_mac, RPORT, LPORT);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  iss = tcp.seq;
  itest_advance(&t, 1000, 100); /* the SYN again: it timed out */
  segment(RPORT, 5000, iss + 1, TCPF_SYN | TCPF_ACK);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  tcp_send(&t.net, &conn, (const uint8_t *)"data", 4);
  wire_clear(&t);
  itest_advance(&t, 2999, 1);
  ASSERT_EQ(t.wire.tx_count, 0);
  itest_advance(&t, 1, 1);
  ASSERT_EQ(t.wire.tx_count, 1);
}

/* An ICMP error from @p from about the n-th segment we sent (its header
 * and first 8 octets quoted) */
static void icmp_about_sent(int n, uint32_t from, uint8_t type, uint8_t code,
                            const uint8_t rest[4], uint32_t seq_override) {
  uint8_t msg[128], quote[28], f[192];
  peer_ip_t ip, rip = peer_ip(from, t.net.ipv4_addr, 1);
  peer_tcp_t tcp;
  int i = -1;
  uint16_t len;
  do {
    i = wire_find_tcp(&t, (uint16_t)(i + 1), &ip, &tcp);
  } while (i >= 0 && n-- > 0);
  if (i < 0)
    return;
  memcpy(quote, wire_sent(&t, (uint16_t)i)->data + 14, 28);
  if (seq_override)
    peer_put32(quote + 24, seq_override);
  len = peer_icmp(msg, type, code, rest, quote, 28);
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &rip, msg, len));
}

/* REQ-TCP-135, REQ-ICMPv4-013: Port Unreachable for our SYN refuses the
 * connection */
TEST(itest_tcp_135_unreachable_in_syn_sent) {
  up();
  tcp_connect(&t.net, &conn, PEER_IP, peer_mac, RPORT, LPORT);
  icmp_about_sent(0, PEER_IP, 3, 3, NULL, 0);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_TRUE(ev_error + ev_reset == 1);
}

/* REQ-TCP-135, REQ-ICMPv4-016 (RFC 1191): Fragmentation Needed lowers the
 * segment size to the next-hop MTU, and the data goes again in pieces */
TEST(itest_tcp_135_fragmentation_needed_lowers_mss) {
  static uint8_t big[1400];
  static const uint8_t mtu_1000[4] = {0, 0, 0x03, 0xE8};
  static tcp_saw_tx_ctx_t btx;
  static uint8_t btx_mem[1460];
  peer_ip_t ip;
  peer_tcp_t tcp;
  up();
  tcp_saw_tx_init(&btx, btx_mem, sizeof(btx_mem));
  conn.txbuf_ctx = &btx;
  established();
  tcp_send(&t.net, &conn, big, sizeof(big));
  icmp_about_sent(0, 0x0A0000FEu, 3, 4, mtu_1000, 0);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  wire_clear(&t);
  itest_advance(&t, 3000, 100);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_TRUE(tcp.data_len > 0 && tcp.data_len <= 960);
}

/* REQ-TCP-136, 173, REQ-ICMPv4-024, 044: soft errors — Host Unreachable,
 * Time Exceeded — are reported and do not abort */
TEST(itest_tcp_136_soft_errors_do_not_abort) {
  up();
  conn.on_event = count_soft;
  ev_soft = 0;
  established();
  tcp_send(&t.net, &conn, (const uint8_t *)"x", 1);
  icmp_about_sent(0, 0x0A0000FEu, 3, 1, NULL, 0);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  ASSERT_EQ(ev_soft, 1);
  ASSERT_EQ(tcp_last_error(&conn), 0x0301);
  icmp_about_sent(0, 0x0A0000FEu, 11, 0, NULL, 0);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  ASSERT_EQ(tcp_last_error(&conn), 0x0B00);
}

/* REQ-TCP-137: hard errors (Protocol Unreachable) abort — but not one
 * quoting a sequence number we never sent */
TEST(itest_tcp_137_hard_errors_abort) {
  uint32_t iss;
  up();
  iss = established();
  tcp_send(&t.net, &conn, (const uint8_t *)"x", 1);
  icmp_about_sent(0, PEER_IP, 3, 2, NULL, iss + 900000u);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  icmp_about_sent(0, PEER_IP, 3, 2, NULL, 0);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_EQ(ev_error, 1);
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
  RUN_TEST(itest_tcp_063_urgent_data_in_line);
  RUN_TEST(itest_tcp_156_window_unsigned);
  RUN_TEST(itest_tcp_157_options_in_any_segment);
  RUN_TEST(itest_tcp_158_illegal_option_length);
  RUN_XFAIL(itest_tcp_160_rst_into_zero_window);
  RUN_TEST(itest_tcp_161_closed_or_aborted);
  RUN_XFAIL(itest_tcp_162_r1_and_r2);
  RUN_TEST(itest_tcp_164_syn_retransmitted_three_minutes);
  RUN_TEST(itest_tcp_166_window_shrunk);
  RUN_TEST(itest_tcp_167_zero_window_kept_open);
  RUN_XFAIL(itest_tcp_168_listen_on_a_live_connection);
  RUN_TEST(itest_tcp_169_listen_beside_an_open);
  RUN_TEST(itest_tcp_170_local_address);
  RUN_XFAIL(itest_tcp_171_same_local_address);
  RUN_XFAIL(itest_tcp_172_open_to_broadcast_refused);
  RUN_XFAIL(itest_tcp_174_tos);
  RUN_TEST(itest_tcp_176_syn_to_broadcast_dropped);
  RUN_XFAIL(itest_tcp_177_syn_from_unspecified_ignored);
  RUN_TEST(itest_tcp_179_retransmit_not_early);
  RUN_XFAIL(itest_tcp_180_push_and_no_indefinite_buffering);
  RUN_XFAIL(itest_tcp_181_rto_three_seconds_after_syn_timeout);
  RUN_XFAIL(itest_tcp_135_unreachable_in_syn_sent);
  RUN_XFAIL(itest_tcp_135_fragmentation_needed_lowers_mss);
  RUN_XFAIL(itest_tcp_136_soft_errors_do_not_abort);
  RUN_XFAIL(itest_tcp_137_hard_errors_abort);
  ITEST_REPORT();
  return test_failures;
}
