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
static int ev_connected, ev_reset, ev_error, ev_closed, ev_data, ev_writable;

static void on_event(tcp_conn_t *c, uint8_t events) {
  (void)c;
  ev_connected += (events & TCP_EVT_CONNECTED) != 0;
  ev_reset += (events & TCP_EVT_RESET) != 0;
  ev_error += (events & TCP_EVT_ERROR) != 0;
  ev_closed += (events & TCP_EVT_CLOSED) != 0;
  ev_data += (events & TCP_EVT_DATA) != 0;
  ev_writable += (events & TCP_EVT_WRITABLE) != 0;
}

static void no_events(void) {
  ev_connected = ev_reset = ev_error = ev_closed = ev_data = ev_writable = 0;
}

/* The stack with frame buffers of @p rx_frame and @p tx_frame bytes, and
 * one connection whose TX buffer holds @p tx_size bytes (at most 1460) */
static void up_sized(uint16_t rx_frame, uint16_t tx_frame, uint16_t tx_size) {
  static uint8_t big_tx_mem[1460];
  itest_up(&t, rx_frame, tx_frame);
  if (tx_size > sizeof(tx_mem))
    tcp_saw_tx_init(&tx_ctx, big_tx_mem, tx_size);
  else
    tcp_saw_tx_init(&tx_ctx, tx_mem, tx_size);
  tcp_saw_rx_init(&rx_ctx, rx_mem, sizeof(rx_mem));
  tcp_conn_init(&conn, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops, &rx_ctx,
                on_event);
  tcp_set_connections(&t.net, table, 1);
  no_events();
}

static void up(void) { up_sized(1514, 1514, sizeof(tx_mem)); }

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

/* ── More of RFC 9293, RFC 1122 and RFC 6298 ── */

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

/* REQ-IPv4-063, 064, REQ-TCP-077: with a 576-byte MTU the MSS we announce
 * and the segments we send fit it */
TEST(itest_tcp_077_mtu_bounds_segments) {
  static uint8_t big[1400];
  static tcp_saw_tx_ctx_t btx;
  static uint8_t btx_mem[1460];
  peer_ip_t ip;
  peer_tcp_t tcp;
  up();
  t.net.mtu = 576;
  tcp_saw_tx_init(&btx, btx_mem, sizeof(btx_mem));
  conn.txbuf_ctx = &btx;
  tcp_listen(&conn, LPORT);
  wire_clear(&t);
  segment(RPORT, 1000, 0, TCPF_SYN);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.mss, 536);
  segment(RPORT, 1001, tcp.seq + 1, TCPF_ACK);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  wire_clear(&t);
  ASSERT_EQ(tcp_send(&t.net, &conn, big, sizeof(big)), (int)sizeof(big));
  itest_advance(&t, 200, 100);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.data_len, 536);
  ASSERT_TRUE(ip.total_len <= 576);
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
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t ms;
  int resent = 0, soft_at = 0;
  up();
  conn.on_event = count_soft;
  ev_soft = 0;
  established();
  ASSERT_EQ(tcp_set_max_retransmits(&conn, 0), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(tcp_set_max_retransmits(&conn, 5), NET_OK);
  tcp_send(&t.net, &conn, (const uint8_t *)"lost", 4);
  for (ms = 0; ms < 600000 && tcp_status(&conn) == TCP_ESTABLISHED; ms += 100) {
    wire_clear(&t);
    itest_advance(&t, 100, 100);
    if (nth_segment(0, &ip, &tcp) && tcp.data_len == 4)
      resent++;
    if (ev_soft && !soft_at)
      soft_at = resent;
  }
  ASSERT_EQ(soft_at, 3); /* R1: reported with the third retransmission */
  ASSERT_EQ(ev_soft, 1);
  ASSERT_EQ(tcp_last_error(&conn), TCP_SOFT_RETRANSMITTING);
  ASSERT_EQ(resent, 5); /* R2 */
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_EQ(ev_error, 1);
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

#if NET_USE_IPV6
/* REQ-TCP-170, 172: over IPv6 OPEN takes a local address — one of ours —
 * and no multicast remote */
TEST(itest_tcp_170_local_address_ipv6) {
  static const uint8_t global[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                     0,    0,    0,    0,    0, 0, 0, 0x0a};
  static const uint8_t not_ours[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                       0,    0,    0,    0,    0, 0, 0, 0x0c};
  static const uint8_t remote[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                     0,    0,    0, 0, 0, 0, 0, 0x99};
  static const uint8_t group[16] = {0xff, 0x02, 0, 0, 0, 0, 0, 0,
                                    0,    0,    0, 0, 0, 0, 0, 0xfb};
  const uint8_t *src_for, *f;
  up();
  ipv6_start(&t.net);
  ASSERT_EQ(ipv6_addr_add(&t.net, global, 0xFFFFFFFFu, 0xFFFFFFFFu), NET_OK);
  itest_advance(&t, 3000, 100);           /* past Duplicate Address Detection */
  src_for = ipv6_src_for(&t.net, remote); /* link-local, by default */
  ASSERT_TRUE(src_for != NULL && memcmp(src_for, global, 16) != 0);
  ASSERT_EQ(tcp6_connect_from(&t.net, &conn, not_ours, remote, peer_mac, RPORT,
                              LPORT),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(
      tcp6_connect_from(&t.net, &conn, global, group, peer_mac, RPORT, LPORT),
      NET_ERR_INVALID_PARAM);
  wire_clear(&t);
  ASSERT_EQ(
      tcp6_connect_from(&t.net, &conn, global, remote, peer_mac, RPORT, LPORT),
      NET_OK);
  ASSERT_EQ(t.wire.tx_count, 1);
  f = wire_sent(&t, 0)->data;
  ASSERT_EQ(peer_get16(f + 12), 0x86DD); /* IPv6 */
  ASSERT_EQ(f[14 + 6], 6);               /* TCP */
  ASSERT_MEM_EQ(f + 14 + 8, global, 16); /* from the address chosen */
  ASSERT_MEM_EQ(f + 14 + 24, remote, 16);
  ASSERT_EQ(f[54 + 13], TCPF_SYN);
}
#endif

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

/* REQ-TCP-179, 092: no retransmission before the RTO (1 s at first) */
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
  uint32_t iss;
  uint16_t i;
  up();
  for (i = 0; i < sizeof(big); i++)
    big[i] = (uint8_t)i;
  tcp_saw_tx_init(&btx, btx_mem, sizeof(btx_mem));
  conn.txbuf_ctx = &btx;
  iss = established();
  tcp_send(&t.net, &conn, big, sizeof(big));
  icmp_about_sent(0, 0x0A0000FEu, 3, 4, mtu_1000, 0);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  wire_clear(&t);
  itest_advance(&t, 3000, 100);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.seq, iss + 1);
  ASSERT_EQ(tcp.data_len, 960);
  ASSERT_TRUE(ip.total_len <= 1000);
  /* the rest follows where the piece ended */
  wire_clear(&t);
  segment(RPORT, 1001, iss + 1 + 960, TCPF_ACK);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.seq, iss + 1 + 960);
  ASSERT_EQ(tcp.data_len, 440);
  ASSERT_MEM_EQ(tcp.data, big + 960, 440);
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

/* ── Helpers for the tests of the state machine ── */

/* A segment built by hand: any source, options, checksum, data offset */
typedef struct {
  uint32_t src; /* the peer's address */
  uint16_t sport, dport;
  uint32_t seq, ack;
  uint8_t flags;
  uint16_t window;
  const uint8_t *opt; /* TCP options, a multiple of 4 bytes */
  uint8_t olen;
  const void *data;
  uint16_t len;
  uint16_t cksum_xor;    /* not 0: a wrong checksum */
  uint32_t pseudo_src;   /* not 0: the checksum as if sent from here */
  uint8_t doff;          /* not 0: this data offset, in words */
  const uint8_t *ip_opt; /* IP options, a multiple of 4 bytes */
  uint8_t ip_olen;
} raw_seg_t;

/* From the peer's port to ours, window 4096 */
static raw_seg_t raw(uint32_t seq, uint32_t ack, uint8_t flags) {
  raw_seg_t r;
  memset(&r, 0, sizeof(r));
  r.src = PEER_IP;
  r.sport = RPORT;
  r.dport = LPORT;
  r.seq = seq;
  r.ack = ack;
  r.flags = flags;
  r.window = 4096;
  return r;
}

static void deliver_raw(const raw_seg_t *r) {
  static uint8_t buf[1600], f[1700];
  peer_ip_t ip = peer_ip(r->src, t.net.ipv4_addr, 6);
  uint8_t hlen = (uint8_t)(20 + r->olen);
  uint16_t total = (uint16_t)(hlen + r->len), i;
  uint32_t from = r->pseudo_src ? r->pseudo_src : ip.src;
  uint32_t sum = 0;
  memset(buf, 0, hlen);
  peer_put16(buf, r->sport);
  peer_put16(buf + 2, r->dport);
  peer_put32(buf + 4, r->seq);
  peer_put32(buf + 8, r->ack);
  buf[12] = (uint8_t)((r->doff ? r->doff : hlen / 4u) << 4);
  buf[13] = r->flags;
  peer_put16(buf + 14, r->window);
  if (r->olen)
    memcpy(buf + 20, r->opt, r->olen);
  if (r->len)
    memcpy(buf + hlen, r->data, r->len);
  sum += (from >> 16) + (from & 0xFFFF) + (ip.dst >> 16) + (ip.dst & 0xFFFF);
  sum += 6 + total;
  for (i = 0; i + 1u < total; i += 2)
    sum += peer_get16(buf + i);
  if (total & 1u)
    sum += (uint32_t)buf[total - 1] << 8;
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
  peer_put16(buf + 16, (uint16_t)(~sum ^ r->cksum_xor));
  ip.options = r->ip_opt;
  ip.options_len = r->ip_olen;
  itest_receive(&t, f,
                peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, buf, total));
}

/* Data from the peer at @p seq, acknowledging @p ack */
static void peer_data(uint32_t seq, uint32_t ack, const void *d, uint16_t len) {
  segment_opts(seq, ack, TCPF_ACK | TCPF_PSH, 4096, 0, NULL, 0, d, len);
}

/* The last TCP segment sent since the last wire_clear() */
static int last_segment(peer_ip_t *ip, peer_tcp_t *tcp) {
  peer_ip_t i2;
  peer_tcp_t t2;
  int i = -1, found = 0;
  while ((i = wire_find_tcp(&t, (uint16_t)(i + 1), &i2, &t2)) >= 0) {
    *ip = i2;
    *tcp = t2;
    found = 1;
  }
  return found;
}

/* The data offset, in words, of the n-th TCP segment sent */
static int data_offset(int n) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  int i = -1;
  do {
    i = wire_find_tcp(&t, (uint16_t)(i + 1), &ip, &tcp);
  } while (i >= 0 && n-- > 0);
  return i < 0 ? -1 : ip.payload[12] >> 4;
}

/* The connection, opened by the peer at 1000, brought to @p s; our ISS.
 * The peer's next sequence number is 1001, or 1002 once it has sent its
 * FIN (CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT); our FIN, where we have
 * sent one, is at ISS + 1 */
static uint32_t in_state(tcp_state_t s) {
  uint32_t iss = established();
  switch (s) {
  case TCP_FIN_WAIT_1:
    tcp_close(&t.net, &conn);
    break;
  case TCP_FIN_WAIT_2:
    tcp_close(&t.net, &conn);
    segment(RPORT, 1001, iss + 2, TCPF_ACK);
    break;
  case TCP_CLOSE_WAIT:
    segment(RPORT, 1001, iss + 1, TCPF_FIN | TCPF_ACK);
    break;
  case TCP_LAST_ACK:
    segment(RPORT, 1001, iss + 1, TCPF_FIN | TCPF_ACK);
    tcp_close(&t.net, &conn);
    break;
  case TCP_CLOSING:
    tcp_close(&t.net, &conn);
    segment(RPORT, 1001, iss + 1, TCPF_FIN | TCPF_ACK);
    break;
  case TCP_TIME_WAIT:
    tcp_close(&t.net, &conn);
    segment(RPORT, 1001, iss + 2, TCPF_FIN | TCPF_ACK);
    break;
  default:
    break;
  }
  wire_clear(&t);
  no_events();
  return iss;
}

/* ── Opening and closing (RFC 9293 §3.5, §3.6) ── */

/* REQ-TCP-001, 002, 010, 012, 032..035, 054, 076: passive open — the
 * application's connection listens; a SYN is answered with SYN,ACK (our
 * ISS, the peer's SYN acknowledged, our MSS) to where it came from; the
 * ACK of our SYN establishes */
TEST(itest_tcp_002_passive_open) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_EQ(tcp_listen(&conn, LPORT), NET_OK);
  ASSERT_EQ(tcp_status(&conn), TCP_LISTEN);
  ASSERT_EQ(t.wire.tx_count, 0);
  segment(RPORT, 1000, 0, TCPF_SYN);
  ASSERT_EQ(tcp_status(&conn), TCP_SYN_RECEIVED);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_SYN | TCPF_ACK);
  ASSERT_EQ(tcp.ack, 1001u); /* RCV.NXT = IRS + 1 */
  ASSERT_EQ(tcp.sport, LPORT);
  ASSERT_EQ(tcp.dport, RPORT);
  ASSERT_EQ(ip.src, t.net.ipv4_addr);
  ASSERT_EQ(ip.dst, PEER_IP);
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, peer_mac, 6);
  ASSERT_EQ(tcp.mss, 1460);
  iss = tcp.seq;
  ASSERT_EQ(ev_connected, 0);
  segment(RPORT, 1001, iss + 1, TCPF_ACK);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  ASSERT_EQ(ev_connected, 1);
  ASSERT_EQ(t.wire.tx_count, 1); /* the ACK needs no answer */
  tcp_send(&t.net, &conn, (const uint8_t *)"x", 1);
  ASSERT_TRUE(nth_segment(1, &ip, &tcp));
  ASSERT_EQ(tcp.seq, iss + 1); /* the SYN took ISS */
}

/* REQ-TCP-001, 003, 013, 038: active open — a SYN with our MSS, SYN-SENT; the
 * peer's SYN,ACK is acknowledged and establishes */
TEST(itest_tcp_003_active_open) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  ASSERT_EQ(tcp_connect(&t.net, &conn, PEER_IP, peer_mac, RPORT, LPORT),
            NET_OK);
  ASSERT_EQ(tcp_status(&conn), TCP_SYN_SENT);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_SYN);
  ASSERT_EQ(tcp.sport, LPORT);
  ASSERT_EQ(tcp.dport, RPORT);
  ASSERT_EQ(ip.dst, PEER_IP);
  ASSERT_EQ(tcp.mss, 1460);
  iss = tcp.seq;
  segment(RPORT, 5000, iss + 1, TCPF_SYN | TCPF_ACK);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  ASSERT_EQ(ev_connected, 1);
  ASSERT_TRUE(nth_segment(1, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_ACK);
  ASSERT_EQ(tcp.seq, iss + 1);
  ASSERT_EQ(tcp.ack, 5001u);
}

/* REQ-TCP-004, 039: simultaneous open — the peer's SYN crosses ours:
 * SYN-RECEIVED, our SYN again with its ACK, and the peer's ACK of our SYN
 * establishes */
TEST(itest_tcp_004_simultaneous_open) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  tcp_connect(&t.net, &conn, PEER_IP, peer_mac, RPORT, LPORT);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  iss = tcp.seq;
  segment(RPORT, 5000, 0, TCPF_SYN);
  ASSERT_EQ(tcp_status(&conn), TCP_SYN_RECEIVED);
  ASSERT_TRUE(nth_segment(1, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_SYN | TCPF_ACK);
  ASSERT_EQ(tcp.seq, iss);
  ASSERT_EQ(tcp.ack, 5001u);
  ASSERT_EQ(ev_connected, 0);
  /* the peer's own SYN,ACK, then its ACK of ours */
  segment(RPORT, 5000, iss + 1, TCPF_SYN | TCPF_ACK);
  ASSERT_FALSE(sent_rst());
  segment(RPORT, 5001, iss + 1, TCPF_ACK);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  ASSERT_EQ(ev_connected, 1);
}

/* REQ-TCP-001, 005, 008, 009, 015, 059, 060, 064, 071: we close first — FIN,
 * FIN-WAIT-1; its ACK, FIN-WAIT-2, where data still arrives; the peer's FIN,
 * TIME-WAIT, which lasts 2 × MSL (MSL 2 minutes) and ends in CLOSED */
TEST(itest_tcp_005_active_close) {
  uint8_t buf[8];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = established();
  ASSERT_EQ(tcp_close(&t.net, &conn), NET_OK);
  ASSERT_EQ(tcp_status(&conn), TCP_FIN_WAIT_1);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_FIN | TCPF_ACK);
  ASSERT_EQ(tcp.seq, iss + 1);
  ASSERT_EQ(tcp.ack, 1001u);
  segment(RPORT, 1001, iss + 1, TCPF_ACK); /* not of our FIN */
  ASSERT_EQ(tcp_status(&conn), TCP_FIN_WAIT_1);
  segment(RPORT, 1001, iss + 2, TCPF_ACK);
  ASSERT_EQ(tcp_status(&conn), TCP_FIN_WAIT_2);
  peer_data(1001, iss + 2, "late", 4);
  ASSERT_EQ(tcp_status(&conn), TCP_FIN_WAIT_2);
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 4);
  wire_clear(&t);
  segment(RPORT, 1005, iss + 2, TCPF_FIN | TCPF_ACK);
  ASSERT_EQ(tcp_status(&conn), TCP_TIME_WAIT);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_ACK);
  ASSERT_EQ(tcp.ack, 1006u);
  ASSERT_EQ(ev_closed, 0);
  ASSERT_EQ(NET_DEFAULT_TCP_MSL_MS, 120000);
  itest_advance(&t, 2u * NET_DEFAULT_TCP_MSL_MS - 100u, 100);
  ASSERT_EQ(tcp_status(&conn), TCP_TIME_WAIT);
  itest_advance(&t, 100, 100);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_EQ(ev_closed, 1);
}

/* REQ-TCP-001, 006, 015, 062, 068, 069: the peer closes first — its FIN is
 * acknowledged, CLOSE-WAIT, where we still send; our close, LAST-ACK; the
 * ACK of our FIN, CLOSED */
TEST(itest_tcp_006_passive_close) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = established();
  segment(RPORT, 1001, iss + 1, TCPF_FIN | TCPF_ACK);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSE_WAIT);
  ASSERT_EQ(ev_closed, 1);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_ACK);
  ASSERT_EQ(tcp.ack, 1002u); /* RCV.NXT is past the FIN */
  wire_clear(&t);
  ASSERT_EQ(tcp_send(&t.net, &conn, (const uint8_t *)"bye", 3), 3);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.data_len, 3);
  segment(RPORT, 1002, iss + 4, TCPF_ACK);
  wire_clear(&t);
  ASSERT_EQ(tcp_close(&t.net, &conn), NET_OK);
  ASSERT_EQ(tcp_status(&conn), TCP_LAST_ACK);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_FIN | TCPF_ACK);
  ASSERT_EQ(tcp.seq, iss + 4);
  segment(RPORT, 1002, iss + 4, TCPF_ACK); /* not of our FIN */
  ASSERT_EQ(tcp_status(&conn), TCP_LAST_ACK);
  segment(RPORT, 1002, iss + 5, TCPF_ACK);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_EQ(ev_closed, 2);
}

/* REQ-TCP-001, 007, 061, 070: both close at once — the peer's FIN in
 * FIN-WAIT-1 without the ACK of ours, CLOSING, then that ACK, TIME-WAIT; a
 * FIN that acknowledges ours goes straight to TIME-WAIT */
TEST(itest_tcp_007_simultaneous_close) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = in_state(TCP_FIN_WAIT_1);
  segment(RPORT, 1001, iss + 1, TCPF_FIN | TCPF_ACK);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSING);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 1002u);
  segment(RPORT, 1002, iss + 1, TCPF_ACK); /* not of our FIN */
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSING);
  segment(RPORT, 1002, iss + 2, TCPF_ACK);
  ASSERT_EQ(tcp_status(&conn), TCP_TIME_WAIT);

  up();
  iss = in_state(TCP_FIN_WAIT_1);
  segment(RPORT, 1001, iss + 2, TCPF_FIN | TCPF_ACK);
  ASSERT_EQ(tcp_status(&conn), TCP_TIME_WAIT);
}

/* REQ-TCP-011, 012, 013, 017: tcp_conn_init() refuses a connection
 * without buffers and leaves a good one CLOSED; the opens refuse port 0;
 * tcp_status() of no connection is CLOSED */
TEST(itest_tcp_011_conn_init_validates) {
  up();
  ASSERT_EQ(tcp_conn_init(NULL, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops,
                          &rx_ctx, NULL),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(tcp_conn_init(&conn, NULL, &tx_ctx, &tcp_saw_rx_ops, &rx_ctx, NULL),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(tcp_conn_init(&conn, &tcp_saw_tx_ops, NULL, &tcp_saw_rx_ops,
                          &rx_ctx, NULL),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(tcp_conn_init(&conn, &tcp_saw_tx_ops, &tx_ctx, NULL, &rx_ctx, NULL),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(tcp_conn_init(&conn, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops,
                          NULL, NULL),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(tcp_conn_init(&conn, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops,
                          &rx_ctx, NULL),
            NET_OK);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_EQ(tcp_status(NULL), TCP_CLOSED);
  ASSERT_EQ(tcp_listen(&conn, 0), NET_ERR_INVALID_PARAM);
  ASSERT_EQ(tcp_connect(&t.net, &conn, PEER_IP, peer_mac, 0, LPORT),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(tcp_connect(&t.net, &conn, PEER_IP, peer_mac, RPORT, 0),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-TCP-013 (RFC 9293 §3.10.1): an active open on a connection in use
 * is refused and leaves it */
TEST(itest_tcp_013_connect_on_a_live_connection) {
  up();
  established();
  ASSERT_EQ(tcp_connect(&t.net, &conn, PEER2_IP, peer_mac, RPORT, LPORT),
            NET_ERR_BUSY);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(tcp_send(&t.net, &conn, (const uint8_t *)"x", 1), 1);
  ASSERT_EQ(t.wire.tx_count, 1);
}

/* REQ-TCP-014, 024, 025, 055, 064, 065, 066: data both ways — ours
 * leaves at SND.NXT and its ACK frees the buffer (TCP_EVT_WRITABLE); the
 * peer's is delivered (TCP_EVT_DATA), acknowledged at once, RCV.NXT past
 * it and the window less by it */
TEST(itest_tcp_014_send_and_receive) {
  uint8_t buf[16];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  tcp_listen(&conn, LPORT);
  ASSERT_TRUE(tcp_send(&t.net, &conn, (const uint8_t *)"no", 2) < 0);
  iss = established();
  ASSERT_TRUE(tcp_tx_idle(&conn));
  ASSERT_EQ(tcp_send(&t.net, &conn, (const uint8_t *)"hello", 5), 5);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.seq, iss + 1);
  ASSERT_EQ(tcp.ack, 1001u);
  ASSERT_EQ(tcp.data_len, 5);
  ASSERT_MEM_EQ(tcp.data, "hello", 5);
  ASSERT_FALSE(tcp_tx_idle(&conn));
  segment(RPORT, 1001, iss + 6, TCPF_ACK);
  ASSERT_EQ(ev_writable, 1);
  ASSERT_TRUE(tcp_tx_idle(&conn));
  wire_clear(&t);
  ASSERT_EQ(tcp_send(&t.net, &conn, (const uint8_t *)"!", 1), 1);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.seq, iss + 6);

  wire_clear(&t);
  peer_data(1001, iss + 6, "abc", 3);
  ASSERT_EQ(ev_data, 1);
  ASSERT_EQ(t.wire.tx_count, 1); /* acknowledged without a tick */
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_ACK);
  ASSERT_EQ(tcp.seq, iss + 7);
  ASSERT_EQ(tcp.ack, 1004u);
  ASSERT_EQ(tcp.window, sizeof(rx_mem) - 3);
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 3);
  ASSERT_MEM_EQ(buf, "abc", 3);
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 0);
}

/* ── Segments received (RFC 9293 §3.1, §3.10.7) ── */

/* REQ-TCP-018, 019, 140: a segment whose checksum is wrong — in its own
 * bytes, or computed over another pseudo-header — is dropped silently */
TEST(itest_tcp_018_bad_checksum_dropped) {
  uint8_t buf[8];
  raw_seg_t r;
  uint32_t iss;
  up();
  tcp_listen(&conn, LPORT);
  r = raw(1000, 0, TCPF_SYN);
  r.cksum_xor = 0x0100;
  deliver_raw(&r);
  ASSERT_EQ(tcp_status(&conn), TCP_LISTEN);
  ASSERT_EQ(t.wire.tx_count, 0);

  up();
  iss = established();
  r = raw(1001, iss + 1, TCPF_ACK | TCPF_PSH);
  r.data = "abc";
  r.len = 3;
  r.cksum_xor = 0x0001;
  deliver_raw(&r);
  r.cksum_xor = 0;
  r.pseudo_src = PEER2_IP; /* summed as if from another address */
  deliver_raw(&r);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(ev_data, 0);
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 0);
  r.pseudo_src = 0;
  deliver_raw(&r); /* the same, checksummed right */
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 3);
}

/* REQ-TCP-021, 022: a data offset below 5, or beyond the segment, drops
 * the segment silently */
TEST(itest_tcp_021_bad_data_offset_dropped) {
  raw_seg_t r;
  up();
  tcp_listen(&conn, LPORT);
  r = raw(1000, 0, TCPF_SYN);
  r.doff = 4;
  deliver_raw(&r);
  r.doff = 6; /* 24 bytes of header in a 20-byte segment */
  deliver_raw(&r);
  r.doff = 15;
  deliver_raw(&r);
  ASSERT_EQ(tcp_status(&conn), TCP_LISTEN);
  ASSERT_EQ(t.wire.tx_count, 0);
  r.doff = 0;
  deliver_raw(&r);
  ASSERT_EQ(tcp_status(&conn), TCP_SYN_RECEIVED);
}

/* Two connections of the application and an empty slot between them */
static tcp_conn_t conn2;
static tcp_conn_t *pair[3] = {&conn, NULL, &conn2};
static tcp_saw_tx_ctx_t tx2_ctx;
static tcp_saw_rx_ctx_t rx2_ctx;
static uint8_t tx2_mem[512], rx2_mem[512];
static int ev2_error;

static void on_event2(tcp_conn_t *c, uint8_t events) {
  (void)c;
  ev2_error += (events & (TCP_EVT_ERROR | TCP_EVT_RESET)) != 0;
}

/* The second connection initialised, and the table of both bound */
static void pair_init(void) {
  tcp_saw_tx_init(&tx2_ctx, tx2_mem, sizeof(tx2_mem));
  tcp_saw_rx_init(&rx2_ctx, rx2_mem, sizeof(rx2_mem));
  tcp_conn_init(&conn2, &tcp_saw_tx_ops, &tx2_ctx, &tcp_saw_rx_ops, &rx2_ctx,
                on_event2);
  tcp_set_connections(&t.net, pair, 3);
  ev2_error = 0;
}

/* REQ-TCP-023, 148, 149, 150: the connections are the application's
 * table; a listener takes a SYN from anyone, and from then on a segment
 * belongs to the connection whose remote address, remote port and local
 * port it carries — another address with the same ports is another
 * connection, and no match is no connection (a RST) */
TEST(itest_tcp_023_matched_by_addresses_and_ports) {
  uint8_t buf[8];
  peer_ip_t ip;
  peer_tcp_t tcp;
  raw_seg_t r;
  uint32_t iss, iss2;
  up();
  pair_init();
  tcp_listen(&conn, LPORT);
  tcp_listen(&conn2, LPORT);
  segment(RPORT, 1000, 0, TCPF_SYN);
  ASSERT_EQ(tcp_status(&conn), TCP_SYN_RECEIVED);
  ASSERT_EQ(tcp_status(&conn2), TCP_LISTEN);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  iss = tcp.seq;
  r = raw(7000, 0, TCPF_SYN); /* the same ports, from another host */
  r.src = PEER2_IP;
  deliver_raw(&r);
  ASSERT_EQ(tcp_status(&conn2), TCP_SYN_RECEIVED);
  ASSERT_TRUE(nth_segment(1, &ip, &tcp));
  ASSERT_EQ(ip.dst, PEER2_IP);
  ASSERT_EQ(tcp.ack, 7001u);
  iss2 = tcp.seq;
  segment(RPORT, 1001, iss + 1, TCPF_ACK);
  r = raw(7001, iss2 + 1, TCPF_ACK | TCPF_PSH);
  r.src = PEER2_IP;
  r.data = "two";
  r.len = 3;
  deliver_raw(&r);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  ASSERT_EQ(tcp_status(&conn2), TCP_ESTABLISHED);
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 0);
  ASSERT_EQ(tcp_recv(&conn2, buf, sizeof(buf)), 3);

  wire_clear(&t);
  r = raw(9000, 0, TCPF_SYN); /* no listener left */
  r.sport = RPORT + 1;
  deliver_raw(&r);
  ASSERT_TRUE(sent_rst());
  wire_clear(&t);
  r = raw(1001, iss + 1, TCPF_ACK); /* the first peer, another local port */
  r.dport = LPORT + 1;
  deliver_raw(&r);
  ASSERT_TRUE(sent_rst());
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  ASSERT_EQ(tcp_status(&conn2), TCP_ESTABLISHED);
  ASSERT_EQ(ev_error + ev_reset + ev2_error, 0);
}

/* REQ-TCP-026, 027: sequence numbers are compared modulo 2^32 — data
 * across the wrap is in order, and what lies before it is old */
TEST(itest_tcp_026_sequence_numbers_wrap) {
  uint8_t buf[16];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  tcp_listen(&conn, LPORT);
  segment(RPORT, 0xFFFFFFFDu, 0, TCPF_SYN);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.ack, 0xFFFFFFFEu);
  iss = tcp.seq;
  segment(RPORT, 0xFFFFFFFEu, iss + 1, TCPF_ACK);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  wire_clear(&t);
  peer_data(0xFFFFFFFEu, iss + 1, "abcdef", 6);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 4u);
  peer_data(4, iss + 1, "gh", 2);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 6u);
  peer_data(0xFFFFFFFEu, iss + 1, "abcdef", 6); /* before the window */
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 6u);
  peer_data(0xFFFFFFFFu, iss + 1, "bcdefghij", 9); /* its end is new */
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 8u);
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 10);
  ASSERT_MEM_EQ(buf, "abcdefghij", 10);
}

/* Our ISS answering a SYN from the peer's port @p sport */
static uint32_t iss_for(uint16_t sport) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  wire_clear(&t);
  segment(sport, 1000, 0, TCPF_SYN);
  if (!nth_segment(0, &ip, &tcp))
    return 0;
  segment(sport, 1001, 0, TCPF_RST); /* LISTEN again */
  return tcp.seq;
}

/* REQ-TCP-028, 029: the ISS is clock-driven — for one connection id it
 * advances 250000 a second, a 4 µs clock — plus an offset that differs
 * from one connection id to another */
TEST(itest_tcp_028_iss_clock_driven) {
  uint32_t a, b, c;
  up();
  tcp_listen(&conn, LPORT);
  a = iss_for(RPORT);
  c = iss_for(RPORT + 1);
  itest_advance(&t, 1000, 100);
  b = iss_for(RPORT);
  ASSERT_EQ(b - a, 250000u);
  ASSERT_TRUE(c != a);
  ASSERT_TRUE(iss_for(RPORT + 1) - c == 250000u);
}

/* REQ-TCP-030, 031, 073, 075: in LISTEN a RST is ignored, an ACK draws
 * <SEQ=SEG.ACK><CTL=RST>, and anything else without SYN is dropped */
TEST(itest_tcp_030_listen_rst_and_ack) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  up();
  tcp_listen(&conn, LPORT);
  segment(RPORT, 1000, 0, TCPF_RST);
  segment(RPORT, 1000, 0, TCPF_FIN);
  ASSERT_EQ(t.wire.tx_count, 0);
  segment(RPORT, 1000, 4242, TCPF_ACK);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_RST);
  ASSERT_EQ(tcp.seq, 4242u);
  ASSERT_EQ(tcp.dport, RPORT);
  segment(RPORT, 1000, 4242, TCPF_RST | TCPF_ACK); /* never a RST to a RST */
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_EQ(tcp_status(&conn), TCP_LISTEN);
}

/* REQ-TCP-036, 040: in SYN-SENT an ACK is acceptable if SND.UNA < SEG.ACK
 * <= SND.NXT; any other draws <SEQ=SEG.ACK><CTL=RST> and changes nothing */
TEST(itest_tcp_036_syn_sent_unacceptable_ack) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  tcp_connect(&t.net, &conn, PEER_IP, peer_mac, RPORT, LPORT);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  iss = tcp.seq;
  wire_clear(&t);
  segment(RPORT, 5000, iss, TCPF_SYN | TCPF_ACK); /* SEG.ACK = ISS */
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_RST);
  ASSERT_EQ(tcp.seq, iss);
  wire_clear(&t);
  segment(RPORT, 5000, iss + 2, TCPF_SYN | TCPF_ACK); /* beyond SND.NXT */
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_RST);
  ASSERT_EQ(tcp.seq, iss + 2);
  wire_clear(&t);
  segment(RPORT, 5000, iss + 2, TCPF_RST | TCPF_ACK); /* no RST to a RST */
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(tcp_status(&conn), TCP_SYN_SENT);
  ASSERT_EQ(ev_reset + ev_error, 0);
  segment(RPORT, 5000, iss + 1, TCPF_SYN | TCPF_ACK);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
}

/* REQ-TCP-037: in SYN-SENT a RST that acknowledges our SYN refuses the
 * connection; one without an ACK is ignored */
TEST(itest_tcp_037_syn_sent_reset) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  tcp_connect(&t.net, &conn, PEER_IP, peer_mac, RPORT, LPORT);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  iss = tcp.seq;
  segment(RPORT, 0, 0, TCPF_RST);
  ASSERT_EQ(tcp_status(&conn), TCP_SYN_SENT);
  segment(RPORT, 0, iss + 1, TCPF_RST | TCPF_ACK);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_EQ(ev_reset, 1);
  ASSERT_EQ(t.wire.tx_count, 1); /* only our SYN */
}

/* REQ-TCP-041, 042, 044, 045, 067: a segment is acceptable if it begins
 * or ends in the receive window; one that is not is answered with an ACK
 * (a RST is not) and dropped.  Of an acceptable one only the bytes from
 * RCV.NXT on are taken, and none after a gap */
TEST(itest_tcp_041_acceptability) {
  uint8_t buf[32];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = established();                           /* RCV.NXT 1001, RCV.WND 512 */
  segment(RPORT, 1001 + 512, iss + 1, TCPF_ACK); /* just past the window */
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_ACK);
  ASSERT_EQ(tcp.seq, iss + 1);
  ASSERT_EQ(tcp.ack, 1001u);
  segment(RPORT, 1001 + 511, iss + 1, TCPF_ACK); /* its last octet */
  ASSERT_EQ(t.wire.tx_count, 1);
  peer_data(1001 + 512, iss + 1, "x", 1);
  ASSERT_EQ(t.wire.tx_count, 2);
  ASSERT_EQ(ev_data, 0);
  segment(RPORT, 1001 + 600, 0, TCPF_RST); /* outside: no answer */
  ASSERT_EQ(t.wire.tx_count, 2);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);

  peer_data(1001, iss + 1, "0123456789", 10);
  wire_clear(&t);
  peer_data(1006, iss + 1, "56789abcde", 10); /* its second half is new */
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 1016u);
  wire_clear(&t);
  peer_data(1001, iss + 1, "0123456789", 10); /* all of it old */
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 1016u);
  peer_data(1100, iss + 1, "zz", 2); /* in the window, after a gap */
  ASSERT_EQ(t.wire.tx_count, 2);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 1016u);
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 15);
  ASSERT_MEM_EQ(buf, "0123456789abcde", 15);
}

/* REQ-TCP-043, 083: with the receive buffer full the window is zero; then
 * only an empty segment at RCV.NXT is acceptable */
TEST(itest_tcp_043_zero_window_acceptability) {
  static uint8_t fill[512];
  uint8_t buf[8];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = established();
  peer_data(1001, iss + 1, fill, sizeof(fill));
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 1513u);
  ASSERT_EQ(tcp.window, 0);
  wire_clear(&t);
  segment(RPORT, 1513, iss + 1, TCPF_ACK);
  ASSERT_EQ(t.wire.tx_count, 0);
  segment(RPORT, 1514, iss + 1, TCPF_ACK);
  ASSERT_EQ(t.wire.tx_count, 1);
  peer_data(1513, iss + 1, "x", 1);
  ASSERT_EQ(t.wire.tx_count, 2);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 1513u);
  ASSERT_EQ(tcp.window, 0);
  ASSERT_EQ(tcp_recv(&conn, fill, sizeof(fill)), 512);
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 0);
}

/* REQ-TCP-047, 049: a RST in the window aborts an open connection and
 * the application is told; one outside the window is ignored */
TEST(itest_tcp_047_rst_aborts) {
  static const tcp_state_t states[] = {TCP_ESTABLISHED, TCP_FIN_WAIT_1,
                                       TCP_FIN_WAIT_2, TCP_CLOSE_WAIT};
  unsigned i;
  for (i = 0; i < sizeof(states) / sizeof(states[0]); i++) {
    uint32_t nxt = states[i] == TCP_CLOSE_WAIT ? 1002u : 1001u;
    up();
    in_state(states[i]);
    ASSERT_EQ(tcp_status(&conn), states[i]);
    segment(RPORT, nxt + 600, 0, TCPF_RST);
    segment(RPORT, nxt - 1, 0, TCPF_RST);
    ASSERT_EQ(tcp_status(&conn), states[i]);
    ASSERT_EQ(ev_reset, 0);
    segment(RPORT, nxt + 5, 0, TCPF_RST);
    ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
    ASSERT_EQ(ev_reset, 1);
    ASSERT_EQ(t.wire.tx_count, 0);
  }
}

/* REQ-TCP-048: once both sides have closed — CLOSING, LAST-ACK,
 * TIME-WAIT — a RST just closes */
TEST(itest_tcp_048_rst_after_both_closed) {
  static const tcp_state_t states[] = {TCP_CLOSING, TCP_LAST_ACK,
                                       TCP_TIME_WAIT};
  unsigned i;
  for (i = 0; i < sizeof(states) / sizeof(states[0]); i++) {
    up();
    in_state(states[i]);
    ASSERT_EQ(tcp_status(&conn), states[i]);
    segment(RPORT, 1002, 0, TCPF_RST);
    ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
    ASSERT_EQ(ev_reset + ev_error, 0);
    ASSERT_EQ(t.wire.tx_count, 0);
  }
}

/* REQ-TCP-051: a SYN in the window of a synchronized connection is an
 * error — a RST, CLOSED, the application told; one outside the window
 * draws an ACK */
TEST(itest_tcp_051_syn_in_established) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = established();
  segment(RPORT, 1001 + 600, 0, TCPF_SYN);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_ACK);
  ASSERT_EQ(tcp.ack, 1001u);
  wire_clear(&t);
  segment(RPORT, 1001, 0, TCPF_SYN);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_EQ(ev_error, 1);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_TRUE(tcp.flags & TCPF_RST);
  ASSERT_EQ(tcp.seq, iss + 1);
}

/* REQ-TCP-053: a segment without ACK is dropped, its data with it */
TEST(itest_tcp_053_no_ack_dropped) {
  uint8_t buf[8];
  raw_seg_t r;
  up();
  established();
  r = raw(1001, 0, TCPF_PSH);
  r.data = "abc";
  r.len = 3;
  deliver_raw(&r);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(ev_data, 0);
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 0);
}

/* REQ-TCP-056, 057: an ACK of something not yet sent is answered with an
 * ACK and the segment dropped; an old ACK changes nothing, and the
 * segment's data is taken */
TEST(itest_tcp_056_ack_of_unsent_and_old_ack) {
  uint8_t buf[8];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = established();
  peer_data(1001, iss + 50, "abc", 3);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_ACK);
  ASSERT_EQ(tcp.seq, iss + 1);
  ASSERT_EQ(tcp.ack, 1001u);
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 0);

  tcp_send(&t.net, &conn, (const uint8_t *)"hello", 5);
  segment(RPORT, 1001, iss + 6, TCPF_ACK);
  tcp_send(&t.net, &conn, (const uint8_t *)"again", 5);
  wire_clear(&t);
  peer_data(1001, iss + 1, "xyz", 3); /* an ACK from before "hello" */
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 3);
  ASSERT_FALSE(tcp_tx_idle(&conn)); /* "again" is still unacknowledged */
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 1004u);
  segment(RPORT, 1004, iss + 11, TCPF_ACK);
  ASSERT_TRUE(tcp_tx_idle(&conn));
}

/* REQ-TCP-058, 084: the send window is taken from the newest segment —
 * an older one that arrives late does not change it — and bounds what we
 * send; a window update that acknowledges nothing new lets the rest go */
TEST(itest_tcp_058_send_window) {
  static uint8_t out[100];
  static uint8_t ten[10];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = established();
  /* the peer's second segment (window 50) overtakes its first (4096) */
  segment_opts(1011, iss + 1, TCPF_ACK | TCPF_PSH, 50, 0, NULL, 0, "bb", 2);
  segment_opts(1001, iss + 1, TCPF_ACK | TCPF_PSH, 4096, 0, NULL, 0, ten, 10);
  wire_clear(&t);
  ASSERT_EQ(tcp_send(&t.net, &conn, out, sizeof(out)), (int)sizeof(out));
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.data_len, 50);
  /* all acknowledged, the window closed: nothing more goes */
  segment_opts(1011, iss + 51, TCPF_ACK, 0, 0, NULL, 0, NULL, 0);
  ASSERT_EQ(t.wire.tx_count, 1);
  /* the window opens, nothing new acknowledged: the rest goes at once */
  segment_opts(1011, iss + 51, TCPF_ACK, 4096, 0, NULL, 0, NULL, 0);
  ASSERT_EQ(t.wire.tx_count, 2);
  ASSERT_TRUE(nth_segment(1, &ip, &tcp));
  ASSERT_EQ(tcp.seq, iss + 51);
  ASSERT_EQ(tcp.data_len, 50);
}

/* REQ-TCP-067, 083: data beyond the window is cut off — the window is
 * the free space of the receive buffer */
TEST(itest_tcp_067_trimmed_to_window) {
  static uint8_t big[600], got[600];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  uint16_t i;
  up();
  iss = established();
  for (i = 0; i < sizeof(big); i++)
    big[i] = (uint8_t)i;
  peer_data(1001, iss + 1, big, sizeof(big));
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 1001u + 512u);
  ASSERT_EQ(tcp.window, 0);
  ASSERT_EQ(tcp_recv(&conn, got, sizeof(got)), 512);
  ASSERT_MEM_EQ(got, big, 512);
}

/* REQ-TCP-068: a FIN counts when everything before it has arrived — then
 * RCV.NXT passes it and it is acknowledged; a FIN after a gap is not
 * processed */
TEST(itest_tcp_068_fin_in_sequence) {
  uint8_t buf[8];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = established();
  segment(RPORT, 1005, iss + 1, TCPF_FIN | TCPF_ACK); /* 4 octets missing */
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 1001u);
  segment_opts(1003, iss + 1, TCPF_FIN | TCPF_ACK, 4096, 0, NULL, 0, "cd", 2);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 1001u);
  ASSERT_EQ(ev_closed, 0);
  segment_opts(1001, iss + 1, TCPF_FIN | TCPF_ACK, 4096, 0, NULL, 0, "abcd", 4);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSE_WAIT);
  ASSERT_EQ(ev_closed, 1);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 1006u);
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 4);
  wire_clear(&t); /* the FIN again: acknowledged, nothing changes */
  segment_opts(1001, iss + 1, TCPF_FIN | TCPF_ACK, 4096, 0, NULL, 0, "abcd", 4);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSE_WAIT);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 1006u);
}

/* REQ-TCP-072..075: a segment for no connection draws a RST — from an
 * ACK <SEQ=SEG.ACK><CTL=RST>, else <SEQ=0><ACK=SEG.SEQ+SEG.LEN>
 * <CTL=RST,ACK> — unless it is a RST itself */
TEST(itest_tcp_072_reset_for_no_connection) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  raw_seg_t r;
  up(); /* the connection is CLOSED */
  segment(RPORT, 1000, 0, TCPF_SYN);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_RST | TCPF_ACK);
  ASSERT_EQ(tcp.seq, 0u);
  ASSERT_EQ(tcp.ack, 1001u);
  ASSERT_EQ(tcp.sport, LPORT);
  ASSERT_EQ(tcp.dport, RPORT);
  ASSERT_EQ(ip.dst, PEER_IP);
  wire_clear(&t);
  r = raw(2000, 0, TCPF_SYN | TCPF_FIN); /* SYN, 4 octets, FIN: 6 */
  r.data = "data";
  r.len = 4;
  deliver_raw(&r);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_RST | TCPF_ACK);
  ASSERT_EQ(tcp.ack, 2006u);
  wire_clear(&t);
  r = raw(3000, 777, TCPF_ACK | TCPF_PSH);
  r.data = "abc";
  r.len = 3;
  deliver_raw(&r);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_RST);
  ASSERT_EQ(tcp.seq, 777u);
  wire_clear(&t);
  segment(RPORT, 1000, 0, TCPF_RST);
  segment(RPORT, 1000, 777, TCPF_RST | TCPF_ACK);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* ── Options and segment size (RFC 9293 §3.1, §3.2, §3.7.1) ── */

/* REQ-TCP-078, 079, 081, 109..112, 115: the peer's SYN options are
 * walked — a NOP, an option we do not know (skipped by its length), the
 * MSS, End of Option List (nothing after it counts) — and no segment
 * exceeds the peer's MSS; without the option, 536 */
TEST(itest_tcp_078_peer_mss_and_options) {
  static const uint8_t opts[16] = {1, 99, 6,  0xAA, 0xBB, 0xCC, 0xDD, 2,
                                   4, 1,  44, 0,    2,    4,    0,    100};
  static uint8_t out[1000];
  peer_ip_t ip;
  peer_tcp_t tcp;
  up_sized(1514, 1514, 1460);
  tcp_listen(&conn, LPORT);
  segment_opts(1000, 0, TCPF_SYN, 4096, 0, opts, sizeof(opts), NULL, 0);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_SYN | TCPF_ACK);
  segment(RPORT, 1001, tcp.seq + 1, TCPF_ACK);
  wire_clear(&t);
  ASSERT_EQ(tcp_send(&t.net, &conn, out, sizeof(out)), (int)sizeof(out));
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.data_len, 300); /* MSS 300: {2, 4, 1, 44} */

  up_sized(1514, 1514, 1460);
  tcp_listen(&conn, LPORT);
  segment_opts(1000, 0, TCPF_SYN, 4096, 0, NULL, 0, NULL, 0);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  segment(RPORT, 1001, tcp.seq + 1, TCPF_ACK);
  wire_clear(&t);
  ASSERT_EQ(tcp_send(&t.net, &conn, out, sizeof(out)), (int)sizeof(out));
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.data_len, 536);
}

/* REQ-TCP-077, 081: the MSS we announce is what the RX frame buffer
 * takes, and no segment we send is larger than the TX frame buffer
 * carries */
TEST(itest_tcp_077_mss_from_the_frame_buffers) {
  static uint8_t out[1000];
  peer_ip_t ip;
  peer_tcp_t tcp;
  up_sized(600, 1514, 512);
  tcp_listen(&conn, LPORT);
  segment(RPORT, 1000, 0, TCPF_SYN);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.mss, 600 - 14 - 20 - 20);

  up_sized(1514, 400, 1460);
  tcp_listen(&conn, LPORT);
  segment(RPORT, 1000, 0, TCPF_SYN); /* the peer takes 1460 */
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.mss, 1460);
  segment(RPORT, 1001, tcp.seq + 1, TCPF_ACK);
  wire_clear(&t);
  ASSERT_EQ(tcp_send(&t.net, &conn, out, sizeof(out)), (int)sizeof(out));
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.data_len, 400 - 14 - 20 - 20);
  ASSERT_EQ(wire_sent(&t, 0)->len, 400);
}

/* REQ-TCP-076, 116: the MSS option goes in our SYN and SYN,ACK, and in
 * no other segment: an ACK, data, a FIN and a RST have no options */
TEST(itest_tcp_116_options_only_in_syn) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  tcp_connect(&t.net, &conn, PEER_IP, peer_mac, RPORT, LPORT);
  ASSERT_EQ(data_offset(0), 6);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.mss, 1460);

  up();
  tcp_listen(&conn, LPORT);
  segment(RPORT, 1000, 0, TCPF_SYN);
  ASSERT_EQ(data_offset(0), 6); /* SYN,ACK */
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.mss, 1460);
  iss = tcp.seq;
  segment(RPORT, 1001, iss + 1, TCPF_ACK);
  wire_clear(&t);
  peer_data(1001, iss + 1, "abc", 3);
  ASSERT_EQ(data_offset(0), 5); /* ACK */
  tcp_send(&t.net, &conn, (const uint8_t *)"data", 4);
  ASSERT_EQ(data_offset(1), 5); /* data */
  segment(RPORT, 1004, iss + 5, TCPF_ACK);
  tcp_close(&t.net, &conn);
  ASSERT_EQ(data_offset(2), 5); /* FIN */
  tcp_abort(&t.net, &conn);
  ASSERT_EQ(data_offset(3), 5); /* RST */
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_TRUE(tcp.flags & TCPF_RST);
  segment(RPORT, 1004, iss + 6, TCPF_ACK); /* no connection now */
  ASSERT_EQ(data_offset(4), 5);            /* the RST in reply */
}

/* REQ-TCP-119 (113, 114, 117, 118, 122: not implemented): window scale,
 * timestamps and SACK offered in the peer's SYN are not negotiated — our
 * SYN,ACK carries the MSS option alone — and the peer's window is taken
 * unscaled */
TEST(itest_tcp_119_window_scale_not_negotiated) {
  static const uint8_t opts[20] = {3, 3, 7, 1, 8, 10, 0, 0, 0, 1,
                                   0, 0, 0, 0, 4, 2,  2, 4, 5, 0xB4};
  static uint8_t out[300];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  tcp_listen(&conn, LPORT);
  segment_opts(1000, 0, TCPF_SYN, 4096, 0, opts, sizeof(opts), NULL, 0);
  ASSERT_EQ(data_offset(0), 6);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(ip.payload[20], 2); /* the 4 option bytes: an MSS option */
  ASSERT_EQ(ip.payload[21], 4);
  iss = tcp.seq;
  segment_opts(1001, iss + 1, TCPF_ACK, 100, 0, NULL, 0, NULL, 0);
  wire_clear(&t);
  ASSERT_EQ(tcp_send(&t.net, &conn, out, sizeof(out)), (int)sizeof(out));
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.data_len, 100); /* not 100 << 7 */
}

/* REQ-TCP-182 (deviation), REQ-IPv4-067: IP options on a segment are
 * ignored, not passed up; a source-routed segment is dropped */
TEST(itest_tcp_182_ip_options) {
  static const uint8_t nops[4] = {1, 1, 1, 0};
  static const uint8_t lsrr[8] = {131, 7, 4, 10, 0, 0, 7, 0};
  peer_ip_t ip;
  peer_tcp_t tcp;
  raw_seg_t r;
  up();
  tcp_listen(&conn, LPORT);
  r = raw(1000, 0, TCPF_SYN);
  r.ip_opt = lsrr;
  r.ip_olen = sizeof(lsrr);
  deliver_raw(&r);
  ASSERT_EQ(tcp_status(&conn), TCP_LISTEN);
  ASSERT_EQ(t.wire.tx_count, 0);
  r.ip_opt = nops;
  r.ip_olen = sizeof(nops);
  deliver_raw(&r);
  ASSERT_EQ(tcp_status(&conn), TCP_SYN_RECEIVED);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(ip.ihl_bytes, 20); /* and none are sent */
}

/* ── Windows (RFC 9293 §3.8.6) ── */

/* REQ-TCP-082, 083: every segment but a RST advertises the free space of
 * the receive buffer */
TEST(itest_tcp_082_window_advertised) {
  static uint8_t in[100];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  tcp_listen(&conn, LPORT);
  segment(RPORT, 1000, 0, TCPF_SYN);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.window, sizeof(rx_mem)); /* SYN,ACK */
  iss = tcp.seq;
  segment(RPORT, 1001, iss + 1, TCPF_ACK);
  wire_clear(&t);
  peer_data(1001, iss + 1, in, sizeof(in));
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.window, sizeof(rx_mem) - 100); /* ACK */
  tcp_send(&t.net, &conn, (const uint8_t *)"data", 4);
  ASSERT_TRUE(nth_segment(1, &ip, &tcp));
  ASSERT_EQ(tcp.window, sizeof(rx_mem) - 100); /* data */
  segment(RPORT, 1101, iss + 5, TCPF_ACK);
  tcp_close(&t.net, &conn);
  ASSERT_TRUE(nth_segment(2, &ip, &tcp));
  ASSERT_EQ(tcp.window, sizeof(rx_mem) - 100); /* FIN */
  tcp_abort(&t.net, &conn);
  ASSERT_TRUE(nth_segment(3, &ip, &tcp));
  ASSERT_TRUE(tcp.flags & TCPF_RST);
  ASSERT_EQ(tcp.window, 0);
}

/* REQ-TCP-085, 086, 087: into a zero window nothing is sent; after the
 * retransmission timeout a probe of one octet goes, the same octet again
 * at twice the interval while it is unanswered, and when the window
 * opens the rest follows */
TEST(itest_tcp_085_zero_window_probe) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = established();
  segment_opts(1001, iss + 1, TCPF_ACK, 0, 0, NULL, 0, NULL, 0);
  ASSERT_EQ(tcp_send(&t.net, &conn, (const uint8_t *)"abcdef", 6), 6);
  ASSERT_EQ(t.wire.tx_count, 0);
  itest_advance(&t, 999, 1);
  ASSERT_EQ(t.wire.tx_count, 0);
  itest_advance(&t, 1, 1);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.seq, iss + 1);
  ASSERT_EQ(tcp.data_len, 1);
  ASSERT_EQ(tcp.data[0], 'a');
  segment_opts(1001, iss + 1, TCPF_ACK, 0, 0, NULL, 0, NULL, 0); /* still 0 */
  itest_advance(&t, 1999, 1);
  ASSERT_EQ(t.wire.tx_count, 1);
  itest_advance(&t, 1, 1);
  ASSERT_EQ(t.wire.tx_count, 2);
  ASSERT_TRUE(nth_segment(1, &ip, &tcp));
  ASSERT_EQ(tcp.seq, iss + 1);
  ASSERT_EQ(tcp.data_len, 1);
  ASSERT_EQ(tcp.data[0], 'a');
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  segment_opts(1001, iss + 2, TCPF_ACK, 4096, 0, NULL, 0, NULL, 0);
  ASSERT_EQ(t.wire.tx_count, 3);
  ASSERT_TRUE(nth_segment(2, &ip, &tcp));
  ASSERT_EQ(tcp.seq, iss + 2);
  ASSERT_EQ(tcp.data_len, 5);
  ASSERT_MEM_EQ(tcp.data, "bcdef", 5);
}

/* REQ-TCP-088 (RFC 9293 §3.8.6.2.2): the right edge of the window does
 * not move in small steps — space freed by the application is advertised
 * only once it is min(half the buffer, the MSS) more than the window
 * offered */
TEST(itest_tcp_088_receiver_silly_window_avoidance) {
  static uint8_t in[300], out[512];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up(); /* a 512-byte receive buffer: steps of 256 */
  iss = established();
  peer_data(1001, iss + 1, in, 300);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.window, 212);
  ASSERT_EQ(tcp_recv(&conn, out, 100), 100);
  wire_clear(&t);
  tcp_window_update(&t.net, &conn); /* 100 more: too little to say */
  ASSERT_EQ(t.wire.tx_count, 0);
  peer_data(1301, iss + 1, in, 212);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 1513u);
  ASSERT_EQ(tcp.window, 0); /* the edge stays at 1513 */
  ASSERT_EQ(tcp_recv(&conn, out, 200), 200);
  wire_clear(&t);
  tcp_window_update(&t.net, &conn); /* 300 free now */
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.window, 300);
}

/* REQ-TCP-089 (deviation), REQ-TCP-084: there is no sender silly-window
 * avoidance — what the peer's window allows goes at once, however little */
TEST(itest_tcp_089_small_window_small_segment) {
  static uint8_t out[100];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = established();
  segment_opts(1001, iss + 1, TCPF_ACK, 10, 0, NULL, 0, NULL, 0);
  wire_clear(&t);
  ASSERT_EQ(tcp_send(&t.net, &conn, out, sizeof(out)), (int)sizeof(out));
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.data_len, 10);
}

/* ── Retransmission (RFC 6298) and what stands in for congestion control ── */

/* REQ-TCP-090, 092, 094, 095, 096: an unacknowledged segment is sent
 * again, the same octets at the same sequence number, after 1 s, then at
 * intervals that double up to 60 s; after the eighth the connection is
 * given up (REQ-TCP-162) */
TEST(itest_tcp_090_retransmission_schedule) {
  static const uint32_t expected[8] = {1000,  3000,  7000,   15000,
                                       31000, 63000, 123000, 183000};
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss, ms;
  int n = 0;
  up();
  iss = established();
  tcp_send(&t.net, &conn, (const uint8_t *)"lost", 4);
  for (ms = 100; ms <= 243000 && tcp_status(&conn) == TCP_ESTABLISHED;
       ms += 100) {
    wire_clear(&t);
    itest_advance(&t, 100, 100);
    if (!nth_segment(0, &ip, &tcp) || (tcp.flags & TCPF_RST))
      continue;
    ASSERT_TRUE(n < 8);
    ASSERT_EQ(ms, expected[n]);
    ASSERT_EQ(tcp.seq, iss + 1);
    ASSERT_EQ(tcp.data_len, 4);
    ASSERT_MEM_EQ(tcp.data, "lost", 4);
    n++;
  }
  ASSERT_EQ(n, 8);
  ASSERT_EQ(ms, 243000u + 100u);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_EQ(ev_error, 1);
  ASSERT_TRUE(sent_rst());
}

/* REQ-TCP-097, 098: an ACK of new data restarts the retransmission
 * timer while something is still unacknowledged, and stops it when
 * nothing is */
TEST(itest_tcp_097_ack_restarts_or_stops_the_timer) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = established();
  tcp_send(&t.net, &conn, (const uint8_t *)"data", 4);
  tcp_close(&t.net, &conn); /* our FIN follows at ISS + 5 */
  itest_advance(&t, 600, 100);
  segment(RPORT, 1001, iss + 5, TCPF_ACK); /* the data, not the FIN */
  wire_clear(&t);
  itest_advance(&t, 900, 100); /* 1.5 s after the FIN: the timer restarted */
  ASSERT_EQ(t.wire.tx_count, 0);
  itest_advance(&t, 100, 100);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_FIN | TCPF_ACK);
  ASSERT_EQ(tcp.seq, iss + 5);

  up();
  iss = established();
  tcp_send(&t.net, &conn, (const uint8_t *)"data", 4);
  itest_advance(&t, 500, 100);
  segment(RPORT, 1001, iss + 5, TCPF_ACK);
  wire_clear(&t);
  itest_advance(&t, 300000, 100);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
}

/* REQ-TCP-091, 099 (deviations), REQ-TCP-093, 100: no round-trip time is
 * measured.  The timeout is 1 s however fast the peer answers — never
 * less — and once backed off it stays so for later segments */
TEST(itest_tcp_091_rto_not_measured) {
  uint32_t iss;
  up();
  iss = established();
  tcp_send(&t.net, &conn, (const uint8_t *)"a", 1);
  segment(RPORT, 1001, iss + 2, TCPF_ACK); /* a round trip of no time */
  tcp_send(&t.net, &conn, (const uint8_t *)"b", 1);
  wire_clear(&t);
  itest_advance(&t, 999, 1);
  ASSERT_EQ(t.wire.tx_count, 0);
  itest_advance(&t, 1, 1);
  ASSERT_EQ(t.wire.tx_count, 1); /* "b" again */
  segment(RPORT, 1001, iss + 3, TCPF_ACK);
  tcp_send(&t.net, &conn, (const uint8_t *)"c", 1);
  wire_clear(&t);
  itest_advance(&t, 1999, 1);
  ASSERT_EQ(t.wire.tx_count, 0);
  itest_advance(&t, 1, 1);
  ASSERT_EQ(t.wire.tx_count, 1);
}

/* REQ-TCP-101..105 (deviations), REQ-TCP-108, 130, 131, 145: no
 * congestion window — one segment in flight, never more than RFC 5681's
 * loss window, whatever the peer's window; the next leaves when it is
 * acknowledged, and a timeout resends that one segment.  Nothing is held
 * back as Nagle would, but nothing more is taken while one is in flight */
TEST(itest_tcp_108_one_segment_in_flight) {
  static uint8_t out[1400];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up_sized(1514, 1514, 1460);
  tcp_listen(&conn, LPORT);
  segment_opts(1000, 0, TCPF_SYN, 65535, 0, NULL, 0, NULL, 0); /* MSS 536 */
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  iss = tcp.seq;
  segment_opts(1001, iss + 1, TCPF_ACK, 65535, 0, NULL, 0, NULL, 0);
  wire_clear(&t);
  ASSERT_EQ(tcp_send(&t.net, &conn, out, 1), 1); /* a small one, at once */
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_EQ(tcp_send(&t.net, &conn, out, 1), 0); /* one is in flight */
  segment_opts(1001, iss + 2, TCPF_ACK, 65535, 0, NULL, 0, NULL, 0);
  wire_clear(&t);
  ASSERT_EQ(tcp_send(&t.net, &conn, out, sizeof(out)), (int)sizeof(out));
  itest_advance(&t, 900, 100);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.data_len, 536);
  itest_advance(&t, 100, 100); /* the timeout: the same segment, alone */
  ASSERT_EQ(t.wire.tx_count, 2);
  ASSERT_TRUE(nth_segment(1, &ip, &tcp));
  ASSERT_EQ(tcp.seq, iss + 2);
  ASSERT_EQ(tcp.data_len, 536);
  segment_opts(1001, iss + 2 + 536, TCPF_ACK, 65535, 0, NULL, 0, NULL, 0);
  ASSERT_EQ(t.wire.tx_count, 3); /* its ACK releases the next */
  ASSERT_TRUE(nth_segment(2, &ip, &tcp));
  ASSERT_EQ(tcp.seq, iss + 2 + 536);
  ASSERT_EQ(tcp.data_len, 536);
}

/* REQ-TCP-066, 126, 127, 128, REQ-TCP-125 (deviation): no delayed ACK —
 * every data segment is acknowledged as it arrives, no time passing */
TEST(itest_tcp_127_ack_not_delayed) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  up();
  iss = established();
  peer_data(1001, iss + 1, "one", 3);
  ASSERT_EQ(t.wire.tx_count, 1);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 1004u);
  peer_data(1004, iss + 1, "two", 3);
  ASSERT_EQ(t.wire.tx_count, 2);
  ASSERT_TRUE(last_segment(&ip, &tcp));
  ASSERT_EQ(tcp.ack, 1007u);
}

/* REQ-TCP-133 (132: not implemented): no keep-alive is sent — an idle
 * connection is silent, and stays open */
TEST(itest_tcp_133_no_keep_alive) {
  up();
  established();
  itest_advance(&t, 3u * 3600u * 1000u, 1000);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
}

/* REQ-TCP-139, 152, REQ-TCP-141 (deviation): every segment sent — SYN,
 * ACK, data, FIN, RST — carries a checksum the peer verifies, computed by
 * the stack itself; the frame is built in the application's TX buffer */
TEST(itest_tcp_139_checksum_sent) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  int i;
  up();
  tcp_listen(&conn, LPORT);
  segment(RPORT, 1000, 0, TCPF_SYN);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  iss = tcp.seq;
  segment(RPORT, 1001, iss + 1, TCPF_ACK);
  peer_data(1001, iss + 1, "abc", 3);
  tcp_send(&t.net, &conn, (const uint8_t *)"odd", 3);
  ASSERT_MEM_EQ(t.tx_buf, wire_sent(&t, 2)->data, wire_sent(&t, 2)->len);
  segment(RPORT, 1004, iss + 4, TCPF_ACK);
  tcp_close(&t.net, &conn);
  tcp_abort(&t.net, &conn);
  segment(RPORT, 1004, iss + 5, TCPF_ACK);
  ASSERT_EQ(t.wire.tx_count, 6);
  for (i = 0; i < 6; i++) {
    ASSERT_TRUE(nth_segment(i, &ip, &tcp));
    ASSERT_TRUE(ip.header_cksum_ok);
    ASSERT_TRUE(tcp.cksum_ok);
  }
}

/* REQ-TCP-175: segments carry the configured TTL, NET_DEFAULT_TTL */
TEST(itest_tcp_175_ttl) {
  peer_ip_t ip;
  peer_tcp_t tcp;
  up();
  segment(RPORT, 1000, 0, TCPF_SYN); /* no listener: a RST */
  tcp_connect(&t.net, &conn, PEER_IP, peer_mac, RPORT, LPORT);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(ip.ttl, NET_DEFAULT_TTL);
  ASSERT_TRUE(nth_segment(1, &ip, &tcp));
  ASSERT_EQ(ip.ttl, NET_DEFAULT_TTL);
}

/* ── The buffer interface (tcp_buf.h) ── */

/* Buffers of the test's own: flat, one segment in flight, calls counted */
typedef struct {
  uint8_t mem[64];
  uint16_t len, sent;
  int writes, acks, marks;
  uint32_t acked;
} own_tx_t;

typedef struct {
  uint8_t mem[64];
  uint16_t len;
  const uint8_t *from; /* where deliver() was given its data */
  int delivers, reads;
} own_rx_t;

static uint16_t own_write(void *ctx, const uint8_t *d, uint16_t n) {
  own_tx_t *b = (own_tx_t *)ctx;
  uint16_t room = (uint16_t)(sizeof(b->mem) - b->len);
  b->writes++;
  if (b->sent)
    return 0;
  if (n > room)
    n = room;
  memcpy(b->mem + b->len, d, n);
  b->len = (uint16_t)(b->len + n);
  return n;
}

static uint16_t own_next(void *ctx, const uint8_t **d, uint16_t mss) {
  own_tx_t *b = (own_tx_t *)ctx;
  if (b->sent || b->len == 0)
    return 0;
  *d = b->mem;
  b->sent = b->len < mss ? b->len : mss;
  return b->sent;
}

static void own_ack(void *ctx, uint32_t n) {
  own_tx_t *b = (own_tx_t *)ctx;
  b->acks++;
  b->acked += n;
  if (n > b->sent)
    n = b->sent;
  memmove(b->mem, b->mem + n, b->len - n);
  b->len = (uint16_t)(b->len - n);
  b->sent = (uint16_t)(b->sent - n);
}

static uint16_t own_in_flight(const void *ctx) {
  return ((const own_tx_t *)ctx)->sent;
}

static uint16_t own_queued(const void *ctx) {
  return ((const own_tx_t *)ctx)->len;
}

static uint16_t own_writable(const void *ctx) {
  const own_tx_t *b = (const own_tx_t *)ctx;
  return b->sent ? 0 : (uint16_t)(sizeof(b->mem) - b->len);
}

static void own_mark(void *ctx) {
  own_tx_t *b = (own_tx_t *)ctx;
  b->marks++;
  b->sent = 0;
}

static uint16_t own_deliver(void *ctx, const uint8_t *d, uint16_t n) {
  own_rx_t *b = (own_rx_t *)ctx;
  uint16_t room = (uint16_t)(sizeof(b->mem) - b->len);
  b->delivers++;
  b->from = d;
  if (n > room)
    n = room;
  memcpy(b->mem + b->len, d, n);
  b->len = (uint16_t)(b->len + n);
  return n;
}

static uint16_t own_read(void *ctx, uint8_t *dst, uint16_t max) {
  own_rx_t *b = (own_rx_t *)ctx;
  uint16_t n = b->len < max ? b->len : max;
  b->reads++;
  memcpy(dst, b->mem, n);
  memmove(b->mem, b->mem + n, b->len - n);
  b->len = (uint16_t)(b->len - n);
  return n;
}

static uint16_t own_readable(const void *ctx) {
  return ((const own_rx_t *)ctx)->len;
}

static uint16_t own_available(const void *ctx) {
  const own_rx_t *b = (const own_rx_t *)ctx;
  return (uint16_t)(sizeof(b->mem) - b->len);
}

static const tcp_txbuf_ops_t own_tx_ops = {
    own_write,  own_next,     own_ack, own_in_flight,
    own_queued, own_writable, own_mark};
static const tcp_rxbuf_ops_t own_rx_ops = {own_deliver, own_read, own_readable,
                                           own_available};

/* REQ-TCP-142, 143, 144, 151: TCP reaches a connection's data only
 * through the operations the application gave it — what is sent comes
 * from next_segment(), an ACK is passed to ack(), a timeout to
 * mark_retransmit(), received data to deliver() straight from the
 * received frame, and the window is available() */
TEST(itest_tcp_142_buffers_through_their_operations) {
  static own_tx_t otx;
  static own_rx_t orx;
  uint8_t buf[8];
  peer_ip_t ip;
  peer_tcp_t tcp;
  uint32_t iss;
  itest_up(&t, 1514, 1514);
  memset(&otx, 0, sizeof(otx));
  memset(&orx, 0, sizeof(orx));
  ASSERT_EQ(tcp_conn_init(&conn, &own_tx_ops, &otx, &own_rx_ops, &orx, NULL),
            NET_OK);
  tcp_set_connections(&t.net, table, 1);
  tcp_listen(&conn, LPORT);
  segment(RPORT, 1000, 0, TCPF_SYN);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.window, 64); /* available() */
  iss = tcp.seq;
  segment(RPORT, 1001, iss + 1, TCPF_ACK);
  ASSERT_EQ(otx.acks, 0); /* the SYN is not the buffer's */
  wire_clear(&t);

  ASSERT_EQ(tcp_send(&t.net, &conn, (const uint8_t *)"hello", 5), 5);
  ASSERT_EQ(otx.writes, 1);
  ASSERT_EQ(otx.sent, 5);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_MEM_EQ(tcp.data, "hello", 5);
  itest_advance(&t, 1000, 100);
  ASSERT_EQ(otx.marks, 1);
  ASSERT_TRUE(nth_segment(1, &ip, &tcp));
  ASSERT_MEM_EQ(tcp.data, "hello", 5);
  segment(RPORT, 1001, iss + 6, TCPF_ACK);
  ASSERT_EQ(otx.acks, 1);
  ASSERT_EQ(otx.acked, 5u);
  ASSERT_EQ(otx.len, 0);

  wire_clear(&t);
  peer_data(1001, iss + 6, "abc", 3);
  ASSERT_EQ(orx.delivers, 1);
  ASSERT_TRUE(orx.from >= t.rx_buf && orx.from + 3 <= t.rx_buf + 1514);
  ASSERT_TRUE(nth_segment(0, &ip, &tcp));
  ASSERT_EQ(tcp.window, 61);
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 3);
  ASSERT_EQ(orx.reads, 1);
  ASSERT_MEM_EQ(buf, "abc", 3);
}

#if NET_USE_IPV6
/* ── TCP over IPv6: the peer's frames built and parsed here ── */

static const uint8_t peer6[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                  0,    0,    0, 0, 0, 0, 0, 0x99};
static const uint8_t global6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                    0,    0,    0,    0,    0, 0, 0, 0x0a};
static uint8_t ll6[16];

/* The stack with its link-local address and a global one, both past
 * Duplicate Address Detection */
static void up6(uint16_t tx_size) {
  up_sized(1514, 1514, tx_size);
  ipv6_start(&t.net);
  ipv6_addr_add(&t.net, global6, NET_IP6_INFINITE, NET_IP6_INFINITE);
  itest_advance(&t, 3000, 100);
  ipv6_link_local_from_mac(t.net.mac, ll6);
  wire_clear(&t);
}

/* The checksum of a segment over the IPv6 pseudo-header (RFC 8200 §8.1),
 * by the peer's arithmetic */
static uint16_t cksum6(const uint8_t *src, const uint8_t *dst,
                       const uint8_t *seg, uint16_t len) {
  static uint8_t buf[40 + WIRE_FRAME_MAX];
  memcpy(buf, src, 16);
  memcpy(buf + 16, dst, 16);
  peer_put32(buf + 32, len);
  peer_put32(buf + 36, 6);
  memcpy(buf + 40, seg, len);
  return peer_cksum(buf, (uint16_t)(40u + len));
}

/* A segment from the peer's link-local address to @p dst, one of ours;
 * an MSS option if @p mss is not 0, a wrong checksum if @p cksum_xor is */
static void segment6(const uint8_t *dst, uint16_t sport, uint32_t seq,
                     uint32_t ack, uint8_t flags, uint16_t mss,
                     uint16_t cksum_xor) {
  uint8_t f[128];
  uint8_t *ip = f + 14, *s = ip + 40;
  uint8_t hlen = mss ? 24 : 20;
  memcpy(f, t.net.mac, 6);
  memcpy(f + 6, peer_mac, 6);
  peer_put16(f + 12, 0x86DD);
  memset(ip, 0, 40u + hlen);
  ip[0] = 0x60;
  peer_put16(ip + 4, hlen);
  ip[6] = 6;
  ip[7] = 64;
  memcpy(ip + 8, peer6, 16);
  memcpy(ip + 24, dst, 16);
  peer_put16(s, sport);
  peer_put16(s + 2, LPORT);
  peer_put32(s + 4, seq);
  peer_put32(s + 8, ack);
  s[12] = (uint8_t)((hlen / 4u) << 4);
  s[13] = flags;
  peer_put16(s + 14, 4096);
  if (mss) {
    s[20] = 2;
    s[21] = 4;
    peer_put16(s + 22, mss);
  }
  peer_put16(s + 16, (uint16_t)(cksum6(peer6, dst, s, hlen) ^ cksum_xor));
  itest_receive(&t, f, (uint16_t)(54u + hlen));
}

/* The n-th TCP segment sent over IPv6: its IPv6 header, and the segment
 * parsed; 0 if there is none */
static int sent6(int n, const uint8_t **ip6, peer_tcp_t *tcp) {
  const wire_frame_t *f;
  uint16_t i;
  for (i = 0; (f = wire_sent(&t, i)) != NULL; i++) {
    peer_ip_t ip;
    if (f->len < 74 || peer_get16(f->data + 12) != 0x86DD || f->data[20] != 6 ||
        n-- != 0)
      continue;
    memset(&ip, 0, sizeof(ip));
    ip.proto = 6;
    ip.payload = f->data + 54;
    ip.payload_len = peer_get16(f->data + 18);
    *ip6 = f->data + 14;
    return peer_parse_tcp(&ip, tcp);
  }
  return 0;
}

/* REQ-TCP-020, 080, 139: over IPv6 the checksum covers the IPv6
 * pseudo-header, received and sent; with no MSS option from the peer a
 * segment carries at most 1220 octets */
TEST(itest_tcp_020_ipv6_checksum_and_default_mss) {
  static uint8_t out[1400];
  const uint8_t *ip6;
  peer_tcp_t tcp;
  uint32_t iss;
  up6(1460);
  tcp_listen(&conn, LPORT);
  segment6(ll6, RPORT, 1000, 0, TCPF_SYN, 0, 0x0100);
  ASSERT_EQ(tcp_status(&conn), TCP_LISTEN);
  ASSERT_EQ(t.wire.tx_count, 0);
  segment6(ll6, RPORT, 1000, 0, TCPF_SYN, 0, 0);
  ASSERT_EQ(tcp_status(&conn), TCP_SYN_RECEIVED);
  ASSERT_TRUE(sent6(0, &ip6, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_SYN | TCPF_ACK);
  ASSERT_EQ(tcp.ack, 1001u);
  ASSERT_EQ(tcp.mss, 1440);
  ASSERT_MEM_EQ(ip6 + 8, ll6, 16);
  ASSERT_MEM_EQ(ip6 + 24, peer6, 16);
  ASSERT_EQ(cksum6(ll6, peer6, ip6 + 40, peer_get16(ip6 + 4)), 0);
  iss = tcp.seq;
  segment6(ll6, RPORT, 1001, iss + 1, TCPF_ACK, 0, 0);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  wire_clear(&t);
  ASSERT_EQ(tcp_send(&t.net, &conn, out, sizeof(out)), (int)sizeof(out));
  ASSERT_TRUE(sent6(0, &ip6, &tcp));
  ASSERT_EQ(tcp.data_len, 1220);
  ASSERT_EQ(cksum6(ll6, peer6, ip6 + 40, peer_get16(ip6 + 4)), 0);
}

/* REQ-TCP-023, 148: the local address is part of what names a
 * connection — the same peer and ports, to another of our addresses, is
 * another connection */
TEST(itest_tcp_023_local_address_ipv6) {
  const uint8_t *ip6;
  peer_tcp_t tcp;
  uint32_t iss;
  up6(512);
  pair_init();
  tcp_listen(&conn, LPORT);
  tcp_listen(&conn2, LPORT);
  segment6(ll6, RPORT, 1000, 0, TCPF_SYN, 1440, 0);
  ASSERT_TRUE(sent6(0, &ip6, &tcp));
  iss = tcp.seq;
  segment6(ll6, RPORT, 1001, iss + 1, TCPF_ACK, 0, 0);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  ASSERT_EQ(tcp_status(&conn2), TCP_LISTEN);
  wire_clear(&t);
  segment6(global6, RPORT, 1200, 0, TCPF_SYN, 1440, 0);
  ASSERT_EQ(tcp_status(&conn2), TCP_SYN_RECEIVED);
  ASSERT_TRUE(sent6(0, &ip6, &tcp));
  ASSERT_EQ(tcp.flags, TCPF_SYN | TCPF_ACK);
  ASSERT_EQ(tcp.ack, 1201u);
  ASSERT_MEM_EQ(ip6 + 8, global6, 16);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  ASSERT_EQ(ev_error + ev_reset, 0);
}
/* An ICMPv6 error of @p type and @p code, @p param in its 4-byte field,
 * from the peer about the n-th TCP segment we sent over IPv6: as much of
 * the packet quoted as an error of 1280 octets holds (RFC 4443 §2.4) */
static void icmp6_about_sent(int n, uint8_t type, uint8_t code,
                             uint32_t param) {
  static uint8_t f[WIRE_FRAME_MAX], sum[40 + 1280];
  const wire_frame_t *sent = NULL;
  uint8_t *ip = f + 14, *msg = ip + 40;
  uint16_t i, quote, len;
  for (i = 0; (sent = wire_sent(&t, i)) != NULL; i++) {
    if (sent->len >= 74 && peer_get16(sent->data + 12) == 0x86DD &&
        sent->data[20] == 6 && n-- == 0)
      break;
  }
  if (!sent)
    return;
  quote = (uint16_t)(sent->len - 14u);
  if (quote > 1280u - 48u)
    quote = 1280u - 48u;
  len = (uint16_t)(8u + quote);
  memcpy(f, t.net.mac, 6);
  memcpy(f + 6, peer_mac, 6);
  peer_put16(f + 12, 0x86DD);
  memset(ip, 0, 40);
  ip[0] = 0x60;
  peer_put16(ip + 4, len);
  ip[6] = 58;
  ip[7] = 64;
  memcpy(ip + 8, peer6, 16);
  memcpy(ip + 24, sent->data + 14 + 8, 16); /* to the segment's source */
  msg[0] = type;
  msg[1] = code;
  peer_put16(msg + 2, 0);
  peer_put32(msg + 4, param);
  memcpy(msg + 8, sent->data + 14, quote);
  memcpy(sum, ip + 8, 32);
  peer_put32(sum + 32, len);
  peer_put32(sum + 36, 58);
  memcpy(sum + 40, msg, len);
  peer_put16(msg + 2, peer_cksum(sum, (uint16_t)(40u + len)));
  itest_receive(&t, f, (uint16_t)(54u + len));
}

/* REQ-TCP-135, REQ-ICMPv6-018, 019, 020 (RFC 8201): over IPv6 a Packet Too
 * Big about a segment in flight lowers the segment size to the path MTU,
 * and the data goes again in pieces; one about a segment never sent
 * changes nothing */
TEST(itest_tcp_135_packet_too_big_ipv6) {
  static uint8_t out[1400];
  const uint8_t *ip6;
  peer_tcp_t tcp;
  uint32_t iss;
  uint16_t i;
  up6(1460);
  for (i = 0; i < sizeof(out); i++)
    out[i] = (uint8_t)i;
  tcp_listen(&conn, LPORT);
  segment6(ll6, RPORT, 1000, 0, TCPF_SYN, 1440, 0);
  ASSERT_TRUE(sent6(0, &ip6, &tcp));
  iss = tcp.seq;
  segment6(ll6, RPORT, 1001, iss + 1, TCPF_ACK, 0, 0);
  wire_clear(&t);
  ASSERT_EQ(tcp_send(&t.net, &conn, out, sizeof(out)), (int)sizeof(out));
  ASSERT_TRUE(sent6(0, &ip6, &tcp));
  ASSERT_EQ(tcp.data_len, 1400);
  icmp6_about_sent(0, 2, 0, 1280);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  wire_clear(&t);
  itest_advance(&t, 1000, 100);
  ASSERT_TRUE(sent6(0, &ip6, &tcp));
  ASSERT_EQ(tcp.seq, iss + 1);
  ASSERT_EQ(tcp.data_len, 1280 - 40 - 20);
  wire_clear(&t);
  segment6(ll6, RPORT, 1001, iss + 1 + 1220, TCPF_ACK, 0, 0);
  ASSERT_TRUE(sent6(0, &ip6, &tcp));
  ASSERT_EQ(tcp.seq, iss + 1 + 1220);
  ASSERT_EQ(tcp.data_len, 180);
  ASSERT_MEM_EQ(tcp.data, out + 1220, 180);
}

/* REQ-TCP-135, 136, 137, REQ-ICMPv6-011, 015: over IPv6 too, a hard
 * error — Port Unreachable for our SYN — refuses the connection, and a
 * soft one — no route — is reported and does not abort */
TEST(itest_tcp_135_unreachable_ipv6) {
  const uint8_t *ip6;
  peer_tcp_t tcp;
  uint32_t iss;
  up6(512);
  ASSERT_EQ(tcp6_connect(&t.net, &conn, peer6, peer_mac, RPORT, LPORT), NET_OK);
  icmp6_about_sent(0, 1, 4, 0);
  ASSERT_EQ(tcp_status(&conn), TCP_CLOSED);
  ASSERT_EQ(ev_error, 1);

  up6(512);
  conn.on_event = count_soft;
  ev_soft = 0;
  tcp_listen(&conn, LPORT);
  segment6(ll6, RPORT, 1000, 0, TCPF_SYN, 1440, 0);
  ASSERT_TRUE(sent6(0, &ip6, &tcp));
  iss = tcp.seq;
  segment6(ll6, RPORT, 1001, iss + 1, TCPF_ACK, 0, 0);
  wire_clear(&t);
  tcp_send(&t.net, &conn, (const uint8_t *)"x", 1);
  icmp6_about_sent(0, 1, 0, 0);
  ASSERT_EQ(tcp_status(&conn), TCP_ESTABLISHED);
  ASSERT_EQ(ev_soft, 1);
  ASSERT_EQ(tcp_last_error(&conn), 0x0100);
}
#endif

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
  RUN_TEST(itest_tcp_077_mtu_bounds_segments);
  RUN_TEST(itest_tcp_063_urgent_data_in_line);
  RUN_TEST(itest_tcp_156_window_unsigned);
  RUN_TEST(itest_tcp_157_options_in_any_segment);
  RUN_TEST(itest_tcp_158_illegal_option_length);
  RUN_TEST(itest_tcp_160_rst_into_zero_window);
  RUN_TEST(itest_tcp_161_closed_or_aborted);
  RUN_TEST(itest_tcp_162_r1_and_r2);
  RUN_TEST(itest_tcp_164_syn_retransmitted_three_minutes);
  RUN_TEST(itest_tcp_166_window_shrunk);
  RUN_TEST(itest_tcp_167_zero_window_kept_open);
  RUN_TEST(itest_tcp_168_listen_on_a_live_connection);
  RUN_TEST(itest_tcp_169_listen_beside_an_open);
  RUN_TEST(itest_tcp_170_local_address);
#if NET_USE_IPV6
  RUN_TEST(itest_tcp_170_local_address_ipv6);
#endif
  RUN_TEST(itest_tcp_171_same_local_address);
  RUN_TEST(itest_tcp_172_open_to_broadcast_refused);
  RUN_TEST(itest_tcp_174_tos);
  RUN_TEST(itest_tcp_176_syn_to_broadcast_dropped);
  RUN_TEST(itest_tcp_177_syn_from_unspecified_ignored);
  RUN_TEST(itest_tcp_179_retransmit_not_early);
  RUN_TEST(itest_tcp_180_push_and_no_indefinite_buffering);
  RUN_TEST(itest_tcp_181_rto_three_seconds_after_syn_timeout);
  RUN_TEST(itest_tcp_135_unreachable_in_syn_sent);
  RUN_TEST(itest_tcp_135_fragmentation_needed_lowers_mss);
  RUN_TEST(itest_tcp_136_soft_errors_do_not_abort);
  RUN_TEST(itest_tcp_137_hard_errors_abort);
  RUN_TEST(itest_tcp_002_passive_open);
  RUN_TEST(itest_tcp_003_active_open);
  RUN_TEST(itest_tcp_004_simultaneous_open);
  RUN_TEST(itest_tcp_005_active_close);
  RUN_TEST(itest_tcp_006_passive_close);
  RUN_TEST(itest_tcp_007_simultaneous_close);
  RUN_TEST(itest_tcp_011_conn_init_validates);
  RUN_TEST(itest_tcp_013_connect_on_a_live_connection);
  RUN_TEST(itest_tcp_014_send_and_receive);
  RUN_TEST(itest_tcp_018_bad_checksum_dropped);
  RUN_TEST(itest_tcp_021_bad_data_offset_dropped);
  RUN_TEST(itest_tcp_023_matched_by_addresses_and_ports);
  RUN_TEST(itest_tcp_026_sequence_numbers_wrap);
  RUN_TEST(itest_tcp_028_iss_clock_driven);
  RUN_TEST(itest_tcp_030_listen_rst_and_ack);
  RUN_TEST(itest_tcp_036_syn_sent_unacceptable_ack);
  RUN_TEST(itest_tcp_037_syn_sent_reset);
  RUN_TEST(itest_tcp_041_acceptability);
  RUN_TEST(itest_tcp_043_zero_window_acceptability);
  RUN_TEST(itest_tcp_047_rst_aborts);
  RUN_TEST(itest_tcp_048_rst_after_both_closed);
  RUN_TEST(itest_tcp_051_syn_in_established);
  RUN_TEST(itest_tcp_053_no_ack_dropped);
  RUN_TEST(itest_tcp_056_ack_of_unsent_and_old_ack);
  RUN_TEST(itest_tcp_058_send_window);
  RUN_TEST(itest_tcp_067_trimmed_to_window);
  RUN_TEST(itest_tcp_068_fin_in_sequence);
  RUN_TEST(itest_tcp_072_reset_for_no_connection);
  RUN_TEST(itest_tcp_078_peer_mss_and_options);
  RUN_TEST(itest_tcp_077_mss_from_the_frame_buffers);
  RUN_TEST(itest_tcp_116_options_only_in_syn);
  RUN_TEST(itest_tcp_119_window_scale_not_negotiated);
  RUN_TEST(itest_tcp_182_ip_options);
  RUN_TEST(itest_tcp_082_window_advertised);
  RUN_TEST(itest_tcp_085_zero_window_probe);
  RUN_TEST(itest_tcp_088_receiver_silly_window_avoidance);
  RUN_TEST(itest_tcp_089_small_window_small_segment);
  RUN_TEST(itest_tcp_090_retransmission_schedule);
  RUN_TEST(itest_tcp_097_ack_restarts_or_stops_the_timer);
  RUN_TEST(itest_tcp_091_rto_not_measured);
  RUN_TEST(itest_tcp_108_one_segment_in_flight);
  RUN_TEST(itest_tcp_127_ack_not_delayed);
  RUN_TEST(itest_tcp_133_no_keep_alive);
  RUN_TEST(itest_tcp_139_checksum_sent);
  RUN_TEST(itest_tcp_175_ttl);
  RUN_TEST(itest_tcp_142_buffers_through_their_operations);
#if NET_USE_IPV6
  RUN_TEST(itest_tcp_020_ipv6_checksum_and_default_mss);
  RUN_TEST(itest_tcp_023_local_address_ipv6);
  RUN_TEST(itest_tcp_135_packet_too_big_ipv6);
  RUN_TEST(itest_tcp_135_unreachable_ipv6);
#endif
  ITEST_REPORT();
  return test_failures;
}
