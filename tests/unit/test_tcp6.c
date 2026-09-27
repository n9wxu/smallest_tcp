/**
 * @file test_tcp6.c
 * @brief Unit tests for TCP over IPv6 (RFC 9293 with RFC 8200 §8).
 *
 * Frames go in through eth_input(); a dual-stack listener serves IPv4 and
 * IPv6.  The state machine itself is covered by test_tcp; these tests
 * check what changes with the address family.  Built with NET_USE_IPV6=1.
 */

#include "eth.h"
#include "ipv4.h"
#include "ipv6.h"
#include "net.h"
#include "net_endian.h"
#include "tcp.h"
#include "tcp_buf.h"
#include "test_main.h"
#include <string.h>

#if !NET_USE_IPV6
#error "test_tcp6 needs NET_USE_IPV6=1"
#endif

/* ── Stub MAC driver ──────────────────────────────────────────────── */

#define MAX_SENT 8
static uint8_t sent[MAX_SENT][1514];
static uint16_t sent_len[MAX_SENT];
static int send_count;

static int stub_init(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_send(void *ctx, const uint8_t *f, uint16_t l) {
  (void)ctx;
  /* MLD reports (Hop-by-Hop + ICMPv6 131/132/143) belong to test_mld */
  if (l > 62 && f[12] == 0x86 && f[13] == 0xDD && f[20] == 0 && f[54] == 58 &&
      (f[62] == 143 || f[62] == 131 || f[62] == 132))
    return (int)l;
  int i = send_count < MAX_SENT ? send_count : MAX_SENT - 1;
  memcpy(sent[i], f, l);
  sent_len[i] = l;
  send_count++;
  return (int)l;
}
static int stub_poll(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_peek(void *ctx, uint16_t o, uint8_t *b, uint16_t l) {
  (void)ctx;
  (void)o;
  (void)b;
  (void)l;
  return 0;
}
static void stub_discard(void *ctx) { (void)ctx; }
static void stub_close(void *ctx) { (void)ctx; }

static const net_mac_t stub_drv = {
    .init = stub_init,
    .send = stub_send,
    .poll = stub_poll,
    .peek = stub_peek,
    .discard = stub_discard,
    .close = stub_close,
};

/* ── Addresses ────────────────────────────────────────────────────── */

static const uint8_t our_mac[6] = NET_DEFAULT_MAC;
static const uint8_t peer_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
static const uint8_t our_ll[16] = {0xFE, 0x80, 0, 0,    0,    0,    0,    0,
                                   0,    0,    0, 0xFF, 0xFE, 0xDE, 0xAD, 0x01};
static const uint8_t peer_ll[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                    0,    0,    0, 0, 0, 0, 0, 1};
static const uint8_t peer2_ll[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                     0,    0,    0, 0, 0, 0, 0, 2};
static const uint8_t our_global[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
                                       0,    0,    0,    0,    0, 0, 0, 0x99};
static const uint8_t peer_global[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
                                        0,    0,    0,    0,    0, 0, 0, 0x01};
static const uint8_t all_nodes[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                      0,    0,    0, 0, 0, 0, 0, 1};
static const uint8_t mac_all_nodes[6] = {0x33, 0x33, 0, 0, 0, 1};

#define PEER_PORT 50000u
#define ECHO_PORT 7u
#define PEER_ISS 1000u

/* ── Fixture ──────────────────────────────────────────────────────── */

static uint8_t rx_buf[1514], tx_buf[1514];
static net_t net;
static uint8_t tx_mem[1024], rx_mem[1024];
static tcp_saw_tx_ctx_t tx_ctx;
static tcp_saw_rx_ctx_t rx_ctx;
static tcp_conn_t conn;
static tcp_conn_t *table[1];
static int evt_connected, evt_data, evt_reset;

static void on_event(tcp_conn_t *c, uint8_t ev) {
  (void)c;
  if (ev & TCP_EVT_CONNECTED)
    evt_connected++;
  if (ev & TCP_EVT_DATA)
    evt_data++;
  if (ev & TCP_EVT_RESET)
    evt_reset++;
}

static void reset_sent(void) {
  memset(sent, 0, sizeof(sent));
  send_count = 0;
}

/** IPv6 up (link-local preferred), one connection registered. */
static void setup_cap(uint16_t tx_cap, int start_ipv6) {
  int ctx = 0;
  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, tx_cap, NULL, &stub_drv, &ctx);
  if (start_ipv6) {
    ipv6_start(&net);
    ipv6_tick(&net, 1000);
    ipv6_tick(&net, 1000);
  }
  tcp_saw_tx_init(&tx_ctx, tx_mem, sizeof(tx_mem));
  tcp_saw_rx_init(&rx_ctx, rx_mem, sizeof(rx_mem));
  tcp_conn_init(&conn, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops, &rx_ctx,
                on_event);
  table[0] = &conn;
  tcp_set_connections(&net, table, 1);
  evt_connected = evt_data = evt_reset = 0;
  reset_sent();
}

static void setup(void) { setup_cap(sizeof(tx_buf), 1); }

/** A global address in slot 1, as SLAAC will add (stage 4). */
static void add_global(void) {
  memcpy(net.ip6.addr[1].addr, our_global, 16);
  net.ip6.addr[1].state = NET_IP6_PREFERRED;
}

/* ── Frames ───────────────────────────────────────────────────────── */

/** Ethernet + IPv6 + TCP segment from src to dst; MSS option if mss. */
static uint16_t tcp6_frame(uint8_t *f, const uint8_t *src, const uint8_t *dst,
                           uint16_t sport, uint16_t dport, uint32_t seq,
                           uint32_t ack, uint8_t flags, const char *data,
                           uint16_t mss) {
  uint16_t dlen = data ? (uint16_t)strlen(data) : 0;
  uint16_t hlen = mss ? 24 : 20;
  uint16_t tlen = (uint16_t)(hlen + dlen);
  memcpy(f, ipv6_is_multicast(dst) ? mac_all_nodes : our_mac, 6);
  memcpy(f + 6, peer_mac, 6);
  net_write16be(f + 12, NET_ETHERTYPE_IPV6);
  ipv6_build(f + 14, tlen, IPV6_NH_TCP, src, dst, 64);
  uint8_t *t = f + 54;
  memset(t, 0, hlen);
  net_write16be(t + TCP_OFF_SPORT, sport);
  net_write16be(t + TCP_OFF_DPORT, dport);
  net_write32be(t + TCP_OFF_SEQ, seq);
  net_write32be(t + TCP_OFF_ACK, ack);
  t[TCP_OFF_DOFF] = (uint8_t)((hlen / 4) << 4);
  t[TCP_OFF_FLAGS] = flags;
  net_write16be(t + TCP_OFF_WINDOW, 4096);
  if (mss) {
    t[20] = TCP_OPT_MSS;
    t[21] = 4;
    net_write16be(t + 22, mss);
  }
  if (dlen)
    memcpy(t + hlen, data, dlen);
  net_write16be(t + TCP_OFF_CKSUM, ipv6_cksum(src, dst, IPV6_NH_TCP, t, tlen));
  return (uint16_t)(54 + tlen);
}

static void input(uint8_t *f, uint16_t len) { eth_input(&net, f, len); }

/* Sent frame i, IPv6 */
static const uint8_t *s_ip6(int i) { return sent[i] + 14; }
static const uint8_t *s_tcp6(int i) { return sent[i] + 54; }
static uint8_t s_flags(int i) { return s_tcp6(i)[TCP_OFF_FLAGS]; }
static uint32_t s_seq(int i) { return net_read32be(s_tcp6(i) + TCP_OFF_SEQ); }
static uint32_t s_ack(int i) { return net_read32be(s_tcp6(i) + TCP_OFF_ACK); }

/** Sent frame i is IPv6/TCP with a valid checksum, from src to dst. */
static int s_tcp6_ok(int i, const uint8_t *src, const uint8_t *dst) {
  const uint8_t *ip = s_ip6(i);
  uint16_t plen = net_read16be(ip + 4);
  return net_read16be(sent[i] + 12) == NET_ETHERTYPE_IPV6 &&
         ip[6] == IPV6_NH_TCP && sent_len[i] == 54 + plen &&
         memcmp(ip + 8, src, 16) == 0 && memcmp(ip + 24, dst, 16) == 0 &&
         ipv6_cksum(ip + 8, ip + 24, IPV6_NH_TCP, ip + 40, plen) == 0;
}

/** MSS option of the SYN in sent frame i (0 if none). */
static uint16_t s_mss(int i) {
  const uint8_t *t = s_tcp6(i);
  if ((t[TCP_OFF_DOFF] >> 4) < 6 || t[20] != TCP_OPT_MSS)
    return 0;
  return net_read16be(t + 22);
}

/** Passive open from peer_ll up to ESTABLISHED; returns our ISS. */
static uint32_t establish(const uint8_t *src, const uint8_t *dst) {
  uint8_t f[256];
  tcp_listen(&conn, ECHO_PORT);
  input(f, tcp6_frame(f, src, dst, PEER_PORT, ECHO_PORT, PEER_ISS, 0,
                      TCP_FLAG_SYN, NULL, 1440));
  uint32_t iss = s_seq(0);
  input(f, tcp6_frame(f, src, dst, PEER_PORT, ECHO_PORT, PEER_ISS + 1, iss + 1,
                      TCP_FLAG_ACK, NULL, 0));
  reset_sent();
  return iss;
}

/* ══ Passive open ═════════════════════════════════════════════════ */

TEST(test_tcp6_syn_ack) {
  uint8_t f[256];
  setup();
  tcp_listen(&conn, ECHO_PORT);
  input(f, tcp6_frame(f, peer_ll, our_ll, PEER_PORT, ECHO_PORT, PEER_ISS, 0,
                      TCP_FLAG_SYN, NULL, 1400));
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_tcp6_ok(0, our_ll, peer_ll));
  ASSERT_MEM_EQ(sent[0], peer_mac, 6);
  ASSERT_EQ(s_ip6(0)[7], NET_IPV6_DEFAULT_HOP_LIMIT);
  ASSERT_EQ(s_flags(0), TCP_FLAG_SYN | TCP_FLAG_ACK);
  ASSERT_EQ(s_ack(0), PEER_ISS + 1);
  ASSERT_EQ(net_read16be(s_tcp6(0) + TCP_OFF_SPORT), ECHO_PORT);
  ASSERT_EQ(net_read16be(s_tcp6(0) + TCP_OFF_DPORT), PEER_PORT);
  /* our MSS over IPv6 from a 1514-byte buffer: 1514 - 14 - 40 - 20 */
  ASSERT_EQ(s_mss(0), 1440);
  ASSERT_EQ(conn.state, TCP_SYN_RECEIVED);
  ASSERT_EQ(conn.ip_ver, 6);
  ASSERT_MEM_EQ(conn.remote_ip6, peer_ll, 16);
  ASSERT_EQ(conn.snd_mss, 1400);
}

TEST(test_tcp6_handshake_and_data) {
  uint8_t f[256], buf[16];
  setup();
  uint32_t iss = establish(peer_ll, our_ll);
  ASSERT_EQ(conn.state, TCP_ESTABLISHED);
  ASSERT_EQ(evt_connected, 1);
  input(f, tcp6_frame(f, peer_ll, our_ll, PEER_PORT, ECHO_PORT, PEER_ISS + 1,
                      iss + 1, TCP_FLAG_ACK | TCP_FLAG_PSH, "ping6", 0));
  ASSERT_EQ(evt_data, 1);
  ASSERT_EQ(send_count, 1); /* ACK */
  ASSERT_TRUE(s_tcp6_ok(0, our_ll, peer_ll));
  ASSERT_EQ(s_ack(0), PEER_ISS + 1 + 5);
  ASSERT_EQ(tcp_recv(&conn, buf, sizeof(buf)), 5);
  ASSERT_MEM_EQ(buf, "ping6", 5);

  reset_sent();
  ASSERT_EQ(tcp_send(&net, &conn, (const uint8_t *)"pong6", 5), 5);
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_tcp6_ok(0, our_ll, peer_ll));
  ASSERT_EQ(s_seq(0), iss + 1);
  ASSERT_MEM_EQ(s_tcp6(0) + 20, "pong6", 5);
}

TEST(test_tcp6_default_peer_mss_is_1220) {
  uint8_t f[256];
  setup();
  tcp_listen(&conn, ECHO_PORT);
  input(f, tcp6_frame(f, peer_ll, our_ll, PEER_PORT, ECHO_PORT, PEER_ISS, 0,
                      TCP_FLAG_SYN, NULL, 0));
  ASSERT_EQ(conn.snd_mss, 1220); /* RFC 9293 §3.7.1 */
}

TEST(test_tcp6_our_mss_from_small_buffer) {
  uint8_t f[256];
  setup();
  net.rx.capacity = 600; /* what we can receive, not what we can send */
  tcp_listen(&conn, ECHO_PORT);
  input(f, tcp6_frame(f, peer_ll, our_ll, PEER_PORT, ECHO_PORT, PEER_ISS, 0,
                      TCP_FLAG_SYN, NULL, 1440));
  ASSERT_EQ(s_mss(0), 600 - 14 - 40 - 20);
}

/* A buffer larger than an Ethernet frame: the MSS is the MTU's, 1440 */
TEST(test_tcp6_our_mss_within_ethernet_mtu) {
  static uint8_t big_rx[2048];
  uint8_t f[256];
  setup();
  net.rx.buf = big_rx;
  net.rx.capacity = sizeof(big_rx);
  tcp_listen(&conn, ECHO_PORT);
  input(f, tcp6_frame(f, peer_ll, our_ll, PEER_PORT, ECHO_PORT, PEER_ISS, 0,
                      TCP_FLAG_SYN, NULL, 1440));
  ASSERT_EQ(s_mss(0), 1440);
}

TEST(test_tcp6_bad_checksum_dropped) {
  uint8_t f[256];
  setup();
  tcp_listen(&conn, ECHO_PORT);
  uint16_t len = tcp6_frame(f, peer_ll, our_ll, PEER_PORT, ECHO_PORT, PEER_ISS,
                            0, TCP_FLAG_SYN, NULL, 1440);
  f[54 + TCP_OFF_SEQ] ^= 1;
  input(f, len);
  ASSERT_EQ(send_count, 0);
  ASSERT_EQ(conn.state, TCP_LISTEN);
}

TEST(test_tcp6_multicast_destination_dropped) {
  uint8_t f[256];
  setup();
  tcp_listen(&conn, ECHO_PORT);
  input(f, tcp6_frame(f, peer_ll, all_nodes, PEER_PORT, ECHO_PORT, PEER_ISS, 0,
                      TCP_FLAG_SYN, NULL, 1440));
  ASSERT_EQ(send_count, 0);
  ASSERT_EQ(conn.state, TCP_LISTEN);
}

/* ══ Resets ═══════════════════════════════════════════════════════ */

TEST(test_tcp6_syn_to_closed_port_rst) {
  uint8_t f[256];
  setup();
  input(f, tcp6_frame(f, peer_ll, our_ll, PEER_PORT, 9999, PEER_ISS, 0,
                      TCP_FLAG_SYN, NULL, 0));
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_tcp6_ok(0, our_ll, peer_ll));
  ASSERT_MEM_EQ(sent[0], peer_mac, 6);
  ASSERT_EQ(s_flags(0), TCP_FLAG_RST | TCP_FLAG_ACK);
  ASSERT_EQ(s_seq(0), 0);
  ASSERT_EQ(s_ack(0), PEER_ISS + 1);
}

TEST(test_tcp6_ack_to_closed_port_rst_seq) {
  uint8_t f[256];
  setup();
  input(f, tcp6_frame(f, peer_ll, our_ll, PEER_PORT, 9999, PEER_ISS, 777,
                      TCP_FLAG_ACK, NULL, 0));
  ASSERT_EQ(send_count, 1);
  ASSERT_EQ(s_flags(0), TCP_FLAG_RST);
  ASSERT_EQ(s_seq(0), 777);
}

TEST(test_tcp6_peer_rst_closes) {
  uint8_t f[256];
  setup();
  establish(peer_ll, our_ll);
  input(f, tcp6_frame(f, peer_ll, our_ll, PEER_PORT, ECHO_PORT, PEER_ISS + 1, 0,
                      TCP_FLAG_RST, NULL, 0));
  ASSERT_EQ(conn.state, TCP_CLOSED);
  ASSERT_EQ(evt_reset, 1);
}

TEST(test_tcp6_other_peer_does_not_match) {
  /* Same port, different IPv6 address: not this connection's segment */
  uint8_t f[256];
  setup();
  uint32_t iss = establish(peer_ll, our_ll);
  input(f, tcp6_frame(f, peer2_ll, our_ll, PEER_PORT, ECHO_PORT, PEER_ISS + 1,
                      iss + 1, TCP_FLAG_ACK | TCP_FLAG_PSH, "intruder", 0));
  ASSERT_EQ(evt_data, 0);
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_tcp6_ok(0, our_ll, peer2_ll));
  ASSERT_EQ(s_flags(0), TCP_FLAG_RST);
}

/* ══ Timers and close ═════════════════════════════════════════════ */

TEST(test_tcp6_syn_ack_retransmitted_over_ipv6) {
  uint8_t f[256];
  setup();
  tcp_listen(&conn, ECHO_PORT);
  input(f, tcp6_frame(f, peer_ll, our_ll, PEER_PORT, ECHO_PORT, PEER_ISS, 0,
                      TCP_FLAG_SYN, NULL, 1440));
  reset_sent();
  tcp_tick(&net, NET_DEFAULT_TCP_RTO_INIT_MS);
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_tcp6_ok(0, our_ll, peer_ll));
  ASSERT_EQ(s_flags(0), TCP_FLAG_SYN | TCP_FLAG_ACK);
}

TEST(test_tcp6_close_sends_fin) {
  setup();
  uint32_t iss = establish(peer_ll, our_ll);
  ASSERT_EQ(tcp_close(&net, &conn), NET_OK);
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_tcp6_ok(0, our_ll, peer_ll));
  ASSERT_TRUE(s_flags(0) & TCP_FLAG_FIN);
  ASSERT_EQ(s_seq(0), iss + 1);
}

/* ══ Addresses ════════════════════════════════════════════════════ */

TEST(test_tcp6_reply_from_the_address_used) {
  /* A peer that connects to our global address gets answers from it */
  uint8_t f[256];
  setup();
  add_global();
  tcp_listen(&conn, ECHO_PORT);
  input(f, tcp6_frame(f, peer_global, our_global, PEER_PORT, ECHO_PORT,
                      PEER_ISS, 0, TCP_FLAG_SYN, NULL, 1440));
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_tcp6_ok(0, our_global, peer_global));
  uint32_t iss = s_seq(0);
  input(f, tcp6_frame(f, peer_global, our_global, PEER_PORT, ECHO_PORT,
                      PEER_ISS + 1, iss + 1, TCP_FLAG_ACK, NULL, 0));
  reset_sent();
  tcp_send(&net, &conn, (const uint8_t *)"g", 1);
  ASSERT_TRUE(s_tcp6_ok(0, our_global, peer_global));
}

/** An IPv4 SYN from 10.0.0.1, with an MSS option if mss. */
static uint16_t tcp4_syn(uint8_t *f, uint16_t mss) {
  uint16_t hlen = mss ? 24 : 20;
  memcpy(f, our_mac, 6);
  memcpy(f + 6, peer_mac, 6);
  net_write16be(f + 12, NET_ETHERTYPE_IPV4);
  uint8_t *t = f + 34;
  memset(t, 0, hlen);
  net_write16be(t + TCP_OFF_SPORT, PEER_PORT);
  net_write16be(t + TCP_OFF_DPORT, ECHO_PORT);
  net_write32be(t + TCP_OFF_SEQ, PEER_ISS);
  t[TCP_OFF_DOFF] = (uint8_t)((hlen / 4) << 4);
  t[TCP_OFF_FLAGS] = TCP_FLAG_SYN;
  net_write16be(t + TCP_OFF_WINDOW, 4096);
  if (mss) {
    t[20] = TCP_OPT_MSS;
    t[21] = 4;
    net_write16be(t + 22, mss);
  }
  net_write16be(t + TCP_OFF_CKSUM,
                ipv4_cksum(NET_IPV4(10, 0, 0, 1), NET_DEFAULT_IPV4_ADDR,
                           IPV4_PROTO_TCP, t, hlen));
  ipv4_build(f + 14, hlen, IPV4_PROTO_TCP, NET_IPV4(10, 0, 0, 1),
             NET_DEFAULT_IPV4_ADDR);
  return (uint16_t)(34 + hlen);
}

TEST(test_tcp6_listener_also_serves_ipv4) {
  uint8_t f[256];
  setup();
  tcp_listen(&conn, ECHO_PORT);
  input(f, tcp4_syn(f, 0));
  ASSERT_EQ(send_count, 1);
  ASSERT_EQ(net_read16be(sent[0] + 12), NET_ETHERTYPE_IPV4);
  ASSERT_EQ(conn.ip_ver, 4);
  ASSERT_EQ(conn.remote_ip, NET_IPV4(10, 0, 0, 1));
  ASSERT_EQ(conn.snd_mss, 536); /* IPv4 default without an MSS option */
  ASSERT_EQ(sent[0][34 + TCP_OFF_FLAGS], TCP_FLAG_SYN | TCP_FLAG_ACK);
}

/* ══ Send MSS fits our TX frame buffer ════════════════════════════ */

TEST(test_tcp6_peer_mss_clamped_to_tx_buffer) {
  /* A 600-byte TX frame buffer carries 526 bytes of TCP over IPv6: a
   * larger MSS from the peer must not produce segments that can't be
   * built (they would never be sent) */
  uint8_t f[256];
  static char big[700];
  setup_cap(600, 1);
  tcp_listen(&conn, ECHO_PORT);
  input(f, tcp6_frame(f, peer_ll, our_ll, PEER_PORT, ECHO_PORT, PEER_ISS, 0,
                      TCP_FLAG_SYN, NULL, 1440));
  ASSERT_EQ(conn.snd_mss, 526);
  uint32_t iss = s_seq(0);
  input(f, tcp6_frame(f, peer_ll, our_ll, PEER_PORT, ECHO_PORT, PEER_ISS + 1,
                      iss + 1, TCP_FLAG_ACK, NULL, 0));
  reset_sent();
  memset(big, 'b', sizeof(big) - 1);
  tcp_send(&net, &conn, (const uint8_t *)big, sizeof(big) - 1);
  ASSERT_EQ(send_count, 1);
  ASSERT_EQ(sent_len[0], 600);
}

TEST(test_tcp4_peer_mss_clamped_to_tx_buffer) {
  uint8_t f[256];
  setup_cap(600, 1);
  tcp_listen(&conn, ECHO_PORT);
  input(f, tcp4_syn(f, 1460));
  ASSERT_EQ(conn.snd_mss, 600 - 14 - 20 - 20);
}

/* ══ Active open ══════════════════════════════════════════════════ */

TEST(test_tcp6_connect) {
  uint8_t f[256];
  setup();
  ASSERT_EQ(tcp6_connect(&net, &conn, peer_ll, peer_mac, 80, 40001), NET_OK);
  ASSERT_EQ(conn.state, TCP_SYN_SENT);
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_tcp6_ok(0, our_ll, peer_ll));
  ASSERT_EQ(s_flags(0), TCP_FLAG_SYN);
  ASSERT_EQ(s_mss(0), 1440);
  uint32_t iss = s_seq(0);
  reset_sent();
  input(f, tcp6_frame(f, peer_ll, our_ll, 80, 40001, 5000, iss + 1,
                      TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 1200));
  ASSERT_EQ(conn.state, TCP_ESTABLISHED);
  ASSERT_EQ(evt_connected, 1);
  ASSERT_EQ(conn.snd_mss, 1200);
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(s_tcp6_ok(0, our_ll, peer_ll));
  ASSERT_EQ(s_flags(0), TCP_FLAG_ACK);
  ASSERT_EQ(s_ack(0), 5001);
}

TEST(test_tcp6_connect_without_source_fails) {
  setup_cap(sizeof(tx_buf), 0); /* IPv6 not started */
  ASSERT_NE(tcp6_connect(&net, &conn, peer_ll, peer_mac, 80, 40001), NET_OK);
  ASSERT_EQ(send_count, 0);
  ASSERT_EQ(conn.state, TCP_CLOSED);
}

int main(void) {
  fprintf(stderr, "=== TCP over IPv6 tests ===\n");
  RUN_TEST(test_tcp6_syn_ack);
  RUN_TEST(test_tcp6_handshake_and_data);
  RUN_TEST(test_tcp6_default_peer_mss_is_1220);
  RUN_TEST(test_tcp6_our_mss_from_small_buffer);
  RUN_TEST(test_tcp6_our_mss_within_ethernet_mtu);
  RUN_TEST(test_tcp6_bad_checksum_dropped);
  RUN_TEST(test_tcp6_multicast_destination_dropped);
  RUN_TEST(test_tcp6_syn_to_closed_port_rst);
  RUN_TEST(test_tcp6_ack_to_closed_port_rst_seq);
  RUN_TEST(test_tcp6_peer_rst_closes);
  RUN_TEST(test_tcp6_other_peer_does_not_match);
  RUN_TEST(test_tcp6_syn_ack_retransmitted_over_ipv6);
  RUN_TEST(test_tcp6_close_sends_fin);
  RUN_TEST(test_tcp6_reply_from_the_address_used);
  RUN_TEST(test_tcp6_listener_also_serves_ipv4);
  RUN_TEST(test_tcp6_peer_mss_clamped_to_tx_buffer);
  RUN_TEST(test_tcp4_peer_mss_clamped_to_tx_buffer);
  RUN_TEST(test_tcp6_connect);
  RUN_TEST(test_tcp6_connect_without_source_fails);
  TEST_REPORT();
  return test_failures;
}
