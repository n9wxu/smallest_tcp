/**
 * @file test_tcp.c
 * @brief Unit tests for the TCP state machine (tcp.c) + checksum.
 *
 * Tests the three-way handshake (passive and active open), data transfer,
 * graceful close, RST handling, retransmit timer, and checksum.
 *
 * All network I/O is intercepted via a stub MAC driver. Tests craft raw
 * TCP-over-IPv4-over-Ethernet frames by hand and inject them via tcp_input.
 *
 * REQ-TCP-001..100.
 */

#include "eth.h"
#include "ipv4.h"
#include "net.h"
#include "net_endian.h"
#include "tcp.h"
#include "tcp_buf.h"
#include "test_main.h"
#include <string.h>

/* ── Stub MAC driver ──────────────────────────────────────────────── */

static uint8_t sent_frames[8][1514];
static uint16_t sent_lens[8];
static int send_count;

static int stub_init(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_send(void *ctx, const uint8_t *f, uint16_t l) {
  (void)ctx;
  int idx = send_count < 8 ? send_count : 7;
  memcpy(sent_frames[idx], f, l);
  sent_lens[idx] = l;
  send_count++;
  return (int)l;
}
static int stub_recv(void *ctx, uint8_t *f, uint16_t m) {
  (void)ctx;
  (void)f;
  (void)m;
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

static const net_mac_t stub_mac_drv = {
    .init = stub_init,
    .send = stub_send,
    .recv = stub_recv,
    .peek = stub_peek,
    .discard = stub_discard,
    .close = stub_close,
};

/* ── Test fixture ─────────────────────────────────────────────────── */

#define TX_BUF_CAP 1024u
#define RX_BUF_CAP 1024u
#define NET_BUF_CAP 1514u

static uint8_t net_rx_buf[NET_BUF_CAP], net_tx_buf[NET_BUF_CAP];
static net_t net;

static uint8_t tcp_tx_mem[TX_BUF_CAP], tcp_rx_mem[RX_BUF_CAP];
static tcp_saw_tx_ctx_t tcp_tx_ctx;
static tcp_saw_rx_ctx_t tcp_rx_ctx;
static tcp_conn_t conn;
static tcp_conn_t *conn_table[1];

/* Event tracking */
static int evt_connected, evt_data, evt_writable, evt_closed, evt_reset,
    evt_error;

static void on_event(tcp_conn_t *c, uint8_t ev) {
  (void)c;
  if (ev & TCP_EVT_CONNECTED)
    evt_connected++;
  if (ev & TCP_EVT_DATA)
    evt_data++;
  if (ev & TCP_EVT_WRITABLE)
    evt_writable++;
  if (ev & TCP_EVT_CLOSED)
    evt_closed++;
  if (ev & TCP_EVT_RESET)
    evt_reset++;
  if (ev & TCP_EVT_ERROR)
    evt_error++;
}

static void setup(void) {
  int ctx = 0;
  memset(&net, 0, sizeof(net));
  memset(sent_frames, 0, sizeof(sent_frames));
  memset(sent_lens, 0, sizeof(sent_lens));
  send_count = 0;
  evt_connected = evt_data = evt_writable = evt_closed = evt_reset = evt_error =
      0;

  net_init(&net, net_rx_buf, sizeof(net_rx_buf), net_tx_buf, sizeof(net_tx_buf),
           NULL, &stub_mac_drv, &ctx);

  tcp_saw_tx_init(&tcp_tx_ctx, tcp_tx_mem, TX_BUF_CAP);
  tcp_saw_rx_init(&tcp_rx_ctx, tcp_rx_mem, RX_BUF_CAP);

  tcp_conn_init(&conn, &tcp_saw_tx_ops, &tcp_tx_ctx, &tcp_saw_rx_ops,
                &tcp_rx_ctx, on_event);

  conn_table[0] = &conn;
  tcp_connections.conns = conn_table;
  tcp_connections.count = 1;
}

/* ── Frame building helpers ───────────────────────────────────────── */

static const uint8_t remote_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
static const uint8_t our_mac[6] = NET_DEFAULT_MAC;

#define REMOTE_IP NET_IPV4(10, 0, 0, 1)
#define LOCAL_IP NET_DEFAULT_IPV4_ADDR
#define REMOTE_PORT 54321u
#define LOCAL_PORT 7u

/**
 * Build a raw TCP segment into frame[].
 * Returns total frame length.
 */
static uint16_t build_tcp_frame(uint8_t *frame, uint32_t src_ip,
                                uint16_t src_port, uint16_t dst_port,
                                uint32_t seq, uint32_t ack, uint8_t flags,
                                uint16_t window, const uint8_t *data,
                                uint16_t data_len, uint16_t peer_mss) {
  /* ETH */
  memcpy(frame + 0, our_mac, 6);
  memcpy(frame + 6, remote_mac, 6);
  net_write16be(frame + 12, NET_ETHERTYPE_IPV4);

  /* TCP */
  uint8_t *ip = frame + ETH_HDR_SIZE;
  uint8_t *tcp = ip + IPV4_HDR_SIZE;
  uint8_t hdr_words = peer_mss ? 6u : 5u;
  uint16_t hdr_len = (uint16_t)hdr_words * 4u;
  uint16_t tcp_len = hdr_len + data_len;

  net_write16be(tcp + TCP_OFF_SPORT, src_port);
  net_write16be(tcp + TCP_OFF_DPORT, dst_port);
  net_write32be(tcp + TCP_OFF_SEQ, seq);
  net_write32be(tcp + TCP_OFF_ACK, ack);
  tcp[TCP_OFF_DOFF] = (uint8_t)(hdr_words << 4);
  tcp[TCP_OFF_FLAGS] = flags;
  net_write16be(tcp + TCP_OFF_WINDOW, window);
  net_write16be(tcp + TCP_OFF_CKSUM, 0);
  net_write16be(tcp + TCP_OFF_URG, 0);

  if (peer_mss) {
    tcp[TCP_OFF_OPT + 0] = TCP_OPT_MSS;
    tcp[TCP_OFF_OPT + 1] = 4;
    net_write16be(tcp + TCP_OFF_OPT + 2, peer_mss);
  }
  if (data && data_len > 0)
    memcpy(tcp + hdr_len, data, data_len);

  uint16_t ck = tcp_checksum(src_ip, LOCAL_IP, tcp, tcp_len);
  net_write16be(tcp + TCP_OFF_CKSUM, ck);

  ipv4_build(ip, tcp_len, IPV4_PROTO_TCP, src_ip, LOCAL_IP);

  return (uint16_t)(ETH_HDR_SIZE + IPV4_HDR_SIZE + tcp_len);
}

/* Parse the flags byte from the Nth sent frame (0-based) */
static uint8_t sent_tcp_flags(int n) {
  return sent_frames[n][ETH_HDR_SIZE + IPV4_HDR_SIZE + TCP_OFF_FLAGS];
}
static uint32_t sent_tcp_seq(int n) {
  return net_read32be(sent_frames[n] + ETH_HDR_SIZE + IPV4_HDR_SIZE +
                      TCP_OFF_SEQ);
}
static uint32_t sent_tcp_ack(int n) {
  return net_read32be(sent_frames[n] + ETH_HDR_SIZE + IPV4_HDR_SIZE +
                      TCP_OFF_ACK);
}

/* Inject a frame into the stack */
static void inject(uint8_t *frame, uint16_t len) {
  eth_frame_t eth;
  eth_parse(frame, len, &eth);
  ipv4_hdr_t ip;
  if (ipv4_parse(eth.payload, eth.payload_len, &ip) != NET_OK)
    return;
  tcp_input(&net, &ip, &eth);
}

/* ══════════════════════════════════════════════════════════════════
 * Checksum tests (REQ-TCP-018, REQ-TCP-019)
 * ══════════════════════════════════════════════════════════════════ */

TEST(test_tcp_checksum_basic) {
  /* Build a minimal TCP header and verify round-trip checksum */
  uint8_t tcp_seg[20];
  memset(tcp_seg, 0, sizeof(tcp_seg));
  net_write16be(tcp_seg + TCP_OFF_SPORT, 12345);
  net_write16be(tcp_seg + TCP_OFF_DPORT, 80);
  net_write32be(tcp_seg + TCP_OFF_SEQ, 0x01020304u);
  net_write32be(tcp_seg + TCP_OFF_ACK, 0u);
  tcp_seg[TCP_OFF_DOFF] = (5u << 4);
  tcp_seg[TCP_OFF_FLAGS] = TCP_FLAG_SYN;
  net_write16be(tcp_seg + TCP_OFF_WINDOW, 4096);

  uint16_t ck = tcp_checksum(REMOTE_IP, LOCAL_IP, tcp_seg, 20);
  ASSERT_NE(ck, 0); /* Non-trivial payload should produce non-zero */

  /* Store checksum and re-compute — should yield 0xFFFF or 0x0000 */
  net_write16be(tcp_seg + TCP_OFF_CKSUM, ck);
  uint16_t verify = tcp_checksum(REMOTE_IP, LOCAL_IP, tcp_seg, 20);
  ASSERT_TRUE(verify == 0xFFFFu || verify == 0x0000u);
}

/* ══════════════════════════════════════════════════════════════════
 * Passive open: three-way handshake (server side)
 * REQ-TCP-002, REQ-TCP-032..REQ-TCP-035
 * ══════════════════════════════════════════════════════════════════ */

TEST(test_tcp_passive_open_syn_synack_ack) {
  setup();
  tcp_listen(&conn, LOCAL_PORT);
  ASSERT_EQ(conn.state, TCP_LISTEN);

  /* Step 1: Receive SYN from client */
  uint8_t frame[256];
  uint16_t len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT,
                                 1000u, 0u, TCP_FLAG_SYN, 4096, NULL, 0, 536);
  inject(frame, len);

  /* Stack must have sent SYN-ACK */
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE((sent_tcp_flags(0) & TCP_FLAG_SYN) != 0);
  ASSERT_TRUE((sent_tcp_flags(0) & TCP_FLAG_ACK) != 0);
  ASSERT_EQ(sent_tcp_ack(0), 1001u); /* ACK = client ISN + 1 */
  ASSERT_EQ(conn.state, TCP_SYN_RECEIVED);

  uint32_t our_isn = sent_tcp_seq(0);

  /* Step 2: Client sends ACK to our SYN-ACK */
  send_count = 0;
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 1001u,
                        our_isn + 1u, TCP_FLAG_ACK, 4096, NULL, 0, 0);
  inject(frame, len);

  ASSERT_EQ(conn.state, TCP_ESTABLISHED);
  ASSERT_EQ(evt_connected, 1);
}

/* ══════════════════════════════════════════════════════════════════
 * Active open: three-way handshake (client side)
 * REQ-TCP-003, REQ-TCP-036..REQ-TCP-038
 * ══════════════════════════════════════════════════════════════════ */

TEST(test_tcp_active_open_syn_synack_ack) {
  setup();
  tcp_connect(&net, &conn, REMOTE_IP, remote_mac, REMOTE_PORT, LOCAL_PORT);
  ASSERT_EQ(conn.state, TCP_SYN_SENT);
  ASSERT_EQ(send_count, 1);
  /* SYN must have been sent */
  ASSERT_TRUE((sent_tcp_flags(0) & TCP_FLAG_SYN) != 0);
  ASSERT_EQ((sent_tcp_flags(0) & TCP_FLAG_ACK), 0); /* Pure SYN */

  uint32_t our_isn = sent_tcp_seq(0);
  send_count = 0;

  /* Server replies with SYN-ACK */
  uint8_t frame[256];
  uint16_t len = build_tcp_frame(
      frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 5000u, our_isn + 1u,
      TCP_FLAG_SYN | TCP_FLAG_ACK, 8192, NULL, 0, 536);
  inject(frame, len);

  ASSERT_EQ(conn.state, TCP_ESTABLISHED);
  ASSERT_EQ(evt_connected, 1);
  /* Stack must have sent ACK */
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE((sent_tcp_flags(0) & TCP_FLAG_ACK) != 0);
  ASSERT_EQ(sent_tcp_ack(0), 5001u); /* ACK = server ISN + 1 */
}

/* ══════════════════════════════════════════════════════════════════
 * Data transfer: send and receive
 * REQ-TCP-014, REQ-TCP-064..REQ-TCP-067
 * ══════════════════════════════════════════════════════════════════ */

TEST(test_tcp_data_receive) {
  setup();
  /* Bring connection to ESTABLISHED */
  tcp_listen(&conn, LOCAL_PORT);
  uint8_t frame[512];
  uint16_t len;
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 1000u, 0u,
                        TCP_FLAG_SYN, 4096, NULL, 0, 536);
  inject(frame, len);
  uint32_t our_isn = sent_tcp_seq(0);
  send_count = 0;
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 1001u,
                        our_isn + 1u, TCP_FLAG_ACK, 4096, NULL, 0, 0);
  inject(frame, len);
  ASSERT_EQ(conn.state, TCP_ESTABLISHED);
  send_count = 0;

  /* Send data segment from peer */
  uint8_t data[5] = {'H', 'e', 'l', 'l', 'o'};
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 1001u,
                        our_isn + 1u, TCP_FLAG_ACK | TCP_FLAG_PSH, 4096, data,
                        5, 0);
  inject(frame, len);

  ASSERT_EQ(evt_data, 1);
  ASSERT_EQ(send_count, 1); /* ACK sent */
  ASSERT_TRUE((sent_tcp_flags(0) & TCP_FLAG_ACK) != 0);

  /* Read the data */
  uint8_t out[10];
  uint16_t n = tcp_recv(&conn, out, sizeof(out));
  ASSERT_EQ(n, 5);
  ASSERT_MEM_EQ(out, data, 5);
}

TEST(test_tcp_data_send) {
  setup();
  /* Bring to ESTABLISHED (active open) */
  tcp_connect(&net, &conn, REMOTE_IP, remote_mac, REMOTE_PORT, LOCAL_PORT);
  uint32_t our_isn = sent_tcp_seq(0);
  send_count = 0;

  uint8_t frame[512];
  uint16_t len = build_tcp_frame(
      frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 5000u, our_isn + 1u,
      TCP_FLAG_SYN | TCP_FLAG_ACK, 8192, NULL, 0, 1460);
  inject(frame, len);
  ASSERT_EQ(conn.state, TCP_ESTABLISHED);
  send_count = 0;

  /* Send data */
  uint8_t payload[4] = {0x01, 0x02, 0x03, 0x04};
  int accepted = tcp_send(&net, &conn, payload, 4);
  ASSERT_EQ(accepted, 4);
  ASSERT_EQ(send_count, 1); /* Segment should have been sent immediately */

  /* Check the sent frame contains our payload */
  uint8_t *tcp_seg =
      sent_frames[0] + ETH_HDR_SIZE + IPV4_HDR_SIZE + TCP_HDR_SIZE;
  ASSERT_MEM_EQ(tcp_seg, payload, 4);
}

/* ══════════════════════════════════════════════════════════════════
 * Graceful close (active): FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT
 * REQ-TCP-005, REQ-TCP-059, REQ-TCP-071
 * ══════════════════════════════════════════════════════════════════ */

TEST(test_tcp_active_close) {
  setup();
  /* Bring to ESTABLISHED (passive open) */
  tcp_listen(&conn, LOCAL_PORT);
  uint8_t frame[512];
  uint16_t len;
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 2000u, 0u,
                        TCP_FLAG_SYN, 4096, NULL, 0, 536);
  inject(frame, len);
  uint32_t our_isn = sent_tcp_seq(0);
  send_count = 0;
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 2001u,
                        our_isn + 1u, TCP_FLAG_ACK, 4096, NULL, 0, 0);
  inject(frame, len);
  ASSERT_EQ(conn.state, TCP_ESTABLISHED);
  send_count = 0;

  /* We initiate close */
  tcp_close(&net, &conn);
  ASSERT_EQ(conn.state, TCP_FIN_WAIT_1);
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE((sent_tcp_flags(0) & TCP_FLAG_FIN) != 0);

  uint32_t our_fin_seq = sent_tcp_seq(0);
  send_count = 0;

  /* Peer ACKs our FIN → FIN_WAIT_2 */
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 2001u,
                        our_fin_seq + 1u, TCP_FLAG_ACK, 4096, NULL, 0, 0);
  inject(frame, len);
  ASSERT_EQ(conn.state, TCP_FIN_WAIT_2);

  /* Peer sends their FIN → TIME_WAIT */
  send_count = 0;
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 2001u,
                        our_fin_seq + 1u, TCP_FLAG_FIN | TCP_FLAG_ACK, 4096,
                        NULL, 0, 0);
  inject(frame, len);
  ASSERT_EQ(conn.state, TCP_TIME_WAIT);
  ASSERT_EQ(send_count, 1); /* ACK for peer FIN */
}

/* ══════════════════════════════════════════════════════════════════
 * Passive close: CLOSE_WAIT → LAST_ACK → CLOSED
 * REQ-TCP-006, REQ-TCP-062
 * ══════════════════════════════════════════════════════════════════ */

TEST(test_tcp_passive_close) {
  setup();
  tcp_listen(&conn, LOCAL_PORT);
  uint8_t frame[512];
  uint16_t len;
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 3000u, 0u,
                        TCP_FLAG_SYN, 4096, NULL, 0, 536);
  inject(frame, len);
  uint32_t our_isn = sent_tcp_seq(0);
  send_count = 0;
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 3001u,
                        our_isn + 1u, TCP_FLAG_ACK, 4096, NULL, 0, 0);
  inject(frame, len);
  ASSERT_EQ(conn.state, TCP_ESTABLISHED);
  send_count = 0;

  /* Peer sends FIN → CLOSE_WAIT */
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 3001u,
                        our_isn + 1u, TCP_FLAG_FIN | TCP_FLAG_ACK, 4096, NULL,
                        0, 0);
  inject(frame, len);
  ASSERT_EQ(conn.state, TCP_CLOSE_WAIT);
  ASSERT_EQ(evt_closed, 1); /* Application notified */
  send_count = 0;

  /* App calls tcp_close → LAST_ACK */
  tcp_close(&net, &conn);
  ASSERT_EQ(conn.state, TCP_LAST_ACK);
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE((sent_tcp_flags(0) & TCP_FLAG_FIN) != 0);
  uint32_t our_fin_seq = sent_tcp_seq(0);
  send_count = 0;

  /* Peer ACKs our FIN → CLOSED */
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 3002u,
                        our_fin_seq + 1u, TCP_FLAG_ACK, 4096, NULL, 0, 0);
  inject(frame, len);
  ASSERT_EQ(conn.state, TCP_CLOSED);
  ASSERT_EQ(evt_closed, 2); /* CLOSED event fires again */
}

/* ══════════════════════════════════════════════════════════════════
 * RST handling (REQ-TCP-046, REQ-TCP-047, REQ-TCP-075)
 * ══════════════════════════════════════════════════════════════════ */

TEST(test_tcp_rst_in_established_aborts) {
  setup();
  tcp_listen(&conn, LOCAL_PORT);
  uint8_t frame[512];
  uint16_t len;
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 4000u, 0u,
                        TCP_FLAG_SYN, 4096, NULL, 0, 536);
  inject(frame, len);
  uint32_t our_isn = sent_tcp_seq(0);
  send_count = 0;
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 4001u,
                        our_isn + 1u, TCP_FLAG_ACK, 4096, NULL, 0, 0);
  inject(frame, len);
  ASSERT_EQ(conn.state, TCP_ESTABLISHED);

  /* Peer sends RST */
  send_count = 0;
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 4001u,
                        our_isn + 1u, TCP_FLAG_RST, 0, NULL, 0, 0);
  inject(frame, len);
  ASSERT_EQ(conn.state, TCP_CLOSED);
  ASSERT_EQ(evt_reset, 1);
}

TEST(test_tcp_no_rst_in_listen_for_rst) {
  /* REQ-TCP-075: RST arriving in LISTEN must be silently discarded */
  setup();
  tcp_listen(&conn, LOCAL_PORT);
  uint8_t frame[256];
  uint16_t len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT,
                                 8000u, 0u, TCP_FLAG_RST, 0, NULL, 0, 0);
  inject(frame, len);
  ASSERT_EQ(conn.state, TCP_LISTEN); /* No state change */
  ASSERT_EQ(send_count, 0);          /* No RST response */
}

TEST(test_tcp_rst_sent_for_unknown_port) {
  /* REQ-TCP-072: no matching connection → RST */
  setup();
  tcp_listen(&conn, LOCAL_PORT);
  uint8_t frame[256];
  /* Send SYN to a port we're NOT listening on */
  uint16_t len =
      build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, 9999u /* wrong port */,
                      9000u, 0u, TCP_FLAG_SYN, 4096, NULL, 0, 0);
  inject(frame, len);
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE((sent_tcp_flags(0) & TCP_FLAG_RST) != 0);
}

/* ══════════════════════════════════════════════════════════════════
 * TIME_WAIT expiry (REQ-TCP-008)
 * ══════════════════════════════════════════════════════════════════ */

TEST(test_tcp_timewait_expires) {
  setup();
  tcp_listen(&conn, LOCAL_PORT);
  uint8_t frame[512];
  uint16_t len;
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 5000u, 0u,
                        TCP_FLAG_SYN, 4096, NULL, 0, 536);
  inject(frame, len);
  uint32_t our_isn = sent_tcp_seq(0);
  send_count = 0;
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 5001u,
                        our_isn + 1u, TCP_FLAG_ACK, 4096, NULL, 0, 0);
  inject(frame, len);

  /* Fast-track to TIME_WAIT via close sequence */
  tcp_close(&net, &conn);
  /* send_count was 0 before tcp_close, so the FIN is at slot 0 */
  uint32_t fin_seq = sent_tcp_seq(0);
  send_count = 0;

  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 5001u,
                        fin_seq + 1u, TCP_FLAG_ACK, 4096, NULL, 0, 0);
  inject(frame, len);
  ASSERT_EQ(conn.state, TCP_FIN_WAIT_2);

  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 5001u,
                        fin_seq + 1u, TCP_FLAG_FIN | TCP_FLAG_ACK, 4096, NULL,
                        0, 0);
  inject(frame, len);
  ASSERT_EQ(conn.state, TCP_TIME_WAIT);

  /* Tick past 2×MSL */
  tcp_tick(&net, NET_DEFAULT_TCP_MSL_MS * 2u + 1u);
  ASSERT_EQ(conn.state, TCP_CLOSED);
  ASSERT_TRUE(evt_closed >= 1);
}

/* ══════════════════════════════════════════════════════════════════
 * Retransmit timer (REQ-TCP-090..100)
 * ══════════════════════════════════════════════════════════════════ */

TEST(test_tcp_retransmit_on_timeout) {
  setup();
  /* Active open — SYN not answered → retransmit */
  tcp_connect(&net, &conn, REMOTE_IP, remote_mac, REMOTE_PORT, LOCAL_PORT);
  ASSERT_EQ(send_count, 1); /* Initial SYN */
  ASSERT_EQ(conn.state, TCP_SYN_SENT);

  send_count = 0;
  /* Advance past RTO */
  tcp_tick(&net, NET_DEFAULT_TCP_RTO_INIT_MS + 1u);
  ASSERT_EQ(send_count, 1); /* Retransmit SYN */
  ASSERT_TRUE((sent_tcp_flags(0) & TCP_FLAG_SYN) != 0);
  ASSERT_EQ(conn.rto_ms, NET_DEFAULT_TCP_RTO_INIT_MS * 2u); /* Doubled */
}

TEST(test_tcp_rto_resets_on_ack) {
  setup();
  /* Active open, complete handshake */
  tcp_connect(&net, &conn, REMOTE_IP, remote_mac, REMOTE_PORT, LOCAL_PORT);
  uint32_t our_isn = sent_tcp_seq(0);
  send_count = 0;

  uint8_t frame[512];
  uint16_t len = build_tcp_frame(
      frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 6000u, our_isn + 1u,
      TCP_FLAG_SYN | TCP_FLAG_ACK, 8192, NULL, 0, 1460);
  inject(frame, len);
  ASSERT_EQ(conn.state, TCP_ESTABLISHED);

  /* Send some data */
  send_count = 0;
  uint8_t data[4] = {1, 2, 3, 4};
  tcp_send(&net, &conn, data, 4);
  ASSERT_EQ(send_count, 1);
  ASSERT_TRUE(conn.rto_active); /* Timer running */

  /* Peer ACKs the data */
  send_count = 0;
  uint32_t data_seq = sent_tcp_seq(0);
  len = build_tcp_frame(frame, REMOTE_IP, REMOTE_PORT, LOCAL_PORT, 6001u,
                        data_seq + 4u, TCP_FLAG_ACK, 8192, NULL, 0, 0);
  inject(frame, len);

  ASSERT_FALSE(conn.rto_active); /* Timer stopped */
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void) {
  fprintf(stderr, "=== test_tcp ===\n");
  RUN_TEST(test_tcp_checksum_basic);
  RUN_TEST(test_tcp_passive_open_syn_synack_ack);
  RUN_TEST(test_tcp_active_open_syn_synack_ack);
  RUN_TEST(test_tcp_data_receive);
  RUN_TEST(test_tcp_data_send);
  RUN_TEST(test_tcp_active_close);
  RUN_TEST(test_tcp_passive_close);
  RUN_TEST(test_tcp_rst_in_established_aborts);
  RUN_TEST(test_tcp_no_rst_in_listen_for_rst);
  RUN_TEST(test_tcp_rst_sent_for_unknown_port);
  RUN_TEST(test_tcp_timewait_expires);
  RUN_TEST(test_tcp_retransmit_on_timeout);
  RUN_TEST(test_tcp_rto_resets_on_ack);
  TEST_REPORT();
  return test_failures;
}
