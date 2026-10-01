/**
 * @file itest_tftp.c
 * @brief The TFTP client, black box: a server on the wire — RRQ, DATA and
 *        ACK built and read by the peer's own codec below — and the
 *        tftp_client_* API.
 */

#include "itest.h"
#include "tftp.h"
#include "udp.h"
#include <string.h>

#define OP_RRQ 1
#define OP_DATA 3
#define OP_ACK 4

#define LOCAL_PORT 50000
#define SERVER_TID 40000 /* the server's transfer port */

static itest_t t;
static tftp_client_t c;
static int done_calls;

static void on_done(uint8_t ok, uint16_t code, const char *msg, void *ctx) {
  (void)ok;
  (void)code;
  (void)msg;
  (void)ctx;
  done_calls++;
}

static void on_port(net_t *net, uint32_t src_ip, uint16_t src_port,
                    const uint8_t *src_mac, const uint8_t *data, uint16_t len) {
  tftp_client_input(net, &c, src_ip, src_mac, src_port, data, len);
}

static const udp_port_entry_t ports[] = {{LOCAL_PORT, on_port}};

/* A transfer of 512-byte blocks started: the RRQ on the wire */
static void get(void) {
  itest_up(&t, 1514, 1514);
  udp_set_ports(&t.net, ports, 1);
  tftp_client_init(&c, LOCAL_PORT, NULL, on_done, NULL);
  done_calls = 0;
  tftp_client_get(&t.net, &c, PEER_IP, peer_mac, "image.bin", 0);
}

/* DATA @p block — a full block, so not the last — from the server's TID */
static void data_block(uint16_t block) {
  static uint8_t pkt[4 + 512], f[600];
  peer_put16(pkt, OP_DATA);
  peer_put16(pkt + 2, block);
  memset(pkt + 4, 'd', 512);
  itest_receive(&t, f,
                peer_udp_frame(f, &t.net, PEER_IP, t.net.ipv4_addr, SERVER_TID,
                               LOCAL_PORT, pkt, sizeof(pkt)));
}

/* The opcode of the last packet the client sent, its block in @p block;
 * 0 if it sent none */
static uint16_t last_sent(uint16_t *block) {
  peer_ip_t ip;
  peer_udp_t udp;
  if (!t.wire.tx_count ||
      !peer_parse_ipv4(wire_sent(&t, (uint16_t)(t.wire.tx_count - 1u)), &ip) ||
      !peer_parse_udp(&ip, &udp) || udp.data_len < 4)
    return 0;
  *block = peer_get16(udp.data + 2);
  return peer_get16(udp.data);
}

/* Tick @p step ms at a time, at most @p limit ms: the time until the
 * client sends (the wire cleared first); 0 if it does not */
static uint32_t ms_to_send(uint32_t limit, uint32_t step) {
  uint32_t ms;
  wire_clear(&t);
  for (ms = step; ms <= limit; ms += step) {
    tftp_client_tick(&t.net, &c, step);
    if (t.wire.tx_count)
      return ms;
  }
  return 0;
}

/* REQ-TFTP-039, 021: an unanswered RRQ goes again after the first timeout
 * (3 s), then each time after twice the wait before (RFC 1123 §4.2.3.2) */
TEST(itest_tftp_039_retransmission_backs_off) {
  uint16_t block;
  get();
  ASSERT_EQ(ms_to_send(30000, 10), 3000u);
  ASSERT_EQ(last_sent(&block), OP_RRQ);
  ASSERT_EQ(ms_to_send(30000, 10), 6000u);
  ASSERT_EQ(ms_to_send(30000, 10), 12000u);
  ASSERT_EQ(last_sent(&block), OP_RRQ);
}

/* REQ-TFTP-039, 020: a server that answers within 10 ms: the timeout
 * follows its round trips down to the 1 s floor, and a lost block is
 * asked for again after 1 s */
TEST(itest_tftp_039_timeout_shrinks_for_a_fast_server) {
  uint16_t b, block = 0;
  get();
  for (b = 1; b <= 8; b++) {
    tftp_client_tick(&t.net, &c, 10);
    data_block(b);
  }
  ASSERT_EQ(ms_to_send(5000, 10), 1000u);
  ASSERT_EQ(last_sent(&block), OP_ACK);
  ASSERT_EQ(block, 8);
}

/* REQ-TFTP-039: a server slower than the first timeout (4 s round trips):
 * the RRQ is sent again once, then the timeout grows past the round trip
 * and nothing more is (RFC 1123 §4.2.3.2) */
TEST(itest_tftp_039_timeout_grows_for_a_slow_server) {
  uint16_t b;
  uint32_t ms;
  int resent = 0;
  get();
  for (b = 1; b <= 6; b++) {
    wire_clear(&t);
    for (ms = 0; ms < 4000; ms += 100)
      tftp_client_tick(&t.net, &c, 100);
    resent += t.wire.tx_count;
    data_block(b);
  }
  ASSERT_EQ(resent, 1);
  ASSERT_EQ(done_calls, 0);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_RECEIVING);
}

static uint8_t got[1024];
static uint16_t got_len;

static void on_data(uint16_t block, const uint8_t *data, uint16_t len,
                    void *ctx) {
  (void)block;
  (void)ctx;
  if (got_len + len <= sizeof(got))
    memcpy(got + got_len, data, len);
  got_len = (uint16_t)(got_len + len);
}

/* DATA @p block carrying @p n bytes from the server's TID */
static void data_bytes(uint16_t block, const void *bytes, uint16_t n) {
  static uint8_t pkt[4 + 512], f[600];
  peer_put16(pkt, OP_DATA);
  peer_put16(pkt + 2, block);
  memcpy(pkt + 4, bytes, n);
  itest_receive(&t, f,
                peer_udp_frame(f, &t.net, PEER_IP, t.net.ipv4_addr, SERVER_TID,
                               LOCAL_PORT, pkt, (uint16_t)(4 + n)));
}

/* REQ-TFTP-004 (RFC 1350 §2, RFC 1123 §4.2.4): netascii is asked for, and
 * the text arrives with local newlines — CR LF as '\n', CR NUL as '\r',
 * also when a block ends between the two */
TEST(itest_tftp_004_netascii) {
  static const char rrq[] = "\0\1text.txt\0netascii\0";
  static uint8_t blk1[512];
  static char want[600];
  peer_ip_t ip;
  peer_udp_t udp;
  itest_up(&t, 1514, 1514);
  udp_set_ports(&t.net, ports, 1);
  tftp_client_init(&c, LOCAL_PORT, on_data, on_done, NULL);
  ASSERT_EQ(tftp_client_set_mode(&c, TFTP_MODE_NETASCII), NET_OK);
  done_calls = 0;
  got_len = 0;
  ASSERT_EQ(tftp_client_get(&t.net, &c, PEER_IP, peer_mac, "text.txt", 0),
            NET_OK);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip) &&
              peer_parse_udp(&ip, &udp));
  ASSERT_EQ(udp.data_len, sizeof(rrq) - 1);
  ASSERT_MEM_EQ(udp.data, rrq, sizeof(rrq) - 1);

  memcpy(blk1, "ab\r\ncd\r\0", 8);
  memset(blk1 + 8, 'x', 503);
  blk1[511] = '\r'; /* its LF opens the next block */
  data_bytes(1, blk1, sizeof(blk1));
  data_bytes(2, "\nend\r\n", 6);
  ASSERT_EQ(done_calls, 1);
  ASSERT_EQ(tftp_client_state(&c), TFTP_STATE_DONE);
  memcpy(want, "ab\ncd\r", 6);
  memset(want + 6, 'x', 503);
  memcpy(want + 509, "\nend\n", 5);
  ASSERT_EQ(got_len, 514);
  ASSERT_MEM_EQ(got, want, 514);
}

/* REQ-TFTP-004: octet stays the default, and the bytes are untouched */
TEST(itest_tftp_004_octet_untouched) {
  peer_ip_t ip;
  peer_udp_t udp;
  itest_up(&t, 1514, 1514);
  udp_set_ports(&t.net, ports, 1);
  tftp_client_init(&c, LOCAL_PORT, on_data, on_done, NULL);
  got_len = 0;
  tftp_client_get(&t.net, &c, PEER_IP, peer_mac, "image.bin", 0);
  ASSERT_TRUE(peer_parse_ipv4(wire_sent(&t, 0), &ip) &&
              peer_parse_udp(&ip, &udp));
  ASSERT_MEM_EQ(udp.data + 2, "image.bin\0octet\0", 16);
  data_bytes(1, "a\r\nb\r", 5);
  ASSERT_EQ(got_len, 5);
  ASSERT_MEM_EQ(got, "a\r\nb\r", 5);
  ASSERT_EQ(tftp_client_set_mode(&c, 7), NET_ERR_INVALID_PARAM);
}

int main(void) {
  fprintf(stderr, "=== itest_tftp ===\n");
  RUN_TEST(itest_tftp_039_retransmission_backs_off);
  RUN_TEST(itest_tftp_039_timeout_shrinks_for_a_fast_server);
  RUN_TEST(itest_tftp_039_timeout_grows_for_a_slow_server);
  RUN_TEST(itest_tftp_004_netascii);
  RUN_TEST(itest_tftp_004_octet_untouched);
  ITEST_REPORT();
  return test_failures;
}
