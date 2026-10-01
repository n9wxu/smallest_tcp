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

int main(void) {
  fprintf(stderr, "=== itest_tftp ===\n");
  RUN_XFAIL(itest_tftp_039_retransmission_backs_off);
  RUN_XFAIL(itest_tftp_039_timeout_shrinks_for_a_fast_server);
  RUN_XFAIL(itest_tftp_039_timeout_grows_for_a_slow_server);
  ITEST_REPORT();
  return test_failures;
}
