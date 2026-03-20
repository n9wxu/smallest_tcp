/**
 * @file test_icmp.c
 * @brief Unit tests for ICMPv4 (RFC 792).
 */

#include "eth.h"
#include "icmp.h"
#include "ipv4.h"
#include "net.h"
#include "net_cksum.h"
#include "net_endian.h"
#include "test_main.h"
#include <string.h>

/* ── Stub MAC driver ──────────────────────────────────────────────── */

static uint8_t sent_frame[1514];
static uint16_t sent_len;
static int send_count;

static int stub_init(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_send(void *ctx, const uint8_t *f, uint16_t l) {
  (void)ctx;
  memcpy(sent_frame, f, l);
  sent_len = l;
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

static uint8_t rx_buf[512], tx_buf[512];
static net_t net;

static void setup(void) {
  int ctx = 0;
  memset(&net, 0, sizeof(net));
  memset(sent_frame, 0, sizeof(sent_frame));
  sent_len = 0;
  send_count = 0;
  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf), NULL,
           &stub_mac_drv, &ctx);
}

/* Build a complete Ethernet + IPv4 + ICMP Echo Request frame */
static uint16_t build_echo_request(uint8_t *frame, uint32_t src_ip,
                                   const uint8_t *src_mac, uint16_t id,
                                   uint16_t seq, const uint8_t *data,
                                   uint16_t data_len) {
  static const uint8_t our_mac[6] = NET_DEFAULT_MAC;
  uint16_t icmp_len = ICMP_HDR_SIZE + data_len;
  uint16_t ip_total = IPV4_HDR_SIZE + icmp_len;

  /* Ethernet header */
  memcpy(frame, our_mac, 6);
  memcpy(frame + 6, src_mac, 6);
  net_write16be(frame + 12, NET_ETHERTYPE_IPV4);

  /* IPv4 header */
  uint8_t *ip = frame + ETH_HDR_SIZE;
  ipv4_build(ip, icmp_len, IPV4_PROTO_ICMP, src_ip, NET_DEFAULT_IPV4_ADDR);

  /* ICMP Echo Request */
  uint8_t *icmp = ip + IPV4_HDR_SIZE;
  icmp[ICMP_OFF_TYPE] = ICMP_TYPE_ECHO_REQUEST;
  icmp[ICMP_OFF_CODE] = 0;
  net_write16be(icmp + ICMP_OFF_CKSUM, 0);
  net_write16be(icmp + ICMP_OFF_ID, id);
  net_write16be(icmp + ICMP_OFF_SEQ, seq);
  if (data && data_len > 0) {
    memcpy(icmp + ICMP_HDR_SIZE, data, data_len);
  }
  uint16_t cksum = net_cksum(icmp, icmp_len);
  net_write16be(icmp + ICMP_OFF_CKSUM, cksum);

  return ETH_HDR_SIZE + ip_total;
}

/* ── Tests ────────────────────────────────────────────────────────── */

TEST(test_icmp_echo_reply) {
  setup();
  uint8_t src_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
  uint8_t payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};
  uint8_t frame[200];
  uint16_t len = build_echo_request(frame, NET_IPV4(10, 0, 0, 1), src_mac,
                                    0x1234, 0x0001, payload, 4);

  /* Parse and dispatch */
  eth_frame_t eth;
  eth_parse(frame, len, &eth);
  ipv4_hdr_t ip;
  ipv4_parse(eth.payload, eth.payload_len, &ip);
  icmp_input(&net, &ip, &eth);

  ASSERT_EQ(send_count, 1);

  /* Parse the reply */
  eth_frame_t rep_eth;
  eth_parse(sent_frame, sent_len, &rep_eth);
  ipv4_hdr_t rep_ip;
  ASSERT_EQ(ipv4_parse(rep_eth.payload, rep_eth.payload_len, &rep_ip), NET_OK);

  /* Reply goes to sender */
  ASSERT_EQ(rep_ip.dst_ip, NET_IPV4(10, 0, 0, 1));
  ASSERT_EQ(rep_ip.src_ip, NET_DEFAULT_IPV4_ADDR);
  ASSERT_EQ(rep_ip.protocol, IPV4_PROTO_ICMP);

  /* ICMP Echo Reply */
  uint8_t *icmp = rep_ip.payload;
  ASSERT_EQ(icmp[ICMP_OFF_TYPE], ICMP_TYPE_ECHO_REPLY);
  ASSERT_EQ(icmp[ICMP_OFF_CODE], 0);
  ASSERT_EQ(net_read16be(icmp + ICMP_OFF_ID), 0x1234);
  ASSERT_EQ(net_read16be(icmp + ICMP_OFF_SEQ), 0x0001);
  /* Verify payload data preserved */
  ASSERT_MEM_EQ(icmp + ICMP_HDR_SIZE, payload, 4);
  /* Verify ICMP checksum */
  ASSERT_TRUE(net_cksum_verify(icmp, rep_ip.payload_len));
}

TEST(test_icmp_no_reply_to_broadcast_dst) {
  setup();
  uint8_t src_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02};
  uint8_t frame[200];
  /* Build echo request targeting broadcast */
  static const uint8_t our_mac[6] = NET_DEFAULT_MAC;
  uint16_t icmp_len = ICMP_HDR_SIZE;
  memcpy(frame, our_mac, 6);
  memcpy(frame + 6, src_mac, 6);
  net_write16be(frame + 12, NET_ETHERTYPE_IPV4);
  uint8_t *ip = frame + ETH_HDR_SIZE;
  ipv4_build(ip, icmp_len, IPV4_PROTO_ICMP, NET_IPV4(10, 0, 0, 1), 0xFFFFFFFFu);
  uint8_t *icmp = ip + IPV4_HDR_SIZE;
  icmp[0] = ICMP_TYPE_ECHO_REQUEST;
  icmp[1] = 0;
  net_write16be(icmp + 2, 0);
  net_write16be(icmp + 4, 1);
  net_write16be(icmp + 6, 1);
  net_write16be(icmp + 2, net_cksum(icmp, icmp_len));

  uint16_t len = ETH_HDR_SIZE + IPV4_HDR_SIZE + icmp_len;
  eth_frame_t eth;
  eth_parse(frame, len, &eth);
  ipv4_hdr_t iphdr;
  ipv4_parse(eth.payload, eth.payload_len, &iphdr);
  icmp_input(&net, &iphdr, &eth);

  ASSERT_EQ(send_count, 0); /* No reply to broadcast */
}

TEST(test_icmp_bad_checksum_discarded) {
  setup();
  uint8_t src_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03};
  uint8_t frame[200];
  uint16_t len = build_echo_request(frame, NET_IPV4(10, 0, 0, 1), src_mac,
                                    0x5678, 0x0002, NULL, 0);
  /* Corrupt ICMP checksum */
  frame[ETH_HDR_SIZE + IPV4_HDR_SIZE + ICMP_OFF_CKSUM] ^= 0xFF;

  eth_frame_t eth;
  eth_parse(frame, len, &eth);
  ipv4_hdr_t ip;
  ipv4_parse(eth.payload, eth.payload_len, &ip);
  icmp_input(&net, &ip, &eth);

  ASSERT_EQ(send_count, 0); /* Bad checksum → discarded */
}

TEST(test_icmp_unknown_type_discarded) {
  setup();
  uint8_t src_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x04};
  uint8_t frame[200];
  uint16_t len =
      build_echo_request(frame, NET_IPV4(10, 0, 0, 1), src_mac, 0, 0, NULL, 0);
  /* Change type to unknown (99) and fix checksum */
  uint8_t *icmp = frame + ETH_HDR_SIZE + IPV4_HDR_SIZE;
  icmp[ICMP_OFF_TYPE] = 99;
  net_write16be(icmp + ICMP_OFF_CKSUM, 0);
  net_write16be(icmp + ICMP_OFF_CKSUM, net_cksum(icmp, ICMP_HDR_SIZE));

  eth_frame_t eth;
  eth_parse(frame, len, &eth);
  ipv4_hdr_t ip;
  ipv4_parse(eth.payload, eth.payload_len, &ip);
  icmp_input(&net, &ip, &eth);

  ASSERT_EQ(send_count, 0); /* Unknown type → discarded */
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void) {
  fprintf(stderr, "=== test_icmp ===\n");
  RUN_TEST(test_icmp_echo_reply);
  RUN_TEST(test_icmp_no_reply_to_broadcast_dst);
  RUN_TEST(test_icmp_bad_checksum_discarded);
  RUN_TEST(test_icmp_unknown_type_discarded);
  TEST_REPORT();
  return test_failures;
}
