/**
 * @file test_udp.c
 * @brief Unit tests for UDP (RFC 768).
 */

#include "eth.h"
#include "icmp.h"
#include "ipv4.h"
#include "net.h"
#include "net_cksum.h"
#include "net_endian.h"
#include "test_main.h"
#include "udp.h"
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

static uint8_t rx_buf[1024], tx_buf[1024];
static net_t net;

/* ── Handler tracking ─────────────────────────────────────────────── */

static int handler_called;
static uint32_t handler_src_ip;
static uint16_t handler_src_port;
static uint16_t handler_data_len;
static uint8_t handler_data[256];

static void echo_handler(net_t *n, uint32_t src_ip, uint16_t src_port,
                         const uint8_t *src_mac, const uint8_t *data,
                         uint16_t data_len) {
  (void)n;
  (void)src_mac;
  handler_called = 1;
  handler_src_ip = src_ip;
  handler_src_port = src_port;
  handler_data_len = data_len;
  if (data_len > 0 && data_len <= sizeof(handler_data)) {
    memcpy(handler_data, data, data_len);
  }
}

static const udp_port_entry_t port_entries[] = {
    {7, echo_handler}, /* Echo port */
};

static void setup(void) {
  int ctx = 0;
  memset(&net, 0, sizeof(net));
  memset(sent_frame, 0, sizeof(sent_frame));
  sent_len = 0;
  send_count = 0;
  handler_called = 0;
  handler_data_len = 0;
  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf), NULL,
           &stub_mac_drv, &ctx);
  /* Register port handlers */
  udp_ports.entries = port_entries;
  udp_ports.count = 1;
}

/* Build Ethernet + IPv4 + UDP frame */
static uint16_t build_udp_frame(uint8_t *frame, uint32_t src_ip,
                                const uint8_t *src_mac, uint16_t src_port,
                                uint16_t dst_port, const uint8_t *data,
                                uint16_t data_len) {
  static const uint8_t our_mac[6] = NET_DEFAULT_MAC;
  uint16_t udp_len = UDP_HDR_SIZE + data_len;
  uint16_t ip_payload = udp_len;

  /* Ethernet */
  memcpy(frame, our_mac, 6);
  memcpy(frame + 6, src_mac, 6);
  net_write16be(frame + 12, NET_ETHERTYPE_IPV4);

  /* IPv4 */
  uint8_t *ip = frame + ETH_HDR_SIZE;
  ipv4_build(ip, ip_payload, IPV4_PROTO_UDP, src_ip, NET_DEFAULT_IPV4_ADDR);

  /* UDP header */
  uint8_t *udp = ip + IPV4_HDR_SIZE;
  net_write16be(udp + UDP_OFF_SPORT, src_port);
  net_write16be(udp + UDP_OFF_DPORT, dst_port);
  net_write16be(udp + UDP_OFF_LEN, udp_len);
  net_write16be(udp + UDP_OFF_CKSUM, 0);
  if (data && data_len > 0) {
    memcpy(udp + UDP_HDR_SIZE, data, data_len);
  }
  /* Compute UDP checksum */
  uint16_t ck = udp_checksum(src_ip, NET_DEFAULT_IPV4_ADDR, udp, udp_len);
  net_write16be(udp + UDP_OFF_CKSUM, ck);

  return ETH_HDR_SIZE + IPV4_HDR_SIZE + udp_len;
}

/* ── Tests ────────────────────────────────────────────────────────── */

TEST(test_udp_dispatch_to_handler) {
  setup();
  uint8_t src_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
  uint8_t payload[5] = {'H', 'e', 'l', 'l', 'o'};
  uint8_t frame[200];
  uint16_t len = build_udp_frame(frame, NET_IPV4(10, 0, 0, 1), src_mac, 12345,
                                 7, payload, 5);

  eth_frame_t eth;
  eth_parse(frame, len, &eth);
  ipv4_hdr_t ip;
  ipv4_parse(eth.payload, eth.payload_len, &ip);
  udp_input(&net, &ip, &eth);

  ASSERT_TRUE(handler_called);
  ASSERT_EQ(handler_src_ip, NET_IPV4(10, 0, 0, 1));
  ASSERT_EQ(handler_src_port, 12345);
  ASSERT_EQ(handler_data_len, 5);
  ASSERT_MEM_EQ(handler_data, payload, 5);
}

TEST(test_udp_no_handler_sends_icmp) {
  setup();
  uint8_t src_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02};
  uint8_t frame[200];
  /* Send to port 9999 which has no handler */
  uint16_t len = build_udp_frame(frame, NET_IPV4(10, 0, 0, 1), src_mac, 5555,
                                 9999, NULL, 0);

  eth_frame_t eth;
  eth_parse(frame, len, &eth);
  ipv4_hdr_t ip;
  ipv4_parse(eth.payload, eth.payload_len, &ip);
  udp_input(&net, &ip, &eth);

  ASSERT_FALSE(handler_called);
  /* Should send ICMP Port Unreachable */
  ASSERT_EQ(send_count, 1);
  /* Verify it's an ICMP Destination Unreachable */
  eth_frame_t rep_eth;
  eth_parse(sent_frame, sent_len, &rep_eth);
  ipv4_hdr_t rep_ip;
  ASSERT_EQ(ipv4_parse(rep_eth.payload, rep_eth.payload_len, &rep_ip), NET_OK);
  ASSERT_EQ(rep_ip.protocol, IPV4_PROTO_ICMP);
  ASSERT_EQ(rep_ip.payload[ICMP_OFF_TYPE], ICMP_TYPE_DEST_UNREACH);
  ASSERT_EQ(rep_ip.payload[ICMP_OFF_CODE], ICMP_CODE_PORT_UNREACH);
}

TEST(test_udp_bad_length_discarded) {
  setup();
  uint8_t src_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03};
  uint8_t frame[200];
  uint16_t len =
      build_udp_frame(frame, NET_IPV4(10, 0, 0, 1), src_mac, 1234, 7, NULL, 0);
  /* Corrupt UDP length to 4 (< 8) */
  uint8_t *udp = frame + ETH_HDR_SIZE + IPV4_HDR_SIZE;
  net_write16be(udp + UDP_OFF_LEN, 4);

  eth_frame_t eth;
  eth_parse(frame, len, &eth);
  ipv4_hdr_t ip;
  ipv4_parse(eth.payload, eth.payload_len, &ip);
  udp_input(&net, &ip, &eth);

  ASSERT_FALSE(handler_called);
}

TEST(test_udp_zero_checksum_accepted) {
  setup();
  uint8_t src_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x04};
  uint8_t payload[3] = {1, 2, 3};
  uint8_t frame[200];
  uint16_t len = build_udp_frame(frame, NET_IPV4(10, 0, 0, 1), src_mac, 8888, 7,
                                 payload, 3);
  /* Set checksum to 0 (means "no checksum") */
  uint8_t *udp = frame + ETH_HDR_SIZE + IPV4_HDR_SIZE;
  net_write16be(udp + UDP_OFF_CKSUM, 0);

  eth_frame_t eth;
  eth_parse(frame, len, &eth);
  ipv4_hdr_t ip;
  ipv4_parse(eth.payload, eth.payload_len, &ip);
  udp_input(&net, &ip, &eth);

  ASSERT_TRUE(handler_called);
  ASSERT_EQ(handler_data_len, 3);
}

TEST(test_udp_send) {
  setup();
  uint8_t dst_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  uint8_t data[4] = {0xCA, 0xFE, 0xBA, 0xBE};
  net_err_t err =
      udp_send(&net, NET_IPV4(10, 0, 0, 1), dst_mac, 5000, 7, data, 4);
  ASSERT_EQ(err, NET_OK);
  ASSERT_EQ(send_count, 1);

  /* Parse the sent frame */
  eth_frame_t eth;
  eth_parse(sent_frame, sent_len, &eth);
  ASSERT_EQ(eth.ethertype, NET_ETHERTYPE_IPV4);

  ipv4_hdr_t ip;
  ASSERT_EQ(ipv4_parse(eth.payload, eth.payload_len, &ip), NET_OK);
  ASSERT_EQ(ip.protocol, IPV4_PROTO_UDP);
  ASSERT_EQ(ip.dst_ip, NET_IPV4(10, 0, 0, 1));

  /* Check UDP header */
  uint8_t *udp = ip.payload;
  ASSERT_EQ(net_read16be(udp + UDP_OFF_SPORT), 5000);
  ASSERT_EQ(net_read16be(udp + UDP_OFF_DPORT), 7);
  ASSERT_EQ(net_read16be(udp + UDP_OFF_LEN), 12); /* 8 + 4 */
  /* Verify payload */
  ASSERT_MEM_EQ(udp + UDP_HDR_SIZE, data, 4);
  /* Verify UDP checksum */
  uint16_t ck = net_read16be(udp + UDP_OFF_CKSUM);
  ASSERT_NE(ck, 0); /* Checksum should be non-zero */
}

TEST(test_udp_send_too_large) {
  setup();
  uint8_t dst_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  /* Try to send more data than fits in tx buffer */
  net_err_t err =
      udp_send(&net, NET_IPV4(10, 0, 0, 1), dst_mac, 5000, 7, NULL, 2000);
  ASSERT_EQ(err, NET_ERR_BUF_TOO_SMALL);
}

TEST(test_udp_checksum_computation) {
  /* Known-value test for pseudo-header checksum */
  uint8_t udp_pkt[12];
  net_write16be(udp_pkt + UDP_OFF_SPORT, 1234);
  net_write16be(udp_pkt + UDP_OFF_DPORT, 5678);
  net_write16be(udp_pkt + UDP_OFF_LEN, 12);
  net_write16be(udp_pkt + UDP_OFF_CKSUM, 0);
  udp_pkt[8] = 0xDE;
  udp_pkt[9] = 0xAD;
  udp_pkt[10] = 0xBE;
  udp_pkt[11] = 0xEF;

  uint16_t ck =
      udp_checksum(NET_IPV4(10, 0, 0, 2), NET_IPV4(10, 0, 0, 1), udp_pkt, 12);
  ASSERT_NE(ck, 0); /* Should produce a non-zero checksum */

  /* Verify: set the checksum and re-verify */
  net_write16be(udp_pkt + UDP_OFF_CKSUM, ck);
  uint16_t verify =
      udp_checksum(NET_IPV4(10, 0, 0, 2), NET_IPV4(10, 0, 0, 1), udp_pkt, 12);
  /* After setting correct checksum, re-computing should give 0xFFFF (valid) */
  ASSERT_TRUE(verify == 0xFFFF || verify == 0x0000);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void) {
  fprintf(stderr, "=== test_udp ===\n");
  RUN_TEST(test_udp_dispatch_to_handler);
  RUN_TEST(test_udp_no_handler_sends_icmp);
  RUN_TEST(test_udp_bad_length_discarded);
  RUN_TEST(test_udp_zero_checksum_accepted);
  RUN_TEST(test_udp_send);
  RUN_TEST(test_udp_send_too_large);
  RUN_TEST(test_udp_checksum_computation);
  TEST_REPORT();
  return test_failures;
}
