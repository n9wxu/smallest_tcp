/**
 * @file test_arp.c
 * @brief Unit tests for ARP (RFC 826).
 */

#include "arp.h"
#include "eth.h"
#include "net.h"
#include "net_endian.h"
#include "test_main.h"
#include <string.h>

/* ── Stub MAC driver that captures sent frames ────────────────────── */

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

static const net_mac_t stub_mac = {
    .init = stub_init,
    .send = stub_send,
    .recv = stub_recv,
    .peek = stub_peek,
    .discard = stub_discard,
    .close = stub_close,
};

/* ── Helper to set up net_t ───────────────────────────────────────── */

static uint8_t rx[512], tx[512];
static net_t net;

static void setup(void) {
  int ctx = 0;
  memset(&net, 0, sizeof(net));
  memset(sent_frame, 0, sizeof(sent_frame));
  sent_len = 0;
  send_count = 0;
  net_init(&net, rx, sizeof(rx), tx, sizeof(tx), NULL, &stub_mac, &ctx);
}

/* Build a raw ARP request frame targeting our IP */
static uint16_t build_arp_request(uint8_t *frame, uint32_t sender_ip,
                                  const uint8_t *sender_mac,
                                  uint32_t target_ip) {
  /* Ethernet header */
  static const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  memcpy(frame, bcast, 6);
  memcpy(frame + 6, sender_mac, 6);
  net_write16be(frame + 12, NET_ETHERTYPE_ARP);
  /* ARP payload */
  uint8_t *arp = frame + 14;
  net_write16be(arp + ARP_OFF_HTYPE, ARP_HTYPE_ETHERNET);
  net_write16be(arp + ARP_OFF_PTYPE, ARP_PTYPE_IPV4);
  arp[ARP_OFF_HLEN] = 6;
  arp[ARP_OFF_PLEN] = 4;
  net_write16be(arp + ARP_OFF_OPER, ARP_OPER_REQUEST);
  memcpy(arp + ARP_OFF_SHA, sender_mac, 6);
  net_write32be(arp + ARP_OFF_SPA, sender_ip);
  memset(arp + ARP_OFF_THA, 0, 6);
  net_write32be(arp + ARP_OFF_TPA, target_ip);
  return 14 + ARP_PKT_SIZE;
}

/* ── Tests ────────────────────────────────────────────────────────── */

TEST(test_arp_reply_to_request) {
  setup();
  uint8_t sender_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
  uint8_t frame[100];
  uint16_t len = build_arp_request(frame, NET_IPV4(10, 0, 0, 1), sender_mac,
                                   NET_DEFAULT_IPV4_ADDR);
  eth_frame_t eth;
  eth_parse(frame, len, &eth);
  arp_input(&net, &eth);

  /* Should have sent a reply */
  ASSERT_EQ(send_count, 1);
  /* Reply should be unicast to sender */
  ASSERT_MEM_EQ(sent_frame, sender_mac, 6);
  /* Source should be our MAC */
  ASSERT_MEM_EQ(sent_frame + 6, net.mac, 6);
  /* EtherType = ARP */
  ASSERT_EQ(net_read16be(sent_frame + 12), NET_ETHERTYPE_ARP);
  /* Operation = Reply */
  ASSERT_EQ(net_read16be(sent_frame + 14 + ARP_OFF_OPER), ARP_OPER_REPLY);
  /* Sender IP in reply = our IP */
  ASSERT_EQ(net_read32be(sent_frame + 14 + ARP_OFF_SPA), NET_DEFAULT_IPV4_ADDR);
  /* Target IP in reply = original sender's IP */
  ASSERT_EQ(net_read32be(sent_frame + 14 + ARP_OFF_TPA), NET_IPV4(10, 0, 0, 1));
}

TEST(test_arp_ignore_other_ip) {
  setup();
  uint8_t sender_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02};
  uint8_t frame[100];
  /* Target IP is NOT ours */
  uint16_t len = build_arp_request(frame, NET_IPV4(10, 0, 0, 1), sender_mac,
                                   NET_IPV4(10, 0, 0, 99));
  eth_frame_t eth;
  eth_parse(frame, len, &eth);
  arp_input(&net, &eth);
  ASSERT_EQ(send_count, 0); /* No reply sent */
}

TEST(test_arp_reject_invalid_htype) {
  setup();
  uint8_t frame[100];
  uint8_t sender_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  uint16_t len = build_arp_request(frame, NET_IPV4(10, 0, 0, 1), sender_mac,
                                   NET_DEFAULT_IPV4_ADDR);
  /* Corrupt HTYPE */
  net_write16be(frame + 14 + ARP_OFF_HTYPE, 99);
  eth_frame_t eth;
  eth_parse(frame, len, &eth);
  arp_input(&net, &eth);
  ASSERT_EQ(send_count, 0);
}

TEST(test_arp_reject_short_packet) {
  setup();
  uint8_t frame[30]; /* Too short for ARP */
  memset(frame, 0, sizeof(frame));
  net_write16be(frame + 12, NET_ETHERTYPE_ARP);
  eth_frame_t eth;
  eth_parse(frame, 20, &eth); /* only 6 bytes of ARP payload */
  arp_input(&net, &eth);
  ASSERT_EQ(send_count, 0);
}

TEST(test_arp_reply_updates_gateway_mac) {
  setup();
  /* Simulate an ARP reply from the gateway */
  uint8_t gw_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
  uint8_t frame[100];
  static const uint8_t our_mac_default[6] = NET_DEFAULT_MAC;
  memcpy(frame, our_mac_default, 6);
  memcpy(frame + 6, gw_mac, 6);
  net_write16be(frame + 12, NET_ETHERTYPE_ARP);
  uint8_t *arp = frame + 14;
  net_write16be(arp + ARP_OFF_HTYPE, ARP_HTYPE_ETHERNET);
  net_write16be(arp + ARP_OFF_PTYPE, ARP_PTYPE_IPV4);
  arp[ARP_OFF_HLEN] = 6;
  arp[ARP_OFF_PLEN] = 4;
  net_write16be(arp + ARP_OFF_OPER, ARP_OPER_REPLY);
  memcpy(arp + ARP_OFF_SHA, gw_mac, 6);
  net_write32be(arp + ARP_OFF_SPA, NET_DEFAULT_GATEWAY);
  memcpy(arp + ARP_OFF_THA, our_mac_default, 6);
  net_write32be(arp + ARP_OFF_TPA, NET_DEFAULT_IPV4_ADDR);

  eth_frame_t eth;
  eth_parse(frame, 14 + ARP_PKT_SIZE, &eth);
  arp_input(&net, &eth);

  ASSERT_TRUE(net.gateway_mac_valid);
  ASSERT_MEM_EQ(net.gateway_mac, gw_mac, 6);
}

TEST(test_arp_request_broadcast) {
  setup();
  net_err_t err = arp_request(&net, NET_IPV4(10, 0, 0, 5));
  ASSERT_EQ(err, NET_OK);
  ASSERT_EQ(send_count, 1);
  /* Destination MAC should be broadcast */
  static const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  ASSERT_MEM_EQ(sent_frame, bcast, 6);
  /* Operation = Request */
  ASSERT_EQ(net_read16be(sent_frame + 14 + ARP_OFF_OPER), ARP_OPER_REQUEST);
  /* Target IP */
  ASSERT_EQ(net_read32be(sent_frame + 14 + ARP_OFF_TPA), NET_IPV4(10, 0, 0, 5));
}

TEST(test_arp_next_hop_local) {
  setup();
  uint32_t hop = arp_next_hop(&net, NET_IPV4(10, 0, 0, 5));
  ASSERT_EQ(hop, NET_IPV4(10, 0, 0, 5)); /* Same subnet → direct */
}

TEST(test_arp_next_hop_remote) {
  setup();
  uint32_t hop = arp_next_hop(&net, NET_IPV4(192, 168, 1, 1));
  ASSERT_EQ(hop, NET_DEFAULT_GATEWAY); /* Different subnet → gateway */
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void) {
  fprintf(stderr, "=== test_arp ===\n");
  RUN_TEST(test_arp_reply_to_request);
  RUN_TEST(test_arp_ignore_other_ip);
  RUN_TEST(test_arp_reject_invalid_htype);
  RUN_TEST(test_arp_reject_short_packet);
  RUN_TEST(test_arp_reply_updates_gateway_mac);
  RUN_TEST(test_arp_request_broadcast);
  RUN_TEST(test_arp_next_hop_local);
  RUN_TEST(test_arp_next_hop_remote);
  TEST_REPORT();
  return test_failures;
}
