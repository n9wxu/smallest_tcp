/**
 * @file itest_udp.c
 * @brief UDP's application interface, black box: what a handler learns,
 *        what a sender may choose, and the ICMP errors reported back.
 */

#include "itest.h"
#include "udp.h"
#include <string.h>

#define OPEN_PORT 7000
#define APP_PORT 5000
#define PEER_PORT 6000

static itest_t t;
static int delivered;
static uint32_t seen_dst;
static int errors;
static uint16_t err_port, err_dst_port, err_mtu;
static uint32_t err_dst;
static uint8_t err_type, err_code;

static void on_datagram(net_t *net, uint32_t src_ip, uint16_t src_port,
                        const uint8_t *src_mac, const uint8_t *data,
                        uint16_t len) {
  (void)src_ip;
  (void)src_port;
  (void)src_mac;
  (void)data;
  (void)len;
  delivered++;
  seen_dst = udp_rx_dst_ip(net);
}

static void on_error(net_t *net, uint16_t local_port, uint32_t dst_ip,
                     uint16_t dst_port, uint8_t type, uint8_t code,
                     uint16_t mtu) {
  (void)net;
  errors++;
  err_port = local_port;
  err_dst = dst_ip;
  err_dst_port = dst_port;
  err_type = type;
  err_code = code;
  err_mtu = mtu;
}

static const udp_port_entry_t ports[] = {{OPEN_PORT, on_datagram}};

static void up(void) {
  itest_up(&t, 1514, 1514);
  udp_set_ports(&t.net, ports, 1);
  udp_set_error_handler(&t.net, on_error);
  delivered = errors = 0;
  seen_dst = 0;
}

/* REQ-UDP-040: a handler learns the datagram's destination address */
TEST(itest_udp_040_destination_address_passed_up) {
  uint8_t f[128];
  up();
  itest_receive(&t, f,
                peer_udp_frame(f, &t.net, PEER_IP, t.net.ipv4_addr, PEER_PORT,
                               OPEN_PORT, "x", 1));
  ASSERT_EQ(seen_dst, t.net.ipv4_addr);
  itest_receive(&t, f,
                peer_udp_frame(f, &t.net, PEER_IP, 0xFFFFFFFFu, PEER_PORT,
                               OPEN_PORT, "x", 1));
  ASSERT_EQ(seen_dst, 0xFFFFFFFFu);
  ASSERT_EQ(delivered, 2);
}

/* REQ-UDP-041: the source is ours, or 0.0.0.0 while acquiring an address */
TEST(itest_udp_041_source_must_be_ours) {
  up();
  memcpy(t.net.tx.buf + UDP_PAYLOAD_OFFSET, "x", 1);
  ASSERT_EQ(udp_send_inplace_from(&t.net, 0x0A00004Du, PEER_IP, peer_mac,
                                  APP_PORT, PEER_PORT, 1, 64),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(udp_send_inplace_from(&t.net, t.net.ipv4_addr, PEER_IP, peer_mac,
                                  APP_PORT, PEER_PORT, 1, 64),
            NET_OK);
  t.net.ipv4_addr = 0;
  ASSERT_EQ(udp_send_inplace_from(&t.net, 0, 0xFFFFFFFFu, broadcast_mac,
                                  APP_PORT, PEER_PORT, 1, 64),
            NET_OK);
}

/* The datagram the application sent, quoted in an ICMP error of @p type
 * and @p code (and @p rest) from @p from */
static void icmp_error_about_last_send(uint32_t from, uint8_t type,
                                       uint8_t code, const uint8_t rest[4]) {
  uint8_t msg[128], f[192];
  const wire_frame_t *sent = wire_sent(&t, 0);
  peer_ip_t ip = peer_ip(from, t.net.ipv4_addr, 1);
  uint16_t n = peer_icmp(msg, type, code, rest, sent->data + 14, 28);
  itest_receive(&t, f, peer_ipv4_frame(f, t.net.mac, peer_mac, &ip, msg, n));
}

/* REQ-UDP-038, REQ-ICMPv4-011, 012, 015, 042, REQ-IPv4-053: Port
 * Unreachable about a datagram we sent reaches the application, by the
 * quoted protocol and ports */
TEST(itest_udp_038_port_unreachable_reported) {
  up();
  udp_send(&t.net, PEER_IP, peer_mac, APP_PORT, PEER_PORT,
           (const uint8_t *)"hello", 5);
  icmp_error_about_last_send(PEER_IP, 3, 3, NULL);
  ASSERT_EQ(errors, 1);
  ASSERT_EQ(err_port, APP_PORT);
  ASSERT_EQ(err_dst, PEER_IP);
  ASSERT_EQ(err_dst_port, PEER_PORT);
  ASSERT_EQ(err_type, 3);
  ASSERT_EQ(err_code, 3);
}

/* REQ-UDP-039, REQ-ICMPv4-016, 024, 029, 028: Fragmentation Needed (with
 * the next-hop MTU), Time Exceeded and Parameter Problem are reported;
 * Source Quench is discarded */
TEST(itest_udp_038_errors_of_every_kind_reported) {
  static const uint8_t mtu_1280[4] = {0, 0, 0x05, 0x00};
  up();
  udp_send(&t.net, REMOTE_IP, peer_mac, APP_PORT, PEER_PORT,
           (const uint8_t *)"hello", 5);
  icmp_error_about_last_send(0x0A0000FEu, 3, 4, mtu_1280);
  ASSERT_EQ(errors, 1);
  ASSERT_EQ(err_code, 4);
  ASSERT_EQ(err_mtu, 1280);
  icmp_error_about_last_send(0x0A0000FEu, 11, 0, NULL);
  ASSERT_EQ(err_type, 11);
  icmp_error_about_last_send(0x0A0000FEu, 12, 0, NULL);
  ASSERT_EQ(err_type, 12);
  ASSERT_EQ(errors, 3);
  icmp_error_about_last_send(0x0A0000FEu, 4, 0, NULL);
  ASSERT_EQ(errors, 3);
}

int main(void) {
  fprintf(stderr, "=== itest_udp ===\n");
  RUN_XFAIL(itest_udp_040_destination_address_passed_up);
  RUN_XFAIL(itest_udp_041_source_must_be_ours);
  RUN_XFAIL(itest_udp_038_port_unreachable_reported);
  RUN_XFAIL(itest_udp_038_errors_of_every_kind_reported);
  ITEST_REPORT();
  return test_failures;
}
