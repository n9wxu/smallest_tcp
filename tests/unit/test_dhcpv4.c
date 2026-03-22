/**
 * @file test_dhcpv4.c
 * @brief Unit tests for DHCPv4 client and server.
 *
 * Tests REQ-DHCPv4-001..078.
 * Uses the same stub MAC driver pattern as test_udp.c.
 */

#include "dhcpv4_client.h"
#include "dhcpv4_server.h"
#include "eth.h"
#include "net.h"
#include "net_endian.h"
#include "test_main.h"
#include "udp.h"
#include <string.h>

/* ── Wire offsets (local copy for test readability) ──────────────── */
#define DHCP_OFF_OP 0
#define DHCP_OFF_XID 4
#define DHCP_OFF_FLAGS 10
#define DHCP_OFF_CIADDR 12
#define DHCP_OFF_YIADDR 16
#define DHCP_OFF_CHADDR 28
#define DHCP_OFF_MAGIC 236
#define DHCP_OFF_OPTIONS 240
#define DHCP_MIN_LEN 300
#define DHCP_MAGIC 0x63825363u
#define DHCP_OP_REQUEST 1
#define DHCP_OP_REPLY 2
#define DHCP_MSG_DISCOVER 1
#define DHCP_MSG_OFFER 2
#define DHCP_MSG_REQUEST 3
#define DHCP_MSG_ACK 5
#define DHCP_MSG_NAK 6
#define OPT_SUBNET_MASK 1
#define OPT_ROUTER 3
#define OPT_LEASE_TIME 51
#define OPT_MSG_TYPE 53
#define OPT_SERVER_ID 54
#define OPT_REQUESTED_IP 50
#define OPT_T1 58
#define OPT_T2 59
#define OPT_END 255

/* ETH+IP+UDP header size — DHCP payload starts at this offset */
#define FRAME_HDR_SIZE (14u + 20u + 8u)

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
  return l;
}
static int stub_poll(void *ctx) {
  (void)ctx;
  return 0;
}
static int stub_peek(void *ctx, uint16_t off, uint8_t *buf, uint16_t n) {
  (void)ctx;
  (void)off;
  (void)buf;
  (void)n;
  return 0;
}
static void stub_discard(void *ctx) { (void)ctx; }
static void stub_close(void *ctx) { (void)ctx; }

static const net_mac_t stub_mac = {stub_init, stub_send,    stub_poll,
                                   stub_peek, stub_discard, stub_close};

/* ── Shared test state ────────────────────────────────────────────── */

static uint8_t rx_buf[1514], tx_buf[1514];
static net_t net;
static int dummy_ctx = 0;

static dhcpv4_client_t cli;
static dhcpv4_server_t srv;

static int event_count;
static uint8_t last_event;

static void on_event(uint8_t ev, void *ctx) {
  (void)ctx;
  event_count++;
  last_event = ev;
}

/* ── Helpers: parse DHCP payload from the last sent frame ─────────── */

/* Returns pointer into sent_frame where DHCP payload starts */
static const uint8_t *sent_dhcp(void) { return sent_frame + FRAME_HDR_SIZE; }
static uint16_t sent_dhcp_len(void) {
  return (sent_len > FRAME_HDR_SIZE) ? (sent_len - FRAME_HDR_SIZE) : 0u;
}

/* Find first occurrence of a DHCP option in an options field */
static uint8_t find_opt_byte(const uint8_t *opts, uint16_t len, uint8_t code) {
  uint16_t i = 0;
  while (i < len) {
    uint8_t c = opts[i++];
    if (c == OPT_END)
      break;
    if (c == 0)
      continue;
    if (i >= len)
      break;
    uint8_t olen = opts[i++];
    if (c == code && olen >= 1)
      return opts[i];
    i += olen;
  }
  return 0;
}

static uint32_t find_opt_u32(const uint8_t *opts, uint16_t len, uint8_t code) {
  uint16_t i = 0;
  while (i < len) {
    uint8_t c = opts[i++];
    if (c == OPT_END)
      break;
    if (c == 0)
      continue;
    if (i >= len)
      break;
    uint8_t olen = opts[i++];
    if (c == code && olen >= 4)
      return net_read32be(opts + i);
    i += olen;
  }
  return 0u;
}

/* ── Helpers: build test DHCP messages ───────────────────────────── */

/* Build minimal DHCP OFFER/ACK/NAK payload into buf.
   Returns total length (always >= DHCP_MIN_LEN). */
static uint16_t make_server_msg(uint8_t *buf, uint8_t msg_type, uint32_t xid,
                                uint32_t yiaddr, uint32_t server_ip,
                                uint32_t lease, uint32_t t1, uint32_t t2,
                                uint32_t subnet, uint32_t router) {
  memset(buf, 0, DHCP_MIN_LEN + 64);
  buf[DHCP_OFF_OP] = DHCP_OP_REPLY;
  buf[1] = 1;
  buf[2] = 6;
  net_write32be(buf + DHCP_OFF_XID, xid);
  net_write32be(buf + DHCP_OFF_YIADDR, yiaddr);
  net_write32be(buf + DHCP_OFF_MAGIC, DHCP_MAGIC);

  uint16_t pos = DHCP_OFF_OPTIONS;
  buf[pos++] = OPT_MSG_TYPE;
  buf[pos++] = 1;
  buf[pos++] = msg_type;
  buf[pos++] = OPT_SERVER_ID;
  buf[pos++] = 4;
  net_write32be(buf + pos, server_ip);
  pos += 4;
  if (lease) {
    buf[pos++] = OPT_LEASE_TIME;
    buf[pos++] = 4;
    net_write32be(buf + pos, lease);
    pos += 4;
  }
  if (t1) {
    buf[pos++] = OPT_T1;
    buf[pos++] = 4;
    net_write32be(buf + pos, t1);
    pos += 4;
  }
  if (t2) {
    buf[pos++] = OPT_T2;
    buf[pos++] = 4;
    net_write32be(buf + pos, t2);
    pos += 4;
  }
  if (subnet) {
    buf[pos++] = OPT_SUBNET_MASK;
    buf[pos++] = 4;
    net_write32be(buf + pos, subnet);
    pos += 4;
  }
  if (router) {
    buf[pos++] = OPT_ROUTER;
    buf[pos++] = 4;
    net_write32be(buf + pos, router);
    pos += 4;
  }
  buf[pos++] = OPT_END;
  return (pos < DHCP_MIN_LEN) ? DHCP_MIN_LEN : pos;
}

/* ── Setup ────────────────────────────────────────────────────────── */

static void setup(void) {
  memset(&net, 0, sizeof(net));
  memset(sent_frame, 0, sizeof(sent_frame));
  send_count = 0;
  sent_len = 0;
  event_count = 0;
  last_event = 0;
  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf), NULL,
           &stub_mac, &dummy_ctx);
  udp_ports.entries = NULL;
  udp_ports.count = 0;
}

/* ══════════════════════════════════════════════════════════════════
 * CLIENT TESTS
 * ══════════════════════════════════════════════════════════════════ */

/* REQ-DHCPv4-001: init zeros struct */
TEST(test_dhcp_client_init_zeros_state) {
  setup();
  dhcpv4_client_init(&cli, on_event, NULL, NULL);
  ASSERT_EQ(cli.state, DHCPV4_CLI_INIT);
  ASSERT_EQ(cli.xid, 0u);
  ASSERT_EQ(cli.on_event, on_event);
}

/* REQ-DHCPv4-002, 008..017: DHCPDISCOVER sent on start */
TEST(test_dhcp_client_start_sends_discover) {
  setup();
  dhcpv4_client_init(&cli, NULL, NULL, NULL);
  dhcpv4_client_start(&net, &cli);

  ASSERT_TRUE(send_count >= 1);
  ASSERT_EQ(cli.state, DHCPV4_CLI_SELECTING);

  const uint8_t *d = sent_dhcp();
  /* REQ-DHCPv4-008: op=BOOTREQUEST */
  ASSERT_EQ(d[DHCP_OFF_OP], DHCP_OP_REQUEST);
  /* REQ-DHCPv4-010: ciaddr = 0 */
  ASSERT_EQ(net_read32be(d + DHCP_OFF_CIADDR), 0u);
  /* REQ-DHCPv4-012: magic cookie */
  ASSERT_EQ(net_read32be(d + DHCP_OFF_MAGIC), DHCP_MAGIC);
  /* REQ-DHCPv4-013: message type = DISCOVER */
  uint16_t opt_len = sent_dhcp_len() - DHCP_OFF_OPTIONS;
  ASSERT_EQ(find_opt_byte(d + DHCP_OFF_OPTIONS, opt_len, OPT_MSG_TYPE),
            DHCP_MSG_DISCOVER);
  /* REQ-DHCPv4-011: chaddr matches net.mac */
  ASSERT_MEM_EQ(d + DHCP_OFF_CHADDR, net.mac, 6);
}

/* REQ-DHCPv4-016,017: DISCOVER goes to broadcast IP */
TEST(test_dhcp_client_discover_to_broadcast) {
  setup();
  dhcpv4_client_init(&cli, NULL, NULL, NULL);
  dhcpv4_client_start(&net, &cli);

  ASSERT_TRUE(send_count >= 1);
  /* Parse IPv4 dest from sent frame (offset 30 = ETH(14) + IP dst(16)) */
  uint32_t dst_ip = net_read32be(sent_frame + 14 + 16);
  ASSERT_EQ(dst_ip, 0xFFFFFFFFu); /* 255.255.255.255 */
  /* UDP dport = 67 */
  uint16_t dport = net_read16be(sent_frame + 14 + 20 + 2);
  ASSERT_EQ(dport, 67u);
  /* UDP sport = 68 */
  uint16_t sport = net_read16be(sent_frame + 14 + 20);
  ASSERT_EQ(sport, 68u);
}

/* REQ-DHCPv4-018..021: OFFER → sends REQUEST */
TEST(test_dhcp_client_offer_triggers_request) {
  setup();
  dhcpv4_client_init(&cli, NULL, NULL, NULL);
  dhcpv4_client_start(&net, &cli);

  int discovers = send_count;
  uint32_t xid = cli.xid;

  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen = make_server_msg(
      msg, DHCP_MSG_OFFER, xid, NET_IPV4(10, 0, 0, 50), NET_IPV4(10, 0, 0, 1),
      3600, 0, 0, NET_IPV4(255, 255, 255, 0), NET_IPV4(10, 0, 0, 1));

  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), msg, mlen);

  ASSERT_EQ(cli.state, DHCPV4_CLI_REQUESTING);
  ASSERT_EQ(cli.offered_ip, NET_IPV4(10, 0, 0, 50));
  ASSERT_TRUE(send_count > discovers);

  /* Verify REQUEST has Requested IP option */
  const uint8_t *d = sent_dhcp();
  uint16_t opt_len = sent_dhcp_len() - DHCP_OFF_OPTIONS;
  ASSERT_EQ(find_opt_byte(d + DHCP_OFF_OPTIONS, opt_len, OPT_MSG_TYPE),
            DHCP_MSG_REQUEST);
  uint32_t req_ip =
      find_opt_u32(d + DHCP_OFF_OPTIONS, opt_len, OPT_REQUESTED_IP);
  ASSERT_EQ(req_ip, NET_IPV4(10, 0, 0, 50));
}

/* REQ-DHCPv4-028..036: ACK → BOUND, IP configured, timers set */
TEST(test_dhcp_client_ack_enters_bound) {
  setup();
  dhcpv4_client_init(&cli, on_event, NULL, NULL);
  dhcpv4_client_start(&net, &cli);

  uint32_t xid = cli.xid;
  uint8_t msg[DHCP_MIN_LEN + 64];
  /* Feed OFFER first */
  uint16_t mlen =
      make_server_msg(msg, DHCP_MSG_OFFER, xid, NET_IPV4(10, 0, 0, 50),
                      NET_IPV4(10, 0, 0, 1), 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), msg, mlen);

  /* Feed ACK */
  mlen = make_server_msg(msg, DHCP_MSG_ACK, xid, NET_IPV4(10, 0, 0, 50),
                         NET_IPV4(10, 0, 0, 1), 3600, 1800, 3150,
                         NET_IPV4(255, 255, 255, 0), NET_IPV4(10, 0, 0, 1));
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), msg, mlen);

  ASSERT_EQ(cli.state, DHCPV4_CLI_BOUND);
  ASSERT_EQ(net.ipv4_addr, NET_IPV4(10, 0, 0, 50));       /* REQ-DHCPv4-029 */
  ASSERT_EQ(net.subnet_mask, NET_IPV4(255, 255, 255, 0)); /* REQ-DHCPv4-030 */
  ASSERT_EQ(net.gateway_ipv4, NET_IPV4(10, 0, 0, 1));     /* REQ-DHCPv4-031 */
  ASSERT_EQ(cli.lease_time, 3600u);                       /* REQ-DHCPv4-033 */
  ASSERT_EQ(cli.t1, 1800u);                               /* REQ-DHCPv4-034 */
  ASSERT_EQ(cli.t2, 3150u);                               /* REQ-DHCPv4-034 */
  ASSERT_EQ(event_count, 1);
  ASSERT_EQ(last_event, DHCPV4_EVT_BOUND);
}

/* REQ-DHCPv4-035,036: default T1/T2 when not present in ACK */
TEST(test_dhcp_client_default_t1_t2) {
  setup();
  dhcpv4_client_init(&cli, NULL, NULL, NULL);
  dhcpv4_client_start(&net, &cli);

  uint32_t xid = cli.xid;
  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen =
      make_server_msg(msg, DHCP_MSG_OFFER, xid, NET_IPV4(10, 0, 0, 50),
                      NET_IPV4(10, 0, 0, 1), 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), msg, mlen);

  /* ACK without T1/T2 */
  mlen = make_server_msg(msg, DHCP_MSG_ACK, xid, NET_IPV4(10, 0, 0, 50),
                         NET_IPV4(10, 0, 0, 1), 3600, 0, 0,
                         NET_IPV4(255, 255, 255, 0), 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), msg, mlen);

  ASSERT_EQ(cli.state, DHCPV4_CLI_BOUND);
  ASSERT_EQ(cli.t1, 1800u); /* 0.5 × 3600 — REQ-DHCPv4-035 */
  ASSERT_EQ(cli.t2, 3150u); /* 0.875 × 3600 — REQ-DHCPv4-036 */
}

/* REQ-DHCPv4-037..038: NAK → restart INIT, IP cleared */
TEST(test_dhcp_client_nak_restarts_init) {
  setup();
  dhcpv4_client_init(&cli, on_event, NULL, NULL);
  dhcpv4_client_start(&net, &cli);

  uint32_t xid = cli.xid;
  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen =
      make_server_msg(msg, DHCP_MSG_OFFER, xid, NET_IPV4(10, 0, 0, 50),
                      NET_IPV4(10, 0, 0, 1), 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), msg, mlen);

  /* Feed NAK */
  mlen = make_server_msg(msg, DHCP_MSG_NAK, xid, 0, NET_IPV4(10, 0, 0, 1), 0, 0,
                         0, 0, 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), msg, mlen);

  ASSERT_EQ(cli.state, DHCPV4_CLI_SELECTING); /* restarted */
  ASSERT_EQ(net.ipv4_addr, 0u);
  ASSERT_TRUE(last_event == DHCPV4_EVT_NAK);
}

/* Static function for opt handler test */
static uint8_t s_got_dns[4];
static uint8_t s_got_dns_len;
static uint8_t s_dns_called;

static void dns_handler_fn(uint8_t opt, const uint8_t *data, uint8_t len,
                           void *ctx) {
  (void)opt;
  (void)ctx;
  s_dns_called = 1;
  s_got_dns_len = len;
  if (len >= 4)
    memcpy(s_got_dns, data, 4);
}

/* REQ-DHCPv4-053: option handler invoked — corrected version */
TEST(test_dhcp_client_opt_handler_called_v2) {
  setup();
  s_dns_called = 0;
  s_got_dns_len = 0;
  memset(s_got_dns, 0, 4);

  static const dhcpv4_opt_entry_t entries[] = {{6, dns_handler_fn, NULL}};
  static const dhcpv4_opt_table_t tbl = {entries, 1};

  dhcpv4_client_init(&cli, NULL, NULL, &tbl);
  dhcpv4_client_start(&net, &cli);
  uint32_t xid = cli.xid;

  /* OFFER */
  uint8_t offer[DHCP_MIN_LEN + 64];
  uint16_t olen =
      make_server_msg(offer, DHCP_MSG_OFFER, xid, NET_IPV4(10, 0, 0, 50),
                      NET_IPV4(10, 0, 0, 1), 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), offer, olen);

  /* Build ACK with DNS option 6 */
  uint8_t msg[DHCP_MIN_LEN + 64];
  memset(msg, 0, sizeof(msg));
  msg[DHCP_OFF_OP] = DHCP_OP_REPLY;
  msg[1] = 1;
  msg[2] = 6;
  net_write32be(msg + DHCP_OFF_XID, xid);
  net_write32be(msg + DHCP_OFF_YIADDR, NET_IPV4(10, 0, 0, 50));
  net_write32be(msg + DHCP_OFF_MAGIC, DHCP_MAGIC);
  uint16_t pos = DHCP_OFF_OPTIONS;
  msg[pos++] = OPT_MSG_TYPE;
  msg[pos++] = 1;
  msg[pos++] = DHCP_MSG_ACK;
  msg[pos++] = OPT_SERVER_ID;
  msg[pos++] = 4;
  net_write32be(msg + pos, NET_IPV4(10, 0, 0, 1));
  pos += 4;
  msg[pos++] = OPT_LEASE_TIME;
  msg[pos++] = 4;
  net_write32be(msg + pos, 3600);
  pos += 4;
  msg[pos++] = 6;
  msg[pos++] = 4; /* DNS */
  net_write32be(msg + pos, NET_IPV4(8, 8, 8, 8));
  pos += 4;
  msg[pos++] = OPT_END;
  uint16_t mlen = (pos < DHCP_MIN_LEN) ? DHCP_MIN_LEN : pos;

  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), msg, mlen);

  ASSERT_EQ(cli.state, DHCPV4_CLI_BOUND);
  ASSERT_TRUE(s_dns_called);
  ASSERT_EQ(net_read32be(s_got_dns), NET_IPV4(8, 8, 8, 8));
}

/* REQ-DHCPv4-058: NULL opt_table — no handlers, still applies mandatory opts */
TEST(test_dhcp_client_null_opt_table) {
  setup();
  dhcpv4_client_init(&cli, NULL, NULL, NULL); /* NULL opt_table */
  dhcpv4_client_start(&net, &cli);
  uint32_t xid = cli.xid;

  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen =
      make_server_msg(msg, DHCP_MSG_OFFER, xid, NET_IPV4(10, 0, 0, 50),
                      NET_IPV4(10, 0, 0, 1), 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), msg, mlen);

  mlen = make_server_msg(msg, DHCP_MSG_ACK, xid, NET_IPV4(10, 0, 0, 50),
                         NET_IPV4(10, 0, 0, 1), 3600, 0, 0,
                         NET_IPV4(255, 255, 255, 0), 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), msg, mlen);

  ASSERT_EQ(cli.state, DHCPV4_CLI_BOUND);
  ASSERT_EQ(net.ipv4_addr, NET_IPV4(10, 0, 0, 50));
  ASSERT_EQ(net.subnet_mask, NET_IPV4(255, 255, 255, 0));
}

/* REQ-DHCPv4-045: retransmit DISCOVER after timer expiry */
TEST(test_dhcp_client_retransmit_discover) {
  setup();
  dhcpv4_client_init(&cli, NULL, NULL, NULL);
  dhcpv4_client_start(&net, &cli);
  int first = send_count;

  /* Tick past the 4000ms retransmit timer */
  dhcpv4_client_tick(&net, &cli, 5000u);

  ASSERT_TRUE(send_count > first); /* should have sent another DISCOVER */
  ASSERT_EQ(cli.state, DHCPV4_CLI_SELECTING);
}

/* ══════════════════════════════════════════════════════════════════
 * SERVER TESTS
 * ══════════════════════════════════════════════════════════════════ */

static const dhcpv4_server_cfg_t server_cfg = {
    .server_ip = 0x0A000001u,   /* 10.0.0.1   */
    .offered_ip = 0x0A000032u,  /* 10.0.0.50  */
    .subnet_mask = 0xFFFFFF00u, /* 255.255.255.0 */
    .gateway = 0x0A000001u,     /* 10.0.0.1   */
    .dns = 0,
    .lease_time_s = 3600,
};

/* Build a minimal DHCPDISCOVER client message */
static uint16_t make_client_msg(uint8_t *buf, uint8_t msg_type, uint32_t xid,
                                const uint8_t *chaddr, uint32_t req_ip,
                                uint32_t server_id) {
  memset(buf, 0, DHCP_MIN_LEN + 32);
  buf[DHCP_OFF_OP] = DHCP_OP_REQUEST;
  buf[1] = 1;
  buf[2] = 6;
  net_write32be(buf + DHCP_OFF_XID, xid);
  net_write16be(buf + DHCP_OFF_FLAGS, 0x8000u);
  memcpy(buf + DHCP_OFF_CHADDR, chaddr, 6);
  net_write32be(buf + DHCP_OFF_MAGIC, DHCP_MAGIC);
  uint16_t pos = DHCP_OFF_OPTIONS;
  buf[pos++] = OPT_MSG_TYPE;
  buf[pos++] = 1;
  buf[pos++] = msg_type;
  if (server_id) {
    buf[pos++] = OPT_SERVER_ID;
    buf[pos++] = 4;
    net_write32be(buf + pos, server_id);
    pos += 4;
  }
  if (req_ip) {
    buf[pos++] = OPT_REQUESTED_IP;
    buf[pos++] = 4;
    net_write32be(buf + pos, req_ip);
    pos += 4;
  }
  buf[pos++] = OPT_END;
  return (pos < DHCP_MIN_LEN) ? DHCP_MIN_LEN : pos;
}

/* REQ-DHCPv4-064,065: DISCOVER → OFFER */
TEST(test_dhcp_server_offer_on_discover) {
  setup();
  dhcpv4_server_init(&srv, &server_cfg, on_event, NULL);

  uint8_t chaddr[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
  uint8_t msg[DHCP_MIN_LEN + 32];
  uint16_t mlen =
      make_client_msg(msg, DHCP_MSG_DISCOVER, 0xDEAD1234u, chaddr, 0, 0);

  dhcpv4_server_input(&net, &srv, 0, chaddr, msg, mlen);

  ASSERT_TRUE(send_count >= 1);
  const uint8_t *d = sent_dhcp();
  /* REQ-DHCPv4-074: op = BOOTREPLY */
  ASSERT_EQ(d[DHCP_OFF_OP], DHCP_OP_REPLY);
  /* REQ-DHCPv4-075: xid echoed */
  ASSERT_EQ(net_read32be(d + DHCP_OFF_XID), 0xDEAD1234u);
  /* yiaddr = offered_ip */
  ASSERT_EQ(net_read32be(d + DHCP_OFF_YIADDR), server_cfg.offered_ip);
  /* Message type = OFFER */
  uint16_t opt_len = sent_dhcp_len() - DHCP_OFF_OPTIONS;
  ASSERT_EQ(find_opt_byte(d + DHCP_OFF_OPTIONS, opt_len, OPT_MSG_TYPE),
            DHCP_MSG_OFFER);
  /* REQ-DHCPv4-065: server ID, lease time, subnet mask present */
  ASSERT_EQ(find_opt_u32(d + DHCP_OFF_OPTIONS, opt_len, OPT_SERVER_ID),
            server_cfg.server_ip);
  ASSERT_EQ(find_opt_u32(d + DHCP_OFF_OPTIONS, opt_len, OPT_LEASE_TIME),
            server_cfg.lease_time_s);
  /* Event fired */
  ASSERT_EQ(last_event, DHCPV4_SRV_EVT_OFFER);
}

/* REQ-DHCPv4-068: REQUEST with correct IP → ACK */
TEST(test_dhcp_server_ack_on_correct_request) {
  setup();
  dhcpv4_server_init(&srv, &server_cfg, on_event, NULL);

  uint8_t chaddr[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02};
  uint8_t msg[DHCP_MIN_LEN + 32];
  uint16_t mlen = make_client_msg(msg, DHCP_MSG_REQUEST, 0x1234ABCDu, chaddr,
                                  server_cfg.offered_ip, server_cfg.server_ip);

  dhcpv4_server_input(&net, &srv, 0, chaddr, msg, mlen);

  ASSERT_TRUE(send_count >= 1);
  const uint8_t *d = sent_dhcp();
  uint16_t opt_len = sent_dhcp_len() - DHCP_OFF_OPTIONS;
  ASSERT_EQ(find_opt_byte(d + DHCP_OFF_OPTIONS, opt_len, OPT_MSG_TYPE),
            DHCP_MSG_ACK);
  ASSERT_EQ(net_read32be(d + DHCP_OFF_YIADDR), server_cfg.offered_ip);
  ASSERT_EQ(last_event, DHCPV4_SRV_EVT_ACK);
}

/* REQ-DHCPv4-069: REQUEST with wrong IP → NAK */
TEST(test_dhcp_server_nak_on_wrong_request) {
  setup();
  dhcpv4_server_init(&srv, &server_cfg, on_event, NULL);

  uint8_t chaddr[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03};
  uint8_t msg[DHCP_MIN_LEN + 32];
  uint16_t mlen = make_client_msg(msg, DHCP_MSG_REQUEST, 0xCAFEBABEu, chaddr,
                                  NET_IPV4(192, 168, 1, 100), /* wrong IP */
                                  server_cfg.server_ip);

  dhcpv4_server_input(&net, &srv, 0, chaddr, msg, mlen);

  ASSERT_TRUE(send_count >= 1);
  const uint8_t *d = sent_dhcp();
  uint16_t opt_len = sent_dhcp_len() - DHCP_OFF_OPTIONS;
  ASSERT_EQ(find_opt_byte(d + DHCP_OFF_OPTIONS, opt_len, OPT_MSG_TYPE),
            DHCP_MSG_NAK);
  ASSERT_EQ(last_event, DHCPV4_SRV_EVT_NAK);
}

/* REQ-DHCPv4-070: RELEASE → silently ignored */
TEST(test_dhcp_server_release_ignored) {
  setup();
  dhcpv4_server_init(&srv, &server_cfg, NULL, NULL);

  uint8_t chaddr[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x04};
  uint8_t msg[DHCP_MIN_LEN + 32];
  uint16_t mlen =
      make_client_msg(msg, 7 /* RELEASE */, 0x11223344u, chaddr, 0, 0);

  dhcpv4_server_input(&net, &srv, 0, chaddr, msg, mlen);

  ASSERT_EQ(send_count, 0); /* No reply */
}

/* REQ-DHCPv4-073: invalid op → ignored */
TEST(test_dhcp_server_invalid_op_ignored) {
  setup();
  dhcpv4_server_init(&srv, &server_cfg, NULL, NULL);

  uint8_t chaddr[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x05};
  uint8_t msg[DHCP_MIN_LEN + 32];
  uint16_t mlen =
      make_client_msg(msg, DHCP_MSG_DISCOVER, 0xABCDEF01u, chaddr, 0, 0);
  msg[DHCP_OFF_OP] = DHCP_OP_REPLY; /* flip to BOOTREPLY — should be ignored */

  dhcpv4_server_input(&net, &srv, 0, chaddr, msg, mlen);
  ASSERT_EQ(send_count, 0);
}

/* REQ-DHCPv4-073: wrong magic cookie → ignored */
TEST(test_dhcp_server_bad_magic_ignored) {
  setup();
  dhcpv4_server_init(&srv, &server_cfg, NULL, NULL);

  uint8_t chaddr[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x06};
  uint8_t msg[DHCP_MIN_LEN + 32];
  uint16_t mlen =
      make_client_msg(msg, DHCP_MSG_DISCOVER, 0xABCDEF02u, chaddr, 0, 0);
  net_write32be(msg + DHCP_OFF_MAGIC, 0xDEADBEEFu); /* corrupt magic */

  dhcpv4_server_input(&net, &srv, 0, chaddr, msg, mlen);
  ASSERT_EQ(send_count, 0);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void) {
  fprintf(stderr, "=== test_dhcpv4 ===\n");
  RUN_TEST(test_dhcp_client_init_zeros_state);
  RUN_TEST(test_dhcp_client_start_sends_discover);
  RUN_TEST(test_dhcp_client_discover_to_broadcast);
  RUN_TEST(test_dhcp_client_offer_triggers_request);
  RUN_TEST(test_dhcp_client_ack_enters_bound);
  RUN_TEST(test_dhcp_client_default_t1_t2);
  RUN_TEST(test_dhcp_client_nak_restarts_init);
  RUN_TEST(test_dhcp_client_opt_handler_called_v2);
  RUN_TEST(test_dhcp_client_null_opt_table);
  RUN_TEST(test_dhcp_client_retransmit_discover);
  RUN_TEST(test_dhcp_server_offer_on_discover);
  RUN_TEST(test_dhcp_server_ack_on_correct_request);
  RUN_TEST(test_dhcp_server_nak_on_wrong_request);
  RUN_TEST(test_dhcp_server_release_ignored);
  RUN_TEST(test_dhcp_server_invalid_op_ignored);
  RUN_TEST(test_dhcp_server_bad_magic_ignored);
  TEST_REPORT();
  return test_failures;
}
