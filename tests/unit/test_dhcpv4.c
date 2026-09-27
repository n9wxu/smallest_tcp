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
#define DHCP_OFF_SIADDR 20
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
#define DHCP_MSG_INFORM 8
#define OPT_SUBNET_MASK 1
#define OPT_ROUTER 3
#define OPT_LEASE_TIME 51
#define OPT_MSG_TYPE 53
#define OPT_SERVER_ID 54
#define OPT_REQUESTED_IP 50
#define OPT_T1 58
#define OPT_T2 59
#define OPT_END 255

/* The server's MAC, the source of its replies */
static const uint8_t server_mac[6] = {0x02, 0x53, 0x45, 0x52, 0x56, 0x01};

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

/* T1 or T2 as the client fuzzed it: less than 1/16 before @p base */
static int fuzzed(uint32_t got, uint32_t base) {
  return got <= base && got > base - base / 16u;
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
  udp_set_ports(&net, NULL, 0);
}

/* Start the client and wait out the start-up delay: the first DISCOVER has
   just gone */
static void start_discovery(void) {
  int before = send_count;
  uint32_t ms;
  dhcpv4_client_start(&net, &cli);
  for (ms = 0; send_count == before && ms <= DHCPV4_START_DELAY_MAX_MS; ms++)
    dhcpv4_client_tick(&net, &cli, 1u);
}

/* ══════════════════════════════════════════════════════════════════
 * CLIENT TESTS
 * ══════════════════════════════════════════════════════════════════ */

/* REQ-DHCPv4-001: init zeros struct */
TEST(test_dhcp_client_init_zeros_state) {
  setup();
  dhcpv4_client_init(&cli, &net, on_event, NULL, NULL);
  ASSERT_EQ(cli.state, DHCPV4_CLI_INIT);
  ASSERT_EQ(cli.xid, 0u);
  ASSERT_EQ(cli.on_event, on_event);
}

/* REQ-DHCPv4-050, 051: the frame buffers must take a DHCP message — TX a
   300-byte one, RX the 576-byte datagram a server may send (RFC 2131 §2) */
TEST(test_dhcp_client_init_checks_buffers) {
  setup();
  ASSERT_EQ(DHCPV4_CLIENT_TX_MIN, 342);
  ASSERT_EQ(DHCPV4_CLIENT_RX_MIN, 590);
  ASSERT_EQ(dhcpv4_client_init(&cli, &net, NULL, NULL, NULL), NET_OK);
  net.tx.capacity = DHCPV4_CLIENT_TX_MIN - 1;
  ASSERT_EQ(dhcpv4_client_init(&cli, &net, NULL, NULL, NULL),
            NET_ERR_BUF_TOO_SMALL);
  net.tx.capacity = DHCPV4_CLIENT_TX_MIN;
  net.rx.capacity = DHCPV4_CLIENT_RX_MIN - 1;
  ASSERT_EQ(dhcpv4_client_init(&cli, &net, NULL, NULL, NULL),
            NET_ERR_BUF_TOO_SMALL);
  net.rx.capacity = DHCPV4_CLIENT_RX_MIN;
  ASSERT_EQ(dhcpv4_client_init(&cli, &net, NULL, NULL, NULL), NET_OK);
  ASSERT_EQ(dhcpv4_client_init(NULL, &net, NULL, NULL, NULL),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(dhcpv4_client_init(&cli, NULL, NULL, NULL, NULL),
            NET_ERR_INVALID_PARAM);
}

/* REQ-DHCPv4-002, 008..017: DHCPDISCOVER sent on start */
TEST(test_dhcp_client_start_sends_discover) {
  setup();
  dhcpv4_client_init(&cli, &net, NULL, NULL, NULL);
  start_discovery();

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
  dhcpv4_client_init(&cli, &net, NULL, NULL, NULL);
  start_discovery();

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
  dhcpv4_client_init(&cli, &net, NULL, NULL, NULL);
  start_discovery();

  int discovers = send_count;
  uint32_t xid = cli.xid;

  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen = make_server_msg(
      msg, DHCP_MSG_OFFER, xid, NET_IPV4(10, 0, 0, 50), NET_IPV4(10, 0, 0, 1),
      3600, 0, 0, NET_IPV4(255, 255, 255, 0), NET_IPV4(10, 0, 0, 1));

  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), server_mac, msg, mlen);

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
  dhcpv4_client_init(&cli, &net, on_event, NULL, NULL);
  start_discovery();

  uint32_t xid = cli.xid;
  uint8_t msg[DHCP_MIN_LEN + 64];
  /* Feed OFFER first */
  uint16_t mlen =
      make_server_msg(msg, DHCP_MSG_OFFER, xid, NET_IPV4(10, 0, 0, 50),
                      NET_IPV4(10, 0, 0, 1), 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), server_mac, msg, mlen);

  /* Feed ACK */
  mlen = make_server_msg(msg, DHCP_MSG_ACK, xid, NET_IPV4(10, 0, 0, 50),
                         NET_IPV4(10, 0, 0, 1), 3600, 1800, 3150,
                         NET_IPV4(255, 255, 255, 0), NET_IPV4(10, 0, 0, 1));
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), server_mac, msg, mlen);

  ASSERT_EQ(cli.state, DHCPV4_CLI_BOUND);
  ASSERT_EQ(net.ipv4_addr, NET_IPV4(10, 0, 0, 50));       /* REQ-DHCPv4-029 */
  ASSERT_EQ(net.subnet_mask, NET_IPV4(255, 255, 255, 0)); /* REQ-DHCPv4-030 */
  ASSERT_EQ(net.gateway_ipv4, NET_IPV4(10, 0, 0, 1));     /* REQ-DHCPv4-031 */
  ASSERT_EQ(cli.lease_time, 3600u);                       /* REQ-DHCPv4-033 */
  ASSERT_TRUE(fuzzed(cli.t1, 1800u));                     /* REQ-DHCPv4-034 */
  ASSERT_TRUE(fuzzed(cli.t2, 3150u));                     /* REQ-DHCPv4-034 */
  ASSERT_EQ(event_count, 1);
  ASSERT_EQ(last_event, DHCPV4_EVT_BOUND);
}

/* REQ-DHCPv4-035,036: default T1/T2 when not present in ACK */
TEST(test_dhcp_client_default_t1_t2) {
  setup();
  dhcpv4_client_init(&cli, &net, NULL, NULL, NULL);
  start_discovery();

  uint32_t xid = cli.xid;
  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen =
      make_server_msg(msg, DHCP_MSG_OFFER, xid, NET_IPV4(10, 0, 0, 50),
                      NET_IPV4(10, 0, 0, 1), 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), server_mac, msg, mlen);

  /* ACK without T1/T2 */
  mlen = make_server_msg(msg, DHCP_MSG_ACK, xid, NET_IPV4(10, 0, 0, 50),
                         NET_IPV4(10, 0, 0, 1), 3600, 0, 0,
                         NET_IPV4(255, 255, 255, 0), 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), server_mac, msg, mlen);

  ASSERT_EQ(cli.state, DHCPV4_CLI_BOUND);
  ASSERT_TRUE(fuzzed(cli.t1, 1800u)); /* 0.5 × 3600 — REQ-DHCPv4-035 */
  ASSERT_TRUE(fuzzed(cli.t2, 3150u)); /* 0.875 × 3600 — REQ-DHCPv4-036 */
}

/* REQ-DHCPv4-037..038: NAK → restart INIT, IP cleared */
TEST(test_dhcp_client_nak_restarts_init) {
  setup();
  dhcpv4_client_init(&cli, &net, on_event, NULL, NULL);
  start_discovery();

  uint32_t xid = cli.xid;
  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen =
      make_server_msg(msg, DHCP_MSG_OFFER, xid, NET_IPV4(10, 0, 0, 50),
                      NET_IPV4(10, 0, 0, 1), 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), server_mac, msg, mlen);

  /* Feed NAK */
  mlen = make_server_msg(msg, DHCP_MSG_NAK, xid, 0, NET_IPV4(10, 0, 0, 1), 0, 0,
                         0, 0, 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), server_mac, msg, mlen);

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

  dhcpv4_client_init(&cli, &net, NULL, NULL, &tbl);
  start_discovery();
  uint32_t xid = cli.xid;

  /* OFFER */
  uint8_t offer[DHCP_MIN_LEN + 64];
  uint16_t olen =
      make_server_msg(offer, DHCP_MSG_OFFER, xid, NET_IPV4(10, 0, 0, 50),
                      NET_IPV4(10, 0, 0, 1), 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), server_mac, offer, olen);

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

  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), server_mac, msg, mlen);

  ASSERT_EQ(cli.state, DHCPV4_CLI_BOUND);
  ASSERT_TRUE(s_dns_called);
  ASSERT_EQ(net_read32be(s_got_dns), NET_IPV4(8, 8, 8, 8));
}

/* REQ-DHCPv4-058: NULL opt_table — no handlers, still applies mandatory opts */
TEST(test_dhcp_client_null_opt_table) {
  setup();
  dhcpv4_client_init(&cli, &net, NULL, NULL, NULL); /* NULL opt_table */
  start_discovery();
  uint32_t xid = cli.xid;

  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen =
      make_server_msg(msg, DHCP_MSG_OFFER, xid, NET_IPV4(10, 0, 0, 50),
                      NET_IPV4(10, 0, 0, 1), 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), server_mac, msg, mlen);

  mlen = make_server_msg(msg, DHCP_MSG_ACK, xid, NET_IPV4(10, 0, 0, 50),
                         NET_IPV4(10, 0, 0, 1), 3600, 0, 0,
                         NET_IPV4(255, 255, 255, 0), 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), server_mac, msg, mlen);

  ASSERT_EQ(cli.state, DHCPV4_CLI_BOUND);
  ASSERT_EQ(net.ipv4_addr, NET_IPV4(10, 0, 0, 50));
  ASSERT_EQ(net.subnet_mask, NET_IPV4(255, 255, 255, 0));
}

/* REQ-DHCPv4-045: retransmit DISCOVER after timer expiry */
TEST(test_dhcp_client_retransmit_discover) {
  setup();
  dhcpv4_client_init(&cli, &net, NULL, NULL, NULL);
  start_discovery();
  int first = send_count;

  /* Tick past the 4000ms retransmit timer */
  dhcpv4_client_tick(&net, &cli, 5000u);

  ASSERT_TRUE(send_count > first); /* should have sent another DISCOVER */
  ASSERT_EQ(cli.state, DHCPV4_CLI_SELECTING);
}

/* ── Helpers: retransmission timing ──────────────────────────────── */

/* Tick 1 ms at a time until the client sends (at most limit_ms); the ms
   waited */
static uint32_t ms_until_sent(uint32_t limit_ms) {
  int before = send_count;
  uint32_t ms = 0;
  while (send_count == before && ms < limit_ms) {
    dhcpv4_client_tick(&net, &cli, 1u);
    ms++;
  }
  return ms;
}

/* 1 if ms is base_ms ± 1 s; says what it was if not */
static int within_a_second(uint32_t ms, uint32_t base_ms) {
  if (ms + 1000u >= base_ms && ms <= base_ms + 1000u)
    return 1;
  fprintf(stderr, "    waited %lu ms, expected %lu ± 1000\n", (unsigned long)ms,
          (unsigned long)base_ms);
  return 0;
}

/* REQ-DHCPv4-045: 4, 8, 16, 32, then 64 s between DISCOVERs, ±1 s */
TEST(test_dhcp_client_discover_backoff) {
  static const uint32_t base_ms[] = {4000, 8000, 16000, 32000, 64000, 64000};
  uint8_t i;
  setup();
  dhcpv4_client_init(&cli, &net, NULL, NULL, NULL);
  start_discovery();
  for (i = 0; i < 6; i++)
    ASSERT_TRUE(within_a_second(ms_until_sent(70000u), base_ms[i]));
  ASSERT_EQ(cli.state, DHCPV4_CLI_SELECTING);
}

/* REQ-DHCPv4-046: the wait is randomised */
TEST(test_dhcp_client_backoff_randomised) {
  uint32_t seed, first = 0, waited;
  int differs = 0;
  for (seed = 1; seed <= 8; seed++) {
    setup();
    net_random_seed(&net, seed * 0x9E3779B9u);
    dhcpv4_client_init(&cli, &net, NULL, NULL, NULL);
    start_discovery();
    waited = ms_until_sent(10000u);
    ASSERT_TRUE(within_a_second(waited, 4000u));
    if (seed == 1)
      first = waited;
    else if (waited != first)
      differs = 1;
  }
  ASSERT_TRUE(differs);
}

static uint8_t sent_msg_type(void) {
  return find_opt_byte(sent_dhcp() + DHCP_OFF_OPTIONS,
                       sent_dhcp_len() - DHCP_OFF_OPTIONS, OPT_MSG_TYPE);
}

/* RFC 2131 §4.4.1: the first DISCOVER waits a random one to ten seconds,
   so devices powered up together do not all ask at once; the client is in
   INIT meanwhile */
TEST(test_dhcp_client_start_waits_one_to_ten_seconds) {
  uint32_t seed, first = 0, waited;
  int differs = 0;
  ASSERT_EQ(DHCPV4_START_DELAY_MAX_MS, 10000);
  for (seed = 1; seed <= 8; seed++) {
    setup();
    net_random_seed(&net, seed * 0x9E3779B9u);
    dhcpv4_client_init(&cli, &net, NULL, NULL, NULL);
    dhcpv4_client_start(&net, &cli);
    ASSERT_EQ(send_count, 0);
    ASSERT_EQ(cli.state, DHCPV4_CLI_INIT);
    waited = ms_until_sent(11000u);
    ASSERT_TRUE(waited >= 1000u && waited <= 10000u);
    ASSERT_EQ(sent_msg_type(), DHCP_MSG_DISCOVER);
    ASSERT_EQ(cli.state, DHCPV4_CLI_SELECTING);
    if (seed == 1)
      first = waited;
    else if (waited != first)
      differs = 1;
  }
  ASSERT_TRUE(differs);
}

/* RFC 2131 §3.1, §4.4.1: four REQUEST retransmissions unanswered —
   discovery starts again, with a new xid, and the application is told */
TEST(test_dhcp_client_requesting_gives_up) {
  static const uint32_t base_ms[] = {4000, 8000, 16000, 32000};
  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen;
  uint32_t xid;
  uint8_t i;
  setup();
  dhcpv4_client_init(&cli, &net, on_event, NULL, NULL);
  start_discovery();
  xid = cli.xid;
  mlen = make_server_msg(msg, DHCP_MSG_OFFER, xid, NET_IPV4(10, 0, 0, 50),
                         NET_IPV4(10, 0, 0, 1), 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, NET_IPV4(10, 0, 0, 1), server_mac, msg, mlen);

  for (i = 0; i < 4; i++) {
    ASSERT_TRUE(within_a_second(ms_until_sent(70000u), base_ms[i]));
    ASSERT_EQ(sent_msg_type(), DHCP_MSG_REQUEST);
  }
  ASSERT_EQ(event_count, 0);
  ASSERT_TRUE(within_a_second(ms_until_sent(70000u), 64000u));
  ASSERT_EQ(cli.state, DHCPV4_CLI_SELECTING);
  ASSERT_EQ(sent_msg_type(), DHCP_MSG_DISCOVER);
  ASSERT_NE(cli.xid, xid);
  ASSERT_EQ(event_count, 1);
  ASSERT_EQ(last_event, DHCPV4_EVT_TIMEOUT);
}

/* ── Helpers: the lease clock ─────────────────────────────────────── */

#define SERVER_IP NET_IPV4(10, 0, 0, 1)
#define BROADCAST_IP 0xFFFFFFFFu

static uint32_t clock_s; /* seconds since bind_lease() */

/* Start, take the OFFER and bind with the ACK's lease, T1 and T2 (0 =
   absent); the clock starts at 0 and the frames sent so far are forgotten.
   T1 and T2 are as the client fuzzed them. */
static void bind_lease_fuzzed(uint32_t lease, uint32_t t1, uint32_t t2) {
  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen;
  dhcpv4_client_init(&cli, &net, on_event, NULL, NULL);
  start_discovery();
  mlen = make_server_msg(msg, DHCP_MSG_OFFER, cli.xid, NET_IPV4(10, 0, 0, 50),
                         SERVER_IP, lease, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, SERVER_IP, server_mac, msg, mlen);
  mlen = make_server_msg(msg, DHCP_MSG_ACK, cli.xid, NET_IPV4(10, 0, 0, 50),
                         SERVER_IP, lease, t1, t2, NET_IPV4(255, 255, 255, 0),
                         SERVER_IP);
  dhcpv4_client_input(&net, &cli, SERVER_IP, server_mac, msg, mlen);
  send_count = 0;
  clock_s = 0;
}

/* As bind_lease_fuzzed(), with T1 and T2 exactly as given or the defaults:
   the schedule tests count from them (the fuzz has its own test) */
static void bind_lease(uint32_t lease, uint32_t t1, uint32_t t2) {
  bind_lease_fuzzed(lease, t1, t2);
  cli.t1 = t1 ? t1 : lease / 2u;
  cli.t2 = t2 ? t2 : lease - lease / 8u;
  cli.next_request_s = cli.t1;
}

static void tick_seconds(uint32_t step_s) {
  dhcpv4_client_tick(&net, &cli, step_s * 1000u);
  clock_s += step_s;
}

/* Tick step_s at a time until the client sends (for at most limit_s); the
   clock then */
static uint32_t clock_at_next_send(uint32_t step_s, uint32_t limit_s) {
  int before = send_count;
  uint32_t end = clock_s + limit_s;
  while (send_count == before && clock_s < end)
    tick_seconds(step_s);
  return clock_s;
}

/* Tick step_s at a time until the client is in state (for at most
   limit_s); the clock then */
static uint32_t clock_at_state(uint8_t state, uint32_t step_s,
                               uint32_t limit_s) {
  uint32_t end = clock_s + limit_s;
  while (cli.state != state && clock_s < end)
    tick_seconds(step_s);
  return clock_s;
}

/* 1 if got == want; says what it got if not */
static int is_u32(uint32_t got, uint32_t want) {
  if (got == want)
    return 1;
  fprintf(stderr, "    got %lu, expected %lu\n", (unsigned long)got,
          (unsigned long)want);
  return 0;
}

static uint32_t sent_ip_dst(void) { return net_read32be(sent_frame + 14 + 16); }

/* 1 if the next frame, a second at a time, is sent at at_s, in state, to
   dst_ip; says what it was if not */
static int next_sent_is(uint32_t at_s, uint8_t state, uint32_t dst_ip) {
  uint32_t t = clock_at_next_send(1u, 4000u);
  if (t == at_s && cli.state == state && sent_ip_dst() == dst_ip)
    return 1;
  fprintf(stderr,
          "    sent at %lu s in state %u to %08lx, expected %lu s in state %u "
          "to %08lx\n",
          (unsigned long)t, cli.state, (unsigned long)sent_ip_dst(),
          (unsigned long)at_s, state, (unsigned long)dst_ip);
  return 0;
}

/* REQ-DHCPv4-005..007, 026, 027: through a whole 3600 s lease (T1 1800 s,
   T2 3150 s) — REQUESTs to the server, then broadcast, each after half the
   time left until T2 or expiry but at least 60 s later; at expiry the
   address goes and a DISCOVER follows (RFC 2131 §4.4.5) */
TEST(test_dhcp_client_renew_rebind_timing) {
  setup();
  bind_lease(3600, 0, 0);
  ASSERT_TRUE(next_sent_is(1800, DHCPV4_CLI_RENEWING, SERVER_IP));
  ASSERT_TRUE(next_sent_is(2475, DHCPV4_CLI_RENEWING, SERVER_IP));
  ASSERT_TRUE(next_sent_is(2812, DHCPV4_CLI_RENEWING, SERVER_IP));
  ASSERT_TRUE(next_sent_is(2981, DHCPV4_CLI_RENEWING, SERVER_IP));
  ASSERT_TRUE(next_sent_is(3065, DHCPV4_CLI_RENEWING, SERVER_IP));
  ASSERT_TRUE(next_sent_is(3125, DHCPV4_CLI_RENEWING, SERVER_IP));
  ASSERT_TRUE(next_sent_is(3150, DHCPV4_CLI_REBINDING, BROADCAST_IP));
  ASSERT_TRUE(next_sent_is(3375, DHCPV4_CLI_REBINDING, BROADCAST_IP));
  ASSERT_TRUE(next_sent_is(3487, DHCPV4_CLI_REBINDING, BROADCAST_IP));
  ASSERT_TRUE(next_sent_is(3547, DHCPV4_CLI_REBINDING, BROADCAST_IP));
  ASSERT_EQ(event_count, 1); /* BOUND */
  ASSERT_TRUE(next_sent_is(3600, DHCPV4_CLI_SELECTING, BROADCAST_IP));
  ASSERT_EQ(sent_msg_type(), DHCP_MSG_DISCOVER);
  ASSERT_EQ(send_count, 11);
  ASSERT_EQ(last_event, DHCPV4_EVT_EXPIRED);
  ASSERT_EQ(net.ipv4_addr, 0u);
}

/* REQ-DHCPv4-026, 040: a renewing REQUEST and a RELEASE are unicast to the
   server — at the MAC its ACK came from, not the broadcast MAC */
TEST(test_dhcp_client_unicasts_to_the_server_mac) {
  setup();
  bind_lease(3600, 0, 0);
  ASSERT_TRUE(next_sent_is(1800, DHCPV4_CLI_RENEWING, SERVER_IP));
  ASSERT_MEM_EQ(sent_frame, server_mac, 6);
  dhcpv4_client_release(&net, &cli);
  ASSERT_EQ(sent_ip_dst(), SERVER_IP);
  ASSERT_MEM_EQ(sent_frame, server_mac, 6);
}

/* RFC 2131 §4.3.2: only a REQUEST selecting an offer names the server;
   one extending the lease MUST NOT carry the Server Identifier */
static uint32_t sent_server_id(void) {
  return find_opt_u32(sent_dhcp() + DHCP_OFF_OPTIONS,
                      sent_dhcp_len() - DHCP_OFF_OPTIONS, OPT_SERVER_ID);
}

TEST(test_dhcp_client_server_id_only_when_selecting) {
  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen;
  setup();
  dhcpv4_client_init(&cli, &net, NULL, NULL, NULL);
  start_discovery();
  mlen = make_server_msg(msg, DHCP_MSG_OFFER, cli.xid, NET_IPV4(10, 0, 0, 50),
                         SERVER_IP, 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, SERVER_IP, server_mac, msg, mlen);
  ASSERT_EQ(sent_msg_type(), DHCP_MSG_REQUEST);
  ASSERT_EQ(sent_server_id(), SERVER_IP);

  bind_lease(3600, 0, 0);
  ASSERT_TRUE(next_sent_is(1800, DHCPV4_CLI_RENEWING, SERVER_IP));
  ASSERT_EQ(sent_msg_type(), DHCP_MSG_REQUEST);
  ASSERT_EQ(sent_server_id(), 0u);
  ASSERT_TRUE(is_u32(clock_at_state(DHCPV4_CLI_REBINDING, 1u, 4000u), 3150u));
  ASSERT_EQ(sent_ip_dst(), BROADCAST_IP);
  ASSERT_EQ(sent_msg_type(), DHCP_MSG_REQUEST);
  ASSERT_EQ(sent_server_id(), 0u);
}

/* REQ-DHCPv4-037: a NAK must come from the server asked — the one selected
   (REQUESTING) or ours (RENEWING); rebinding asks every server, and any
   may refuse.  A NAK names its server (RFC 2131 Table 3): one without is
   malformed. */
#define OTHER_SERVER NET_IPV4(10, 0, 0, 9)

static void nak_from(uint32_t server_id) {
  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen = make_server_msg(msg, DHCP_MSG_NAK, cli.xid, 0,
                                  server_id ? server_id : 1u, 0, 0, 0, 0, 0);
  if (!server_id) /* no Server Identifier: turn option 54 into another */
    msg[DHCP_OFF_OPTIONS + 3] = 250;
  dhcpv4_client_input(&net, &cli, server_id, server_mac, msg, mlen);
}

TEST(test_dhcp_client_nak_from_the_server_asked) {
  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen;
  setup();
  dhcpv4_client_init(&cli, &net, on_event, NULL, NULL);
  start_discovery();
  mlen = make_server_msg(msg, DHCP_MSG_OFFER, cli.xid, NET_IPV4(10, 0, 0, 50),
                         SERVER_IP, 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, SERVER_IP, server_mac, msg, mlen);
  nak_from(OTHER_SERVER);
  nak_from(0);
  ASSERT_EQ(cli.state, DHCPV4_CLI_REQUESTING);
  ASSERT_EQ(event_count, 0);
  nak_from(SERVER_IP);
  ASSERT_EQ(cli.state, DHCPV4_CLI_SELECTING);
  ASSERT_EQ(last_event, DHCPV4_EVT_NAK);

  bind_lease(3600, 0, 0);
  ASSERT_TRUE(next_sent_is(1800, DHCPV4_CLI_RENEWING, SERVER_IP));
  event_count = 0;
  nak_from(OTHER_SERVER);
  nak_from(0);
  ASSERT_EQ(cli.state, DHCPV4_CLI_RENEWING);
  ASSERT_EQ(event_count, 0);
  ASSERT_EQ(net.ipv4_addr, NET_IPV4(10, 0, 0, 50));
  nak_from(SERVER_IP);
  ASSERT_EQ(cli.state, DHCPV4_CLI_SELECTING);
  ASSERT_EQ(net.ipv4_addr, 0u);

  bind_lease(3600, 0, 0);
  ASSERT_TRUE(is_u32(clock_at_state(DHCPV4_CLI_REBINDING, 1u, 4000u), 3150u));
  event_count = 0;
  nak_from(0);
  ASSERT_EQ(cli.state, DHCPV4_CLI_REBINDING);
  nak_from(OTHER_SERVER);
  ASSERT_EQ(cli.state, DHCPV4_CLI_SELECTING);
  ASSERT_EQ(last_event, DHCPV4_EVT_NAK);
}

/* REQ-DHCPv4-033; RFC 2131 Table 3: an ACK to a REQUEST carries the lease
   time.  One without — or with a lease of 0 s — grants nothing and is
   dropped: taken, it left the client bound for good, like an infinite
   lease */
static void ack_without_lease(int zero_lease) {
  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen = make_server_msg(msg, DHCP_MSG_ACK, cli.xid,
                                  NET_IPV4(10, 0, 0, 50), SERVER_IP,
                                  zero_lease ? 1u : 0u, 0, 0, 0, 0);
  if (zero_lease) /* options: 53 (3 bytes), 54 (6), 51 — its value */
    net_write32be(msg + DHCP_OFF_OPTIONS + 11, 0);
  dhcpv4_client_input(&net, &cli, SERVER_IP, server_mac, msg, mlen);
}

TEST(test_dhcp_client_ack_without_lease_time_dropped) {
  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen;
  setup();
  dhcpv4_client_init(&cli, &net, on_event, NULL, NULL);
  start_discovery();
  mlen = make_server_msg(msg, DHCP_MSG_OFFER, cli.xid, NET_IPV4(10, 0, 0, 50),
                         SERVER_IP, 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, SERVER_IP, server_mac, msg, mlen);
  ack_without_lease(0);
  ack_without_lease(1);
  ASSERT_EQ(cli.state, DHCPV4_CLI_REQUESTING);
  ASSERT_EQ(event_count, 0);

  bind_lease(3600, 0, 0);
  ASSERT_TRUE(next_sent_is(1800, DHCPV4_CLI_RENEWING, SERVER_IP));
  ack_without_lease(0);
  ack_without_lease(1);
  ASSERT_EQ(cli.state, DHCPV4_CLI_RENEWING);
  ASSERT_EQ(event_count, 1); /* BOUND only */
  ASSERT_TRUE(is_u32(clock_at_state(DHCPV4_CLI_SELECTING, 10u, 4000u), 3600u));
  ASSERT_EQ(last_event, DHCPV4_EVT_EXPIRED);
}

/* RFC 2131 §4.4.1, §4.4.5: the lease runs from when the original REQUEST
   was sent — the first of REQUESTING, RENEWING or REBINDING — not from
   the ACK, which comes a round trip or more later */
TEST(test_dhcp_client_lease_timed_from_the_request) {
  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen;
  setup();
  dhcpv4_client_init(&cli, &net, on_event, NULL, NULL);
  start_discovery();
  mlen = make_server_msg(msg, DHCP_MSG_OFFER, cli.xid, NET_IPV4(10, 0, 0, 50),
                         SERVER_IP, 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, SERVER_IP, server_mac, msg, mlen);
  dhcpv4_client_tick(&net, &cli, 2000u); /* the ACK takes 2 s */
  mlen = make_server_msg(msg, DHCP_MSG_ACK, cli.xid, NET_IPV4(10, 0, 0, 50),
                         SERVER_IP, 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, SERVER_IP, server_mac, msg, mlen);
  ASSERT_EQ(cli.state, DHCPV4_CLI_BOUND);
  send_count = 0;
  clock_s = 2; /* since the REQUEST */
  ASSERT_TRUE(is_u32(clock_at_next_send(1u, 4000u), cli.t1));

  /* A renewal answered after a retransmission: from the first REQUEST */
  bind_lease(3600, 0, 0);
  ASSERT_TRUE(next_sent_is(1800, DHCPV4_CLI_RENEWING, SERVER_IP));
  ASSERT_TRUE(next_sent_is(2475, DHCPV4_CLI_RENEWING, SERVER_IP));
  tick_seconds(5);
  mlen = make_server_msg(msg, DHCP_MSG_ACK, cli.xid, NET_IPV4(10, 0, 0, 50),
                         SERVER_IP, 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, SERVER_IP, server_mac, msg, mlen);
  ASSERT_EQ(last_event, DHCPV4_EVT_RENEWED);
  ASSERT_TRUE(is_u32(clock_at_next_send(1u, 4000u), 1800u + cli.t1));
}

/* REQ-DHCPv4-005, 055: an ACK while RENEWING starts the lease again —
   from the renewal's REQUEST at 1800 s, not from the ACK 100 s later */
TEST(test_dhcp_client_renewal_restarts_lease) {
  uint8_t msg[DHCP_MIN_LEN + 64];
  uint16_t mlen;
  setup();
  bind_lease(3600, 0, 0);
  ASSERT_TRUE(is_u32(clock_at_next_send(1u, 4000u), 1800u));
  tick_seconds(100);
  mlen = make_server_msg(msg, DHCP_MSG_ACK, cli.xid, NET_IPV4(10, 0, 0, 50),
                         SERVER_IP, 3600, 0, 0, 0, 0);
  dhcpv4_client_input(&net, &cli, SERVER_IP, server_mac, msg, mlen);
  ASSERT_EQ(cli.state, DHCPV4_CLI_BOUND);
  ASSERT_EQ(last_event, DHCPV4_EVT_RENEWED);
  ASSERT_TRUE(is_u32(clock_at_next_send(1u, 4000u), 1800u + cli.t1));
  ASSERT_EQ(cli.state, DHCPV4_CLI_RENEWING);
}

/* RFC 2131 §4.4.5: T1 and T2 "with some random fuzz", so clients bound
   together do not renew together: both come forward by the same random
   share of themselves, less than 1/16 — never later than the server said,
   and in their order.  An infinite lease has neither. */
TEST(test_dhcp_client_t1_t2_fuzzed) {
  uint32_t seed, first_t1 = 0;
  int differs = 0;
  for (seed = 1; seed <= 8; seed++) {
    setup();
    net_random_seed(&net, seed * 0x9E3779B9u);
    bind_lease_fuzzed(3600, 0, 0);
    ASSERT_TRUE(fuzzed(cli.t1, 1800u));
    ASSERT_TRUE(fuzzed(cli.t2, 3150u));
    ASSERT_TRUE(is_u32(clock_at_next_send(1u, 4000u), cli.t1));
    if (seed == 1)
      first_t1 = cli.t1;
    else if (cli.t1 != first_t1)
      differs = 1;
    bind_lease_fuzzed(30000000u, 5000000u, 15000000u);
    ASSERT_TRUE(fuzzed(cli.t1, 5000000u));
    ASSERT_TRUE(fuzzed(cli.t2, 15000000u));
  }
  ASSERT_TRUE(differs);
  bind_lease_fuzzed(0xFFFFFFFFu, 0, 0);
  ASSERT_TRUE(is_u32(clock_at_next_send(3600u, 400u * 86400u), 400u * 86400u));
}

/* RFC 2131 §3.3: an infinite lease is never renewed and never expires,
   whatever T1 and T2 say */
TEST(test_dhcp_client_infinite_lease) {
  setup();
  bind_lease(0xFFFFFFFFu, 0, 0);
  ASSERT_TRUE(is_u32(clock_at_next_send(3600u, 400u * 86400u), 400u * 86400u));
  ASSERT_EQ(cli.state, DHCPV4_CLI_BOUND);
  ASSERT_EQ(net.ipv4_addr, NET_IPV4(10, 0, 0, 50));

  bind_lease(0xFFFFFFFFu, 1800, 3150);
  ASSERT_TRUE(is_u32(clock_at_next_send(60u, 86400u), 86400u));
  ASSERT_EQ(cli.state, DHCPV4_CLI_BOUND);
}

/* REQ-DHCPv4-047: a lease, T1, T2 and the waits between them far past
   2^32 ms (49.7 days) — 30,000,000 s, T1 5,000,000 s, T2 15,000,000 s */
TEST(test_dhcp_client_long_lease) {
  setup();
  bind_lease(30000000u, 5000000u, 15000000u);
  ASSERT_TRUE(is_u32(clock_at_next_send(1000u, 40000000u), 5000000u));
  ASSERT_EQ(cli.state, DHCPV4_CLI_RENEWING);
  ASSERT_TRUE(is_u32(clock_at_next_send(1000u, 40000000u), 10000000u));
  ASSERT_TRUE(is_u32(clock_at_state(DHCPV4_CLI_REBINDING, 1000u, 40000000u),
                     15000000u));
  ASSERT_TRUE(is_u32(clock_at_next_send(1000u, 40000000u), 22500000u));
  ASSERT_TRUE(is_u32(clock_at_state(DHCPV4_CLI_SELECTING, 1000u, 40000000u),
                     30000000u));
  ASSERT_EQ(last_event, DHCPV4_EVT_EXPIRED);
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

/* REQ-DHCPv4-078: the frame buffers must take a DHCP message both ways */
TEST(test_dhcp_server_init_checks_buffers) {
  setup();
  ASSERT_EQ(DHCPV4_SERVER_TX_MIN, 342);
  ASSERT_EQ(DHCPV4_SERVER_RX_MIN, 342);
  ASSERT_EQ(dhcpv4_server_init(&srv, &net, &server_cfg, NULL, NULL), NET_OK);
  net.tx.capacity = DHCPV4_SERVER_TX_MIN - 1;
  ASSERT_EQ(dhcpv4_server_init(&srv, &net, &server_cfg, NULL, NULL),
            NET_ERR_BUF_TOO_SMALL);
  net.tx.capacity = DHCPV4_SERVER_TX_MIN;
  net.rx.capacity = DHCPV4_SERVER_RX_MIN - 1;
  ASSERT_EQ(dhcpv4_server_init(&srv, &net, &server_cfg, NULL, NULL),
            NET_ERR_BUF_TOO_SMALL);
  net.rx.capacity = DHCPV4_SERVER_RX_MIN;
  ASSERT_EQ(dhcpv4_server_init(&srv, &net, &server_cfg, NULL, NULL), NET_OK);
  ASSERT_EQ(dhcpv4_server_init(&srv, &net, NULL, NULL, NULL),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(dhcpv4_server_init(NULL, &net, &server_cfg, NULL, NULL),
            NET_ERR_INVALID_PARAM);
  ASSERT_EQ(dhcpv4_server_init(&srv, NULL, &server_cfg, NULL, NULL),
            NET_ERR_INVALID_PARAM);
}

/* REQ-DHCPv4-064,065: DISCOVER → OFFER */
TEST(test_dhcp_server_offer_on_discover) {
  setup();
  dhcpv4_server_init(&srv, &net, &server_cfg, on_event, NULL);

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
  dhcpv4_server_init(&srv, &net, &server_cfg, on_event, NULL);

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
  dhcpv4_server_init(&srv, &net, &server_cfg, on_event, NULL);

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
  dhcpv4_server_init(&srv, &net, &server_cfg, NULL, NULL);

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
  dhcpv4_server_init(&srv, &net, &server_cfg, NULL, NULL);

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
  dhcpv4_server_init(&srv, &net, &server_cfg, NULL, NULL);

  uint8_t chaddr[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x06};
  uint8_t msg[DHCP_MIN_LEN + 32];
  uint16_t mlen =
      make_client_msg(msg, DHCP_MSG_DISCOVER, 0xABCDEF02u, chaddr, 0, 0);
  net_write32be(msg + DHCP_OFF_MAGIC, 0xDEADBEEFu); /* corrupt magic */

  dhcpv4_server_input(&net, &srv, 0, chaddr, msg, mlen);
  ASSERT_EQ(send_count, 0);
}

/* 1 if every option of the message sent is one of the n codes; says which
   is not if not */
static int sent_options_only(const uint8_t *codes, size_t n) {
  const uint8_t *o = sent_dhcp() + DHCP_OFF_OPTIONS;
  uint16_t len = sent_dhcp_len() - DHCP_OFF_OPTIONS, i = 0;
  while (i + 1 < len && o[i] != OPT_END) {
    if (o[i] != 0 && !memchr(codes, o[i], n)) {
      fprintf(stderr, "    option %u sent\n", o[i]);
      return 0;
    }
    i = (uint16_t)(i + (o[i] ? 2 + o[i + 1] : 1));
  }
  return 1;
}

/* RFC 2131 Table 3: a DHCPNAK carries only the message type and server
   identifier; ciaddr, yiaddr and siaddr are 0 */
TEST(test_dhcp_server_nak_is_bare) {
  static const uint8_t allowed[] = {OPT_MSG_TYPE, OPT_SERVER_ID};
  uint8_t chaddr[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x07};
  uint8_t msg[DHCP_MIN_LEN + 32];
  uint16_t mlen;
  const uint8_t *d;
  setup();
  dhcpv4_server_init(&srv, &net, &server_cfg, on_event, NULL);
  mlen = make_client_msg(msg, DHCP_MSG_REQUEST, 0x5EED0001u, chaddr, 0,
                         server_cfg.server_ip);
  net_write32be(msg + DHCP_OFF_CIADDR, NET_IPV4(192, 168, 1, 100));

  dhcpv4_server_input(&net, &srv, NET_IPV4(192, 168, 1, 100), chaddr, msg,
                      mlen);

  ASSERT_EQ(last_event, DHCPV4_SRV_EVT_NAK);
  ASSERT_EQ(sent_msg_type(), DHCP_MSG_NAK);
  ASSERT_TRUE(sent_options_only(allowed, sizeof(allowed)));
  d = sent_dhcp();
  ASSERT_EQ(net_read32be(d + DHCP_OFF_CIADDR), 0u);
  ASSERT_EQ(net_read32be(d + DHCP_OFF_YIADDR), 0u);
  ASSERT_EQ(net_read32be(d + DHCP_OFF_SIADDR), 0u);
}

/* REQ-DHCPv4-071; RFC 2131 §4.3.5, Table 3: the DHCPACK to a DHCPINFORM
   carries the configuration but no lease time; yiaddr is 0 and ciaddr the
   client's, to which it is sent */
TEST(test_dhcp_server_inform_ack_has_no_lease) {
  static const uint8_t allowed[] = {OPT_MSG_TYPE, OPT_SERVER_ID,
                                    OPT_SUBNET_MASK, OPT_ROUTER, 6 /* DNS */};
  uint8_t chaddr[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x08};
  uint8_t msg[DHCP_MIN_LEN + 32];
  uint16_t mlen, opt_len;
  const uint8_t *d;
  setup();
  dhcpv4_server_init(&srv, &net, &server_cfg, on_event, NULL);
  mlen = make_client_msg(msg, DHCP_MSG_INFORM, 0x5EED0002u, chaddr, 0, 0);
  net_write16be(msg + DHCP_OFF_FLAGS, 0);
  net_write32be(msg + DHCP_OFF_CIADDR, NET_IPV4(10, 0, 0, 77));

  dhcpv4_server_input(&net, &srv, NET_IPV4(10, 0, 0, 77), chaddr, msg, mlen);

  ASSERT_EQ(last_event, DHCPV4_SRV_EVT_ACK);
  ASSERT_EQ(sent_msg_type(), DHCP_MSG_ACK);
  ASSERT_TRUE(sent_options_only(allowed, sizeof(allowed)));
  d = sent_dhcp();
  opt_len = sent_dhcp_len() - DHCP_OFF_OPTIONS;
  ASSERT_EQ(find_opt_u32(d + DHCP_OFF_OPTIONS, opt_len, OPT_SUBNET_MASK),
            server_cfg.subnet_mask);
  ASSERT_EQ(find_opt_u32(d + DHCP_OFF_OPTIONS, opt_len, OPT_ROUTER),
            server_cfg.gateway);
  ASSERT_EQ(net_read32be(d + DHCP_OFF_YIADDR), 0u);
  ASSERT_EQ(net_read32be(d + DHCP_OFF_CIADDR), NET_IPV4(10, 0, 0, 77));
  ASSERT_EQ(sent_ip_dst(), NET_IPV4(10, 0, 0, 77));
}

/* RFC 2131 Table 3: the DHCPACK to a renewing client's DHCPREQUEST echoes
   its ciaddr, with the lease */
TEST(test_dhcp_server_renewal_ack_echoes_ciaddr) {
  uint8_t chaddr[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x09};
  uint8_t msg[DHCP_MIN_LEN + 32];
  uint16_t mlen, opt_len;
  const uint8_t *d;
  setup();
  dhcpv4_server_init(&srv, &net, &server_cfg, on_event, NULL);
  mlen = make_client_msg(msg, DHCP_MSG_REQUEST, 0x5EED0003u, chaddr, 0, 0);
  net_write32be(msg + DHCP_OFF_CIADDR, server_cfg.offered_ip);

  dhcpv4_server_input(&net, &srv, server_cfg.offered_ip, chaddr, msg, mlen);

  ASSERT_EQ(sent_msg_type(), DHCP_MSG_ACK);
  d = sent_dhcp();
  opt_len = sent_dhcp_len() - DHCP_OFF_OPTIONS;
  ASSERT_EQ(net_read32be(d + DHCP_OFF_CIADDR), server_cfg.offered_ip);
  ASSERT_EQ(net_read32be(d + DHCP_OFF_YIADDR), server_cfg.offered_ip);
  ASSERT_EQ(find_opt_u32(d + DHCP_OFF_OPTIONS, opt_len, OPT_LEASE_TIME),
            server_cfg.lease_time_s);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void) {
  fprintf(stderr, "=== test_dhcpv4 ===\n");
  RUN_TEST(test_dhcp_client_init_zeros_state);
  RUN_TEST(test_dhcp_client_init_checks_buffers);
  RUN_TEST(test_dhcp_client_start_sends_discover);
  RUN_TEST(test_dhcp_client_discover_to_broadcast);
  RUN_TEST(test_dhcp_client_offer_triggers_request);
  RUN_TEST(test_dhcp_client_ack_enters_bound);
  RUN_TEST(test_dhcp_client_default_t1_t2);
  RUN_TEST(test_dhcp_client_nak_restarts_init);
  RUN_TEST(test_dhcp_client_opt_handler_called_v2);
  RUN_TEST(test_dhcp_client_null_opt_table);
  RUN_TEST(test_dhcp_client_retransmit_discover);
  RUN_TEST(test_dhcp_client_discover_backoff);
  RUN_TEST(test_dhcp_client_backoff_randomised);
  RUN_TEST(test_dhcp_client_requesting_gives_up);
  RUN_TEST(test_dhcp_client_start_waits_one_to_ten_seconds);
  RUN_TEST(test_dhcp_client_renew_rebind_timing);
  RUN_TEST(test_dhcp_client_renewal_restarts_lease);
  RUN_TEST(test_dhcp_client_unicasts_to_the_server_mac);
  RUN_TEST(test_dhcp_client_server_id_only_when_selecting);
  RUN_TEST(test_dhcp_client_nak_from_the_server_asked);
  RUN_TEST(test_dhcp_client_ack_without_lease_time_dropped);
  RUN_TEST(test_dhcp_client_lease_timed_from_the_request);
  RUN_TEST(test_dhcp_client_infinite_lease);
  RUN_TEST(test_dhcp_client_t1_t2_fuzzed);
  RUN_TEST(test_dhcp_client_long_lease);
  RUN_TEST(test_dhcp_server_init_checks_buffers);
  RUN_TEST(test_dhcp_server_offer_on_discover);
  RUN_TEST(test_dhcp_server_ack_on_correct_request);
  RUN_TEST(test_dhcp_server_nak_on_wrong_request);
  RUN_TEST(test_dhcp_server_release_ignored);
  RUN_TEST(test_dhcp_server_invalid_op_ignored);
  RUN_TEST(test_dhcp_server_bad_magic_ignored);
  RUN_TEST(test_dhcp_server_nak_is_bare);
  RUN_TEST(test_dhcp_server_inform_ack_has_no_lease);
  RUN_TEST(test_dhcp_server_renewal_ack_echoes_ciaddr);
  TEST_REPORT();
  return test_failures;
}
