/**
 * @file test_dhcpv6.c
 * @brief Unit tests for the DHCPv6 client (RFC 8415): stateless
 *        Information-Request, stateful Solicit/Advertise/Request/Reply,
 *        Renew, Rebind, expiry, Release, retransmission.
 *
 * The test plays the server by feeding messages to dhcpv6_client_input().
 * Built with NET_USE_IPV6=1.
 */

#include "dhcpv6_client.h"
#include "eth.h"
#include "ipv6.h"
#include "ndp.h"
#include "net.h"
#include "net_endian.h"
#include "test_main.h"
#include "udp.h"
#include <string.h>

#if !NET_USE_IPV6
#error "test_dhcpv6 needs NET_USE_IPV6=1"
#endif

/* ── Stub MAC driver ──────────────────────────────────────────────── */

#define MAX_SENT 32
static uint8_t sent[MAX_SENT][600];
static uint16_t sent_len[MAX_SENT];
static uint32_t sent_at[MAX_SENT]; /* test clock when sent */
static int send_count;
static uint32_t now_ms;

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
  memcpy(sent[i], f, l < 600 ? l : 600);
  sent_len[i] = l;
  sent_at[i] = now_ms;
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

/* ── Constants ────────────────────────────────────────────────────── */

static const uint8_t our_ll[16] = {0xFE, 0x80, 0, 0,    0,    0,    0,    0,
                                   0,    0,    0, 0xFF, 0xFE, 0xDE, 0xAD, 0x01};
static const uint8_t server_ll[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                      0,    0,    0, 0, 0, 0, 0, 5};
static const uint8_t all_dhcp[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                     0,    0,    0, 0, 0, 1, 0, 2};
static const uint8_t all_dhcp_mac[6] = {0x33, 0x33, 0, 1, 0, 2};
/* DUID-LL of 02:00:00:de:ad:01 (RFC 8415 §11.4) */
static const uint8_t our_duid[10] = {0, 3, 0, 1, 0x02, 0, 0, 0xDE, 0xAD, 0x01};
/* A server DUID-LLT */
static const uint8_t srv_duid[14] = {0, 1, 0, 1, 0x2E, 0x3F, 0x10, 0x20,
                                     0x52, 0x54, 0, 0x11, 0x22, 0x33};
static const uint8_t other_duid[10] = {0, 3, 0, 1, 0x02, 0, 0, 0, 0, 0x99};
static const uint8_t lease_addr[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
                                       0,    0,    0,    0,    0, 0, 0, 0x77};
static const uint8_t dns_servers[32] = {
    0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
    0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53, 0x53};

/* ── Fixture ──────────────────────────────────────────────────────── */

static uint8_t rx_buf[1514], tx_buf[1514];
static net_t net;
static dhcpv6_client_t cli;
static int ev_info, ev_bound, ev_renewed, ev_expired, dns_calls;
static uint8_t dns_seen[64];
static uint16_t dns_len;

static void on_ev(uint8_t e, void *ctx) {
  (void)ctx;
  if (e == DHCPV6_EVT_INFO)
    ev_info++;
  if (e == DHCPV6_EVT_BOUND)
    ev_bound++;
  if (e == DHCPV6_EVT_RENEWED)
    ev_renewed++;
  if (e == DHCPV6_EVT_EXPIRED)
    ev_expired++;
}

static void on_dns(uint16_t o, const uint8_t *d, uint16_t l, void *ctx) {
  (void)o;
  (void)ctx;
  dns_calls++;
  dns_len = l;
  memcpy(dns_seen, d, l < 64 ? l : 64);
}

static const dhcpv6_opt_entry_t opt_entries[] = {
    {DHCPV6_OPT_DNS_SERVERS, on_dns, NULL}};
static const dhcpv6_opt_table_t opts = {opt_entries, 1};

static void reset_sent(void) {
  send_count = 0;
  memset(sent_len, 0, sizeof(sent_len));
}

static void setup(void) {
  int ctx = 0;
  net_init(&net, rx_buf, sizeof(rx_buf), tx_buf, sizeof(tx_buf), NULL,
           &stub_drv, &ctx);
  ipv6_start(&net);
  for (int i = 0; i < 6; i++)
    ipv6_tick(&net, NDP_RTR_SOLICITATION_INTERVAL_MS); /* DAD + RS done */
  reset_sent();
  now_ms = 0;
  ev_info = ev_bound = ev_renewed = ev_expired = dns_calls = 0;
  dns_len = 0;
  dhcpv6_client_init(&cli, on_ev, NULL, &opts);
}

/** Advance the client (and IPv6) in 10 ms steps. */
static void run(uint32_t ms) {
  for (uint32_t t = 0; t < ms; t += 10) {
    now_ms += 10;
    dhcpv6_client_tick(&net, &cli, 10);
    ipv6_tick(&net, 10);
  }
}

/** Run until the client sends (at most max_ms); returns the message. */
static const uint8_t *run_until_send(uint32_t max_ms) {
  int before = send_count;
  for (uint32_t t = 0; t < max_ms && send_count == before; t += 10) {
    now_ms += 10;
    dhcpv6_client_tick(&net, &cli, 10);
    ipv6_tick(&net, 10);
  }
  if (send_count == before)
    return NULL;
  return sent[send_count - 1] + UDP6_PAYLOAD_OFFSET;
}

static int last(void) { return send_count - 1; }
static const uint8_t *s_msg(int i) { return sent[i] + UDP6_PAYLOAD_OFFSET; }
static uint16_t s_mlen(int i) {
  return (uint16_t)(sent_len[i] - UDP6_PAYLOAD_OFFSET);
}
static uint32_t s_xid(int i) {
  return (uint32_t)s_msg(i)[1] << 16 | (uint32_t)s_msg(i)[2] << 8 |
         s_msg(i)[3];
}

/** Top-level option @p code of a message, or NULL. */
static const uint8_t *find_opt(const uint8_t *m, uint16_t len, uint16_t code,
                               uint16_t *olen) {
  uint16_t off = 4;
  while (off + 4 <= len) {
    uint16_t c = net_read16be(m + off), l = net_read16be(m + off + 2);
    if (off + 4 + l > len)
      return NULL;
    if (c == code) {
      *olen = l;
      return m + off + 4;
    }
    off = (uint16_t)(off + 4 + l);
  }
  return NULL;
}

static const uint8_t *s_opt(int i, uint16_t code, uint16_t *olen) {
  return find_opt(s_msg(i), s_mlen(i), code, olen);
}

/* ── Server messages ──────────────────────────────────────────────── */

static uint8_t srv[512];
static uint16_t srv_len;

static void m_begin(uint8_t type, uint32_t xid) {
  srv[0] = type;
  srv[1] = (uint8_t)(xid >> 16);
  srv[2] = (uint8_t)(xid >> 8);
  srv[3] = (uint8_t)xid;
  srv_len = 4;
}

static void m_opt(uint16_t code, const void *data, uint16_t len) {
  net_write16be(srv + srv_len, code);
  net_write16be(srv + srv_len + 2, len);
  memcpy(srv + srv_len + 4, data, len);
  srv_len = (uint16_t)(srv_len + 4 + len);
}

/** IA_NA with one IA Address. */
static void m_ia_na(uint32_t t1, uint32_t t2, const uint8_t *addr,
                    uint32_t pref, uint32_t valid) {
  uint8_t ia[40];
  net_write32be(ia, 0x00DEAD01u); /* our IAID: MAC bytes 2..5 */
  net_write32be(ia + 4, t1);
  net_write32be(ia + 8, t2);
  net_write16be(ia + 12, DHCPV6_OPT_IAADDR);
  net_write16be(ia + 14, 24);
  memcpy(ia + 16, addr, 16);
  net_write32be(ia + 32, pref);
  net_write32be(ia + 36, valid);
  m_opt(DHCPV6_OPT_IA_NA, ia, 40);
}

static void deliver(void) {
  dhcpv6_client_input(&net, &cli, server_ll, srv, srv_len);
}

/* A full stateful binding with the given timers; leaves sends cleared. */
static void bind_lease(uint32_t t1, uint32_t t2, uint32_t pref,
                       uint32_t valid) {
  dhcpv6_client_start(&net, &cli, DHCPV6_MODE_STATEFUL);
  run_until_send(1100);
  m_begin(DHCPV6_ADVERTISE, s_xid(last()));
  m_opt(DHCPV6_OPT_CLIENTID, our_duid, 10);
  m_opt(DHCPV6_OPT_SERVERID, srv_duid, 14);
  m_ia_na(t1, t2, lease_addr, pref, valid);
  deliver();
  m_begin(DHCPV6_REPLY, s_xid(last()));
  m_opt(DHCPV6_OPT_CLIENTID, our_duid, 10);
  m_opt(DHCPV6_OPT_SERVERID, srv_duid, 14);
  m_ia_na(t1, t2, lease_addr, pref, valid);
  deliver();
  reset_sent();
}

/* ══ Stateless ════════════════════════════════════════════════════ */

TEST(test_dhcpv6_information_request) {
  setup();
  dhcpv6_client_start(&net, &cli, DHCPV6_MODE_STATELESS);
  ASSERT_EQ(send_count, 0);
  ASSERT_NOT_NULL(run_until_send(1100)); /* random 0..1 s delay */
  const uint8_t *ip = sent[0] + 14;
  const uint8_t *udp = ip + 40;
  ASSERT_MEM_EQ(sent[0], all_dhcp_mac, 6);
  ASSERT_MEM_EQ(ip + 8, our_ll, 16);
  ASSERT_MEM_EQ(ip + 24, all_dhcp, 16);
  ASSERT_EQ(ip[6], IPV6_NH_UDP);
  ASSERT_EQ(net_read16be(udp), DHCPV6_CLIENT_PORT);
  ASSERT_EQ(net_read16be(udp + 2), DHCPV6_SERVER_PORT);
  ASSERT_EQ(ipv6_cksum(ip + 8, ip + 24, IPV6_NH_UDP, udp,
                       net_read16be(udp + 4)),
            0);
  ASSERT_EQ(s_msg(0)[0], DHCPV6_INFORMATION_REQUEST);
  uint16_t l;
  const uint8_t *o = s_opt(0, DHCPV6_OPT_CLIENTID, &l);
  ASSERT_NOT_NULL(o);
  ASSERT_EQ(l, 10);
  ASSERT_MEM_EQ(o, our_duid, 10); /* REQ-DHCPv6-033..035 */
  o = s_opt(0, DHCPV6_OPT_ELAPSED_TIME, &l);
  ASSERT_NOT_NULL(o);
  ASSERT_EQ(l, 2);
  ASSERT_EQ(net_read16be(o), 0);
  o = s_opt(0, DHCPV6_OPT_ORO, &l);
  ASSERT_NOT_NULL(o);
  int has_dns = 0;
  for (uint16_t i = 0; i + 1 < l; i += 2)
    if (net_read16be(o + i) == DHCPV6_OPT_DNS_SERVERS)
      has_dns = 1;
  ASSERT_TRUE(has_dns);
  ASSERT_NULL(s_opt(0, DHCPV6_OPT_IA_NA, &l));
}

TEST(test_dhcpv6_retransmission_backoff) {
  /* RFC 8415 §15: RT = IRT ± 10 %, then 2·RTprev ± 10 % of RTprev */
  setup();
  dhcpv6_client_start(&net, &cli, DHCPV6_MODE_STATELESS);
  run_until_send(1100);
  run_until_send(1200);
  run_until_send(2400);
  ASSERT_EQ(send_count, 3);
  uint32_t rt1 = sent_at[1] - sent_at[0];
  uint32_t rt2 = sent_at[2] - sent_at[1];
  ASSERT_TRUE(rt1 >= 890 && rt1 <= 1110);
  ASSERT_TRUE(rt2 * 10 >= rt1 * 19 - 200 && rt2 * 10 <= rt1 * 21 + 200);
  ASSERT_EQ(s_xid(1), s_xid(0)); /* same exchange, same transaction */
  /* Elapsed Time (hundredths of a second) at the retransmission */
  uint16_t l;
  const uint8_t *o = s_opt(1, DHCPV6_OPT_ELAPSED_TIME, &l);
  ASSERT_NOT_NULL(o);
  uint32_t cs = net_read16be(o);
  ASSERT_TRUE(cs * 10u + 20u >= rt1 && cs * 10u <= rt1 + 20u);
}

TEST(test_dhcpv6_reply_to_information_request) {
  setup();
  dhcpv6_client_start(&net, &cli, DHCPV6_MODE_STATELESS);
  run_until_send(1100);
  m_begin(DHCPV6_REPLY, s_xid(0));
  m_opt(DHCPV6_OPT_CLIENTID, our_duid, 10);
  m_opt(DHCPV6_OPT_SERVERID, srv_duid, 14);
  m_opt(DHCPV6_OPT_DNS_SERVERS, dns_servers, 32);
  deliver();
  ASSERT_EQ(ev_info, 1);
  ASSERT_EQ(dns_calls, 1);
  ASSERT_EQ(dns_len, 32);
  ASSERT_MEM_EQ(dns_seen, dns_servers, 32);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_INFORMED);
  reset_sent();
  run(30000);
  ASSERT_EQ(send_count, 0); /* no more retransmissions */
}

TEST(test_dhcpv6_reply_wrong_xid_ignored) {
  setup();
  dhcpv6_client_start(&net, &cli, DHCPV6_MODE_STATELESS);
  run_until_send(1100);
  m_begin(DHCPV6_REPLY, s_xid(0) ^ 1);
  m_opt(DHCPV6_OPT_CLIENTID, our_duid, 10);
  m_opt(DHCPV6_OPT_SERVERID, srv_duid, 14);
  m_opt(DHCPV6_OPT_DNS_SERVERS, dns_servers, 32);
  deliver();
  ASSERT_EQ(ev_info, 0);
  ASSERT_EQ(dns_calls, 0);
}

TEST(test_dhcpv6_reply_for_other_client_ignored) {
  setup();
  dhcpv6_client_start(&net, &cli, DHCPV6_MODE_STATELESS);
  run_until_send(1100);
  m_begin(DHCPV6_REPLY, s_xid(0));
  m_opt(DHCPV6_OPT_CLIENTID, other_duid, 10);
  m_opt(DHCPV6_OPT_SERVERID, srv_duid, 14);
  deliver();
  m_begin(DHCPV6_REPLY, s_xid(0)); /* no Client Identifier at all */
  m_opt(DHCPV6_OPT_SERVERID, srv_duid, 14);
  deliver();
  ASSERT_EQ(ev_info, 0);
}

TEST(test_dhcpv6_truncated_option_ignored) {
  setup();
  dhcpv6_client_start(&net, &cli, DHCPV6_MODE_STATELESS);
  run_until_send(1100);
  m_begin(DHCPV6_REPLY, s_xid(0));
  m_opt(DHCPV6_OPT_CLIENTID, our_duid, 10);
  m_opt(DHCPV6_OPT_SERVERID, srv_duid, 14);
  m_opt(DHCPV6_OPT_DNS_SERVERS, dns_servers, 32);
  net_write16be(srv + srv_len - 32 - 2, 200); /* DNS length overruns */
  deliver();
  ASSERT_EQ(ev_info, 0);
  ASSERT_EQ(dns_calls, 0);
}

/* ══ Stateful ═════════════════════════════════════════════════════ */

TEST(test_dhcpv6_solicit) {
  setup();
  dhcpv6_client_start(&net, &cli, DHCPV6_MODE_STATEFUL);
  ASSERT_NOT_NULL(run_until_send(1100));
  ASSERT_EQ(s_msg(0)[0], DHCPV6_SOLICIT);
  uint16_t l;
  const uint8_t *o = s_opt(0, DHCPV6_OPT_CLIENTID, &l);
  ASSERT_NOT_NULL(o);
  ASSERT_MEM_EQ(o, our_duid, 10);
  o = s_opt(0, DHCPV6_OPT_IA_NA, &l);
  ASSERT_NOT_NULL(o); /* REQ-DHCPv6-015 */
  ASSERT_EQ(l, 12);
  ASSERT_EQ(net_read32be(o), 0x00DEAD01u); /* IAID from the MAC */
  ASSERT_EQ(net_read32be(o + 4), 0u);
  ASSERT_EQ(net_read32be(o + 8), 0u);
  ASSERT_NOT_NULL(s_opt(0, DHCPV6_OPT_ELAPSED_TIME, &l));
  ASSERT_NOT_NULL(s_opt(0, DHCPV6_OPT_ORO, &l));
  ASSERT_NULL(s_opt(0, DHCPV6_OPT_SERVERID, &l));
}

TEST(test_dhcpv6_first_solicit_rt_above_irt) {
  /* RFC 8415 §15: for the first Solicit, RAND is strictly positive */
  setup();
  dhcpv6_client_start(&net, &cli, DHCPV6_MODE_STATEFUL);
  run_until_send(1100);
  run_until_send(1200);
  uint32_t rt1 = sent_at[1] - sent_at[0];
  ASSERT_TRUE(rt1 > 1000 && rt1 <= 1110);
}

TEST(test_dhcpv6_advertise_then_request) {
  setup();
  dhcpv6_client_start(&net, &cli, DHCPV6_MODE_STATEFUL);
  run_until_send(1100);
  uint32_t sol_xid = s_xid(0);
  m_begin(DHCPV6_ADVERTISE, sol_xid);
  m_opt(DHCPV6_OPT_CLIENTID, our_duid, 10);
  m_opt(DHCPV6_OPT_SERVERID, srv_duid, 14);
  m_ia_na(0, 0, lease_addr, 3600, 7200);
  deliver();
  ASSERT_EQ(send_count, 2); /* Request at once */
  ASSERT_EQ(s_msg(1)[0], DHCPV6_REQUEST);
  ASSERT_NE(s_xid(1), sol_xid); /* a new exchange */
  ASSERT_MEM_EQ(sent[1], all_dhcp_mac, 6);
  uint16_t l;
  const uint8_t *o = s_opt(1, DHCPV6_OPT_SERVERID, &l);
  ASSERT_NOT_NULL(o);
  ASSERT_EQ(l, 14);
  ASSERT_MEM_EQ(o, srv_duid, 14);
  ASSERT_NOT_NULL(s_opt(1, DHCPV6_OPT_CLIENTID, &l));
  o = s_opt(1, DHCPV6_OPT_IA_NA, &l);
  ASSERT_NOT_NULL(o);
  ASSERT_TRUE(l >= 12 + 28);
  ASSERT_EQ(net_read16be(o + 12), DHCPV6_OPT_IAADDR);
  ASSERT_MEM_EQ(o + 16, lease_addr, 16);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_REQUEST);
}

TEST(test_dhcpv6_advertise_without_server_id_ignored) {
  setup();
  dhcpv6_client_start(&net, &cli, DHCPV6_MODE_STATEFUL);
  run_until_send(1100);
  m_begin(DHCPV6_ADVERTISE, s_xid(0));
  m_opt(DHCPV6_OPT_CLIENTID, our_duid, 10);
  m_ia_na(0, 0, lease_addr, 3600, 7200);
  deliver();
  ASSERT_EQ(send_count, 1);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_SOLICIT);
}

TEST(test_dhcpv6_advertise_without_address_ignored) {
  uint8_t status[2] = {0, 2}; /* NoAddrsAvail */
  setup();
  dhcpv6_client_start(&net, &cli, DHCPV6_MODE_STATEFUL);
  run_until_send(1100);
  m_begin(DHCPV6_ADVERTISE, s_xid(0));
  m_opt(DHCPV6_OPT_CLIENTID, our_duid, 10);
  m_opt(DHCPV6_OPT_SERVERID, srv_duid, 14);
  m_opt(DHCPV6_OPT_STATUS_CODE, status, 2);
  deliver();
  ASSERT_EQ(send_count, 1);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_SOLICIT);
}

TEST(test_dhcpv6_reply_binds_address) {
  setup();
  bind_lease(1000, 1600, 3600, 7200);
  ASSERT_EQ(ev_bound, 1);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_BOUND);
  int slot = ipv6_addr_slot(&net, lease_addr);
  ASSERT_TRUE(slot > 0);
  ASSERT_EQ(ipv6_addr_state(&net, (uint8_t)slot), NET_IP6_TENTATIVE);
  ASSERT_EQ(net.ip6[slot].valid_s, 7200u);
  ASSERT_EQ(net.ip6[slot].preferred_s, 3600u);
  run(2000); /* REQ-DHCPv6-032: DAD before use */
  ASSERT_EQ(ipv6_addr_state(&net, (uint8_t)slot), NET_IP6_PREFERRED);
  ASSERT_EQ(cli.t1_s, 1000u);
  ASSERT_EQ(cli.t2_s, 1600u);
}

TEST(test_dhcpv6_renew_at_t1) {
  setup();
  bind_lease(10, 16, 3600, 7200);
  run(9990);
  for (int i = 0; i < send_count && i < MAX_SENT; i++)
    ASSERT_NE(s_msg(i)[0], DHCPV6_RENEW);
  ASSERT_NOT_NULL(run_until_send(20));
  ASSERT_EQ(s_msg(last())[0], DHCPV6_RENEW);
  uint16_t l;
  const uint8_t *o = s_opt(last(), DHCPV6_OPT_SERVERID, &l);
  ASSERT_NOT_NULL(o);
  ASSERT_MEM_EQ(o, srv_duid, 14);
  o = s_opt(last(), DHCPV6_OPT_IA_NA, &l);
  ASSERT_NOT_NULL(o);
  ASSERT_MEM_EQ(o + 16, lease_addr, 16);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_RENEW);
}

TEST(test_dhcpv6_reply_to_renew_extends) {
  setup();
  bind_lease(10, 16, 3600, 7200);
  run(10000);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_RENEW);
  m_begin(DHCPV6_REPLY, s_xid(last()));
  m_opt(DHCPV6_OPT_CLIENTID, our_duid, 10);
  m_opt(DHCPV6_OPT_SERVERID, srv_duid, 14);
  m_ia_na(100, 160, lease_addr, 5000, 9000);
  deliver();
  ASSERT_EQ(ev_renewed, 1);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_BOUND);
  int slot = ipv6_addr_slot(&net, lease_addr);
  ASSERT_TRUE(slot > 0);
  ASSERT_EQ(net.ip6[slot].valid_s, 9000u);
  ASSERT_EQ(cli.t1_s, 100u);
}

TEST(test_dhcpv6_rebind_at_t2) {
  setup();
  bind_lease(10, 16, 3600, 7200);
  run(15990);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_RENEW);
  run(20);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_REBIND);
  ASSERT_EQ(s_msg(last())[0], DHCPV6_REBIND);
  uint16_t l;
  ASSERT_NULL(s_opt(last(), DHCPV6_OPT_SERVERID, &l)); /* to any server */
  ASSERT_NOT_NULL(s_opt(last(), DHCPV6_OPT_IA_NA, &l));
}

TEST(test_dhcpv6_lease_expires) {
  setup();
  bind_lease(10, 16, 15, 20);
  run(19990);
  ASSERT_EQ(ev_expired, 0);
  run(20);
  ASSERT_EQ(ev_expired, 1); /* REQ-DHCPv6-038 */
  ASSERT_EQ(ipv6_addr_slot(&net, lease_addr), -1);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_SOLICIT);
  ASSERT_NOT_NULL(run_until_send(1200));
  ASSERT_EQ(s_msg(last())[0], DHCPV6_SOLICIT);
}

TEST(test_dhcpv6_request_gives_up_after_ten) {
  setup();
  dhcpv6_client_start(&net, &cli, DHCPV6_MODE_STATEFUL);
  run_until_send(1100);
  m_begin(DHCPV6_ADVERTISE, s_xid(0));
  m_opt(DHCPV6_OPT_CLIENTID, our_duid, 10);
  m_opt(DHCPV6_OPT_SERVERID, srv_duid, 14);
  m_ia_na(0, 0, lease_addr, 3600, 7200);
  deliver();
  reset_sent();
  int requests = 0;
  for (int i = 0; i < 12; i++) {
    const uint8_t *m = run_until_send(40000);
    ASSERT_NOT_NULL(m);
    if (m[0] != DHCPV6_REQUEST)
      break;
    requests++;
  }
  ASSERT_EQ(requests, 9); /* 10 in all with the one sent at once */
  ASSERT_EQ(s_msg(last())[0], DHCPV6_SOLICIT);
}

TEST(test_dhcpv6_zero_t1_t2_from_preferred_lifetime) {
  setup();
  bind_lease(0, 0, 1000, 2000);
  ASSERT_EQ(cli.t1_s, 500u);  /* 0.5 × preferred */
  ASSERT_EQ(cli.t2_s, 812u);  /* ≈ 0.8 × preferred (0.8125: shifts) */
}

TEST(test_dhcpv6_stateful_reply_options_to_handlers) {
  setup();
  dhcpv6_client_start(&net, &cli, DHCPV6_MODE_STATEFUL);
  run_until_send(1100);
  m_begin(DHCPV6_ADVERTISE, s_xid(0));
  m_opt(DHCPV6_OPT_CLIENTID, our_duid, 10);
  m_opt(DHCPV6_OPT_SERVERID, srv_duid, 14);
  m_ia_na(0, 0, lease_addr, 3600, 7200);
  deliver();
  m_begin(DHCPV6_REPLY, s_xid(last()));
  m_opt(DHCPV6_OPT_CLIENTID, our_duid, 10);
  m_opt(DHCPV6_OPT_SERVERID, srv_duid, 14);
  m_ia_na(0, 0, lease_addr, 3600, 7200);
  m_opt(DHCPV6_OPT_DNS_SERVERS, dns_servers, 16);
  deliver();
  ASSERT_EQ(ev_bound, 1);
  ASSERT_EQ(dns_calls, 1);
  ASSERT_EQ(dns_len, 16);
}

TEST(test_dhcpv6_release) {
  setup();
  bind_lease(1000, 1600, 3600, 7200);
  dhcpv6_client_release(&net, &cli);
  ASSERT_EQ(send_count, 1);
  ASSERT_EQ(s_msg(0)[0], DHCPV6_RELEASE);
  uint16_t l;
  const uint8_t *o = s_opt(0, DHCPV6_OPT_SERVERID, &l);
  ASSERT_NOT_NULL(o);
  ASSERT_MEM_EQ(o, srv_duid, 14);
  ASSERT_NOT_NULL(s_opt(0, DHCPV6_OPT_CLIENTID, &l));
  o = s_opt(0, DHCPV6_OPT_IA_NA, &l);
  ASSERT_NOT_NULL(o);
  ASSERT_MEM_EQ(o + 16, lease_addr, 16);
  ASSERT_EQ(ipv6_addr_slot(&net, lease_addr), -1);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_IDLE);
  reset_sent();
  run(20000);
  ASSERT_EQ(send_count, 0);
}

int main(void) {
  fprintf(stderr, "=== DHCPv6 client tests ===\n");
  RUN_TEST(test_dhcpv6_information_request);
  RUN_TEST(test_dhcpv6_retransmission_backoff);
  RUN_TEST(test_dhcpv6_reply_to_information_request);
  RUN_TEST(test_dhcpv6_reply_wrong_xid_ignored);
  RUN_TEST(test_dhcpv6_reply_for_other_client_ignored);
  RUN_TEST(test_dhcpv6_truncated_option_ignored);
  RUN_TEST(test_dhcpv6_solicit);
  RUN_TEST(test_dhcpv6_first_solicit_rt_above_irt);
  RUN_TEST(test_dhcpv6_advertise_then_request);
  RUN_TEST(test_dhcpv6_advertise_without_server_id_ignored);
  RUN_TEST(test_dhcpv6_advertise_without_address_ignored);
  RUN_TEST(test_dhcpv6_reply_binds_address);
  RUN_TEST(test_dhcpv6_renew_at_t1);
  RUN_TEST(test_dhcpv6_reply_to_renew_extends);
  RUN_TEST(test_dhcpv6_rebind_at_t2);
  RUN_TEST(test_dhcpv6_lease_expires);
  RUN_TEST(test_dhcpv6_request_gives_up_after_ten);
  RUN_TEST(test_dhcpv6_zero_t1_t2_from_preferred_lifetime);
  RUN_TEST(test_dhcpv6_stateful_reply_options_to_handlers);
  RUN_TEST(test_dhcpv6_release);
  TEST_REPORT();
  return test_failures;
}
