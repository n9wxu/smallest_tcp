/**
 * @file itest_dhcpv6.c
 * @brief The DHCPv6 client, black box: its messages on the wire, a
 *        server played by the test, the events and options the
 *        application gets, and the address the interface comes to use.
 */

#include "dhcpv6_client.h"
#include "ipv6.h"
#include "itest.h"
#include "udp.h"
#include <string.h>

#define M_SOLICIT 1
#define M_ADVERTISE 2
#define M_REQUEST 3
#define M_RENEW 5
#define M_REBIND 6
#define M_REPLY 7
#define M_RELEASE 8
#define M_DECLINE 9
#define M_INFORMATION_REQUEST 11

#define O_CLIENTID 1
#define O_SERVERID 2
#define O_IA_NA 3
#define O_IAADDR 5
#define O_ORO 6
#define O_ELAPSED 8
#define O_STATUS 13
#define O_DNS 23
#define O_DOMAINS 24
#define O_REFRESH 32
#define O_SOL_MAX_RT 82
#define O_INF_MAX_RT 83

#define STATUS_NO_ADDRS 2

static itest_t t;
static dhcpv6_client_t cli;
static uint8_t ll[16];
static uint8_t our_duid[10];

static const uint8_t all_dhcp[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                     0,    0,    0, 0, 0, 1, 0, 2};
static const uint8_t all_dhcp_mac[6] = {0x33, 0x33, 0, 1, 0, 2};
static const uint8_t server_ll[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                      0,    0,    0, 0, 0, 0, 0, 5};
/* DUID-LLT of the server, and of a second one */
static const uint8_t server_duid[14] = {0,    1, 0,    1,    0x2A, 0x2B, 0x2C,
                                        0x2D, 2, 0x53, 0x52, 0x56, 0,    1};
static const uint8_t server2_duid[14] = {0,    1, 0,    1,    0x3A, 0x3B, 0x3C,
                                         0x3D, 2, 0x53, 0x52, 0x56, 0,    2};
static const uint8_t lease[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 3, 0, 0,
                                  0,    0,    0,    0,    0, 0, 0, 0x77};
static const uint8_t lease2[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 3, 0, 0,
                                   0,    0,    0,    0,    0, 0, 0, 0x78};
static const uint8_t dns_servers[32] = {
    0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
    0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x54};
static const uint8_t domains[13] = {7,   'e', 'x', 'a', 'm', 'p', 'l',
                                    'e', 3,   'c', 'o', 'm', 0};

/* What the application saw */
static int events[5];
static int dns_calls, domain_calls;
static uint8_t dns_seen[64];
static uint16_t dns_seen_len;

static void on_event(uint8_t event, void *ctx) {
  (void)ctx;
  if (event < 5)
    events[event]++;
}

static void on_option(uint16_t option, const uint8_t *data, uint16_t len,
                      void *ctx) {
  (void)ctx;
  if (option == O_DNS) {
    dns_calls++;
    dns_seen_len = len < sizeof(dns_seen) ? len : (uint16_t)sizeof(dns_seen);
    memcpy(dns_seen, data, dns_seen_len);
  } else if (option == O_DOMAINS) {
    domain_calls++;
  }
}

static const dhcpv6_opt_entry_t opt_entries[] = {
    {O_DNS, on_option, NULL},
    {O_DOMAINS, on_option, NULL},
};
static const dhcpv6_opt_table_t opt_table = {opt_entries, 2};

static void on_dhcp(net_t *net, const uint8_t *src_ip, uint16_t src_port,
                    const uint8_t *src_mac, const uint8_t *data, uint16_t len) {
  (void)src_port;
  (void)src_mac;
  dhcpv6_client_input(net, &cli, src_ip, data, len);
}

static const udp6_port_entry_t ports6[] = {{DHCPV6_CLIENT_PORT, on_dhcp}};

/* IPv6 up (the link-local address past DAD), the client initialised */
static void up(void) {
  static const uint8_t duid_ll[4] = {0, 3, 0, 1};
  itest_up(&t, 1514, 1514);
  udp6_set_ports(&t.net, ports6, 1);
  peer_link_local(t.net.mac, ll);
  memcpy(our_duid, duid_ll, 4);
  memcpy(our_duid + 4, t.net.mac, 6);
  ipv6_start(&t.net);
  itest_advance(&t, 15000, 100);
  dhcpv6_client_init(&cli, on_event, NULL, &opt_table);
  memset(events, 0, sizeof(events));
  dns_calls = domain_calls = 0;
  wire_clear(&t);
}

/* Time passes for the stack and the client, in steps of @p step ms */
static void run(uint32_t ms, uint32_t step) {
  while (ms) {
    uint32_t n = ms < step ? ms : step;
    net_tick(&t.net, n);
    dhcpv6_client_tick(&t.net, &cli, n);
    ms -= n;
  }
}

/* ── What the client sent ── */

typedef struct {
  peer_ip6_t ip;
  peer_udp_t udp;
  const uint8_t *eth;
  uint8_t type;
  uint32_t xid;
  const uint8_t *opts;
  uint16_t opts_len;
} sent_msg_t;

/* The @p k-th DHCPv6 message sent since wire_clear(): 1 if there is one */
static int dhcp_sent(int k, sent_msg_t *m) {
  uint16_t i;
  const wire_frame_t *f;
  for (i = 0; (f = wire_sent(&t, i)) != NULL; i++) {
    if (!peer_parse_ipv6(f, &m->ip) || !peer_parse_udp6(&m->ip, &m->udp) ||
        m->udp.dport != DHCPV6_SERVER_PORT || m->udp.data_len < 4 || k-- != 0)
      continue;
    m->eth = f->data;
    m->type = m->udp.data[0];
    m->xid = peer_get32(m->udp.data) & 0xFFFFFFu;
    m->opts = m->udp.data + 4;
    m->opts_len = (uint16_t)(m->udp.data_len - 4);
    return 1;
  }
  return 0;
}

static int dhcp_count(void) {
  sent_msg_t m;
  int n = 0;
  while (dhcp_sent(n, &m))
    n++;
  return n;
}

/* Time passes in steps of @p step ms until the client has sent a message,
 * at most @p max_ms; @return the time passed, or -1 */
static long run_until_sent(uint32_t max_ms, uint32_t step, sent_msg_t *m) {
  uint32_t ms;
  for (ms = 0; ms < max_ms && !dhcp_sent(0, m); ms += step)
    run(step, step);
  return dhcp_sent(0, m) ? (long)ms : -1;
}

/* Option @p code among @p len bytes of options: its data, its length in
 * @p olen; NULL if absent or the options are malformed */
static const uint8_t *option(const uint8_t *opts, uint16_t len, uint16_t code,
                             uint16_t *olen) {
  while (len >= 4) {
    uint16_t c = peer_get16(opts), l = peer_get16(opts + 2);
    if (4u + l > len)
      return NULL;
    if (c == code) {
      *olen = l;
      return opts + 4;
    }
    opts += 4 + l;
    len = (uint16_t)(len - 4 - l);
  }
  return NULL;
}

static const uint8_t *msg_option(const sent_msg_t *m, uint16_t code,
                                 uint16_t *olen) {
  return option(m->opts, m->opts_len, code, olen);
}

/* 1 if the message's Option Request option asks for @p code */
static int requests(const sent_msg_t *m, uint16_t code) {
  uint16_t l, i;
  const uint8_t *oro = msg_option(m, O_ORO, &l);
  for (i = 0; oro && i + 1 < l; i = (uint16_t)(i + 2)) {
    if (peer_get16(oro + i) == code)
      return 1;
  }
  return 0;
}

/* The message's Elapsed Time, in hundredths of a second; -1 if absent */
static long elapsed(const sent_msg_t *m) {
  uint16_t l;
  const uint8_t *e = msg_option(m, O_ELAPSED, &l);
  return e && l == 2 ? (long)peer_get16(e) : -1;
}

/* 1 if the message goes as every client message must: from our
 * link-local address, port 546, to All_DHCP_Relay_Agents_and_Servers,
 * port 547, with our DUID-LL as Client Identifier */
static int well_addressed(const sent_msg_t *m) {
  uint16_t l;
  const uint8_t *cid = msg_option(m, O_CLIENTID, &l);
  return memcmp(m->eth, all_dhcp_mac, 6) == 0 &&
         memcmp(m->ip.dst, all_dhcp, 16) == 0 &&
         memcmp(m->ip.src, ll, 16) == 0 && m->udp.sport == DHCPV6_CLIENT_PORT &&
         m->udp.cksum_ok && cid && l == 10 && memcmp(cid, our_duid, 10) == 0;
}

/* The message's IA_NA: 1 if present with our IAID; the address of its IA
 * Address option in @p addr (NULL if it has none) */
static int ia_na(const sent_msg_t *m, const uint8_t **addr) {
  uint16_t l, al;
  const uint8_t *ia = msg_option(m, O_IA_NA, &l);
  *addr = NULL;
  if (!ia || l < 12 || memcmp(ia, t.net.mac + 2, 4) != 0)
    return 0;
  *addr = option(ia + 12, (uint16_t)(l - 12), O_IAADDR, &al);
  if (*addr && al != 24)
    return 0;
  return 1;
}

/* ── The server's messages ── */

static uint8_t srv[512];
static uint16_t srv_len;

static void m_begin(uint8_t type, uint32_t xid) {
  peer_put32(srv, xid);
  srv[0] = type;
  srv_len = 4;
}

static void m_opt(uint16_t code, const void *data, uint16_t len) {
  peer_put16(srv + srv_len, code);
  peer_put16(srv + srv_len + 2, len);
  if (len)
    memcpy(srv + srv_len + 4, data, len);
  srv_len = (uint16_t)(srv_len + 4 + len);
}

static void m_opt32(uint16_t code, uint32_t value) {
  uint8_t v[4];
  peer_put32(v, value);
  m_opt(code, v, 4);
}

/* Our Client Identifier and the Server Identifier @p duid */
static void m_ids(const uint8_t *duid) {
  m_opt(O_CLIENTID, our_duid, 10);
  m_opt(O_SERVERID, duid, 14);
}

/* An IA_NA for our IAID with one address */
static void m_ia_na(uint32_t t1, uint32_t t2, const uint8_t *addr,
                    uint32_t preferred, uint32_t valid) {
  uint8_t ia[40];
  memcpy(ia, t.net.mac + 2, 4);
  peer_put32(ia + 4, t1);
  peer_put32(ia + 8, t2);
  peer_put16(ia + 12, O_IAADDR);
  peer_put16(ia + 14, 24);
  memcpy(ia + 16, addr, 16);
  peer_put32(ia + 32, preferred);
  peer_put32(ia + 36, valid);
  m_opt(O_IA_NA, ia, 40);
}

/* The message built, from the server to the client's port */
static void m_send(void) {
  static uint8_t seg[600], f[700];
  peer_ip6_t ip = peer_ip6(server_ll, ll, 17);
  uint16_t n =
      peer_udp6(seg, &ip, DHCPV6_SERVER_PORT, DHCPV6_CLIENT_PORT, srv, srv_len);
  itest_receive(&t, f, peer_ipv6_frame(f, t.net.mac, peer_mac, &ip, seg, n));
}

/* Stateful operation started and the Solicit sent: it is in @p sol, and
 * the wire log is cleared */
static sent_msg_t soliciting(void) {
  sent_msg_t sol;
  memset(&sol, 0, sizeof(sol));
  dhcpv6_client_start(&t.net, &cli, DHCPV6_MODE_STATEFUL);
  run_until_sent(2000, 1, &sol);
  wire_clear(&t);
  return sol;
}

/* Solicit, Advertise, Request, Reply: bound to `lease` with the timers
 * given; a second after the Reply the address is past DAD.  The wire log
 * is cleared at the Reply. */
static void bound(uint32_t t1, uint32_t t2, uint32_t preferred,
                  uint32_t valid) {
  sent_msg_t m = soliciting();
  m_begin(M_ADVERTISE, m.xid);
  m_ids(server_duid);
  m_ia_na(t1, t2, lease, preferred, valid);
  m_send();
  dhcp_sent(0, &m);
  m_begin(M_REPLY, m.xid);
  m_ids(server_duid);
  m_ia_na(t1, t2, lease, preferred, valid);
  m_send();
  wire_clear(&t);
}

/* An Echo Request to @p dst from the link: 1 if answered.  Clears the
 * wire log. */
static int answers_echo(const uint8_t *dst) {
  static uint8_t f[128];
  peer_ip6_t ip = peer_ip6(peer6_ll, dst, 58), rip;
  peer_icmp_t icmp;
  int answered;
  wire_clear(&t);
  itest_receive(&t, f,
                peer_icmp6_frame(f, t.net.mac, &ip, 128, 0, NULL, "x", 1));
  answered = wire_find_icmp6(&t, 0, 129, &rip, &icmp) >= 0;
  wire_clear(&t);
  return answered;
}

/* ── Stateless: Information-request ── */

/* REQ-DHCPv6-001..006, 033, 034, 035: started for other configuration,
 * the client sends an Information-request to ff02::1:2, ports 546 → 547,
 * with its DUID-LL (type 3, hardware type 1, the MAC) as Client
 * Identifier, an Elapsed Time of 0, and an Option Request for the DNS
 * servers, the search list, the Information Refresh Time and INF_MAX_RT;
 * no IA_NA */
TEST(itest_dhcpv6_001_information_request) {
  sent_msg_t m;
  const uint8_t *addr;
  uint16_t l;
  up();
  dhcpv6_client_start(&t.net, &cli, DHCPV6_MODE_STATELESS);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_INFO_REQUEST);
  ASSERT_TRUE(run_until_sent(2000, 1, &m) >= 0);
  ASSERT_EQ(m.type, M_INFORMATION_REQUEST);
  ASSERT_TRUE(well_addressed(&m));
  ASSERT_EQ(m.udp.dport, 547);
  ASSERT_EQ(elapsed(&m), 0);
  ASSERT_TRUE(requests(&m, O_DNS));
  ASSERT_TRUE(requests(&m, O_DOMAINS));
  ASSERT_TRUE(requests(&m, O_REFRESH));
  ASSERT_TRUE(requests(&m, O_INF_MAX_RT));
  ASSERT_FALSE(ia_na(&m, &addr));
  ASSERT_NULL(msg_option(&m, O_SERVERID, &l));
}

/* REQ-DHCPv6-007, 008, 009: the Reply ends the exchange: its DNS servers
 * and search list reach the application's option handlers, with
 * DHCPV6_EVT_INFO, and nothing more is sent */
TEST(itest_dhcpv6_007_reply_configures) {
  sent_msg_t m;
  up();
  dhcpv6_client_start(&t.net, &cli, DHCPV6_MODE_STATELESS);
  ASSERT_TRUE(run_until_sent(2000, 1, &m) >= 0);
  wire_clear(&t);
  m_begin(M_REPLY, m.xid);
  m_ids(server_duid);
  m_opt(O_DNS, dns_servers, 32);
  m_opt(O_DOMAINS, domains, 13);
  m_send();
  ASSERT_EQ(events[DHCPV6_EVT_INFO], 1);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_INFORMED);
  ASSERT_EQ(dns_calls, 1);
  ASSERT_EQ(dns_seen_len, 32);
  ASSERT_MEM_EQ(dns_seen, dns_servers, 32);
  ASSERT_EQ(domain_calls, 1);
  run(60000, 100);
  ASSERT_EQ(dhcp_count(), 0);
}

/* REQ-DHCPv6-019, 027, 052: a Reply with another transaction ID, without
 * a Server Identifier, without a Client Identifier or with another
 * client's, is discarded */
TEST(itest_dhcpv6_019_replies_validated) {
  static const uint8_t other_duid[10] = {0, 3, 0, 1, 2, 0x4F, 0x54, 0x48, 0, 9};
  uint8_t other_type[10];
  sent_msg_t m;
  up();
  dhcpv6_client_start(&t.net, &cli, DHCPV6_MODE_STATELESS);
  ASSERT_TRUE(run_until_sent(2000, 1, &m) >= 0);
  m_begin(M_REPLY, m.xid ^ 1u);
  m_ids(server_duid);
  m_opt(O_DNS, dns_servers, 32);
  m_send();
  m_begin(M_REPLY, m.xid);
  m_opt(O_CLIENTID, our_duid, 10);
  m_opt(O_DNS, dns_servers, 32);
  m_send();
  m_begin(M_REPLY, m.xid);
  m_opt(O_SERVERID, server_duid, 14);
  m_opt(O_DNS, dns_servers, 32);
  m_send();
  m_begin(M_REPLY, m.xid);
  m_opt(O_CLIENTID, other_duid, 10);
  m_opt(O_SERVERID, server_duid, 14);
  m_opt(O_DNS, dns_servers, 32);
  m_send();
  memcpy(other_type, our_duid, 10); /* our MAC in a DUID of another type */
  other_type[1] = 4;
  m_begin(M_REPLY, m.xid);
  m_opt(O_CLIENTID, other_type, 10);
  m_opt(O_SERVERID, server_duid, 14);
  m_opt(O_DNS, dns_servers, 32);
  m_send();
  ASSERT_EQ(events[DHCPV6_EVT_INFO], 0);
  ASSERT_EQ(dns_calls, 0);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_INFO_REQUEST);
  m_begin(M_REPLY, m.xid);
  m_ids(server_duid);
  m_opt(O_DNS, dns_servers, 32);
  m_send();
  ASSERT_EQ(events[DHCPV6_EVT_INFO], 1);
}

/* REQ-DHCPv6-042, 043: options are code, length, data: an unknown one is
 * skipped by its length; a message whose options do not end where the
 * message ends is discarded whole */
TEST(itest_dhcpv6_042_options_parsed) {
  sent_msg_t m;
  up();
  dhcpv6_client_start(&t.net, &cli, DHCPV6_MODE_STATELESS);
  ASSERT_TRUE(run_until_sent(2000, 1, &m) >= 0);
  m_begin(M_REPLY, m.xid);
  m_ids(server_duid);
  m_opt(O_DNS, dns_servers, 32);
  srv_len = (uint16_t)(srv_len - 1); /* the last option runs past the end */
  m_send();
  m_begin(M_REPLY, m.xid);
  m_ids(server_duid);
  m_opt(O_DNS, dns_servers, 32);
  srv[srv_len++] = 0; /* three bytes that are no option */
  srv[srv_len++] = 23;
  srv[srv_len++] = 0;
  m_send();
  ASSERT_EQ(events[DHCPV6_EVT_INFO], 0);
  ASSERT_EQ(dns_calls, 0);
  m_begin(M_REPLY, m.xid);
  m_opt(9999, "wxyz!", 5);
  m_ids(server_duid);
  m_opt(9998, NULL, 0);
  m_opt(O_DNS, dns_servers, 16);
  m_send();
  ASSERT_EQ(events[DHCPV6_EVT_INFO], 1);
  ASSERT_EQ(dns_calls, 1);
  ASSERT_EQ(dns_seen_len, 16);
}

/* REQ-DHCPv6-054: the information is refreshed after the Information
 * Refresh Time of the Reply — 24 hours without the option, at least 10
 * minutes */
TEST(itest_dhcpv6_054_information_refreshed) {
  sent_msg_t m, again;
  up();
  dhcpv6_client_start(&t.net, &cli, DHCPV6_MODE_STATELESS);
  ASSERT_TRUE(run_until_sent(2000, 1, &m) >= 0);
  m_begin(M_REPLY, m.xid);
  m_ids(server_duid);
  m_opt32(O_REFRESH, 60); /* below IRT_MINIMUM: 600 s it is */
  m_send();
  wire_clear(&t);
  run(599000, 1000);
  ASSERT_EQ(dhcp_count(), 0);
  run(2100, 100);
  ASSERT_TRUE(dhcp_sent(0, &again));
  ASSERT_EQ(again.type, M_INFORMATION_REQUEST);
  ASSERT_TRUE(again.xid != m.xid);
  ASSERT_EQ(elapsed(&again), 0);
  m_begin(M_REPLY, again.xid);
  m_ids(server_duid); /* no option: IRT_DEFAULT, a day */
  m_send();
  wire_clear(&t);
  run(86399000u, 1000);
  ASSERT_EQ(dhcp_count(), 0);
  run(2100, 100);
  ASSERT_TRUE(dhcp_count() >= 1);
}

/* ── Retransmission ── */

/* REQ-DHCPv6-039, 040, 041, 050: an unanswered message is sent again
 * after RT = IRT ± 10 % (1 s for an Information-request), then 2·RT ± 10 %
 * each time, with the same transaction ID and the Elapsed Time since the
 * first transmission, in hundredths of a second (to a thousandth) */
TEST(itest_dhcpv6_039_retransmission) {
  sent_msg_t first, m;
  long rt, prev = 0, total = 0;
  int k;
  up();
  dhcpv6_client_start(&t.net, &cli, DHCPV6_MODE_STATELESS);
  ASSERT_TRUE(run_until_sent(2000, 1, &first) >= 0);
  for (k = 1; k <= 6; k++) {
    wire_clear(&t);
    rt = run_until_sent(200000, 1, &m);
    ASSERT_TRUE(rt > 0);
    if (k == 1) {
      ASSERT_TRUE(rt >= 900 && rt <= 1100);
    } else { /* 2·RTprev ± 0.1·RTprev, give or take the arithmetic */
      ASSERT_TRUE(rt * 10 >= prev * 19 - 20 && rt * 10 <= prev * 21 + 20);
    }
    total += rt;
    ASSERT_EQ(m.type, M_INFORMATION_REQUEST);
    ASSERT_EQ(m.xid, first.xid);
    ASSERT_TRUE(elapsed(&m) >= total / 10 - 2 &&
                elapsed(&m) <= total / 10 + total / 10000 + 2);
    prev = rt;
  }
}

/* REQ-DHCPv6-039, 040: RT is capped at MRT ± 10 % — 30 s for a Request — and a
 * Request is sent REQ_MAX_RC (10) times; then the client solicits again */
TEST(itest_dhcpv6_040_request_backoff_capped) {
  sent_msg_t m, req;
  long rt;
  int k;
  up();
  m = soliciting();
  m_begin(M_ADVERTISE, m.xid);
  m_ids(server_duid);
  m_ia_na(100, 160, lease, 200, 300);
  m_send();
  ASSERT_TRUE(dhcp_sent(0, &req));
  ASSERT_EQ(req.type, M_REQUEST);
  for (k = 2; k <= 10; k++) {
    wire_clear(&t);
    rt = run_until_sent(100000, 10, &m);
    ASSERT_EQ(m.type, M_REQUEST);
    ASSERT_EQ(m.xid, req.xid);
    ASSERT_TRUE(rt <= 33000);
    if (k == 2) /* IRT: REQ_TIMEOUT, 1 s */
      ASSERT_TRUE(rt >= 900 && rt <= 1100);
    if (k >= 8)
      ASSERT_TRUE(rt >= 27000);
  }
  wire_clear(&t);
  ASSERT_TRUE(run_until_sent(100000, 10, &m) >= 0);
  ASSERT_EQ(m.type, M_SOLICIT);
  ASSERT_TRUE(m.xid != req.xid);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_SOLICIT);
}

/* REQ-DHCPv6-051: the first Solicit's RT is strictly greater than IRT
 * (1 s), and at most 10 % more */
TEST(itest_dhcpv6_051_first_solicit_rt_above_irt) {
  uint8_t seed;
  for (seed = 0; seed < 16; seed++) {
    sent_msg_t m;
    long rt;
    up();
    net_random_seed(&t.net, &seed, 1);
    soliciting();
    rt = run_until_sent(3000, 1, &m);
    ASSERT_TRUE(rt > 1000 && rt <= 1100);
    ASSERT_EQ(m.type, M_SOLICIT);
  }
}

/* ── Stateful: Solicit, Advertise, Request, Reply ── */

/* REQ-DHCPv6-010, 011, 013..017, 020, 021, 023..026, 028, 031: started
 * for an address, the client sends a Solicit — to ff02::1:2 port 547,
 * Client Identifier, Elapsed Time, an IA_NA without addresses, an Option
 * Request with SOL_MAX_RT; the Advertise is answered by a Request with a
 * new transaction ID, the server's identifier and the offered address in
 * the IA_NA, to ff02::1:2; the Reply's address is configured */
TEST(itest_dhcpv6_011_address_assigned) {
  sent_msg_t sol, req;
  const uint8_t *addr, *sid;
  uint16_t l;
  up();
  dhcpv6_client_start(&t.net, &cli, DHCPV6_MODE_STATEFUL);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_SOLICIT);
  ASSERT_TRUE(run_until_sent(2000, 1, &sol) >= 0);
  ASSERT_EQ(sol.type, M_SOLICIT);
  ASSERT_TRUE(well_addressed(&sol));
  ASSERT_EQ(sol.udp.dport, 547);
  ASSERT_EQ(elapsed(&sol), 0);
  ASSERT_TRUE(ia_na(&sol, &addr));
  ASSERT_NULL(addr);
  ASSERT_TRUE(requests(&sol, O_SOL_MAX_RT));
  ASSERT_TRUE(requests(&sol, O_DNS));
  ASSERT_FALSE(requests(&sol, O_REFRESH));
  ASSERT_NULL(msg_option(&sol, O_SERVERID, &l));

  wire_clear(&t);
  m_begin(M_ADVERTISE, sol.xid);
  m_ids(server_duid);
  m_ia_na(100, 160, lease, 200, 300);
  m_send();
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_REQUEST);
  ASSERT_TRUE(dhcp_sent(0, &req));
  ASSERT_EQ(req.type, M_REQUEST);
  ASSERT_TRUE(req.xid != sol.xid);
  ASSERT_TRUE(well_addressed(&req));
  ASSERT_EQ(elapsed(&req), 0);
  ASSERT_NOT_NULL(sid = msg_option(&req, O_SERVERID, &l));
  ASSERT_EQ(l, 14);
  ASSERT_MEM_EQ(sid, server_duid, 14);
  ASSERT_TRUE(ia_na(&req, &addr));
  ASSERT_NOT_NULL(addr);
  ASSERT_MEM_EQ(addr, lease, 16);
  ASSERT_TRUE(requests(&req, O_SOL_MAX_RT));

  ASSERT_EQ(ipv6_addr_slot(&t.net, lease), -1);
  m_begin(M_REPLY, req.xid);
  m_ids(server_duid);
  m_ia_na(100, 160, lease, 200, 300);
  m_opt(O_DNS, dns_servers, 32);
  m_send();
  ASSERT_EQ(events[DHCPV6_EVT_BOUND], 1);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_BOUND);
  ASSERT_EQ(dns_calls, 1); /* the Reply's other options too */
  ASSERT_TRUE(ipv6_addr_slot(&t.net, lease) > 0);
  run(1100, 10);
  ASSERT_TRUE(ipv6_is_ours(&t.net, lease));
  ASSERT_TRUE(answers_echo(lease));
}

/* REQ-DHCPv6-032, 046: the leased address goes through Duplicate Address
 * Detection before it is used; found in use, it is never used — and
 * (deviation) no Decline tells the server */
TEST(itest_dhcpv6_032_leased_address_probed) {
  static const uint8_t unspec[16] = {0};
  static uint8_t f[128];
  uint8_t body[24], rest[4] = {0x20, 0, 0, 0};
  peer_ip6_t ip, na_ip = peer_ip6(peer6_ll, all_nodes6, 58);
  peer_icmp_t icmp;
  uint8_t all_nodes_mac[6];
  sent_msg_t m;
  int k;
  up();
  bound(100, 160, 200, 300);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_TENTATIVE);
  ASSERT_FALSE(answers_echo(lease));
  run(10, 10);
  ASSERT_TRUE(wire_find_icmp6(&t, 0, 135, &ip, &icmp) >= 0);
  ASSERT_MEM_EQ(ip.src, unspec, 16);
  ASSERT_MEM_EQ(icmp.data, lease, 16);
  na_ip.hop_limit = 255; /* another node has it */
  memcpy(body, lease, 16);
  peer_nd_lla(body + 16, 2, peer_mac);
  peer_mcast6_mac(all_nodes6, all_nodes_mac);
  itest_receive(
      &t, f,
      peer_icmp6_frame(f, all_nodes_mac, &na_ip, 136, 0, rest, body, 24));
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_DUPLICATE);
  wire_clear(&t);
  run(20000, 100);
  for (k = 0; dhcp_sent(k, &m); k++)
    ASSERT_TRUE(m.type != M_DECLINE);
  ASSERT_FALSE(answers_echo(lease));
}

/* REQ-DHCPv6-022 (deviation): the first usable Advertise is taken at
 * once — the client does not collect Advertises for the first RT, nor
 * weigh their preference; a later one changes nothing */
TEST(itest_dhcpv6_022_first_advertise_taken) {
  sent_msg_t sol, req;
  const uint8_t *sid, *addr;
  uint16_t l;
  up();
  sol = soliciting();
  m_begin(M_ADVERTISE, sol.xid);
  m_ids(server_duid);
  m_ia_na(100, 160, lease, 200, 300);
  m_send();
  ASSERT_TRUE(dhcp_sent(0, &req)); /* no time has passed */
  m_begin(M_ADVERTISE, sol.xid);
  m_ids(server2_duid);
  m_opt(7, "\xFF", 1); /* Preference 255 */
  m_ia_na(100, 160, lease2, 200, 300);
  m_send();
  m_begin(M_ADVERTISE, req.xid); /* nor does an Advertise stand for a Reply */
  m_ids(server_duid);
  m_ia_na(100, 160, lease, 200, 300);
  m_send();
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_REQUEST);
  ASSERT_EQ(events[DHCPV6_EVT_BOUND], 0);
  ASSERT_EQ(dhcp_count(), 1);
  ASSERT_NOT_NULL(sid = msg_option(&req, O_SERVERID, &l));
  ASSERT_MEM_EQ(sid, server_duid, 14);
  ASSERT_TRUE(ia_na(&req, &addr));
  ASSERT_MEM_EQ(addr, lease, 16);
}

/* An Advertise for @p sol with the IA_NA of @p len bytes at @p ia */
static void advertise_ia(const sent_msg_t *sol, const uint8_t *ia,
                         uint16_t len) {
  m_begin(M_ADVERTISE, sol->xid);
  m_ids(server_duid);
  m_opt(O_IA_NA, ia, len);
  m_send();
}

/* REQ-DHCPv6-019, 021, 044, 052: an Advertise offers an address in an IA
 * Address option nested in the IA_NA of our IAID — after other nested
 * options too.  Without an address, for another IAID, with a failure
 * status in the IA_NA or the message, a valid lifetime of 0 or a
 * preferred lifetime above the valid one, without a Server Identifier,
 * or with another transaction ID, it is not taken */
TEST(itest_dhcpv6_021_advertise_offers) {
  static const uint8_t no_addrs[2] = {0, STATUS_NO_ADDRS};
  uint8_t ia[64];
  sent_msg_t sol, req;
  const uint8_t *addr;
  up();
  sol = soliciting();
  memcpy(ia, t.net.mac + 2, 4);
  peer_put32(ia + 4, 100);
  peer_put32(ia + 8, 160);
  advertise_ia(&sol, ia, 12); /* no address */
  peer_put16(ia + 12, O_IAADDR);
  peer_put16(ia + 14, 24);
  memcpy(ia + 16, lease, 16);
  peer_put32(ia + 32, 0);
  peer_put32(ia + 36, 0);
  advertise_ia(&sol, ia, 40); /* valid lifetime 0 */
  peer_put32(ia + 32, 301);
  peer_put32(ia + 36, 300);
  advertise_ia(&sol, ia, 40); /* preferred above valid */
  peer_put32(ia + 32, 200);
  ia[0] ^= 0x80;
  advertise_ia(&sol, ia, 40); /* another IAID */
  ia[0] ^= 0x80;
  peer_put16(ia + 40, O_STATUS);
  peer_put16(ia + 42, 2);
  memcpy(ia + 44, no_addrs, 2);
  advertise_ia(&sol, ia, 46); /* NoAddrsAvail in the IA_NA */
  m_begin(M_ADVERTISE, sol.xid);
  m_ids(server_duid);
  m_opt(O_STATUS, no_addrs, 2); /* ... in the message */
  m_opt(O_IA_NA, ia, 40);
  m_send();
  m_begin(M_ADVERTISE, sol.xid);
  m_opt(O_CLIENTID, our_duid, 10); /* no Server Identifier */
  m_opt(O_IA_NA, ia, 40);
  m_send();
  m_begin(M_ADVERTISE, sol.xid ^ 0x800000u); /* another exchange's */
  m_ids(server_duid);
  m_opt(O_IA_NA, ia, 40);
  m_send();
  ASSERT_EQ(dhcp_count(), 0);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_SOLICIT);

  /* an unknown nested option, then the address */
  peer_put16(ia + 12, 9999);
  peer_put16(ia + 14, 4);
  memset(ia + 16, 0xEE, 4);
  peer_put16(ia + 20, O_IAADDR);
  peer_put16(ia + 22, 24);
  memcpy(ia + 24, lease2, 16);
  peer_put32(ia + 40, 200);
  peer_put32(ia + 44, 300);
  advertise_ia(&sol, ia, 48);
  ASSERT_TRUE(dhcp_sent(0, &req));
  ASSERT_EQ(req.type, M_REQUEST);
  ASSERT_TRUE(ia_na(&req, &addr));
  ASSERT_MEM_EQ(addr, lease2, 16);
}

/* REQ-DHCPv6-050: the Elapsed Time is the exchange's: a Request that
 * follows a Solicit sent twice starts at 0 again */
TEST(itest_dhcpv6_050_elapsed_time_of_each_exchange) {
  sent_msg_t sol, again, req;
  up();
  sol = soliciting();
  ASSERT_TRUE(run_until_sent(3000, 10, &again) >= 0);
  ASSERT_EQ(again.type, M_SOLICIT);
  ASSERT_TRUE(elapsed(&again) >= 100);
  wire_clear(&t);
  m_begin(M_ADVERTISE, sol.xid);
  m_ids(server_duid);
  m_ia_na(100, 160, lease, 200, 300);
  m_send();
  ASSERT_TRUE(dhcp_sent(0, &req));
  ASSERT_EQ(req.type, M_REQUEST);
  ASSERT_EQ(elapsed(&req), 0);
}

/* REQ-DHCPv6-028: a Reply to the Request that brings no usable lease
 * sends the client back to soliciting */
TEST(itest_dhcpv6_028_reply_without_a_lease) {
  static const uint8_t no_addrs[2] = {0, STATUS_NO_ADDRS};
  uint8_t ia[18];
  sent_msg_t sol, req, m;
  up();
  sol = soliciting();
  m_begin(M_ADVERTISE, sol.xid);
  m_ids(server_duid);
  m_ia_na(100, 160, lease, 200, 300);
  m_send();
  ASSERT_TRUE(dhcp_sent(0, &req));
  wire_clear(&t);
  memcpy(ia, t.net.mac + 2, 4);
  memset(ia + 4, 0, 8);
  peer_put16(ia + 12, O_STATUS);
  peer_put16(ia + 14, 2);
  memcpy(ia + 16, no_addrs, 2);
  m_begin(M_REPLY, req.xid);
  m_ids(server_duid);
  m_opt(O_IA_NA, ia, 18);
  m_send();
  ASSERT_EQ(events[DHCPV6_EVT_BOUND], 0);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_SOLICIT);
  ASSERT_TRUE(dhcp_sent(0, &m));
  ASSERT_EQ(m.type, M_SOLICIT);
  ASSERT_TRUE(m.xid != sol.xid);
}

/* REQ-DHCPv6-027: a bound client expects no Reply: one that arrives —
 * the Reply it has already used, sent again — changes nothing */
TEST(itest_dhcpv6_027_reply_when_bound_ignored) {
  sent_msg_t sol, req;
  up();
  sol = soliciting();
  m_begin(M_ADVERTISE, sol.xid);
  m_ids(server_duid);
  m_ia_na(100, 160, lease, 200, 300);
  m_send();
  ASSERT_TRUE(dhcp_sent(0, &req));
  m_begin(M_REPLY, req.xid);
  m_ids(server_duid);
  m_ia_na(100, 160, lease, 200, 300);
  m_send();
  ASSERT_EQ(events[DHCPV6_EVT_BOUND], 1);
  run(50000, 100);
  wire_clear(&t);
  m_begin(M_REPLY, req.xid);
  m_ids(server_duid);
  m_ia_na(100, 160, lease, 200, 300);
  m_send();
  ASSERT_EQ(events[DHCPV6_EVT_BOUND], 1);
  ASSERT_EQ(events[DHCPV6_EVT_RENEWED], 0);
  run(49900, 100); /* T1 still counts from the first Reply */
  ASSERT_EQ(dhcp_count(), 0);
  run(100, 100);
  ASSERT_EQ(dhcp_count(), 1);
}

/* ── The lease: renewal, rebinding, expiry, release ── */

/* REQ-DHCPv6-030, 036: at T1 after the Reply — not before — the client
 * sends a Renew: a new transaction ID, the server's identifier, the
 * leased address in the IA_NA */
TEST(itest_dhcpv6_036_renew_at_t1) {
  sent_msg_t m, again;
  const uint8_t *sid, *addr;
  uint16_t l;
  long rt;
  up();
  bound(100, 160, 200, 300);
  run(99900, 100);
  ASSERT_EQ(dhcp_count(), 0);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_BOUND);
  run(100, 100);
  ASSERT_TRUE(dhcp_sent(0, &m));
  ASSERT_EQ(m.type, M_RENEW);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_RENEW);
  ASSERT_TRUE(well_addressed(&m));
  ASSERT_EQ(elapsed(&m), 0);
  ASSERT_NOT_NULL(sid = msg_option(&m, O_SERVERID, &l));
  ASSERT_MEM_EQ(sid, server_duid, 14);
  ASSERT_TRUE(ia_na(&m, &addr));
  ASSERT_NOT_NULL(addr);
  ASSERT_MEM_EQ(addr, lease, 16);
  ASSERT_TRUE(requests(&m, O_SOL_MAX_RT));
  m_begin(M_REPLY, m.xid); /* a Reply for another address renews nothing */
  m_ids(server_duid);
  m_ia_na(100, 160, lease2, 200, 300);
  m_send();
  ASSERT_EQ(events[DHCPV6_EVT_RENEWED], 0);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_RENEW);
  wire_clear(&t);
  rt = run_until_sent(30000, 10, &again); /* REN_TIMEOUT: 10 s */
  ASSERT_TRUE(rt >= 9000 && rt <= 11000);
  ASSERT_EQ(again.type, M_RENEW);
  ASSERT_EQ(again.xid, m.xid);
}

/* REQ-DHCPv6-029, 036: the Reply to the Renew extends the lease —
 * DHCPV6_EVT_RENEWED — and its timers and lifetimes count from it: the
 * address outlives its first valid lifetime, and the next Renew comes T1
 * later */
TEST(itest_dhcpv6_029_reply_to_renew_extends) {
  sent_msg_t m;
  up();
  bound(100, 160, 200, 300);
  run(100000, 100);
  ASSERT_TRUE(dhcp_sent(0, &m));
  m_begin(M_REPLY, m.xid);
  m_ids(server_duid);
  m_ia_na(250, 280, lease, 290, 300);
  m_send();
  ASSERT_EQ(events[DHCPV6_EVT_RENEWED], 1);
  ASSERT_EQ(events[DHCPV6_EVT_BOUND], 1);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_BOUND);
  wire_clear(&t);
  run(249900, 100); /* 350 s after the first Reply */
  ASSERT_EQ(dhcp_count(), 0);
  ASSERT_TRUE(answers_echo(lease));
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_PREFERRED);
  wire_clear(&t);
  run(100, 100);
  ASSERT_TRUE(dhcp_sent(0, &m));
  ASSERT_EQ(m.type, M_RENEW);
}

/* REQ-DHCPv6-029: the address's preferred lifetime is the lease's: past
 * it the address is deprecated, yet still ours */
TEST(itest_dhcpv6_029_preferred_lifetime) {
  up();
  bound(0xFFFFFFFFu, 0xFFFFFFFFu, 50, 300); /* never renewed */
  run(49000, 100);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_PREFERRED);
  run(1100, 100);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_DEPRECATED);
  ASSERT_EQ(dhcp_count(), 0);
  ASSERT_TRUE(answers_echo(lease));
}

/* REQ-DHCPv6-037: with the Renew unanswered, at T2 the client sends a
 * Rebind — no Server Identifier — and takes the Reply of any server,
 * whose identifier its later messages carry */
TEST(itest_dhcpv6_037_rebind_at_t2) {
  sent_msg_t renew, m, again;
  const uint8_t *sid, *addr;
  uint16_t l;
  long rt;
  int k, n;
  up();
  bound(100, 160, 200, 300);
  run(100000, 100);
  ASSERT_TRUE(dhcp_sent(0, &renew));
  run(59900, 100);
  n = dhcp_count();
  ASSERT_TRUE(n >= 3); /* the Renew, at 10 s, 20 s, 40 s after T1 */
  for (k = 0; k < n; k++) {
    ASSERT_TRUE(dhcp_sent(k, &m));
    ASSERT_EQ(m.type, M_RENEW);
    ASSERT_EQ(m.xid, renew.xid);
  }
  wire_clear(&t);
  run(100, 100);
  ASSERT_TRUE(dhcp_sent(0, &m));
  ASSERT_EQ(m.type, M_REBIND);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_REBIND);
  ASSERT_TRUE(m.xid != renew.xid);
  ASSERT_TRUE(well_addressed(&m));
  ASSERT_NULL(msg_option(&m, O_SERVERID, &l));
  ASSERT_TRUE(ia_na(&m, &addr));
  ASSERT_MEM_EQ(addr, lease, 16);
  wire_clear(&t);
  rt = run_until_sent(30000, 10, &again); /* REB_TIMEOUT: 10 s */
  ASSERT_TRUE(rt >= 9000 && rt <= 11000);
  ASSERT_EQ(again.type, M_REBIND);
  ASSERT_EQ(again.xid, m.xid);
  m_begin(M_REPLY, m.xid);
  m_ids(server2_duid);
  m_ia_na(100, 160, lease, 200, 300);
  m_send();
  ASSERT_EQ(events[DHCPV6_EVT_RENEWED], 1);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_BOUND);
  wire_clear(&t);
  run(100000, 100);
  ASSERT_TRUE(dhcp_sent(0, &m));
  ASSERT_EQ(m.type, M_RENEW);
  ASSERT_NOT_NULL(sid = msg_option(&m, O_SERVERID, &l));
  ASSERT_MEM_EQ(sid, server2_duid, 14);
}

/* REQ-DHCPv6-038: with no server answering, when the valid lifetime ends
 * the address is removed, the application told (DHCPV6_EVT_EXPIRED), and
 * the client solicits again */
TEST(itest_dhcpv6_038_lease_expires) {
  sent_msg_t m;
  int k;
  up();
  bound(100, 160, 200, 300);
  run(298900, 100);
  ASSERT_TRUE(answers_echo(lease));
  run(1000, 100); /* the interface drops it within the last second */
  ASSERT_EQ(events[DHCPV6_EVT_EXPIRED], 0);
  wire_clear(&t);
  run(100, 100);
  ASSERT_EQ(events[DHCPV6_EVT_EXPIRED], 1);
  ASSERT_EQ(ipv6_addr_slot(&t.net, lease), -1);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_SOLICIT);
  for (k = 0; dhcp_sent(k, &m); k++) {
  }
  ASSERT_TRUE(k >= 1 && dhcp_sent(k - 1, &m));
  ASSERT_EQ(m.type, M_SOLICIT);
  ASSERT_FALSE(answers_echo(lease));
}

/* REQ-DHCPv6-030: T1 and T2 of 0 leave the times to the client: half and
 * 0.8125 of the preferred lifetime */
TEST(itest_dhcpv6_030_t1_t2_left_to_the_client) {
  sent_msg_t m;
  up();
  bound(0, 0, 200, 300);
  run(99900, 100);
  ASSERT_EQ(dhcp_count(), 0);
  run(100, 100);
  ASSERT_TRUE(dhcp_sent(0, &m));
  ASSERT_EQ(m.type, M_RENEW);
  run(61900, 100);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_RENEW);
  run(100, 100); /* 162 s: 100 + 50 + 12 */
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_REBIND);
}

/* REQ-DHCPv6-049, 056: dhcpv6_client_release() sends one Release — Client and
 * Server Identifier, Elapsed Time, the address in the IA_NA — from the
 * link-local address, and the address is the interface's no more */
TEST(itest_dhcpv6_049_release) {
  sent_msg_t m;
  const uint8_t *sid, *addr;
  uint16_t l;
  up();
  bound(100, 160, 200, 300);
  run(2000, 100);
  ASSERT_TRUE(ipv6_is_ours(&t.net, lease));
  wire_clear(&t);
  dhcpv6_client_release(&t.net, &cli);
  ASSERT_EQ(dhcp_count(), 1);
  ASSERT_TRUE(dhcp_sent(0, &m));
  ASSERT_EQ(m.type, M_RELEASE);
  ASSERT_TRUE(well_addressed(&m));
  ASSERT_EQ(elapsed(&m), 0);
  ASSERT_NOT_NULL(sid = msg_option(&m, O_SERVERID, &l));
  ASSERT_MEM_EQ(sid, server_duid, 14);
  ASSERT_TRUE(ia_na(&m, &addr));
  ASSERT_NOT_NULL(addr);
  ASSERT_MEM_EQ(addr, lease, 16);
  ASSERT_NULL(msg_option(&m, O_ORO, &l)); /* it asks for nothing */
  ASSERT_EQ(ipv6_addr_slot(&t.net, lease), -1);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_IDLE);
  m_begin(M_REPLY, m.xid); /* an idle client takes no lease */
  m_ids(server_duid);
  m_ia_na(100, 160, lease, 200, 300);
  m_send();
  ASSERT_EQ(ipv6_addr_slot(&t.net, lease), -1);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_IDLE);
  wire_clear(&t);
  run(400000, 100); /* one Release: not sent again; nothing renewed */
  ASSERT_EQ(dhcp_count(), 0);

  up(); /* with no lease there is nothing to release */
  soliciting();
  dhcpv6_client_release(&t.net, &cli);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_IDLE);
  run(10000, 100);
  ASSERT_EQ(dhcp_count(), 0);
}

/* REQ-DHCPv6-045 (deviation): the /64 of the leased address counts as
 * on-link, though a lease says nothing about what is on the link */
TEST(itest_dhcpv6_045_leased_prefix_on_link) {
  up();
  ASSERT_FALSE(ipv6_on_link(&t.net, lease2));
  bound(100, 160, 200, 300);
  ASSERT_TRUE(ipv6_on_link(&t.net, lease2));
}

/* ── Delays, and what a server may override ── */

/* REQ-DHCPv6-048: the first Information-request (or Solicit) waits a
 * random time of at most INF_MAX_DELAY (SOL_MAX_DELAY): 1 s */
TEST(itest_dhcpv6_048_start_delay_at_most_a_second) {
  uint32_t seed;
  up();
  for (seed = 0; seed < 20000; seed++) {
    dhcpv6_client_init(&cli, on_event, NULL, &opt_table);
    net_random_seed(&t.net, (const uint8_t *)&seed, sizeof(seed));
    dhcpv6_client_start(&t.net, &cli,
                        (seed & 1) ? DHCPV6_MODE_STATEFUL
                                   : DHCPV6_MODE_STATELESS);
    dhcpv6_client_tick(&t.net, &cli, 1000);
    ASSERT_EQ(t.wire.tx_count, 1);
    wire_clear(&t);
  }
}

/* REQ-DHCPv6-047: an IA_NA whose T1 is greater than its T2, both above
 * 0, is discarded: the Advertise then offers nothing */
TEST(itest_dhcpv6_047_t1_above_t2_discarded) {
  sent_msg_t sol;
  up();
  sol = soliciting();
  m_begin(M_ADVERTISE, sol.xid);
  m_ids(server_duid);
  m_ia_na(161, 160, lease, 200, 300);
  m_send();
  ASSERT_EQ(dhcp_count(), 0);
  ASSERT_EQ(dhcpv6_client_state(&cli), DHCPV6_CLI_SOLICIT);
}

/* REQ-DHCPv6-053: SOL_MAX_RT of an Advertise is taken — also of one that
 * offers no address — and caps the Solicit's RT: at 60 s ± 10 % here, not
 * at the default hour */
TEST(itest_dhcpv6_053_sol_max_rt_from_a_refusing_server) {
  static const uint8_t no_addrs[2] = {0, STATUS_NO_ADDRS};
  sent_msg_t sol, m;
  long rt = 0;
  int k;
  up();
  sol = soliciting();
  m_begin(M_ADVERTISE, sol.xid);
  m_ids(server_duid);
  m_opt(O_STATUS, no_addrs, 2);
  m_opt32(O_SOL_MAX_RT, 60);
  m_send();
  ASSERT_EQ(dhcp_count(), 0);
  for (k = 0; k < 10; k++) { /* 1, 2, 4 ... 64 s would come next */
    wire_clear(&t);
    rt = run_until_sent(400000, 100, &m);
    ASSERT_TRUE(rt > 0 && rt <= 66100);
    ASSERT_EQ(m.type, M_SOLICIT);
  }
  ASSERT_TRUE(rt >= 54000);
}

/* REQ-DHCPv6-053: a SOL_MAX_RT below 60 s or above a day is ignored */
TEST(itest_dhcpv6_053_sol_max_rt_out_of_range_ignored) {
  sent_msg_t sol, m;
  long rt = 0;
  int k;
  up();
  sol = soliciting();
  m_begin(M_ADVERTISE, sol.xid);
  m_ids(server_duid);
  m_opt32(O_SOL_MAX_RT, 59);
  m_send();
  for (k = 0; k < 8; k++) { /* 1, 2, 4 ... 128 s: beyond 59 s */
    wire_clear(&t);
    rt = run_until_sent(400000, 100, &m);
    ASSERT_TRUE(rt > 0);
  }
  ASSERT_TRUE(rt > 100000);

  up();
  sol = soliciting();
  m_begin(M_ADVERTISE, sol.xid);
  m_ids(server_duid);
  m_opt32(O_SOL_MAX_RT, 86401);
  m_send();
  for (k = 0; k < 13; k++) { /* ... 4096 s: beyond the default hour */
    wire_clear(&t);
    rt = run_until_sent(8000000, 1000, &m);
    ASSERT_TRUE(rt > 0);
  }
  ASSERT_TRUE(rt >= 3240000 && rt <= 3961000);
}

/* REQ-DHCPv6-055: when the Information Refresh Time has run out, the
 * Information-request waits a random time of up to INF_MAX_DELAY (1 s) */
TEST(itest_dhcpv6_055_refresh_delayed_at_random) {
  uint8_t seed;
  long first = -1;
  int differ = 0;
  for (seed = 0; seed < 8; seed++) {
    sent_msg_t m;
    long ms;
    up();
    net_random_seed(&t.net, &seed, 1);
    dhcpv6_client_start(&t.net, &cli, DHCPV6_MODE_STATELESS);
    ASSERT_TRUE(run_until_sent(2000, 1, &m) >= 0);
    m_begin(M_REPLY, m.xid);
    m_ids(server_duid);
    m_opt32(O_REFRESH, 600);
    m_send();
    wire_clear(&t);
    run(599000, 1000);
    ms = run_until_sent(3000, 1, &m);
    ASSERT_TRUE(ms >= 1000 && ms <= 2000);
    if (first < 0)
      first = ms;
    differ += ms != first;
  }
  ASSERT_TRUE(differ > 0);
}

int main(void) {
  fprintf(stderr, "=== itest_dhcpv6 ===\n");
  RUN_TEST(itest_dhcpv6_001_information_request);
  RUN_TEST(itest_dhcpv6_007_reply_configures);
  RUN_TEST(itest_dhcpv6_019_replies_validated);
  RUN_TEST(itest_dhcpv6_042_options_parsed);
  RUN_TEST(itest_dhcpv6_054_information_refreshed);
  RUN_TEST(itest_dhcpv6_039_retransmission);
  RUN_TEST(itest_dhcpv6_040_request_backoff_capped);
  RUN_TEST(itest_dhcpv6_051_first_solicit_rt_above_irt);
  RUN_TEST(itest_dhcpv6_011_address_assigned);
  RUN_TEST(itest_dhcpv6_032_leased_address_probed);
  RUN_TEST(itest_dhcpv6_022_first_advertise_taken);
  RUN_TEST(itest_dhcpv6_021_advertise_offers);
  RUN_TEST(itest_dhcpv6_050_elapsed_time_of_each_exchange);
  RUN_TEST(itest_dhcpv6_028_reply_without_a_lease);
  RUN_TEST(itest_dhcpv6_027_reply_when_bound_ignored);
  RUN_TEST(itest_dhcpv6_036_renew_at_t1);
  RUN_TEST(itest_dhcpv6_029_reply_to_renew_extends);
  RUN_TEST(itest_dhcpv6_029_preferred_lifetime);
  RUN_TEST(itest_dhcpv6_037_rebind_at_t2);
  RUN_TEST(itest_dhcpv6_038_lease_expires);
  RUN_TEST(itest_dhcpv6_030_t1_t2_left_to_the_client);
  RUN_TEST(itest_dhcpv6_049_release);
  RUN_TEST(itest_dhcpv6_045_leased_prefix_on_link);
  RUN_TEST(itest_dhcpv6_053_sol_max_rt_out_of_range_ignored);
  RUN_TEST(itest_dhcpv6_048_start_delay_at_most_a_second);
  RUN_TEST(itest_dhcpv6_047_t1_above_t2_discarded);
  RUN_TEST(itest_dhcpv6_053_sol_max_rt_from_a_refusing_server);
  RUN_TEST(itest_dhcpv6_055_refresh_delayed_at_random);
  ITEST_REPORT();
  return test_failures;
}
