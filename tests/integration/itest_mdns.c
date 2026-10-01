/**
 * @file itest_mdns.c
 * @brief The mDNS responder, black box: queries on the wire to
 *        224.0.0.251, the mdns_* API, and the responses it multicasts.
 */

#include "itest.h"
#include "mdns.h"
#include "udp.h"
#include <string.h>

#define HOST "pyro-dead01.local"
#define SVC "_pyro._tcp.local"
#define INST "Pyro Unit 1._pyro._tcp.local"
#define META "_services._dns-sd._udp.local"
#define T_A 1
#define T_PTR 12
#define T_TXT 16
#define T_SRV 33
#define T_NSEC 47
#define FLAG_TC 0x0200

static itest_t t;
static mdns_t m;

static void on_mdns(net_t *net, uint32_t src_ip, uint16_t src_port,
                    const uint8_t *src_mac, const uint8_t *data, uint16_t len) {
  (void)net;
  mdns_input(&m, src_ip, src_mac, src_port, data, len);
}

static const udp_port_entry_t ports[] = {{MDNS_PORT, on_mdns}};
static const char *const txt[] = {"txtvers=1", NULL};
enum { R_A, R_PTR, R_SRV, R_TXT, N_REC };
static const mdns_record_t records[N_REC] = {
    {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
    {.type = DNS_TYPE_PTR, .ttl = 4500, .name = SVC, .rdata.ptr = INST},
    {.type = DNS_TYPE_SRV,
     .ttl = 120,
     .name = INST,
     .rdata.srv = {0, 0, 80, HOST}},
    {.type = DNS_TYPE_TXT, .ttl = 4500, .name = INST, .rdata.txt = txt},
};
#define SERVICE ((1u << R_PTR) | (1u << R_SRV) | (1u << R_TXT))

static net_err_t up_with(const mdns_record_t *recs, uint8_t n, uint16_t tx) {
  itest_up(&t, 1514, tx);
  udp_set_ports(&t.net, ports, 1);
  return mdns_init(&m, &t.net, recs, n, NULL, NULL);
}

/* Probed and announced, the wire log cleared */
static void running(const mdns_record_t *recs, uint8_t n) {
  up_with(recs, n, 1514);
  mdns_start(&m);
  mdns_tick(&m, 250);
  mdns_tick(&m, 250);
  mdns_tick(&m, 250);
  mdns_tick(&m, 250);
  mdns_tick(&m, 1000);
  wire_clear(&t);
}

/* A multicast DNS message from the peer, port 5353 */
static void multicast(peer_dns_t *q) {
  static const uint8_t group_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};
  uint8_t f[1600], seg[1520];
  peer_ip_t ip = peer_ip(PEER_IP, MDNS_GROUP, 17);
  uint16_t n;
  ip.ttl = 255;
  peer_dns_end(q);
  n = peer_udp(seg, &ip, MDNS_PORT, MDNS_PORT, q->buf, q->len);
  itest_receive(&t, f, peer_ipv4_frame(f, group_mac, peer_mac, &ip, seg, n));
}

static void query(const char *name, uint16_t type, uint16_t flags) {
  peer_dns_t q;
  peer_dns_begin(&q, 0, flags);
  peer_dns_question(&q, name, type, 1);
  multicast(&q);
}

/* The @p k-th mDNS response sent over IPv4, parsed; 0 if none */
static int response(int k, peer_dns_msg_t *msg) {
  uint16_t i;
  peer_ip_t ip;
  peer_udp_t udp;
  for (i = 0; wire_sent(&t, i); i++) {
    if (peer_parse_ipv4(wire_sent(&t, i), &ip) && peer_parse_udp(&ip, &udp) &&
        udp.sport == MDNS_PORT && k-- == 0)
      return peer_dns_parse(udp.data, udp.data_len, msg);
  }
  return 0;
}

static int responses(void) {
  peer_dns_msg_t msg;
  int k = 0;
  while (response(k, &msg))
    k++;
  return k;
}

/* REQ-MDNS-032, 033, REQ-DNSSD-018: the goodbye withdraws every record and
 * the service type's meta-query listing, TTL 0 */
TEST(itest_mdns_033_goodbye_includes_the_meta_query_ptr) {
  peer_dns_msg_t g;
  const peer_rr_t *r;
  uint16_t i;
  char target[256];
  running(records, N_REC);
  mdns_stop(&m);
  ASSERT_TRUE(response(0, &g));
  for (i = 0; i < g.n_rr; i++)
    ASSERT_EQ(g.rr[i].ttl, 0u);
  ASSERT_NOT_NULL(peer_dns_find(&g, 0, HOST, T_A));
  ASSERT_NOT_NULL(peer_dns_find(&g, 0, SVC, T_PTR));
  ASSERT_NOT_NULL(peer_dns_find(&g, 0, INST, T_SRV));
  ASSERT_NOT_NULL(r = peer_dns_find(&g, 0, META, T_PTR));
  ASSERT_TRUE(peer_dns_read_name(&g, r->rdata_off, target));
  ASSERT_TRUE(strcmp(target, SVC) == 0);
}

/* REQ-DNSSD-029: a record that no packet could carry is refused at init */
TEST(itest_dnssd_029_record_too_big_for_any_packet_refused) {
  static char e1[201], e2[201], e3[201];
  static const char *const big[] = {e1, e2, e3, NULL};
  static const mdns_record_t recs[] = {
      {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
      {.type = DNS_TYPE_TXT, .ttl = 4500, .name = INST, .rdata.txt = big},
  };
  memset(e1, 'a', 200);
  memset(e2, 'b', 200);
  memset(e3, 'c', 200);
  ASSERT_EQ(up_with(recs, 2, 300), NET_ERR_BUF_TOO_SMALL);
  ASSERT_EQ(up_with(recs, 2, 1514), NET_OK);
}

/* REQ-MDNS-027 (RFC 6762 §7.2): a truncated query is answered after
 * 400-500 ms, even for a unique record */
TEST(itest_mdns_027_truncated_query_waits_400_to_500ms) {
  running(records, N_REC);
  query(HOST, T_A, FLAG_TC);
  mdns_tick(&m, 399);
  ASSERT_EQ(responses(), 0);
  mdns_tick(&m, 101);
  ASSERT_EQ(responses(), 1);
}

/* REQ-MDNS-027, 029: known answers that follow a truncated query strike
 * what it would have been answered */
TEST(itest_mdns_029_known_answers_after_truncated_query) {
  peer_dns_t q;
  peer_dns_msg_t r;
  uint8_t rd[256];
  running(records, N_REC);
  peer_dns_begin(&q, 0, FLAG_TC);
  peer_dns_question(&q, SVC, T_PTR, 1);
  peer_dns_question(&q, HOST, T_A, 1);
  multicast(&q);
  peer_dns_begin(&q, 0, 0); /* the continuation: answers only */
  peer_dns_rr(&q, 0, SVC, T_PTR, 1, 4500, rd, peer_dns_name(rd, INST));
  multicast(&q);
  mdns_tick(&m, 500);
  ASSERT_EQ(responses(), 1);
  ASSERT_TRUE(response(0, &r));
  ASSERT_NOT_NULL(peer_dns_find(&r, 0, HOST, T_A));
  ASSERT_NULL(peer_dns_find(&r, 0, SVC, T_PTR));
}

/* REQ-MDNS-032, REQ-DNSSD-018: one service withdrawn while the host stays:
 * a goodbye for its records and its type, then silence about them */
TEST(itest_dnssd_018_withdraw_one_service) {
  peer_dns_msg_t g;
  running(records, N_REC);
  mdns_withdraw(&m, SERVICE);
  ASSERT_EQ(responses(), 1);
  ASSERT_TRUE(response(0, &g));
  ASSERT_EQ(g.an, 4);
  ASSERT_EQ(g.ar, 0);
  ASSERT_NOT_NULL(peer_dns_find(&g, 0, SVC, T_PTR));
  ASSERT_NOT_NULL(peer_dns_find(&g, 0, INST, T_SRV));
  ASSERT_NOT_NULL(peer_dns_find(&g, 0, INST, T_TXT));
  ASSERT_NOT_NULL(peer_dns_find(&g, 0, META, T_PTR));
  ASSERT_NULL(peer_dns_find(&g, 0, HOST, T_A));
  ASSERT_EQ(g.rr[0].ttl, 0u);

  wire_clear(&t);
  query(SVC, T_PTR, 0);
  query(INST, T_SRV, 0);
  query(INST, T_A, 0); /* an NSEC, were the name still ours */
  query(META, T_PTR, 0);
  mdns_tick(&m, 200);
  ASSERT_EQ(responses(), 0);
  query(HOST, T_A, 0);
  ASSERT_EQ(responses(), 1);

  wire_clear(&t);
  mdns_stop(&m); /* goodbye to what is left */
  ASSERT_TRUE(response(0, &g));
  ASSERT_EQ(g.an, 1);
  ASSERT_NOT_NULL(peer_dns_find(&g, 0, HOST, T_A));
}

/* REQ-DNSSD-018: a type another instance still offers keeps its listing */
TEST(itest_dnssd_018_withdraw_one_of_two_instances) {
  static const mdns_record_t recs[] = {
      {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
      {.type = DNS_TYPE_PTR, .ttl = 4500, .name = SVC, .rdata.ptr = INST},
      {.type = DNS_TYPE_PTR,
       .ttl = 4500,
       .name = SVC,
       .rdata.ptr = "Pyro Unit 2._pyro._tcp.local"},
  };
  peer_dns_msg_t g;
  running(recs, 3);
  mdns_withdraw(&m, 1u << 1);
  ASSERT_TRUE(response(0, &g));
  ASSERT_EQ(g.an, 1);
  ASSERT_NULL(peer_dns_find(&g, 0, META, T_PTR));
}

/* REQ-MDNS-016, REQ-DNSSD-018: withdrawn before announcing: no goodbye,
 * and the withdrawn name is not probed */
TEST(itest_dnssd_018_withdraw_while_probing) {
  peer_dns_msg_t p;
  up_with(records, N_REC, 1514);
  mdns_start(&m);
  wire_clear(&t);
  mdns_withdraw(&m, SERVICE);
  ASSERT_EQ(t.wire.tx_count, 0);
  mdns_tick(&m, 250);
  ASSERT_EQ(responses(), 1); /* the first probe */
  ASSERT_TRUE(response(0, &p));
  ASSERT_EQ(p.qd, 1);
  ASSERT_TRUE(strcmp(p.qname, HOST) == 0);
  ASSERT_NULL(peer_dns_find(&p, 1, INST, T_SRV));
}

int main(void) {
  fprintf(stderr, "=== itest_mdns ===\n");
  RUN_TEST(itest_mdns_033_goodbye_includes_the_meta_query_ptr);
  RUN_TEST(itest_dnssd_029_record_too_big_for_any_packet_refused);
  RUN_TEST(itest_mdns_027_truncated_query_waits_400_to_500ms);
  RUN_TEST(itest_mdns_029_known_answers_after_truncated_query);
  RUN_TEST(itest_dnssd_018_withdraw_one_service);
  RUN_TEST(itest_dnssd_018_withdraw_one_of_two_instances);
  RUN_TEST(itest_dnssd_018_withdraw_while_probing);
  ITEST_REPORT();
  return test_failures;
}
