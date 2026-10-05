/**
 * @file itest_mdns_no_tiebreak.c
 * @brief The mDNS responder built without simultaneous-probe tiebreaking
 *        (MDNS_TIEBREAK 0), black box: two responders that claim the same
 *        name on one link, each a whole stack, and what becomes of the
 *        name.
 */

#include "itest.h"
#include "mdns.h"
#include "udp.h"
#include <string.h>

#if MDNS_TIEBREAK
#error "this suite is the responder built with MDNS_TIEBREAK 0"
#endif

#define HOST "pyro-dead01.local"
#define SVC "_pyro._tcp.local"
#define INST "Pyro Unit 1._pyro._tcp.local"
#define T_A 1
#define T_ANY 255
#define C_IN 1
#define C_TOP 0x8000 /* QU in questions */
#define FLAG_QR 0x8000

/* A host: a stack on its own wire, its responder, and what the test saw
 * of it — the conflicts it reported and the probes it sent */
typedef struct {
  itest_t t;
  mdns_t m;
  int conflicts;
  int probes;
} host_t;

static host_t a, b;

static void on_conflict(mdns_t *m, uint8_t index, void *ctx) {
  (void)m;
  (void)index;
  ((host_t *)ctx)->conflicts++;
}

static void on_mdns(net_t *net, uint32_t src_ip, uint16_t src_port,
                    const uint8_t *src_mac, const uint8_t *data, uint16_t len) {
  host_t *h = (net == &a.t.net) ? &a : &b;
  mdns_input(&h->m, src_ip, src_mac, src_port, data, len);
}

/* Both hosts advertise the same names; the A record is each one's own
 * address, so their data differ */
static const udp_port_entry_t ports[] = {{MDNS_PORT, on_mdns}};
static const char *const txt[] = {"txtvers=1", NULL};
static const mdns_record_t records[] = {
    {.type = DNS_TYPE_A, .ttl = 120, .name = HOST, .rdata.a = 0},
    {.type = DNS_TYPE_PTR, .ttl = 4500, .name = SVC, .rdata.ptr = INST},
    {.type = DNS_TYPE_SRV,
     .ttl = 120,
     .name = INST,
     .rdata.srv = {0, 0, 80, HOST}},
    {.type = DNS_TYPE_TXT, .ttl = 4500, .name = INST, .rdata.txt = txt},
};
#define N_REC ((uint8_t)(sizeof(records) / sizeof(records[0])))

/* Host @p h up at 10.0.0.@p octet, with a MAC address of its own — and so
 * random delays of its own */
static void host_up(host_t *h, uint8_t octet) {
  memset(h, 0, sizeof(*h));
  itest_up(&h->t, 1514, 1514);
  h->t.net.mac[5] = octet;
  h->t.net.ipv4_addr = 0x0A000000u | octet;
  net_random_seed(&h->t.net, h->t.net.mac, 6);
  udp_set_ports(&h->t.net, ports, 1);
  mdns_init(&h->m, &h->t.net, records, N_REC, on_conflict, h);
}

static void both_up(void) {
  host_up(&a, 2);
  host_up(&b, 3);
}

/* The frame is an mDNS query over IPv4: a probe, from these hosts */
static int is_probe(const wire_frame_t *f) {
  peer_ip_t ip;
  peer_udp_t udp;
  return peer_parse_ipv4(f, &ip) && peer_parse_udp(&ip, &udp) &&
         udp.sport == MDNS_PORT && udp.data_len >= 12 &&
         !(peer_get16(udp.data + 2) & FLAG_QR);
}

/* What @p from sent reaches @p to */
static void carry(host_t *from, host_t *to) {
  static wire_frame_t sent[WIRE_TX_SLOTS];
  uint16_t n = 0, i;
  while (n < WIRE_TX_SLOTS && wire_sent(&from->t, n)) {
    sent[n] = *wire_sent(&from->t, n);
    n++;
  }
  wire_clear(&from->t);
  for (i = 0; i < n; i++) {
    from->probes += is_probe(&sent[i]);
    itest_receive(&to->t, sent[i].data, sent[i].len);
  }
}

/* The link: every frame to the other host, and what that makes it send */
static void exchange(void) {
  int rounds = 0;
  while ((wire_sent(&a.t, 0) || wire_sent(&b.t, 0)) && rounds++ < 16) {
    carry(&a, &b);
    carry(&b, &a);
  }
}

static void tick(host_t *h, uint32_t ms) {
  itest_advance(&h->t, ms, ms);
  mdns_tick(&h->m, ms);
}

/* Both hosts' time, 10 ms at a time, the link carrying their frames */
static void run(uint32_t ms) {
  for (; ms; ms -= 10) {
    tick(&a, 10);
    tick(&b, 10);
    exchange();
  }
}

/* One host's time alone, until its first probe is out */
static void until_first_probe(host_t *h, host_t *other) {
  int k;
  for (k = 0; k < 30 && h->probes == 0; k++) {
    tick(h, 10);
    carry(h, other);
  }
}

/* One host has the name and the other was told of the conflict */
static int settled(void) {
  const host_t *keeps = a.conflicts ? &b : &a, *lost = a.conflicts ? &a : &b;
  return a.conflicts + b.conflicts == 1 &&
         mdns_state(&keeps->m) == MDNS_STATE_RUNNING &&
         mdns_state(&lost->m) == MDNS_STATE_CONFLICT;
}

/* REQ-MDNS-081: without tiebreaking, another host's probe for a name we
 * probe for — with later data, which a tiebreak would lose to — is a
 * query like any other: the probes go on at their 250 ms, then the
 * announcement, and no conflict is reported */
TEST(itest_mdns_081_another_hosts_probe_is_not_deferred_to) {
  uint8_t f[1600], seg[1520], rd[4];
  peer_ip_t ip = peer_ip(PEER_IP, MDNS_GROUP, 17);
  static const uint8_t group_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB};
  peer_dns_t q;
  both_up();
  mdns_start(&a.m);
  until_first_probe(&a, &b);
  ASSERT_EQ(a.probes, 1);
  peer_dns_begin(&q, 0, 0);
  peer_dns_question(&q, HOST, T_ANY, C_IN | C_TOP);
  peer_put32(rd, 0x0A0000C8u); /* 10.0.0.200 > 10.0.0.2 */
  peer_dns_rr(&q, 1, HOST, T_A, C_IN, 120, rd, 4);
  peer_dns_end(&q);
  ip.ttl = 255;
  itest_receive(
      &a.t, f,
      peer_ipv4_frame(f, group_mac, peer_mac, &ip, seg,
                      peer_udp(seg, &ip, MDNS_PORT, MDNS_PORT, q.buf, q.len)));
  run(500);
  ASSERT_EQ(a.probes, 3);
  ASSERT_EQ(mdns_state(&a.m), MDNS_STATE_PROBING);
  run(250);
  ASSERT_EQ(mdns_state(&a.m), MDNS_STATE_ANNOUNCING);
  ASSERT_EQ(a.conflicts, 0);
}

/* REQ-MDNS-081, 053: two hosts claim one name, the second while the first
 * still probes.  Neither defers to the other's probes; the first to
 * announce does so while the second probes, which is a conflict to the
 * second: the first keeps the name, the second is told to take another */
TEST(itest_mdns_081_first_to_announce_keeps_the_name) {
  both_up();
  mdns_start(&a.m);
  until_first_probe(&a, &b);
  mdns_start(&b.m);
  run(3000);
  ASSERT_EQ(a.probes, 3);
  ASSERT_EQ(a.conflicts, 0);
  ASSERT_EQ(b.conflicts, 1);
  ASSERT_EQ(mdns_state(&a.m), MDNS_STATE_RUNNING);
  ASSERT_EQ(mdns_state(&b.m), MDNS_STATE_CONFLICT);
}

/* REQ-MDNS-081, 057: a dead heat — both hosts' first probes at the same
 * moment, so both announce at the same moment.  Each then holds a name
 * the other announced with other data: both probe for it again (§9),
 * after random delays of their own — spread over more than the second
 * for which a record just multicast is held back, or they would announce
 * together again — and now one announces first.  One keeps the name, the
 * other is told; nobody is left sharing it */
TEST(itest_mdns_081_dead_heat_settled_by_probing_again) {
  both_up();
  mdns_start(&a.m);
  mdns_start(&b.m);
  until_first_probe(&a, &b);
  until_first_probe(&b, &a);
  ASSERT_EQ(a.probes, 1);
  ASSERT_EQ(b.probes, 1);
  run(760);
  /* each has announced and heard the other: back to probing, no callback */
  ASSERT_EQ(a.probes, 3);
  ASSERT_EQ(b.probes, 3);
  ASSERT_EQ(mdns_state(&a.m), MDNS_STATE_PROBING);
  ASSERT_EQ(mdns_state(&b.m), MDNS_STATE_PROBING);
  ASSERT_EQ(a.conflicts + b.conflicts, 0);
  run(10000);
  ASSERT_TRUE(settled());
}

/* REQ-MDNS-081: two hosts that start at the same moment, each with its
 * own random delay before the first probe: one keeps the name */
TEST(itest_mdns_081_started_together_one_keeps_the_name) {
  both_up();
  mdns_start(&a.m);
  mdns_start(&b.m);
  run(10000);
  ASSERT_TRUE(settled());
}

int main(void) {
  RUN_TEST(itest_mdns_081_another_hosts_probe_is_not_deferred_to);
  RUN_TEST(itest_mdns_081_first_to_announce_keeps_the_name);
  RUN_TEST(itest_mdns_081_dead_heat_settled_by_probing_again);
  RUN_TEST(itest_mdns_081_started_together_one_keeps_the_name);
  ITEST_REPORT();
  return test_failures;
}
