/**
 * @file itest_dhcpv4.c
 * @brief The DHCPv4 client and server, black box: DHCP messages and ARP
 *        on the wire, built and read by the peer's own codec below, and
 *        the dhcpv4_client_* and dhcpv4_server_* API.
 */

#include "dhcpv4_client.h"
#include "dhcpv4_server.h"
#include "itest.h"
#include "udp.h"
#include <string.h>

/* ── The peer's DHCP codec (RFC 2131 §2, RFC 2132) ── */

#define BOOTREQUEST 1
#define BOOTREPLY 2

#define M_DISCOVER 1
#define M_OFFER 2
#define M_REQUEST 3
#define M_DECLINE 4
#define M_ACK 5
#define M_NAK 6
#define M_RELEASE 7
#define M_INFORM 8

#define O_PAD 0
#define O_MASK 1
#define O_ROUTER 3
#define O_DNS 6
#define O_NTP 42
#define O_VENDOR 43
#define O_REQ_IP 50
#define O_LEASE 51
#define O_OVERLOAD 52
#define O_TYPE 53
#define O_SERVER 54
#define O_PRL 55
#define O_MAX_SIZE 57
#define O_T1 58
#define O_T2 59
#define O_CLASS 60
#define O_CLIENT_ID 61
#define O_PRIVATE 224 /* site-specific (RFC 2132 §2): an application's */
#define O_END 255

#define F_SECS 8
#define F_FLAGS 10
#define F_CIADDR 12
#define F_YIADDR 16
#define F_SIADDR 20
#define F_GIADDR 24
#define F_CHADDR 28
#define F_SNAME 44
#define F_FILE 108
#define F_COOKIE 236
#define F_OPTIONS 240
#define MAGIC 0x63825363u

/* A message the peer builds */
typedef struct {
  uint8_t b[1024];
  uint16_t end; /* where the next option goes in the options field */
} dmsg_t;

static void dopt(dmsg_t *m, uint8_t code, const void *v, uint8_t len) {
  m->b[m->end] = code;
  m->b[m->end + 1] = len;
  memcpy(m->b + m->end + 2, v, len);
  m->end = (uint16_t)(m->end + 2u + len);
}

static void dopt32(dmsg_t *m, uint8_t code, uint32_t v) {
  uint8_t b[4];
  peer_put32(b, v);
  dopt(m, code, b, 4);
}

/* The fixed fields zeroed but for these, the cookie, and option 53 */
static void dbegin(dmsg_t *m, uint8_t op, uint8_t type, uint32_t xid,
                   const uint8_t chaddr[6]) {
  memset(m, 0, sizeof(*m));
  m->b[0] = op;
  m->b[1] = 1;
  m->b[2] = 6;
  peer_put32(m->b + 4, xid);
  memcpy(m->b + F_CHADDR, chaddr, 6);
  peer_put32(m->b + F_COOKIE, MAGIC);
  m->end = F_OPTIONS;
  dopt(m, O_TYPE, &type, 1);
}

/* The End option; the message's length, at least 300 */
static uint16_t dfinish(dmsg_t *m) {
  m->b[m->end++] = O_END;
  return m->end < 300 ? 300 : m->end;
}

/* A message the stack sent */
typedef struct {
  peer_ip_t ip;
  peer_udp_t udp;
  const uint8_t *m;
  uint16_t len;
  uint8_t type;
} dsent_t;

/* Option @p code of the options field, the peer's own walk: NULL if none */
static const uint8_t *dget(const dsent_t *d, uint8_t code, uint8_t *len) {
  uint16_t p = F_OPTIONS;
  while (p < d->len && d->m[p] != O_END) {
    if (d->m[p] == O_PAD) {
      p++;
      continue;
    }
    if (p + 2u > d->len || p + 2u + d->m[p + 1] > d->len)
      return NULL;
    if (d->m[p] == code) {
      *len = d->m[p + 1];
      return d->m + p + 2;
    }
    p = (uint16_t)(p + 2u + d->m[p + 1]);
  }
  return NULL;
}

static uint32_t dget32(const dsent_t *d, uint8_t code) {
  uint8_t len;
  const uint8_t *v = dget(d, code, &len);
  return v && len == 4 ? peer_get32(v) : 0u;
}

static int dhas(const dsent_t *d, uint8_t code) {
  uint8_t len;
  return dget(d, code, &len) != NULL;
}

/* The codes of the options field in order, pads left out: their count */
static uint8_t dcodes(const dsent_t *d, uint8_t *codes, uint8_t max) {
  uint16_t p = F_OPTIONS;
  uint8_t n = 0;
  while (p + 1u < d->len && d->m[p] != O_END && n < max) {
    if (d->m[p] == O_PAD) {
      p++;
      continue;
    }
    codes[n++] = d->m[p];
    p = (uint16_t)(p + 2u + d->m[p + 1]);
  }
  return n;
}

/* Where @p code is among @p codes: its index, or -1 */
static int at(const uint8_t *codes, uint8_t n, uint8_t code) {
  uint8_t i;
  for (i = 0; i < n; i++)
    if (codes[i] == code)
      return i;
  return -1;
}

static int count_of(const uint8_t *codes, uint8_t n, uint8_t code) {
  uint8_t i;
  int k = 0;
  for (i = 0; i < n; i++)
    k += codes[i] == code;
  return k;
}

static itest_t t;

/* Frame @p i as a DHCP message on port 67 or 68: 1 if it is one */
static int dparse(uint16_t i, dsent_t *d) {
  const wire_frame_t *f = wire_sent(&t, i);
  uint8_t len;
  const uint8_t *type;
  memset(d, 0, sizeof(*d));
  if (!f || !peer_parse_ipv4(f, &d->ip) || !peer_parse_udp(&d->ip, &d->udp) ||
      (d->udp.dport != 67 && d->udp.dport != 68) || d->udp.data_len < 244 ||
      peer_get32(d->udp.data + F_COOKIE) != MAGIC)
    return 0;
  d->m = d->udp.data;
  d->len = d->udp.data_len;
  type = dget(d, O_TYPE, &len);
  d->type = type && len == 1 ? type[0] : 0;
  return 1;
}

/* The first DHCP message of @p type sent: its frame's index, or -1 */
static int dfind(uint8_t type, dsent_t *d) {
  uint16_t i;
  for (i = 0; wire_sent(&t, i); i++)
    if (dparse(i, d) && d->type == type)
      return i;
  return -1;
}

static int flags_reserved_zero(const dsent_t *d) {
  return (peer_get16(d->m + F_FLAGS) & 0x7FFFu) == 0;
}

/* ── The client ── */

#define SERVER_IP PEER_IP
#define OFFERED 0x0A000032u /* 10.0.0.50 */
#define MASK 0xFFFFFF00u
#define ROUTER PEER_IP
#define LEASE 3600u
#define RELAY_IP 0x0A0000FEu /* 10.0.0.254 */

static const uint8_t other_mac[6] = {0x02, 0x4F, 0x54, 0x48, 0x45, 0x52};
static const uint8_t relay_mac[6] = {0x02, 0x52, 0x45, 0x4C, 0x41, 0x59};
static const uint8_t zero_mac[6] = {0};

static dhcpv4_client_t cli;
static uint32_t xid; /* the client's, from its DISCOVER */
static uint8_t events[32];
static uint8_t n_events;

static void on_client_event(uint8_t event, void *ctx) {
  (void)ctx;
  if (n_events < sizeof(events))
    events[n_events++] = event;
}

static int got_event(uint8_t event) {
  uint8_t i;
  for (i = 0; i < n_events; i++)
    if (events[i] == event)
      return 1;
  return 0;
}

static void on_68(net_t *net, uint32_t src_ip, uint16_t src_port,
                  const uint8_t *src_mac, const uint8_t *data, uint16_t len) {
  (void)src_port;
  dhcpv4_client_input(net, &cli, src_ip, src_mac, data, len);
}

static const udp_port_entry_t client_ports[] = {{68, on_68}};

/* A client with no address, as an application starts it, past its
 * start-up wait: the DISCOVER is on the wire */
static void client_up(const dhcpv4_opt_table_t *opts) {
  dsent_t d;
  itest_up(&t, 1514, 1514);
  t.net.ipv4_addr = 0;
  t.net.subnet_mask = 0;
  t.net.gateway_ipv4 = 0;
  udp_set_ports(&t.net, client_ports, 1);
  n_events = 0;
  dhcpv4_client_init(&cli, &t.net, on_client_event, NULL, opts);
  dhcpv4_client_start(&t.net, &cli);
  dhcpv4_client_tick(&t.net, &cli, DHCPV4_START_DELAY_MAX_MS);
  xid = dfind(M_DISCOVER, &d) >= 0 ? peer_get32(d.m + 4) : 0;
}

/* A reply to the client: BOOTREPLY, its xid and chaddr, @p yiaddr */
static void reply_begin(dmsg_t *m, uint8_t type, uint32_t yiaddr) {
  dbegin(m, BOOTREPLY, type, xid, t.net.mac);
  peer_put32(m->b + F_YIADDR, yiaddr);
}

/* Broadcast from @p src_ip, @p src_mac, port 67 */
static void to_client_from(dmsg_t *m, uint32_t src_ip, const uint8_t *src_mac) {
  static uint8_t f[1200], seg[1100];
  peer_ip_t ip = peer_ip(src_ip, 0xFFFFFFFFu, 17);
  uint16_t n = peer_udp(seg, &ip, 67, 68, m->b, dfinish(m));
  itest_receive(&t, f, peer_ipv4_frame(f, broadcast_mac, src_mac, &ip, seg, n));
}

static void to_client(dmsg_t *m) { to_client_from(m, SERVER_IP, peer_mac); }

static void offer(void) {
  dmsg_t m;
  reply_begin(&m, M_OFFER, OFFERED);
  dopt32(&m, O_SERVER, SERVER_IP);
  dopt32(&m, O_LEASE, LEASE);
  dopt32(&m, O_MASK, MASK);
  dopt32(&m, O_ROUTER, ROUTER);
  to_client(&m);
}

/* An ACK of OFFERED from SERVER_IP, before its lease and parameters */
static void ack_begin(dmsg_t *m) {
  reply_begin(m, M_ACK, OFFERED);
  dopt32(m, O_SERVER, SERVER_IP);
}

/* An ACK with the mask, the router, the lease, and T1 and T2 if not 0 */
static void ack(uint32_t lease, uint32_t t1, uint32_t t2) {
  dmsg_t m;
  ack_begin(&m);
  dopt32(&m, O_LEASE, lease);
  dopt32(&m, O_MASK, MASK);
  dopt32(&m, O_ROUTER, ROUTER);
  if (t1)
    dopt32(&m, O_T1, t1);
  if (t2)
    dopt32(&m, O_T2, t2);
  to_client(&m);
}

/* The client a second past the ARP probe of its ACK (1 s, RFC 5227) */
#define PROBED_MS 2000u

/* A client bound to OFFERED (after the ARP probe), the wire cleared */
static void bound(uint32_t lease, uint32_t t1, uint32_t t2) {
  client_up(NULL);
  offer();
  ack(lease, t1, t2);
  dhcpv4_client_tick(&t.net, &cli, PROBED_MS);
  wire_clear(&t);
}

/* Tick a second at a time, at most @p limit_s: the seconds until the client
 * sends a DHCP message, parsed into @p d (the wire cleared before); 0 if
 * it sends none */
static uint32_t secs_to_next(uint32_t limit_s, dsent_t *d) {
  uint32_t s;
  for (s = 1; s <= limit_s; s++) {
    wire_clear(&t);
    dhcpv4_client_tick(&t.net, &cli, 1000);
    if (dfind(M_DISCOVER, d) >= 0 || dfind(M_REQUEST, d) >= 0 ||
        dfind(M_DECLINE, d) >= 0)
      return s;
  }
  return 0;
}

/* The seconds into the lease of an event @p s seconds after bound() */
static uint32_t lease_s(uint32_t s) { return s + PROBED_MS / 1000u; }

/* Within the client's fuzz (less than 1/16 earlier) of @p base, give or
 * take the second the clock steps by */
static int near_fuzzed(uint32_t got, uint32_t base) {
  return got <= base + 1u && got >= base - base / 16u;
}

static void arp_from(uint16_t op, const uint8_t *sha, uint32_t spa,
                     uint32_t tpa, const uint8_t *eth_dst) {
  uint8_t f[64];
  itest_receive(&t, f, peer_arp_frame(f, eth_dst, op, sha, spa, zero_mac, tpa));
}

/* The client just ACKed: what it sent since is on the wire */
static void acked(void) {
  client_up(NULL);
  offer();
  wire_clear(&t);
  ack(LEASE, 0, 0);
}

/* REQ-DHCPv4-081: the address of an ACK is probed — an ARP Probe: our MAC,
 * sender IP 0, target the address (RFC 5227 §2.1.1) — and used only when a
 * second has passed without an answer; a request for it from a third host
 * (with its own sender address) is no conflict, and not ours to answer */
TEST(itest_dhcpv4_081_ack_probed_before_use) {
  peer_arp_t a;
  uint16_t i, probes = 0;
  acked();
  for (i = 0; wire_sent(&t, i); i++) {
    if (!peer_parse_arp(wire_sent(&t, i), &a))
      continue;
    probes++;
    ASSERT_MEM_EQ(wire_sent(&t, i)->data, broadcast_mac, 6);
    ASSERT_EQ(a.op, 1);
    ASSERT_MEM_EQ(a.sha, t.net.mac, 6);
    ASSERT_EQ(a.spa, 0u);
    ASSERT_MEM_EQ(a.tha, zero_mac, 6);
    ASSERT_EQ(a.tpa, OFFERED);
  }
  ASSERT_EQ(probes, 1);
  ASSERT_EQ(t.net.ipv4_addr, 0u);
  ASSERT_FALSE(got_event(DHCPV4_EVT_BOUND));
  ASSERT_EQ(dhcpv4_client_state(&cli), DHCPV4_CLI_CHECKING);

  wire_clear(&t);
  arp_from(1, other_mac, PEER2_IP, OFFERED, broadcast_mac);
  ASSERT_EQ(t.wire.tx_count, 0);
  dhcpv4_client_tick(&t.net, &cli, 999);
  ASSERT_EQ(t.net.ipv4_addr, 0u);
  ASSERT_FALSE(got_event(DHCPV4_EVT_BOUND));
  dhcpv4_client_tick(&t.net, &cli, 1);
  ASSERT_TRUE(got_event(DHCPV4_EVT_BOUND));
  ASSERT_EQ(dhcpv4_client_state(&cli), DHCPV4_CLI_BOUND);
  ASSERT_EQ(t.net.ipv4_addr, OFFERED);
  ASSERT_EQ(t.net.subnet_mask, MASK);
}

/* REQ-DHCPv4-080, 082: an ARP reply from the address while it is probed:
 * a DHCPDECLINE — broadcast from 0.0.0.0, naming the address and the
 * server and nothing else (RFC 2131 Table 5, §4.4.4) — the address never
 * used, and discovery again after 10 s */
TEST(itest_dhcpv4_080_address_in_use_declined) {
  dsent_t d;
  uint8_t codes[16], n;
  acked();
  arp_from(2, other_mac, OFFERED, 0, t.net.mac);
  wire_clear(&t);
  dhcpv4_client_tick(&t.net, &cli, 1000);
  ASSERT_TRUE(dfind(M_DECLINE, &d) >= 0);
  ASSERT_EQ(d.ip.src, 0u);
  ASSERT_EQ(d.ip.dst, 0xFFFFFFFFu);
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, broadcast_mac, 6);
  ASSERT_EQ(d.udp.sport, 68);
  ASSERT_EQ(d.udp.dport, 67);
  ASSERT_EQ(d.m[0], BOOTREQUEST);
  ASSERT_MEM_EQ(d.m + F_CHADDR, t.net.mac, 6);
  ASSERT_EQ(peer_get16(d.m + F_SECS), 0);
  ASSERT_EQ(peer_get16(d.m + F_FLAGS), 0);
  ASSERT_EQ(peer_get32(d.m + F_CIADDR), 0u);
  ASSERT_EQ(peer_get32(d.m + F_YIADDR), 0u);
  ASSERT_EQ(peer_get32(d.m + F_SIADDR), 0u);
  ASSERT_EQ(peer_get32(d.m + F_GIADDR), 0u);
  ASSERT_EQ(dget32(&d, O_REQ_IP), OFFERED);
  ASSERT_EQ(dget32(&d, O_SERVER), SERVER_IP);
  n = dcodes(&d, codes, sizeof(codes));
  ASSERT_EQ(n, 3);
  ASSERT_TRUE(at(codes, n, O_TYPE) >= 0);
  ASSERT_EQ(t.net.ipv4_addr, 0u);
  ASSERT_FALSE(got_event(DHCPV4_EVT_BOUND));
  ASSERT_TRUE(got_event(DHCPV4_EVT_DECLINED));
  ASSERT_EQ(dhcpv4_client_state(&cli), DHCPV4_CLI_INIT);

  wire_clear(&t);
  dhcpv4_client_tick(&t.net, &cli, 9999);
  ASSERT_EQ(t.wire.tx_count, 0);
  dhcpv4_client_tick(&t.net, &cli, 1);
  ASSERT_TRUE(dfind(M_DISCOVER, &d) >= 0);
}

/* REQ-DHCPv4-080: another host probing for the address, or asking from
 * it, is a conflict too (RFC 5227 §2.1.1); our own probe echoed back by
 * the link is not */
TEST(itest_dhcpv4_080_other_probe_or_request_conflicts) {
  dsent_t d;
  acked();
  arp_from(1, other_mac, 0, OFFERED, broadcast_mac);
  wire_clear(&t);
  dhcpv4_client_tick(&t.net, &cli, 1000);
  ASSERT_TRUE(dfind(M_DECLINE, &d) >= 0);

  acked();
  arp_from(1, other_mac, OFFERED, PEER_IP, broadcast_mac);
  wire_clear(&t);
  dhcpv4_client_tick(&t.net, &cli, 1000);
  ASSERT_TRUE(dfind(M_DECLINE, &d) >= 0);

  acked();
  arp_from(1, t.net.mac, 0, OFFERED, broadcast_mac);
  wire_clear(&t);
  dhcpv4_client_tick(&t.net, &cli, 1000);
  ASSERT_TRUE(dfind(M_DECLINE, &d) < 0);
  ASSERT_EQ(t.net.ipv4_addr, OFFERED);
}

/* REQ-DHCPv4-039, 081: released while its address is still probed, the
 * lease is given up without a RELEASE — nothing was sent from the address
 * — and the address never used */
TEST(itest_dhcpv4_039_release_while_probing) {
  acked();
  wire_clear(&t);
  dhcpv4_client_release(&t.net, &cli);
  dhcpv4_client_tick(&t.net, &cli, PROBED_MS);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(t.net.ipv4_addr, 0u);
  ASSERT_FALSE(got_event(DHCPV4_EVT_BOUND));
  ASSERT_EQ(dhcpv4_client_state(&cli), DHCPV4_CLI_INIT);
}

/* REQ-DHCPv4-020: an OFFER without a Server Identifier names no server to
 * select (RFC 2131 Table 3): dropped, where it was answered with a REQUEST
 * naming 0.0.0.0 */
TEST(itest_dhcpv4_020_offer_without_server_id_dropped) {
  dmsg_t m;
  dsent_t d;
  client_up(NULL);
  wire_clear(&t);
  reply_begin(&m, M_OFFER, OFFERED);
  dopt32(&m, O_LEASE, LEASE);
  to_client(&m);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(dhcpv4_client_state(&cli), DHCPV4_CLI_SELECTING);
  offer();
  ASSERT_TRUE(dfind(M_REQUEST, &d) >= 0);
  ASSERT_EQ(dget32(&d, O_SERVER), SERVER_IP);
}

/* REQ-DHCPv4-084: options in 'file' and 'sname' are read when the Option
 * Overload option says so — the lease time and mask from 'file', the
 * router and T1 from 'sname' */
TEST(itest_dhcpv4_084_options_in_file_and_sname) {
  static const uint8_t in_file[] = {O_LEASE, 4,   0,   0,   0x0E, 0x10,  O_MASK,
                                    4,       255, 255, 255, 0,    O_END, O_PAD};
  static const uint8_t in_sname[] = {O_ROUTER, 4, 10, 0, 0,    1,    O_T1,
                                     4,        0, 0,  3, 0x84, O_END};
  static const uint8_t both = 3;
  dmsg_t m;
  dsent_t d;
  uint32_t s;
  client_up(NULL);
  offer();
  ack_begin(&m);
  dopt(&m, O_OVERLOAD, &both, 1);
  memcpy(m.b + F_FILE, in_file, sizeof(in_file));
  memcpy(m.b + F_SNAME, in_sname, sizeof(in_sname));
  to_client(&m);
  dhcpv4_client_tick(&t.net, &cli, PROBED_MS);
  ASSERT_EQ(dhcpv4_client_state(&cli), DHCPV4_CLI_BOUND);
  ASSERT_EQ(t.net.ipv4_addr, OFFERED);
  ASSERT_EQ(t.net.subnet_mask, MASK);
  ASSERT_EQ(t.net.gateway_ipv4, 0x0A000001u);
  s = secs_to_next(3600, &d);
  ASSERT_EQ(d.type, M_REQUEST);
  ASSERT_TRUE(near_fuzzed(lease_s(s), 900));
}

/* REQ-DHCPv4-084: 'sname' holds options only when option 52 says so:
 * with 1, only 'file' is read, and a server name that looks like options
 * is a name */
TEST(itest_dhcpv4_084_sname_unread_unless_overloaded) {
  static const uint8_t in_file[] = {O_LEASE, 4, 0, 0, 0x0E, 0x10, O_END};
  static const uint8_t in_sname[] = {O_MASK, 4, 255, 255, 0, 0, O_END};
  static const uint8_t file_only = 1;
  dmsg_t m;
  client_up(NULL);
  offer();
  ack_begin(&m);
  dopt(&m, O_OVERLOAD, &file_only, 1);
  memcpy(m.b + F_FILE, in_file, sizeof(in_file));
  memcpy(m.b + F_SNAME, in_sname, sizeof(in_sname));
  to_client(&m);
  dhcpv4_client_tick(&t.net, &cli, PROBED_MS);
  ASSERT_EQ(dhcpv4_client_state(&cli), DHCPV4_CLI_BOUND);
  ASSERT_EQ(t.net.subnet_mask, 0u);
}

static uint8_t opt_value[300];
static uint16_t opt_len;
static int opt_calls;

static void on_private(uint8_t option, const uint8_t *data, uint8_t len,
                       void *ctx) {
  (void)option;
  (void)ctx;
  memcpy(opt_value, data, len);
  opt_len = len;
  opt_calls++;
}

static const dhcpv4_opt_entry_t private_entry[] = {
    {O_PRIVATE, on_private, NULL}};
static const dhcpv4_opt_table_t private_table = {private_entry, 1};

/* REQ-DHCPv4-089, 053: an option split into parts is one option, the parts
 * joined in order — a lease time and a router split mid-value, and the
 * application's option given to its handler once, whole */
TEST(itest_dhcpv4_089_split_options_joined) {
  static const uint8_t lease_hi[] = {0, 0}, lease_lo[] = {0x0E, 0x10};
  static const uint8_t router_hi[] = {10, 0}, router_lo[] = {0, 1};
  dmsg_t m;
  dsent_t d;
  uint32_t s;
  opt_calls = 0;
  client_up(&private_table);
  offer();
  ack_begin(&m);
  dopt(&m, O_LEASE, lease_hi, 2);
  dopt(&m, O_ROUTER, router_hi, 2);
  dopt(&m, O_PRIVATE, "abc", 3);
  dopt32(&m, O_MASK, MASK);
  dopt(&m, O_LEASE, lease_lo, 2);
  dopt(&m, O_PRIVATE, "def", 3);
  dopt(&m, O_ROUTER, router_lo, 2);
  to_client(&m);
  dhcpv4_client_tick(&t.net, &cli, PROBED_MS);
  ASSERT_EQ(dhcpv4_client_state(&cli), DHCPV4_CLI_BOUND);
  ASSERT_EQ(t.net.gateway_ipv4, 0x0A000001u);
  ASSERT_EQ(opt_calls, 1);
  ASSERT_EQ(opt_len, 6);
  ASSERT_MEM_EQ(opt_value, "abcdef", 6);
  s = secs_to_next(3600, &d);
  ASSERT_EQ(d.type, M_REQUEST);
  ASSERT_TRUE(near_fuzzed(lease_s(s), 1800));
}

/* REQ-DHCPv4-089, 084: the parts are joined in the aggregate buffer's
 * order (RFC 3396 §5): the options field, then 'file', then 'sname' */
TEST(itest_dhcpv4_089_split_across_fields_in_order) {
  static const uint8_t in_file[] = {O_PRIVATE, 2, 'c', 'd', O_END};
  static const uint8_t in_sname[] = {O_PRIVATE, 2, 'e', 'f', O_END};
  static const uint8_t both = 3;
  dmsg_t m;
  opt_calls = 0;
  client_up(&private_table);
  offer();
  ack_begin(&m);
  dopt32(&m, O_LEASE, LEASE);
  dopt(&m, O_OVERLOAD, &both, 1);
  dopt(&m, O_PRIVATE, "ab", 2);
  memcpy(m.b + F_FILE, in_file, sizeof(in_file));
  memcpy(m.b + F_SNAME, in_sname, sizeof(in_sname));
  to_client(&m);
  ASSERT_EQ(opt_calls, 1);
  ASSERT_EQ(opt_len, 6);
  ASSERT_MEM_EQ(opt_value, "abcdef", 6);
}

/* REQ-DHCPv4-053: a split option longer than a handler can be given (255
 * bytes) is not given in pieces: not at all */
TEST(itest_dhcpv4_053_split_option_too_long_not_delivered) {
  static uint8_t part[200];
  dmsg_t m;
  opt_calls = 0;
  memset(part, 'x', sizeof(part));
  client_up(&private_table);
  offer();
  ack_begin(&m);
  dopt32(&m, O_LEASE, LEASE);
  dopt(&m, O_PRIVATE, part, 200);
  dopt(&m, O_PRIVATE, part, 100);
  to_client(&m);
  dhcpv4_client_tick(&t.net, &cli, PROBED_MS);
  ASSERT_EQ(dhcpv4_client_state(&cli), DHCPV4_CLI_BOUND);
  ASSERT_EQ(opt_calls, 0);
}

/* REQ-DHCPv4-088: T1 after T2 breaks the order RFC 2131 §4.4.5 requires:
 * the client takes the defaults, and renews — unicast — at 0.5 × lease */
TEST(itest_dhcpv4_088_t1_after_t2_replaced_by_defaults) {
  dsent_t d;
  uint32_t s;
  bound(LEASE, 3000, 2000);
  s = secs_to_next(LEASE, &d);
  ASSERT_EQ(d.type, M_REQUEST);
  ASSERT_EQ(d.ip.dst, SERVER_IP);
  ASSERT_TRUE(near_fuzzed(lease_s(s), 1800));
}

/* REQ-DHCPv4-088: T2 at or past the end of the lease: the defaults — the
 * renewal at 0.5 × lease, and rebinding, broadcast, at 0.875 × lease */
TEST(itest_dhcpv4_088_t2_past_lease_replaced_by_defaults) {
  dsent_t d;
  uint32_t s, total;
  bound(LEASE, 1000, 4000);
  s = secs_to_next(LEASE, &d);
  ASSERT_EQ(d.ip.dst, SERVER_IP);
  total = lease_s(s);
  ASSERT_TRUE(near_fuzzed(total, 1800));
  do {
    s = secs_to_next(LEASE, &d);
    total += s;
  } while (s && d.type == M_REQUEST && d.ip.dst == SERVER_IP);
  ASSERT_EQ(d.type, M_REQUEST);
  ASSERT_EQ(d.ip.dst, 0xFFFFFFFFu);
  ASSERT_TRUE(near_fuzzed(total, 3150));
}

/* REQ-DHCPv4-091: the REQUEST for an offer has the DISCOVER's 'secs' and
 * goes to the same broadcast address — retransmitted too */
TEST(itest_dhcpv4_091_request_has_the_discovers_secs_and_destination) {
  dsent_t disc, req;
  client_up(NULL);
  ASSERT_TRUE(dfind(M_DISCOVER, &disc) >= 0);
  offer();
  ASSERT_TRUE(dfind(M_REQUEST, &req) >= 0);
  ASSERT_EQ(peer_get16(req.m + F_SECS), peer_get16(disc.m + F_SECS));
  ASSERT_EQ(req.ip.dst, disc.ip.dst);
  ASSERT_EQ(req.ip.dst, 0xFFFFFFFFu);
  ASSERT_TRUE(secs_to_next(10, &req) > 0);
  ASSERT_EQ(req.type, M_REQUEST);
  ASSERT_EQ(peer_get16(req.m + F_SECS), peer_get16(disc.m + F_SECS));
  ASSERT_EQ(req.ip.dst, 0xFFFFFFFFu);
}

/* REQ-DHCPv4-092: the reserved flag bits are zero in every message */
TEST(itest_dhcpv4_092_reserved_flag_bits_zero) {
  dsent_t d;
  client_up(NULL);
  ASSERT_TRUE(dfind(M_DISCOVER, &d) >= 0);
  ASSERT_TRUE(flags_reserved_zero(&d));
  wire_clear(&t);
  offer();
  ASSERT_TRUE(dfind(M_REQUEST, &d) >= 0);
  ASSERT_TRUE(flags_reserved_zero(&d));
  ack(LEASE, 0, 0);
  dhcpv4_client_tick(&t.net, &cli, PROBED_MS);
  ASSERT_TRUE(secs_to_next(LEASE, &d) > 0); /* renewing */
  ASSERT_TRUE(flags_reserved_zero(&d));
  while (secs_to_next(LEASE, &d) && d.ip.dst == SERVER_IP)
    ;
  ASSERT_EQ(d.ip.dst, 0xFFFFFFFFu); /* rebinding */
  ASSERT_TRUE(flags_reserved_zero(&d));
  wire_clear(&t);
  dhcpv4_client_release(&t.net, &cli);
  ASSERT_TRUE(dfind(M_RELEASE, &d) >= 0);
  ASSERT_TRUE(flags_reserved_zero(&d));
}

/* REQ-DHCPv4-093: requests to the server go to the address of its Server
 * Identifier — not to the source of its ACK, a relay agent here — at the
 * MAC the ACK came from */
TEST(itest_dhcpv4_093_unicast_to_the_server_identifier) {
  dmsg_t m;
  dsent_t d;
  client_up(NULL);
  reply_begin(&m, M_OFFER, OFFERED);
  dopt32(&m, O_SERVER, REMOTE_IP);
  dopt32(&m, O_LEASE, LEASE);
  to_client_from(&m, RELAY_IP, relay_mac);
  reply_begin(&m, M_ACK, OFFERED);
  dopt32(&m, O_SERVER, REMOTE_IP);
  dopt32(&m, O_LEASE, LEASE);
  dopt32(&m, O_MASK, MASK);
  dopt32(&m, O_ROUTER, RELAY_IP);
  to_client_from(&m, RELAY_IP, relay_mac);
  dhcpv4_client_tick(&t.net, &cli, PROBED_MS);
  ASSERT_TRUE(secs_to_next(LEASE, &d) > 0);
  ASSERT_EQ(d.type, M_REQUEST);
  ASSERT_EQ(d.ip.dst, REMOTE_IP);
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, relay_mac, 6);
  wire_clear(&t);
  dhcpv4_client_release(&t.net, &cli);
  ASSERT_TRUE(dfind(M_RELEASE, &d) >= 0);
  ASSERT_EQ(d.ip.dst, REMOTE_IP);
  ASSERT_EQ(dget32(&d, O_SERVER), REMOTE_IP);
}

/* REQ-DHCPv4-094: no DISCOVER names a server — nor one after a NAK, when
 * the client has known one */
TEST(itest_dhcpv4_094_discover_names_no_server) {
  dmsg_t m;
  dsent_t d;
  client_up(NULL);
  ASSERT_TRUE(dfind(M_DISCOVER, &d) >= 0);
  ASSERT_FALSE(dhas(&d, O_SERVER));
  offer();
  wire_clear(&t);
  reply_begin(&m, M_NAK, 0);
  dopt32(&m, O_SERVER, SERVER_IP);
  to_client(&m);
  ASSERT_TRUE(dfind(M_DISCOVER, &d) >= 0);
  ASSERT_FALSE(dhas(&d, O_SERVER));
}

/* REQ-DHCPv4-095, 040: a RELEASE names the server and nothing else — no
 * Requested IP Address, no lease time, no Parameter Request List; the
 * address in ciaddr, flags 0 (RFC 2131 Table 5) */
TEST(itest_dhcpv4_095_release_names_only_the_server) {
  dsent_t d;
  uint8_t codes[16], n;
  bound(LEASE, 0, 0);
  dhcpv4_client_release(&t.net, &cli);
  ASSERT_TRUE(dfind(M_RELEASE, &d) >= 0);
  n = dcodes(&d, codes, sizeof(codes));
  ASSERT_EQ(n, 2);
  ASSERT_EQ(dget32(&d, O_SERVER), SERVER_IP);
  ASSERT_FALSE(dhas(&d, O_REQ_IP));
  ASSERT_EQ(peer_get32(d.m + F_CIADDR), OFFERED);
  ASSERT_EQ(peer_get16(d.m + F_FLAGS), 0);
  ASSERT_EQ(d.ip.dst, SERVER_IP);
}

/* REQ-DHCPv4-023, 024: the REQUEST for an offer names the server and the
 * address; renewing and rebinding ones name neither — the address is in
 * ciaddr (RFC 2131 §4.3.2, Table 4) */
TEST(itest_dhcpv4_024_only_the_selecting_request_names_the_address) {
  dsent_t d;
  client_up(NULL);
  offer();
  ASSERT_TRUE(dfind(M_REQUEST, &d) >= 0);
  ASSERT_EQ(dget32(&d, O_SERVER), SERVER_IP);
  ASSERT_EQ(dget32(&d, O_REQ_IP), OFFERED);
  ASSERT_EQ(peer_get32(d.m + F_CIADDR), 0u);
  ack(LEASE, 0, 0);
  dhcpv4_client_tick(&t.net, &cli, PROBED_MS);
  ASSERT_TRUE(secs_to_next(LEASE, &d) > 0);
  ASSERT_EQ(d.ip.dst, SERVER_IP); /* renewing */
  ASSERT_FALSE(dhas(&d, O_SERVER));
  ASSERT_FALSE(dhas(&d, O_REQ_IP));
  ASSERT_EQ(peer_get32(d.m + F_CIADDR), OFFERED);
  while (secs_to_next(LEASE, &d) && d.ip.dst == SERVER_IP)
    ;
  ASSERT_EQ(d.ip.dst, 0xFFFFFFFFu); /* rebinding */
  ASSERT_FALSE(dhas(&d, O_SERVER));
  ASSERT_FALSE(dhas(&d, O_REQ_IP));
  ASSERT_EQ(peer_get32(d.m + F_CIADDR), OFFERED);
}

/* Milliseconds, a millisecond at a time, until the client sends again */
static uint32_t ms_to_next(uint32_t limit_ms) {
  uint32_t ms;
  wire_clear(&t);
  for (ms = 1; ms <= limit_ms; ms++) {
    dhcpv4_client_tick(&t.net, &cli, 1);
    if (t.wire.tx_count)
      return ms;
  }
  return 0;
}

/* REQ-DHCPv4-045, 046: the DISCOVER is retransmitted after 4, 8, 16, 32,
 * 64 and 64 s, each randomized by a uniform ±1 s — differently by clients
 * seeded differently */
TEST(itest_dhcpv4_046_randomized_exponential_backoff) {
  static const uint32_t base_s[] = {4, 8, 16, 32, 64, 64};
  uint32_t first[4];
  uint8_t k, i, distinct = 0;
  for (k = 0; k < 4; k++) {
    itest_up(&t, 1514, 1514);
    t.net.ipv4_addr = 0;
    net_random_seed(&t.net, &k, 1);
    udp_set_ports(&t.net, client_ports, 1);
    dhcpv4_client_init(&cli, &t.net, NULL, NULL, NULL);
    dhcpv4_client_start(&t.net, &cli);
    dhcpv4_client_tick(&t.net, &cli, DHCPV4_START_DELAY_MAX_MS);
    for (i = 0; i < 6; i++) {
      uint32_t ms = ms_to_next(70000);
      if (i == 0)
        first[k] = ms;
      ASSERT_TRUE(ms >= base_s[i] * 1000u - 1000u);
      ASSERT_TRUE(ms <= base_s[i] * 1000u + 1000u);
    }
  }
  for (k = 1; k < 4; k++)
    distinct += first[k] != first[0];
  ASSERT_TRUE(distinct > 0);
}

/* ── The server ── */

#define SRV_XID 0x5EED1234u
#define OTHER_SERVER 0x0A00004Du /* 10.0.0.77 */
#define OTHER_ADDR 0x0A000078u   /* 10.0.0.120 */

static const uint8_t mac_a[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0A};
static const uint8_t mac_b[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0B};

static dhcpv4_server_t srv;
static dhcpv4_server_cfg_t cfg;
static uint8_t srv_events[16];
static uint8_t n_srv_events;

static void on_server_event(uint8_t event, void *ctx) {
  (void)ctx;
  if (n_srv_events < sizeof(srv_events))
    srv_events[n_srv_events++] = event;
}

static void on_67(net_t *net, uint32_t src_ip, uint16_t src_port,
                  const uint8_t *src_mac, const uint8_t *data, uint16_t len) {
  (void)src_port;
  dhcpv4_server_input(net, &srv, src_ip, src_mac, data, len);
}

static const udp_port_entry_t server_ports[] = {{67, on_67}};

/* A server at our address offering OFFERED, with a router and DNS server
 * when not 0 */
static void server_up(uint32_t gateway, uint32_t dns) {
  itest_up(&t, 1514, 1514);
  udp_set_ports(&t.net, server_ports, 1);
  memset(&cfg, 0, sizeof(cfg));
  cfg.server_ip = t.net.ipv4_addr;
  cfg.offered_ip = OFFERED;
  cfg.subnet_mask = MASK;
  cfg.gateway = gateway;
  cfg.dns = dns;
  cfg.lease_time_s = LEASE;
  n_srv_events = 0;
  dhcpv4_server_init(&srv, &t.net, &cfg, on_server_event, NULL);
}

/* A client message from @p mac, broadcast flag set */
static void client_begin(dmsg_t *m, uint8_t type, const uint8_t *mac) {
  dbegin(m, BOOTREQUEST, type, SRV_XID, mac);
  peer_put16(m->b + F_FLAGS, 0x8000);
}

/* Sent from @p mac: from ciaddr to the server if it is set (renewing),
 * else broadcast from 0.0.0.0; the wire cleared first */
static void to_server(dmsg_t *m, const uint8_t *mac) {
  static uint8_t f[1200], seg[1100];
  uint32_t ciaddr = peer_get32(m->b + F_CIADDR);
  peer_ip_t ip = peer_ip(ciaddr, ciaddr ? cfg.server_ip : 0xFFFFFFFFu, 17);
  uint16_t n = peer_udp(seg, &ip, 68, 67, m->b, dfinish(m));
  wire_clear(&t);
  itest_receive(
      &t, f,
      peer_ipv4_frame(f, ciaddr ? t.net.mac : broadcast_mac, mac, &ip, seg, n));
}

static void discover(const uint8_t *mac) {
  dmsg_t m;
  client_begin(&m, M_DISCOVER, mac);
  to_server(&m, mac);
}

/* A REQUEST for @p addr: selecting @p server if not 0, else INIT-REBOOT */
static void request(const uint8_t *mac, uint32_t server, uint32_t addr) {
  dmsg_t m;
  client_begin(&m, M_REQUEST, mac);
  if (server)
    dopt32(&m, O_SERVER, server);
  dopt32(&m, O_REQ_IP, addr);
  to_server(&m, mac);
}

/* The server's answer, if it sent one: its type, else 0 */
static uint8_t answer(dsent_t *d) {
  return t.wire.tx_count == 1 && dparse(0, d) ? d->type : 0;
}

/* REQ-DHCPv4-085: a DECLINE of the address — another host uses it: the
 * server offers it to no one again, until the application initialises it
 * again */
TEST(itest_dhcpv4_085_declined_address_offered_no_more) {
  dmsg_t m;
  dsent_t d;
  server_up(0, 0);
  discover(mac_a);
  ASSERT_EQ(answer(&d), M_OFFER);
  request(mac_a, cfg.server_ip, OFFERED);
  ASSERT_EQ(answer(&d), M_ACK);
  client_begin(&m, M_DECLINE, mac_a);
  peer_put16(m.b + F_FLAGS, 0);
  dopt32(&m, O_REQ_IP, OFFERED);
  dopt32(&m, O_SERVER, cfg.server_ip);
  to_server(&m, mac_a);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(srv_events[n_srv_events - 1], DHCPV4_SRV_EVT_DECLINE);
  ASSERT_TRUE(srv.declined);
  discover(mac_a);
  ASSERT_EQ(t.wire.tx_count, 0);
  discover(mac_b);
  ASSERT_EQ(t.wire.tx_count, 0);
  request(mac_a, cfg.server_ip, OFFERED);
  ASSERT_NE(answer(&d), M_ACK);

  dhcpv4_server_init(&srv, &t.net, &cfg, on_server_event, NULL);
  discover(mac_b);
  ASSERT_EQ(answer(&d), M_OFFER);
}

/* REQ-DHCPv4-086, 060: a REQUEST that selects another server declines our
 * offer: no NAK, no ACK — and the address is free for another client */
TEST(itest_dhcpv4_086_request_for_another_server_unanswered) {
  dsent_t d;
  server_up(0, 0);
  discover(mac_a);
  ASSERT_EQ(answer(&d), M_OFFER);
  request(mac_a, OTHER_SERVER, OTHER_ADDR);
  ASSERT_EQ(t.wire.tx_count, 0);
  request(mac_a, OTHER_SERVER, OFFERED);
  ASSERT_EQ(t.wire.tx_count, 0);
  discover(mac_b);
  ASSERT_EQ(answer(&d), M_OFFER);
}

/* REQ-DHCPv4-087: an INIT-REBOOT client the server has no record of is
 * not answered, whatever it asks for; its own client is — NAKed for an
 * address not its own (RFC 2131 §4.3.2) */
TEST(itest_dhcpv4_087_unknown_init_reboot_client_unanswered) {
  dsent_t d;
  server_up(0, 0);
  request(mac_b, 0, OTHER_ADDR);
  ASSERT_EQ(t.wire.tx_count, 0);
  request(mac_b, 0, OFFERED);
  ASSERT_EQ(t.wire.tx_count, 0);
  discover(mac_a);
  ASSERT_EQ(answer(&d), M_OFFER);
  request(mac_b, 0, OFFERED);
  ASSERT_EQ(t.wire.tx_count, 0);
  request(mac_a, 0, OTHER_ADDR);
  ASSERT_EQ(answer(&d), M_NAK);
  request(mac_a, 0, OFFERED);
  ASSERT_EQ(answer(&d), M_ACK);
}

/* REQ-DHCPv4-060, 070: the address goes to one client, known by its
 * chaddr: a second gets no offer, and a NAK if it asks for the address,
 * until the first releases it */
TEST(itest_dhcpv4_060_address_kept_for_its_client) {
  dmsg_t m;
  dsent_t d;
  server_up(0, 0);
  discover(mac_a);
  ASSERT_EQ(answer(&d), M_OFFER);
  ASSERT_EQ(peer_get32(d.m + F_YIADDR), OFFERED);
  discover(mac_b);
  ASSERT_EQ(t.wire.tx_count, 0);
  request(mac_b, cfg.server_ip, OFFERED);
  ASSERT_EQ(answer(&d), M_NAK);
  request(mac_a, cfg.server_ip, OFFERED);
  ASSERT_EQ(answer(&d), M_ACK);
  discover(mac_a); /* its own address again */
  ASSERT_EQ(answer(&d), M_OFFER);
  dbegin(&m, BOOTREQUEST, M_RELEASE, SRV_XID, mac_a);
  peer_put32(m.b + F_CIADDR, OFFERED);
  dopt32(&m, O_SERVER, cfg.server_ip);
  to_server(&m, mac_a);
  ASSERT_EQ(t.wire.tx_count, 0);
  discover(mac_b);
  ASSERT_EQ(answer(&d), M_OFFER);
  ASSERT_EQ(peer_get32(d.m + F_YIADDR), OFFERED);
}

/* REQ-DHCPv4-090, 098: requested options in the order requested — the
 * Subnet Mask still before the Router */
TEST(itest_dhcpv4_090_options_in_the_order_requested) {
  static const uint8_t prl1[] = {O_DNS, O_ROUTER, O_MASK};
  static const uint8_t prl2[] = {O_ROUTER, O_DNS, O_MASK};
  dmsg_t m;
  dsent_t d;
  uint8_t codes[16], n;
  server_up(0x0A000002u, 0x0A000002u);
  client_begin(&m, M_DISCOVER, mac_a);
  dopt(&m, O_PRL, prl1, sizeof(prl1));
  to_server(&m, mac_a);
  ASSERT_EQ(answer(&d), M_OFFER);
  n = dcodes(&d, codes, sizeof(codes));
  ASSERT_TRUE(at(codes, n, O_DNS) >= 0);
  ASSERT_TRUE(at(codes, n, O_DNS) < at(codes, n, O_MASK));
  ASSERT_TRUE(at(codes, n, O_MASK) < at(codes, n, O_ROUTER));

  client_begin(&m, M_REQUEST, mac_a);
  dopt32(&m, O_SERVER, cfg.server_ip);
  dopt32(&m, O_REQ_IP, OFFERED);
  dopt(&m, O_PRL, prl2, sizeof(prl2));
  to_server(&m, mac_a);
  ASSERT_EQ(answer(&d), M_ACK);
  n = dcodes(&d, codes, sizeof(codes));
  ASSERT_TRUE(at(codes, n, O_MASK) >= 0);
  ASSERT_TRUE(at(codes, n, O_MASK) < at(codes, n, O_ROUTER));
  ASSERT_TRUE(at(codes, n, O_ROUTER) < at(codes, n, O_DNS));
}

/* REQ-DHCPv4-096: OFFER and ACK carry the Server Identifier and the lease
 * time, and never a Requested IP Address, Parameter Request List, Client
 * Identifier or Maximum Message Size, though the request had them */
TEST(itest_dhcpv4_096_offer_and_ack_options) {
  static const uint8_t prl[] = {O_MASK, O_ROUTER};
  static const uint8_t id[] = {1, 2, 0, 0, 0, 0, 0, 0x0A};
  static const uint8_t max_size[] = {0x05, 0xDC};
  static const uint8_t types[] = {M_DISCOVER, M_REQUEST};
  dmsg_t m;
  dsent_t d;
  uint8_t i;
  server_up(0x0A000002u, 0);
  for (i = 0; i < 2; i++) {
    client_begin(&m, types[i], mac_a);
    if (types[i] == M_REQUEST)
      dopt32(&m, O_SERVER, cfg.server_ip);
    dopt32(&m, O_REQ_IP, OFFERED);
    dopt32(&m, O_LEASE, 60);
    dopt(&m, O_PRL, prl, sizeof(prl));
    dopt(&m, O_CLIENT_ID, id, sizeof(id));
    dopt(&m, O_MAX_SIZE, max_size, sizeof(max_size));
    to_server(&m, mac_a);
    ASSERT_EQ(answer(&d), i == 0 ? M_OFFER : M_ACK);
    ASSERT_EQ(dget32(&d, O_SERVER), cfg.server_ip);
    ASSERT_EQ(dget32(&d, O_LEASE), LEASE);
    ASSERT_FALSE(dhas(&d, O_REQ_IP));
    ASSERT_FALSE(dhas(&d, O_PRL));
    ASSERT_FALSE(dhas(&d, O_CLIENT_ID));
    ASSERT_FALSE(dhas(&d, O_MAX_SIZE));
  }
}

/* REQ-DHCPv4-097: each requested parameter once; one the server has no
 * value for — no DNS server configured, an option it does not know — left
 * out */
TEST(itest_dhcpv4_097_requested_parameters_once_or_not_at_all) {
  static const uint8_t prl[] = {O_ROUTER, O_ROUTER, O_MASK,
                                O_DNS,    O_NTP,    O_MASK};
  dmsg_t m;
  dsent_t d;
  uint8_t codes[16], n;
  server_up(0x0A000002u, 0);
  client_begin(&m, M_DISCOVER, mac_a);
  dopt(&m, O_PRL, prl, sizeof(prl));
  to_server(&m, mac_a);
  ASSERT_EQ(answer(&d), M_OFFER);
  n = dcodes(&d, codes, sizeof(codes));
  ASSERT_EQ(count_of(codes, n, O_ROUTER), 1);
  ASSERT_EQ(count_of(codes, n, O_MASK), 1);
  ASSERT_EQ(count_of(codes, n, O_DNS), 0);
  ASSERT_EQ(count_of(codes, n, O_NTP), 0);
}

/* REQ-DHCPv4-098: with no Parameter Request List, the Subnet Mask still
 * comes before the Router (RFC 2132 §3.3) */
TEST(itest_dhcpv4_098_subnet_mask_before_router) {
  dsent_t d;
  uint8_t codes[16], n;
  server_up(0x0A000002u, 0x0A000002u);
  discover(mac_a);
  ASSERT_EQ(answer(&d), M_OFFER);
  n = dcodes(&d, codes, sizeof(codes));
  ASSERT_TRUE(at(codes, n, O_MASK) >= 0);
  ASSERT_TRUE(at(codes, n, O_MASK) < at(codes, n, O_ROUTER));
}

/* REQ-DHCPv4-099: vendor-specific information and a vendor class the
 * server cannot interpret are ignored: the same OFFER as without them */
TEST(itest_dhcpv4_099_vendor_information_ignored) {
  static uint8_t plain[600];
  static const uint8_t vendor[] = {1, 2, 0xAB, 0xCD};
  dmsg_t m;
  dsent_t d;
  uint16_t len;
  server_up(0x0A000002u, 0x0A000002u);
  discover(mac_a);
  ASSERT_EQ(answer(&d), M_OFFER);
  len = d.len;
  memcpy(plain, d.m, len);
  client_begin(&m, M_DISCOVER, mac_a);
  dopt(&m, O_VENDOR, vendor, sizeof(vendor));
  dopt(&m, O_CLASS, "acme-widget", 11);
  to_server(&m, mac_a);
  ASSERT_EQ(answer(&d), M_OFFER);
  ASSERT_EQ(d.len, len);
  ASSERT_MEM_EQ(d.m, plain, len);
}

/* REQ-DHCPv4-100: the Server Identifier is the server's address on the
 * client's link — the source of its replies, on the subnet it offers */
TEST(itest_dhcpv4_100_server_identifier_reachable) {
  dsent_t d;
  server_up(0, 0);
  discover(mac_a);
  ASSERT_EQ(answer(&d), M_OFFER);
  ASSERT_EQ(dget32(&d, O_SERVER), cfg.server_ip);
  ASSERT_EQ(d.ip.src, cfg.server_ip);
  ASSERT_EQ(cfg.server_ip & MASK, peer_get32(d.m + F_YIADDR) & MASK);
}

/* REQ-DHCPv4-071: the ACK to a DHCPINFORM carries no lease time and
 * assigns no address; it goes to the client's own (ciaddr) */
TEST(itest_dhcpv4_071_inform_answered_without_a_lease) {
  dmsg_t m;
  dsent_t d;
  server_up(0x0A000002u, 0);
  dbegin(&m, BOOTREQUEST, M_INFORM, SRV_XID, mac_b);
  peer_put32(m.b + F_CIADDR, OTHER_ADDR);
  to_server(&m, mac_b);
  ASSERT_EQ(answer(&d), M_ACK);
  ASSERT_FALSE(dhas(&d, O_LEASE));
  ASSERT_EQ(peer_get32(d.m + F_YIADDR), 0u);
  ASSERT_EQ(peer_get32(d.m + F_CIADDR), OTHER_ADDR);
  ASSERT_EQ(d.ip.dst, OTHER_ADDR);
  ASSERT_EQ(dget32(&d, O_MASK), MASK);
}

int main(void) {
  fprintf(stderr, "=== itest_dhcpv4 ===\n");
  RUN_TEST(itest_dhcpv4_081_ack_probed_before_use);
  RUN_TEST(itest_dhcpv4_080_address_in_use_declined);
  RUN_TEST(itest_dhcpv4_080_other_probe_or_request_conflicts);
  RUN_TEST(itest_dhcpv4_039_release_while_probing);
  RUN_TEST(itest_dhcpv4_020_offer_without_server_id_dropped);
  RUN_TEST(itest_dhcpv4_084_options_in_file_and_sname);
  RUN_TEST(itest_dhcpv4_084_sname_unread_unless_overloaded);
  RUN_TEST(itest_dhcpv4_089_split_options_joined);
  RUN_TEST(itest_dhcpv4_089_split_across_fields_in_order);
  RUN_TEST(itest_dhcpv4_053_split_option_too_long_not_delivered);
  RUN_TEST(itest_dhcpv4_088_t1_after_t2_replaced_by_defaults);
  RUN_TEST(itest_dhcpv4_088_t2_past_lease_replaced_by_defaults);
  RUN_TEST(itest_dhcpv4_091_request_has_the_discovers_secs_and_destination);
  RUN_TEST(itest_dhcpv4_092_reserved_flag_bits_zero);
  RUN_TEST(itest_dhcpv4_093_unicast_to_the_server_identifier);
  RUN_TEST(itest_dhcpv4_094_discover_names_no_server);
  RUN_TEST(itest_dhcpv4_095_release_names_only_the_server);
  RUN_TEST(itest_dhcpv4_024_only_the_selecting_request_names_the_address);
  RUN_TEST(itest_dhcpv4_046_randomized_exponential_backoff);
  RUN_TEST(itest_dhcpv4_085_declined_address_offered_no_more);
  RUN_TEST(itest_dhcpv4_086_request_for_another_server_unanswered);
  RUN_TEST(itest_dhcpv4_087_unknown_init_reboot_client_unanswered);
  RUN_TEST(itest_dhcpv4_060_address_kept_for_its_client);
  RUN_TEST(itest_dhcpv4_090_options_in_the_order_requested);
  RUN_TEST(itest_dhcpv4_096_offer_and_ack_options);
  RUN_TEST(itest_dhcpv4_097_requested_parameters_once_or_not_at_all);
  RUN_TEST(itest_dhcpv4_098_subnet_mask_before_router);
  RUN_TEST(itest_dhcpv4_099_vendor_information_ignored);
  RUN_TEST(itest_dhcpv4_100_server_identifier_reachable);
  RUN_TEST(itest_dhcpv4_071_inform_answered_without_a_lease);
  ITEST_REPORT();
  return test_failures;
}
