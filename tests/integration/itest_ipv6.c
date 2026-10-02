/**
 * @file itest_ipv6.c
 * @brief IPv6 and ICMPv6, black box: packets on the wire, a UDP port and a
 *        TCP connection the test registers, and what the stack sends back.
 */

#include "icmpv6.h"
#include "ipv6.h"
#include "itest.h"
#include "ndp.h"
#include "tcp.h"
#include "tcp_buf.h"
#include "udp.h"
#include <string.h>

#define OPEN_PORT 7000
#define CLOSED_PORT 7001
#define TCP_PORT 80
#define PEER_PORT 5000

#define NH_HOPOPT 0
#define NH_TCP 6
#define NH_UDP 17
#define NH_ROUTING 43
#define NH_FRAGMENT 44
#define NH_ICMPV6 58
#define NH_DSTOPTS 60

#define T_DEST_UNREACH 1
#define T_TOO_BIG 2
#define T_TIME_EXCEEDED 3
#define T_PARAM_PROBLEM 4
#define T_ECHO_REQUEST 128
#define T_ECHO_REPLY 129
#define T_MLD_V2_REPORT 143

static itest_t t;
/* Our link-local address, the global one in the router's prefix, and the
 * link-local address's solicited-node group */
static uint8_t ll[16], global[16], sn[16];

static int delivered;
static uint8_t got[2048];
static uint16_t got_len;
static const uint8_t *got_ptr;

static void on_datagram6(net_t *net, const uint8_t *src_ip, uint16_t src_port,
                         const uint8_t *src_mac, const uint8_t *data,
                         uint16_t len) {
  (void)net;
  (void)src_ip;
  (void)src_port;
  (void)src_mac;
  delivered++;
  got_ptr = data;
  got_len = len < sizeof(got) ? len : (uint16_t)sizeof(got);
  memcpy(got, data, got_len);
}

static const udp6_port_entry_t ports6[] = {{OPEN_PORT, on_datagram6}};

static tcp_conn_t conn;
static tcp_conn_t *table[1] = {&conn};
static tcp_saw_tx_ctx_t tx_ctx;
static tcp_saw_rx_ctx_t rx_ctx;
static uint8_t tx_mem[1460], rx_mem[512];

/* Started on frame buffers of @p rx and @p tx bytes: the link-local
 * address past DAD, the router solicitations over */
static void up_bufs(uint16_t rx, uint16_t tx) {
  itest_up(&t, rx, tx);
  udp6_set_ports(&t.net, ports6, 1);
  tcp_saw_tx_init(&tx_ctx, tx_mem, sizeof(tx_mem));
  tcp_saw_rx_init(&rx_ctx, rx_mem, sizeof(rx_mem));
  tcp_conn_init(&conn, &tcp_saw_tx_ops, &tx_ctx, &tcp_saw_rx_ops, &rx_ctx,
                NULL);
  tcp_set_connections(&t.net, table, 1);
  peer_link_local(t.net.mac, ll);
  memcpy(global, prefix6, 8);
  memcpy(global + 8, ll + 8, 8);
  peer_solicited_node(ll, sn);
  ipv6_start(&t.net);
  itest_advance(&t, 15000, 100);
  delivered = 0;
  got_ptr = NULL;
  wire_clear(&t);
}

static void up(void) { up_bufs(1514, 1514); }

/* ... and the global address, configured statically and past DAD */
static void up_global(void) {
  up();
  ipv6_addr_add(&t.net, global, NET_IP6_INFINITE, NET_IP6_INFINITE);
  itest_advance(&t, 3000, 100);
  wire_clear(&t);
}

/* ── The peer's packets ── */

/* Our MAC for a unicast destination, the group's for a multicast one */
static void mac_for(const uint8_t *dst, uint8_t mac[6]) {
  if (dst[0] == 0xFF)
    peer_mcast6_mac(dst, mac);
  else
    memcpy(mac, t.net.mac, 6);
}

/* An IPv6 packet as @p ip describes it, to @p mac (NULL: as mac_for()) */
static void deliver(const uint8_t *mac, const peer_ip6_t *ip,
                    const void *payload, uint16_t len) {
  static uint8_t f[WIRE_FRAME_MAX];
  uint8_t m[6];
  if (!mac) {
    mac_for(ip->dst, m);
    mac = m;
  }
  itest_receive(&t, f, peer_ipv6_frame(f, mac, peer_mac, ip, payload, len));
}

static const uint8_t id_seq[4] = {0x12, 0x34, 0x00, 0x07};

/* An Echo Request (identifier 0x1234, sequence 7) from @p src to @p dst */
static void echo(const uint8_t *src, const uint8_t *dst, const void *data,
                 uint16_t len) {
  static uint8_t msg[WIRE_FRAME_MAX];
  peer_ip6_t ip = peer_ip6(src, dst, NH_ICMPV6);
  uint16_t n = peer_icmp6(msg, &ip, T_ECHO_REQUEST, 0, id_seq, data, len);
  deliver(NULL, &ip, msg, n);
}

/* A UDP datagram from @p src:PEER_PORT to @p dst:@p port */
static void datagram(const uint8_t *src, const uint8_t *dst, uint16_t port,
                     const void *data, uint16_t len) {
  static uint8_t seg[WIRE_FRAME_MAX];
  peer_ip6_t ip = peer_ip6(src, dst, NH_UDP);
  uint16_t n = peer_udp6(seg, &ip, PEER_PORT, port, data, len);
  deliver(NULL, &ip, seg, n);
}

/* The first ICMPv6 message of @p type sent since wire_clear() */
static int sent(uint8_t type, peer_ip6_t *ip, peer_icmp_t *icmp) {
  return wire_find_icmp6(&t, 0, type, ip, icmp) >= 0;
}

/* An extension header of 8 bytes: next header, length 0, a PadN option of
 * 4 bytes (or, for a Routing header, type 253 and @p segments_left) */
static void ext_header(uint8_t *h, uint8_t this_type, uint8_t next,
                       uint8_t segments_left) {
  memset(h, 0, 8);
  h[0] = next;
  if (this_type == NH_ROUTING) {
    h[2] = 253; /* a routing type a host does not process (experimental) */
    h[3] = segments_left;
  } else {
    h[2] = 1; /* PadN */
    h[3] = 4;
  }
}

/* ── Header checks and the payload length ── */

/* REQ-IPv6-001, 004: a header whose version is not 6 is dropped */
TEST(itest_ipv6_001_version_checked) {
  static uint8_t f[256], msg[64];
  peer_ip6_t ip;
  uint16_t n, len;
  up();
  ip = peer_ip6(peer6_ll, ll, NH_ICMPV6);
  n = peer_icmp6(msg, &ip, T_ECHO_REQUEST, 0, id_seq, "v", 1);
  len = peer_ipv6_frame(f, t.net.mac, peer_mac, &ip, msg, n);
  f[14] = 0x40;
  itest_receive(&t, f, len);
  f[14] = 0x50;
  itest_receive(&t, f, len);
  ASSERT_EQ(t.wire.tx_count, 0);
  f[14] = 0x60;
  itest_receive(&t, f, len);
  ASSERT_EQ(wire_count_icmp6(&t, T_ECHO_REPLY), 1);
}

/* REQ-IPv6-002, 004: a Payload Length beyond the frame, or a frame cut
 * short, is dropped */
TEST(itest_ipv6_002_payload_length_checked) {
  static uint8_t f[256], msg[64];
  peer_ip6_t ip;
  uint16_t n, len;
  up();
  ip = peer_ip6(peer6_ll, ll, NH_ICMPV6);
  n = peer_icmp6(msg, &ip, T_ECHO_REQUEST, 0, id_seq, "abcd", 4);
  len = peer_ipv6_frame(f, t.net.mac, peer_mac, &ip, msg, n);
  peer_put16(f + 18, (uint16_t)(n + 1)); /* one byte more than sent */
  itest_receive(&t, f, len);
  peer_put16(f + 18, n);
  itest_receive(&t, f, (uint16_t)(len - 1)); /* the frame cut short */
  itest_receive(&t, f, 14 + 39);             /* not even a header */
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-IPv6-003: the Payload Length, not the frame, bounds the payload —
 * bytes after it are link padding */
TEST(itest_ipv6_003_payload_length_bounds_the_payload) {
  static uint8_t f[256], msg[64];
  peer_ip6_t ip, rip;
  peer_icmp_t icmp;
  uint16_t n, len;
  up();
  ip = peer_ip6(peer6_ll, ll, NH_ICMPV6);
  n = peer_icmp6(msg, &ip, T_ECHO_REQUEST, 0, id_seq, "pad", 3);
  len = peer_ipv6_frame(f, t.net.mac, peer_mac, &ip, msg, n);
  memset(f + len, 0xEE, 20);
  itest_receive(&t, f, (uint16_t)(len + 20));
  ASSERT_TRUE(sent(T_ECHO_REPLY, &rip, &icmp));
  ASSERT_EQ(rip.plen, n);
  ASSERT_EQ(icmp.data_len, 3);
  ASSERT_MEM_EQ(icmp.data, "pad", 3);
  ASSERT_TRUE(icmp.cksum_ok);
}

/* ── Building the header ── */

/* REQ-IPv6-005, 024..029, 031, REQ-ICMPv6-001, 003: version 6, traffic
 * class and flow label 0 (whatever the request had), the Payload Length,
 * the Next Header, Hop Limit 64, the destination; no header checksum —
 * the ICMPv6 checksum covers the pseudo-header */
TEST(itest_ipv6_024_header_built) {
  static uint8_t msg[64];
  peer_ip6_t ip, rip;
  peer_icmp_t icmp;
  const wire_frame_t *f;
  uint16_t n;
  up();
  ip = peer_ip6(peer6_ll, ll, NH_ICMPV6);
  ip.tclass = 0xB8;
  ip.flow = 0x12345;
  n = peer_icmp6(msg, &ip, T_ECHO_REQUEST, 0, id_seq, "hdr", 3);
  deliver(NULL, &ip, msg, n);
  ASSERT_TRUE(sent(T_ECHO_REPLY, &rip, &icmp));
  f = wire_sent(&t, 0);
  ASSERT_EQ(f->data[14] >> 4, 6);
  ASSERT_EQ(rip.tclass, 0);
  ASSERT_EQ(rip.flow, 0);
  ASSERT_EQ(rip.plen, n);
  ASSERT_EQ(f->len, 14 + 40 + n); /* 40 bytes of header, nothing more */
  ASSERT_EQ(rip.nh, NH_ICMPV6);
  ASSERT_EQ(rip.hop_limit, 64);
  ASSERT_MEM_EQ(rip.src, ll, 16);
  ASSERT_MEM_EQ(rip.dst, peer6_ll, 16);
  ASSERT_TRUE(icmp.cksum_ok);
}

/* REQ-IPv6-047, 028, 044, 045: an application's payload, written at
 * UDP6_PAYLOAD_OFFSET of the TX buffer, goes out with the headers built
 * around it — the IPv6 header at offset 14 — and a valid, non-zero
 * checksum over the pseudo-header */
TEST(itest_ipv6_047_built_in_place) {
  peer_ip6_t ip;
  peer_udp_t udp;
  up();
  memcpy(t.net.tx.buf + UDP6_PAYLOAD_OFFSET, "in place", 8);
  ASSERT_EQ(
      udp6_send_inplace(&t.net, peer6_ll, peer_mac, 1234, PEER_PORT, 8, 64),
      NET_OK);
  ASSERT_TRUE(peer_parse_ipv6(wire_sent(&t, 0), &ip));
  ASSERT_EQ(ip.nh, NH_UDP);
  ASSERT_TRUE(peer_parse_udp6(&ip, &udp));
  ASSERT_EQ(wire_sent(&t, 0)->len, UDP6_PAYLOAD_OFFSET + 8);
  ASSERT_EQ(ip.payload - wire_sent(&t, 0)->data, 14 + 40);
  ASSERT_MEM_EQ(udp.data, "in place", 8);
  ASSERT_TRUE(udp.cksum_ok);
  ASSERT_EQ(udp.sport, 1234);
  ASSERT_EQ(udp.dport, PEER_PORT);
}

/* REQ-IPv6-046: a handler's payload points into the received frame */
TEST(itest_ipv6_046_parsed_in_place) {
  up();
  datagram(peer6_ll, ll, OPEN_PORT, "zero copy", 9);
  ASSERT_EQ(delivered, 1);
  ASSERT_TRUE(got_ptr >= t.net.rx.buf &&
              got_ptr + 9 <= t.net.rx.buf + t.net.rx.capacity);
  ASSERT_EQ(got_ptr - t.net.rx.buf, 14 + 40 + 8);
}

/* REQ-IPv6-044, 045: a UDP datagram with a zero or a wrong checksum is
 * dropped; one sent carries a valid checksum */
TEST(itest_ipv6_044_upper_layer_checksums) {
  static uint8_t seg[64];
  peer_ip6_t ip, rip;
  peer_udp_t udp;
  uint16_t n;
  up();
  ip = peer_ip6(peer6_ll, ll, NH_UDP);
  n = peer_udp6(seg, &ip, PEER_PORT, OPEN_PORT, "sum", 3);
  peer_put16(seg + 6, 0);
  deliver(NULL, &ip, seg, n);
  peer_put16(seg + 6, 0x1234);
  deliver(NULL, &ip, seg, n);
  ASSERT_EQ(delivered, 0);
  ASSERT_EQ(t.wire.tx_count, 0);
  n = peer_udp6(seg, &ip, PEER_PORT, OPEN_PORT, "sum", 3);
  deliver(NULL, &ip, seg, n);
  ASSERT_EQ(delivered, 1);
  udp6_send(&t.net, peer6_ll, peer_mac, OPEN_PORT, PEER_PORT,
            (const uint8_t *)"back", 4);
  ASSERT_TRUE(peer_parse_ipv6(wire_sent(&t, 0), &rip));
  ASSERT_TRUE(peer_parse_udp6(&rip, &udp));
  ASSERT_TRUE(udp.cksum_ok);
}

/* ── Destinations and sources ── */

/* REQ-IPv6-006..009, 038: our link-local and global addresses, all-nodes,
 * the solicited-node group and a group the application joined */
TEST(itest_ipv6_006_destinations_accepted) {
  static const uint8_t group[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                    0,    0,    0, 0, 0, 1, 0, 3};
  up_global();
  ASSERT_EQ(ipv6_mcast_join(&t.net, group), NET_OK);
  wire_clear(&t);
  echo(peer6_ll, ll, "a", 1);
  echo(offlink6, global, "b", 1);
  echo(peer6_ll, all_nodes6, "c", 1);
  echo(peer6_ll, sn, "d", 1);
  echo(peer6_ll, group, "e", 1);
  ASSERT_EQ(wire_count_icmp6(&t, T_ECHO_REPLY), 5);
}

/* REQ-IPv6-010, REQ-SLAAC-012: another host's address, a group not
 * joined, a tentative address of ours: dropped */
TEST(itest_ipv6_010_other_destinations_dropped) {
  static const uint8_t other[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                    0,    0,    0, 0, 0, 0, 0, 0x42};
  static const uint8_t group[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                    0,    0,    0, 0, 0, 1, 0, 3};
  peer_ip6_t ip;
  static uint8_t msg[64];
  uint16_t n;
  up();
  echo(peer6_ll, other, "a", 1);
  ip = peer_ip6(peer6_ll, group, NH_ICMPV6);
  n = peer_icmp6(msg, &ip, T_ECHO_REQUEST, 0, id_seq, "b", 1);
  deliver(t.net.mac, &ip, msg, n); /* at our MAC, to a group not ours */
  echo(offlink6, global, "c", 1);  /* not configured */
  ipv6_addr_add(&t.net, global, NET_IP6_INFINITE, NET_IP6_INFINITE);
  echo(offlink6, global, "d", 1); /* tentative */
  datagram(offlink6, global, OPEN_PORT, "e", 1);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(delivered, 0);
}

/* REQ-IPv6-011, REQ-ICMPv6-030: a multicast source is dropped */
TEST(itest_ipv6_011_multicast_source_dropped) {
  static const uint8_t group_src[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                        0,    0,    0, 0, 0, 0, 0, 0x99};
  up();
  echo(group_src, ll, "a", 1);
  datagram(group_src, ll, OPEN_PORT, "b", 1);
  datagram(group_src, ll, CLOSED_PORT, "c", 1);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(delivered, 0);
}

/* REQ-IPv6-012: a packet claiming to come from our own address is
 * dropped */
TEST(itest_ipv6_012_own_source_dropped) {
  up_global();
  echo(ll, ll, "a", 1);
  echo(global, ll, "b", 1);
  datagram(ll, ll, OPEN_PORT, "c", 1);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(delivered, 0);
}

/* REQ-IPv6-013, REQ-ICMPv6-031: a packet from :: is accepted, but nothing
 * is ever sent to :: — no echo reply, no error */
TEST(itest_ipv6_013_unspecified_source) {
  static const uint8_t unspec[16] = {0};
  up();
  datagram(unspec, ll, OPEN_PORT, "a", 1);
  ASSERT_EQ(delivered, 1);
  echo(unspec, ll, "b", 1);
  datagram(unspec, ll, CLOSED_PORT, "c", 1);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-IPv6-014, 015, 016: ICMPv6, UDP and TCP each reach their protocol */
TEST(itest_ipv6_014_upper_layers_dispatched) {
  static uint8_t seg[64];
  peer_tcp_seg_t s;
  peer_ip6_t ip;
  peer_tcp_t tcp;
  int i;
  up();
  echo(peer6_ll, ll, "icmp", 4);
  ASSERT_EQ(wire_count_icmp6(&t, T_ECHO_REPLY), 1);
  datagram(peer6_ll, ll, OPEN_PORT, "udp", 3);
  ASSERT_EQ(delivered, 1);
  ASSERT_MEM_EQ(got, "udp", 3);
  tcp_listen(&conn, TCP_PORT);
  wire_clear(&t);
  memset(&s, 0, sizeof(s));
  s.sport = 40000;
  s.dport = TCP_PORT;
  s.seq = 1000;
  s.flags = TCPF_SYN;
  s.window = 4096;
  s.mss = 1440;
  ip = peer_ip6(peer6_ll, ll, NH_TCP);
  deliver(NULL, &ip, seg, peer_tcp6(seg, &ip, &s));
  for (i = 0; wire_sent(&t, (uint16_t)i); i++) {
    if (peer_parse_ipv6(wire_sent(&t, (uint16_t)i), &ip) &&
        peer_parse_tcp6(&ip, &tcp))
      break;
  }
  ASSERT_TRUE(wire_sent(&t, (uint16_t)i) != NULL);
  ASSERT_EQ(tcp.flags, TCPF_SYN | TCPF_ACK);
  ASSERT_EQ(tcp.ack, 1001);
  ASSERT_TRUE(tcp.cksum_ok);
  ASSERT_MEM_EQ(ip.src, ll, 16);
}

/* ── Extension headers ── */

/* REQ-IPv6-017, REQ-ICMPv6-026, 027: an unknown Next Header draws
 * Parameter Problem code 1 pointing at that field — in the fixed header,
 * or in the extension header before it; Hop-by-Hop anywhere but first is
 * one too */
TEST(itest_ipv6_017_unknown_next_header) {
  static uint8_t pkt[64];
  peer_ip6_t ip, rip;
  peer_icmp_t icmp;
  const wire_frame_t *f;
  up();
  ip = peer_ip6(peer6_ll, ll, 253);
  memset(pkt, 0x55, 8);
  deliver(NULL, &ip, pkt, 8);
  ASSERT_TRUE(sent(T_PARAM_PROBLEM, &rip, &icmp));
  f = wire_sent(&t, 0);
  ASSERT_EQ(icmp.code, 1);
  ASSERT_EQ(peer_get32(icmp.rest), 6);
  ASSERT_MEM_EQ(rip.src, ll, 16);
  ASSERT_MEM_EQ(rip.dst, peer6_ll, 16);
  ASSERT_MEM_EQ(f->data, peer_mac, 6);
  ASSERT_EQ(icmp.data_len, 40 + 8); /* the whole packet quoted */
  ASSERT_EQ(icmp.data[6], 253);
  ASSERT_TRUE(icmp.cksum_ok);

  wire_clear(&t);
  ip = peer_ip6(peer6_ll, ll, NH_HOPOPT);
  ext_header(pkt, NH_HOPOPT, 253, 0);
  deliver(NULL, &ip, pkt, 16);
  ASSERT_TRUE(sent(T_PARAM_PROBLEM, &rip, &icmp));
  ASSERT_EQ(icmp.code, 1);
  ASSERT_EQ(peer_get32(icmp.rest), 40);

  wire_clear(&t);
  ip = peer_ip6(peer6_ll, ll, NH_DSTOPTS);
  ext_header(pkt, NH_DSTOPTS, NH_HOPOPT, 0);
  ext_header(pkt + 8, NH_HOPOPT, NH_ICMPV6, 0);
  deliver(NULL, &ip, pkt, 24);
  ASSERT_TRUE(sent(T_PARAM_PROBLEM, &rip, &icmp));
  ASSERT_EQ(icmp.code, 1);
  ASSERT_EQ(peer_get32(icmp.rest), 40);
}

/* REQ-IPv6-018, 020: Hop-by-Hop, Destination Options and a Routing header
 * with no segments left are walked in order, by their length, to the
 * upper layer */
TEST(itest_ipv6_018_extension_headers_walked) {
  static uint8_t pkt[128], msg[64];
  peer_ip6_t ip, rip;
  peer_icmp_t icmp;
  uint16_t n;
  up();
  ext_header(pkt, NH_HOPOPT, NH_DSTOPTS, 0);
  memset(pkt + 8, 0, 16); /* Destination Options of 16 bytes */
  pkt[8] = NH_ROUTING;
  pkt[9] = 1;
  pkt[10] = 1; /* PadN to its end */
  pkt[11] = 12;
  ext_header(pkt + 24, NH_ROUTING, NH_ICMPV6, 0);
  ip = peer_ip6(peer6_ll, ll, NH_HOPOPT);
  ip.ext = pkt;
  ip.ext_len = 32;
  n = peer_icmp6(msg, &ip, T_ECHO_REQUEST, 0, id_seq, "chain", 5);
  deliver(NULL, &ip, msg, n);
  ASSERT_TRUE(sent(T_ECHO_REPLY, &rip, &icmp));
  ASSERT_MEM_EQ(icmp.data, "chain", 5);

  ip = peer_ip6(peer6_ll, ll, NH_DSTOPTS);
  ext_header(pkt, NH_DSTOPTS, NH_UDP, 0);
  ip.ext = pkt;
  ip.ext_len = 8;
  ip.nh = NH_DSTOPTS;
  {
    peer_ip6_t inner = ip;
    inner.nh = NH_UDP; /* the checksum names UDP, not the chain */
    n = peer_udp6(msg, &inner, PEER_PORT, OPEN_PORT, "dst", 3);
  }
  deliver(NULL, &ip, msg, n);
  ASSERT_EQ(delivered, 1);
  ASSERT_MEM_EQ(got, "dst", 3);
}

/* REQ-IPv6-019: Hop-by-Hop options are skipped without looking at them —
 * deviation: an unrecognized option whose type says "discard" does not
 * stop the packet */
TEST(itest_ipv6_019_options_skipped) {
  static uint8_t hbh[8], msg[64];
  peer_ip6_t ip, rip;
  peer_icmp_t icmp;
  uint16_t n;
  up();
  memset(hbh, 0, 8);
  hbh[0] = NH_ICMPV6;
  hbh[2] = 0xC2; /* type 11xxxxxx: discard, and Parameter Problem */
  hbh[3] = 4;
  ip = peer_ip6(peer6_ll, ll, NH_HOPOPT);
  ip.ext = hbh;
  ip.ext_len = 8;
  n = peer_icmp6(msg, &ip, T_ECHO_REQUEST, 0, id_seq, "opt", 3);
  deliver(NULL, &ip, msg, n);
  ASSERT_TRUE(sent(T_ECHO_REPLY, &rip, &icmp));
  ASSERT_EQ(wire_count_icmp6(&t, T_PARAM_PROBLEM), 0);
}

/* REQ-IPv6-022, 023, REQ-ICMPv6-024: fragments are dropped — deviation:
 * there is no reassembly, and so no Time Exceeded when one would time
 * out */
TEST(itest_ipv6_022_fragments_dropped) {
  static uint8_t fh[8], msg[64];
  peer_ip6_t ip;
  uint16_t n;
  up();
  memset(fh, 0, 8);
  fh[0] = NH_ICMPV6;
  fh[3] = 1; /* offset 0, more fragments */
  peer_put32(fh + 4, 0x99);
  ip = peer_ip6(peer6_ll, ll, NH_FRAGMENT);
  ip.ext = fh;
  ip.ext_len = 8;
  {
    peer_ip6_t inner = ip;
    inner.ext_len = 0;
    n = peer_icmp6(msg, &inner, T_ECHO_REQUEST, 0, id_seq, "frag", 4);
  }
  deliver(NULL, &ip, msg, n);
  peer_put16(fh + 2, (uint16_t)(16 << 3)); /* a later one, the last */
  deliver(NULL, &ip, msg, 8);
  itest_advance(&t, 61000, 1000);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-IPv6-021: what the stack sends carries no extension header — but
 * an MLD report, behind the Hop-by-Hop Router Alert MLD requires */
TEST(itest_ipv6_021_no_extension_headers_sent) {
  static const uint8_t group[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                    0,    0,    0, 0, 0, 1, 0, 3};
  peer_ip6_t ip;
  peer_icmp_t icmp;
  up();
  echo(peer6_ll, ll, "a", 1);
  datagram(peer6_ll, ll, CLOSED_PORT, "b", 1);
  udp6_send(&t.net, peer6_ll, peer_mac, OPEN_PORT, PEER_PORT,
            (const uint8_t *)"c", 1);
  ASSERT_EQ(t.wire.tx_count, 3);
  ASSERT_TRUE(peer_parse_ipv6(wire_sent(&t, 0), &ip));
  ASSERT_EQ(ip.nh, NH_ICMPV6);
  ASSERT_TRUE(peer_parse_ipv6(wire_sent(&t, 1), &ip));
  ASSERT_EQ(ip.nh, NH_ICMPV6);
  ASSERT_TRUE(peer_parse_ipv6(wire_sent(&t, 2), &ip));
  ASSERT_EQ(ip.nh, NH_UDP);
  wire_clear(&t);
  ipv6_mcast_join(&t.net, group);
  ASSERT_TRUE(sent(T_MLD_V2_REPORT, &ip, &icmp));
  ASSERT_EQ(ip.nh, NH_HOPOPT);
  ASSERT_EQ(ip.ext_len, 8);
  ASSERT_EQ(ip.ext[2], 5); /* Router Alert */
  ASSERT_EQ(ip.ext[3], 2);
  ASSERT_EQ(peer_get16(ip.ext + 4), 0); /* MLD */
}

/* ── Sending: source address, size ── */

/* REQ-IPv6-030, 041, 042, 043: link-scope destinations get the link-local
 * source, others the global one; with no global address a global
 * destination has no source, and the send fails */
TEST(itest_ipv6_030_source_selection) {
  static const uint8_t site_group[16] = {0xFF, 0x05, 0, 0, 0, 0, 0, 0,
                                         0,    0,    0, 0, 0, 0, 0, 3};
  peer_ip6_t ip;
  up();
  ASSERT_EQ(
      udp6_send(&t.net, offlink6, peer_mac, 1, 2, (const uint8_t *)"x", 1),
      NET_ERR_INVALID_PARAM);
  ASSERT_EQ(t.wire.tx_count, 0);
  udp6_send(&t.net, site_group, peer_mac, 1, 2, (const uint8_t *)"x", 1);
  ASSERT_TRUE(peer_parse_ipv6(wire_sent(&t, 0), &ip));
  ASSERT_MEM_EQ(ip.src, ll, 16); /* the group is still reached */

  up_global();
  udp6_send(&t.net, peer6_ll, peer_mac, 1, 2, (const uint8_t *)"x", 1);
  udp6_send(&t.net, all_nodes6, peer_mac, 1, 2, (const uint8_t *)"x", 1);
  udp6_send(&t.net, offlink6, peer_mac, 1, 2, (const uint8_t *)"x", 1);
  udp6_send(&t.net, site_group, peer_mac, 1, 2, (const uint8_t *)"x", 1);
  ASSERT_TRUE(peer_parse_ipv6(wire_sent(&t, 0), &ip));
  ASSERT_MEM_EQ(ip.src, ll, 16);
  ASSERT_TRUE(peer_parse_ipv6(wire_sent(&t, 1), &ip));
  ASSERT_MEM_EQ(ip.src, ll, 16);
  ASSERT_TRUE(peer_parse_ipv6(wire_sent(&t, 2), &ip));
  ASSERT_MEM_EQ(ip.src, global, 16);
  ASSERT_MEM_EQ(ip.dst, offlink6, 16);
  ASSERT_TRUE(peer_parse_ipv6(wire_sent(&t, 3), &ip));
  ASSERT_MEM_EQ(ip.src, global, 16);
}

/* REQ-IPv6-041, REQ-SLAAC-023: a deprecated address is a source only when
 * no preferred one fits */
TEST(itest_ipv6_041_deprecated_source_as_last_resort) {
  peer_ip6_t ip;
  up();
  ipv6_addr_add(&t.net, global, NET_IP6_INFINITE, 0);
  itest_advance(&t, 3000, 100);
  ASSERT_EQ(ipv6_addr_state(&t.net, 1), NET_IP6_DEPRECATED);
  wire_clear(&t);
  ASSERT_EQ(
      udp6_send(&t.net, offlink6, peer_mac, 1, 2, (const uint8_t *)"x", 1),
      NET_OK);
  ASSERT_TRUE(peer_parse_ipv6(wire_sent(&t, 0), &ip));
  ASSERT_MEM_EQ(ip.src, global, 16);
}

/* REQ-IPv6-032, 033, 034: nothing is fragmented — a packet fills at most
 * the Ethernet MTU of 1500 bytes; a larger datagram is refused */
TEST(itest_ipv6_032_never_fragmented) {
  static uint8_t data[1500];
  peer_ip6_t ip;
  up_bufs(WIRE_FRAME_MAX, WIRE_FRAME_MAX);
  ASSERT_EQ(udp6_send(&t.net, peer6_ll, peer_mac, 1, 2, data, 1500 - 48),
            NET_OK);
  ASSERT_TRUE(peer_parse_ipv6(wire_sent(&t, 0), &ip));
  ASSERT_EQ(40 + ip.plen, 1500);
  ASSERT_EQ(ip.nh, NH_UDP); /* no Fragment header */
  ASSERT_EQ(udp6_send(&t.net, peer6_ll, peer_mac, 1, 2, data, 1500 - 47),
            NET_ERR_BUF_TOO_SMALL);
  ASSERT_EQ(t.wire.tx_count, 1);
}

/* ── Addresses ── */

/* REQ-IPv6-035, 036, REQ-SLAAC-001, 002, 003: the link-local address is
 * fe80::/64 and the Modified EUI-64 of the MAC — ff:fe in the middle, the
 * universal/local bit inverted (RFC 4291 App. A) */
TEST(itest_ipv6_035_link_local_from_the_mac) {
  static const uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  static const uint8_t expect[16] = {0xFE, 0x80, 0,    0,    0,    0,
                                     0,    0,    0x02, 0x11, 0x22, 0xFF,
                                     0xFE, 0x33, 0x44, 0x55};
  static const uint8_t expect_default[16] = {0xFE, 0x80, 0,    0,    0,    0,
                                             0,    0,    0x00, 0x00, 0x00, 0xFF,
                                             0xFE, 0xDE, 0xAD, 0x01};
  peer_ip6_t ip;
  peer_icmp_t icmp;
  itest_up(&t, 1514, 1514);
  ASSERT_EQ(t.net.mac[0], 0x02); /* the default MAC: locally administered */
  ipv6_start(&t.net);
  itest_advance(&t, 1100, 100);
  ASSERT_TRUE(sent(135, &ip, &icmp)); /* the DAD probe */
  ASSERT_MEM_EQ(icmp.data, expect_default, 16);

  itest_up(&t, 1514, 1514);
  memcpy(t.net.mac, mac, 6);
  ipv6_start(&t.net);
  itest_advance(&t, 1100, 100);
  ASSERT_TRUE(sent(135, &ip, &icmp));
  ASSERT_MEM_EQ(icmp.data, expect, 16);
  itest_advance(&t, 15000, 100);
  wire_clear(&t);
  echo(peer6_ll, expect, "eui", 3);
  ASSERT_TRUE(sent(T_ECHO_REPLY, &ip, &icmp));
  ASSERT_MEM_EQ(ip.src, expect, 16);
}

/* REQ-IPv6-038, 039, 040: frames to the all-nodes MAC and our
 * solicited-node MAC (33:33 + the low 32 bits) are taken; another group's
 * MAC is not; what we send to a group goes to its MAC */
TEST(itest_ipv6_038_link_layer_groups) {
  static const uint8_t all_nodes_mac[6] = {0x33, 0x33, 0, 0, 0, 1};
  static const uint8_t sn_mac[6] = {0x33, 0x33, 0xFF, 0xDE, 0xAD, 0x01};
  static const uint8_t other_sn_mac[6] = {0x33, 0x33, 0xFF, 0, 0, 0x42};
  static const uint8_t mdns_mac[6] = {0x33, 0x33, 0, 0, 0, 0xFB};
  static uint8_t msg[64];
  peer_ip6_t ip, rip;
  peer_icmp_t icmp;
  uint16_t n;
  up();
  ip = peer_ip6(peer6_ll, ll, NH_ICMPV6);
  n = peer_icmp6(msg, &ip, T_ECHO_REQUEST, 0, id_seq, "m", 1);
  deliver(all_nodes_mac, &ip, msg, n);
  deliver(sn_mac, &ip, msg, n);
  ASSERT_EQ(wire_count_icmp6(&t, T_ECHO_REPLY), 2);
  deliver(other_sn_mac, &ip, msg, n);
  deliver(mdns_mac, &ip, msg, n);
  ASSERT_EQ(wire_count_icmp6(&t, T_ECHO_REPLY), 2);
  wire_clear(&t);
  ndp_send_ns(&t.net, peer6_ll, 0);
  ASSERT_TRUE(sent(135, &rip, &icmp));
  {
    uint8_t g[16], m[6];
    peer_solicited_node(peer6_ll, g);
    peer_mcast6_mac(g, m);
    ASSERT_MEM_EQ(wire_sent(&t, 0)->data, m, 6);
    ASSERT_MEM_EQ(rip.dst, g, 16);
  }
}

/* ── ICMPv6 ── */

/* REQ-ICMPv6-002: a message with a bad checksum, or too short to have
 * one, is dropped */
TEST(itest_icmpv6_002_bad_checksum_dropped) {
  static uint8_t msg[64];
  peer_ip6_t ip;
  uint16_t n;
  up();
  ip = peer_ip6(peer6_ll, ll, NH_ICMPV6);
  n = peer_icmp6(msg, &ip, T_ECHO_REQUEST, 0, id_seq, "bad", 3);
  msg[2] ^= 0x01;
  deliver(NULL, &ip, msg, n);
  deliver(NULL, &ip, msg, 3);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-ICMPv6-004..008: an Echo Reply, code 0, with the request's
 * identifier, sequence number and data, from the address the request was
 * sent to, back to its source and the MAC it came from */
TEST(itest_icmpv6_004_echo_reply) {
  static uint8_t data[1000];
  peer_ip6_t ip;
  peer_icmp_t icmp;
  uint16_t i;
  up_global();
  for (i = 0; i < sizeof(data); i++)
    data[i] = (uint8_t)(i * 7);
  echo(peer6_ll, ll, data, sizeof(data));
  ASSERT_TRUE(sent(T_ECHO_REPLY, &ip, &icmp));
  ASSERT_EQ(icmp.code, 0);
  ASSERT_MEM_EQ(icmp.rest, id_seq, 4);
  ASSERT_EQ(icmp.data_len, sizeof(data));
  ASSERT_MEM_EQ(icmp.data, data, sizeof(data));
  ASSERT_MEM_EQ(ip.src, ll, 16);
  ASSERT_MEM_EQ(ip.dst, peer6_ll, 16);
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, peer_mac, 6);
  ASSERT_TRUE(icmp.cksum_ok);
  wire_clear(&t);
  echo(offlink6, global, "far", 3);
  ASSERT_TRUE(sent(T_ECHO_REPLY, &ip, &icmp));
  ASSERT_MEM_EQ(ip.src, global, 16);
  ASSERT_MEM_EQ(ip.dst, offlink6, 16);
}

/* REQ-ICMPv6-009: an Echo Request to a group is answered from a unicast
 * address of ours */
TEST(itest_icmpv6_009_group_echo_answered_from_unicast) {
  static const uint8_t global_group[16] = {0xFF, 0x0E, 0, 0, 0, 0, 0, 0,
                                           0,    0,    0, 0, 0, 1, 0, 2};
  peer_ip6_t ip;
  peer_icmp_t icmp;
  up_global();
  ipv6_mcast_join(&t.net, global_group);
  wire_clear(&t);
  echo(peer6_ll, all_nodes6, "all", 3);
  ASSERT_TRUE(sent(T_ECHO_REPLY, &ip, &icmp));
  ASSERT_MEM_EQ(ip.src, ll, 16);
  ASSERT_MEM_EQ(ip.dst, peer6_ll, 16);
  wire_clear(&t);
  echo(offlink6, global_group, "glob", 4);
  ASSERT_TRUE(sent(T_ECHO_REPLY, &ip, &icmp));
  ASSERT_MEM_EQ(ip.src, global, 16);
}

/* REQ-ICMPv6-016, 017, 032: a datagram to a closed port draws Destination
 * Unreachable code 4 quoting the whole invoking packet — or as much of a
 * large one as fits in 1280 bytes */
TEST(itest_icmpv6_016_port_unreachable) {
  static uint8_t data[1400], seg[1500], f[WIRE_FRAME_MAX];
  peer_ip6_t ip, rip;
  peer_icmp_t icmp;
  uint16_t n, len;
  up();
  ip = peer_ip6(peer6_ll, ll, NH_UDP);
  n = peer_udp6(seg, &ip, PEER_PORT, CLOSED_PORT, "closed", 6);
  len = peer_ipv6_frame(f, t.net.mac, peer_mac, &ip, seg, n);
  itest_receive(&t, f, len);
  ASSERT_TRUE(sent(T_DEST_UNREACH, &rip, &icmp));
  ASSERT_EQ(icmp.code, 4);
  ASSERT_EQ(peer_get32(icmp.rest), 0);
  ASSERT_MEM_EQ(rip.src, ll, 16);
  ASSERT_MEM_EQ(rip.dst, peer6_ll, 16);
  ASSERT_MEM_EQ(wire_sent(&t, 0)->data, peer_mac, 6);
  ASSERT_EQ(icmp.data_len, 40 + 8 + 6);
  ASSERT_MEM_EQ(icmp.data, f + 14, 40 + 8 + 6); /* the packet, unchanged */
  ASSERT_TRUE(icmp.cksum_ok);
  wire_clear(&t);
  memset(data, 0xA5, sizeof(data));
  n = peer_udp6(seg, &ip, PEER_PORT, CLOSED_PORT, data, sizeof(data));
  len = peer_ipv6_frame(f, t.net.mac, peer_mac, &ip, seg, n);
  itest_receive(&t, f, len);
  ASSERT_TRUE(sent(T_DEST_UNREACH, &rip, &icmp));
  ASSERT_EQ(40 + rip.plen, 1280);
  ASSERT_EQ(icmp.data_len, 1280 - 48);
  ASSERT_MEM_EQ(icmp.data, f + 14, 1280 - 48);
}

/* REQ-ICMPv6-017, 032: the quote is cut to what the TX buffer holds */
TEST(itest_icmpv6_017_quote_fits_the_tx_buffer) {
  static uint8_t data[600];
  peer_ip6_t ip;
  peer_icmp_t icmp;
  up_bufs(1514, 300);
  datagram(peer6_ll, ll, CLOSED_PORT, data, sizeof(data));
  ASSERT_TRUE(sent(T_DEST_UNREACH, &ip, &icmp));
  ASSERT_EQ(wire_sent(&t, 0)->len, 300);
  ASSERT_EQ(icmp.data_len, 300 - 14 - 48);
  ASSERT_TRUE(icmp.cksum_ok);
}

/* REQ-ICMPv6-021, 023: a host originates neither Packet Too Big nor Time
 * Exceeded: a packet with Hop Limit 0 or 1 is processed normally, an echo
 * too large to answer is dropped */
TEST(itest_icmpv6_021_no_router_errors) {
  static uint8_t msg[1500], big[1000];
  peer_ip6_t ip;
  uint16_t n;
  up_bufs(1514, 600);
  ip = peer_ip6(peer6_ll, ll, NH_ICMPV6);
  ip.hop_limit = 0;
  n = peer_icmp6(msg, &ip, T_ECHO_REQUEST, 0, id_seq, "zero", 4);
  deliver(NULL, &ip, msg, n);
  ip.hop_limit = 1;
  n = peer_icmp6(msg, &ip, T_ECHO_REQUEST, 0, id_seq, "one", 3);
  deliver(NULL, &ip, msg, n);
  ASSERT_EQ(wire_count_icmp6(&t, T_ECHO_REPLY), 2);
  wire_clear(&t);
  n = peer_icmp6(msg, &ip, T_ECHO_REQUEST, 0, id_seq, big, sizeof(big));
  deliver(NULL, &ip, msg, n);
  ASSERT_EQ(t.wire.tx_count, 0);
  ASSERT_EQ(wire_count_icmp6(&t, T_TOO_BIG), 0);
  ASSERT_EQ(wire_count_icmp6(&t, T_TIME_EXCEEDED), 0);
}

/* REQ-ICMPv6-028: no error is sent about an ICMPv6 error, nor about a
 * Redirect */
TEST(itest_icmpv6_028_no_error_about_errors) {
  static uint8_t quote[48], msg[128];
  peer_ip6_t ip;
  uint8_t type;
  uint16_t n;
  up();
  memset(quote, 0, sizeof(quote));
  quote[0] = 0x60;
  memcpy(quote + 8, ll, 16);
  memcpy(quote + 24, peer6_ll, 16);
  quote[6] = 253;
  ip = peer_ip6(peer6_ll, ll, NH_ICMPV6);
  for (type = 1; type <= 4; type++) {
    n = peer_icmp6(msg, &ip, type, 0, NULL, quote, sizeof(quote));
    deliver(NULL, &ip, msg, n);
  }
  n = peer_icmp6(msg, &ip, 100, 0, NULL, quote, sizeof(quote));
  deliver(NULL, &ip, msg, n);
  ip.hop_limit = 255;
  ip.src = router6_ll;
  n = peer_icmp6(msg, &ip, 137, 0, NULL, quote, sizeof(quote));
  deliver(NULL, &ip, msg, n);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-ICMPv6-029: no error about a packet sent to a group, or to a
 * link-layer multicast or broadcast address */
TEST(itest_icmpv6_029_no_error_about_group_packets) {
  static uint8_t seg[64];
  peer_ip6_t ip;
  uint16_t n;
  up();
  datagram(peer6_ll, all_nodes6, CLOSED_PORT, "a", 1);
  ip = peer_ip6(peer6_ll, ll, NH_UDP);
  n = peer_udp6(seg, &ip, PEER_PORT, CLOSED_PORT, "b", 1);
  {
    static const uint8_t all_nodes_mac[6] = {0x33, 0x33, 0, 0, 0, 1};
    deliver(all_nodes_mac, &ip, seg, n);
  }
  deliver(broadcast_mac, &ip, seg, n);
  ip = peer_ip6(peer6_ll, all_nodes6, 253);
  deliver(NULL, &ip, seg, 8);
  ASSERT_EQ(t.wire.tx_count, 0);
}

/* REQ-ICMPv6-039: an informational message of unknown type is dropped */
TEST(itest_icmpv6_039_unknown_informational_dropped) {
  static uint8_t msg[64];
  peer_ip6_t ip;
  uint16_t n;
  up();
  ip = peer_ip6(peer6_ll, ll, NH_ICMPV6);
  n = peer_icmp6(msg, &ip, 200, 0, NULL, "?", 1);
  deliver(NULL, &ip, msg, n);
  n = peer_icmp6(msg, &ip, T_ECHO_REPLY, 0, id_seq, "!", 1);
  deliver(NULL, &ip, msg, n);
  ASSERT_EQ(t.wire.tx_count, 0);
}

int main(void) {
  fprintf(stderr, "=== itest_ipv6 ===\n");
  RUN_TEST(itest_ipv6_001_version_checked);
  RUN_TEST(itest_ipv6_002_payload_length_checked);
  RUN_TEST(itest_ipv6_003_payload_length_bounds_the_payload);
  RUN_TEST(itest_ipv6_024_header_built);
  RUN_TEST(itest_ipv6_047_built_in_place);
  RUN_TEST(itest_ipv6_046_parsed_in_place);
  RUN_TEST(itest_ipv6_044_upper_layer_checksums);
  RUN_TEST(itest_ipv6_006_destinations_accepted);
  RUN_TEST(itest_ipv6_010_other_destinations_dropped);
  RUN_TEST(itest_ipv6_011_multicast_source_dropped);
  RUN_TEST(itest_ipv6_012_own_source_dropped);
  RUN_TEST(itest_ipv6_013_unspecified_source);
  RUN_TEST(itest_ipv6_014_upper_layers_dispatched);
  RUN_TEST(itest_ipv6_017_unknown_next_header);
  RUN_TEST(itest_ipv6_018_extension_headers_walked);
  RUN_TEST(itest_ipv6_019_options_skipped);
  RUN_TEST(itest_ipv6_022_fragments_dropped);
  RUN_TEST(itest_ipv6_021_no_extension_headers_sent);
  RUN_TEST(itest_ipv6_030_source_selection);
  RUN_TEST(itest_ipv6_041_deprecated_source_as_last_resort);
  RUN_TEST(itest_ipv6_032_never_fragmented);
  RUN_TEST(itest_ipv6_035_link_local_from_the_mac);
  RUN_TEST(itest_ipv6_038_link_layer_groups);
  RUN_TEST(itest_icmpv6_002_bad_checksum_dropped);
  RUN_TEST(itest_icmpv6_004_echo_reply);
  RUN_TEST(itest_icmpv6_009_group_echo_answered_from_unicast);
  RUN_TEST(itest_icmpv6_016_port_unreachable);
  RUN_TEST(itest_icmpv6_017_quote_fits_the_tx_buffer);
  RUN_TEST(itest_icmpv6_021_no_router_errors);
  RUN_TEST(itest_icmpv6_028_no_error_about_errors);
  RUN_TEST(itest_icmpv6_029_no_error_about_group_packets);
  RUN_TEST(itest_icmpv6_039_unknown_informational_dropped);
  ITEST_REPORT();
  return test_failures;
}
