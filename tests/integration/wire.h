/**
 * @file wire.h
 * @brief Black-box integration tests: the stack on a scripted link.
 *
 * The stack is driven only through its public API — net_init(),
 * net_poll(), net_tick() and the protocol modules' functions — and
 * observed only on the wire and through that API.  The test plays the
 * network: it queues frames for the stack to receive and inspects the
 * frames it sends.  The peer side builds and parses frames with its own
 * code (and its own checksum), never the stack's, so a test checks the
 * stack against the RFCs and not against itself.
 *
 * Every test names the requirements it verifies (REQ-... IDs, checked by
 * scripts/trace.py).  Test files include itest.h.  See docs/test-plan.md.
 */

#ifndef WIRE_H
#define WIRE_H

#include "net.h"
#include <stdint.h>

/* ── The link ─────────────────────────────────────────────────────── */

#define WIRE_FRAME_MAX 2048
#define WIRE_RX_SLOTS 8
#define WIRE_TX_SLOTS 32

typedef struct {
  uint8_t data[WIRE_FRAME_MAX];
  uint16_t len;
} wire_frame_t;

typedef struct {
  wire_frame_t rx[WIRE_RX_SLOTS]; /* queued for the stack, oldest first */
  uint8_t rx_count;
  wire_frame_t tx[WIRE_TX_SLOTS]; /* what the stack sent, in order */
  uint16_t tx_count;              /* frames sent; beyond the slots: lost */
} wire_t;

/** The driver the stack is initialised with; its context is a wire_t. */
extern const net_mac_t wire_driver;

/** A stack on a wire, with its own frame buffers. */
typedef struct itest_s {
  wire_t wire;
  net_t net;
  uint8_t rx_buf[WIRE_FRAME_MAX];
  uint8_t tx_buf[WIRE_FRAME_MAX];
  /** The application's own polling (an HTTP server's, say), run after
   *  each frame the stack takes; NULL for none */
  void (*service)(struct itest_s *t);
} itest_t;

/**
 * net_init() with frame buffers of @p rx_size and @p tx_size bytes (at
 * most WIRE_FRAME_MAX) and the configured default addresses, then the
 * driver opened.  @return what net_init() returned.
 */
net_err_t itest_up(itest_t *t, uint16_t rx_size, uint16_t tx_size);

/** Queue a frame for the stack. */
void wire_deliver(itest_t *t, const uint8_t *frame, uint16_t len);

/** net_poll() until the stack has taken every queued frame. */
void itest_poll(itest_t *t);

/** Queue a frame and let the stack take it. */
void itest_receive(itest_t *t, const uint8_t *frame, uint16_t len);

/** net_tick() for @p ms milliseconds, in steps of at most @p step ms. */
void itest_advance(itest_t *t, uint32_t ms, uint32_t step);

/** Forget what the stack has sent so far. */
void wire_clear(itest_t *t);

/** Frame @p i of those sent since the last wire_clear(), or NULL. */
const wire_frame_t *wire_sent(const itest_t *t, uint16_t i);

/* ── The peer: frames built and parsed independently of the stack ── */

/** The peer on the link (10.0.0.1, a fixed MAC). */
extern const uint8_t peer_mac[6];
#define PEER_IP 0x0A000001u
/** A second host on the subnet, and one on another network */
#define PEER2_IP 0x0A000063u
#define REMOTE_IP 0xC6336401u /* 198.51.100.1 (TEST-NET-2) */
extern const uint8_t broadcast_mac[6];

/** RFC 1071 checksum of @p len bytes, the peer's own. */
uint16_t peer_cksum(const void *data, uint16_t len);

/** An IPv4 header as the peer writes it or reads it. */
typedef struct {
  uint32_t src, dst;
  uint8_t proto;
  uint8_t ttl;
  uint8_t tos;
  uint16_t id;
  uint8_t df, mf;
  uint16_t frag_offset; /* in bytes, a multiple of 8 */
  const uint8_t *options;
  uint8_t options_len; /* a multiple of 4, at most 40 */
  /* filled in by peer_parse_ipv4() */
  uint8_t ihl_bytes;
  uint16_t total_len;
  int header_cksum_ok;
  const uint8_t *payload;
  uint16_t payload_len;
} peer_ip_t;

/** An IPv4 header for @p proto from @p src to @p dst: TTL 64, DF clear,
 *  no options, the rest 0. */
peer_ip_t peer_ip(uint32_t src, uint32_t dst, uint8_t proto);

/**
 * Ethernet + IPv4 header (+ options) + @p len bytes of @p payload.
 * @return The frame length.
 */
uint16_t peer_ipv4_frame(uint8_t *frame, const uint8_t dst_mac[6],
                         const uint8_t src_mac[6], const peer_ip_t *ip,
                         const void *payload, uint16_t len);

/** A UDP datagram (checksummed) to put in an IPv4 frame; @return its
 *  length (8 + @p len). */
uint16_t peer_udp(uint8_t *out, const peer_ip_t *ip, uint16_t sport,
                  uint16_t dport, const void *data, uint16_t len);

/** An ICMP message: type, code, the 4 header bytes after the checksum,
 *  data; @return its length. */
uint16_t peer_icmp(uint8_t *out, uint8_t type, uint8_t code,
                   const uint8_t rest[4], const void *data, uint16_t len);

/** A whole UDP frame from the peer to the stack (unicast). */
uint16_t peer_udp_frame(uint8_t *frame, const net_t *net, uint32_t src,
                        uint32_t dst, uint16_t sport, uint16_t dport,
                        const void *data, uint16_t len);

/** An ARP frame: @p op 1 request, 2 reply. */
uint16_t peer_arp_frame(uint8_t *frame, const uint8_t eth_dst[6], uint16_t op,
                        const uint8_t sha[6], uint32_t spa,
                        const uint8_t tha[6], uint32_t tpa);

/** Parse a sent frame as Ethernet + IPv4: 1 if it is one. */
int peer_parse_ipv4(const wire_frame_t *f, peer_ip_t *ip);

/** A parsed UDP datagram */
typedef struct {
  uint16_t sport, dport, len, cksum;
  int cksum_ok;
  const uint8_t *data;
  uint16_t data_len;
} peer_udp_t;

int peer_parse_udp(const peer_ip_t *ip, peer_udp_t *udp);

/** A parsed ICMP message */
typedef struct {
  uint8_t type, code;
  int cksum_ok;
  const uint8_t *rest; /* the 4 bytes after the checksum */
  const uint8_t *data;
  uint16_t data_len;
} peer_icmp_t;

int peer_parse_icmp(const peer_ip_t *ip, peer_icmp_t *icmp);

/** A TCP segment the peer sends: header fields, an MSS option if
 *  @p mss is not 0, data */
typedef struct {
  uint16_t sport, dport;
  uint32_t seq, ack;
  uint8_t flags; /* TCPF_* */
  uint16_t window;
  uint16_t mss;
  const void *data;
  uint16_t len;
} peer_tcp_seg_t;

#define TCPF_FIN 0x01
#define TCPF_SYN 0x02
#define TCPF_RST 0x04
#define TCPF_PSH 0x08
#define TCPF_ACK 0x10

/** A whole TCP frame from the peer at @p src to the stack. */
uint16_t peer_tcp_frame(uint8_t *frame, const net_t *net, uint32_t src,
                        const peer_tcp_seg_t *seg);

/** A parsed TCP segment */
typedef struct {
  uint16_t sport, dport;
  uint32_t seq, ack;
  uint8_t flags;
  uint16_t window;
  uint16_t mss; /* 0 if no MSS option */
  int cksum_ok;
  const uint8_t *data;
  uint16_t data_len;
} peer_tcp_t;

int peer_parse_tcp(const peer_ip_t *ip, peer_tcp_t *tcp);

/** The first frame sent (from @p from on) that is TCP, parsed into
 *  @p ip and @p tcp: its index, or -1. */
int wire_find_tcp(const itest_t *t, uint16_t from, peer_ip_t *ip,
                  peer_tcp_t *tcp);

/** The peer as a TCP client of a server in the stack: connects, sends,
 *  acknowledges and collects what the server sends, in order. */
typedef struct {
  uint16_t sport, dport;
  uint32_t snd_nxt; /* the peer's next sequence number */
  uint32_t rcv_nxt; /* the next byte expected from the stack */
  int connected, fin, rst;
  uint8_t data[8192];
  uint16_t len;
  uint16_t seen; /* frames of the wire log already looked at */
} peer_client_t;

/** SYN, the stack's SYN,ACK, ACK.  @return 1 if connected. */
int peer_connect(itest_t *t, peer_client_t *c, uint16_t sport, uint16_t dport);

/** Send @p len bytes (one segment, PSH,ACK), then collect. */
void peer_send(itest_t *t, peer_client_t *c, const void *data, uint16_t len);

/** Acknowledge everything the stack sends until it stops sending; data
 *  in order is appended to c->data; a FIN is acknowledged and noted. */
void peer_collect(itest_t *t, peer_client_t *c);

/** Our FIN,ACK, then collect. */
void peer_close(itest_t *t, peer_client_t *c);

/* ── DNS messages (mDNS), the peer's own codec ── */

/** A DNS message the peer builds: names written uncompressed */
typedef struct {
  uint8_t buf[1500];
  uint16_t len;
  uint16_t qd, an, ns, ar;
} peer_dns_t;

void peer_dns_begin(peer_dns_t *m, uint16_t id, uint16_t flags);
void peer_dns_question(peer_dns_t *m, const char *name, uint16_t type,
                       uint16_t class_);
/** A resource record in @p section (0 answer, 1 authority, 2 additional);
 *  sections must be added in order */
void peer_dns_rr(peer_dns_t *m, int section, const char *name, uint16_t type,
                 uint16_t class_, uint32_t ttl, const void *rdata,
                 uint16_t rdlen);
/** PTR rdata: @p target as an uncompressed name; @return its length */
uint16_t peer_dns_name(uint8_t *out, const char *name);
/** The header counts written: call before sending */
void peer_dns_end(peer_dns_t *m);

/** A parsed resource record */
typedef struct {
  char name[256];
  uint16_t type, class_;
  uint32_t ttl;
  const uint8_t *rdata;
  uint16_t rdlen;
  uint16_t rdata_off; /* within the message, for names in rdata */
  int section;        /* 0 answer, 1 authority, 2 additional */
} peer_rr_t;

/** A parsed DNS message: its header and up to 32 records */
typedef struct {
  const uint8_t *msg;
  uint16_t len;
  uint16_t id, flags, qd, an, ns, ar;
  char qname[256]; /* the first question's */
  uint16_t qtype;
  peer_rr_t rr[32];
  uint16_t n_rr;
} peer_dns_msg_t;

/** Parse @p len bytes; 1 if well formed. */
int peer_dns_parse(const uint8_t *msg, uint16_t len, peer_dns_msg_t *out);
/** Decode the name at @p off of @p m into @p out (dotted, no final dot). */
int peer_dns_read_name(const peer_dns_msg_t *m, uint16_t off, char *out);
/** The first record in @p section named @p name (case-insensitive) of
 *  @p type, or NULL */
const peer_rr_t *peer_dns_find(const peer_dns_msg_t *m, int section,
                               const char *name, uint16_t type);

/** A parsed ARP packet */
typedef struct {
  uint16_t op;
  const uint8_t *sha, *tha;
  uint32_t spa, tpa;
} peer_arp_t;

int peer_parse_arp(const wire_frame_t *f, peer_arp_t *arp);

/** Big-endian field access, the peer's own */
uint16_t peer_get16(const uint8_t *p);
uint32_t peer_get32(const uint8_t *p);
void peer_put16(uint8_t *p, uint16_t v);
void peer_put32(uint8_t *p, uint32_t v);

/* ── IPv6: Ethernet + IPv6 frames, ICMPv6 (Neighbor Discovery, MLD), UDP
 *    and TCP over IPv6, the peer's own codec and checksum ── */

/** The peer's link-local address (fe80::99), a router's link-local
 *  address (fe80::1) and MAC, the prefix it advertises (2001:db8:1::/64),
 *  a host beyond it (2001:db8:9::9), and the well-known groups */
extern const uint8_t peer6_ll[16];
extern const uint8_t router6_ll[16];
extern const uint8_t router6_mac[6];
extern const uint8_t prefix6[16];
extern const uint8_t offlink6[16];
extern const uint8_t all_nodes6[16];
extern const uint8_t all_routers6[16];

/** An IPv6 header as the peer writes it or reads it. */
typedef struct {
  const uint8_t *src, *dst; /* 16 bytes each */
  uint8_t nh;               /* the fixed header's Next Header */
  uint8_t hop_limit;
  uint8_t tclass;
  uint32_t flow; /* 20 bits */
  /** Extension headers between the fixed header and the payload, their
   *  Next Header fields filled in; NULL for none */
  const uint8_t *ext;
  uint16_t ext_len;
  /* filled in by peer_parse_ipv6() */
  uint16_t plen;          /* the Payload Length field */
  uint8_t proto;          /* the upper-layer protocol, after the chain */
  const uint8_t *payload; /* the upper-layer message */
  uint16_t payload_len;
} peer_ip6_t;

/** A header from @p src to @p dst carrying @p nh: Hop Limit 64, traffic
 *  class and flow label 0, no extension headers. */
peer_ip6_t peer_ip6(const uint8_t *src, const uint8_t *dst, uint8_t nh);

/**
 * Ethernet + IPv6 header + the extension headers + @p len bytes of
 * @p payload.  @return The frame length.
 */
uint16_t peer_ipv6_frame(uint8_t *frame, const uint8_t dst_mac[6],
                         const uint8_t src_mac[6], const peer_ip6_t *ip,
                         const void *payload, uint16_t len);

/** The Ethernet address of an IPv6 group: 33:33 + its low 32 bits. */
void peer_mcast6_mac(const uint8_t *group, uint8_t mac[6]);

/** The solicited-node group of @p addr: ff02::1:ff + its low 24 bits. */
void peer_solicited_node(const uint8_t *addr, uint8_t group[16]);

/** fe80::/64 + the Modified EUI-64 identifier of @p mac. */
void peer_link_local(const uint8_t mac[6], uint8_t addr[16]);

/** The upper-layer checksum over the IPv6 pseudo-header (RFC 8200 §8.1):
 *  the value to store with the field zero, 0 over a valid message. */
uint16_t peer_cksum6(const uint8_t *src, const uint8_t *dst, uint8_t nh,
                     const uint8_t *data, uint16_t len);

/** An ICMPv6 message for @p ip (whose addresses the checksum covers):
 *  type, code, the 4 bytes after the checksum, the body; @return its
 *  length. */
uint16_t peer_icmp6(uint8_t *out, const peer_ip6_t *ip, uint8_t type,
                    uint8_t code, const uint8_t rest[4], const void *body,
                    uint16_t len);

/** A whole ICMPv6 frame from peer_mac to @p dst_mac. */
uint16_t peer_icmp6_frame(uint8_t *frame, const uint8_t dst_mac[6],
                          const peer_ip6_t *ip, uint8_t type, uint8_t code,
                          const uint8_t rest[4], const void *body,
                          uint16_t len);

/** A Neighbor Discovery link-layer address option (type 1 source, 2
 *  target) for @p mac; @return 8. */
uint16_t peer_nd_lla(uint8_t *out, uint8_t type, const uint8_t mac[6]);

/** A Prefix Information option; @return 32. */
uint16_t peer_nd_prefix(uint8_t *out, const uint8_t prefix[16],
                        uint8_t prefix_len, uint8_t flags, uint32_t valid_s,
                        uint32_t preferred_s);

/** A UDP datagram (checksummed over @p ip) to put in an IPv6 frame;
 *  @return its length (8 + @p len). */
uint16_t peer_udp6(uint8_t *out, const peer_ip6_t *ip, uint16_t sport,
                   uint16_t dport, const void *data, uint16_t len);

/** A TCP segment (checksummed over @p ip); @return its length. */
uint16_t peer_tcp6(uint8_t *out, const peer_ip6_t *ip,
                   const peer_tcp_seg_t *seg);

/** Parse a frame as Ethernet + IPv6, walking Hop-by-Hop, Routing and
 *  Destination Options headers: 1 if it is one. */
int peer_parse_ipv6(const wire_frame_t *f, peer_ip6_t *ip);

/** A parsed ICMPv6 message (cksum_ok over the pseudo-header) */
int peer_parse_icmp6(const peer_ip6_t *ip, peer_icmp_t *icmp);
int peer_parse_udp6(const peer_ip6_t *ip, peer_udp_t *udp);
int peer_parse_tcp6(const peer_ip6_t *ip, peer_tcp_t *tcp);

/** The Neighbor Discovery option of @p type in the @p len bytes of
 *  options at @p opts, or NULL (also if an option is malformed). */
const uint8_t *peer_nd_option(const uint8_t *opts, uint16_t len, uint8_t type);

/** The first frame sent (from @p from on) that is ICMPv6 of @p type,
 *  parsed: its index, or -1. */
int wire_find_icmp6(const itest_t *t, uint16_t from, uint8_t type,
                    peer_ip6_t *ip, peer_icmp_t *icmp);

/** How many frames sent since the last wire_clear() are ICMPv6 of
 *  @p type. */
int wire_count_icmp6(const itest_t *t, uint8_t type);

#endif /* WIRE_H */
