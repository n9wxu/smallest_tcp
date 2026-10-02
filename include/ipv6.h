/**
 * @file ipv6.h
 * @brief IPv6 — Internet Protocol version 6 (RFC 8200, RFC 4291).
 *
 * Parse/build the fixed 40-byte header in place, walk extension headers,
 * dispatch by upper-layer protocol.  No fragmentation or reassembly.
 * Addresses are 16-byte arrays in network byte order.
 *
 * Start IPv6 on an interface with ipv6_start() (forms the link-local
 * address and runs Duplicate Address Detection); net_tick() runs its
 * timers.  See docs/design/ipv6.md.
 */

#ifndef IPV6_H
#define IPV6_H

#include "eth.h"
#include "net.h"
#include "net_cksum.h"
#include <stdint.h>
#include <string.h>

/* Header layout */
#define IPV6_OFF_VTF 0  /* Version (4) | Traffic Class (8) | Flow (20) */
#define IPV6_OFF_PLEN 4 /* Payload Length (2) */
#define IPV6_OFF_NH 6   /* Next Header (1) */
#define IPV6_OFF_HLIM 7 /* Hop Limit (1) */
#define IPV6_OFF_SRC 8
#define IPV6_OFF_DST 24
#define IPV6_HDR_SIZE 40

#define IPV6_MIN_MTU 1280 /* RFC 8200 §5 */

/* Next Header values */
#define IPV6_NH_HOPOPT 0
#define IPV6_NH_TCP 6
#define IPV6_NH_UDP 17
#define IPV6_NH_ROUTING 43
#define IPV6_NH_FRAGMENT 44
#define IPV6_NH_ICMPV6 58
#define IPV6_NH_NONE 59
#define IPV6_NH_DSTOPTS 60

/* Routing header (RFC 8200 §4.4) */
#define IPV6_ROUTING_OFF_TYPE 2
#define IPV6_ROUTING_OFF_SEGMENTS 3 /* Segments Left */

/* Parsed header */

/**
 * @brief An IPv6 packet after the extension-header walk.  Pointers point
 * into the received frame.
 */
typedef struct {
  const uint8_t *src;   /**< Source address (16 bytes) */
  const uint8_t *dst;   /**< Destination address (16 bytes) */
  uint8_t next_header;  /**< Upper-layer protocol after the chain; or
                             IPV6_NH_ROUTING: the chain stops at a Routing
                             header with segments left */
  uint8_t hop_limit;    /**< Hop Limit */
  uint8_t *header;      /**< Start of the IPv6 header */
  uint16_t header_len;  /**< 40 + extension headers */
  uint8_t *payload;     /**< Upper-layer header */
  uint16_t payload_len; /**< Upper-layer length */
  uint16_t nh_offset;   /**< Offset (from header) of the Next Header
                             field naming next_header — the Parameter
                             Problem pointer if it is unknown */
} ipv6_hdr_t;

/* Addresses */
extern const uint8_t ipv6_unspecified[16]; /**< :: */
extern const uint8_t ipv6_all_nodes[16];   /**< ff02::1 */
extern const uint8_t ipv6_all_routers[16]; /**< ff02::2 */

static inline int ipv6_addr_equal(const uint8_t *a, const uint8_t *b) {
  return memcmp(a, b, 16) == 0;
}

static inline int ipv6_is_unspecified(const uint8_t *a) {
  return ipv6_addr_equal(a, ipv6_unspecified);
}

static inline int ipv6_is_multicast(const uint8_t *a) { return a[0] == 0xFF; }

/** fe80::/10 */
static inline int ipv6_is_link_local(const uint8_t *a) {
  return a[0] == 0xFE && (a[1] & 0xC0) == 0x80;
}

/** Ethernet MAC of a multicast group: 33:33 + low 32 bits (RFC 2464 §7). */
static inline void ipv6_mcast_mac(const uint8_t *group, uint8_t mac[6]) {
  mac[0] = 0x33;
  mac[1] = 0x33;
  memcpy(mac + 2, group + 12, 4);
}

/** Solicited-node group of an address: ff02::1:ff00:0/104 + low 24 bits. */
static inline void ipv6_solicited_node(const uint8_t *addr, uint8_t out[16]) {
  static const uint8_t prefix[13] = {0xFF, 0x02, 0, 0, 0, 0,   0,
                                     0,    0,    0, 0, 1, 0xFF};
  memcpy(out, prefix, 13);
  memcpy(out + 13, addr + 13, 3);
}

/** Link-local address fe80::/64 + Modified EUI-64 of the MAC
 *  (RFC 4291 App. A: insert ff:fe, flip the U/L bit). */
static inline void ipv6_link_local_from_mac(const uint8_t mac[6],
                                            uint8_t out[16]) {
  memset(out, 0, 8);
  out[0] = 0xFE;
  out[1] = 0x80;
  out[8] = (uint8_t)(mac[0] ^ 0x02);
  out[9] = mac[1];
  out[10] = mac[2];
  out[11] = 0xFF;
  out[12] = 0xFE;
  out[13] = mac[3];
  out[14] = mac[4];
  out[15] = mac[5];
}

/* Packets */

/**
 * Parse an IPv6 header and its extension-header chain in place.
 *
 * Checks the version and that 40 + Payload Length fits in @p data_len
 * (extra bytes are link padding).  Skips Hop-by-Hop (first only),
 * Routing and Destination Options headers; stops at a Routing header
 * with segments left, which becomes @p out's next_header and payload.
 *
 * @return NET_OK; NET_ERR_INVALID_PARAM for a malformed packet, a
 *         fragment (no reassembly) or No Next Header.
 */
net_err_t ipv6_parse(uint8_t *data, uint16_t data_len, ipv6_hdr_t *out);

/**
 * Process a received IPv6 packet (after Ethernet dispatch): validate,
 * check the addresses, dispatch by upper-layer protocol.
 */
void ipv6_input(net_t *net, const eth_frame_t *eth);

/**
 * Write a 40-byte IPv6 header: version 6, traffic class 0, flow label 0.
 */
void ipv6_build(uint8_t *buf, uint16_t payload_len, uint8_t next_header,
                const uint8_t *src, const uint8_t *dst, uint8_t hop_limit);

/**
 * Upper-layer checksum (TCP, UDP, ICMPv6) of @p data over the
 * pseudo-header (RFC 8200 §8.1).  With the checksum field zero, this is the
 * value to store; over a received message it is 0 when the checksum is valid.
 */
uint16_t ipv6_cksum(const uint8_t *src, const uint8_t *dst, uint8_t next_header,
                    const uint8_t *data, uint16_t len);

/* The interface's addresses */

/**
 * Form the link-local address from the MAC and start Duplicate Address
 * Detection on it.  IPv6 stays silent until this is called.
 */
void ipv6_start(net_t *net);

/** Advance DAD, router discovery, MLD, the address lifetimes and the
 *  ICMPv6 error rate limit (called by net_tick()). */
void ipv6_tick(net_t *net, uint32_t elapsed_ms);

/** State (NET_IP6_*) of address slot @p slot. */
uint8_t ipv6_addr_state(const net_t *net, uint8_t slot);

/** Slot holding @p addr in any state but NONE, or -1. */
int ipv6_addr_slot(const net_t *net, const uint8_t *addr);

/** True if @p addr is one of our usable (PREFERRED/DEPRECATED) addresses. */
int ipv6_is_ours(const net_t *net, const uint8_t *addr);

/**
 * Source address for a packet to @p dst (RFC 6724, one interface):
 * link-local for link-local and link-scope multicast destinations, else
 * a preferred global address, else a deprecated one; a multicast group of
 * wider scope falls back to the link-local address.
 * @return Pointer into net->ip6, or NULL if none is usable — and for the
 *         unspecified address, to which nothing is sent.
 */
const uint8_t *ipv6_src_for(const net_t *net, const uint8_t *dst);

/** True if @p mac is all-nodes or the solicited-node group of one of our
 *  configured (incl. tentative) addresses. */
int ipv6_mac_accepted(const net_t *net, const uint8_t *mac);

/**
 * Add a global address (static configuration, SLAAC, DHCPv6) and start
 * Duplicate Address Detection on it.  Lifetimes in seconds
 * (NET_IP6_INFINITE: never expires).
 * @return NET_OK (also if already configured); NET_ERR_INVALID_PARAM for
 *         a multicast or unspecified address; NET_ERR_BUF_TOO_SMALL when
 *         all NET_IPV6_ADDRS slots are taken.
 */
net_err_t ipv6_addr_add(net_t *net, const uint8_t *addr, uint32_t valid_s,
                        uint32_t preferred_s);

/**
 * Listen to an IPv6 multicast group (e.g. ff02::fb for mDNS): frames and
 * packets for it are accepted, and MLD reports it.
 * @return NET_OK (also if already joined); NET_ERR_INVALID_PARAM if not
 *         multicast; NET_ERR_BUF_TOO_SMALL if NET_MAX_MCAST6_GROUPS are in
 *         use.
 */
net_err_t ipv6_mcast_join(net_t *net, const uint8_t *group);

/** Stop listening to a group (MLD reports the leave). */
void ipv6_mcast_leave(net_t *net, const uint8_t *group);

/** True if @p group was joined with ipv6_mcast_join(). */
int ipv6_mcast_is_member(const net_t *net, const uint8_t *group);

/** Remove one of our global addresses (no-op if absent). */
void ipv6_addr_remove(net_t *net, const uint8_t *addr);

/**
 * New lifetimes for the address in @p slot (SLAAC, DHCPv6 renewal); a
 * usable address becomes PREFERRED or DEPRECATED to match.
 */
void ipv6_addr_set_lifetimes(net_t *net, uint8_t slot, uint32_t valid_s,
                             uint32_t preferred_s);

/** MAC of the default router, or NULL if none (RA router lifetime). */
const uint8_t *ipv6_router_mac(const net_t *net);

/**
 * True if @p dst is on the link: link-local, or in the /64 of one of our
 * global addresses (RA prefixes are on-link and autonomous together in
 * practice).  Off-link destinations go through ipv6_router_mac().
 */
int ipv6_on_link(const net_t *net, const uint8_t *dst);

#endif /* IPV6_H */
