/**
 * @file net_config.h
 * @brief Compile-time configuration.
 *
 * Every setting below is a default.  Override one with -D, or put the
 * application's settings in a header named by NET_CONFIG_FILE (CMake:
 * -DSMALLEST_TCP_CONFIG_FILE=path), which is included first.  The library
 * and the application must be compiled with the same settings: several of
 * them change the layout of net_t.  The modules' own tunables are in their
 * headers; docs/design/configuration.md lists every one.
 */

#ifndef NET_CONFIG_H
#define NET_CONFIG_H

#ifdef NET_CONFIG_FILE
#include NET_CONFIG_FILE
#endif

/* A prefix for every external name of the stack — stcp_, say — so that it
 * links beside code with a net_init() or a tcp_write() of its own.  The
 * stack and every file that includes its headers are compiled with the
 * same prefix (net_rename.h; CMake: -DSMALLEST_TCP_API_PREFIX=stcp_). */
#ifdef NET_API_PREFIX
#include "net_rename.h"
#endif

/* The network layers Ethernet dispatches to (IPv4 with ARP and ICMP; IPv6
 * with ICMPv6, NDP and MLD) — one or both — and the transports they
 * dispatch to.  A layer set to 0 is left out of net_t and of the API, and
 * its source files out of the build.  CMake sets all four
 * (SMALLEST_TCP_IPV4, _IPV6, _UDP, _TCP). */
#ifndef NET_USE_IPV4
#define NET_USE_IPV4 1
#endif
#ifndef NET_USE_IPV6
#define NET_USE_IPV6 0
#endif
#ifndef NET_USE_UDP
#define NET_USE_UDP 1
#endif
#ifndef NET_USE_TCP
#define NET_USE_TCP 1
#endif
#if !NET_USE_IPV4 && !NET_USE_IPV6
#error "NET_USE_IPV4 and NET_USE_IPV6 are both 0: no network layer"
#endif

/** The link MTU net_init() sets (net_t.mtu, RFC 1122 §3.3.3): the most
 *  any datagram sent carries, headers included */
#ifndef NET_DEFAULT_MTU
#define NET_DEFAULT_MTU 1500
#endif

/** How long a MAC learned by ARP (the gateway's) stays valid without a
 *  new reply (RFC 1122 §2.3.2.1: out-of-date entries are flushed) */
#ifndef NET_ARP_GATEWAY_TIMEOUT_MS
#define NET_ARP_GATEWAY_TIMEOUT_MS 300000u
#endif
/** Targets ARP requests are remembered for, so none is requested more than
 *  once a second (RFC 1122 §2.3.2.1); at least 1 */
#ifndef NET_ARP_RATE_SLOTS
#define NET_ARP_RATE_SLOTS 2
#endif

/* Multicast groups joined at once, IPv4 (ipv4_mcast_join(), igmp_join();
 * 0 compiles IPv4 multicast reception out) and IPv6 (ipv6_mcast_join()).
 * All-hosts, all-nodes and the solicited-node groups need no slot. */
#ifndef NET_MAX_MCAST_GROUPS
#define NET_MAX_MCAST_GROUPS 1
#endif
#ifndef NET_MAX_MCAST6_GROUPS
#define NET_MAX_MCAST6_GROUPS 1
#endif

/* IPv6 */
/* Address slots: [0] link-local, the rest global (SLAAC/DHCPv6/static) */
#ifndef NET_IPV6_ADDRS
#define NET_IPV6_ADDRS 2
#endif
/* Neighbor Solicitations per DAD run (RFC 4862 DupAddrDetectTransmits) */
#ifndef NET_IPV6_DAD_TRANSMITS
#define NET_IPV6_DAD_TRANSMITS 1
#endif
#ifndef NET_IPV6_DEFAULT_HOP_LIMIT
#define NET_IPV6_DEFAULT_HOP_LIMIT 64
#endif

/* Byte order where the compiler does not predefine __BYTE_ORDER__: 1
 * selects big-endian (net_endian.h) */
#ifndef NET_8BIT_TARGET
#define NET_8BIT_TARGET 0
#endif

/* Debug log to stderr (hosted builds only) */
#ifndef NET_DEBUG
#define NET_DEBUG 0
#endif

/* Identity defaults, applied by net_init() */
#define NET_IPV4(a, b, c, d)                                                   \
  ((uint32_t)(a) << 24 | (uint32_t)(b) << 16 | (uint32_t)(c) << 8 |            \
   (uint32_t)(d))

#ifndef NET_DEFAULT_IPV4_ADDR
#define NET_DEFAULT_IPV4_ADDR NET_IPV4(10, 0, 0, 2)
#endif
#ifndef NET_DEFAULT_SUBNET_MASK
#define NET_DEFAULT_SUBNET_MASK NET_IPV4(255, 255, 255, 0)
#endif
#ifndef NET_DEFAULT_GATEWAY
#define NET_DEFAULT_GATEWAY NET_IPV4(10, 0, 0, 1)
#endif
#ifndef NET_DEFAULT_MAC
#define NET_DEFAULT_MAC                                                        \
  { 0x02, 0x00, 0x00, 0xde, 0xad, 0x01 }
#endif

/* TCP timing, in milliseconds: the retransmission timeout before a round
 * trip has been measured, the least a measured one may be (RFC 6298 2.1,
 * 2.4), the ceiling of its doubling, the clock granularity G that RFC
 * 6298 2.3 adds to the smoothed round trip — at least the interval between
 * calls of net_tick() — and the maximum segment lifetime (TIME-WAIT lasts
 * twice that) */
#ifndef NET_DEFAULT_TCP_RTO_INIT_MS
#define NET_DEFAULT_TCP_RTO_INIT_MS 1000
#endif
#ifndef NET_DEFAULT_TCP_RTO_MIN_MS
#define NET_DEFAULT_TCP_RTO_MIN_MS 1000
#endif
#ifndef NET_DEFAULT_TCP_RTO_MAX_MS
#define NET_DEFAULT_TCP_RTO_MAX_MS 60000
#endif
#ifndef NET_DEFAULT_TCP_CLOCK_GRANULARITY_MS
#define NET_DEFAULT_TCP_CLOCK_GRANULARITY_MS 100
#endif
#ifndef NET_DEFAULT_TCP_MSL_MS
#define NET_DEFAULT_TCP_MSL_MS 120000
#endif

#endif /* NET_CONFIG_H */
