/**
 * @file net_config.h
 * @brief Compile-time configuration.
 *
 * Every setting below is a default.  Override one with -D, or put the
 * application's settings in a header named by NET_CONFIG_FILE (CMake:
 * -DSMALLEST_TCP_CONFIG_FILE=path), which is included first.  The library
 * and the application must be compiled with the same settings: several of
 * them change the layout of net_t.
 */

#ifndef NET_CONFIG_H
#define NET_CONFIG_H

#ifdef NET_CONFIG_FILE
#include NET_CONFIG_FILE
#endif

/* Protocols compiled into the IPv4 / IPv6 dispatch */
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

/* Multicast groups joined at once (0 compiles multicast RX out) */
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

/* Architecture */
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

/* TCP timing */
#ifndef NET_DEFAULT_TCP_RTO_INIT_MS
#define NET_DEFAULT_TCP_RTO_INIT_MS 1000
#endif
#ifndef NET_DEFAULT_TCP_RTO_MAX_MS
#define NET_DEFAULT_TCP_RTO_MAX_MS 60000
#endif
#ifndef NET_DEFAULT_TCP_MSL_MS
#define NET_DEFAULT_TCP_MSL_MS 120000
#endif

#endif /* NET_CONFIG_H */
