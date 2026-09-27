/**
 * @file igmp.h
 * @brief Minimal IGMPv2 host (RFC 2236) — join/leave signalling only.
 *
 * Sends unsolicited Version 2 Membership Reports when joining a group and a
 * Leave Group message when leaving, so IGMP-snooping switches forward the
 * group to us.  Queries are not answered: V1 only joins link-local groups
 * (224.0.0.0/24, e.g. mDNS 224.0.0.251), which snooping switches must flood
 * regardless of membership (RFC 4541 §2.1.2).
 *
 * Messages carry the IP Router Alert option and TTL 1 (RFC 2236 §2).
 */

#ifndef IGMP_H
#define IGMP_H

#include "ipv4.h" /* an IPv4 protocol: needs NET_USE_IPV4 */
#include "net.h"
#include <stdint.h>

#define IGMP_TYPE_QUERY 0x11
#define IGMP_TYPE_V2_REPORT 0x16
#define IGMP_TYPE_LEAVE 0x17

#define IGMP_ALL_ROUTERS 0xE0000002u /* 224.0.0.2 */

/** An IGMP message: Ethernet + IPv4 with Router Alert + 8 bytes. */
#define IGMP_FRAME_SIZE (14 + 24 + 8)

/**
 * Join @p group: ipv4_mcast_join() + one Membership Report.
 * RFC 2236 §3 recommends repeating the report once after a short delay;
 * call igmp_report() for that.
 */
net_err_t igmp_join(net_t *net, uint32_t group);

/** Send a Version 2 Membership Report for @p group. */
net_err_t igmp_report(net_t *net, uint32_t group);

/** Leave @p group: Leave Group message to 224.0.0.2 + ipv4_mcast_leave(). */
net_err_t igmp_leave(net_t *net, uint32_t group);

#endif /* IGMP_H */
