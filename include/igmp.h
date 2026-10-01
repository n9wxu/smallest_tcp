/**
 * @file igmp.h
 * @brief IGMPv2 host (RFC 2236).
 *
 * Sends an unsolicited Membership Report when joining a group and a Leave
 * Group message when leaving, so IGMP-snooping switches forward the group
 * to us.  Once a group is joined with igmp_join(), queries are answered:
 * each joined group's report goes out after a random delay within the
 * query's Max Response Time, unless another host's report for the group is
 * heard first; an IGMPv1 query makes every report version 1, and stops
 * Leave messages, for 400 s.  The all-hosts group 224.0.0.1 is never
 * reported.  Timers run from net_tick().
 *
 * Messages carry the IP Router Alert option and TTL 1 (RFC 2236 §2).
 */

#ifndef IGMP_H
#define IGMP_H

#include "ipv4.h" /* an IPv4 protocol: needs NET_USE_IPV4 */
#include "net.h"
#include <stdint.h>

#define IGMP_TYPE_QUERY 0x11
#define IGMP_TYPE_V1_REPORT 0x12
#define IGMP_TYPE_V2_REPORT 0x16
#define IGMP_TYPE_LEAVE 0x17

#define IGMP_ALL_ROUTERS 0xE0000002u /* 224.0.0.2 */

/** An IGMP message: Ethernet + IPv4 with Router Alert + 8 bytes. */
#define IGMP_FRAME_SIZE (14 + 24 + 8)

/**
 * Join @p group: ipv4_mcast_join() + one Membership Report, and IGMP
 * answers queries from then on (net->igmp_ops).  RFC 2236 §3 recommends
 * repeating the report once after a short delay; call igmp_report() for
 * that.
 */
net_err_t igmp_join(net_t *net, uint32_t group);

/** Send a Membership Report for @p group: version 2, or version 1 while an
 *  IGMPv1 querier is present.  Nothing for 224.0.0.1. */
net_err_t igmp_report(net_t *net, uint32_t group);

/** Leave @p group: ipv4_mcast_leave() + a Leave Group message to
 *  224.0.0.2 — none while an IGMPv1 querier is present. */
net_err_t igmp_leave(net_t *net, uint32_t group);

#endif /* IGMP_H */
