/**
 * @file mld.h
 * @brief Multicast Listener Discovery for hosts: MLDv2 (RFC 3810) with
 *        MLDv1 (RFC 2710) compatibility.
 *
 * Reports the groups the interface listens to — the solicited-node group
 * of each configured address and the groups joined with ipv6_mcast_join()
 * — so switches that snoop MLD forward them.  All-nodes is never reported
 * (RFC 3810 §6).  Driven by ipv6_tick(); queries arrive via icmpv6_input().
 */

#ifndef MLD_H
#define MLD_H

#include "eth.h"
#include "ipv6.h"
#include "net.h"
#include <stdint.h>

#define MLD_QUERY 130
#define MLD_V1_REPORT 131
#define MLD_V1_DONE 132
#define MLD_V2_REPORT 143

/* MLDv2 Multicast Address Record types (RFC 3810 §5.2.12) */
#define MLD_MODE_IS_EXCLUDE 2    /* answer to a query: listening */
#define MLD_CHANGE_TO_INCLUDE 3  /* with no sources: left the group */
#define MLD_CHANGE_TO_EXCLUDE 4  /* with no sources: joined the group */

#define MLD_V1_QUERY_LEN 24
#define MLD_V2_QUERY_MIN_LEN 28
#define MLD_HOP_LIMIT 1
#define MLD_UNSOLICITED_INTERVAL_MS 1000 /* RFC 3810 §9.11 */
#define MLD_OLDER_QUERIER_S 260          /* RFC 3810 §9.12 */

/** Process an MLD message (types 130-132, 143) whose checksum is valid. */
void mld_input(net_t *net, const ipv6_hdr_t *ip);

/**
 * Report a change of our listening groups now (unsolicited), and once more
 * after MLD_UNSOLICITED_INTERVAL_MS (Robustness Variable 2).
 * @param leaving  A group we just left (reported as such), or NULL.
 */
void mld_report_change(net_t *net, const uint8_t *leaving);

/** Advance query-response and retransmission timers (from ipv6_tick()). */
void mld_tick(net_t *net, uint32_t elapsed_ms);

#endif /* MLD_H */
