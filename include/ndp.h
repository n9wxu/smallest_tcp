/**
 * @file ndp.h
 * @brief Neighbor Discovery (RFC 4861) for a host without a neighbour
 *        cache, Duplicate Address Detection and SLAAC (RFC 4862).
 */

#ifndef NDP_H
#define NDP_H

#include "eth.h"
#include "ipv6.h"
#include "net.h"
#include <stdint.h>

#define NDP_HOP_LIMIT 255 /* all ND messages (RFC 4861 §6.1, §7.1) */

/* Offsets in the ICMPv6 message */
#define NDP_OFF_FLAGS 4  /* NA: R|S|O flags */
#define NDP_OFF_TARGET 8 /* NS, NA: target address */
#define NDP_NS_NA_LEN 24 /* NS/NA without options */
#define NDP_RS_LEN 8     /* RS without options */
#define NDP_RA_LEN 16    /* RA without options */
#define NDP_RA_OFF_HOPLIMIT 4
#define NDP_RA_OFF_FLAGS 5
#define NDP_RA_OFF_LIFETIME 6 /* router lifetime, seconds */

#define NDP_RA_MANAGED 0x80 /* M: get addresses from DHCPv6 */
#define NDP_RA_OTHER 0x40   /* O: get other configuration from DHCPv6 */

#define NDP_NA_FLAG_R 0x80 /* Router */
#define NDP_NA_FLAG_S 0x40 /* Solicited */
#define NDP_NA_FLAG_O 0x20 /* Override */

/* Options: type, length in units of 8 bytes, value */
#define NDP_OPT_SLLA 1   /* Source Link-Layer Address */
#define NDP_OPT_TLLA 2   /* Target Link-Layer Address */
#define NDP_OPT_PREFIX 3 /* Prefix Information */
#define NDP_OPT_MTU 5
#define NDP_OPT_LLA_LEN 8 /* type, length, 6-byte MAC */
#define NDP_OPT_PREFIX_LEN 32
#define NDP_PREFIX_FLAG_L 0x80 /* on-link */
#define NDP_PREFIX_FLAG_A 0x40 /* autonomous address configuration */

/* RFC 4861 §10 */
#define NDP_RETRANS_TIMER_MS 1000
#define NDP_MAX_RTR_SOLICITATION_DELAY_MS 1000
#define NDP_RTR_SOLICITATION_INTERVAL_MS 4000
#ifndef NDP_MAX_RTR_SOLICITATIONS
#define NDP_MAX_RTR_SOLICITATIONS 3
#endif

#define SLAAC_TWO_HOURS_S 7200u /* RFC 4862 §5.5.3(e) */

/**
 * Process a Neighbor Discovery message (ICMPv6 types 133-137) whose
 * checksum icmpv6_input() has verified.
 */
void ndp_input(net_t *net, const ipv6_hdr_t *ip, const eth_frame_t *eth);

/**
 * Send a Neighbor Solicitation for @p target.
 * @param dad  1: Duplicate Address Detection probe (source ::, no Source
 *             Link-Layer Address option); 0: address resolution.
 */
net_err_t ndp_send_ns(net_t *net, const uint8_t *target, int dad);

/** Start DAD on address slot @p slot (state becomes TENTATIVE). */
void ndp_dad_start(net_t *net, uint8_t slot, uint16_t delay_ms);

/** Advance Router Solicitation and DAD timers by @p elapsed_ms (called
 *  by ipv6_tick()).  Solicitations start once the link-local address is
 *  preferred and stop at the first Router Advertisement. */
void ndp_tick(net_t *net, uint32_t elapsed_ms);

#endif /* NDP_H */
